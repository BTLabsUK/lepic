// SPDX-License-Identifier: Apache-2.0
//! A large wallet history for benchmarks, written through the repository traits.
//!
//! The history is a mined one in account 0: a receive stores its output and the S2 it answered
//! with; a send stores S1 and S3, a counterparty, a finalize mark, its spent input and its
//! change. Slate bytes are the V3 vectors with the slate id swapped, so they decode as real ones.
//! The same arguments always write the same records: a fixed seed, no clock.
//!
//! Commitments are curve points no keychain derived, under keys `m/0/0/<child>` from the
//! account's key counter on. A caller that wants the unspent outputs spendable replaces each one
//! with the output its key and amount commit to.

use std::collections::VecDeque;

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::ser::{ProtocolVersion, deserialize};
use uuid::Uuid;

use crate::account::{AccountIndex, AccountRecord};
use crate::error::{Record, StoreError};
use crate::output::{COMMITMENT_LEN, KEY_ID_LEN, KeyId, OutputRecord, OutputStatus};
use crate::slate::{SlateStage, StoredSlate};
use crate::store::{Repositories, WalletStore};
use crate::transaction::{TransactionEntry, TxDirection, TxId, TxState};
use crate::tx_record::TxMarks;

const SEED: u64 = 0x4c45_5049_435f_4d30;
/// 2025-01-01T00:00:00Z.
const START_SECONDS: i64 = 1_735_689_600;
const SECONDS_BETWEEN: i64 = 600;
const SECONDS_TO_MINE: i64 = 120;
const NANO_PER_EPIC: u64 = 100_000_000;
const PEERS: u32 = 50;
const SEND_LIMIT_BLOCKS: u64 = 1_440;
const FEE: u64 = 800_000;
const CODEC: &str = "legacy-v3";
const LABEL: &str = "default";

const EPICBOX_S1: &str =
    include_str!("../../../testdata/vectors/slates/send_epicbox_plain_s1_v3.json");
const EPICBOX_S2: &str =
    include_str!("../../../testdata/vectors/slates/send_epicbox_plain_s2_v3.json");
const EPICBOX_S3: &str =
    include_str!("../../../testdata/vectors/slates/send_epicbox_plain_s3_v3.json");
const FILE_S1: &str = include_str!("../../../testdata/vectors/slates/send_file_plain_s1_v3.json");
const FILE_S3: &str = include_str!("../../../testdata/vectors/slates/send_file_plain_s3_v3.json");

/// The slates of each kind of entry, decoded once.
struct Vectors {
    epicbox_s1: (String, String),
    epicbox_s2: (String, String),
    epicbox_s3: (String, String),
    file_s1: (String, String),
    file_s3: (String, String),
}

impl Vectors {
    fn load() -> Result<Self, StoreError> {
        Ok(Self {
            epicbox_s1: vector(EPICBOX_S1)?,
            epicbox_s2: vector(EPICBOX_S2)?,
            epicbox_s3: vector(EPICBOX_S3)?,
            file_s1: vector(FILE_S1)?,
            file_s3: vector(FILE_S3)?,
        })
    }
}

/// The vector's slate id and V3 JSON.
fn vector(file: &str) -> Result<(String, String), StoreError> {
    let corrupt = || StoreError::Corrupt {
        record: Record::Slate,
        field: "seed vector",
    };
    let root: serde_json::Value = serde_json::from_str(file).map_err(|_| corrupt())?;
    let expected = root.get("expected").ok_or_else(corrupt)?;
    let text = |key: &str| {
        expected
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    match (text("slate_id"), text("json")) {
        (Some(id), Some(json)) => Ok((id, json)),
        _ => Err(corrupt()),
    }
}

fn slate(vector: &(String, String), slate_id: Uuid, stage: SlateStage) -> StoredSlate {
    let (vector_id, json) = vector;
    StoredSlate {
        slate_id,
        stage,
        codec: CODEC.to_owned(),
        bytes: json
            .replace(vector_id.as_str(), &slate_id.hyphenated().to_string())
            .into_bytes(),
    }
}

/// SplitMix64: a fixed sequence from [`SEED`].
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ z.wrapping_shr(31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next().checked_rem(bound).unwrap_or(0)
    }

    fn uuid(&mut self) -> Uuid {
        let high = self.next().to_be_bytes();
        let low = self.next().to_be_bytes();
        let mut bytes = [0_u8; 16];
        for (slot, byte) in bytes.iter_mut().zip(high.into_iter().chain(low)) {
            *slot = byte;
        }
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    }

    /// A plain output identifier whose commitment is a curve point.
    fn identifier(&mut self) -> OutputIdentifier {
        loop {
            let mut bytes = vec![
                OutputFeatures::Plain.as_u8(),
                if self.next() & 1 == 0 { 0x08 } else { 0x09 },
            ];
            while bytes.len() <= COMMITMENT_LEN {
                bytes.extend_from_slice(&self.next().to_be_bytes());
            }
            bytes.truncate(COMMITMENT_LEN.saturating_add(1));
            if let Ok(id) = deserialize::<OutputIdentifier>(&bytes, ProtocolVersion::V1) {
                return id;
            }
        }
    }
}

fn out_of_range(field: &'static str) -> StoreError {
    StoreError::OutOfRange { field }
}

/// `ceil(index * unspent / transactions)`: entry `index` is a receive when this rises at it,
/// which spreads `unspent` receives over the history and makes the first entry one.
fn receives_before(index: u64, unspent: u64, transactions: u64) -> Result<u64, StoreError> {
    index
        .checked_mul(unspent)
        .and_then(|product| product.checked_add(transactions.checked_sub(1)?))
        .and_then(|sum| sum.checked_div(transactions))
        .ok_or_else(|| out_of_range("transactions"))
}

/// The key `m/0/0/<child>`: depth, then four big-endian components.
fn key_id(child: u32) -> KeyId {
    let mut bytes = [0_u8; KEY_ID_LEN];
    let components = [0_u32, 0, child, 0];
    let encoded = std::iter::once(3).chain(components.iter().flat_map(|part| part.to_be_bytes()));
    for (slot, byte) in bytes.iter_mut().zip(encoded) {
        *slot = byte;
    }
    KeyId(bytes)
}

fn time(index: u64, extra: i64) -> Result<Timestamp, StoreError> {
    i64::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(SECONDS_BETWEEN))
        .and_then(|offset| START_SECONDS.checked_add(offset)?.checked_add(extra))
        .and_then(|seconds| Timestamp::from_second(seconds).ok())
        .ok_or_else(|| out_of_range("created_at"))
}

fn peer(n: u64) -> String {
    format!("es{n:0>50}")
}

/// Writes `transactions` mined entries in account 0, of which `unspent` are receives whose
/// outputs stay unspent; every send spends one output and keeps its change unspent until the
/// next send spends it. `unspent` must lie between 1 and `transactions`, or both be zero.
pub fn seed<S: WalletStore + ?Sized>(
    store: &S,
    transactions: u32,
    unspent: u32,
) -> Result<(), StoreError> {
    if unspent > transactions || (unspent == 0 && transactions > 0) {
        return Err(out_of_range("unspent"));
    }
    let vectors = Vectors::load()?;
    store.write(|repos| write_history(repos, &vectors, transactions, unspent))
}

fn write_history(
    repos: &mut dyn Repositories,
    vectors: &Vectors,
    transactions: u32,
    unspent: u32,
) -> Result<(), StoreError> {
    let mut account = match repos.account(AccountIndex(0))? {
        Some(account) => account,
        None => AccountRecord {
            index: AccountIndex(0),
            label: LABEL.to_owned(),
            next_child: 0,
        },
    };
    let first_child = account.next_child;
    account.next_child = first_child
        .checked_add(transactions)
        .ok_or_else(|| out_of_range("next_child"))?;
    repos.put_account(&account)?;

    let mut draw = Draw(SEED);
    let mut outputs: Vec<OutputRecord> = Vec::new();
    // Indices into `outputs` of the outputs no entry has spent yet, oldest first.
    let mut pool: VecDeque<usize> = VecDeque::new();
    let total = u64::from(transactions);
    let receives = u64::from(unspent);
    for index in 0..total {
        let child = u32::try_from(index)
            .ok()
            .and_then(|index| first_child.checked_add(index))
            .ok_or_else(|| out_of_range("next_child"))?;
        let entry = Entry {
            index,
            slate_id: draw.uuid(),
            height: Height::new(index.checked_add(1).ok_or_else(|| out_of_range("height"))?),
            created_at: time(index, 0)?,
            updated_at: time(index, SECONDS_TO_MINE)?,
        };
        let receive = receives_before(index.saturating_add(1), receives, total)?
            > receives_before(index, receives, total)?;
        // The first entry is a receive, so a send always finds an output to spend.
        let input = if receive { None } else { pool.pop_front() };
        let (id, amount) = match input.and_then(|input| outputs.get_mut(input)) {
            None => write_receive(repos, vectors, &mut draw, &entry)?,
            Some(input) => {
                let written = write_send(repos, vectors, &mut draw, &entry, input.amount)?;
                input.status = OutputStatus::Spent;
                input.tx = Some(written.0);
                written
            }
        };
        repos.set_confirmed_height(id, entry.height)?;
        outputs.push(OutputRecord {
            id: draw.identifier(),
            key_id: key_id(child),
            account: AccountIndex(0),
            amount,
            status: OutputStatus::Unspent,
            height: entry.height,
            lock_height: Height::ZERO,
            mmr_index: Some(
                index
                    .checked_add(2)
                    .ok_or_else(|| out_of_range("mmr_index"))?,
            ),
            tx: Some(id),
        });
        pool.push_back(outputs.len().saturating_sub(1));
    }
    for output in &outputs {
        repos.insert_output(output)?;
    }
    Ok(())
}

/// What a receive and a send of the history share.
struct Entry {
    index: u64,
    slate_id: Uuid,
    height: Height,
    created_at: Timestamp,
    updated_at: Timestamp,
}

/// Stores a mined receive and returns it with the amount of its output.
fn write_receive(
    repos: &mut dyn Repositories,
    vectors: &Vectors,
    draw: &mut Draw,
    entry: &Entry,
) -> Result<(TxId, Amount), StoreError> {
    // Large enough to pay for every send a chain of change can make at 100,000 transactions.
    let amount = draw
        .below(500)
        .checked_add(500)
        .and_then(|epic| epic.checked_mul(NANO_PER_EPIC))
        .map(Amount::new)
        .ok_or_else(|| out_of_range("amount"))?;
    let id = repos.insert_transaction(&TransactionEntry {
        account: AccountIndex(0),
        direction: TxDirection::Incoming,
        state: TxState::Confirmed,
        slate_id: Some(entry.slate_id),
        transport: Some("epicbox".to_owned()),
        amount_credited: amount,
        amount_debited: Amount::ZERO,
        fee: None,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })?;
    repos.insert_slate(&slate(
        &vectors.epicbox_s2,
        entry.slate_id,
        SlateStage::Standard2,
    ))?;
    repos.set_counterparty(id, &peer(draw.below(u64::from(PEERS))))?;
    Ok((id, amount))
}

/// Stores a mined, finalized send of part of `input` and returns it with its change.
fn write_send(
    repos: &mut dyn Repositories,
    vectors: &Vectors,
    draw: &mut Draw,
    entry: &Entry,
    input: Amount,
) -> Result<(TxId, Amount), StoreError> {
    let fee = Fee::new(FEE);
    let available = input
        .value()
        .checked_sub(fee.value())
        .ok_or_else(|| out_of_range("amount"))?;
    // Up to one EPIC and never more than half the input, so the send always has change.
    let sent = draw
        .below(100)
        .checked_add(1)
        .and_then(|cents| cents.checked_mul(NANO_PER_EPIC.checked_div(100)?))
        .map(|sent| sent.min(available.checked_div(2).unwrap_or(0)))
        .ok_or_else(|| out_of_range("amount"))?;
    let change = Amount::new(
        available
            .checked_sub(sent)
            .ok_or_else(|| out_of_range("amount"))?,
    );
    let by_file = entry.index.checked_rem(5) == Some(0);
    let id = repos.insert_transaction(&TransactionEntry {
        account: AccountIndex(0),
        direction: TxDirection::Outgoing,
        state: TxState::Confirmed,
        slate_id: Some(entry.slate_id),
        transport: Some(if by_file { "file" } else { "epicbox" }.to_owned()),
        amount_credited: change,
        amount_debited: input,
        fee: Some(fee),
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })?;
    let (s1, s3) = if by_file {
        (&vectors.file_s1, &vectors.file_s3)
    } else {
        (&vectors.epicbox_s1, &vectors.epicbox_s3)
    };
    repos.insert_slate(&slate(s1, entry.slate_id, SlateStage::Standard1))?;
    repos.insert_slate(&slate(s3, entry.slate_id, SlateStage::Standard3))?;
    if !by_file {
        repos.set_counterparty(id, &peer(draw.below(u64::from(PEERS))))?;
    }
    let cutoff = entry
        .height
        .value()
        .checked_add(SEND_LIMIT_BLOCKS)
        .ok_or_else(|| out_of_range("height"))?;
    repos.put_tx_marks(
        id,
        &TxMarks {
            local_cutoff: Some(Height::new(cutoff)),
            finalized_at: Some(entry.height),
            ..TxMarks::default()
        },
    )?;
    Ok((id, change))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::MemoryStore;
    use crate::context::{CONTEXT_KEY_LEN, StoreKeys};

    fn seeded(transactions: u32, unspent: u32) -> MemoryStore {
        let store = MemoryStore::new(StoreKeys::from_bytes(
            [1; CONTEXT_KEY_LEN],
            [1; CONTEXT_KEY_LEN],
        ));
        seed(&store, transactions, unspent).unwrap();
        store
    }

    type Contents = (
        Vec<crate::StoredTransaction>,
        Vec<OutputRecord>,
        Vec<StoredSlate>,
        Option<AccountRecord>,
    );

    fn contents(store: &MemoryStore) -> Contents {
        store
            .read(|repos| {
                let transactions = repos.transactions(AccountIndex(0))?;
                let mut outputs = repos.outputs(AccountIndex(0), None)?;
                outputs.sort_by_key(|output| *output.commitment());
                let mut slates = Vec::new();
                for transaction in &transactions {
                    slates.extend(repos.slates(transaction.entry.slate_id.unwrap())?);
                }
                Ok::<_, StoreError>((
                    transactions,
                    outputs,
                    slates,
                    repos.account(AccountIndex(0))?,
                ))
            })
            .unwrap()
    }

    #[test]
    fn seed_writes_the_counts_asked_for() {
        let (transactions, outputs, slates, account) = contents(&seeded(40, 7));
        assert_eq!(transactions.len(), 40);
        let receives = transactions
            .iter()
            .filter(|tx| tx.entry.direction == TxDirection::Incoming)
            .count();
        assert_eq!(receives, 7);
        assert_eq!(outputs.len(), 40);
        let unspent = outputs
            .iter()
            .filter(|output| output.status == OutputStatus::Unspent)
            .count();
        assert_eq!(unspent, 7);
        assert_eq!(outputs.len() - unspent, 33);
        let stages = |stage| slates.iter().filter(|slate| slate.stage == stage).count();
        assert_eq!(stages(SlateStage::Standard1), 33);
        assert_eq!(stages(SlateStage::Standard2), 7);
        assert_eq!(stages(SlateStage::Standard3), 33);
        assert!(slates.iter().all(|slate| {
            String::from_utf8_lossy(&slate.bytes).contains(&slate.slate_id.hyphenated().to_string())
        }));
        assert_eq!(account.unwrap().next_child, 40);
        assert_eq!(
            transactions[0].entry.direction,
            TxDirection::Incoming,
            "a send needs an output before it"
        );
    }

    #[test]
    fn seed_writes_the_same_store_twice() {
        assert_eq!(contents(&seeded(60, 5)), contents(&seeded(60, 5)));
    }

    #[test]
    fn seed_refuses_more_unspent_than_transactions() {
        let store = MemoryStore::new(StoreKeys::from_bytes(
            [1; CONTEXT_KEY_LEN],
            [1; CONTEXT_KEY_LEN],
        ));
        assert!(matches!(
            seed(&store, 3, 4),
            Err(StoreError::OutOfRange { field: "unspent" })
        ));
    }
}
