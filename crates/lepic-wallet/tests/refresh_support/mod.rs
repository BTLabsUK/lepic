//! The G-05 refresh sessions (`testdata/vectors/engine/refresh_*.json`) as engine fixtures: the
//! subject's wallet seeded with the state upstream started from, over a `MockNode` that replays
//! the session, and the comparison of the wallet's stored state with the state upstream ended
//! in, mapped through `docs/compat/states.md`.

// Each test binary uses a different subset of these helpers, and test helpers may unwrap, index
// and panic (docs/rules.md).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, TransactionEntry, TxDirection, TxId, TxState,
};
use lepic_wallet::scan::ScannedBlock;
use serde_json::Value;
use uuid::Uuid;

use crate::scan_support::{AnyWallet, snapshot, write};
use crate::support::{Harness, fixed_time};

/// Every refresh session, sorted by name.
pub fn refresh_vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/engine");
    let mut vectors: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.starts_with("refresh_") && name.ends_with(".json")
        })
        .map(|path| {
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            let vector: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(vector["inputs"]["session"], "refresh", "{name}");
            (name, vector)
        })
        .collect();
    vectors.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        !vectors.is_empty(),
        "expected G-05 refresh vectors in {dir:?}"
    );
    vectors
}

/// The refresh vector `name`.
pub fn refresh_vector(name: &str) -> Value {
    refresh_vectors()
        .into_iter()
        .find(|(found, _)| found == name)
        .unwrap_or_else(|| panic!("no refresh vector {name}"))
        .1
}

pub fn number(value: &Value) -> u64 {
    match value {
        Value::String(text) => text.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn output_status(name: &str) -> OutputStatus {
    match name {
        "Unconfirmed" => OutputStatus::Unconfirmed,
        "Unspent" => OutputStatus::Unspent,
        "Locked" => OutputStatus::Locked,
        "Spent" => OutputStatus::Spent,
        other => panic!("upstream output status {other} has no stored form"),
    }
}

/// The LEPIC direction and state of an upstream entry, per `docs/compat/states.md`. An
/// unconfirmed `TxSentCreated` stands for a posted transaction: the sessions record the node
/// after the transaction was mined, so the sender posted it.
pub fn transaction_state(tx_type: &str, confirmed: bool) -> (TxDirection, TxState) {
    match (tx_type, confirmed) {
        ("TxSentCreated" | "TxSentMempool", false) => (TxDirection::Outgoing, TxState::Posted),
        ("TxSent", true) => (TxDirection::Outgoing, TxState::Confirmed),
        ("TxSentCancelled", false) => (TxDirection::Outgoing, TxState::Cancelled),
        ("ConfirmedCoinbase" | "TxReceived" | "TxReceivedMempool", true) => {
            (TxDirection::Incoming, TxState::Confirmed)
        }
        ("TxReceived", false) => (TxDirection::Incoming, TxState::Received),
        ("TxReceivedCancelled", false) => (TxDirection::Incoming, TxState::Cancelled),
        (other, confirmed) => panic!("no mapping for {other} with confirmed = {confirmed}"),
    }
}

/// The slate id a seeded entry gets when upstream's has one; upstream's own ids are not
/// recorded.
fn slate_id(upstream_id: u64) -> Uuid {
    Uuid::from_u128(u128::from(upstream_id) + 1)
}

fn optional_number(value: &Value) -> Option<u64> {
    (!value.is_null()).then(|| number(value))
}

/// The account component of an output's key id, which follows the depth byte.
fn key_account(output: &Value) -> AccountIndex {
    let key_id = output["key_id"].as_str().unwrap();
    AccountIndex(u32::from_str_radix(&key_id[2..10], 16).unwrap())
}

/// Stores `inputs.before` in the restored wallet's database: its transactions, outputs, key
/// counter, last confirmed height and last scanned block. Returns upstream's entry ids with the
/// ids the store gave them.
pub fn seed_before(harness: &Harness, vector: &Value) -> BTreeMap<u64, TxId> {
    let before = &vector["inputs"]["before"];
    write(harness, |repos| {
        let mut account = repos.account(AccountIndex(0))?.unwrap();
        account.next_child = u32::try_from(number(&before["next_child_index"])).unwrap();
        repos.put_account(&account)?;

        let mut ids = BTreeMap::new();
        for tx in before["transactions"].as_array().unwrap() {
            let (direction, state) = transaction_state(
                tx["tx_type"].as_str().unwrap(),
                tx["confirmed"].as_bool().unwrap(),
            );
            let upstream_id = number(&tx["id"]);
            let id = repos.insert_transaction(&TransactionEntry {
                account: AccountIndex(0),
                direction,
                state,
                slate_id: tx["has_slate_id"]
                    .as_bool()
                    .unwrap()
                    .then(|| slate_id(upstream_id)),
                transport: None,
                amount_credited: Amount::new(number(&tx["amount_credited"])),
                amount_debited: Amount::new(number(&tx["amount_debited"])),
                fee: optional_number(&tx["fee"]).map(Fee::new),
                created_at: fixed_time(),
                updated_at: fixed_time(),
            })?;
            ids.insert(upstream_id, id);
        }
        for output in before["outputs"].as_array().unwrap() {
            let features = if output["is_coinbase"].as_bool().unwrap() {
                OutputFeatures::Coinbase
            } else {
                OutputFeatures::Plain
            };
            let commitment = Commitment::from_hex(output["commit"].as_str().unwrap()).unwrap();
            repos.put_output(&OutputRecord {
                id: OutputIdentifier::new(features, commitment),
                key_id: KeyId(
                    unhex(output["key_id"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                ),
                account: key_account(output),
                amount: Amount::new(number(&output["value"])),
                status: output_status(output["status"].as_str().unwrap()),
                height: Height::new(number(&output["height"])),
                lock_height: Height::new(number(&output["lock_height"])),
                mmr_index: optional_number(&output["mmr_index"]),
                tx: optional_number(&output["tx_log_entry"]).map(|id| ids[&id]),
            })?;
        }

        repos.put_setting(
            "refresh.last_confirmed_height",
            &number(&before["last_confirmed_height"]).to_string(),
        )?;
        let block = &before["last_scanned_block"];
        repos.put_setting(
            "scan.last_scanned",
            &format!(
                "{} {} {} {}",
                number(&block["height"]),
                block["hash"].as_str().unwrap(),
                number(&block["start_pmmr_index"]),
                number(&block["last_pmmr_index"]),
            ),
        )?;
        Ok(ids)
    })
}

/// Asserts that the wallet holds exactly the outputs and transactions upstream ended with, and
/// the last confirmed height it recorded.
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
pub fn assert_matches_upstream<N: lepic_node::NodeApi + 'static>(
    harness: &Harness,
    wallet: &AnyWallet<N>,
    vector: &Value,
    ids: &BTreeMap<u64, TxId>,
    name: &str,
) {
    let after = &vector["expected"]["after"];
    let state = snapshot(harness);
    let expected_outputs = after["outputs"].as_array().unwrap();
    let expected_transactions = after["transactions"].as_array().unwrap();
    assert_eq!(
        state.outputs.len(),
        expected_outputs.len(),
        "{name}: outputs"
    );
    let outputs: BTreeMap<String, &OutputRecord> = state
        .outputs
        .iter()
        .map(|output| (hex(output.commitment()), output))
        .collect();
    for expected in expected_outputs {
        let commit = expected["commit"].as_str().unwrap();
        let context = format!("{name}: output {commit}");
        let stored = outputs
            .get(commit)
            .unwrap_or_else(|| panic!("{context} missing"));
        assert_eq!(hex(&stored.key_id.0), expected["key_id"], "{context}");
        assert_eq!(stored.account, key_account(expected), "{context}");
        assert_eq!(
            stored.amount.value(),
            number(&expected["value"]),
            "{context}"
        );
        assert_eq!(
            stored.status,
            output_status(expected["status"].as_str().unwrap()),
            "{context}"
        );
        assert_eq!(
            stored.height,
            Height::new(number(&expected["height"])),
            "{context}"
        );
        assert_eq!(
            stored.lock_height,
            Height::new(number(&expected["lock_height"])),
            "{context}"
        );
        assert_eq!(
            stored.id.features.is_coinbase(),
            expected["is_coinbase"].as_bool().unwrap(),
            "{context}"
        );
        assert_eq!(
            stored.mmr_index,
            optional_number(&expected["mmr_index"]),
            "{context}"
        );
        assert_eq!(
            stored.tx,
            optional_number(&expected["tx_log_entry"]).map(|id| ids[&id]),
            "{context}"
        );
    }

    assert_eq!(
        state.transactions.len(),
        expected_transactions.len(),
        "{name}: transactions"
    );
    for expected in expected_transactions {
        let upstream_id = number(&expected["id"]);
        let context = format!("{name}: transaction {upstream_id}");
        let entry = &state
            .transactions
            .iter()
            .find(|tx| tx.id == ids[&upstream_id])
            .unwrap_or_else(|| panic!("{context} missing"))
            .entry;
        let (direction, tx_state) = transaction_state(
            expected["tx_type"].as_str().unwrap(),
            expected["confirmed"].as_bool().unwrap(),
        );
        assert_eq!(entry.direction, direction, "{context}");
        assert_eq!(entry.state, tx_state, "{context}");
        assert_eq!(
            entry.amount_credited.value(),
            number(&expected["amount_credited"]),
            "{context}"
        );
        assert_eq!(
            entry.amount_debited.value(),
            number(&expected["amount_debited"]),
            "{context}"
        );
        assert_eq!(
            entry.fee.map(Fee::value),
            optional_number(&expected["fee"]),
            "{context}"
        );
        assert_eq!(
            entry.slate_id.is_some(),
            expected["has_slate_id"].as_bool().unwrap(),
            "{context}"
        );
    }

    let default_account = state
        .accounts
        .iter()
        .find(|account| account.index == AccountIndex(0))
        .unwrap();
    assert_eq!(
        u64::from(default_account.next_child),
        number(&after["next_child_index"]),
        "{name}: next child index"
    );
    assert_eq!(
        wallet.last_confirmed_height().unwrap(),
        Some(Height::new(number(&after["last_confirmed_height"]))),
        "{name}: last confirmed height"
    );
    assert_eq!(harness.node.violations(), [], "{name}: replay violations");
}

/// Asserts the scanned position upstream's update recorded after its scan.
pub fn assert_scanned_like_upstream<N: lepic_node::NodeApi + 'static>(
    wallet: &AnyWallet<N>,
    vector: &Value,
    name: &str,
) {
    let expected = &vector["expected"]["after"]["last_scanned_block"];
    let ScannedBlock {
        height,
        hash,
        start_pmmr_index,
        last_pmmr_index,
    } = wallet
        .last_scanned_block()
        .unwrap()
        .unwrap_or_else(|| panic!("{name}: no scanned block recorded"));
    assert_eq!(height, Height::new(number(&expected["height"])), "{name}");
    assert_eq!(hash.to_hex(), expected["hash"], "{name}");
    assert_eq!(
        start_pmmr_index,
        number(&expected["start_pmmr_index"]),
        "{name}"
    );
    assert_eq!(
        last_pmmr_index,
        number(&expected["last_pmmr_index"]),
        "{name}"
    );
}
