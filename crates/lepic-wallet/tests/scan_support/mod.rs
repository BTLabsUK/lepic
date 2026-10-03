//! The G-05 restore sessions (`testdata/vectors/engine/restore_*.json`) as engine fixtures: a
//! wallet restored from the subject's phrase over a `MockNode` that replays the session, and the
//! comparison of the wallet's stored state with the state upstream ended in, mapped through
//! `docs/compat/states.md`.

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
use lepic_node::mock::MockNode;
use lepic_node::{
    LocatedKernel, NodeApi, NodeClient, NodeError, NodeVersion, OutputLocation, PmmrIndices,
    Propagation, Tip, UnspentOutputs,
};
use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_primitives::tx::Transaction;
use lepic_store::{
    AccountIndex, AccountRecord, CONTEXT_KEY_LEN, ContextKey, MemoryStore, OutputRecord,
    OutputStatus, Repositories, StoreError, StoredTransaction, TxDirection, TxState, WalletStore,
};
use lepic_wallet::scan::{ScanOptions, ScannedBlock};
use lepic_wallet::{Ports, StoreOpener, Wallet};
use serde_json::Value;

use crate::support::{Harness, MemoryStores, TestVault, password};

/// A test wallet over any node, so tests can wrap the mock node.
pub type AnyWallet<N> = Wallet<N, MemoryStores, TestVault>;

pub const PASSWORD: &str = "restore password";

/// Every restore session, sorted by name.
pub fn restore_vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/engine");
    let mut vectors: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.starts_with("restore_") && name.ends_with(".json")
        })
        .map(|path| {
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            let vector: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(vector["inputs"]["session"], "restore", "{name}");
            (name, vector)
        })
        .collect();
    vectors.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        !vectors.is_empty(),
        "expected G-05 restore vectors in {dir:?}"
    );
    vectors
}

/// The vector `restore_full_scan`.
pub fn full_scan_vector() -> Value {
    restore_vectors()
        .into_iter()
        .find(|(name, _)| name == "restore_full_scan")
        .unwrap()
        .1
}

fn number(value: &Value) -> u64 {
    match value {
        Value::String(text) => text.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}

/// A harness whose node replays the vector's session.
pub fn harness(vector: &Value) -> Harness {
    assert_eq!(vector["inputs"]["subject"]["keychain"], "mainnet");
    let mut harness = Harness::new();
    harness.node = MockNode::from_recording(&vector.to_string()).unwrap();
    harness
}

/// Restores the subject's wallet from its phrase, without scanning.
pub fn restore<N: NodeApi + 'static>(harness: &Harness, wallet: &AnyWallet<N>, vector: &Value) {
    let phrase = vector["inputs"]["subject"]["mnemonic"].as_str().unwrap();
    harness
        .block_on(wallet.restore(password(PASSWORD), phrase))
        .unwrap();
}

/// A restore scan on the vector's chain, which matures coinbase outputs as its chain type does.
pub fn options(vector: &Value) -> ScanOptions {
    ScanOptions {
        coinbase_maturity: number(&vector["inputs"]["chain"]["coinbase_maturity"]),
        ..ScanOptions::restore(Network::Mainnet)
    }
}

/// The mock node's client with answers the recorded session does not cover: `get_outputs`
/// answers from `held`, and every height a page of unspent outputs reports is raised.
pub struct Rechecking {
    pub inner: NodeClient<MockNode>,
    pub held: Vec<OutputLocation>,
    pub raise_heights: u64,
}

impl NodeApi for Rechecking {
    fn get_version(&self) -> impl Future<Output = Result<NodeVersion, NodeError>> + Send {
        self.inner.get_version()
    }

    fn get_tip(&self) -> impl Future<Output = Result<Tip, NodeError>> + Send {
        self.inner.get_tip()
    }

    fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> impl Future<Output = Result<Option<LocatedKernel>, NodeError>> + Send {
        self.inner.get_kernel(excess, min_height, max_height)
    }

    fn get_outputs(
        &self,
        commitments: &[Commitment],
    ) -> impl Future<Output = Result<Vec<OutputLocation>, NodeError>> + Send {
        let held: Vec<OutputLocation> = self
            .held
            .iter()
            .filter(|location| commitments.contains(&location.commitment))
            .copied()
            .collect();
        std::future::ready(Ok(held))
    }

    fn get_unspent_outputs(
        &self,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> impl Future<Output = Result<UnspentOutputs, NodeError>> + Send {
        let answer = self.inner.get_unspent_outputs(start_index, end_index, max);
        let raise = self.raise_heights;
        async move {
            let mut page = answer.await?;
            for output in &mut page.outputs {
                output.height = Height::new(output.height.value() + raise);
            }
            Ok(page)
        }
    }

    fn get_pmmr_indices(
        &self,
        start_height: Height,
        end_height: Option<Height>,
    ) -> impl Future<Output = Result<PmmrIndices, NodeError>> + Send {
        self.inner.get_pmmr_indices(start_height, end_height)
    }

    fn push_transaction(
        &self,
        transaction: &Transaction,
        propagation: Propagation,
    ) -> impl Future<Output = Result<(), NodeError>> + Send {
        self.inner.push_transaction(transaction, propagation)
    }
}

/// A second, unlocked handle on the harness's restored wallet over a [`Rechecking`] node.
pub fn rechecking_wallet(
    harness: &Harness,
    held: Vec<OutputLocation>,
    raise_heights: u64,
) -> AnyWallet<Rechecking> {
    let ports = harness.ports(harness.vault.clone());
    let node = Rechecking {
        inner: ports.node,
        held,
        raise_heights,
    };
    let wallet = Wallet::new(
        harness.config(Network::Mainnet),
        Ports {
            node,
            stores: ports.stores,
            secrets: ports.secrets,
            transports: ports.transports,
            clock: ports.clock,
            rng: ports.rng,
            runtime: ports.runtime,
        },
    )
    .unwrap();
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();
    wallet
}

/// Where the node holds a stored output, as `get_outputs` reports it.
pub fn location(output: &OutputRecord) -> OutputLocation {
    OutputLocation {
        commitment: Commitment::from_bytes(output.commitment()).unwrap(),
        features: output.id.features,
        height: output.height,
        mmr_index: output.mmr_index.unwrap(),
    }
}

/// The harness's database, shared with every wallet handle on it.
pub fn store(harness: &Harness) -> MemoryStore {
    harness
        .stores
        .open(
            &harness.data_dir,
            ContextKey::from_bytes([0; CONTEXT_KEY_LEN]),
        )
        .unwrap()
}

/// Everything a scan may change, for comparing two runs.
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub accounts: Vec<AccountRecord>,
    pub outputs: Vec<OutputRecord>,
    pub transactions: Vec<StoredTransaction>,
    pub last_scanned: Option<String>,
    pub checkpoint: Option<String>,
}

pub fn snapshot(harness: &Harness) -> Snapshot {
    store(harness)
        .read(|repos| {
            let accounts = repos.accounts()?;
            let mut outputs = Vec::new();
            let mut transactions = Vec::new();
            for account in &accounts {
                outputs.extend(repos.outputs(account.index, None)?);
                transactions.extend(repos.transactions(account.index)?);
            }
            Ok::<_, StoreError>(Snapshot {
                accounts,
                outputs,
                transactions,
                last_scanned: repos.setting("scan.last_scanned")?,
                checkpoint: repos.setting("scan.checkpoint")?,
            })
        })
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

/// The LEPIC direction and state of an upstream entry a scan can produce, per
/// `docs/compat/states.md`.
fn transaction_state(tx_type: &str, confirmed: bool) -> (TxDirection, TxState) {
    match (tx_type, confirmed) {
        ("ConfirmedCoinbase" | "TxReceived", true) => (TxDirection::Incoming, TxState::Confirmed),
        ("TxReceived", false) => (TxDirection::Incoming, TxState::Received),
        (other, confirmed) => panic!("no mapping for {other} with confirmed = {confirmed}"),
    }
}

/// Asserts that the wallet holds exactly the outputs and transactions upstream ended with, and
/// the scanned position and key counter it recorded.
pub fn assert_matches_upstream<N: NodeApi + 'static>(
    harness: &Harness,
    wallet: &AnyWallet<N>,
    vector: &Value,
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
    assert_eq!(
        state.transactions.len(),
        expected_transactions.len(),
        "{name}: transactions"
    );
    let outputs: BTreeMap<String, &OutputRecord> = state
        .outputs
        .iter()
        .map(|output| (hex(output.commitment()), output))
        .collect();
    let mut linked = Vec::new();
    for expected in expected_outputs {
        let commit = expected["commit"].as_str().unwrap();
        let context = format!("{name}: output {commit}");
        let stored = outputs
            .get(commit)
            .unwrap_or_else(|| panic!("{context} missing"));
        assert_eq!(hex(&stored.key_id.0), expected["key_id"], "{context}");
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
            Some(number(&expected["mmr_index"])),
            "{context}"
        );
        assert_eq!(
            stored.account,
            AccountIndex(u32::from_str_radix(&key_account_hex(expected), 16).unwrap()),
            "{context}"
        );

        let tx_id = stored
            .tx
            .unwrap_or_else(|| panic!("{context} has no transaction"));
        let upstream = expected_transactions
            .iter()
            .find(|tx| tx["id"] == expected["tx_log_entry"])
            .unwrap_or_else(|| panic!("{context}: upstream entry missing"));
        let entry = &state
            .transactions
            .iter()
            .find(|tx| tx.id == tx_id)
            .unwrap_or_else(|| panic!("{context}: transaction {tx_id} missing"))
            .entry;
        let (direction, tx_state) = transaction_state(
            upstream["tx_type"].as_str().unwrap(),
            upstream["confirmed"].as_bool().unwrap(),
        );
        assert_eq!(entry.direction, direction, "{context}");
        assert_eq!(entry.state, tx_state, "{context}");
        assert_eq!(
            entry.amount_credited.value(),
            number(&upstream["amount_credited"]),
            "{context}"
        );
        assert_eq!(
            entry.amount_debited.value(),
            number(&upstream["amount_debited"]),
            "{context}"
        );
        assert_eq!(entry.fee.is_none(), upstream["fee"].is_null(), "{context}");
        assert_eq!(
            entry.slate_id.is_some(),
            upstream["has_slate_id"].as_bool().unwrap(),
            "{context}"
        );
        linked.push(tx_id);
    }
    linked.sort();
    linked.dedup();
    assert_eq!(
        linked.len(),
        expected_transactions.len(),
        "{name}: every transaction belongs to an output"
    );

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

    let scanned = wallet.last_scanned_block().unwrap();
    assert_eq!(after["init_status"], "InitComplete", "{name}");
    let expected_block = &after["last_scanned_block"];
    let ScannedBlock {
        height,
        hash,
        start_pmmr_index,
        last_pmmr_index,
    } = scanned.unwrap_or_else(|| panic!("{name}: no scanned block recorded"));
    assert_eq!(
        height,
        Height::new(number(&expected_block["height"])),
        "{name}"
    );
    assert_eq!(hash.to_hex(), expected_block["hash"], "{name}");
    assert_eq!(
        start_pmmr_index,
        number(&expected_block["start_pmmr_index"]),
        "{name}"
    );
    assert_eq!(
        last_pmmr_index,
        number(&expected_block["last_pmmr_index"]),
        "{name}"
    );
    assert!(state.checkpoint.is_none(), "{name}: checkpoint left behind");
    assert_eq!(harness.node.violations(), [], "{name}: replay violations");
}

/// The account component of the expected output's key id, which follows the depth byte.
fn key_account_hex(expected: &Value) -> String {
    expected["key_id"].as_str().unwrap()[2..10].to_owned()
}

/// Every output in the replayed session's UTXO listing, by commitment hex.
pub fn listed_commitments(vector: &Value) -> Vec<String> {
    vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|exchange| exchange["method"] == "get_unspent_outputs")
        .flat_map(|exchange| {
            exchange["response"]["result"]["Ok"]["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|output| output["commit"].as_str().unwrap().to_owned())
        })
        .collect()
}

/// Runs `operation` in one write transaction of the harness's database.
pub fn write<R>(
    harness: &Harness,
    operation: impl FnOnce(&mut dyn Repositories) -> Result<R, StoreError>,
) -> R {
    store(harness).write(operation).unwrap()
}
