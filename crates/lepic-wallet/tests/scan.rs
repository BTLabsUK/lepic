//! Scan and restore over the G-05 restore session: interruption and resume, cancellation,
//! repeated scans, progress events and the reconciliation of stored outputs.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod scan_support;
mod support;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lepic_crypto::Commitment;
use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, Keychain, LegacyProofBuilder, ProofBuilder, SwitchCommitment};
use lepic_node::mock::{ChainOutput, MockNode};
use lepic_node::{
    LocatedKernel, NodeApi, NodeClient, NodeError, NodeVersion, OutputLocation, PmmrIndices,
    Propagation, Tip, UnspentOutputs,
};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_primitives::tx::Transaction;
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, TransactionEntry, TxDirection, TxId, TxState,
};
use lepic_wallet::scan::{ScanCancel, ScanError, ScanOptions, ScanStart};
use lepic_wallet::{Event, Ports, Wallet, WalletError};
use scan_support::{PASSWORD, Snapshot, full_scan_vector, options, restore, snapshot, write};
use serde_json::Value;
use support::{Harness, MemoryStores, TestVault, fixed_time, password};
use tokio::sync::Notify;
use tokio::sync::broadcast::Receiver;

const SMALL_PAGE: NonZeroU64 = NonZeroU64::new(4).unwrap();

/// What happens on one `get_unspent_outputs` call, counted from 1.
#[derive(Clone, Copy)]
enum Disturbance {
    Fail(usize),
    Cancel(usize),
    /// The request never answers; [`DisturbedNode::hanging`] is notified when it starts.
    Hang(usize),
}

/// The mock node's client, disturbed on one `get_unspent_outputs` call: it fails as an
/// unresponsive node does, cancels the scan as it answers, or never answers.
struct DisturbedNode {
    inner: NodeClient<MockNode>,
    disturbance: Disturbance,
    cancel: ScanCancel,
    hanging: Arc<Notify>,
    unspent_calls: AtomicUsize,
}

impl NodeApi for DisturbedNode {
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
        self.inner.get_outputs(commitments)
    }

    fn get_unspent_outputs(
        &self,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> impl Future<Output = Result<UnspentOutputs, NodeError>> + Send {
        let call = self.unspent_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let fail = matches!(self.disturbance, Disturbance::Fail(at) if at == call);
        let hang = matches!(self.disturbance, Disturbance::Hang(at) if at == call);
        if matches!(self.disturbance, Disturbance::Cancel(at) if at == call) {
            self.cancel.cancel();
        }
        let answer = self.inner.get_unspent_outputs(start_index, end_index, max);
        let hanging = Arc::clone(&self.hanging);
        async move {
            if fail {
                return Err(NodeError::Timeout);
            }
            if hang {
                hanging.notify_one();
                std::future::pending::<()>().await;
            }
            answer.await
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

type DisturbedWallet = Wallet<DisturbedNode, MemoryStores, TestVault>;

fn disturbed_wallet(
    harness: &Harness,
    disturbance: Disturbance,
    cancel: &ScanCancel,
) -> DisturbedWallet {
    disturbed_wallet_notifying(harness, disturbance, cancel, &Arc::default())
}

fn disturbed_wallet_notifying(
    harness: &Harness,
    disturbance: Disturbance,
    cancel: &ScanCancel,
    hanging: &Arc<Notify>,
) -> DisturbedWallet {
    let Ports {
        node,
        stores,
        secrets,
        transports,
        clock,
        rng,
        runtime,
    } = harness.ports(harness.vault.clone());
    let node = DisturbedNode {
        inner: node,
        disturbance,
        cancel: cancel.clone(),
        hanging: Arc::clone(hanging),
        unspent_calls: AtomicUsize::new(0),
    };
    Wallet::new(
        harness.config(Network::Mainnet),
        Ports {
            node,
            stores,
            secrets,
            transports,
            clock,
            rng,
            runtime,
        },
    )
    .unwrap()
}

fn small_pages(vector: &Value) -> ScanOptions {
    ScanOptions {
        page_size: SMALL_PAGE,
        ..options(vector)
    }
}

/// The state an uninterrupted restore of the vector ends in.
fn uninterrupted(vector: &Value) -> Snapshot {
    let harness = scan_support::harness(vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, vector);
    harness
        .block_on(wallet.scan(small_pages(vector), &ScanCancel::new()))
        .unwrap();
    snapshot(&harness)
}

/// A harness with the subject restored and fully scanned.
fn scanned() -> (Harness, support::TestWallet, Value) {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    harness
        .block_on(wallet.scan(options(&vector), &ScanCancel::new()))
        .unwrap();
    (harness, wallet, vector)
}

/// `get_unspent_outputs` requests the mock node answered, over every wallet handle.
fn pages_served(harness: &Harness) -> usize {
    harness
        .node
        .calls()
        .iter()
        .filter(|method| *method == "get_unspent_outputs")
        .count()
}

/// Pages of [`SMALL_PAGE`] outputs in the session's listing.
fn small_page_count(vector: &Value) -> usize {
    scan_support::listed_commitments(vector).len().div_ceil(4)
}

fn drain(events: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| events.try_recv().ok()).collect()
}

fn output_by_child(harness: &Harness, child: u8) -> OutputRecord {
    snapshot(harness)
        .outputs
        .into_iter()
        .find(|output| {
            output.key_id.0[12] == child
                && output.key_id.0[..12] == [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        })
        .unwrap_or_else(|| panic!("no output with child {child}"))
}

fn open_transaction(harness: &Harness, direction: TxDirection, state: TxState) -> TxId {
    write(harness, |repos| {
        repos.insert_transaction(&TransactionEntry {
            account: AccountIndex(0),
            direction,
            state,
            slate_id: None,
            transport: None,
            amount_credited: Amount::ZERO,
            amount_debited: Amount::ZERO,
            fee: None,
            created_at: fixed_time(),
            updated_at: fixed_time(),
        })
    })
}

fn set_output(harness: &Harness, output: &OutputRecord) {
    write(harness, |repos| repos.put_output(output));
}

fn transaction_state(harness: &Harness, tx: TxId) -> TxState {
    snapshot(harness)
        .transactions
        .into_iter()
        .find(|stored| stored.id == tx)
        .unwrap()
        .entry
        .state
}

#[test]
fn restore_interrupted_by_a_node_failure_resumes_to_the_same_outputs() {
    let vector = full_scan_vector();
    let expected = uninterrupted(&vector);
    let harness = scan_support::harness(&vector);
    let cancel = ScanCancel::new();
    let wallet = disturbed_wallet(&harness, Disturbance::Fail(3), &cancel);
    restore(&harness, &wallet, &vector);

    let result = harness.block_on(wallet.scan(small_pages(&vector), &cancel));

    assert!(matches!(result, Err(ScanError::Node(NodeError::Timeout))));
    let partial = snapshot(&harness);
    assert!(!partial.outputs.is_empty(), "the first pages were stored");
    assert!(partial.outputs.len() < expected.outputs.len());
    assert!(partial.checkpoint.is_some());
    assert!(partial.last_scanned.is_none());
    wallet.close();

    // A new handle, as after the app was killed and started again.
    let wallet = harness.wallet();
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();
    let summary = harness
        .block_on(wallet.scan(small_pages(&vector), &ScanCancel::new()))
        .unwrap();

    assert!(summary.resumed);
    assert_eq!(
        pages_served(&harness),
        small_page_count(&vector),
        "no page fetched twice"
    );
    assert_eq!(
        summary.restored + partial.outputs.len() as u64,
        expected.outputs.len() as u64
    );
    assert_eq!(snapshot(&harness), expected);
    scan_support::assert_matches_upstream(&harness, &wallet, &vector, "resumed after failure");
}

#[test]
fn cancelled_restore_resumes_to_the_same_outputs() {
    let vector = full_scan_vector();
    let expected = uninterrupted(&vector);
    let harness = scan_support::harness(&vector);
    let cancel = ScanCancel::new();
    let wallet = disturbed_wallet(&harness, Disturbance::Cancel(2), &cancel);
    restore(&harness, &wallet, &vector);

    let result = harness.block_on(wallet.scan(small_pages(&vector), &cancel));

    assert!(matches!(result, Err(ScanError::Cancelled)));
    let partial = snapshot(&harness);
    assert!(!partial.outputs.is_empty());
    assert!(partial.outputs.len() < expected.outputs.len());
    assert!(partial.checkpoint.is_some());

    let summary = harness
        .block_on(wallet.scan(small_pages(&vector), &ScanCancel::new()))
        .unwrap();

    assert!(summary.resumed);
    assert_eq!(
        pages_served(&harness),
        small_page_count(&vector),
        "no page fetched twice"
    );
    assert_eq!(snapshot(&harness), expected);
    scan_support::assert_matches_upstream(&harness, &wallet, &vector, "resumed after cancel");
}

#[test]
fn page_size_does_not_change_what_a_restore_finds() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    let mut events = wallet.subscribe();

    harness
        .block_on(wallet.scan(small_pages(&vector), &ScanCancel::new()))
        .unwrap();

    scan_support::assert_matches_upstream(&harness, &wallet, &vector, "small pages");
    let pages = pages_served(&harness);
    assert_eq!(pages, small_page_count(&vector));
    let syncs = drain(&mut events)
        .into_iter()
        .filter(|event| matches!(event, Event::Sync(_)))
        .count();
    assert_eq!(syncs, pages + 2, "one start, one per page, one at the end");
}

#[test]
fn cancelling_before_the_scan_stores_nothing() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    let cancel = ScanCancel::new();
    cancel.cancel();

    let result = harness.block_on(wallet.scan(options(&vector), &cancel));

    assert!(matches!(result, Err(ScanError::Cancelled)));
    assert!(harness.node.calls().is_empty());
    let state = snapshot(&harness);
    assert!(state.outputs.is_empty());
    assert!(state.checkpoint.is_none());
}

#[test]
fn scan_of_a_locked_wallet_is_refused() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();

    let result = harness.block_on(wallet.scan(options(&vector), &ScanCancel::new()));

    assert!(matches!(
        result,
        Err(ScanError::Wallet(WalletError::Locked))
    ));
}

#[test]
fn update_scan_after_a_restore_changes_nothing() {
    let (harness, wallet, vector) = scanned();
    let before = snapshot(&harness);
    let mut events = wallet.subscribe();

    let summary = harness
        .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    assert_eq!(
        summary.start_height,
        Height::ZERO,
        "14 - 100 saturates at 0"
    );
    assert_eq!(summary.found, 4);
    assert_eq!(summary.restored, 0);
    assert_eq!(snapshot(&harness), before);
    let events = drain(&mut events);
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, Event::Transaction(_)))
    );
    scan_support::assert_matches_upstream(&harness, &wallet, &vector, "update scan");
}

#[test]
fn progress_starts_at_the_start_height_and_ends_at_the_tip() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    let mut events = wallet.subscribe();

    harness
        .block_on(wallet.scan(small_pages(&vector), &ScanCancel::new()))
        .unwrap();

    let progress: Vec<(u64, u64)> = drain(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::Sync(sync) => Some((sync.height.value(), sync.target.value())),
            _ => None,
        })
        .collect();
    assert_eq!(progress.first(), Some(&(0, 14)));
    assert_eq!(progress.last(), Some(&(14, 14)));
    assert!(progress.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    assert!(progress.iter().all(|&(_, target)| target == 14));
}

#[test]
fn start_above_the_tip_changes_nothing() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);

    let summary = harness
        .block_on(wallet.scan(
            ScanOptions {
                start: ScanStart::Height(Height::new(15)),
                ..options(&vector)
            },
            &ScanCancel::new(),
        ))
        .unwrap();

    assert_eq!(summary.found, 0);
    assert_eq!(harness.node.calls(), ["get_tip"]);
    assert!(snapshot(&harness).last_scanned.is_none());
}

#[test]
fn spent_output_found_unspent_is_revived_and_its_transaction_cancelled() {
    let (harness, wallet, _) = scanned();
    let spending = open_transaction(&harness, TxDirection::Outgoing, TxState::Posted);
    let mut output = output_by_child(&harness, 3);
    let original = output.clone();
    output.status = OutputStatus::Spent;
    output.tx = Some(spending);
    output.mmr_index = None;
    set_output(&harness, &output);
    wallet.close();
    let wallet =
        scan_support::rechecking_wallet(&harness, vec![scan_support::location(&original)], 0);
    let mut events = wallet.subscribe();

    let summary = harness
        .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    assert_eq!(summary.revived, 1);
    let revived = output_by_child(&harness, 3);
    assert_eq!(revived.status, OutputStatus::Unspent);
    assert_eq!(revived.mmr_index, original.mmr_index);
    assert_eq!(transaction_state(&harness, spending), TxState::Cancelled);
    assert!(drain(&mut events).iter().any(|event| matches!(
        event,
        Event::Transaction(change) if change.tx_id == spending && change.to == TxState::Cancelled
    )));
}

#[test]
fn revived_output_of_a_confirmed_transaction_leaves_it_confirmed() {
    let (harness, wallet, _) = scanned();
    let mut output = output_by_child(&harness, 0);
    let confirmed = output.tx.unwrap();
    let held = scan_support::location(&output);
    output.status = OutputStatus::Spent;
    set_output(&harness, &output);
    wallet.close();
    let wallet = scan_support::rechecking_wallet(&harness, vec![held], 0);

    harness
        .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    assert_eq!(output_by_child(&harness, 0).status, OutputStatus::Unspent);
    assert_eq!(transaction_state(&harness, confirmed), TxState::Confirmed);
}

/// An output of this wallet the chain does not hold: key `m/0/0/9`, under a commitment from the
/// session's UTXO listing that belongs to another wallet.
fn unconfirmed_output(harness: &Harness, vector: &Value, tx: TxId) -> OutputRecord {
    let owned: Vec<String> = snapshot(harness)
        .outputs
        .iter()
        .map(|output| {
            Commitment::from_bytes(output.commitment())
                .unwrap()
                .to_hex()
        })
        .collect();
    let foreign = scan_support::listed_commitments(vector)
        .into_iter()
        .find(|commit| !owned.contains(commit))
        .unwrap();
    let mut key_id = [0u8; 17];
    key_id[0] = 3;
    key_id[12] = 9;
    OutputRecord {
        id: OutputIdentifier::new(
            OutputFeatures::Plain,
            Commitment::from_hex(&foreign).unwrap(),
        ),
        key_id: KeyId(key_id),
        account: AccountIndex(0),
        amount: Amount::new(5),
        status: OutputStatus::Unconfirmed,
        height: Height::new(14),
        lock_height: Height::new(14),
        mmr_index: None,
        tx: Some(tx),
    }
}

#[test]
fn locked_and_unconfirmed_outputs_change_only_with_delete_unconfirmed() {
    let (harness, wallet, vector) = scanned();
    let sending = open_transaction(&harness, TxDirection::Outgoing, TxState::Sent);
    let receiving = open_transaction(&harness, TxDirection::Incoming, TxState::Received);
    let mut locked = output_by_child(&harness, 5);
    locked.status = OutputStatus::Locked;
    locked.tx = Some(sending);
    set_output(&harness, &locked);
    let unconfirmed = unconfirmed_output(&harness, &vector, receiving);
    set_output(&harness, &unconfirmed);
    let before = snapshot(&harness);

    let update = ScanOptions::update(Network::Mainnet);
    harness
        .block_on(wallet.scan(update, &ScanCancel::new()))
        .unwrap();

    assert_eq!(
        snapshot(&harness),
        before,
        "a plain update leaves both alone"
    );

    let summary = harness
        .block_on(wallet.scan(
            ScanOptions {
                delete_unconfirmed: true,
                ..update
            },
            &ScanCancel::new(),
        ))
        .unwrap();

    assert_eq!((summary.unlocked, summary.deleted), (1, 1));
    assert_eq!(output_by_child(&harness, 5).status, OutputStatus::Unspent);
    assert_eq!(transaction_state(&harness, sending), TxState::Cancelled);
    assert_eq!(transaction_state(&harness, receiving), TxState::Cancelled);
    assert!(
        snapshot(&harness)
            .outputs
            .iter()
            .all(|output| output.commitment() != unconfirmed.commitment())
    );
}

/// Partial state of a restore whose page `page` failed: every earlier page stored.
fn restore_failing_at(vector: &Value, page: usize) -> Snapshot {
    let harness = scan_support::harness(vector);
    let cancel = ScanCancel::new();
    let wallet = disturbed_wallet(&harness, Disturbance::Fail(page), &cancel);
    restore(&harness, &wallet, vector);
    let result = harness.block_on(wallet.scan(small_pages(vector), &cancel));
    assert!(matches!(result, Err(ScanError::Node(NodeError::Timeout))));
    snapshot(&harness)
}

#[test]
fn cancel_abandons_a_node_request_that_never_answers() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let cancel = ScanCancel::new();
    let hanging = Arc::new(Notify::new());
    let wallet = disturbed_wallet_notifying(&harness, Disturbance::Hang(3), &cancel, &hanging);
    restore(&harness, &wallet, &vector);

    // After the cancel the scan gets a bounded number of polls, so a scan that ignores it fails
    // the test instead of hanging it.
    let result = harness.block_on(async {
        tokio::select! {
            result = wallet.scan(small_pages(&vector), &cancel) => Some(result),
            () = async {
                hanging.notified().await;
                cancel.cancel();
                for _ in 0..100 {
                    tokio::task::yield_now().await;
                }
            } => None,
        }
    });

    assert!(
        matches!(result, Some(Err(ScanError::Cancelled))),
        "scan did not return on cancel: {result:?}"
    );
    assert_eq!(
        pages_served(&harness),
        2,
        "the hanging request never completed"
    );
    let partial = snapshot(&harness);
    assert_eq!(
        partial,
        restore_failing_at(&vector, 3),
        "pages 1 and 2 stored, the checkpoint after page 2"
    );
    assert!(partial.checkpoint.is_some());
}

/// The scanned subject with output `m/0/0/0` locked by an open send.
fn locked_by_a_send() -> (Harness, support::TestWallet, TxId) {
    let (harness, wallet, _) = scanned();
    let sending = open_transaction(&harness, TxDirection::Outgoing, TxState::Sent);
    let mut locked = output_by_child(&harness, 0);
    locked.status = OutputStatus::Locked;
    locked.tx = Some(sending);
    set_output(&harness, &locked);
    (harness, wallet, sending)
}

fn small_page_repair() -> ScanOptions {
    ScanOptions {
        delete_unconfirmed: true,
        page_size: SMALL_PAGE,
        ..ScanOptions::update(Network::Mainnet)
    }
}

#[test]
fn repair_scan_does_not_resume_an_interrupted_plain_scan() {
    let expected = {
        let (harness, wallet, sending) = locked_by_a_send();
        let summary = harness
            .block_on(wallet.scan(small_page_repair(), &ScanCancel::new()))
            .unwrap();
        assert_eq!(summary.unlocked, 1);
        assert_eq!(transaction_state(&harness, sending), TxState::Cancelled);
        snapshot(&harness)
    };
    for failing_page in 2..=5 {
        let (harness, wallet, sending) = locked_by_a_send();
        wallet.close();
        let cancel = ScanCancel::new();
        let plain = disturbed_wallet(&harness, Disturbance::Fail(failing_page), &cancel);
        harness.block_on(plain.open(password(PASSWORD))).unwrap();
        let plain_scan = ScanOptions {
            delete_unconfirmed: false,
            ..small_page_repair()
        };
        let result = harness.block_on(plain.scan(plain_scan, &cancel));
        assert!(
            matches!(result, Err(ScanError::Node(_))),
            "page {failing_page}"
        );
        assert!(
            snapshot(&harness).checkpoint.is_some(),
            "page {failing_page}"
        );
        plain.close();

        let wallet = harness.wallet();
        harness.block_on(wallet.open(password(PASSWORD))).unwrap();
        let summary = harness
            .block_on(wallet.scan(small_page_repair(), &ScanCancel::new()))
            .unwrap();

        assert!(!summary.resumed, "page {failing_page}");
        assert_eq!(summary.unlocked, 1, "page {failing_page}");
        assert_eq!(transaction_state(&harness, sending), TxState::Cancelled);
        assert_eq!(snapshot(&harness), expected, "page {failing_page}");
    }
}

/// One output of the subject on a chain the mock node scripts.
fn chain_output(
    keychain: &Keychain,
    key_id: Identifier,
    amount: u64,
    legacy: bool,
    mmr_index: u64,
) -> ChainOutput {
    let output = if legacy {
        create_output(
            keychain,
            &LegacyProofBuilder::new(keychain).unwrap(),
            amount,
            &key_id,
            SwitchCommitment::Regular,
        )
    } else {
        create_output(
            keychain,
            &ProofBuilder::new(keychain).unwrap(),
            amount,
            &key_id,
            SwitchCommitment::Regular,
        )
    }
    .unwrap();
    ChainOutput {
        commitment: output.commitment,
        features: output.features,
        proof: output.proof,
        height: Height::new(mmr_index),
        mmr_index,
        spent: false,
    }
}

#[test]
fn restore_finds_outputs_on_every_path_the_proofs_rewind_to() {
    let vector = full_scan_vector();
    let phrase = vector["inputs"]["subject"]["mnemonic"].as_str().unwrap();
    let keychain = Keychain::from_mnemonic(phrase, Network::Mainnet).unwrap();
    let hardened = 1u32 << 31;
    let key = |depth, components| Identifier::new(depth, components).unwrap();
    // (key, amount, legacy proof, account it is stored under)
    let cases = [
        (key(3, [2, 0, 3, 0]), 11, false, AccountIndex(2)),
        (key(3, [0, 1, 4, 0]), 12, true, AccountIndex(0)),
        (key(4, [0, 0, 1, 2]), 13, false, AccountIndex(0)),
        (key(3, [0, 0, hardened + 1, 0]), 14, false, AccountIndex(0)),
        (
            key(3, [hardened, 0, 1, 0]),
            15,
            false,
            AccountIndex(hardened),
        ),
        (key(2, [6, 0, 0, 0]), 16, false, AccountIndex(0)),
    ];
    let chain = support::mock_node();
    chain.update_chain(|state| {
        state.outputs = cases
            .iter()
            .zip(1..)
            .map(|((key_id, amount, legacy, _), index)| {
                chain_output(&keychain, *key_id, *amount, *legacy, index)
            })
            .collect();
    });
    let mut harness = Harness::new();
    harness.node = chain;
    let wallet = harness.wallet();
    harness
        .block_on(wallet.restore(password(PASSWORD), phrase))
        .unwrap();

    let summary = harness
        .block_on(wallet.scan(ScanOptions::restore(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    assert_eq!(summary.restored, cases.len() as u64);
    let state = snapshot(&harness);
    assert_eq!(state.outputs.len(), cases.len());
    for (key_id, amount, _, account) in &cases {
        let stored = state
            .outputs
            .iter()
            .find(|output| output.key_id == KeyId(key_id.to_bytes()))
            .unwrap_or_else(|| panic!("output at {key_id:?} not restored"));
        assert_eq!(stored.account, *account, "{key_id:?}");
        assert_eq!(stored.amount, Amount::new(*amount), "{key_id:?}");
        assert_eq!(stored.status, OutputStatus::Unspent, "{key_id:?}");
        let tx = state
            .transactions
            .iter()
            .find(|tx| Some(tx.id) == stored.tx)
            .unwrap();
        assert_eq!(
            (tx.entry.direction, tx.entry.state, tx.entry.account),
            (TxDirection::Incoming, TxState::Confirmed, *account)
        );
    }
    let accounts: Vec<(u32, &str, u32)> = state
        .accounts
        .iter()
        .map(|account| (account.index.0, account.label.as_str(), account.next_child))
        .collect();
    assert_eq!(
        accounts,
        [
            (0, "default", 0),
            (2, "account_1", 4),
            (hardened, "account_2", 2),
        ],
        "accounts of the parent paths, counters past their restored children"
    );
    assert_eq!(harness.node.violations(), []);
}
