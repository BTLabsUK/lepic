// SPDX-License-Identifier: Apache-2.0
//! The watch of a send that ended unconfirmed: one an earlier version released, seeded here
//! as that version stored it, and one cancelled too late. A refresh or scan that finds it
//! mined confirms it and stores its change again.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::receive_harness;
use crate::send_support;
use crate::support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use jiff::{SignedDuration, Timestamp};
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, NodeError, Propagation, RejectionKind};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::Transaction;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::Slate;
use lepic_store::{
    AccountRecord, OutputRecord, OutputStatus, SlateStage, StoreError, TxId, TxState, TxWatch,
    WalletStore, WatchPhase, WatchedOutput,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::event::TransactionState;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::{DEFAULT_MINIMUM_CONFIRMATIONS, RefreshOutcome};
use lepic_wallet::release::RELEASED_WATCH_BLOCKS;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Clock, Event, Ports, StoreOpener, Wallet, WalletError};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, TIP, context_key, output};
use support::both_stores;
use support::{Harness, TestStore, TestStores, TestVault, TestWallet, fixed_time, password};

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// A day of blocks: the most a node client accepts the tip to move at once.
const DAY: u64 = 1_440;

/// The tip an earlier version released a send finalized at [`TIP`] at: a day of blocks later,
/// the first height its release check allowed.
const RELEASED_AT: u64 = TIP + DAY;

/// A clock the test moves forward, so a tip a day of blocks later is plausible.
#[derive(Clone)]
struct MovableClock(Arc<Mutex<Timestamp>>);

impl MovableClock {
    fn advance(&self, by: SignedDuration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.checked_add(by).unwrap();
    }
}

impl Clock for MovableClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A range proof of the right size. The mock chain serves `get_outputs` without proofs, so any
/// one will do for an output that only a refresh asks about.
fn some_proof() -> lepic_crypto::RangeProof {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/primitives/tx_valid_plain_1_in_2_out.json");
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = vector["expected"]["serialized_v2"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    Transaction::decode(&bytes, ProtocolVersion::V2)
        .unwrap()
        .outputs()[0]
        .proof
        .clone()
}

/// The funded `send_file_plain` sender, its coinbase input on the mock chain, with a send to
/// the peer answered.
struct Releasing {
    harness: Harness,
    peer: lepic_transport::loopback::LoopbackTransport,
    clock: MovableClock,
    wallet: TestWallet,
    store: TestStore,
    tx_id: TxId,
    funding: OutputRecord,
    s2: WireSlate,
}

impl Releasing {
    /// A send the node accepted, now `posted`.
    fn posted() -> Self {
        let releasing = Self::answered();
        releasing.finalize().unwrap();
        assert_eq!(releasing.state(), TxState::Posted);
        releasing
    }

    /// A send the node refused, now `finalized`. The node goes on refusing it, so a refresh
    /// does not post it either.
    fn refused() -> Self {
        let releasing = Self::answered();
        releasing.harness.node.fail_every(
            "push_transaction",
            MockFailure::Rejected(RejectionKind::Internal),
        );
        let error = releasing.finalize().unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        assert_eq!(releasing.state(), TxState::Finalized);
        releasing
    }

    fn answered() -> Self {
        let harness = Harness::new();
        let clock = MovableClock(Arc::new(Mutex::new(fixed_time())));
        let ports: Ports<_, TestStores, TestVault> = Ports {
            clock: Arc::new(clock.clone()),
            ..harness.ports(TestVault::default())
        };
        let wallet = Wallet::new(harness.config(Network::Floonet), ports).unwrap();
        harness
            .block_on(wallet.restore(password("sender"), SENDER_MNEMONIC))
            .unwrap();
        harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(TIP));
        support::complete_restore_scan(&harness.runtime, &wallet);
        let seed = lepic_keychain::Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = harness
            .stores
            .open(
                &harness.data_dir,
                context_key(&seed),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap();
        let keychain = lepic_keychain::Keychain::from_seed(&seed, Network::Floonet).unwrap();
        let funding = output(&keychain, 0, FUNDING, OutputFeatures::Coinbase);
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: ACCOUNT,
                    label: "default".to_owned(),
                    next_child: NEXT_CHILD,
                })?;
                repos.put_output(&funding)
            })
            .unwrap();
        harness.node.update_chain(|chain| {
            crate::support::mine_output(
                chain,
                ChainOutput {
                    commitment: funding.id.commitment,
                    features: OutputFeatures::Coinbase,
                    proof: some_proof(),
                    height: Height::new(1),
                    mmr_index: 1,
                    spent: false,
                },
            );
        });

        let sent = harness
            .block_on(wallet.send(
                &harness.method(),
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap();
        let peer = harness.peer.lock().unwrap().take().unwrap();
        let s1 = harness
            .block_on(peer.next_envelope())
            .unwrap()
            .unwrap()
            .wire()
            .clone();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;
        Self {
            peer,
            harness,
            clock,
            wallet,
            store,
            tx_id: sent.tx_id,
            funding,
            s2,
        }
    }

    fn finalize(&self) -> Result<lepic_wallet::Finalized, FinalizeError> {
        self.harness.block_on(self.wallet.finalize(
            &self.harness.method(),
            &self.s2,
            Propagation::Stem,
        ))
    }

    fn state(&self) -> TxState {
        self.store
            .read(|repos| Ok::<_, StoreError>(repos.transaction(self.tx_id)?.unwrap().state))
            .unwrap()
    }

    fn outputs(&self) -> Vec<OutputRecord> {
        self.store
            .read(|repos| repos.outputs(ACCOUNT, None))
            .unwrap()
    }

    fn final_slate(&self) -> Slate {
        let stored = self
            .store
            .read(|repos| {
                let entry = repos.transaction(self.tx_id)?.unwrap();
                repos.slate(entry.slate_id.unwrap(), SlateStage::Standard3)
            })
            .unwrap()
            .unwrap();
        send_support::legacy_codecs()
            .decode(&WireSlate::binary(
                lepic_slate::codec::MediaType::JSON,
                stored.bytes,
            ))
            .unwrap()
    }

    /// The node's tip moves to `height`, a day and an hour later by the clock.
    fn chain_reaches(&self, height: u64) {
        self.clock.advance(SignedDuration::from_hours(25));
        self.harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(height));
    }

    /// Refreshes until the tip is confirmed: the first refresh after a long jump holds the tip
    /// as pending, the second at the same tip confirms it.
    fn refresh_twice(&self) {
        self.refresh();
        self.refresh();
    }

    fn refresh(&self) {
        let outcome = self.harness.block_on(self.wallet.refresh()).unwrap();
        assert!(
            matches!(outcome, RefreshOutcome::Refreshed(_)),
            "{outcome:?}"
        );
    }

    /// The send as an earlier version left it when it released it at [`RELEASED_AT`]:
    /// cancelled, its input unlocked, its change dropped and kept in a watch of the kernel, and
    /// the release marks stored.
    fn released_by_an_earlier_version(self) -> Self {
        self.chain_reaches(RELEASED_AT);
        self.refresh_twice();
        let slate = self.final_slate();
        let excess = *slate.kernel().unwrap().excess.as_bytes();
        let min_height = slate.height();
        let tx_id = self.tx_id;
        self.store
            .write(|repos| {
                let mut watched = Vec::new();
                for output in repos.outputs_of_transaction(tx_id)? {
                    match output.status {
                        OutputStatus::Unconfirmed => {
                            watched.push(WatchedOutput {
                                commitment: *output.commitment(),
                                key_id: output.key_id,
                                amount: output.amount,
                            });
                            repos.delete_output(output.commitment())?;
                        }
                        OutputStatus::Locked => repos.put_output(&OutputRecord {
                            status: OutputStatus::Unspent,
                            ..output
                        })?,
                        OutputStatus::Unspent | OutputStatus::Spent => {}
                    }
                }
                repos.put_tx_watch(
                    tx_id,
                    &TxWatch {
                        phase: WatchPhase::Kernel,
                        excess,
                        min_height,
                        ended_at: Height::new(RELEASED_AT),
                        outputs: watched,
                    },
                )?;
                let mut marks = repos.tx_marks(tx_id)?;
                marks.kernel_absent_at = Some(Height::new(RELEASED_AT));
                repos.put_tx_marks(tx_id, &marks)?;
                let mut entry = repos.transaction(tx_id)?.unwrap();
                entry.state = TxState::Cancelled;
                repos.update_transaction(tx_id, &entry)
            })
            .unwrap();
        self
    }

    fn kernel_at(&self, height: u64) -> LocatedKernel {
        LocatedKernel {
            kernel: self.final_slate().kernel().unwrap(),
            height: Height::new(height),
            mmr_index: 9,
        }
    }

    /// Nothing changed: the send keeps its state, its input stays locked, its change stays.
    fn assert_untouched(&self, state: TxState, outputs: &[OutputRecord]) {
        assert_eq!(self.state(), state);
        assert_eq!(self.outputs(), outputs);
    }
}

fn transaction_events(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
) -> Vec<(TxState, TxState)> {
    let mut changes = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(TransactionState { from, to, .. }) = event {
            changes.push((from, to));
        }
    }
    changes
}

impl Releasing {
    /// Another node held the transaction and a miner included it at `height` after all: its
    /// inputs are spent, its outputs and kernel are on chain.
    fn mined_elsewhere_at(&self, height: u64) {
        let pushed = self.harness.node.pushed_transactions();
        let mined = self.kernel_at(height);
        self.harness.node.update_chain(|chain| {
            let transaction = &pushed[0];
            for output in &mut chain.outputs {
                if transaction
                    .inputs()
                    .iter()
                    .any(|input| input.commitment == output.commitment)
                {
                    output.spent = true;
                }
            }
            for (position, output) in transaction.outputs().iter().enumerate() {
                crate::support::mine_output(
                    chain,
                    ChainOutput {
                        commitment: output.commitment,
                        features: output.features,
                        proof: output.proof.clone(),
                        height: Height::new(height),
                        mmr_index: 2 + position as u64,
                        spent: false,
                    },
                );
            }
            chain.kernels.push(mined);
        });
    }

    fn change(&self) -> Vec<OutputRecord> {
        self.outputs()
            .into_iter()
            .filter(|output| output.id != self.funding.id)
            .collect()
    }

    fn balance(&self) -> lepic_wallet::event::Balance {
        self.wallet.balance(ACCOUNT).unwrap()
    }

    fn kernel_lookups_by_one_refresh(&self) -> usize {
        let before = self.harness.node.calls().len();
        self.refresh();
        self.harness.node.calls()[before..]
            .iter()
            .filter(|method| *method == "get_kernel")
            .count()
    }
}

both_stores!(a_released_send_mined_inside_the_watch_is_confirmed_and_its_change_returns);
fn a_released_send_mined_inside_the_watch_is_confirmed_and_its_change_returns() {
    let releasing = Releasing::posted();
    let change_before = releasing.change();
    assert_eq!(change_before.len(), 1);
    let releasing = releasing.released_by_an_earlier_version();
    assert!(
        releasing.change().is_empty(),
        "the release dropped the change"
    );
    releasing.mined_elsewhere_at(RELEASED_AT);
    let mut events = releasing.wallet.subscribe();

    releasing.refresh();

    assert_eq!(releasing.state(), TxState::Confirmed);
    assert_eq!(
        transaction_events(&mut events),
        vec![(TxState::Cancelled, TxState::Confirmed)]
    );
    let details = releasing
        .harness
        .block_on(releasing.wallet.transaction_details(releasing.tx_id))
        .unwrap();
    assert_eq!(details.confirmed_height, Some(Height::new(RELEASED_AT)));
    let change = releasing.change();
    assert_eq!(change.len(), 1, "the refresh stores the change again");
    assert_eq!(change[0].id, change_before[0].id);
    assert_eq!(change[0].key_id, change_before[0].key_id);
    assert_eq!(change[0].amount, change_before[0].amount);
    assert_eq!(change[0].status, OutputStatus::Unspent);
    assert_eq!(change[0].height, Height::new(RELEASED_AT));
    let funding = releasing
        .outputs()
        .into_iter()
        .find(|output| output.id == releasing.funding.id)
        .unwrap();
    assert_eq!(funding.status, OutputStatus::Spent);
    let amount = change_before[0].amount;
    let balance = releasing.balance();
    assert_eq!(
        (balance.awaiting_confirmation, balance.spendable),
        (amount, Amount::ZERO)
    );

    // Spendable once it has its confirmations.
    let confirmed_from = RELEASED_AT + DEFAULT_MINIMUM_CONFIRMATIONS - 1;
    releasing.chain_reaches(confirmed_from);
    releasing.refresh();
    let balance = releasing.balance();
    assert_eq!(balance.height, Height::new(confirmed_from));
    assert_eq!(
        (balance.spendable, balance.awaiting_confirmation),
        (amount, Amount::ZERO)
    );
    assert_eq!(releasing.state(), TxState::Confirmed);

    // A scan finds nothing the refresh did not already store.
    support::complete_restore_scan(&releasing.harness.runtime, &releasing.wallet);

    assert_eq!(releasing.balance(), balance);
    assert_eq!(releasing.change().len(), 1);
    assert_eq!(releasing.state(), TxState::Confirmed);
}

both_stores!(a_released_send_mined_after_the_kernel_watch_is_found_by_its_change);
fn a_released_send_mined_after_the_kernel_watch_is_found_by_its_change() {
    let releasing = Releasing::posted();
    let change_before = releasing.change();
    let releasing = releasing.released_by_an_earlier_version();
    assert_eq!(
        releasing.kernel_lookups_by_one_refresh(),
        1,
        "a refresh inside the watch looks the kernel up"
    );
    let watched_until = RELEASED_AT + RELEASED_WATCH_BLOCKS;
    releasing.mined_elsewhere_at(watched_until + 1);

    // A node client accepts a day of blocks at once, so the chain gets there a day at a time.
    let mut height = RELEASED_AT;
    while height <= watched_until {
        height = (height + DAY).min(watched_until + 1);
        releasing.chain_reaches(height);
        releasing.refresh_twice();
    }

    assert_eq!(
        releasing.kernel_lookups_by_one_refresh(),
        0,
        "the kernel watch has ended"
    );
    assert_eq!(releasing.state(), TxState::Confirmed);
    let change = releasing.change();
    assert_eq!(change.len(), 1, "the refresh restores the change");
    assert_eq!(change[0].id, change_before[0].id);
    assert_eq!(change[0].amount, change_before[0].amount);
    assert_eq!(change[0].status, OutputStatus::Unspent);
}

impl Releasing {
    /// The node methods called while `operation` runs, in order, among those that look a
    /// kernel up or read the tip.
    fn lookups_during<R>(&self, operation: impl FnOnce() -> R) -> (R, Vec<String>) {
        let before = self.harness.node.calls().len();
        let result = operation();
        let calls = self.harness.node.calls()[before..]
            .iter()
            .filter(|method| {
                ["get_unconfirmed_transactions", "get_tip", "get_kernel"].contains(&method.as_str())
            })
            .cloned()
            .collect();
        (result, calls)
    }

    fn cancel(&self) -> Result<(), WalletError> {
        self.harness.block_on(self.wallet.cancel(self.tx_id))
    }

    fn history(&self) -> Vec<lepic_wallet::details::TransactionDetails> {
        self.harness
            .block_on(self.wallet.transactions(ACCOUNT))
            .unwrap()
    }
}

both_stores!(cancel_asks_the_node_pool_before_its_chain);
fn cancel_asks_the_node_pool_before_its_chain() {
    let releasing = Releasing::refused();

    let (result, calls) = releasing.lookups_during(|| releasing.cancel());

    result.unwrap();
    assert_eq!(
        calls,
        ["get_unconfirmed_transactions", "get_tip", "get_kernel"]
    );
}

both_stores!(refuses_a_cancel_when_the_node_pool_cannot_be_asked);
fn refuses_a_cancel_when_the_node_pool_cannot_be_asked() {
    let releasing = Releasing::refused();
    let outputs = releasing.outputs();
    assert!(
        outputs
            .iter()
            .any(|output| output.status == OutputStatus::Locked),
        "the send holds a locked input"
    );
    releasing
        .harness
        .node
        .fail_next("get_unconfirmed_transactions", MockFailure::Unreachable);

    let error = releasing.cancel().unwrap_err();

    assert!(
        matches!(error, WalletError::Node(NodeError::Connect(_))),
        "{error:?}"
    );
    releasing.assert_untouched(TxState::Finalized, &outputs);
}

both_stores!(a_late_confirmation_takes_over_the_change_a_scan_restored_first);
/// A scan of an earlier version stored the change of the released send under an entry of its
/// own, as a scan does for an output no record explains; a scan now confirms the send instead.
fn a_late_confirmation_takes_over_the_change_a_scan_restored_first() {
    let releasing = Releasing::posted();
    let change_before = releasing.change();
    let releasing = releasing.released_by_an_earlier_version();
    releasing.mined_elsewhere_at(RELEASED_AT);
    let sends = releasing.history().len();
    releasing
        .store
        .write(|repos| {
            let change = &change_before[0];
            let found = repos.insert_transaction(&lepic_store::TransactionEntry {
                account: ACCOUNT,
                direction: lepic_store::TxDirection::Incoming,
                state: TxState::Confirmed,
                slate_id: None,
                transport: None,
                amount_credited: change.amount,
                amount_debited: Amount::ZERO,
                fee: None,
                created_at: fixed_time(),
                updated_at: fixed_time(),
            })?;
            repos.set_confirmed_height(found, Height::new(RELEASED_AT))?;
            repos.put_scan_found(
                found,
                &lepic_store::ScanFoundRecord {
                    output: Some(*change.commitment()),
                    during: Some(lepic_store::FoundDuring::Rescan),
                    dated_by_block: false,
                },
            )?;
            repos.put_output(&OutputRecord {
                status: OutputStatus::Unspent,
                height: Height::new(RELEASED_AT),
                tx: Some(found),
                ..change.clone()
            })
        })
        .unwrap();
    let restored = releasing.change();
    assert_eq!(restored.len(), 1, "the scan restores the change");
    assert_ne!(restored[0].tx, Some(releasing.tx_id));
    assert_eq!(
        releasing.history().len(),
        sends + 1,
        "under an entry of its own"
    );
    let found_tx = restored[0].tx.unwrap();
    let found = |tx_id| {
        releasing
            .store
            .read(|repos| repos.scan_found(tx_id))
            .unwrap()
    };
    assert!(
        found(found_tx).is_some(),
        "the scan recorded how it found it"
    );

    releasing.refresh();

    assert_eq!(releasing.state(), TxState::Confirmed);
    let change = releasing.change();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].id, change_before[0].id);
    assert_eq!(change[0].tx, Some(releasing.tx_id));
    assert_eq!(change[0].status, OutputStatus::Unspent);
    let history = releasing.history();
    assert_eq!(history.len(), sends, "the restored entry is dropped");
    assert_eq!(found(found_tx), None, "with what the scan recorded of it");
    let credited: u64 = history
        .iter()
        .map(|details| details.transaction.entry.amount_credited.value())
        .sum();
    assert_eq!(credited, change_before[0].amount.value(), "counted once");
}

both_stores!(a_released_send_mined_late_debits_its_input_once);
/// A released send mined after its input was linked to something else is not also counted
/// as a spend by another wallet: the input leaves the history once, in the send.
fn a_released_send_mined_late_debits_its_input_once() {
    let releasing = Releasing::posted().released_by_an_earlier_version();
    releasing
        .store
        .write(|repos| {
            let mut input = repos.output(releasing.funding.commitment())?.unwrap();
            input.tx = None;
            repos.put_output(&input)
        })
        .unwrap();
    let sends = releasing.history().len();
    releasing.mined_elsewhere_at(RELEASED_AT);

    releasing.refresh();

    assert_eq!(releasing.state(), TxState::Confirmed);
    let history = releasing.history();
    assert_eq!(history.len(), sends, "no entry of another wallet's spend");
    let debited: u64 = history
        .iter()
        .map(|details| details.transaction.entry.amount_debited.value())
        .sum();
    assert_eq!(debited, releasing.funding.amount.value(), "debited once");
}

both_stores!(a_tip_held_as_pending_does_not_end_the_watch);
fn a_tip_held_as_pending_does_not_end_the_watch() {
    let releasing = Releasing::posted().released_by_an_earlier_version();
    let watched_until = RELEASED_AT + RELEASED_WATCH_BLOCKS;
    let confirmed = watched_until - 100;
    let mut height = RELEASED_AT;
    while height < confirmed {
        height = (height + DAY).min(confirmed);
        releasing.chain_reaches(height);
        releasing.refresh_twice();
    }
    // One answer past the window, too far ahead of the confirmed tip to be confirmed by itself.
    releasing
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(watched_until + 10));
    releasing.refresh();
    assert_eq!(releasing.state(), TxState::Cancelled);

    // The chain was where the wallet confirmed it, and the send is mined there.
    releasing
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(confirmed));
    releasing.mined_elsewhere_at(confirmed);
    releasing.refresh();

    assert_eq!(releasing.state(), TxState::Confirmed);
}

both_stores!(a_send_an_earlier_version_released_still_loads_and_stays_watched);
/// The marks an earlier version stored with a release still load: the send's details read, a
/// refresh runs and looks its kernel up, and the send stays cancelled while the kernel is not
/// on chain.
fn a_send_an_earlier_version_released_still_loads_and_stays_watched() {
    let releasing = Releasing::posted().released_by_an_earlier_version();
    let marks = releasing
        .store
        .read(|repos| repos.tx_marks(releasing.tx_id))
        .unwrap();
    assert_eq!(marks.kernel_absent_at, Some(Height::new(RELEASED_AT)));

    let details = releasing
        .harness
        .block_on(releasing.wallet.transaction_details(releasing.tx_id))
        .unwrap();
    assert_eq!(details.transaction.entry.state, TxState::Cancelled);
    assert_eq!(
        releasing.kernel_lookups_by_one_refresh(),
        1,
        "the watch looks the kernel up"
    );
    assert_eq!(releasing.state(), TxState::Cancelled);
    assert!(releasing.change().is_empty());
}

impl Releasing {
    /// The final transaction reached a miner although the node here refused it: it is mined
    /// at `height` from the final slate, its inputs spent, its outputs and kernel on chain, and
    /// the node's tip is there.
    fn final_slate_mined_at(&self, height: u64) {
        let slate = self.final_slate();
        let mined = self.kernel_at(height);
        self.chain_reaches(height);
        self.harness.node.update_chain(|chain| {
            for output in &mut chain.outputs {
                if slate
                    .inputs()
                    .iter()
                    .any(|input| input.commitment == output.commitment)
                {
                    output.spent = true;
                }
            }
            for (position, output) in slate.outputs().iter().enumerate() {
                crate::support::mine_output(
                    chain,
                    ChainOutput {
                        commitment: output.commitment,
                        features: output.features,
                        proof: output.proof.clone(),
                        height: Height::new(height),
                        mmr_index: 2 + position as u64,
                        spent: false,
                    },
                );
            }
            chain.kernels.push(mined);
        });
    }

    /// A refresh and the update scan that follows it on the app's refresh path.
    fn refresh_and_scan(&self) {
        self.refresh();
        self.harness.block_on(self.wallet.refresh_scan()).unwrap();
    }

    /// The send confirmed at `height`, alone in the history with what it spent and kept:
    /// its input spent by it, its change its own, no entry found by a scan or of another
    /// wallet.
    fn assert_confirmed_once(&self, height: u64, change_before: &[OutputRecord]) {
        assert_eq!(self.state(), TxState::Confirmed);
        let history = self.history();
        assert_eq!(
            history
                .iter()
                .map(|details| (details.transaction.id, details.origin))
                .collect::<Vec<_>>(),
            vec![(self.tx_id, lepic_wallet::legacy_history::TxOrigin::Wallet)],
            "one row for the payment"
        );
        let details = &history[0];
        assert_eq!(details.confirmed_height, Some(Height::new(height)));
        let change = self.change();
        assert_eq!(change.len(), 1, "{change:?}");
        assert_eq!(change[0].id, change_before[0].id);
        assert_eq!(change[0].amount, change_before[0].amount);
        assert_eq!(change[0].tx, Some(self.tx_id), "the change is the send's");
        assert_eq!(change[0].status, OutputStatus::Unspent);
        let funding = self
            .outputs()
            .into_iter()
            .find(|output| output.id == self.funding.id)
            .unwrap();
        assert_eq!(funding.status, OutputStatus::Spent);
        assert_eq!(
            funding.tx,
            Some(self.tx_id),
            "the input is spent by the send"
        );
    }
}

both_stores!(a_send_cancelled_too_late_comes_back_confirmed_with_its_change);
/// The node here refused the post, the send was cancelled, and another node had relayed it to
/// a miner after all.
fn a_send_cancelled_too_late_comes_back_confirmed_with_its_change() {
    let releasing = Releasing::refused();
    let change_before = releasing.change();
    assert_eq!(change_before.len(), 1);
    releasing.cancel().unwrap();
    assert_eq!(releasing.state(), TxState::Cancelled);
    assert!(releasing.change().is_empty(), "the cancel drops the change");
    let mined_at = TIP + 2;
    releasing.final_slate_mined_at(mined_at);

    releasing.refresh_and_scan();
    releasing.refresh_and_scan();

    releasing.assert_confirmed_once(mined_at, &change_before);

    support::complete_restore_scan(&releasing.harness.runtime, &releasing.wallet);
    releasing.refresh_and_scan();

    releasing.assert_confirmed_once(mined_at, &change_before);
}

both_stores!(a_scan_that_finds_the_change_of_a_send_cancelled_too_late_confirms_the_send);
/// The update scan after a refresh sees the block first: the change it finds is the cancelled
/// send's, not a receive by another wallet.
fn a_scan_that_finds_the_change_of_a_send_cancelled_too_late_confirms_the_send() {
    let releasing = Releasing::refused();
    let change_before = releasing.change();
    releasing.cancel().unwrap();
    releasing.refresh_and_scan();
    let mined_at = TIP + 2;
    releasing.final_slate_mined_at(mined_at);
    let mut events = releasing.wallet.subscribe();

    releasing
        .harness
        .block_on(releasing.wallet.refresh_scan())
        .unwrap();

    releasing.assert_confirmed_once(mined_at, &change_before);
    assert_eq!(
        transaction_events(&mut events),
        vec![(TxState::Cancelled, TxState::Confirmed)]
    );
    releasing.refresh_and_scan();
    releasing.assert_confirmed_once(mined_at, &change_before);
}

both_stores!(a_restore_scan_that_finds_the_change_of_a_send_cancelled_too_late_confirms_the_send);
fn a_restore_scan_that_finds_the_change_of_a_send_cancelled_too_late_confirms_the_send() {
    let releasing = Releasing::refused();
    let change_before = releasing.change();
    releasing.cancel().unwrap();
    let mined_at = TIP + 2;
    releasing.final_slate_mined_at(mined_at);

    support::complete_restore_scan(&releasing.harness.runtime, &releasing.wallet);

    releasing.assert_confirmed_once(mined_at, &change_before);
    releasing.refresh_and_scan();
    releasing.assert_confirmed_once(mined_at, &change_before);
}

impl Releasing {
    /// Sends again to the peer, answered, finalized and posted, returning the new send. The
    /// node takes pushes again from here.
    fn send_again(&self) -> TxId {
        self.harness.node.stop_failing("push_transaction");
        let sent = self
            .harness
            .block_on(self.wallet.send(
                &self.harness.method(),
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap();
        let s1 = self
            .harness
            .block_on(self.peer.next_envelope())
            .unwrap()
            .unwrap()
            .wire()
            .clone();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;
        self.harness
            .block_on(
                self.wallet
                    .finalize(&self.harness.method(), &s2, Propagation::Stem),
            )
            .unwrap();
        sent.tx_id
    }

    fn state_of(&self, tx_id: TxId) -> TxState {
        self.store
            .read(|repos| Ok::<_, StoreError>(repos.transaction(tx_id)?.unwrap().state))
            .unwrap()
    }
}

both_stores!(a_send_cancelled_too_late_takes_its_input_back_from_the_send_that_reused_it);
/// The send was cancelled, its coin went into a second send, and the first is mined: the coin
/// is spent by the first, and the second, which can never be mined, ends.
fn a_send_cancelled_too_late_takes_its_input_back_from_the_send_that_reused_it() {
    let releasing = Releasing::refused();
    let change_before = releasing.change();
    releasing.cancel().unwrap();
    let resend = releasing.send_again();
    assert_eq!(releasing.state_of(resend), TxState::Posted);
    let mined_at = TIP + 2;
    releasing.final_slate_mined_at(mined_at);

    releasing.refresh_and_scan();

    assert_eq!(releasing.state(), TxState::Confirmed);
    assert_eq!(releasing.state_of(resend), TxState::Cancelled);
    let funding = releasing
        .outputs()
        .into_iter()
        .find(|output| output.id == releasing.funding.id)
        .unwrap();
    assert_eq!(funding.status, OutputStatus::Spent);
    assert_eq!(funding.tx, Some(releasing.tx_id), "spent by the mined send");
    let unspent: Vec<OutputRecord> = releasing
        .outputs()
        .into_iter()
        .filter(|output| output.status != OutputStatus::Spent)
        .collect();
    assert_eq!(unspent.len(), 1, "{unspent:?}");
    assert_eq!(unspent[0].id, change_before[0].id);
    assert_eq!(unspent[0].tx, Some(releasing.tx_id));
    assert!(
        releasing
            .history()
            .iter()
            .all(|details| details.origin == lepic_wallet::legacy_history::TxOrigin::Wallet),
        "no entry of another wallet"
    );
}

both_stores!(the_other_install_shows_a_send_cancelled_too_late_as_one_spend_with_its_change);
/// Another install of the phrase, which never saw the send, shows it as the one spend by
/// another wallet the chain shows, its change folded in, as the sending install shows it as
/// its own send.
fn the_other_install_shows_a_send_cancelled_too_late_as_one_spend_with_its_change() {
    let releasing = Releasing::refused();
    let change_before = releasing.change();
    let twin_side = Harness::new();
    let twin = Wallet::new(
        lepic_wallet::WalletConfig {
            data_dir: PathBuf::from("/twin-data"),
            ..twin_side.config(Network::Floonet)
        },
        Ports {
            node: releasing.harness.node.client(),
            clock: Arc::new(releasing.clock.clone()),
            ..twin_side.ports(TestVault::default())
        },
    )
    .unwrap();
    twin_side
        .block_on(twin.restore(password("twin"), SENDER_MNEMONIC))
        .unwrap();
    support::complete_restore_scan(&twin_side.runtime, &twin);
    let seed = lepic_keychain::Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
    let twin_store = twin_side
        .stores
        .open(
            &PathBuf::from("/twin-data"),
            context_key(&seed),
            &lepic_wallet::store_key(&seed).unwrap(),
        )
        .unwrap();
    // The twin holds the funding output too, as a plain one: a coinbase output this young is
    // spent by nobody, so the chain check would never take it for a spend elsewhere.
    twin_store
        .write(|repos| {
            repos.put_account(&AccountRecord {
                index: ACCOUNT,
                label: "default".to_owned(),
                next_child: NEXT_CHILD,
            })?;
            repos.put_output(&OutputRecord {
                id: lepic_primitives::output::OutputIdentifier::new(
                    OutputFeatures::Plain,
                    releasing.funding.id.commitment,
                ),
                tx: None,
                ..releasing.funding.clone()
            })
        })
        .unwrap();
    let twin_refresh_and_scan = || {
        twin_side.block_on(twin.refresh()).unwrap();
        twin_side.block_on(twin.refresh_scan()).unwrap();
    };
    twin_refresh_and_scan();
    releasing.cancel().unwrap();
    let mined_at = TIP + 2;
    releasing.final_slate_mined_at(mined_at);

    releasing.refresh_and_scan();
    twin_refresh_and_scan();

    releasing.assert_confirmed_once(mined_at, &change_before);
    let history = twin_side.block_on(twin.transactions(ACCOUNT)).unwrap();
    let spends: Vec<_> = history
        .iter()
        .filter(|details| details.origin == lepic_wallet::legacy_history::TxOrigin::OtherWallet)
        .collect();
    assert_eq!(spends.len(), 1, "{history:#?}");
    let entry = &spends[0].transaction.entry;
    assert_eq!(entry.direction, lepic_store::TxDirection::Outgoing);
    assert_eq!(entry.amount_debited, releasing.funding.amount);
    assert_eq!(
        entry.amount_credited, change_before[0].amount,
        "the change is the spend's"
    );
}
