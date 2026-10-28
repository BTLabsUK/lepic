// SPDX-License-Identifier: Apache-2.0
//! A transaction the peer can still complete without this wallet: a received payment once its
//! S2 exists, or a finalized send. Cancelling or expiring one first asks the node whether it
//! already holds the kernel, and afterwards keeps it watched, so a later refresh confirms it
//! and restores its outputs if the peer completes it after all. Also: an output restored with
//! another switch commitment counts in the balance but is never spent.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod send_support;
mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use jiff::{SignedDuration, Timestamp};
use lepic_crypto::Commitment;
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, NodeError, Propagation, RejectionKind};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::{Transaction, TransactionBody};
use lepic_slate::codec::WireSlate;
use lepic_store::{
    AccountRecord, KeyId, OutputRecord, OutputStatus, SlateStage, StoreError, StoredSlate, TxId,
    TxState, WalletStore,
};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::{RefreshOutcome, UNFINALIZED_RECEIVE_BLOCKS};
use lepic_wallet::release::{ENDED_RECEIVE_WATCH_BLOCKS, RELEASED_WATCH_BLOCKS};
use lepic_wallet::selection::{SelectionOptions, SelectionStrategy};
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use lepic_wallet::{Clock, Ports, ReceiveRequest, StoreOpener, Wallet, WalletError};
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, TIP, context_key, output};
use serde_json::Value;
use support::{
    Harness, LOOPBACK, TestStore, TestStores, TestVault, TestWallet, fixed_time, password,
};
use uuid::Uuid;

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

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

/// One side of a payment: a wallet, the harness it runs in and its database.
struct Side {
    harness: Harness,
    wallet: TestWallet,
    store: TestStore,
    keychain: Keychain,
}

impl Side {
    fn new(mnemonic: &str, clock: &MovableClock, node: Option<&Harness>) -> Self {
        let mut harness = Harness::new();
        if let Some(shared) = node {
            harness.node = shared.node.clone();
        }
        let ports: Ports<_, TestStores, TestVault> = Ports {
            clock: Arc::new(clock.clone()),
            ..harness.ports(TestVault::default())
        };
        let wallet = Wallet::new(harness.config(Network::Floonet), ports).unwrap();
        harness
            .block_on(wallet.restore(password("party"), mnemonic))
            .unwrap();
        let seed = Seed::from_mnemonic(mnemonic).unwrap();
        let store = harness
            .stores
            .open(&harness.data_dir, context_key(&seed))
            .unwrap();
        Self {
            harness,
            wallet,
            store,
            keychain: Keychain::from_seed(&seed, Network::Floonet).unwrap(),
        }
    }

    fn state(&self, tx_id: TxId) -> TxState {
        self.store
            .read(|repos| Ok::<_, StoreError>(repos.transaction(tx_id)?.unwrap().state))
            .unwrap()
    }

    fn outputs(&self) -> Vec<OutputRecord> {
        self.store
            .read(|repos| repos.outputs(ACCOUNT, None))
            .unwrap()
    }

    fn refresh(&self) {
        let outcome = self.harness.block_on(self.wallet.refresh()).unwrap();
        assert!(
            matches!(outcome, RefreshOutcome::Refreshed(_)),
            "{outcome:?}"
        );
    }

    fn cancel(&self, tx_id: TxId) -> Result<(), WalletError> {
        self.harness.block_on(self.wallet.cancel(tx_id))
    }
}

/// The funded `send_file_plain` sender and a receiver on the same mock node, with a payment of
/// [`AMOUNT`] sent, received and answered.
struct Payment {
    clock: MovableClock,
    sender: Side,
    receiver: Side,
    send_tx: TxId,
    receive_tx: TxId,
    s2: WireSlate,
    /// The receiver's output.
    received: OutputRecord,
}

impl Payment {
    fn answered(ttl_blocks: Option<u64>) -> Self {
        let clock = MovableClock(Arc::new(Mutex::new(fixed_time())));
        let sender = Side::new(SENDER_MNEMONIC, &clock, None);
        sender
            .harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(TIP));
        support::complete_restore_scan(&sender.harness.runtime, &sender.wallet);
        let funding = output(&sender.keychain, 0, FUNDING, OutputFeatures::Coinbase);
        sender
            .store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: ACCOUNT,
                    label: "default".to_owned(),
                    next_child: NEXT_CHILD,
                })?;
                repos.put_output(&funding)
            })
            .unwrap();
        sender.harness.node.update_chain(|chain| {
            chain.outputs.push(ChainOutput {
                commitment: funding.id.commitment,
                features: OutputFeatures::Coinbase,
                proof: some_proof(),
                height: Height::new(1),
                mmr_index: 1,
                spent: false,
            });
        });
        let receiver = Side::new(RECEIVER_MNEMONIC, &clock, Some(&sender.harness));
        support::complete_restore_scan(&receiver.harness.runtime, &receiver.wallet);

        let sent = sender
            .harness
            .block_on(sender.wallet.send(
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ttl_blocks,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    transport: LOOPBACK,
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap();
        let peer = sender.harness.peer.lock().unwrap().take().unwrap();
        let s1 = sender
            .harness
            .block_on(peer.next_envelope())
            .unwrap()
            .unwrap()
            .wire()
            .clone();
        let received = receiver
            .harness
            .block_on(
                receiver
                    .wallet
                    .receive(LOOPBACK, &s1, ReceiveRequest::default()),
            )
            .unwrap();
        let outputs = receiver.outputs();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].status, OutputStatus::Unconfirmed);
        Self {
            clock,
            received: outputs[0].clone(),
            sender,
            receiver,
            send_tx: sent.tx_id,
            receive_tx: received.tx_id,
            s2: received.reply,
        }
    }

    /// The sender finalizes the S2 and posts it; the node records the post but neither pools
    /// nor mines it.
    fn finalized(self) -> Self {
        self.sender
            .harness
            .block_on(
                self.sender
                    .wallet
                    .finalize(LOOPBACK, &self.s2, Propagation::Stem),
            )
            .unwrap();
        self
    }

    fn node(&self) -> &lepic_node::mock::MockNode {
        &self.sender.harness.node
    }

    fn posted(&self) -> Transaction {
        self.node().pushed_transactions()[0].clone()
    }

    fn pool_it(&self) {
        let posted = self.posted();
        self.node().update_chain(|chain| chain.pool.push(posted));
    }

    fn unpool_it(&self) {
        self.node().update_chain(|chain| chain.pool.clear());
    }

    /// A miner includes the posted transaction at `height`: its inputs are spent, its outputs
    /// and kernel are on chain.
    fn mined_at(&self, height: u64) {
        let posted = self.posted();
        self.node().update_chain(|chain| {
            chain.pool.clear();
            for output in &mut chain.outputs {
                if posted
                    .inputs()
                    .iter()
                    .any(|input| input.commitment == output.commitment)
                {
                    output.spent = true;
                }
            }
            for (position, output) in posted.outputs().iter().enumerate() {
                chain.outputs.push(ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height: Height::new(height),
                    mmr_index: 2 + position as u64,
                    spent: false,
                });
            }
            chain.kernels.push(LocatedKernel {
                kernel: posted.kernels()[0],
                height: Height::new(height),
                mmr_index: 9,
            });
        });
    }

    /// The node's tip moves to `height`, a day and an hour later by the clock.
    fn chain_reaches(&self, height: u64) {
        self.clock.advance(SignedDuration::from_hours(25));
        self.node()
            .update_chain(|chain| chain.tip.height = Height::new(height));
    }

    /// Moves the chain to `height` a day of blocks at a time, refreshing the receiver twice at
    /// each step so every tip is confirmed.
    fn receiver_follows_to(&self, height: u64) {
        let mut at = self.tip();
        while at < height {
            at = (at + 1_440).min(height);
            self.chain_reaches(at);
            self.receiver.refresh();
            self.receiver.refresh();
        }
    }

    fn tip(&self) -> u64 {
        let mut tip = 0;
        self.node()
            .update_chain(|chain| tip = chain.tip.height.value());
        tip
    }

    /// The receiver holds the payment's output as unspent from `height`, under the payment.
    fn assert_receive_restored(&self, height: u64) {
        assert_eq!(self.receiver.state(self.receive_tx), TxState::Confirmed);
        let outputs = self.receiver.outputs();
        assert_eq!(outputs.len(), 1, "{outputs:?}");
        assert_eq!(outputs[0].id.commitment, self.received.id.commitment);
        assert_eq!(outputs[0].key_id, self.received.key_id);
        assert_eq!(outputs[0].amount, Amount::new(AMOUNT));
        assert_eq!(outputs[0].status, OutputStatus::Unspent);
        assert_eq!(outputs[0].height, Height::new(height));
        assert_eq!(outputs[0].tx, Some(self.receive_tx));
    }
}

#[test]
fn a_receiver_cancel_after_answering_is_refused_while_the_node_pool_holds_the_payment() {
    let payment = Payment::answered(None).finalized();
    payment.pool_it();

    let error = payment.receiver.cancel(payment.receive_tx).unwrap_err();

    assert!(
        matches!(error, WalletError::InPool(id) if id == payment.receive_tx),
        "{error:?}"
    );
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
    assert_eq!(payment.receiver.outputs(), vec![payment.received.clone()]);
}

#[test]
fn a_receiver_cancel_after_answering_is_refused_once_the_chain_holds_the_payment() {
    let payment = Payment::answered(None).finalized();
    payment.mined_at(TIP + 1);
    payment.chain_reaches(TIP + 1);

    let error = payment.receiver.cancel(payment.receive_tx).unwrap_err();

    assert!(
        matches!(error, WalletError::OnChain(id) if id == payment.receive_tx),
        "{error:?}"
    );
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
}

#[test]
fn a_receiver_cancel_the_node_knows_nothing_of_keeps_a_watch_that_restores_a_late_payment() {
    let payment = Payment::answered(None);
    payment.receiver.cancel(payment.receive_tx).unwrap();
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Cancelled
    );
    assert!(
        payment.receiver.outputs().is_empty(),
        "the output is dropped"
    );

    // The sender still finalizes the S2 it holds, and the chain mines it.
    let payment = payment.finalized();
    payment.mined_at(TIP + 1);
    payment.chain_reaches(TIP + 1);
    payment.receiver.refresh();

    payment.assert_receive_restored(TIP + 1);
}

fn kernel_requests(payment: &Payment) -> usize {
    payment
        .node()
        .calls()
        .iter()
        .filter(|method| *method == "get_kernel")
        .count()
}

#[test]
fn a_receiver_cancel_is_restored_by_its_kernel_when_posted_on_the_last_watched_block() {
    let payment = Payment::answered(None);
    payment.receiver.cancel(payment.receive_tx).unwrap();
    let last = TIP + ENDED_RECEIVE_WATCH_BLOCKS;
    payment.receiver_follows_to(last - 1);
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Cancelled
    );

    let payment = payment.finalized();
    payment.mined_at(last);
    payment.chain_reaches(last);
    payment.receiver.refresh();

    payment.assert_receive_restored(last);
}

#[test]
fn a_receiver_cancel_posted_after_the_kernel_watch_still_arrives_by_its_output() {
    let payment = Payment::answered(None);
    payment.receiver.cancel(payment.receive_tx).unwrap();
    // The sender finalizes the S2 it holds; its post reaches no miner for now.
    let payment = payment.finalized();
    // A day of blocks passes and more: the kernel is no longer looked up.
    let after = TIP + ENDED_RECEIVE_WATCH_BLOCKS + 100;
    payment.receiver_follows_to(after);
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Cancelled
    );
    let kernels_before = kernel_requests(&payment);
    payment.receiver.refresh();
    assert_eq!(
        kernel_requests(&payment),
        kernels_before,
        "past the window, the kernel is not looked up"
    );

    // Much later, the chain mines it.
    let mined = after + 3_000;
    payment.receiver_follows_to(mined - 1);
    payment.mined_at(mined);
    payment.chain_reaches(mined);
    payment.receiver.refresh();

    payment.assert_receive_restored(mined);
    let watched = payment
        .receiver
        .store
        .read(|repos| repos.tx_watch(payment.receive_tx))
        .unwrap();
    assert_eq!(watched, None, "found, it is no longer watched");
}

#[test]
fn a_sender_cancel_of_a_finalized_send_keeps_a_watch_that_restores_its_change() {
    let payment = Payment::answered(None);
    payment.sender.harness.node.fail_next(
        "push_transaction",
        MockFailure::Rejected(RejectionKind::Internal),
    );
    let error = payment
        .sender
        .harness
        .block_on(
            payment
                .sender
                .wallet
                .finalize(LOOPBACK, &payment.s2, Propagation::Stem),
        )
        .unwrap_err();
    assert!(
        matches!(error, FinalizeError::NotPosted { .. }),
        "{error:?}"
    );
    let change_before: Vec<OutputRecord> = payment
        .sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .collect();
    assert_eq!(change_before.len(), 1);
    payment.sender.cancel(payment.send_tx).unwrap();
    assert_eq!(payment.sender.state(payment.send_tx), TxState::Cancelled);

    // The refused post reached another node after all, which mined it.
    let s3 = payment
        .sender
        .store
        .read(|repos| {
            let entry = repos.transaction(payment.send_tx)?.unwrap();
            repos.slate(entry.slate_id.unwrap(), lepic_store::SlateStage::Standard3)
        })
        .unwrap()
        .unwrap();
    let s3 = send_support::legacy_codecs()
        .decode(&WireSlate::binary(
            lepic_slate::codec::MediaType::JSON,
            s3.bytes,
        ))
        .unwrap();
    payment.node().update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel: s3.kernel().unwrap(),
            height: Height::new(TIP + 1),
            mmr_index: 9,
        });
    });
    payment.chain_reaches(TIP + 1);
    payment.sender.refresh();

    assert_eq!(payment.sender.state(payment.send_tx), TxState::Confirmed);
    let restored = payment
        .sender
        .outputs()
        .into_iter()
        .find(|output| output.id == change_before[0].id)
        .unwrap();
    assert_eq!(restored.status, OutputStatus::Unspent);
    assert_eq!(restored.amount, change_before[0].amount);
}

#[test]
fn a_late_payment_found_after_the_kernel_watch_takes_over_the_output_a_scan_restored() {
    let payment = Payment::answered(None);
    payment.receiver.cancel(payment.receive_tx).unwrap();
    let payment = payment.finalized();
    let after = TIP + ENDED_RECEIVE_WATCH_BLOCKS + 100;
    payment.receiver_follows_to(after);
    let mined = after + 1;
    payment.mined_at(mined);
    payment.chain_reaches(mined);
    let entries = |side: &Side| {
        side.store
            .read(|repos| repos.transactions(ACCOUNT))
            .unwrap()
            .len()
    };
    let before = entries(&payment.receiver);
    support::complete_restore_scan(&payment.receiver.harness.runtime, &payment.receiver.wallet);
    assert_eq!(
        entries(&payment.receiver),
        before + 1,
        "the scan adds an entry"
    );

    payment.receiver.refresh();

    payment.assert_receive_restored(mined);
    assert_eq!(
        entries(&payment.receiver),
        before,
        "counted once, in the payment"
    );
}

#[test]
fn a_sender_cancel_mined_after_the_kernel_watch_still_restores_its_change() {
    let payment = Payment::answered(None);
    payment.sender.harness.node.fail_next(
        "push_transaction",
        MockFailure::Rejected(RejectionKind::Internal),
    );
    payment
        .sender
        .harness
        .block_on(
            payment
                .sender
                .wallet
                .finalize(LOOPBACK, &payment.s2, Propagation::Stem),
        )
        .unwrap_err();
    let change: Vec<OutputRecord> = payment
        .sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .collect();
    assert_eq!(change.len(), 1);
    payment.sender.cancel(payment.send_tx).unwrap();

    // A week of blocks and more passes; the kernel is no longer looked up.
    let after = TIP + RELEASED_WATCH_BLOCKS + 100;
    let mut at = TIP;
    while at < after {
        at = (at + 1_440).min(after);
        payment.chain_reaches(at);
        payment.sender.refresh();
        payment.sender.refresh();
    }
    assert_eq!(payment.sender.state(payment.send_tx), TxState::Cancelled);

    // The refused post reached another node after all, which mines it much later.
    let mined = after + 10;
    payment.node().update_chain(|chain| {
        chain.outputs.push(ChainOutput {
            commitment: change[0].id.commitment,
            features: OutputFeatures::Plain,
            proof: some_proof(),
            height: Height::new(mined),
            mmr_index: 20,
            spent: false,
        });
    });
    payment.chain_reaches(mined);
    payment.sender.refresh();

    assert_eq!(payment.sender.state(payment.send_tx), TxState::Confirmed);
    let restored = payment
        .sender
        .outputs()
        .into_iter()
        .find(|output| output.id == change[0].id)
        .unwrap();
    assert_eq!(restored.status, OutputStatus::Unspent);
    assert_eq!(restored.height, Height::new(mined));
}

const TTL_BLOCKS: u64 = 10;

#[test]
fn a_receive_past_its_ttl_is_not_expired_while_the_node_pool_holds_the_payment() {
    let payment = Payment::answered(Some(TTL_BLOCKS)).finalized();
    payment.pool_it();
    payment.chain_reaches(TIP + TTL_BLOCKS);

    payment.receiver.refresh();

    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
    assert_eq!(payment.receiver.outputs(), vec![payment.received.clone()]);
}

#[test]
fn a_receive_past_its_ttl_is_not_expired_once_the_chain_holds_its_kernel() {
    let payment = Payment::answered(Some(TTL_BLOCKS)).finalized();
    let posted = payment.posted();
    // Only the kernel: the output lookup alone would not have seen it yet.
    payment.node().update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel: posted.kernels()[0],
            height: Height::new(TIP + 1),
            mmr_index: 9,
        });
    });
    payment.chain_reaches(TIP + TTL_BLOCKS);

    payment.receiver.refresh();

    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
}

#[test]
fn a_receive_expired_at_its_ttl_is_watched_and_restored_when_mined_later() {
    let payment = Payment::answered(Some(TTL_BLOCKS)).finalized();
    payment.pool_it();
    payment.chain_reaches(TIP + TTL_BLOCKS);
    payment.receiver.refresh();
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );

    // The node drops it from its pool, so the cutoff ends the payment.
    payment.unpool_it();
    payment.receiver.refresh();
    assert_eq!(payment.receiver.state(payment.receive_tx), TxState::Expired);
    assert!(payment.receiver.outputs().is_empty());

    // Another node still mines it.
    payment.mined_at(TIP + TTL_BLOCKS + 1);
    payment.chain_reaches(TIP + TTL_BLOCKS + 1);
    payment.receiver.refresh();

    payment.assert_receive_restored(TIP + TTL_BLOCKS + 1);
}

#[test]
fn a_receive_with_no_ttl_the_node_never_saw_expires_after_the_window_and_is_restored_if_mined() {
    // The sender finalizes, but its post never reaches the node.
    let payment = Payment::answered(None).finalized();
    // The first refresh records when the payment was first seen.
    payment.receiver.refresh();
    let seen = payment.tip();
    let window_end = seen + UNFINALIZED_RECEIVE_BLOCKS;

    payment.receiver_follows_to(window_end - 1);
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
    assert_eq!(payment.receiver.outputs(), vec![payment.received.clone()]);

    payment.receiver_follows_to(window_end);
    assert_eq!(payment.receiver.state(payment.receive_tx), TxState::Expired);
    assert!(payment.receiver.outputs().is_empty());

    // Another node still mines it, inside the watch.
    let mined = window_end + 1;
    payment.mined_at(mined);
    payment.chain_reaches(mined);
    payment.receiver.refresh();

    payment.assert_receive_restored(mined);
    assert!(mined < window_end + ENDED_RECEIVE_WATCH_BLOCKS);
}

#[test]
fn a_receive_with_no_ttl_is_not_expired_after_the_window_while_the_node_pool_holds_it() {
    let payment = Payment::answered(None).finalized();
    payment.receiver.refresh();
    let window_end = payment.tip() + UNFINALIZED_RECEIVE_BLOCKS;
    payment.pool_it();

    payment.receiver_follows_to(window_end);

    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
}

/// An unspent output of the sender's whose commitment uses no switch commitment, as a restore
/// stores one it rewinds.
fn odd_switch_output(keychain: &Keychain, child: u32, value: u64) -> OutputRecord {
    let id = Identifier::new(3, [0, 0, child, 0]).unwrap();
    let commitment: Commitment = keychain.commit(value, &id, SwitchCommitment::None).unwrap();
    OutputRecord {
        id: lepic_primitives::output::OutputIdentifier::new(OutputFeatures::Plain, commitment),
        key_id: KeyId(id.to_bytes()),
        ..output(keychain, child, value, OutputFeatures::Plain)
    }
}

#[test]
fn an_output_with_another_switch_commitment_counts_but_is_never_spent() {
    const ODD: u64 = 50_000_000;
    let payment = Payment::answered(None);
    let sender = &payment.sender;
    sender.cancel(payment.send_tx).unwrap();
    let odd = odd_switch_output(&sender.keychain, 30, ODD);
    sender.store.write(|repos| repos.put_output(&odd)).unwrap();
    let before = sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(before.total, Amount::new(FUNDING + ODD), "it still counts");

    // "Use all": the largest send is paid from the funding output alone.
    let options = SelectionOptions {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SelectionOptions::new(ACCOUNT)
    };
    let max = sender
        .harness
        .block_on(sender.wallet.estimate_max(options))
        .unwrap();
    assert!(max.inputs.iter().all(|input| input.id != odd.id), "{max:?}");
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, max.amount)
            },
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    assert_eq!(sent.fee, max.fee);

    // A send it alone could pay does not select it either.
    let error = sender
        .harness
        .block_on(sender.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(ODD / 2))
            },
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap_err();
    assert!(
        matches!(
            error,
            SendError::Selection(lepic_wallet::selection::SelectionError::NotEnoughFunds { .. })
        ),
        "{error:?}"
    );
    let stored = sender
        .outputs()
        .into_iter()
        .find(|output| output.id == odd.id)
        .unwrap();
    assert_eq!(stored.status, OutputStatus::Unspent);
    assert_eq!(stored.tx, None);
}

#[test]
fn a_pooled_transaction_with_another_kernel_does_not_stop_a_cancel() {
    let payment = Payment::answered(None).finalized();
    let other = Transaction::new(
        BlindingFactor::zero(),
        TransactionBody::new(Vec::new(), Vec::new(), Vec::new()),
    );
    payment.node().update_chain(|chain| chain.pool.push(other));

    payment.receiver.cancel(payment.receive_tx).unwrap();

    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Cancelled
    );
}

/// A slate height far above any chain, which a wallet that did not check the peer's height
/// may have stored.
const FAR_HEIGHT: u64 = 1_000_000_000_000;

/// `bytes`, a stored slate's JSON, under the slate id `id` and with its height set to `height`.
fn slate_moved(bytes: &[u8], id: Uuid, height: u64) -> Vec<u8> {
    let mut slate: Value = serde_json::from_slice(bytes).unwrap();
    slate["id"] = Value::String(id.to_string());
    slate["height"] = match slate["height"] {
        Value::String(_) => Value::String(height.to_string()),
        _ => Value::from(height),
    };
    slate.to_string().into_bytes()
}

/// Stores a copy of the transaction `tx_id` and its slate at `stage` under a new slate id, with
/// the slate's height set to `height`, as a database written before slate heights were checked
/// may hold one. The copy holds no outputs.
fn stored_copy(store: &TestStore, tx_id: TxId, stage: SlateStage, height: u64) -> TxId {
    let id = Uuid::from_u128(u128::from(height) + 7);
    store
        .write(|repos| {
            let mut entry = repos.transaction(tx_id)?.unwrap();
            let slate = repos.slate(entry.slate_id.unwrap(), stage)?.unwrap();
            entry.slate_id = Some(id);
            entry.amount_credited = Amount::ZERO;
            let copy = repos.insert_transaction(&entry)?;
            repos.insert_slate(&StoredSlate {
                slate_id: id,
                stage,
                codec: slate.codec,
                bytes: slate_moved(&slate.bytes, id, height),
            })?;
            Ok::<_, StoreError>(copy)
        })
        .unwrap()
}

fn pool_requests(payment: &Payment) -> usize {
    payment
        .node()
        .calls()
        .iter()
        .filter(|method| *method == "get_unconfirmed_transactions")
        .count()
}

#[test]
fn a_receive_stored_with_a_height_above_the_tip_can_be_cancelled() {
    let payment = Payment::answered(None);
    let copy = stored_copy(
        &payment.receiver.store,
        payment.receive_tx,
        SlateStage::Standard2,
        FAR_HEIGHT,
    );

    payment.receiver.cancel(copy).unwrap();

    assert_eq!(payment.receiver.state(copy), TxState::Cancelled);
}

#[test]
fn a_receive_stored_with_a_height_above_the_tip_expires_without_stopping_refresh() {
    let payment = Payment::answered(None).finalized();
    let copy = stored_copy(
        &payment.receiver.store,
        payment.receive_tx,
        SlateStage::Standard2,
        FAR_HEIGHT,
    );
    payment.receiver.refresh();
    let window_end = payment.tip() + UNFINALIZED_RECEIVE_BLOCKS;

    payment.receiver_follows_to(window_end);

    assert_eq!(payment.receiver.state(copy), TxState::Expired);
    assert_eq!(payment.receiver.state(payment.receive_tx), TxState::Expired);
    // The payment the copy was made from is still watched and restored when mined.
    let mined = window_end + 1;
    payment.mined_at(mined);
    payment.chain_reaches(mined);
    payment.receiver.refresh();
    payment.assert_receive_restored(mined);
}

#[test]
fn a_kernel_lookup_the_node_refuses_keeps_the_payment_open_until_a_later_refresh() {
    let payment = Payment::answered(Some(TTL_BLOCKS)).finalized();
    payment.chain_reaches(TIP + TTL_BLOCKS);
    payment
        .node()
        .fail_next("get_kernel", MockFailure::Rejected(RejectionKind::Internal));

    payment.receiver.refresh();
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );

    payment.receiver.refresh();
    assert_eq!(payment.receiver.state(payment.receive_tx), TxState::Expired);
}

#[test]
fn payments_due_to_expire_ask_the_node_pool_once_per_refresh() {
    let payment = Payment::answered(Some(TTL_BLOCKS)).finalized();
    let copy = stored_copy(
        &payment.receiver.store,
        payment.receive_tx,
        SlateStage::Standard2,
        TIP,
    );
    payment.chain_reaches(TIP + TTL_BLOCKS);
    let before = pool_requests(&payment);

    payment.receiver.refresh();

    assert_eq!(pool_requests(&payment) - before, 1);
    assert_eq!(payment.receiver.state(copy), TxState::Expired);
    assert_eq!(payment.receiver.state(payment.receive_tx), TxState::Expired);
}

#[test]
fn a_receiver_cancel_after_answering_is_refused_while_the_node_tip_is_implausible() {
    let payment = Payment::answered(None);
    payment
        .node()
        .update_chain(|chain| chain.tip.height = Height::new(FAR_HEIGHT));

    let error = payment.receiver.cancel(payment.receive_tx).unwrap_err();

    // Whichever layer refuses the tip, the node client or the wallet, nothing is cancelled.
    assert!(
        matches!(
            error,
            WalletError::Implausible(_) | WalletError::Node(NodeError::ImplausibleTip { .. })
        ),
        "{error:?}"
    );
    assert_eq!(
        payment.receiver.state(payment.receive_tx),
        TxState::Received
    );
    assert_eq!(payment.receiver.outputs(), vec![payment.received.clone()]);
}

#[test]
fn a_late_payment_takes_over_the_output_a_scan_restored_first() {
    let payment = Payment::answered(None);
    payment.receiver.cancel(payment.receive_tx).unwrap();
    let payment = payment.finalized();
    payment.mined_at(TIP + 1);
    payment.chain_reaches(TIP + 1);
    let entries = |side: &Side| {
        side.store
            .read(|repos| repos.transactions(ACCOUNT))
            .unwrap()
            .len()
    };
    let before = entries(&payment.receiver);
    support::complete_restore_scan(&payment.receiver.harness.runtime, &payment.receiver.wallet);
    let restored = payment.receiver.outputs();
    assert_eq!(restored.len(), 1, "the scan restores the output");
    assert_ne!(restored[0].tx, Some(payment.receive_tx));
    assert_eq!(
        entries(&payment.receiver),
        before + 1,
        "under an entry of its own"
    );

    payment.receiver.refresh();

    payment.assert_receive_restored(TIP + 1);
    assert_eq!(
        entries(&payment.receiver),
        before,
        "the restored entry is dropped"
    );
}
