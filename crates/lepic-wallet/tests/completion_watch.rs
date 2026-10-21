//! A transaction the peer can still complete without this wallet: a received payment once its
//! S2 exists, or a finalized send. Cancelling or expiring one first asks the node whether it
//! already holds the kernel, and afterwards keeps it watched, so a later refresh confirms it
//! and restores its outputs if the peer completes it after all.

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
use lepic_keychain::{Keychain, Seed};
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, Propagation, RejectionKind};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::{Transaction, TransactionBody};
use lepic_slate::codec::WireSlate;
use lepic_store::{
    AccountRecord, MemoryStore, OutputRecord, OutputStatus, StoreError, TxId, TxState, WalletStore,
};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::{RefreshOutcome, UNFINALIZED_RECEIVE_BLOCKS};
use lepic_wallet::release::RELEASED_WATCH_BLOCKS;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Clock, Ports, ReceiveRequest, StoreOpener, Wallet, WalletError};
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, TIP, context_key, output};
use support::{Harness, LOOPBACK, MemoryStores, TestVault, TestWallet, fixed_time, password};

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
    store: MemoryStore,
    keychain: Keychain,
}

impl Side {
    fn new(mnemonic: &str, clock: &MovableClock, node: Option<&Harness>) -> Self {
        let mut harness = Harness::new();
        if let Some(shared) = node {
            harness.node = shared.node.clone();
        }
        let ports: Ports<_, MemoryStores, TestVault> = Ports {
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
    assert!(mined < window_end + RELEASED_WATCH_BLOCKS);
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
