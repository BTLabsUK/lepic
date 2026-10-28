// SPDX-License-Identifier: Apache-2.0
//! A cancel and a finalize of the same send running at once on one wallet: whichever commits
//! second must see the other's commit, so the send ends either cancelled with nothing pushed or
//! posted with its inputs still locked.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::FutureExt as _;
use lepic_crypto::Commitment;
use lepic_node::mock::{MockFailure, MockNode};
use lepic_node::{
    BlockHeaderInfo, LocatedKernel, NodeApi, NodeClient, NodeError, NodeVersion, OutputLocation,
    PmmrIndices, PoolTransaction, Propagation, Tip, UnspentOutputs,
};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_primitives::tx::Transaction;
use lepic_slate::codec::WireSlate;
use lepic_store::{OutputStatus, SlateStage, TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::finalize::{FinalizeError, Finalized};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Ports, Wallet, WalletError};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP};
use support::{LOOPBACK, TestStores, TestVault, both_stores, password};
use tokio::sync::Notify;

const AMOUNT: u64 = 100_000_000;

/// The receiver of the G-03 cases.
const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The node call a [`GatedNode`] holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    /// `get_tip` is answered, and the answer handed back once released.
    Tip,
    /// `get_kernel` is answered, and the answer handed back once released.
    Kernel,
    /// `push_transaction` reaches the node only once released.
    Push,
}

/// Where a [`GatedNode`] holds the first call of one kind made after [`Gate::arm`].
#[derive(Clone, Default)]
struct Gate {
    /// Notified when the held call starts waiting.
    reached: Arc<Notify>,
    /// Lets the held call go on.
    release: Arc<Notify>,
    armed: Arc<AtomicBool>,
}

impl Gate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Whether this call is the one to hold.
    fn take(&self) -> bool {
        self.armed.swap(false, Ordering::SeqCst)
    }

    async fn hold(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

/// The mock node's client with one call held at a [`Gate`], so another wallet operation runs
/// between that call and what the wallet does after it.
struct GatedNode {
    inner: NodeClient<MockNode>,
    held: Held,
    gate: Gate,
}

impl NodeApi for GatedNode {
    fn get_version(&self) -> impl Future<Output = Result<NodeVersion, NodeError>> + Send {
        self.inner.get_version()
    }

    fn get_tip(&self) -> impl Future<Output = Result<Tip, NodeError>> + Send {
        let hold = self.held == Held::Tip && self.gate.take();
        let gate = self.gate.clone();
        let answer = self.inner.get_tip();
        async move {
            let answer = answer.await;
            if hold {
                gate.hold().await;
            }
            answer
        }
    }

    fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> impl Future<Output = Result<Option<LocatedKernel>, NodeError>> + Send {
        let hold = self.held == Held::Kernel && self.gate.take();
        let gate = self.gate.clone();
        let answer = self.inner.get_kernel(excess, min_height, max_height);
        async move {
            let answer = answer.await;
            if hold {
                gate.hold().await;
            }
            answer
        }
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
        self.inner.get_unspent_outputs(start_index, end_index, max)
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
        let hold = self.held == Held::Push && self.gate.take();
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let transaction = transaction.clone();
        async move {
            if hold {
                gate.hold().await;
            }
            inner.push_transaction(&transaction, propagation).await
        }
    }

    fn get_header(
        &self,
        height: Height,
    ) -> impl Future<Output = Result<Option<BlockHeaderInfo>, NodeError>> + Send {
        self.inner.get_header(height)
    }

    fn get_unconfirmed_transactions(
        &self,
    ) -> impl Future<Output = Result<Vec<PoolTransaction>, NodeError>> + Send {
        self.inner.get_unconfirmed_transactions()
    }
}

type GatedWallet = Wallet<GatedNode, TestStores, TestVault>;

/// A send delivered to a LEPIC receiver, its S2, and a second handle on the sender's wallet
/// whose node holds `held` at the returned gate.
struct Race {
    sender: Sender,
    tx_id: TxId,
    s2: WireSlate,
    wallet: GatedWallet,
    gate: Gate,
}

impl Race {
    fn new(held: Held) -> Self {
        let sender = Sender::new();
        let sent = sender
            .harness
            .block_on(sender.wallet.send(
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    transport: LOOPBACK,
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap();
        let (s1, _) = sender.received().unwrap();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;

        let harness = &sender.harness;
        let gate = Gate::default();
        let ports = harness.ports(harness.vault.clone());
        let wallet = Wallet::new(
            harness.config(Network::Floonet),
            Ports {
                node: GatedNode {
                    inner: ports.node,
                    held,
                    gate: gate.clone(),
                },
                stores: ports.stores,
                secrets: ports.secrets,
                transports: ports.transports,
                clock: ports.clock,
                rng: ports.rng,
                runtime: ports.runtime,
            },
        )
        .unwrap();
        harness.block_on(wallet.open(password("sender"))).unwrap();
        Self {
            sender,
            tx_id: sent.tx_id,
            s2,
            wallet,
            gate,
        }
    }

    /// Starts the finalize and, while it is held at the gate, runs the cancel as far as it gets,
    /// then lets the finalize go on.
    fn cancel_while_finalize_is_held(
        &self,
    ) -> (Result<Finalized, FinalizeError>, Result<(), WalletError>) {
        self.gate.arm();
        self.sender.harness.block_on(async {
            let finalize = self.wallet.finalize(LOOPBACK, &self.s2, Propagation::Stem);
            let cancel = async {
                self.gate.reached.notified().await;
                // The cancel runs as far as it can while the finalize is held: to its end, or
                // until it waits for the held finalize. Then the finalize goes on.
                let mut cancelling = std::pin::pin!(self.wallet.cancel(self.tx_id));
                let mut early = None;
                for _ in 0..CANCEL_POLLS {
                    if let Some(cancelled) = cancelling.as_mut().now_or_never() {
                        early = Some(cancelled);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                self.gate.release.notify_one();
                match early {
                    Some(cancelled) => cancelled,
                    None => cancelling.await,
                }
            };
            tokio::join!(finalize, cancel)
        })
    }

    /// Starts the cancel and, while it is held at the gate, runs the finalize as far as it gets,
    /// then lets the cancel go on.
    fn finalize_while_cancel_is_held(
        &self,
    ) -> (Result<Finalized, FinalizeError>, Result<(), WalletError>) {
        self.gate.arm();
        self.sender.harness.block_on(async {
            let cancel = self.wallet.cancel(self.tx_id);
            let finalize = async {
                self.gate.reached.notified().await;
                let mut finalizing =
                    std::pin::pin!(self.wallet.finalize(LOOPBACK, &self.s2, Propagation::Stem));
                let mut early = None;
                for _ in 0..CANCEL_POLLS {
                    if let Some(finalized) = finalizing.as_mut().now_or_never() {
                        early = Some(finalized);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                self.gate.release.notify_one();
                match early {
                    Some(finalized) => finalized,
                    None => finalizing.await,
                }
            };
            let (cancelled, finalized) = tokio::join!(cancel, finalize);
            (finalized, cancelled)
        })
    }

    fn state(&self) -> TxState {
        self.sender.transactions()[0].entry.state
    }

    fn pushed(&self) -> usize {
        self.sender.harness.node.pushed_transactions().len()
    }

    fn has_s3(&self) -> bool {
        let slate_id = self.sender.transactions()[0].entry.slate_id.unwrap();
        self.sender
            .read(|repos| repos.slate(slate_id, SlateStage::Standard3))
            .is_some()
    }

    /// The status of the funding output the send spends.
    fn input_status(&self) -> OutputStatus {
        self.sender
            .outputs()
            .into_iter()
            .find(|output| output.amount == Amount::new(FUNDING))
            .unwrap()
            .status
    }

    /// The outputs the send created: its change.
    fn created_outputs(&self) -> Vec<OutputStatus> {
        let tx_id = self.tx_id;
        self.sender
            .read(|repos| repos.outputs_of_transaction(tx_id))
            .into_iter()
            .filter(|output| output.amount != Amount::new(FUNDING))
            .map(|output| output.status)
            .collect()
    }

    /// Ended cancelled: nothing reached the node, the input is spendable again and the change
    /// is gone.
    fn assert_cancelled(&self) {
        assert_eq!(self.state(), TxState::Cancelled);
        assert_eq!(self.pushed(), 0);
        assert_eq!(self.input_status(), OutputStatus::Unspent);
        assert!(self.created_outputs().is_empty());
    }

    /// Ended posted: the node took the transaction once, and the wallet still holds the input
    /// locked and the change unconfirmed, so neither can be spent again.
    fn assert_posted(&self, pushed: usize) {
        assert_eq!(self.state(), TxState::Posted);
        assert_eq!(self.pushed(), pushed);
        assert!(self.has_s3());
        assert_eq!(self.input_status(), OutputStatus::Locked);
        assert_eq!(self.created_outputs(), vec![OutputStatus::Unconfirmed]);
    }
}

fn is_refused_transition(error: &WalletError, from: TxState) -> bool {
    matches!(
        error,
        WalletError::Transition(transition)
            if transition.from == from && transition.to == TxState::Cancelled
    )
}

/// Times the cancel is polled, with a yield to the blocking pool in between, while the
/// other call is held: enough for an unhindered cancel or finalize to finish.
const CANCEL_POLLS: usize = 200;

both_stores!(a_cancel_committed_while_finalize_waits_on_the_tip_keeps_the_send_cancelled);
fn a_cancel_committed_while_finalize_waits_on_the_tip_keeps_the_send_cancelled() {
    let race = Race::new(Held::Tip);

    let (finalized, cancelled) = race.cancel_while_finalize_is_held();

    cancelled.unwrap();
    let error = finalized.unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::NotFinalizable { tx_id, state: TxState::Cancelled }
                if tx_id == race.tx_id
        ),
        "{error:?}"
    );
    assert!(!race.has_s3());
    race.assert_cancelled();
}

both_stores!(a_post_while_cancel_waits_on_the_kernel_lookup_waits_and_pushes_nothing);
fn a_post_while_cancel_waits_on_the_kernel_lookup_waits_and_pushes_nothing() {
    let race = Race::new(Held::Kernel);
    race.sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    race.sender
        .harness
        .block_on(race.wallet.finalize(LOOPBACK, &race.s2, Propagation::Stem))
        .unwrap_err();
    assert_eq!(race.state(), TxState::Finalized);

    let (finalized, cancelled) = race.finalize_while_cancel_is_held();

    // The post waits for the cancel that started first, then finds the send cancelled and
    // leaves it with the wallet: the node never gets it.
    cancelled.unwrap();
    let error = finalized.unwrap_err();
    assert!(
        matches!(
            &error,
            FinalizeError::Wallet(WalletError::Transition(transition))
                if transition.from == TxState::Cancelled && transition.to == TxState::Posted
        ),
        "{error:?}"
    );
    race.assert_cancelled();
}

both_stores!(a_cancel_while_finalize_pushes_does_not_release_inputs_the_node_took);
fn a_cancel_while_finalize_pushes_does_not_release_inputs_the_node_took() {
    let race = Race::new(Held::Push);

    let (finalized, cancelled) = race.cancel_while_finalize_is_held();

    match (finalized, cancelled) {
        (Ok(finalized), Err(error)) => {
            assert!(finalized.pushed);
            assert!(
                matches!(
                    error,
                    WalletError::ChangedDuringCancel(_) | WalletError::InPool(_)
                ) || is_refused_transition(&error, TxState::Posted),
                "{error:?}"
            );
            race.assert_posted(1);
        }
        (Err(_), Ok(())) => race.assert_cancelled(),
        (finalized, cancelled) => panic!(
            "both or neither won: finalize {finalized:?}, cancel {cancelled:?}, state {:?}, \
             pushed {}, input {:?}",
            race.state(),
            race.pushed(),
            race.input_status()
        ),
    }
}
