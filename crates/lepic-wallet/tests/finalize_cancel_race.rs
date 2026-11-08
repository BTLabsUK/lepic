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

use std::path::Path;
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
use lepic_store::{
    OutputStatus, Repositories, SlateStage, StoreError, StoreKey, StoreKeys, TxId, TxState,
    WalletStore,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::finalize::{FinalizeError, Finalized};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Ports, StoreOpener, Wallet, WalletError};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP};
use support::{TestStore, TestStores, TestVault, both_stores, password};
use tokio::sync::{Notify, watch};

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

/// The test's stores, counting the write transactions that ended, so a race can wait for an
/// operation's commit instead of guessing how long the blocking pool takes to run it.
#[derive(Clone)]
struct CountedStores {
    inner: TestStores,
    writes: watch::Sender<u64>,
}

struct CountedStore {
    inner: TestStore,
    writes: watch::Sender<u64>,
}

impl StoreOpener for CountedStores {
    type Store = CountedStore;

    fn open(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<CountedStore, StoreError> {
        Ok(CountedStore {
            inner: self.inner.open(data_dir, keys, store_key)?,
            writes: self.writes.clone(),
        })
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Option<CountedStore>, StoreError> {
        Ok(self
            .inner
            .open_existing(data_dir, keys, store_key)?
            .map(|inner| CountedStore {
                inner,
                writes: self.writes.clone(),
            }))
    }
}

impl WalletStore for CountedStore {
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        self.inner.read(operation)
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let written = self.inner.write(operation);
        self.writes.send_modify(|writes| *writes += 1);
        written
    }
}

type GatedWallet = Wallet<GatedNode, CountedStores, TestVault>;

/// How far the second operation of a race runs while the first is held at the gate.
#[derive(Clone, Copy)]
enum Until {
    /// Until it commits its first write, or ends without one.
    Committed,
    /// Until it first waits: for the turn the held operation has, in the race that uses it.
    Waits,
}

/// A send delivered to a LEPIC receiver, its S2, and a second handle on the sender's wallet
/// whose node holds `held` at the returned gate.
struct Race {
    sender: Sender,
    tx_id: TxId,
    s2: WireSlate,
    wallet: GatedWallet,
    gate: Gate,
    writes: watch::Sender<u64>,
}

impl Race {
    fn new(held: Held) -> Self {
        let sender = Sender::new();
        let sent = sender
            .harness
            .block_on(sender.wallet.send(
                &sender.harness.method(),
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
        let (s1, _) = sender.received().unwrap();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;

        let harness = &sender.harness;
        let gate = Gate::default();
        let ports = harness.ports(harness.vault.clone());
        let writes = watch::Sender::new(0);
        let wallet = Wallet::new(
            harness.config(Network::Floonet),
            Ports {
                node: GatedNode {
                    inner: ports.node,
                    held,
                    gate: gate.clone(),
                },
                stores: CountedStores {
                    inner: ports.stores,
                    writes: writes.clone(),
                },
                secrets: ports.secrets,
                methods: ports.methods,
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
            writes,
        }
    }

    /// Runs `operation` while the other one is held, as far as `until` says, then lets the
    /// held one go on and finishes `operation`.
    async fn run_while_held<T>(&self, operation: impl Future<Output = T>, until: Until) -> T {
        let mut operation = std::pin::pin!(operation);
        let mut writes = self.writes.subscribe();
        let before = *writes.borrow_and_update();
        let early = match until {
            Until::Committed => tokio::select! {
                biased;
                done = &mut operation => Some(done),
                _ = writes.wait_for(|writes| *writes > before) => None,
            },
            Until::Waits => operation.as_mut().now_or_never(),
        };
        self.gate.release.notify_one();
        match early {
            Some(done) => done,
            None => operation.await,
        }
    }

    /// Starts the finalize and, while it is held at the gate, runs the cancel as far as
    /// `until` says, then lets the finalize go on.
    fn cancel_while_finalize_is_held(
        &self,
        until: Until,
    ) -> (Result<Finalized, FinalizeError>, Result<(), WalletError>) {
        self.gate.arm();
        let method = self.sender.harness.method();
        self.sender.harness.block_on(async {
            let finalize = self.wallet.finalize(&method, &self.s2, Propagation::Stem);
            let cancel = async {
                self.gate.reached.notified().await;
                self.run_while_held(self.wallet.cancel(self.tx_id), until)
                    .await
            };
            tokio::join!(finalize, cancel)
        })
    }

    /// Starts the cancel and, while it is held at the gate, runs the finalize until it commits,
    /// then lets the cancel go on.
    fn finalize_while_cancel_is_held(
        &self,
    ) -> (Result<Finalized, FinalizeError>, Result<(), WalletError>) {
        self.gate.arm();
        self.sender.harness.block_on(async {
            let cancel = self.wallet.cancel(self.tx_id);
            let finalize = async {
                self.gate.reached.notified().await;
                self.run_while_held(
                    self.wallet.finalize(
                        &self.sender.harness.method(),
                        &self.s2,
                        Propagation::Stem,
                    ),
                    Until::Committed,
                )
                .await
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

both_stores!(a_cancel_committed_while_finalize_waits_on_the_tip_keeps_the_send_cancelled);
fn a_cancel_committed_while_finalize_waits_on_the_tip_keeps_the_send_cancelled() {
    let race = Race::new(Held::Tip);

    // The cancel commits before the finalize reads the send.
    let (finalized, cancelled) = race.cancel_while_finalize_is_held(Until::Committed);

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
        .block_on(
            race.wallet
                .finalize(&race.sender.harness.method(), &race.s2, Propagation::Stem),
        )
        .unwrap_err();
    assert_eq!(race.state(), TxState::Finalized);

    let (finalized, cancelled) = race.finalize_while_cancel_is_held();

    // The finalize read the send as finalized and committed before the cancel went on; its
    // post waits for the cancel that started first, then finds the send cancelled and leaves
    // it with the wallet: the node never gets it.
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

    // The cancel waits for the posting turn the held push has.
    let (finalized, cancelled) = race.cancel_while_finalize_is_held(Until::Waits);

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
