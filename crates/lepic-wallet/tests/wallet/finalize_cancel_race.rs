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

use crate::receive_harness;
use crate::send_support;
use crate::support;

use std::fmt::Debug;
use std::path::Path;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use futures_util::FutureExt as _;
use lepic_crypto::Commitment;
use lepic_node::mock::{ChainOutput, MockFailure, MockNode};
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
use lepic_transport::method::Method;
use lepic_transport::transport::Destination;
use lepic_wallet::finalize::{FinalizeError, Finalized};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Ports, SharedRng, StoreOpener, Wallet, WalletError};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP};
use support::{TestStore, TestStores, TestVault, both_stores, password};
use tokio::sync::{Notify, watch};

const AMOUNT: u64 = 100_000_000;

/// The receiver of the G-03 cases.
const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The receiver of a second send, so its output differs from the first one's.
const OTHER_RECEIVER_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo zoo vote";

/// The second send's funding, an amount apart from [`FUNDING`].
const SPARE: u64 = 2 * FUNDING;

/// Waits until `held` reaches its gate, and fails the test instead of hanging it when `held`
/// ends before.
async fn until_reached<T: Debug>(
    held: Pin<&mut impl Future<Output = T>>,
    reached: impl Future<Output = ()>,
) {
    tokio::select! {
        biased;
        () = reached => {}
        done = held => panic!("ended before reaching its gate: {done:?}"),
    }
}

/// Waits for `reached`, and fails the test with `what` instead of hanging it when `reached` has
/// not come after a minute. The harness runtime runs no timer, so a thread keeps the time.
async fn within_a_minute(what: &str, reached: impl Future<Output = ()>) {
    let (expired, deadline) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(60));
        let _ = expired.send(());
    });
    tokio::select! {
        biased;
        () = reached => {}
        _ = deadline => panic!("{what}"),
    }
}

/// Notifies when a span named `name` is left for the first time. For an instrumented future
/// that is when its first poll returns, so the test knows the future waits on what it awaited
/// first.
struct SpanLeft {
    name: &'static str,
    left: Arc<Notify>,
    spans: Mutex<Vec<&'static str>>,
}

impl SpanLeft {
    fn new(name: &'static str, left: Arc<Notify>) -> Self {
        Self {
            name,
            left,
            spans: Mutex::new(Vec::new()),
        }
    }
}

impl tracing::Subscriber for SpanLeft {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut spans = self.spans.lock().unwrap();
        spans.push(span.metadata().name());
        tracing::span::Id::from_u64(u64::try_from(spans.len()).unwrap())
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, span: &tracing::span::Id) {
        let index = usize::try_from(span.into_u64()).unwrap() - 1;
        if self.spans.lock().unwrap()[index] == self.name {
            self.left.notify_one();
        }
    }
}

/// The node call a [`GatedNode`] holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    /// `get_tip` is answered, and the answer handed back once released.
    Tip,
    /// `get_kernel` is answered, and the answer handed back once released.
    Kernel,
    /// `push_transaction` reaches the node only once released.
    Push,
    /// `get_unconfirmed_transactions` is answered, and the answer handed back once released.
    Pool,
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
        let hold = self.held == Held::Pool && self.gate.take();
        let gate = self.gate.clone();
        let answer = self.inner.get_unconfirmed_transactions();
        async move {
            let answer = answer.await;
            if hold {
                gate.hold().await;
            }
            answer
        }
    }
}

/// Where a [`CountedStore`] holds the blocking thread of the first write committed after
/// [`WriteGate::arm`], so another wallet operation runs between that commit and what the
/// writer does after it.
#[derive(Clone, Default)]
struct WriteGate {
    /// Notified when the held write has committed and waits.
    reached: Arc<Notify>,
    released: Arc<(Mutex<bool>, Condvar)>,
    armed: Arc<AtomicBool>,
}

impl WriteGate {
    /// Arms the gate once: after a release it would not hold, and the test would check nothing.
    fn arm(&self) {
        assert!(
            !*self.released.0.lock().unwrap(),
            "the write gate was already released"
        );
        assert!(
            !self.armed.swap(true, Ordering::SeqCst),
            "the write gate is already armed"
        );
    }

    /// Holds the calling thread when this write is the one to hold, until [`Self::release`].
    fn hold_if_armed(&self) {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return;
        }
        self.reached.notify_one();
        let (released, wake) = &*self.released;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
    }

    fn release(&self) {
        let (released, wake) = &*self.released;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
}

/// The test's stores, counting the write transactions that ended, so a race can wait for an
/// operation's commit instead of guessing how long the blocking pool takes to run it.
#[derive(Clone)]
struct CountedStores {
    inner: TestStores,
    writes: watch::Sender<u64>,
    gate: WriteGate,
}

struct CountedStore {
    inner: TestStore,
    writes: watch::Sender<u64>,
    gate: WriteGate,
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
            gate: self.gate.clone(),
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
                gate: self.gate.clone(),
            }))
    }

    fn start_over(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<(CountedStore, Option<lepic_store::AtRestReport>), StoreError> {
        let (inner, report) = self.inner.start_over(data_dir, keys, store_key)?;
        let store = CountedStore {
            inner,
            writes: self.writes.clone(),
            gate: self.gate.clone(),
        };
        Ok((store, report))
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
        self.gate.hold_if_armed();
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
    /// The sender's end of the loopback its peer reads, kept as the gated wallet's ports make
    /// a new pair.
    delivers: Arc<dyn Method>,
    tx_id: TxId,
    s2: WireSlate,
    wallet: GatedWallet,
    gate: Gate,
    writes: watch::Sender<u64>,
    write_gate: WriteGate,
}

impl Drop for Race {
    /// Lets a write held at the gate go on, so a race that fails ends instead of waiting on it.
    fn drop(&mut self) {
        self.write_gate.release();
    }
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
        let delivers = harness.method();
        let gate = Gate::default();
        let ports = harness.ports(harness.vault.clone());
        let writes = watch::Sender::new(0);
        let write_gate = WriteGate::default();
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
                    gate: write_gate.clone(),
                },
                secrets: ports.secrets,
                methods: ports.methods,
                clock: ports.clock,
                // Its own draws, so a slate it makes does not repeat one the sender made.
                rng: SharedRng::new(StdRng::seed_from_u64(43)),
                runtime: ports.runtime,
            },
        )
        .unwrap();
        harness.block_on(wallet.open(password("sender"))).unwrap();
        Self {
            sender,
            delivers,
            tx_id: sent.tx_id,
            s2,
            wallet,
            gate,
            writes,
            write_gate,
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
            let mut finalize = pin!(self.wallet.finalize(&method, &self.s2, Propagation::Stem));
            until_reached(finalize.as_mut(), self.gate.reached.notified()).await;
            let cancel = self.run_while_held(self.wallet.cancel(self.tx_id), until);
            tokio::join!(finalize, cancel)
        })
    }

    /// Starts the cancel and, while it is held at the gate, runs the finalize until it commits,
    /// then lets the cancel go on.
    fn finalize_while_cancel_is_held(
        &self,
    ) -> (Result<Finalized, FinalizeError>, Result<(), WalletError>) {
        self.gate.arm();
        let method = self.sender.harness.method();
        self.sender.harness.block_on(async {
            let mut cancel = pin!(self.wallet.cancel(self.tx_id));
            until_reached(cancel.as_mut(), self.gate.reached.notified()).await;
            let finalize = self.run_while_held(
                self.wallet.finalize(&method, &self.s2, Propagation::Stem),
                Until::Committed,
            );
            let (cancelled, finalized) = tokio::join!(cancel, finalize);
            (finalized, cancelled)
        })
    }

    fn state(&self) -> TxState {
        self.sender.transactions()[0].entry.state
    }

    fn state_of(&self, tx_id: TxId) -> TxState {
        self.sender
            .transactions()
            .into_iter()
            .find(|transaction| transaction.id == tx_id)
            .unwrap()
            .entry
            .state
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

    /// Puts the funding output on the node's chain, so a refresh finds the send's input
    /// unspent there.
    fn fund_on_chain(&self) {
        self.put_on_chain(FUNDING, 1);
    }

    /// Puts the sender's output of `value` on the node's chain at `mmr_index`.
    fn put_on_chain(&self, value: u64, mmr_index: u64) {
        let funding = self
            .sender
            .outputs()
            .into_iter()
            .find(|output| output.amount == Amount::new(value))
            .unwrap();
        self.sender.harness.node.update_chain(|chain| {
            crate::support::mine_output(
                chain,
                ChainOutput {
                    commitment: funding.id.commitment,
                    features: funding.id.features,
                    proof: support::some_proof(),
                    height: Height::new(1),
                    mmr_index,
                    spent: false,
                },
            );
        });
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

both_stores!(a_post_while_a_refresh_reads_the_pool_is_not_pushed_again_by_the_refresh);
fn a_post_while_a_refresh_reads_the_pool_is_not_pushed_again_by_the_refresh() {
    let race = Race::new(Held::Pool);
    race.fund_on_chain();
    let harness = &race.sender.harness;
    harness
        .block_on(
            race.wallet
                .finalize(&harness.method(), &race.s2, Propagation::Stem),
        )
        .unwrap();
    // Missing from the pool ten blocks after the accepted push, so a refresh pushes it again.
    harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 10));

    // The refresh found the send due and reads the pool while the user posts it.
    race.gate.arm();
    let (refreshed, posted) = harness.block_on(async {
        let mut refresh = pin!(race.wallet.refresh());
        until_reached(refresh.as_mut(), race.gate.reached.notified()).await;
        let posted = race.wallet.post(race.tx_id, Propagation::Stem).await;
        race.gate.release.notify_one();
        (refresh.await, posted)
    });

    refreshed.unwrap();
    posted.unwrap();
    // Once by the finalize and once by the post: the refresh sees the post's push in the record
    // and leaves the send to the next recheck.
    race.assert_posted(2);
}

both_stores!(a_refresh_while_a_finalize_stores_its_send_leaves_the_first_push_to_the_finalize);
fn a_refresh_while_a_finalize_stores_its_send_leaves_the_first_push_to_the_finalize() {
    let race = Race::new(Held::Push);
    race.fund_on_chain();
    let harness = &race.sender.harness;

    // The finalize has stored the send as finalized and not pushed it yet when the refresh
    // runs.
    let method = harness.method();
    race.write_gate.arm();
    let (finalized, refreshed) = harness.block_on(async {
        let mut finalize = pin!(race.wallet.finalize(&method, &race.s2, Propagation::Stem));
        until_reached(finalize.as_mut(), race.write_gate.reached.notified()).await;
        let refreshed = race.wallet.refresh().await;
        race.write_gate.release();
        (finalize.await, refreshed)
    });

    refreshed.unwrap();
    assert!(finalized.unwrap().pushed);
    race.assert_posted(1);
}

both_stores!(a_finalize_storing_one_send_does_not_stop_a_refresh_pushing_another);
fn a_finalize_storing_one_send_does_not_stop_a_refresh_pushing_another() {
    let race = Race::new(Held::Push);
    race.fund_on_chain();
    let harness = &race.sender.harness;
    let method = harness.method();

    // The first send is stored finalized and never pushed: its finalize was dropped while it
    // waited on the node.
    race.gate.arm();
    harness.block_on(async {
        let mut finalize = pin!(race.wallet.finalize(&method, &race.s2, Propagation::Stem));
        until_reached(finalize.as_mut(), race.gate.reached.notified()).await;
    });
    assert_eq!(race.state_of(race.tx_id), TxState::Finalized);
    assert_eq!(race.pushed(), 0);

    // A second send from other funds, answered by another receiver.
    race.sender.fund(1, SPARE);
    race.put_on_chain(SPARE, 2);
    let other = harness
        .block_on(race.sender.wallet.send(
            &race.delivers,
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
    let (s1, _) = race.sender.received().unwrap();
    let s2 = Receiver::new(OTHER_RECEIVER_MNEMONIC, TIP)
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;

    // The refresh runs while the second send's finalize has stored it and not pushed it yet.
    race.write_gate.arm();
    let (finalized, refreshed) = harness.block_on(async {
        let mut finalize = pin!(race.wallet.finalize(&method, &s2, Propagation::Stem));
        until_reached(finalize.as_mut(), race.write_gate.reached.notified()).await;
        let refreshed = race.wallet.refresh().await;
        race.write_gate.release();
        (finalize.await, refreshed)
    });

    refreshed.unwrap();
    assert!(finalized.unwrap().pushed);
    // The refresh pushed the first send; the finalize pushed the second.
    assert_eq!(race.state_of(race.tx_id), TxState::Posted);
    assert_eq!(race.state_of(other.tx_id), TxState::Posted);
    assert_eq!(race.pushed(), 2);
}

both_stores!(a_refresh_while_a_recover_stores_its_recovery_leaves_one_push);
fn a_refresh_while_a_recover_stores_its_recovery_leaves_one_push() {
    let race = Race::new(Held::Push);
    race.fund_on_chain();
    let harness = &race.sender.harness;
    let method = harness.method();

    // The payment the node refused, which the recover spends back.
    harness
        .node
        .fail_next("push_transaction", MockFailure::PoolRefused);
    let error = harness
        .block_on(race.wallet.finalize(&method, &race.s2, Propagation::Stem))
        .unwrap_err();
    assert!(
        matches!(error, FinalizeError::NotPosted { .. }),
        "{error:?}"
    );
    let pushed = race.pushed();

    // The refresh finds the recovery due after the recover stored it and waits to push it
    // before the recover pushes it.
    let waits = Arc::new(Notify::new());
    let _spans = tracing::subscriber::set_default(SpanLeft::new("push_again", Arc::clone(&waits)));
    race.write_gate.arm();
    let (recovered, refreshed) = harness.block_on(async {
        let mut recover = pin!(race.wallet.recover(race.tx_id));
        until_reached(recover.as_mut(), race.write_gate.reached.notified()).await;
        let mut refresh = pin!(race.wallet.refresh());
        until_reached(
            refresh.as_mut(),
            within_a_minute("the refresh never left span push_again", waits.notified()),
        )
        .await;
        race.write_gate.release();
        tokio::join!(recover, refresh)
    });

    refreshed.unwrap();
    recovered.unwrap();
    assert_eq!(race.pushed(), pushed + 1);
}
