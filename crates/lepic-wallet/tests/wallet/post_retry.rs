// SPDX-License-Identifier: Apache-2.0
//! Pushing a finalized transaction again at refresh until it is mined or its cutoff passes, and
//! ending a send at its cutoff only when the node's own pool refused every push of it.

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

use std::ops::RangeInclusive;
use std::sync::PoisonError;

use lepic_crypto::Commitment;
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, Propagation, RejectionKind};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_primitives::tx::{Transaction, TransactionBody};
use lepic_slate::codec::WireSlate;
use lepic_store::{NodeOutcome, NodePost, OutputStatus, TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::loopback::LoopbackTransport;
use lepic_transport::transport::{Destination, Inbound as _};
use lepic_wallet::details::{ExpiredReason, TransactionDetails};
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, Finalized, WalletConfig};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP};
use support::both_stores;
use support::{Harness, TestWallet, password};

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The wallet-local limit of every send here, in blocks past the tip it was made at.
const CUTOFF_BLOCKS: u64 = 100;

/// The height from which the wallet no longer posts a send made at [`TIP`].
pub(crate) const CUTOFF: u64 = TIP + CUTOFF_BLOCKS;

pub(crate) const PUSH: &str = "push_transaction";

/// The text the mock node's pool answers a transaction it cannot validate with.
const POOL_TEXT: &str = "failed to validate tx";

/// The fee of a send of one input into the receiver's output alone: weight 4, at the floonet
/// base fee of 100,000.
const NO_CHANGE_FEE: u64 = 400_000;

fn request(amount: Amount) -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        local_ttl_blocks: Some(CUTOFF_BLOCKS),
        ..SendRequest::new(ACCOUNT, amount)
    }
}

/// The sender with `count` coinbase outputs of [`FUNDING`] on the mock chain, refreshed at
/// [`TIP`], and the wallet that answers its sends.
pub(crate) fn funded(count: u32) -> (Sender, Receiver) {
    let sender = Sender::new();
    for child in 1..count {
        sender.fund(child, FUNDING);
    }
    let outputs = sender.outputs();
    sender.harness.node.update_chain(|chain| {
        for (position, output) in outputs.iter().enumerate() {
            crate::support::mine_output(
                chain,
                ChainOutput {
                    commitment: output.id.commitment,
                    features: output.id.features,
                    proof: support::some_proof(),
                    height: Height::new(1),
                    mmr_index: 1 + position as u64,
                    spent: false,
                },
            );
        }
    });
    refreshed(&sender.harness, &sender.wallet);
    (sender, Receiver::new(RECEIVER_MNEMONIC, TIP))
}

fn refreshed(harness: &Harness, wallet: &TestWallet) {
    let outcome = harness.block_on(wallet.refresh()).unwrap();
    assert!(
        matches!(outcome, RefreshOutcome::Refreshed(_)),
        "{outcome:?}"
    );
}

/// A send from `wallet` to the peer at the other end of `peer`, and the receiver's S2.
fn answered_send(
    harness: &Harness,
    wallet: &TestWallet,
    peer: &LoopbackTransport,
    receiver: &Receiver,
) -> (TxId, WireSlate) {
    answered_send_of(harness, wallet, peer, receiver, Amount::new(AMOUNT))
}

/// As [`answered_send`], of `amount`.
fn answered_send_of(
    harness: &Harness,
    wallet: &TestWallet,
    peer: &LoopbackTransport,
    receiver: &Receiver,
    amount: Amount,
) -> (TxId, WireSlate) {
    let sent = harness
        .block_on(wallet.send(
            &harness.method(),
            request(amount),
            Delivery::Deliver {
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let s1 = harness
        .block_on(peer.next_envelope())
        .unwrap()
        .unwrap()
        .wire()
        .clone();
    let s2 = receiver
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;
    (sent.tx_id, s2)
}

fn finalize(
    harness: &Harness,
    wallet: &TestWallet,
    s2: &WireSlate,
) -> Result<Finalized, FinalizeError> {
    harness.block_on(wallet.finalize(&harness.method(), s2, Propagation::Stem))
}

/// The wallet opened again, `offline` or not, as the app does on a mode change, and the other
/// end of its loopback transport.
pub(crate) fn reopened(sender: &Sender, offline: bool) -> (TestWallet, LoopbackTransport) {
    sender.wallet.lock();
    let harness = &sender.harness;
    let config = WalletConfig {
        offline,
        ..harness.config(Network::Floonet)
    };
    let wallet = harness.wallet_with(config, harness.vault.clone());
    harness.block_on(wallet.open(password("sender"))).unwrap();
    let peer = harness
        .peer
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap();
    (wallet, peer)
}

/// One send of the funded sender, answered, and the coinbase output it spends.
pub(crate) struct Retrying {
    pub(crate) sender: Sender,
    pub(crate) tx_id: TxId,
    s2: WireSlate,
    pub(crate) funding: Commitment,
}

impl Retrying {
    pub(crate) fn answered() -> Self {
        let (sender, receiver) = funded(1);
        let funding = sender.outputs()[0].id.commitment;
        let (tx_id, s2) = answered_send(&sender.harness, &sender.wallet, &sender.peer, &receiver);
        Self {
            sender,
            tx_id,
            s2,
            funding,
        }
    }

    /// As [`Self::failing`], next to a second send of the same sender, answered and still
    /// open, that holds the other of two funding outputs locked. Returns that send's id.
    pub(crate) fn failing_beside_another(failure: MockFailure) -> (Self, TxId) {
        let (sender, receiver) = funded(2);
        let (tx_id, s2) = answered_send(&sender.harness, &sender.wallet, &sender.peer, &receiver);
        let (other, _) = answered_send(&sender.harness, &sender.wallet, &sender.peer, &receiver);
        let funding = sender
            .outputs()
            .into_iter()
            .find(|output| output.tx == Some(tx_id) && output.status == OutputStatus::Locked)
            .unwrap()
            .id
            .commitment;
        let retrying = Self {
            sender,
            tx_id,
            s2,
            funding,
        };
        retrying.fail_once_finalized(failure);
        (retrying, other)
    }

    /// A send whose every push fails with `failure`, now `finalized` with one push recorded at
    /// [`TIP`].
    pub(crate) fn failing(failure: MockFailure) -> Self {
        let retrying = Self::answered();
        retrying.fail_once_finalized(failure);
        retrying
    }

    /// As [`Self::failing`], for a send of the whole funding less its fee: it has no change.
    pub(crate) fn failing_without_change(failure: MockFailure) -> Self {
        let (sender, receiver) = funded(1);
        let funding = sender.outputs()[0].id.commitment;
        let amount = Amount::new(FUNDING - NO_CHANGE_FEE);
        let (tx_id, s2) = answered_send_of(
            &sender.harness,
            &sender.wallet,
            &sender.peer,
            &receiver,
            amount,
        );
        let retrying = Self {
            sender,
            tx_id,
            s2,
            funding,
        };
        retrying.fail_once_finalized(failure);
        retrying
    }

    fn fail_once_finalized(&self, failure: MockFailure) {
        self.node().fail_every(PUSH, failure);
        let error = self.finalize().unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        assert_eq!(self.state(), TxState::Finalized);
        assert_eq!(self.record().last_height, Height::new(TIP));
    }

    /// A send the node accepted at [`TIP`], now `posted`.
    pub(crate) fn posted() -> Self {
        let retrying = Self::answered();
        retrying.finalize().unwrap();
        assert_eq!(retrying.state(), TxState::Posted);
        retrying
    }

    pub(crate) fn node(&self) -> &lepic_node::mock::MockNode {
        &self.sender.harness.node
    }

    pub(crate) fn finalize(&self) -> Result<Finalized, FinalizeError> {
        finalize(&self.sender.harness, &self.sender.wallet, &self.s2)
    }

    pub(crate) fn post(&self) -> Result<lepic_wallet::finalize::Posted, FinalizeError> {
        self.sender
            .harness
            .block_on(self.sender.wallet.post(self.tx_id, Propagation::Stem))
    }

    pub(crate) fn state(&self) -> TxState {
        self.sender
            .read(|repos| repos.transaction(self.tx_id))
            .unwrap()
            .state
    }

    pub(crate) fn record(&self) -> NodePost {
        self.sender
            .read(|repos| repos.node_post(self.tx_id))
            .unwrap()
    }

    pub(crate) fn details(&self) -> TransactionDetails {
        self.sender
            .harness
            .block_on(self.sender.wallet.transaction_details(self.tx_id))
            .unwrap()
    }

    pub(crate) fn funding_status(&self) -> OutputStatus {
        self.sender
            .outputs()
            .into_iter()
            .find(|output| output.id.commitment == self.funding)
            .unwrap()
            .status
    }

    /// Pushes the node was asked for so far, failed ones included.
    pub(crate) fn pushes(&self) -> usize {
        pushes(self.node())
    }

    /// The node's tip moves to `height` and the wallet refreshes. Every step here stays within
    /// the blocks a refresh confirms at once.
    pub(crate) fn at(&self, height: u64) {
        self.node()
            .update_chain(|chain| chain.tip.height = Height::new(height));
        refreshed(&self.sender.harness, &self.sender.wallet);
    }

    /// Refreshes at every height of `heights` and returns those at which the wallet pushed.
    pub(crate) fn walk(&self, heights: RangeInclusive<u64>) -> Vec<u64> {
        let mut pushed_at = Vec::new();
        for height in heights {
            let before = self.pushes();
            self.at(height);
            let pushed = self.pushes() - before;
            assert!(pushed <= 1, "{pushed} pushes at {height}");
            if pushed == 1 {
                pushed_at.push(height);
            }
        }
        pushed_at
    }

    /// The send's transaction as the wallet finalized it.
    pub(crate) fn final_transaction(&self) -> Transaction {
        let finished = self
            .sender
            .harness
            .block_on(self.sender.wallet.finished_payment(self.tx_id))
            .unwrap();
        let slate = send_support::legacy_codecs().decode(&finished).unwrap();
        let kernel = slate.kernel().unwrap();
        Transaction::new(
            slate.offset().clone(),
            TransactionBody::new(
                slate.inputs().to_vec(),
                slate.outputs().to_vec(),
                vec![kernel],
            ),
        )
    }

    pub(crate) fn kernel_at(&self, height: u64) -> LocatedKernel {
        LocatedKernel {
            kernel: self.final_transaction().kernels()[0],
            height: Height::new(height),
            mmr_index: 100,
        }
    }

    /// A miner includes the send's `transaction` at `height`: its input is spent and its
    /// outputs and kernel are on chain.
    pub(crate) fn mined_at(&self, transaction: &Transaction, height: u64) {
        let kernel = LocatedKernel {
            kernel: transaction.kernels()[0],
            height: Height::new(height),
            mmr_index: 100,
        };
        self.node().update_chain(|chain| {
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
                        mmr_index: 100 + position as u64,
                        spent: false,
                    },
                );
            }
            chain.kernels.push(kernel);
        });
    }

    /// Another wallet on the same recovery phrase spent the send's input.
    pub(crate) fn input_spent_elsewhere(&self) {
        let funding = self.funding;
        self.node().update_chain(|chain| {
            chain.outputs.retain(|output| output.commitment != funding);
        });
    }

    /// The send stays as it is through refreshes up to and past its cutoff, its input locked.
    pub(crate) fn stays_open_past_the_cutoff(&self) {
        let state = self.state();
        for height in [TIP + 50, CUTOFF - 1, CUTOFF, CUTOFF + 5] {
            self.at(height);
            assert_eq!(self.state(), state, "at {height}");
        }
        assert_eq!(self.funding_status(), OutputStatus::Locked);
        assert_eq!(self.details().expired_reason, None);
    }
}

fn pushes(node: &lepic_node::mock::MockNode) -> usize {
    node.calls().iter().filter(|method| *method == PUSH).count()
}

fn not_posted_events(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<TxId> {
    let mut not_posted = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::NotPosted(event) = event {
            not_posted.push(event.tx_id);
        }
    }
    not_posted
}

// Pushing again.

both_stores!(a_failed_send_is_pushed_again_with_a_growing_backoff_until_its_cutoff);
fn a_failed_send_is_pushed_again_with_a_growing_backoff_until_its_cutoff() {
    let retrying = Retrying::failing(MockFailure::HttpStatus(502));

    let pushed_at = retrying.walk(TIP + 1..=CUTOFF + 30);

    // After 1, 2, 4, 8 and 16 blocks, then every 30. The push due at TIP + 121 is past the
    // cutoff.
    assert_eq!(
        pushed_at,
        [1, 3, 7, 15, 31, 61, 91].map(|blocks| TIP + blocks)
    );
    let record = retrying.record();
    assert_eq!(record.attempts, 8);
    assert_eq!(record.last_height, Height::new(TIP + 91));
    assert_eq!(record.last_outcome, NodeOutcome::Unreachable);
    assert_eq!(retrying.state(), TxState::Finalized);
    assert_eq!(retrying.funding_status(), OutputStatus::Locked);
}

/// A send the pool refused at finalizing, which the node takes at the first push again.
fn accepted_after_a_refusal() -> Retrying {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    let refused = retrying.record();
    assert_eq!(refused.last_outcome, NodeOutcome::Refused);
    assert!(
        refused.last_error.as_deref().unwrap().contains(POOL_TEXT),
        "{refused:?}"
    );
    retrying.node().stop_failing(PUSH);

    retrying.at(TIP + 1);

    assert_eq!(retrying.state(), TxState::Posted);
    retrying
}

both_stores!(an_accepted_push_keeps_the_text_of_the_refusal_before_it);
fn an_accepted_push_keeps_the_text_of_the_refusal_before_it() {
    let retrying = accepted_after_a_refusal();

    let record = retrying.record();
    assert_eq!(record.attempts, 2);
    assert_eq!(record.last_outcome, NodeOutcome::Accepted);
    assert_eq!(record.last_height, Height::new(TIP + 1));
    assert!(record.accepted_once);
    assert!(
        record.last_error.as_deref().unwrap().contains(POOL_TEXT),
        "{record:?}"
    );
}

both_stores!(an_accepted_push_ends_the_retries_while_the_pool_holds_the_send);
fn an_accepted_push_ends_the_retries_while_the_pool_holds_the_send() {
    let retrying = accepted_after_a_refusal();
    let pushed = retrying.node().pushed_transactions();
    retrying.node().update_chain(|chain| chain.pool = pushed);

    let pushed_at = retrying.walk(TIP + 2..=TIP + 40);

    assert_eq!(pushed_at, Vec::<u64>::new());
    assert_eq!(retrying.state(), TxState::Posted);
}

both_stores!(a_posted_send_missing_from_the_pool_is_pushed_again_ten_blocks_later);
fn a_posted_send_missing_from_the_pool_is_pushed_again_ten_blocks_later() {
    let retrying = Retrying::posted();
    assert_eq!(retrying.pushes(), 1);

    retrying.at(TIP + 9);
    assert_eq!(retrying.pushes(), 1, "pushed again before ten blocks");
    retrying.at(TIP + 10);
    assert_eq!(retrying.pushes(), 2);

    // Due again at TIP + 20, but the pool now holds it.
    let pushed = retrying.node().pushed_transactions();
    retrying.node().update_chain(|chain| chain.pool = pushed);
    retrying.at(TIP + 20);
    retrying.at(TIP + 30);
    assert_eq!(retrying.pushes(), 2, "a send in the pool was pushed again");
    assert_eq!(retrying.state(), TxState::Posted);
}

both_stores!(an_unreachable_node_costs_one_push_per_refresh);
fn an_unreachable_node_costs_one_push_per_refresh() {
    let (sender, receiver) = funded(3);
    let harness = &sender.harness;
    harness.node.fail_every(PUSH, MockFailure::Unreachable);
    let mut sends = Vec::new();
    for _ in 0..3 {
        let (tx_id, s2) = answered_send(harness, &sender.wallet, &sender.peer, &receiver);
        let error = finalize(harness, &sender.wallet, &s2).unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        sends.push(tx_id);
    }
    assert_eq!(pushes(&harness.node), 3);

    harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 1));
    refreshed(harness, &sender.wallet);

    assert_eq!(pushes(&harness.node), 4, "all three are due, one is pushed");
    let attempts: Vec<u32> = sends
        .iter()
        .map(|tx_id| {
            sender
                .read(|repos| repos.node_post(*tx_id))
                .unwrap()
                .attempts
        })
        .collect();
    assert_eq!(
        attempts.iter().filter(|attempts| **attempts == 2).count(),
        1
    );
}

both_stores!(a_push_at_refresh_the_node_refuses_for_a_spent_input_ends_the_send);
fn a_push_at_refresh_the_node_refuses_for_a_spent_input_ends_the_send() {
    let retrying = Retrying::failing(MockFailure::HttpStatus(502));
    retrying.input_spent_elsewhere();
    retrying.node().fail_every(PUSH, MockFailure::PoolRefused);
    // A refused pool read keeps the refresh's own check for spent inputs from ending the send
    // first, so the push is what finds them gone.
    // The cancel that ends the send reads the pool again, and gets its answer.
    retrying.node().fail_next(
        "get_unconfirmed_transactions",
        MockFailure::Rejected(RejectionKind::Internal),
    );
    let before = retrying.pushes();

    retrying.at(TIP + 1);

    assert_eq!(retrying.pushes(), before + 1);
    assert_eq!(retrying.state(), TxState::Cancelled);
}

both_stores!(a_node_behind_the_wallet_ends_no_send_it_refuses_for_inputs_it_lacks);
fn a_node_behind_the_wallet_ends_no_send_it_refuses_for_inputs_it_lacks() {
    let retrying = Retrying::failing(MockFailure::HttpStatus(502));
    retrying.at(TIP + 5);
    retrying.input_spent_elsewhere();
    retrying.node().fail_every(PUSH, MockFailure::PoolRefused);
    retrying
        .node()
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 2));

    let error = retrying.post().unwrap_err();

    assert!(
        matches!(error, FinalizeError::NotPosted { .. }),
        "{error:?}"
    );
    assert_eq!(retrying.state(), TxState::Finalized);
    assert_eq!(retrying.funding_status(), OutputStatus::Locked);

    // The same refusal from a node at the wallet's height ends it.
    retrying
        .node()
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 5));
    let error = retrying.post().unwrap_err();
    assert!(
        matches!(error, FinalizeError::InputsSpentElsewhere { .. }),
        "{error:?}"
    );
    assert_eq!(retrying.state(), TxState::Cancelled);
}

both_stores!(the_host_hears_of_a_failed_push_once_until_its_text_changes);
fn the_host_hears_of_a_failed_push_once_until_its_text_changes() {
    let retrying = Retrying::answered();
    let mut events = retrying.sender.wallet.subscribe();
    retrying
        .node()
        .fail_every(PUSH, MockFailure::Internal("node busy"));
    retrying.finalize().unwrap_err();
    retrying.at(TIP + 1);
    retrying.at(TIP + 3);
    assert_eq!(retrying.record().attempts, 3);
    assert_eq!(not_posted_events(&mut events), [retrying.tx_id]);

    retrying
        .node()
        .fail_every(PUSH, MockFailure::Internal("node shutting down"));
    retrying.at(TIP + 7);

    assert_eq!(retrying.record().attempts, 4);
    assert_eq!(not_posted_events(&mut events), [retrying.tx_id]);
}

// Ending at the cutoff.

both_stores!(a_send_the_pool_refused_every_time_expires_at_its_cutoff_and_stays_watched);
fn a_send_the_pool_refused_every_time_expires_at_its_cutoff_and_stays_watched() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    // Taken now: an expired send has no finished payment to read.
    let transaction = retrying.final_transaction();
    let mut events = retrying.sender.wallet.subscribe();

    retrying.at(TIP + 50);
    retrying.at(CUTOFF - 1);
    assert_eq!(retrying.state(), TxState::Finalized);
    assert!(retrying.record().attempts > 1);
    retrying.at(CUTOFF);

    assert_eq!(retrying.state(), TxState::Expired);
    let details = retrying.details();
    assert_eq!(details.expired_reason, Some(ExpiredReason::RejectedByNode));
    assert_eq!(details.post_cutoff_height, None);
    assert_eq!(retrying.funding_status(), OutputStatus::Unspent);
    let changes: Vec<(TxState, TxState)> = std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::Transaction(change) => Some((change.from, change.to)),
            _ => None,
        })
        .collect();
    assert_eq!(changes, [(TxState::Finalized, TxState::Expired)]);

    // Another node had taken it after all, and a miner included it.
    retrying.mined_at(&transaction, CUTOFF + 1);
    retrying.at(CUTOFF + 1);
    retrying.at(CUTOFF + 2);

    assert_eq!(retrying.state(), TxState::Confirmed);
    assert_eq!(retrying.details().expired_reason, None);
}

both_stores!(a_send_the_node_once_accepted_stays_posted_past_its_cutoff);
fn a_send_the_node_once_accepted_stays_posted_past_its_cutoff() {
    let retrying = Retrying::posted();
    retrying.node().fail_every(PUSH, MockFailure::PoolRefused);
    // Dropped from the pool: pushed again ten blocks later and refused.
    retrying.at(TIP + 10);
    let record = retrying.record();
    assert_eq!(record.last_outcome, NodeOutcome::Refused);
    assert!(record.accepted_once);

    retrying.stays_open_past_the_cutoff();
}

both_stores!(one_unreachable_answer_among_refusals_keeps_a_send_open_past_its_cutoff);
fn one_unreachable_answer_among_refusals_keeps_a_send_open_past_its_cutoff() {
    let retrying = Retrying::answered();
    retrying.node().fail_next(PUSH, MockFailure::PoolRefused);
    retrying
        .node()
        .fail_next(PUSH, MockFailure::HttpStatus(502));
    retrying.node().fail_every(PUSH, MockFailure::PoolRefused);
    retrying.finalize().unwrap_err();
    retrying.at(TIP + 1);
    retrying.at(TIP + 3);
    let record = retrying.record();
    assert_eq!(record.attempts, 3);
    assert_eq!(record.last_outcome, NodeOutcome::Refused);
    assert!(record.unreachable_once);

    retrying.stays_open_past_the_cutoff();
}

both_stores!(a_proxy_timeout_keeps_a_send_open_past_its_cutoff);
fn a_proxy_timeout_keeps_a_send_open_past_its_cutoff() {
    Retrying::failing(MockFailure::HttpStatus(504)).stays_open_past_the_cutoff();
}

both_stores!(a_node_timeout_keeps_a_send_open_past_its_cutoff);
fn a_node_timeout_keeps_a_send_open_past_its_cutoff() {
    Retrying::failing(MockFailure::Timeout).stays_open_past_the_cutoff();
}

both_stores!(an_unknown_node_error_keeps_a_send_open_past_its_cutoff);
fn an_unknown_node_error_keeps_a_send_open_past_its_cutoff() {
    Retrying::failing(MockFailure::Internal("Request failed: unexpected answer"))
        .stays_open_past_the_cutoff();
}

both_stores!(a_send_never_pushed_stays_open_past_its_cutoff);
fn a_send_never_pushed_stays_open_past_its_cutoff() {
    let (sender, receiver) = funded(1);
    let funding = sender.outputs()[0].id.commitment;
    let (offline, peer) = reopened(&sender, true);
    let (tx_id, s2) = answered_send(&sender.harness, &offline, &peer, &receiver);
    let finalized = finalize(&sender.harness, &offline, &s2).unwrap();
    assert!(!finalized.pushed);
    offline.lock();
    let (online, _peer) = reopened(&sender, false);
    let retrying = Retrying {
        sender,
        tx_id,
        s2,
        funding,
    };
    // The online session is the one that refreshes from here.
    let harness = &retrying.sender.harness;
    harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(CUTOFF + 5));

    // The first refresh holds a tip this far ahead as pending, the second confirms it.
    refreshed(harness, &online);
    refreshed(harness, &online);

    assert_eq!(retrying.pushes(), 0);
    assert_eq!(retrying.sender.read(|repos| repos.node_post(tx_id)), None);
    assert_eq!(retrying.state(), TxState::Finalized);
    assert_eq!(retrying.funding_status(), OutputStatus::Locked);
}

both_stores!(a_refused_send_in_the_pool_at_its_cutoff_is_not_ended);
fn a_refused_send_in_the_pool_at_its_cutoff_is_not_ended() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.at(TIP + 50);
    let transaction = retrying.final_transaction();
    retrying
        .node()
        .update_chain(|chain| chain.pool = vec![transaction]);

    retrying.at(CUTOFF - 1);
    retrying.at(CUTOFF);

    assert_eq!(retrying.state(), TxState::Finalized);
    assert_eq!(retrying.funding_status(), OutputStatus::Locked);
}

both_stores!(a_refused_send_whose_kernel_is_on_chain_at_its_cutoff_is_not_ended);
fn a_refused_send_whose_kernel_is_on_chain_at_its_cutoff_is_not_ended() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.at(TIP + 50);
    let kernel = retrying.kernel_at(TIP + 50);
    retrying
        .node()
        .update_chain(|chain| chain.kernels.push(kernel));

    retrying.at(CUTOFF - 1);
    retrying.at(CUTOFF);

    assert_ne!(retrying.state(), TxState::Expired);
    assert_eq!(retrying.details().expired_reason, None);
}
