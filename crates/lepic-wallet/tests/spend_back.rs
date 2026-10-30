// SPDX-License-Identifier: Apache-2.0
//! Moving a cancelled payment's coins back to the wallet, so the payment can never complete: a
//! send to the wallet itself of exactly the inputs the payment spent. Whichever of the two the
//! chain mines first, the other is refused or can never be mined, and it ends without being
//! taken for another wallet's spend. While the move waits to be mined, the balance counts its
//! coins once, as on their way back.

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

use jiff::SignedDuration;
use lepic_crypto::Commitment;
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, Propagation, RejectionKind};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::tx::{Transaction, TransactionBody};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{OutputStatus, SlateStage, TxDirection, TxId, TxState, WalletStore as _};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::selection::{SelectionOptions, SelectionStrategy};
use lepic_wallet::self_send::{SelfSendError, SelfSent};
use lepic_wallet::send::{Delivery, SendRequest};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP};
use support::{LOOPBACK, MovableClock, fixed_time, some_proof};

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// A sender whose funding output, a plain one, is on the mock chain, mined at height 1. A
/// coinbase output this young would never count as another wallet's spend.
struct Wallet {
    sender: Sender,
    clock: MovableClock,
    funding: Commitment,
}

impl Wallet {
    fn new() -> Self {
        let clock = MovableClock::starting_at(fixed_time());
        let sender = Sender::with_clock(Arc::new(clock.clone()));
        let funding = send_support::output(&sender.keychain, 0, FUNDING, OutputFeatures::Plain);
        sender
            .store
            .write(|repos| repos.put_output(&funding))
            .unwrap();
        assert_eq!(sender.outputs().len(), 1);
        sender.harness.node.update_chain(|chain| {
            chain.outputs.push(ChainOutput {
                commitment: funding.id.commitment,
                features: funding.id.features,
                proof: some_proof(),
                height: Height::new(1),
                mmr_index: 1,
                spent: false,
            });
        });
        Self {
            sender,
            clock,
            funding: funding.id.commitment,
        }
    }

    /// A payment of [`AMOUNT`] the receiver answered and this wallet finalized, whose post the
    /// node refused, cancelled afterwards: the receiver holds its signed half and may still
    /// post it.
    fn cancelled_payment(&self) -> TxId {
        let sent = self
            .sender
            .harness
            .block_on(self.sender.wallet.send(
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
        let (s1, _) = self.sender.received().unwrap();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;
        self.sender.harness.node.fail_next(
            "push_transaction",
            MockFailure::Rejected(RejectionKind::Internal),
        );
        let error = self
            .sender
            .harness
            .block_on(
                self.sender
                    .wallet
                    .finalize(LOOPBACK, &s2, Propagation::Stem),
            )
            .unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        self.sender
            .harness
            .block_on(self.sender.wallet.cancel(sent.tx_id))
            .unwrap();
        assert_eq!(self.state(sent.tx_id), TxState::Cancelled);
        assert_eq!(self.status(&self.funding), OutputStatus::Unspent);
        sent.tx_id
    }

    /// Spends the funding output to the wallet itself, the move back after a cancel.
    fn move_back(&self) -> Result<SelfSent, SelfSendError> {
        self.sender
            .harness
            .block_on(self.sender.wallet.spend_outputs_to_self(
                SelectionOptions {
                    minimum_confirmations: 1,
                    ..SelectionOptions::new(ACCOUNT)
                },
                vec![self.funding],
                Propagation::Fluff,
            ))
    }

    /// The final transaction stored for `tx_id`, as a miner includes it.
    fn final_transaction(&self, tx_id: TxId) -> Transaction {
        let stored = self.sender.read(|repos| {
            let entry = repos.transaction(tx_id)?.unwrap();
            repos.slate(entry.slate_id.unwrap(), SlateStage::Standard3)
        });
        let slate = send_support::legacy_codecs()
            .decode(&WireSlate::binary(MediaType::JSON, stored.unwrap().bytes))
            .unwrap();
        let body = TransactionBody::new(
            slate.inputs().to_vec(),
            slate.outputs().to_vec(),
            vec![slate.kernel().unwrap()],
        );
        Transaction::new(slate.offset().clone(), body)
    }

    /// A miner includes `transaction` at `height`, which becomes the tip a day and an hour
    /// later by the clock: its inputs are spent, its outputs and kernel are on chain.
    fn mined_at(&self, transaction: &Transaction, height: u64) {
        self.clock.advance(SignedDuration::from_hours(25));
        self.sender.harness.node.update_chain(|chain| {
            chain.pool.clear();
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
                kernel: transaction.kernels()[0],
                height: Height::new(height),
                mmr_index: 9,
            });
            chain.tip.height = Height::new(height);
        });
    }

    fn refresh(&self) {
        let outcome = self
            .sender
            .harness
            .block_on(self.sender.wallet.refresh())
            .unwrap();
        assert!(
            matches!(outcome, RefreshOutcome::Refreshed(_)),
            "{outcome:?}"
        );
    }

    fn state(&self, tx_id: TxId) -> TxState {
        self.sender
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .state
    }

    fn status(&self, commitment: &Commitment) -> OutputStatus {
        self.sender
            .outputs()
            .into_iter()
            .find(|output| output.id.commitment == *commitment)
            .unwrap()
            .status
    }

    /// The entries recorded for another wallet's spend: outgoing, with no slate.
    fn other_wallet_spends(&self) -> usize {
        self.sender
            .transactions()
            .iter()
            .filter(|stored| {
                stored.entry.direction == TxDirection::Outgoing && stored.entry.slate_id.is_none()
            })
            .count()
    }

    /// Both entries of the self-send whose outgoing entry is `tx_id`.
    fn entries_of(&self, tx_id: TxId) -> (TxId, TxId) {
        let slate_id = self
            .sender
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .slate_id;
        let received = self
            .sender
            .transactions()
            .into_iter()
            .find(|stored| stored.id != tx_id && stored.entry.slate_id == slate_id)
            .unwrap()
            .id;
        (tx_id, received)
    }
}

/// The receiver posted the cancelled payment and a miner took it before the move back reached
/// the node, which then refuses the move because its input is spent.
#[test]
fn a_move_back_refused_because_the_cancelled_payment_was_mined_names_the_payment() {
    let wallet = Wallet::new();
    let payment = wallet.cancelled_payment();
    wallet.mined_at(&wallet.final_transaction(payment), TIP + 1);
    wallet
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::PoolRefused);

    let error = wallet.move_back().unwrap_err();

    let SelfSendError::Finalize(FinalizeError::InputsSpentByOwnTransaction { tx_id, by, .. }) =
        error
    else {
        panic!("{error:?}");
    };
    assert_eq!(by, payment);
    let (outgoing, incoming) = wallet.entries_of(tx_id);
    assert_eq!(wallet.state(outgoing), TxState::Cancelled);
    assert_eq!(wallet.state(incoming), TxState::Cancelled);
    // The refresh that followed found the payment through its watch.
    assert_eq!(wallet.state(payment), TxState::Confirmed);
    assert_eq!(wallet.status(&wallet.funding), OutputStatus::Spent);
    assert_eq!(wallet.other_wallet_spends(), 0);
}

/// The same race, with no transaction of this wallet on chain: another wallet on the phrase
/// spent the input, as before.
#[test]
fn a_move_back_refused_with_no_own_kernel_on_chain_is_another_wallets_spend() {
    let wallet = Wallet::new();
    wallet.cancelled_payment();
    wallet
        .sender
        .harness
        .node
        .update_chain(|chain| chain.outputs.clear());
    wallet
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::PoolRefused);

    let error = wallet.move_back().unwrap_err();

    assert!(
        matches!(
            error,
            SelfSendError::Finalize(FinalizeError::InputsSpentElsewhere { .. })
        ),
        "{error:?}"
    );
    assert_eq!(wallet.other_wallet_spends(), 1);
}

/// The move back reached no node; the cancelled payment is mined meanwhile. The move can never
/// be mined, so a refresh ends it instead of leaving it waiting to be posted again.
#[test]
fn a_move_back_the_node_never_took_ends_once_the_cancelled_payment_is_mined() {
    let wallet = Wallet::new();
    let payment = wallet.cancelled_payment();
    wallet
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    let error = wallet.move_back().unwrap_err();
    let SelfSendError::Finalize(FinalizeError::NotPosted { tx_id, .. }) = error else {
        panic!("{error:?}");
    };
    let (outgoing, incoming) = wallet.entries_of(tx_id);
    assert_eq!(wallet.state(outgoing), TxState::Finalized);
    wallet.mined_at(&wallet.final_transaction(payment), TIP + 1);

    wallet.refresh();

    assert_eq!(wallet.state(outgoing), TxState::Cancelled);
    assert_eq!(wallet.state(incoming), TxState::Cancelled);
    assert_eq!(wallet.state(payment), TxState::Confirmed);
    assert_eq!(wallet.status(&wallet.funding), OutputStatus::Spent);
    assert_eq!(wallet.other_wallet_spends(), 0);
    // Nothing is left to post again.
    let error = wallet
        .sender
        .harness
        .block_on(wallet.sender.wallet.post(outgoing, Propagation::Fluff))
        .unwrap_err();
    assert!(
        matches!(error, FinalizeError::NotPostable { .. }),
        "{error:?}"
    );
    // The move back stays watched, so a chain that mines it after all still confirms it.
    assert!(
        wallet
            .sender
            .read(|repos| repos.tx_watch(outgoing))
            .is_some()
    );
}

/// A posted move back whose input is still unspent, or whose kernel the node's pool holds, is on
/// its way to the chain and is never ended.
#[test]
fn a_posted_move_back_on_its_way_to_the_chain_is_not_ended() {
    let wallet = Wallet::new();
    wallet.cancelled_payment();
    let sent = wallet.move_back().unwrap();
    assert_eq!(wallet.state(sent.tx_id), TxState::Posted);
    wallet.clock.advance(SignedDuration::from_hours(25));
    wallet
        .sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 1));

    wallet.refresh();
    assert_eq!(wallet.state(sent.tx_id), TxState::Posted);

    let pushed = wallet.sender.harness.node.pushed_transactions()[0].clone();
    wallet.sender.harness.node.update_chain(|chain| {
        chain.pool.push(pushed);
        chain.outputs.clear();
    });
    wallet.refresh();

    assert_eq!(wallet.state(sent.tx_id), TxState::Posted);
    assert_eq!(wallet.other_wallet_spends(), 0);
}

/// Before the node takes a move back its inputs are locked and its output waits as any send's
/// change does; once the node takes it, its coins count once, as awaiting confirmation, and
/// nothing as locked.
#[test]
fn a_posted_move_back_counts_its_coins_once_as_awaiting_confirmation() {
    let wallet = Wallet::new();
    wallet
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    let error = wallet.move_back().unwrap_err();
    let SelfSendError::Finalize(FinalizeError::NotPosted { tx_id, .. }) = error else {
        panic!("{error:?}");
    };
    let fee = wallet
        .sender
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .fee
        .unwrap()
        .value();
    let back = Amount::new(FUNDING - fee);

    let waiting = wallet.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(waiting.total, Amount::new(FUNDING));
    assert_eq!(waiting.locked, Amount::new(FUNDING));
    assert_eq!(waiting.awaiting_finalization, back);
    assert_eq!(waiting.awaiting_confirmation, Amount::ZERO);

    wallet
        .sender
        .harness
        .block_on(wallet.sender.wallet.post(tx_id, Propagation::Fluff))
        .unwrap();
    assert_eq!(wallet.state(tx_id), TxState::Posted);

    let moving = wallet.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(moving.total, back);
    assert_eq!(moving.awaiting_confirmation, back);
    assert_eq!(moving.locked, Amount::ZERO);
    assert_eq!(moving.awaiting_finalization, Amount::ZERO);
    assert_eq!(moving.spendable, Amount::ZERO);
    let outputs = wallet.sender.wallet.outputs(ACCOUNT).unwrap();
    let input = outputs
        .iter()
        .find(|details| details.output.id.commitment == wallet.funding)
        .unwrap();
    assert_eq!(input.output.status, OutputStatus::Locked);
    assert_eq!(input.category, None);

    let posted = wallet.sender.harness.node.pushed_transactions()[0].clone();
    wallet.mined_at(&posted, TIP + 1);
    wallet.refresh();

    let mined = wallet.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(mined.total, back);
    assert_eq!(mined.locked, Amount::ZERO);
    assert_eq!(mined.awaiting_finalization, Amount::ZERO);
}
