//! Sends to the wallet itself: a split into several outputs and a consolidation into one,
//! built, received and finalized in one store transaction and posted.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod send_support;
mod support;

use std::sync::Arc;

use jiff::SignedDuration;
use lepic_node::Propagation;
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_store::OutputStatus::{self, Locked, Unconfirmed, Unspent};
use lepic_store::{AccountIndex, AccountRecord, TxDirection, TxId, TxState, WalletStore as _};
use lepic_wallet::WalletError;
use lepic_wallet::event::{Balance, Event, SelfSentTransaction, TransactionState};
use lepic_wallet::finalize::{FinalizeError, Posted};
use lepic_wallet::refresh::{RefreshOutcome, UNFINALIZED_RECEIVE_BLOCKS};
use lepic_wallet::release::RELEASE_AFTER_BLOCKS;
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use lepic_wallet::selection::{SelectionError, SelectionOptions, SelfSendShape, SplitCount};
use lepic_wallet::self_send::{SELF, SelfSendError};
use lepic_wallet::send::SendError;
use send_support::{ACCOUNT, FUNDING, Sender, TIP, output};
use support::{MovableClock, fixed_time, some_proof};

fn options() -> SelectionOptions {
    SelectionOptions {
        minimum_confirmations: 1,
        ..SelectionOptions::new(ACCOUNT)
    }
}

fn split(outputs: usize) -> SelfSendShape {
    SelfSendShape::Split(SplitCount::new(outputs).unwrap())
}

#[test]
fn split_counts_outside_two_to_ten_do_not_exist() {
    for outputs in [0, 1, 11] {
        assert_eq!(SplitCount::new(outputs), None, "{outputs}");
    }
    for outputs in 2..=10 {
        assert_eq!(SplitCount::new(outputs).unwrap().get(), outputs);
    }
}

#[test]
fn a_split_makes_outputs_of_nearly_equal_value_for_the_estimated_fee() {
    let sender = Sender::new();
    let estimate = sender
        .harness
        .block_on(sender.wallet.estimate_self_send(options(), split(4)))
        .unwrap();

    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .self_send(options(), split(4), Propagation::Fluff),
        )
        .unwrap();

    assert_eq!(sent.selection, estimate);
    assert_eq!(estimate.change.len(), 3);
    let made: Vec<u64> = sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .map(|output| output.amount.value())
        .collect();
    assert_eq!(made.len(), 4);
    assert_eq!(
        made.iter().sum::<u64>(),
        FUNDING - estimate.fee.value(),
        "everything but the fee comes back"
    );
    let (smallest, largest) = (made.iter().min().unwrap(), made.iter().max().unwrap());
    assert!(largest - smallest < 4, "equal parts, the remainder on one");
    let entries = sender.transactions();
    let outgoing = entries.iter().find(|tx| tx.id == sent.tx_id).unwrap();
    let incoming = entries
        .iter()
        .find(|tx| tx.id == sent.received_tx_id)
        .unwrap();
    assert_eq!(outgoing.entry.direction, TxDirection::Outgoing);
    assert_eq!(outgoing.entry.state, TxState::Posted);
    assert_eq!(incoming.entry.direction, TxDirection::Incoming);
    assert_eq!(incoming.entry.state, TxState::Received);
    for entry in [outgoing, incoming] {
        assert_eq!(entry.entry.transport.as_deref(), Some(SELF.as_str()));
        assert_eq!(entry.entry.slate_id, outgoing.entry.slate_id);
    }
    let pushed = sender.harness.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    pushed[0].validate().unwrap();
    assert_eq!(pushed[0].outputs().len(), 4);
    assert!(!sender.has_sender_context(outgoing.entry.slate_id.unwrap()));
}

#[test]
fn a_self_send_reports_itself_and_never_a_received_payment() {
    let sender = Sender::new();
    let mut events = sender.wallet.subscribe();

    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .self_send(options(), split(2), Propagation::Fluff),
        )
        .unwrap();

    let mut self_sent = Vec::new();
    while let Ok(event) = events.try_recv() {
        match event {
            Event::Received(received) => panic!("reported as received: {received:?}"),
            Event::SelfSent(stored) => self_sent.push(stored),
            _ => {}
        }
    }
    assert_eq!(
        self_sent,
        vec![SelfSentTransaction {
            tx_id: sent.tx_id,
            received_tx_id: sent.received_tx_id,
            account: ACCOUNT,
            amount: sent.selection.amount,
        }]
    );
}

#[test]
fn each_entry_of_a_self_send_lists_the_outputs_it_made() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .self_send(options(), split(3), Propagation::Fluff),
        )
        .unwrap();

    let made_by = |tx_id| {
        let mut made: Vec<_> = sender
            .outputs()
            .into_iter()
            .filter(|output| output.status == Unconfirmed && output.tx == Some(tx_id))
            .map(|output| output.id.commitment)
            .collect();
        made.sort_unstable_by_key(|commitment| *commitment.as_bytes());
        made
    };
    let listed = |tx_id| {
        let mut commits = sender
            .harness
            .block_on(sender.wallet.transaction_details(tx_id))
            .unwrap()
            .output_commits;
        commits.sort_unstable_by_key(|commitment| *commitment.as_bytes());
        commits
    };
    let (change, received) = (made_by(sent.tx_id), made_by(sent.received_tx_id));
    assert_eq!((change.len(), received.len()), (2, 1));
    assert_eq!(listed(sent.tx_id), change);
    assert_eq!(listed(sent.received_tx_id), received);
}

#[test]
fn a_consolidation_merges_every_spendable_output_into_one() {
    let sender = Sender::new();
    sender.fund(1, 2 * FUNDING);
    sender.fund(2, 3 * FUNDING);
    let estimate = sender
        .harness
        .block_on(
            sender
                .wallet
                .estimate_self_send(options(), SelfSendShape::Consolidate),
        )
        .unwrap();

    let sent = sender
        .harness
        .block_on(sender.wallet.self_send(
            options(),
            SelfSendShape::Consolidate,
            Propagation::Fluff,
        ))
        .unwrap();

    assert_eq!(sent.selection, estimate);
    assert_eq!(estimate.inputs.len(), 3);
    assert!(estimate.change.is_empty());
    let outputs = sender.outputs();
    let made: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .collect();
    assert_eq!(made.len(), 1);
    assert_eq!(made[0].amount.value(), 6 * FUNDING - estimate.fee.value());
    assert_eq!(made[0].tx, Some(sent.received_tx_id));
    let locked = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .count();
    assert_eq!(locked, 3);
    sender.harness.node.pushed_transactions()[0]
        .validate()
        .unwrap();
}

#[test]
fn a_split_the_funds_cannot_pay_stores_nothing() {
    let sender = Sender::new();
    sender
        .store
        .write(|repos| {
            for output in repos.outputs(ACCOUNT, None)? {
                repos.delete_output(output.commitment())?;
            }
            Ok::<_, lepic_store::StoreError>(())
        })
        .unwrap();
    sender.fund(1, 3);
    let before = (sender.transactions(), sender.outputs());

    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .self_send(options(), split(2), Propagation::Fluff),
        )
        .unwrap_err();

    assert!(
        matches!(
            error,
            SelfSendError::Send(SendError::Selection(SelectionError::NotEnoughFunds { .. }))
        ),
        "{error:?}"
    );
    assert_eq!((sender.transactions(), sender.outputs()), before);
    assert!(sender.harness.node.pushed_transactions().is_empty());
}

/// A self-send the node did not take: stored finalized, its inputs locked, its outputs
/// unconfirmed, with the funding output on the mock chain so a refresh keeps it.
struct Failed {
    sender: Sender,
    clock: MovableClock,
    tx_id: TxId,
    received_tx_id: TxId,
    before: Balance,
}

impl Failed {
    fn split() -> Self {
        Self::shaped(split(2), &[Locked, Unconfirmed, Unconfirmed])
    }

    /// A consolidation of the funding with a second output: no change, so only the incoming
    /// entry holds an unconfirmed output.
    fn consolidation() -> Self {
        Self::shaped(SelfSendShape::Consolidate, &[Locked, Locked, Unconfirmed])
    }

    fn shaped(shape: SelfSendShape, statuses: &[OutputStatus]) -> Self {
        let clock = MovableClock::starting_at(fixed_time());
        let sender = Sender::with_clock(Arc::new(clock.clone()));
        let funding = sender.outputs().remove(0);
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
        if shape == SelfSendShape::Consolidate {
            sender.fund(1, FUNDING);
        }
        let before = sender.wallet.balance(ACCOUNT).unwrap();
        sender
            .harness
            .node
            .fail_next("push_transaction", MockFailure::Unreachable);

        let error = sender
            .harness
            .block_on(
                sender
                    .wallet
                    .self_send(options(), shape, Propagation::Fluff),
            )
            .unwrap_err();

        let SelfSendError::Finalize(FinalizeError::NotPosted { tx_id, .. }) = error else {
            panic!("{error:?}");
        };
        let entries = sender.transactions();
        let outgoing = entries.iter().find(|tx| tx.id == tx_id).unwrap();
        assert_eq!(outgoing.entry.state, TxState::Finalized);
        let received_tx_id = entries
            .iter()
            .find(|tx| tx.id != tx_id && tx.entry.slate_id == outgoing.entry.slate_id)
            .unwrap()
            .id;
        let failed = Self {
            sender,
            clock,
            tx_id,
            received_tx_id,
            before,
        };
        assert_eq!(failed.state(failed.received_tx_id), TxState::Received);
        assert_eq!(failed.statuses(), statuses);
        failed
    }

    fn state(&self, tx_id: TxId) -> TxState {
        self.sender
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .state
    }

    /// The statuses of the stored outputs, funding first.
    fn statuses(&self) -> Vec<OutputStatus> {
        let mut outputs = self.sender.outputs();
        outputs.sort_by_key(|output| output.status != Locked && output.status != Unspent);
        outputs.into_iter().map(|output| output.status).collect()
    }

    /// Both entries ended `cancelled`, the inputs spendable again, the balance as before.
    fn assert_ended(&self) {
        assert_eq!(self.state(self.tx_id), TxState::Cancelled);
        assert_eq!(self.state(self.received_tx_id), TxState::Cancelled);
        assert!(self.statuses().iter().all(|status| *status == Unspent));
        let balance = self.sender.wallet.balance(ACCOUNT).unwrap();
        assert_eq!(balance.total, self.before.total);
        assert_eq!(balance.locked, Amount::ZERO);
    }

    /// The node's tip moves to `height` a day of blocks at a time, a day and an hour later by
    /// the clock, refreshing twice at each step: the first refresh after a jump holds the tip
    /// as pending, the second confirms it.
    fn chain_reaches(&self, height: u64) {
        let mut at = TIP;
        loop {
            at = (at + 1_440).min(height);
            self.clock.advance(SignedDuration::from_hours(25));
            self.sender
                .harness
                .node
                .update_chain(|chain| chain.tip.height = Height::new(at));
            for _ in 0..2 {
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
            if at == height {
                return;
            }
        }
    }
}

/// The transactions the events report as cancelled, in id order.
fn cancelled_by_events(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<TxId> {
    let mut cancelled = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(TransactionState { tx_id, to, .. }) = event {
            assert_eq!(to, TxState::Cancelled);
            cancelled.push(tx_id);
        }
    }
    cancelled.sort();
    cancelled
}

#[test]
fn cancel_of_a_self_send_the_node_did_not_take_ends_both_entries() {
    let failed = Failed::split();
    let mut events = failed.sender.wallet.subscribe();

    failed
        .sender
        .harness
        .block_on(failed.sender.wallet.cancel(failed.tx_id))
        .unwrap();

    failed.assert_ended();
    let mut expected = vec![failed.tx_id, failed.received_tx_id];
    expected.sort();
    assert_eq!(cancelled_by_events(&mut events), expected);
}

#[test]
fn release_of_a_self_send_the_node_did_not_take_ends_both_entries() {
    let failed = Failed::split();
    failed.chain_reaches(TIP + RELEASE_AFTER_BLOCKS);
    assert!(
        failed
            .sender
            .harness
            .block_on(failed.sender.wallet.transaction_details(failed.tx_id))
            .unwrap()
            .releasable
    );

    failed
        .sender
        .harness
        .block_on(failed.sender.wallet.release(failed.tx_id))
        .unwrap();

    failed.assert_ended();
}

#[test]
fn a_self_send_the_node_did_not_take_is_posted_again() {
    let failed = Failed::split();

    let posted = failed
        .sender
        .harness
        .block_on(failed.sender.wallet.post(failed.tx_id, Propagation::Fluff))
        .unwrap();

    assert_eq!(posted, Posted::Accepted);
    assert_eq!(failed.state(failed.tx_id), TxState::Posted);
    assert_eq!(failed.state(failed.received_tx_id), TxState::Received);
    assert_eq!(failed.statuses(), vec![Locked, Unconfirmed, Unconfirmed]);
    assert_eq!(failed.sender.harness.node.pushed_transactions().len(), 1);
}

#[test]
fn a_refresh_never_expires_the_incoming_entry_of_a_self_send_on_its_own() {
    let failed = Failed::split();
    // The first refresh records when the incoming entry was first seen.
    failed.chain_reaches(TIP);

    failed.chain_reaches(TIP + UNFINALIZED_RECEIVE_BLOCKS + 1);

    assert_eq!(failed.state(failed.tx_id), TxState::Finalized);
    assert_eq!(failed.state(failed.received_tx_id), TxState::Received);
    assert_eq!(failed.statuses(), vec![Locked, Unconfirmed, Unconfirmed]);
}

fn repair_scan(failed: &Failed) -> (u64, u64) {
    let summary = failed
        .sender
        .harness
        .block_on(failed.sender.wallet.scan(
            ScanOptions {
                delete_unconfirmed: true,
                ..ScanOptions::update(Network::Floonet)
            },
            &ScanCancel::new(),
        ))
        .unwrap();
    (summary.unlocked, summary.deleted)
}

#[test]
fn a_repair_scan_cancels_a_split_the_node_did_not_take_as_a_cancel_does() {
    let failed = Failed::split();

    assert_eq!(repair_scan(&failed), (1, 2));

    failed.assert_ended();
}

#[test]
fn a_repair_scan_cancels_a_consolidation_the_node_did_not_take_with_its_outgoing_entry() {
    let failed = Failed::consolidation();

    assert_eq!(repair_scan(&failed), (2, 1));

    failed.assert_ended();
}

#[test]
fn cancel_of_the_incoming_entry_of_a_self_send_ends_the_outgoing_one_too() {
    let failed = Failed::consolidation();

    failed
        .sender
        .harness
        .block_on(failed.sender.wallet.cancel(failed.received_tx_id))
        .unwrap();

    failed.assert_ended();
}

#[test]
fn rejects_cancelling_the_incoming_entry_of_a_posted_self_send() {
    let failed = Failed::split();
    failed
        .sender
        .harness
        .block_on(failed.sender.wallet.post(failed.tx_id, Propagation::Fluff))
        .unwrap();

    let error = failed
        .sender
        .harness
        .block_on(failed.sender.wallet.cancel(failed.received_tx_id))
        .unwrap_err();

    assert!(
        matches!(
            error,
            WalletError::PartnerPosted { tx_id, partner }
                if tx_id == failed.received_tx_id && partner == failed.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(failed.state(failed.tx_id), TxState::Posted);
    assert_eq!(failed.state(failed.received_tx_id), TxState::Received);
    assert_eq!(failed.statuses(), vec![Locked, Unconfirmed, Unconfirmed]);
}

fn commitment_of(sender: &Sender, value: u64) -> lepic_crypto::Commitment {
    sender
        .outputs()
        .into_iter()
        .find(|output| output.amount.value() == value && output.status == Unspent)
        .unwrap()
        .id
        .commitment
}

fn spend_named(
    sender: &Sender,
    commitments: Vec<lepic_crypto::Commitment>,
) -> Result<lepic_wallet::self_send::SelfSent, SelfSendError> {
    sender.harness.block_on(sender.wallet.spend_outputs_to_self(
        options(),
        commitments,
        Propagation::Fluff,
    ))
}

#[test]
fn spending_named_outputs_spends_exactly_those_into_one_output() {
    let sender = Sender::new();
    sender.fund(1, 2 * FUNDING);
    sender.fund(2, 3 * FUNDING);
    let funding = commitment_of(&sender, FUNDING);
    let named = vec![
        commitment_of(&sender, 3 * FUNDING),
        commitment_of(&sender, 2 * FUNDING),
    ];

    let sent = spend_named(&sender, named.clone()).unwrap();

    let spent: Vec<_> = sent
        .selection
        .inputs
        .iter()
        .map(|input| input.id.commitment)
        .collect();
    // In increasing value, the order the transaction adds them in.
    assert_eq!(spent, vec![named[1], named[0]]);
    assert!(sent.selection.change.is_empty());
    let outputs = sender.outputs();
    let status_of = |commitment: &lepic_crypto::Commitment| {
        outputs
            .iter()
            .find(|output| output.id.commitment == *commitment)
            .unwrap()
            .status
    };
    assert_eq!(status_of(&named[0]), Locked);
    assert_eq!(status_of(&named[1]), Locked);
    assert_eq!(status_of(&funding), Unspent, "nothing else is locked");
    let made: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == Unconfirmed)
        .collect();
    assert_eq!(made.len(), 1);
    assert_eq!(
        made[0].amount.value(),
        5 * FUNDING - sent.selection.fee.value()
    );
    assert_eq!(made[0].tx, Some(sent.received_tx_id));
    let pushed = sender.harness.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    pushed[0].validate().unwrap();
    assert_eq!(pushed[0].inputs().len(), 2);
    assert_eq!(pushed[0].outputs().len(), 1);
}

#[test]
fn spending_one_named_output_is_allowed() {
    let sender = Sender::new();
    let funding = commitment_of(&sender, FUNDING);

    let sent = spend_named(&sender, vec![funding]).unwrap();

    assert_eq!(sent.selection.inputs.len(), 1);
    assert_eq!(
        sent.selection.amount.value(),
        FUNDING - sent.selection.fee.value()
    );
}

#[test]
fn spending_named_outputs_refuses_what_cannot_be_spent_and_stores_nothing() {
    let sender = Sender::new();
    sender.fund(1, 2 * FUNDING);
    sender.fund(2, 3);
    let funding = commitment_of(&sender, FUNDING);
    let second = commitment_of(&sender, 2 * FUNDING);
    let dust = commitment_of(&sender, 3);
    // An output that is not in the store any more.
    sender.fund(3, 4 * FUNDING);
    let gone = commitment_of(&sender, 4 * FUNDING);
    let record = sender
        .outputs()
        .into_iter()
        .find(|output| output.id.commitment == gone)
        .unwrap();
    sender
        .store
        .write(|repos| repos.delete_output(record.commitment()))
        .unwrap();
    let before = (sender.transactions(), sender.outputs());

    let cases = [
        (Vec::new(), "none"),
        (vec![gone], "unknown"),
        (vec![funding, funding], "twice"),
        (vec![dust], "dust"),
    ];
    let errors: Vec<_> = cases
        .into_iter()
        .map(|(named, case)| (spend_named(&sender, named).unwrap_err(), case))
        .collect();

    let selection = |error: &SelfSendError| match error {
        SelfSendError::Send(SendError::Selection(selection)) => *selection,
        other => panic!("{other:?}"),
    };
    assert_eq!(selection(&errors[0].0), SelectionError::NoOutputsNamed);
    assert_eq!(
        selection(&errors[1].0),
        SelectionError::NamedOutputUnavailable { position: 0 }
    );
    assert_eq!(
        selection(&errors[2].0),
        SelectionError::NamedOutputUnavailable { position: 1 }
    );
    assert!(
        matches!(
            selection(&errors[3].0),
            SelectionError::NotEnoughFunds { .. }
        ),
        "{:?}",
        errors[3]
    );
    assert_eq!((sender.transactions(), sender.outputs()), before);
    assert!(sender.harness.node.pushed_transactions().is_empty());

    // A locked output, an input of a send in progress, is not spendable either.
    let mut record = sender
        .outputs()
        .into_iter()
        .find(|output| output.id.commitment == second)
        .unwrap();
    record.status = Locked;
    sender
        .store
        .write(|repos| repos.put_output(&record))
        .unwrap();
    let error = spend_named(&sender, vec![funding, second]).unwrap_err();
    assert_eq!(
        selection(&error),
        SelectionError::NamedOutputUnavailable { position: 1 }
    );
}

#[test]
fn spending_named_outputs_refuses_young_unconfirmed_and_other_account_outputs() {
    let sender = Sender::new();
    // One confirmation at the tip.
    let mut young = output(&sender.keychain, 1, 2 * FUNDING, OutputFeatures::Plain);
    young.height = Height::new(TIP);
    let mut unconfirmed = output(&sender.keychain, 2, 3 * FUNDING, OutputFeatures::Plain);
    unconfirmed.status = Unconfirmed;
    let mut elsewhere = output(&sender.keychain, 3, 4 * FUNDING, OutputFeatures::Plain);
    elsewhere.account = AccountIndex(1);
    sender
        .store
        .write(|repos| {
            repos.put_account(&AccountRecord {
                index: AccountIndex(1),
                label: "other".to_owned(),
                next_child: 0,
            })?;
            repos.put_output(&young)?;
            repos.put_output(&unconfirmed)?;
            repos.put_output(&elsewhere)
        })
        .unwrap();
    let funding = commitment_of(&sender, FUNDING);
    let before = (sender.transactions(), sender.outputs());
    let spend = |minimum_confirmations, named: lepic_crypto::Commitment| {
        let options = SelectionOptions {
            minimum_confirmations,
            ..SelectionOptions::new(ACCOUNT)
        };
        sender
            .harness
            .block_on(sender.wallet.spend_outputs_to_self(
                options,
                vec![funding, named],
                Propagation::Fluff,
            ))
            .unwrap_err()
    };

    let cases = [
        (spend(2, young.id.commitment), "below the minimum"),
        // Not even when unconfirmed outputs would count.
        (spend(0, unconfirmed.id.commitment), "unconfirmed"),
        (spend(1, elsewhere.id.commitment), "another account"),
    ];

    for (error, case) in cases {
        assert!(
            matches!(
                error,
                SelfSendError::Send(SendError::Selection(
                    SelectionError::NamedOutputUnavailable { position: 1 }
                ))
            ),
            "{case}: {error:?}"
        );
    }
    assert_eq!((sender.transactions(), sender.outputs()), before);
    assert!(sender.harness.node.pushed_transactions().is_empty());
    // The young output is spendable once the minimum is met.
    assert!(
        spend_named(&sender, vec![young.id.commitment])
            .unwrap()
            .selection
            .inputs
            .iter()
            .any(|input| input.id.commitment == young.id.commitment)
    );
}
