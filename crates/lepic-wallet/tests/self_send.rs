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

use lepic_node::Propagation;
use lepic_store::{OutputStatus, TxDirection, TxState, WalletStore as _};
use lepic_wallet::selection::{SelectionError, SelectionOptions, SelfSendShape, SplitCount};
use lepic_wallet::self_send::{SELF, SelfSendError};
use lepic_wallet::send::SendError;
use send_support::{ACCOUNT, FUNDING, Sender};

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
