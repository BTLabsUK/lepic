// SPDX-License-Identifier: Apache-2.0
//! Recovering a payment: a send to the wallet itself that spends exactly the payment's inputs,
//! stored with the payment's recovery in one store transaction and pushed after it.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::post_retry::{CUTOFF, PUSH, Retrying, reopened};
use crate::send_support::{ACCOUNT, TIP};

use lepic_node::mock::MockFailure;
use lepic_node::{NodeError, Propagation};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_primitives::tx::Transaction;
use lepic_store::{
    OutputRecord, OutputStatus, Recovery, RecoveryState, StoredTransaction, TxDirection, TxId,
    TxState,
};
use lepic_wallet::details::CancelledReason;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use lepic_wallet::self_send::SelfSendError;
use lepic_wallet::send::SendError;
use lepic_wallet::{Event, WalletError};
use tokio::sync::broadcast::Receiver;

fn recover(retrying: &Retrying) -> Result<Recovery, SelfSendError> {
    retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.recover(retrying.tx_id))
}

fn refused(result: Result<Recovery, SelfSendError>) -> WalletError {
    match result {
        Err(SelfSendError::Send(SendError::Wallet(error))) => error,
        other => panic!("{other:?}"),
    }
}

/// What a refused recovery must leave as it was.
#[derive(Debug, PartialEq)]
struct Stored {
    transactions: Vec<StoredTransaction>,
    outputs: Vec<OutputRecord>,
    recoveries: Vec<Recovery>,
}

fn stored(retrying: &Retrying) -> Stored {
    Stored {
        transactions: retrying.sender.transactions(),
        outputs: retrying.sender.outputs(),
        recoveries: retrying.sender.read(|repos| repos.recoveries()),
    }
}

fn transaction(retrying: &Retrying, tx_id: TxId) -> StoredTransaction {
    retrying
        .sender
        .transactions()
        .into_iter()
        .find(|stored| stored.id == tx_id)
        .unwrap()
}

fn funding(retrying: &Retrying) -> OutputRecord {
    retrying
        .sender
        .outputs()
        .into_iter()
        .find(|output| output.id.commitment == retrying.funding)
        .unwrap()
}

/// The only output of the recovery's pair: the one it receives.
fn made(retrying: &Retrying, recovery: &Recovery) -> OutputRecord {
    let made: Vec<_> = retrying
        .sender
        .outputs()
        .into_iter()
        .filter(|output| output.tx == Some(recovery.received_tx))
        .collect();
    assert_eq!(made.len(), 1, "{made:?}");
    made[0].clone()
}

/// The pushes the node took of `transaction`, found by its kernel.
fn pushes_of(retrying: &Retrying, transaction: &Transaction) -> usize {
    let excess = transaction.kernels()[0].excess;
    retrying
        .node()
        .pushed_transactions()
        .iter()
        .filter(|pushed| {
            pushed
                .kernels()
                .iter()
                .any(|kernel| kernel.excess == excess)
        })
        .count()
}

/// The recovery transaction the node took last.
fn last_pushed(retrying: &Retrying) -> Transaction {
    retrying
        .node()
        .pushed_transactions()
        .last()
        .unwrap()
        .clone()
}

/// The states the recovery events received so far tell of, each for the payment `tx_id`.
fn recovery_news(events: &mut Receiver<Event>, tx_id: TxId) -> Vec<RecoveryState> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::RecoveryChanged(news) => {
                assert_eq!(news.tx_id, tx_id);
                Some(news.state)
            }
            _ => None,
        })
        .collect()
}

/// The balance while a recovery that makes `made` is open: the payment counts nowhere and the
/// recovery's output waits for its confirmations.
fn assert_balance_while_open(retrying: &Retrying, made: Amount, at: &str) {
    let balance = retrying.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(balance.locked, Amount::ZERO, "{at}");
    assert_eq!(balance.awaiting_finalization, Amount::ZERO, "{at}");
    assert_eq!(balance.awaiting_confirmation, made, "{at}");
    assert_eq!(balance.total, made, "{at}");
}

/// The recovery `recovery` was stored and pushed with exactly the payment's input, into one
/// output, and the input is still held for the payment, now locked.
fn assert_recovered(retrying: &Retrying, recovery: &Recovery) {
    assert_eq!(recovery.tx_id, retrying.tx_id);
    assert_eq!(recovery.state, RecoveryState::Posted);
    assert_eq!(recovery.last_error, None);
    assert_eq!(
        retrying.sender.read(|repos| repos.recovery(retrying.tx_id)),
        Some(recovery.clone())
    );
    let pushed = retrying
        .node()
        .pushed_transactions()
        .last()
        .unwrap()
        .clone();
    let inputs: Vec<_> = pushed
        .inputs()
        .iter()
        .map(|input| input.commitment)
        .collect();
    assert_eq!(inputs, [retrying.funding]);
    assert_eq!(pushed.outputs().len(), 1);
    let sent = transaction(retrying, recovery.sent_tx);
    assert_eq!(sent.entry.direction, TxDirection::Outgoing);
    assert_eq!(sent.entry.state, TxState::Posted);
    let received = transaction(retrying, recovery.received_tx);
    assert_eq!(received.entry.direction, TxDirection::Incoming);
    let funding = funding(retrying);
    assert_eq!(funding.status, OutputStatus::Locked);
    assert_eq!(funding.tx, Some(retrying.tx_id));
}

#[test]
fn recovers_a_payment_the_node_did_not_take_with_exactly_its_inputs() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let pushes = retrying.pushes();

    let recovery = recover(&retrying).unwrap();

    assert_recovered(&retrying, &recovery);
    assert_eq!(retrying.pushes(), pushes + 1);
    assert_eq!(retrying.state(), TxState::Finalized);
}

#[test]
fn recovers_a_posted_payment_the_node_no_longer_holds() {
    let retrying = Retrying::posted();

    let recovery = recover(&retrying).unwrap();

    assert_recovered(&retrying, &recovery);
    assert_eq!(retrying.state(), TxState::Posted);
}

#[test]
fn a_second_recovery_or_post_is_refused_while_the_first_is_open() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    let before = stored(&retrying);
    let pushes = retrying.pushes();

    let error = refused(recover(&retrying));
    assert!(
        matches!(error, WalletError::RecoveryOpen(id) if id == retrying.tx_id),
        "{error:?}"
    );
    let error = retrying.post().unwrap_err();
    let open = matches!(
        error,
        FinalizeError::Wallet(WalletError::RecoveryOpen(id)) if id == retrying.tx_id
    );
    assert!(open, "{error:?}");
    // Either entry of the recovery's pair, posted by hand, is refused the same way.
    for id in [recovery.sent_tx, recovery.received_tx] {
        let error = retrying
            .sender
            .harness
            .block_on(retrying.sender.wallet.post(id, Propagation::Stem))
            .unwrap_err();
        let open = matches!(
            error,
            FinalizeError::Wallet(WalletError::RecoveryOpen(payment))
                if payment == retrying.tx_id
        );
        assert!(open, "{error:?}");
    }

    assert_eq!(stored(&retrying), before);
    assert_eq!(retrying.pushes(), pushes);
}

#[test]
fn recovers_a_cancelled_payment_and_locks_its_inputs_for_it_again() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.cancel(retrying.tx_id))
        .unwrap();
    assert_eq!(retrying.funding_status(), OutputStatus::Unspent);
    retrying.node().stop_failing(PUSH);

    let recovery = recover(&retrying).unwrap();

    assert_recovered(&retrying, &recovery);
    assert_eq!(retrying.state(), TxState::Cancelled);
}

#[test]
fn recovers_an_expired_payment_and_locks_its_inputs_for_it_again() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.at(TIP + 50);
    retrying.at(CUTOFF - 1);
    retrying.at(CUTOFF);
    assert_eq!(retrying.state(), TxState::Expired);
    assert_eq!(retrying.funding_status(), OutputStatus::Unspent);
    retrying.node().stop_failing(PUSH);

    let recovery = recover(&retrying).unwrap();

    assert_recovered(&retrying, &recovery);
    assert_eq!(retrying.state(), TxState::Expired);
}

#[test]
fn refuses_a_payment_whose_kernel_the_node_holds_and_stores_nothing() {
    let retrying = Retrying::posted();
    let transaction = retrying.final_transaction();
    let before = stored(&retrying);
    let pushes = retrying.pushes();

    retrying
        .node()
        .update_chain(|chain| chain.pool.push(transaction.clone()));
    let error = refused(recover(&retrying));
    assert!(
        matches!(error, WalletError::InPool(id) if id == retrying.tx_id),
        "{error:?}"
    );
    assert_eq!(stored(&retrying), before);

    retrying.node().update_chain(|chain| chain.pool.clear());
    retrying.mined_at(&transaction, TIP);
    let error = refused(recover(&retrying));
    assert!(
        matches!(error, WalletError::OnChain(id) if id == retrying.tx_id),
        "{error:?}"
    );

    assert_eq!(stored(&retrying), before);
    assert_eq!(retrying.pushes(), pushes);
}

#[test]
fn refuses_a_send_that_was_not_finalized_and_stores_nothing() {
    let retrying = Retrying::answered();
    assert_eq!(retrying.state(), TxState::Sent);
    let before = stored(&retrying);

    let error = refused(recover(&retrying));

    assert!(
        matches!(error, WalletError::NotRecoverable(id) if id == retrying.tx_id),
        "{error:?}"
    );
    assert_eq!(stored(&retrying), before);
    assert_eq!(retrying.pushes(), 0);
}

#[test]
fn an_offline_session_cannot_recover() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    let (wallet, _peer) = reopened(&retrying.sender, true);

    let error = match retrying
        .sender
        .harness
        .block_on(wallet.recover(retrying.tx_id))
    {
        Err(SelfSendError::Send(SendError::Wallet(error))) => error,
        other => panic!("{other:?}"),
    };

    assert!(
        matches!(error, WalletError::Node(NodeError::Offline)),
        "{error:?}"
    );
    assert_eq!(retrying.sender.read(|repos| repos.recoveries()), []);
}

#[test]
fn a_payment_mined_before_its_recovery_confirms_and_the_recovery_ends() {
    let retrying = Retrying::posted();
    // A miner includes the payment in a block the node's tip does not show yet.
    retrying.mined_at(&retrying.final_transaction(), TIP + 1);
    retrying.node().fail_next(PUSH, MockFailure::PoolRefused);

    let recovery = recover(&retrying).unwrap();

    assert_eq!(recovery.state, RecoveryState::Failed);
    assert!(recovery.last_error.is_some());
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
    }
    assert_eq!(funding(&retrying).tx, Some(retrying.tx_id));

    retrying.at(TIP + 1);

    assert_eq!(retrying.state(), TxState::Confirmed);
    assert_eq!(retrying.funding_status(), OutputStatus::Spent);
    let credited: Vec<_> = retrying
        .sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unspent)
        .collect();
    assert_eq!(credited.len(), 1, "{credited:?}");
    assert_eq!(credited[0].tx, Some(retrying.tx_id));
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
    }
}

/// The answers of a node that refuses a push it cannot take into its pool.
const POOL_REFUSALS: [&str; 3] = [
    // Its pool holds the payment, which spends the same inputs.
    "Failed to update pool: DoubleSpend",
    // The fee is below what it relays.
    "Failed to update pool: LowFeeTransaction(1000)",
    // Any other reason it gives.
    "Failed to update pool: InvalidTx(kernel sum mismatch)",
];

#[test]
fn a_recovery_the_node_refuses_ends_and_leaves_the_payment_open_and_locked() {
    for text in POOL_REFUSALS {
        let retrying = Retrying::failing(MockFailure::PoolRefused);
        retrying
            .node()
            .fail_every(PUSH, MockFailure::Internal(text));

        let recovery = recover(&retrying).unwrap();

        assert_eq!(recovery.state, RecoveryState::Failed, "{text}");
        assert!(
            recovery
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains(text)),
            "{text}: {:?}",
            recovery.last_error
        );
        for id in [recovery.sent_tx, recovery.received_tx] {
            assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
        }
        assert_eq!(retrying.state(), TxState::Finalized, "{text}");
        let funding = funding(&retrying);
        assert_eq!(funding.status, OutputStatus::Locked, "{text}");
        assert_eq!(funding.tx, Some(retrying.tx_id), "{text}");

        // The recovery is not pushed again; only the payment is.
        retrying.node().stop_failing(PUSH);
        retrying.at(TIP + 1);

        let final_transaction = retrying.final_transaction();
        assert!(
            retrying
                .node()
                .pushed_transactions()
                .iter()
                .all(|pushed| *pushed == final_transaction),
            "{text}"
        );
        assert_eq!(
            retrying.sender.read(|repos| repos.recovery(retrying.tx_id)),
            Some(recovery),
            "{text}"
        );
    }
}

#[test]
fn a_recovery_the_node_could_not_take_stays_uncertain_and_is_pushed_again() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().fail_every(PUSH, MockFailure::Unreachable);

    let recovery = recover(&retrying).unwrap();

    assert_eq!(recovery.state, RecoveryState::Uncertain);
    assert_eq!(
        transaction(&retrying, recovery.sent_tx).entry.state,
        TxState::Finalized
    );
    assert_eq!(funding(&retrying).tx, Some(retrying.tx_id));

    retrying.node().stop_failing(PUSH);
    retrying.walk(TIP + 1..=TIP + 4);

    let recovery = retrying
        .sender
        .read(|repos| repos.recovery(retrying.tx_id))
        .unwrap();
    assert_recovered(&retrying, &recovery);
    assert_eq!(retrying.state(), TxState::Finalized);
}

/// The other open payment `other` and the outputs it holds, by commitment.
fn other_payment(retrying: &Retrying, other: TxId) -> (StoredTransaction, Vec<OutputRecord>) {
    let mut held: Vec<_> = retrying
        .sender
        .outputs()
        .into_iter()
        .filter(|output| output.tx == Some(other))
        .collect();
    held.sort_by(|left, right| left.commitment().cmp(right.commitment()));
    (transaction(retrying, other), held)
}

#[test]
fn a_recovery_leaves_another_open_payment_and_its_inputs_alone() {
    // It ends refused, with its pair cancelled.
    let (retrying, other) = Retrying::failing_beside_another(MockFailure::PoolRefused);
    retrying
        .node()
        .fail_every(PUSH, MockFailure::Internal(POOL_REFUSALS[2]));
    let before = other_payment(&retrying, other);
    assert!(
        before
            .1
            .iter()
            .any(|output| output.status == OutputStatus::Locked)
    );

    let recovery = recover(&retrying).unwrap();

    assert_eq!(recovery.state, RecoveryState::Failed);
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
    }
    assert_eq!(other_payment(&retrying, other), before);

    // It ends done at the count.
    let (retrying, other) = Retrying::failing_beside_another(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let before = other_payment(&retrying, other);

    let recovery = recover(&retrying).unwrap();

    assert_recovered(&retrying, &recovery);
    assert_eq!(other_payment(&retrying, other), before);
    retrying.mined_at(&last_pushed(&retrying), TIP + 1);
    let count = retrying.sender.wallet.minimum_confirmations().unwrap();
    for height in TIP + 1..=TIP + count {
        retrying.at(height);
    }
    assert_eq!(stored_recovery(&retrying).state, RecoveryState::Done);
    assert_eq!(other_payment(&retrying, other), before);
}

#[test]
fn neither_the_payment_nor_its_recovery_is_cancelled_while_it_is_open() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    let before = stored(&retrying);
    let wallet = &retrying.sender.wallet;
    let harness = &retrying.sender.harness;

    for id in [retrying.tx_id, recovery.sent_tx, recovery.received_tx] {
        let error = harness.block_on(wallet.cancel(id)).unwrap_err();
        assert!(
            matches!(error, WalletError::RecoveryOpen(payment) if payment == retrying.tx_id),
            "{error:?}"
        );
    }
    assert_eq!(stored(&retrying), before);
}

/// A payment the node refused, recovered, with the recovery mined at `TIP + 1` in a block the
/// wallet has not seen yet. Returns the recovery as stored before any refresh.
fn recovered_and_mined() -> (Retrying, Recovery) {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    let mined = retrying
        .node()
        .pushed_transactions()
        .last()
        .unwrap()
        .clone();
    retrying.mined_at(&mined, TIP + 1);
    (retrying, recovery)
}

fn stored_recovery(retrying: &Retrying) -> Recovery {
    retrying
        .sender
        .read(|repos| repos.recovery(retrying.tx_id))
        .unwrap()
}

#[test]
fn a_recovery_mined_first_cancels_the_payment_at_the_spend_confirmations() {
    let (retrying, recovery) = recovered_and_mined();
    let count = retrying.sender.wallet.minimum_confirmations().unwrap();
    assert!(count > 1);
    let record = retrying.record();
    let payment_pushes = pushes_of(&retrying, &retrying.final_transaction());
    let entries = retrying.sender.transactions().len();
    let made = made(&retrying, &recovery);

    for height in TIP + 1..TIP + count {
        retrying.at(height);
        let at = format!("at {height}");
        assert_eq!(retrying.state(), TxState::Finalized, "{at}");
        let waiting = stored_recovery(&retrying);
        assert_eq!(waiting.state, RecoveryState::Confirming, "{at}");
        assert_eq!(waiting.kernel_height.map(Height::value), Some(TIP + 1));
        let open = matches!(
            refused(recover(&retrying)),
            WalletError::RecoveryOpen(id) if id == retrying.tx_id
        );
        assert!(open, "{at}");
        // Below the count the block may still be replaced: nothing moves yet.
        let input = funding(&retrying);
        assert_eq!(input.status, OutputStatus::Locked, "{at}");
        assert_eq!(input.tx, Some(retrying.tx_id), "{at}");
        assert_eq!(
            self::made(&retrying, &recovery).status,
            OutputStatus::Unconfirmed,
            "{at}"
        );
        assert_eq!(
            transaction(&retrying, recovery.sent_tx).entry.state,
            TxState::Posted,
            "{at}"
        );
        assert_eq!(retrying.sender.transactions().len(), entries, "{at}");
        assert_balance_while_open(&retrying, made.amount, &at);
    }
    // The payment was never pushed again while its recovery was open.
    assert_eq!(retrying.record(), record);
    assert_eq!(
        pushes_of(&retrying, &retrying.final_transaction()),
        payment_pushes
    );

    retrying.at(TIP + count);

    assert_eq!(retrying.state(), TxState::Cancelled);
    assert_eq!(
        retrying.details().cancelled_reason,
        Some(CancelledReason::Recovered)
    );
    let done = stored_recovery(&retrying);
    assert_eq!(done.state, RecoveryState::Done);
    assert_eq!(done.kernel_height.map(Height::value), Some(TIP + 1));
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Confirmed);
    }
    let funding = funding(&retrying);
    assert_eq!(funding.status, OutputStatus::Spent);
    assert_eq!(funding.tx, Some(recovery.sent_tx));
    let outputs = retrying.sender.outputs();
    assert!(
        outputs
            .iter()
            .all(|output| output.tx != Some(retrying.tx_id)),
        "{outputs:?}"
    );
    let credited: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Unspent)
        .collect();
    assert_eq!(credited.len(), 1, "{credited:?}");
    assert_eq!(credited[0].tx, Some(recovery.received_tx));
    assert_eq!(credited[0].height, Height::new(TIP + 1));
}

#[test]
fn a_reorg_below_the_count_leaves_the_payment_open_and_the_recovery_posted() {
    let (retrying, recovery) = recovered_and_mined();
    retrying.at(TIP + 2);
    assert_eq!(stored_recovery(&retrying).state, RecoveryState::Confirming);
    let record = retrying.record();
    let entries = retrying.sender.transactions().len();

    // The block that held the recovery is replaced by one that does not.
    let pushed = last_pushed(&retrying);
    let excess = pushed.kernels()[0].excess;
    let made: Vec<_> = pushed
        .outputs()
        .iter()
        .map(|output| output.commitment)
        .collect();
    let funding_commitment = retrying.funding;
    retrying.node().update_chain(|chain| {
        chain
            .kernels
            .retain(|kernel| kernel.kernel.excess != excess);
        chain
            .outputs
            .retain(|output| !made.contains(&output.commitment));
        for output in &mut chain.outputs {
            if output.commitment == funding_commitment {
                output.spent = false;
            }
        }
    });
    retrying.at(TIP + 3);

    let waiting = stored_recovery(&retrying);
    assert_eq!(waiting.state, RecoveryState::Posted);
    assert_eq!(waiting.kernel_height, None);
    assert_eq!(retrying.state(), TxState::Finalized);
    assert_eq!(retrying.details().cancelled_reason, None);
    assert_eq!(funding(&retrying).tx, Some(retrying.tx_id));
    assert_eq!(retrying.record(), record);
    let sent = transaction(&retrying, recovery.sent_tx).entry;
    assert_eq!(sent.direction, TxDirection::Outgoing);
    assert_eq!(sent.state, TxState::Posted);
    assert_eq!(funding(&retrying).status, OutputStatus::Locked);
    assert_eq!(
        self::made(&retrying, &recovery).status,
        OutputStatus::Unconfirmed
    );
    assert_eq!(retrying.sender.transactions().len(), entries);

    // The posted recovery is pushed again as any posted send is, and only it.
    let pushes = pushes_of(&retrying, &pushed);
    retrying.walk(TIP + 4..=TIP + 10);
    assert_eq!(pushes_of(&retrying, &pushed), pushes + 1);
    assert_eq!(retrying.record(), record);

    // Mined again, it ends the payment at the count from its new block.
    retrying.mined_at(&pushed, TIP + 11);
    let count = retrying.sender.wallet.minimum_confirmations().unwrap();
    for height in TIP + 11..TIP + 11 + count - 1 {
        retrying.at(height);
        assert_eq!(
            stored_recovery(&retrying).state,
            RecoveryState::Confirming,
            "at {height}"
        );
    }
    retrying.at(TIP + 11 + count - 1);
    let done = stored_recovery(&retrying);
    assert_eq!(done.state, RecoveryState::Done);
    assert_eq!(done.kernel_height.map(Height::value), Some(TIP + 11));
    assert_eq!(retrying.state(), TxState::Cancelled);
    assert_eq!(
        retrying.details().cancelled_reason,
        Some(CancelledReason::Recovered)
    );
    assert_eq!(funding(&retrying).tx, Some(recovery.sent_tx));
}

#[test]
fn the_balance_counts_a_payment_being_recovered_once() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let before = retrying.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(before.total, funding(&retrying).amount);

    let recovery = recover(&retrying).unwrap();

    let made = made(&retrying, &recovery);
    assert_balance_while_open(&retrying, made.amount, "once posted");
}

#[test]
fn a_payment_mined_after_its_recovery_was_posted_ends_the_recovery_failed() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    assert_recovered(&retrying, &recovery);
    let entries = retrying.sender.transactions().len();

    retrying.mined_at(&retrying.final_transaction(), TIP + 1);
    retrying.at(TIP + 1);

    assert_eq!(retrying.state(), TxState::Confirmed);
    let ended = stored_recovery(&retrying);
    assert_eq!(ended.state, RecoveryState::Failed);
    assert_eq!(
        ended.last_error.as_deref(),
        Some("the payment was mined first")
    );
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
    }
    assert_eq!(retrying.sender.transactions().len(), entries);
    let funding = funding(&retrying);
    assert_eq!(funding.status, OutputStatus::Spent);
    assert_eq!(funding.tx, Some(retrying.tx_id));
    // Besides the spent input, only the payment's change is left.
    let others: Vec<_> = retrying
        .sender
        .outputs()
        .into_iter()
        .filter(|output| output.id.commitment != retrying.funding)
        .collect();
    assert_eq!(others.len(), 1, "{others:?}");
    assert_eq!(others[0].status, OutputStatus::Unspent);
    assert_eq!(others[0].tx, Some(retrying.tx_id));
}

#[test]
fn a_payment_without_change_mined_after_its_recovery_was_posted_ends_the_recovery_failed() {
    let retrying = Retrying::failing_without_change(MockFailure::PoolRefused);
    assert_eq!(retrying.final_transaction().outputs().len(), 1);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    assert_recovered(&retrying, &recovery);

    retrying.mined_at(&retrying.final_transaction(), TIP + 1);
    retrying.at(TIP + 1);

    assert_eq!(retrying.state(), TxState::Confirmed);
    let ended = stored_recovery(&retrying);
    assert_eq!(ended.state, RecoveryState::Failed);
    assert_eq!(
        ended.last_error.as_deref(),
        Some("the payment was mined first")
    );
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
    }
    let funding = funding(&retrying);
    assert_eq!(funding.status, OutputStatus::Spent);
    assert_eq!(funding.tx, Some(retrying.tx_id));
    assert_eq!(retrying.sender.outputs(), [funding]);
    let balance = retrying.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(balance.total, Amount::ZERO);
}

/// A payment the node refused, cancelled with its change watched for, then recovered with
/// every push of the recovery ending as `push` does. Returns the payment's transaction too,
/// read before the cancel.
fn cancelled_and_recovered(push: Option<MockFailure>) -> (Retrying, Recovery, Transaction) {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    let payment = retrying.final_transaction();
    retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.cancel(retrying.tx_id))
        .unwrap();
    assert!(
        retrying
            .sender
            .read(|repos| repos.tx_watch(retrying.tx_id))
            .is_some()
    );
    match push {
        Some(failure) => retrying.node().fail_every(PUSH, failure),
        None => retrying.node().stop_failing(PUSH),
    }
    let recovery = recover(&retrying).unwrap();
    (retrying, recovery, payment)
}

/// The change of `payment`: of its outputs, the one the wallet holds.
fn payment_change(retrying: &Retrying, payment: &Transaction) -> OutputRecord {
    let on_chain: Vec<_> = payment
        .outputs()
        .iter()
        .map(|output| output.commitment)
        .collect();
    let change: Vec<_> = retrying
        .sender
        .outputs()
        .into_iter()
        .filter(|output| on_chain.contains(&output.id.commitment))
        .collect();
    assert_eq!(change.len(), 1, "{change:?}");
    change[0].clone()
}

/// A cancelled payment mined while its recovery was open is confirmed with its change, and
/// the recovery ended failed with its pair cancelled, all in the step that found it. `error`
/// is the recovery's error, when the test knows it. The pair stays watched when `watched`:
/// a recovery the node refused for its spent inputs can never be mined and is not.
fn assert_ended_by_the_payment(
    retrying: &Retrying,
    (recovery, payment): (&Recovery, &Transaction),
    error: Option<&str>,
    watched: bool,
) {
    assert_eq!(retrying.state(), TxState::Confirmed);
    let ended = stored_recovery(retrying);
    assert_eq!(ended.state, RecoveryState::Failed);
    if let Some(error) = error {
        assert_eq!(ended.last_error.as_deref(), Some(error));
    }
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(retrying, id).entry.state, TxState::Cancelled);
    }
    assert_eq!(
        retrying
            .sender
            .read(|repos| repos.tx_watch(recovery.sent_tx))
            .is_some(),
        watched
    );
    let funding = funding(retrying);
    assert_eq!(funding.status, OutputStatus::Spent);
    assert_eq!(funding.tx, Some(retrying.tx_id));
    let change = payment_change(retrying, payment);
    assert_eq!(change.status, OutputStatus::Unspent);
    assert_eq!(change.tx, Some(retrying.tx_id));
    // The recovery's output is gone with its pair: only the payment's input and change are left.
    let outputs = retrying.sender.outputs();
    assert_eq!(outputs.len(), 2, "{outputs:?}");
    assert!(outputs.contains(&funding) && outputs.contains(&change));
    let balance = retrying.sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(balance.total, change.amount);
    assert_eq!(balance.locked, Amount::ZERO);
}

fn drained(events: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| events.try_recv().ok()).collect()
}

fn news_in(events: &[Event]) -> Vec<RecoveryState> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::RecoveryChanged(news) => Some(news.state),
            _ => None,
        })
        .collect()
}

/// Every balance raised in `events`, after the last recovery event, totals `total`.
fn assert_balances_after_recovery(events: &[Event], total: Amount) {
    let last = events
        .iter()
        .rposition(|event| matches!(event, Event::RecoveryChanged(_)))
        .unwrap();
    let totals: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Balance(balance) => Some(balance.total),
            _ => None,
        })
        .collect();
    assert!(!totals.is_empty(), "{events:?}");
    assert!(totals.iter().all(|seen| *seen == total), "{totals:?}");
    assert!(
        events[last..]
            .iter()
            .any(|event| matches!(event, Event::Balance(_))),
        "{events:?}"
    );
}

#[test]
fn a_cancelled_payment_mined_while_recovered_ends_the_recovery_in_the_same_refresh() {
    let (retrying, recovery, payment) = cancelled_and_recovered(None);
    assert_recovered(&retrying, &recovery);
    let mut events = retrying.sender.wallet.subscribe();

    retrying.mined_at(&payment, TIP + 1);
    retrying.at(TIP + 1);

    let ended = (&recovery, &payment);
    assert_ended_by_the_payment(&retrying, ended, Some("the payment was mined first"), true);
    let events = drained(&mut events);
    assert_eq!(news_in(&events), [RecoveryState::Failed]);
    assert_balances_after_recovery(&events, payment_change(&retrying, &payment).amount);
}

#[test]
fn a_cancelled_payment_mined_while_its_recovery_is_pushed_again_ends_the_recovery() {
    let (retrying, recovery, payment) = cancelled_and_recovered(Some(MockFailure::Unreachable));
    assert_eq!(recovery.state, RecoveryState::Uncertain);
    retrying.node().stop_failing(PUSH);
    // The node refuses the recovery's push: the mined payment spent its input.
    retrying.node().expect_invalid_pushes();
    let pushes = retrying.pushes();
    let mut events = retrying.sender.wallet.subscribe();

    retrying.mined_at(&payment, TIP + 1);
    retrying.at(TIP + 1);

    assert_eq!(retrying.pushes(), pushes + 1, "the recovery's push was due");
    assert_ended_by_the_payment(&retrying, (&recovery, &payment), None, false);
    let events = drained(&mut events);
    assert_eq!(news_in(&events).last(), Some(&RecoveryState::Failed));
    assert_balances_after_recovery(&events, payment_change(&retrying, &payment).amount);
}

#[test]
fn a_cancelled_payment_a_scan_finds_mined_while_recovered_ends_the_recovery() {
    let (retrying, recovery, payment) = cancelled_and_recovered(None);
    assert_recovered(&retrying, &recovery);
    let mut events = retrying.sender.wallet.subscribe();

    retrying.mined_at(&payment, TIP + 1);
    retrying
        .node()
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 1));
    retrying
        .sender
        .harness
        .block_on(
            retrying
                .sender
                .wallet
                .scan(ScanOptions::update(Network::Floonet), &ScanCancel::new()),
        )
        .unwrap();

    let ended = (&recovery, &payment);
    assert_ended_by_the_payment(&retrying, ended, Some("the payment was mined first"), true);
    assert_eq!(news_in(&drained(&mut events)), [RecoveryState::Failed]);
}

#[test]
fn a_repair_scan_leaves_an_open_recovery_alone() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    assert_recovered(&retrying, &recovery);
    let before = stored(&retrying);

    let repair = ScanOptions {
        delete_unconfirmed: true,
        ..ScanOptions::update(Network::Floonet)
    };
    retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.scan(repair, &ScanCancel::new()))
        .unwrap();

    assert_eq!(stored(&retrying), before);
}

#[test]
fn each_change_of_a_recovery_raises_one_event() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let count = retrying.sender.wallet.minimum_confirmations().unwrap();
    let mut events = retrying.sender.wallet.subscribe();

    recover(&retrying).unwrap();
    assert_eq!(
        recovery_news(&mut events, retrying.tx_id),
        [RecoveryState::Posted]
    );

    retrying.mined_at(&last_pushed(&retrying), TIP + 1);
    let mut news = Vec::new();
    for height in TIP + 1..=TIP + count + 1 {
        retrying.at(height);
        news.push((height, recovery_news(&mut events, retrying.tx_id)));
    }

    let expected: Vec<_> = (TIP + 1..=TIP + count + 1)
        .map(|height| {
            let states = if height == TIP + 1 {
                vec![RecoveryState::Confirming]
            } else if height == TIP + count {
                vec![RecoveryState::Done]
            } else {
                Vec::new()
            };
            (height, states)
        })
        .collect();
    assert_eq!(news, expected);
}

#[test]
fn an_unreachable_recovery_raises_one_event_and_one_more_once_a_refresh_pushes_it() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().fail_every(PUSH, MockFailure::Unreachable);
    let mut events = retrying.sender.wallet.subscribe();

    let recovery = recover(&retrying).unwrap();

    assert_eq!(recovery.state, RecoveryState::Uncertain);
    assert_eq!(
        recovery_news(&mut events, retrying.tx_id),
        [RecoveryState::Uncertain]
    );

    retrying.node().stop_failing(PUSH);
    retrying.walk(TIP + 1..=TIP + 6);

    assert_eq!(stored_recovery(&retrying).state, RecoveryState::Posted);
    assert_eq!(
        recovery_news(&mut events, retrying.tx_id),
        [RecoveryState::Posted]
    );
}

#[test]
fn a_refused_recovery_of_a_cancelled_payment_gives_its_inputs_back_unspent() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.cancel(retrying.tx_id))
        .unwrap();
    retrying
        .node()
        .fail_every(PUSH, MockFailure::Internal(POOL_REFUSALS[2]));

    let recovery = recover(&retrying).unwrap();

    assert_eq!(recovery.state, RecoveryState::Failed);
    assert_eq!(stored_recovery(&retrying), recovery);
    assert_eq!(retrying.state(), TxState::Cancelled);
    let funding = funding(&retrying);
    assert_eq!(funding.status, OutputStatus::Unspent);
    assert_eq!(funding.tx, Some(retrying.tx_id));
}

#[test]
fn a_payment_whose_recovery_failed_can_be_recovered_again() {
    for cancelled in [false, true] {
        let retrying = Retrying::failing(MockFailure::PoolRefused);
        if cancelled {
            retrying
                .sender
                .harness
                .block_on(retrying.sender.wallet.cancel(retrying.tx_id))
                .unwrap();
        }
        retrying
            .node()
            .fail_every(PUSH, MockFailure::Internal(POOL_REFUSALS[2]));
        let first = recover(&retrying).unwrap();
        assert_eq!(first.state, RecoveryState::Failed, "cancelled: {cancelled}");
        retrying.node().stop_failing(PUSH);

        let second = recover(&retrying).unwrap();

        assert_recovered(&retrying, &second);
        assert_ne!(second.sent_tx, first.sent_tx, "cancelled: {cancelled}");
        assert_eq!(
            retrying.sender.read(|repos| repos.recoveries()),
            std::slice::from_ref(&second),
            "cancelled: {cancelled}"
        );
        for id in [first.sent_tx, first.received_tx] {
            assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
        }
        let expected = if cancelled {
            TxState::Cancelled
        } else {
            TxState::Finalized
        };
        assert_eq!(retrying.state(), expected);
    }
}

#[test]
fn a_recovery_whose_inputs_another_wallet_spent_fails_and_the_payment_ends() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    assert_recovered(&retrying, &recovery);

    retrying.input_spent_elsewhere();
    retrying.node().fail_every(PUSH, MockFailure::PoolRefused);
    let pushed_at = retrying.walk(TIP + 1..=TIP + 10);

    assert_eq!(pushed_at, [TIP + 10]);
    let ended = stored_recovery(&retrying);
    assert_eq!(ended.state, RecoveryState::Failed);
    for id in [recovery.sent_tx, recovery.received_tx] {
        assert_eq!(transaction(&retrying, id).entry.state, TxState::Cancelled);
    }
    assert_eq!(retrying.state(), TxState::Cancelled);
    assert_eq!(retrying.details().cancelled_reason, None);
    assert!(
        retrying
            .sender
            .read(|repos| repos.tx_marks(retrying.tx_id))
            .inputs_spent_elsewhere
    );
}

#[test]
fn a_cancelled_payment_recovered_to_the_count_stays_cancelled_as_recovered() {
    let retrying = Retrying::failing(MockFailure::PoolRefused);
    retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.cancel(retrying.tx_id))
        .unwrap();
    retrying.node().stop_failing(PUSH);
    let recovery = recover(&retrying).unwrap();
    assert_recovered(&retrying, &recovery);

    retrying.mined_at(&last_pushed(&retrying), TIP + 1);
    let count = retrying.sender.wallet.minimum_confirmations().unwrap();
    for height in TIP + 1..=TIP + count {
        retrying.at(height);
    }

    assert_eq!(stored_recovery(&retrying).state, RecoveryState::Done);
    assert_eq!(retrying.state(), TxState::Cancelled);
    assert_eq!(
        retrying.details().cancelled_reason,
        Some(CancelledReason::Recovered)
    );
    let funding = funding(&retrying);
    assert_eq!(funding.status, OutputStatus::Spent);
    assert_eq!(funding.tx, Some(recovery.sent_tx));
    let made = made(&retrying, &recovery);
    assert_eq!(made.status, OutputStatus::Unspent);
    assert_eq!(made.height, Height::new(TIP + 1));
}
