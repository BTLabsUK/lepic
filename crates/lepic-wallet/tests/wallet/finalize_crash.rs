// SPDX-License-Identifier: Apache-2.0
//! A stop between the node taking a push and the wallet storing the transaction as posted:
//! each write of a finalize fails in turn, the wallet is opened again, and refresh and cancel
//! must leave the spent inputs locked while the node's pool holds the transaction. Covers the
//! sender's finalize of an S2 and the issuer's finalize of an I2.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::epicbox_world as world;

use lepic_crypto::Commitment;
use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_primitives::tx::Transaction;
use lepic_store::{OutputStatus, TxId, TxState};
use lepic_transport::transport::Location;
use lepic_wallet::invoice::InvoiceRequest;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{ProofKey, ReceiveRequest};
use world::{ACCOUNT, AMOUNT, Party, World, pay_request};

/// What one finalize left behind: the transaction it finalized, whether the call failed, and
/// the transaction the node took, if it took one.
struct Stop {
    tx_id: TxId,
    failed: bool,
    pushed: Option<Transaction>,
}

fn export() -> (tempfile::TempDir, Delivery) {
    let dir = tempfile::tempdir().unwrap();
    let delivery = Delivery::Export {
        to: Location::File(dir.path().join("slate.tx")),
    };
    (dir, delivery)
}

fn receive_request() -> ReceiveRequest {
    ReceiveRequest {
        account: None,
        message: None,
        proof_key: ProofKey::Payments,
    }
}

/// The payer sends to the issuer by file and the issuer answers; the payer then finalizes the
/// S2 with `fail` set up on its store first.
fn send_and_finalize(world: &World, fail: impl FnOnce(&Party)) -> Stop {
    let file = crate::support::file();
    let (_dir, delivery) = export();
    let sent = world
        .block_on(world.payer.wallet.send(
            &file,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            delivery,
        ))
        .unwrap();
    let s1 = world
        .block_on(world.payer.wallet.sent_slate(&file, sent.tx_id))
        .unwrap();
    let s2 = world
        .block_on(world.issuer.wallet.receive(&file, &s1, receive_request()))
        .unwrap()
        .reply;
    fail(&world.payer);
    let result = world.block_on(world.payer.wallet.finalize(&file, &s2, Propagation::Fluff));
    stop(world, sent.tx_id, result.is_err())
}

/// The issuer invoices the payer by file and the payer pays; the issuer then finalizes the I2
/// with `fail` set up on its store first. The tx id is the issuer's.
fn invoice_and_finalize(world: &World, fail: impl FnOnce(&Party)) -> (Stop, TxId) {
    let file = crate::support::file();
    let (_dir, delivery) = export();
    let issued = world
        .block_on(world.issuer.wallet.issue_invoice(
            &file,
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
            delivery,
        ))
        .unwrap();
    let i1 = world
        .block_on(world.issuer.wallet.issued_invoice(&file, issued.tx_id))
        .unwrap();
    let paid = world
        .block_on(world.payer.wallet.pay_invoice(&file, &i1, pay_request()))
        .unwrap();
    fail(&world.issuer);
    let result = world.block_on(world.issuer.wallet.finalize_invoice(
        &file,
        &paid.reply,
        Propagation::Fluff,
    ));
    (stop(world, issued.tx_id, result.is_err()), paid.tx_id)
}

fn stop(world: &World, tx_id: TxId, failed: bool) -> Stop {
    let mut pushed = world.node.pushed_transactions();
    assert!(pushed.len() <= 1, "one push at most");
    Stop {
        tx_id,
        failed,
        pushed: pushed.pop(),
    }
}

fn inputs(transaction: &Transaction) -> Vec<Commitment> {
    transaction
        .inputs()
        .iter()
        .map(|input| input.commitment)
        .collect()
}

/// Every input of `transaction` the party holds is still locked.
fn assert_inputs_locked(party: &Party, transaction: &Transaction, when: &str) {
    let spent = inputs(transaction);
    let held: Vec<_> = party
        .read(|repos| repos.outputs(ACCOUNT, None))
        .into_iter()
        .filter(|output| spent.contains(&output.id.commitment))
        .collect();
    assert!(!held.is_empty(), "{when}: the party holds the inputs");
    for output in held {
        assert_eq!(
            output.status,
            OutputStatus::Locked,
            "{when}: an input the node took is released"
        );
    }
}

fn state(party: &Party, tx_id: TxId) -> TxState {
    party.read(|repos| repos.transaction(tx_id)).unwrap().state
}

/// The wallet that pushed is opened again, refreshed and asked to cancel while the node's pool
/// holds `pushed`; the inputs of `holder` stay locked throughout, and a post afterwards
/// records the transaction as posted.
fn assert_survives_the_stop(world: &World, pusher: &Party, tx_id: TxId, pushed: &Transaction) {
    // A real node keeps a transaction it took in its pool; the mock node's push does not.
    world
        .node
        .update_chain(|chain| chain.pool.push(pushed.clone()));
    let reopened = pusher.reopened(&world.node, &world.relay, &world.runtime);
    assert_ne!(state(&reopened, tx_id), TxState::Cancelled);

    world.block_on(reopened.wallet.refresh()).unwrap();
    assert_ne!(state(&reopened, tx_id), TxState::Cancelled, "after refresh");

    let cancelled = world.block_on(reopened.wallet.cancel(tx_id));
    assert_cancel_refused(&cancelled, tx_id);
    assert_ne!(state(&reopened, tx_id), TxState::Cancelled, "after cancel");

    if state(&reopened, tx_id) != TxState::Posted {
        world
            .block_on(reopened.wallet.post(tx_id, Propagation::Fluff))
            .unwrap();
    }
    assert_eq!(state(&reopened, tx_id), TxState::Posted);
}

/// A cancel of a transaction the node holds is refused: as in the pool, or, once a refresh has
/// found it there and recorded it as posted, as a posted transaction.
fn assert_cancel_refused(cancelled: &Result<(), lepic_wallet::WalletError>, tx_id: TxId) {
    assert!(
        matches!(cancelled, Err(lepic_wallet::WalletError::InPool(id)) if *id == tx_id)
            || matches!(
                cancelled,
                Err(lepic_wallet::WalletError::Transition(
                    lepic_wallet::state::InvalidTransition {
                        from: TxState::Posted,
                        to: TxState::Cancelled
                    }
                ))
            ),
        "cancel of a transaction the node holds: {cancelled:?}"
    );
}

/// A write of the sender's finalize fails, after the node took the push or before it: when the
/// node took it, the inputs stay locked across a reopen, a refresh and a cancel, and posting
/// again records the transaction as posted.
#[test]
fn a_stop_after_the_node_took_a_send_keeps_its_inputs_locked() {
    let probe = World::new();
    probe.confirm_tips();
    let mut start = 0;
    let probed = send_and_finalize(&probe, |payer| start = payer.writes());
    assert!(!probed.failed);
    let writes = probe.payer.writes() - start;
    assert!(writes > 0);

    let mut stopped_after_push = 0;
    for succeeding in 0..writes {
        let world = World::new();
        world.confirm_tips();
        let stop = send_and_finalize(&world, |payer| payer.fail_write_after(succeeding));
        let Some(pushed) = stop.pushed else {
            assert!(stop.failed, "write {succeeding}: no push and no failure");
            continue;
        };
        let when = format!("write {succeeding} failed");
        assert_inputs_locked(&world.payer, &pushed, &when);
        if stop.failed {
            stopped_after_push += 1;
        }
        assert_survives_the_stop(&world, &world.payer, stop.tx_id, &pushed);
        assert_inputs_locked(&world.payer, &pushed, &when);
    }
    assert!(
        stopped_after_push > 0,
        "a write after the push failed the finalize"
    );
}

/// As for a send, for the issuer's finalize of a paid invoice: the payer's inputs stay locked,
/// and neither the issuer nor the payer can cancel while the node's pool holds the payment.
#[test]
fn a_stop_after_the_node_took_an_invoice_payment_keeps_the_payer_inputs_locked() {
    let probe = World::new();
    probe.confirm_tips();
    let mut start = 0;
    let (probed, _) = invoice_and_finalize(&probe, |issuer| start = issuer.writes());
    assert!(!probed.failed);
    let writes = probe.issuer.writes() - start;
    assert!(writes > 0);

    let mut stopped_after_push = 0;
    for succeeding in 0..writes {
        let world = World::new();
        world.confirm_tips();
        let (stop, payment) =
            invoice_and_finalize(&world, |issuer| issuer.fail_write_after(succeeding));
        let Some(pushed) = stop.pushed else {
            assert!(stop.failed, "write {succeeding}: no push and no failure");
            continue;
        };
        let when = format!("write {succeeding} failed");
        if stop.failed {
            stopped_after_push += 1;
        }
        assert_survives_the_stop(&world, &world.issuer, stop.tx_id, &pushed);

        // The payer cannot take its inputs back either.
        world.block_on(world.payer.wallet.refresh()).unwrap();
        assert_inputs_locked(&world.payer, &pushed, &when);
        let cancelled = world.block_on(world.payer.wallet.cancel(payment));
        assert_cancel_refused(&cancelled, payment);
        assert_inputs_locked(&world.payer, &pushed, &when);
    }
    assert!(
        stopped_after_push > 0,
        "a write after the push failed the finalize"
    );
}
