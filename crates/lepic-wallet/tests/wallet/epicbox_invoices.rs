// SPDX-License-Identifier: Apache-2.0
//! Invoices and the Epicbox payments address: an invoice or its payment that arrives over
//! Epicbox is acknowledged and dropped, an invoice an older wallet parked is listed until its
//! expiry deletes it, and an invoice issued by file expires unpaid.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::epicbox_world as world;

use std::time::Duration;

use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_slate::codec::WireSlate;
use lepic_store::{OutputStatus, SlateStage, TxState};
use lepic_wallet::Event;
use lepic_wallet::epicbox_invoice::InvoiceExpiry;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice};
use lepic_wallet::selection::{
    SelectionOptions, SelectionStrategy, SelfInputs, SelfOutputs, SelfSendRequest,
};
use lepic_wallet::send::{Delivery, SendRequest};
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, FUNDING, World, pay_request};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The key byte of a peer that posts to the parties, as [`World::post`] takes it.
const PEER: u8 = 8;

fn uuid(slate_id: lepic_slate::model::SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

/// The issuer issues an invoice by file; returns it with its I1.
fn issue_by_file(world: &World, message: Option<&str>) -> (IssuedInvoice, WireSlate) {
    let file = crate::support::file();
    let issued = world
        .block_on(world.issuer.wallet.issue_invoice(
            &file,
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: message.map(str::to_owned),
                ttl_blocks: None,
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("i1.tx"),
                ),
            },
        ))
        .unwrap();
    let i1 = world
        .block_on(world.issuer.wallet.issued_invoice(&file, issued.tx_id))
        .unwrap();
    (issued, i1)
}

fn expired(events: &mut tokio::sync::broadcast::Receiver<Event>) -> usize {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::InvoiceExpired(_)))
        .count()
}

/// An invoice a 0.6.0 wallet parked from an Epicbox sender is listed, pays nothing, and is
/// deleted at its expiry.
#[test]
fn an_old_parked_invoice_is_listed_until_its_expiry_deletes_it() {
    let world = World::new();
    let (issued, i1) = issue_by_file(&world, Some("order 17"));
    world.payer.park(&world.issuer.address, &i1);
    let mut events = world.payer.wallet.subscribe();

    let pending = world
        .payer
        .wallet
        .pending_invoices(InvoiceExpiry::default())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].slate_id, issued.slate_id);
    assert_eq!(pending[0].amount.value(), AMOUNT);
    assert_eq!(pending[0].message.as_deref(), Some("order 17"));
    assert_eq!(pending[0].sender, world.issuer.address.to_string());
    assert_eq!(
        pending[0].expires_at,
        pending[0].received_at.checked_add(DAY).unwrap()
    );
    assert!(
        world
            .payer
            .read(|repos| repos.transactions(ACCOUNT))
            .is_empty()
    );
    let sweep = world
        .block_on(world.payer.wallet.sweep_invoices(InvoiceExpiry::default()))
        .unwrap();
    assert!(sweep.deleted.is_empty(), "{sweep:?}");

    world.payer.clock.advance(DAY + Duration::from_secs(1));
    let sweep = world
        .block_on(world.payer.wallet.sweep_invoices(InvoiceExpiry::default()))
        .unwrap();

    assert_eq!(sweep.deleted, vec![issued.slate_id]);
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoice(uuid(issued.slate_id)))
            .is_none()
    );
    assert!(
        world
            .payer
            .wallet
            .pending_invoices(InvoiceExpiry::default())
            .unwrap()
            .is_empty()
    );
    assert_eq!(expired(&mut events), 1);
}

/// An invoice that arrives at the payments address over Epicbox is acknowledged and dropped:
/// nothing is parked, paid or stored, and the queue moves on.
#[test]
fn an_invoice_over_epicbox_is_acknowledged_and_dropped() {
    let world = World::new();
    let (_, i1) = issue_by_file(&world, None);
    world.post(PEER, &world.payer.address, i1.as_text().unwrap(), 1);

    let summary = world
        .block_on(world.payer.epicbox.drain(&world.payer.wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoices())
            .is_empty()
    );
    assert!(
        world
            .payer
            .read(|repos| repos.transactions(ACCOUNT))
            .is_empty()
    );
}

/// A payment of an invoice that arrives at the issuer over Epicbox is acknowledged and
/// dropped, and the invoice ends at its expiry.
#[test]
fn a_paid_invoice_over_epicbox_is_dropped_and_the_invoice_expires() {
    let world = World::new();
    let (issued, i1) = issue_by_file(&world, None);
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_invoice(&crate::support::file(), &i1, pay_request()),
        )
        .unwrap();
    world.post(
        PEER,
        &world.issuer.address,
        paid.reply.as_text().unwrap(),
        1,
    );
    let mut events = world.issuer.wallet.subscribe();

    let summary = world
        .block_on(world.issuer.epicbox.drain(&world.issuer.wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert!(world.node.pushed_transactions().is_empty());
    assert!(
        world
            .issuer
            .read(|repos| repos.slate(uuid(issued.slate_id), SlateStage::Invoice3))
            .is_none()
    );

    world.issuer.clock.advance(DAY + Duration::from_secs(1));
    let sweep = world
        .block_on(world.issuer.wallet.sweep_invoices(InvoiceExpiry::default()))
        .unwrap();

    assert_eq!(sweep.cancelled, vec![issued.tx_id]);
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.transaction(issued.tx_id))
            .unwrap()
            .state,
        TxState::Cancelled
    );
    assert_eq!(expired(&mut events), 1);
}

#[test]
fn a_cancelled_payment_has_exactly_its_inputs_spent_to_the_payer_itself() {
    let world = World::new();
    // A second output the payer holds, which the self-send must leave alone.
    world.payer.fund(9, 2 * FUNDING);
    let (_, i1) = issue_by_file(&world, None);
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_invoice(&crate::support::file(), &i1, pay_request()),
        )
        .unwrap();
    let locked = |world: &World| -> Vec<_> {
        world
            .payer
            .read(|repos| repos.outputs(ACCOUNT, None))
            .into_iter()
            .filter(|output| output.status == OutputStatus::Locked)
            .map(|output| output.id.commitment)
            .collect()
    };
    let inputs = locked(&world);
    assert_eq!(inputs.len(), 1);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();
    assert!(locked(&world).is_empty());

    // The issuer may still get the signed I2; spending its inputs elsewhere voids it.
    let sent = world
        .block_on(world.payer.wallet.send_to_self(
            SelectionOptions {
                minimum_confirmations: 1,
                ..SelectionOptions::new(ACCOUNT)
            },
            SelfSendRequest {
                inputs: SelfInputs::Named(inputs.clone()),
                outputs: SelfOutputs::Count(1),
            },
            Propagation::Fluff,
        ))
        .unwrap();

    let spent: Vec<_> = sent
        .selection
        .inputs
        .iter()
        .map(|input| input.id.commitment)
        .collect();
    assert_eq!(spent, inputs);
    assert!(sent.selection.change.is_empty());
    assert_eq!(locked(&world), inputs, "the other output stays unspent");
    let pushed = world.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    let pushed_inputs: Vec<_> = pushed[0]
        .inputs()
        .iter()
        .map(|input| input.commitment)
        .collect();
    assert_eq!(pushed_inputs, inputs);
}

#[test]
fn expiry_cancels_an_invoice_issued_by_file_and_left_unpaid() {
    let world = World::new();
    let (issued, _) = issue_by_file(&world, None);
    let expiry = InvoiceExpiry::default();
    assert!(
        world
            .block_on(world.issuer.wallet.sweep_invoices(expiry))
            .unwrap()
            .cancelled
            .is_empty()
    );

    world.issuer.clock.advance(DAY + Duration::from_secs(1));
    let sweep = world
        .block_on(world.issuer.wallet.sweep_invoices(expiry))
        .unwrap();
    assert_eq!(sweep.cancelled, vec![issued.tx_id]);
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.transaction(issued.tx_id))
            .unwrap()
            .state,
        TxState::Cancelled
    );
}

/// A payment S1 posted at the issuer's payments address, exported by file from the payer.
fn exported_s1(world: &World) -> String {
    let path = tempfile::tempdir().unwrap().keep().join("s1.tx");
    world
        .block_on(world.payer.wallet.send(
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(path.clone()),
            },
        ))
        .unwrap();
    std::fs::read_to_string(path).unwrap()
}

/// A message is acknowledged only once its outcome is recorded. Whichever write of the drain
/// fails before the one that records the acknowledgement, the relay still holds the message, and
/// the next drain leaves one received payment.
#[test]
fn a_message_whose_outcome_is_not_recorded_is_not_acknowledged() {
    let probe = World::new();
    let text = exported_s1(&probe);
    probe.post(PEER, &probe.issuer.address, &text, 1);
    let before = probe.issuer.writes();
    let summary = probe
        .block_on(probe.issuer.epicbox.drain(&probe.issuer.wallet))
        .unwrap();
    assert_eq!(summary.received, 1, "{summary:?}");
    let writes = probe.issuer.writes() - before;
    assert!(writes > 1, "{writes} writes");

    let mut held = 0;
    for succeeding in 0..writes {
        let world = World::new();
        let text = exported_s1(&world);
        world.post(PEER, &world.issuer.address, &text, 1);
        world.issuer.fail_write_after(succeeding);
        let first = world
            .block_on(world.issuer.epicbox.drain(&world.issuer.wallet))
            .unwrap();
        let pending = world.relay.pending(&world.issuer.address);
        if succeeding == 0 || succeeding + 1 == writes {
            // The first write notes that the message began, the last that it was acknowledged:
            // a failed one is only logged and the message is still done.
            assert_eq!(pending, 0, "write {succeeding}");
            assert_eq!(first.received, 1, "write {succeeding}: {first:?}");
        } else {
            // Any other write decides whether the message was handled: a failed one leaves it
            // on the relay.
            held += 1;
            assert_eq!(pending, 1, "write {succeeding}: acknowledged all the same");
            assert_eq!(first.held, 1, "write {succeeding}: {first:?}");
        }

        world
            .block_on(world.issuer.epicbox.drain(&world.issuer.wallet))
            .unwrap();
        assert_eq!(world.relay.pending(&world.issuer.address), 0);
        let received = world.issuer.read(|repos| repos.transactions(ACCOUNT)).len();
        assert_eq!(received, 1, "write {succeeding}: one received payment");
    }
    assert_eq!(held, writes - 2, "writes that held the message");
}
