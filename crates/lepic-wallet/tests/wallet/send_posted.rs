// SPDX-License-Identifier: Apache-2.0
//! Sends over Epicbox on the mock relay and the `posted` report: a classic address gets stock
//! slates only, so the sender of a finalized send posts no notice to its receiver. The report a
//! receiver keeps comes from a paired contact; here it is written to the store, and the tests
//! hold the rules for showing it: while the payment waits, for an hour, never dated ahead of the
//! clock, and only for a payment exchanged with a paired contact.
//!
//! The payer of `World` sends and the issuer receives.

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

use lepic_primitives::amount::Amount;
use lepic_slate::model::SlateId;
use lepic_store::{CONTACT_ID_LEN, ContactId, TxDirection, TxId, TxState, WalletStore};
use lepic_transport::transport::Destination;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Clock, Event};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, PortsMethods, World};

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn posted_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentPosted(_) | Event::InvoicePosted(_)))
        .collect()
}

fn drain(world: &World, party: &Party) -> InboxSummary {
    world.block_on(party.epicbox.drain(&party.wallet)).unwrap()
}

fn send(world: &World) -> SentSlate {
    world
        .block_on(world.payer.wallet.send(
            &world.payer.method,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                to: Destination::new(world.issuer.address.to_string()),
            },
        ))
        .unwrap()
}

/// A payment the payer sent and the issuer received and answered: the issuer's transaction.
fn received(world: &World) -> TxId {
    let sent = send(world);
    assert_eq!(drain(world, &world.issuer).received, 1);
    world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
        .unwrap()
        .id
}

/// Stores a `posted` report for the issuer's payment `tx_id`, dated `at`, as a paired
/// contact's notice leaves it: the payment linked to the contact.
fn report(world: &World, tx_id: TxId, at: jiff::Timestamp) {
    world
        .issuer
        .store()
        .write(|repos| repos.set_tx_contact(tx_id, ContactId([4; CONTACT_ID_LEN])))
        .unwrap();
    report_unlinked(world, tx_id, at);
}

/// Stores a `posted` report for the issuer's payment `tx_id`, dated `at`, with no contact.
fn report_unlinked(world: &World, tx_id: TxId, at: jiff::Timestamp) {
    world
        .issuer
        .store()
        .write(|repos| {
            let mut marks = repos.tx_marks(tx_id)?;
            marks.sender_posted_at = Some(at);
            repos.put_tx_marks(tx_id, &marks)
        })
        .unwrap();
}

fn report_shown(world: &World, tx_id: TxId) -> Option<jiff::Timestamp> {
    world
        .block_on(world.issuer.wallet.transaction_details(tx_id))
        .unwrap()
        .sender_reported_posted_at
}

fn set_transaction(
    world: &World,
    tx_id: TxId,
    change: impl FnOnce(&mut lepic_store::TransactionEntry),
) {
    world
        .issuer
        .store()
        .write(|repos| {
            let mut entry = repos.transaction(tx_id)?.unwrap();
            change(&mut entry);
            repos.update_transaction(tx_id, &entry)
        })
        .unwrap();
}

#[test]
fn a_finalized_send_posts_nothing_to_the_receiver() {
    let world = World::new();
    let mut receiver_events = world.issuer.wallet.subscribe();
    let tx_id = received(&world);

    assert_eq!(drain(&world, &world.payer).finalized, 1);

    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(drain(&world, &world.issuer), InboxSummary::default());
    assert!(posted_events(&mut receiver_events).is_empty());
    assert_eq!(report_shown(&world, tx_id), None);
}

#[test]
fn the_report_is_shown_for_an_hour_while_the_payment_waits() {
    let world = World::new();
    let tx_id = received(&world);
    report(&world, tx_id, world.issuer.clock.now());
    assert!(report_shown(&world, tx_id).is_some());

    world.issuer.clock.advance(Duration::from_secs(59 * 60));
    assert!(report_shown(&world, tx_id).is_some());
    world.issuer.clock.advance(Duration::from_secs(60));

    assert_eq!(report_shown(&world, tx_id), None);
}

#[test]
fn the_report_is_not_shown_once_the_payment_confirmed() {
    let world = World::new();
    let tx_id = received(&world);
    report(&world, tx_id, world.issuer.clock.now());

    set_transaction(&world, tx_id, |entry| entry.state = TxState::Confirmed);

    assert_eq!(report_shown(&world, tx_id), None);
}

#[test]
fn a_report_dated_ahead_of_the_clock_is_not_shown() {
    let world = World::new();
    let tx_id = received(&world);
    let ahead = world
        .issuer
        .clock
        .now()
        .checked_add(jiff::SignedDuration::from_mins(10))
        .unwrap();

    report(&world, tx_id, ahead);

    assert_eq!(report_shown(&world, tx_id), None);
}

/// A classic Epicbox address gets no notices: a report stored for a payment from no contact is
/// not shown.
#[test]
fn a_report_for_a_payment_from_a_classic_address_is_not_shown() {
    let world = World::new();
    let tx_id = received(&world);

    report_unlinked(&world, tx_id, world.issuer.clock.now());

    assert_eq!(report_shown(&world, tx_id), None);
}

#[test]
fn a_report_from_a_contact_is_shown_by_a_wallet_without_methods_in_its_ports() {
    let world = World::with_issuer_methods(PortsMethods::Absent);
    let tx_id = received(&world);

    report(&world, tx_id, world.issuer.clock.now());

    assert!(report_shown(&world, tx_id).is_some());
}
