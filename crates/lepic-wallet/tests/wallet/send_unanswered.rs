// SPDX-License-Identifier: Apache-2.0
//! A send over stock Epicbox whose receiver never answers, as one at its open receipt caps
//! does: it cannot say that it refused. A refresh a day after the send marks it once, raises
//! the mark as an uncertain delivery, and leaves the send `sent`. An answer that comes later
//! finalizes it and its mark is deleted. Sends over other routes, and sends answered within
//! the day, are not marked.

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

use lepic_epicbox::EpicboxAddress;
use lepic_primitives::amount::Amount;
use lepic_store::{OutboxState, PaymentDelivery, TxState};
use lepic_transport::transport::Destination;
use lepic_wallet::event::DeliveryNews;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Clock, Event};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

/// The peer key that stands for a receiver that never answers.
const SILENT: u8 = 9;

const HOUR: Duration = Duration::from_secs(3_600);

fn send(world: &World) -> SentSlate {
    send_to(world, &World::address_of(SILENT))
}

fn send_to(world: &World, to: &EpicboxAddress) -> SentSlate {
    world
        .block_on(world.payer.wallet.send(
            &world.payer.method,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
}

fn delivery_news(events: &mut Receiver<Event>) -> Vec<DeliveryNews> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::DeliveryChanged(news) => Some(news),
            _ => None,
        })
        .collect()
}

fn refresh(world: &World) {
    world.block_on(world.payer.wallet.refresh()).unwrap();
}

fn drain(world: &World, party: &Party) -> lepic_wallet::inbox::InboxSummary {
    world.block_on(party.epicbox.drain(&party.wallet)).unwrap()
}

fn uuid(sent: &SentSlate) -> Uuid {
    Uuid::from_bytes(*sent.slate_id.as_bytes())
}

/// The keys of the unanswered marks the payer keeps.
fn marks(world: &World) -> Vec<String> {
    world
        .payer
        .read(|repos| repos.settings_with_prefix("send.unanswered."))
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

/// Sets the transport the payer recorded for `sent`.
fn set_transport(world: &World, sent: &SentSlate, transport: &str) {
    world.payer.write(|repos| {
        let mut entry = repos.transaction(sent.tx_id)?.unwrap();
        entry.transport = Some(transport.to_owned());
        repos.update_transaction(sent.tx_id, &entry)
    });
}

/// Refreshes the payer a day and an hour after `sent` and asserts that nothing marked it.
fn assert_not_marked(world: &World, sent: &SentSlate) {
    let mut events = world.payer.wallet.subscribe();
    world.payer.clock.advance(25 * HOUR);
    refresh(world);
    assert!(delivery_news(&mut events).is_empty());
    let details = world
        .block_on(world.payer.wallet.transaction_details(sent.tx_id))
        .unwrap();
    assert_eq!(details.unanswered_at, None);
    assert!(marks(world).is_empty());
}

#[test]
fn a_send_left_unanswered_for_a_day_is_marked_once_and_stays_sent() {
    let world = World::new();
    let sent = send(&world);
    let mut events = world.payer.wallet.subscribe();

    world.payer.clock.advance(23 * HOUR);
    refresh(&world);
    assert!(delivery_news(&mut events).is_empty());
    let details = world
        .block_on(world.payer.wallet.transaction_details(sent.tx_id))
        .unwrap();
    assert_eq!(details.unanswered_at, None);

    world.payer.clock.advance(HOUR);
    refresh(&world);
    let news = delivery_news(&mut events);
    assert_eq!(
        news,
        vec![DeliveryNews {
            slate_id: sent.slate_id,
            state: OutboxState::Uncertain,
            route: World::address_of(SILENT).to_string(),
        }]
    );
    let details = world
        .block_on(world.payer.wallet.transaction_details(sent.tx_id))
        .unwrap();
    assert_eq!(details.transaction.entry.state, TxState::Sent);
    assert_eq!(details.unanswered_at, Some(world.payer.clock.now()));

    // A later refresh raises nothing again.
    world.payer.clock.advance(HOUR);
    refresh(&world);
    assert!(delivery_news(&mut events).is_empty());
}

#[test]
fn a_cancelled_send_is_not_marked() {
    let world = World::new();
    let sent = send(&world);
    world
        .block_on(world.payer.wallet.cancel(sent.tx_id))
        .unwrap();
    let mut events = world.payer.wallet.subscribe();

    world.payer.clock.advance(25 * HOUR);
    refresh(&world);

    assert!(delivery_news(&mut events).is_empty());
    let details = world
        .block_on(world.payer.wallet.transaction_details(sent.tx_id))
        .unwrap();
    assert_eq!(details.unanswered_at, None);
}

#[test]
fn an_answer_after_the_mark_finalizes_the_send_and_the_mark_is_deleted() {
    let world = World::new();
    let sent = send_to(&world, &world.issuer.address);
    world.payer.clock.advance(24 * HOUR);
    refresh(&world);
    assert_eq!(marks(&world).len(), 1);

    assert_eq!(drain(&world, &world.issuer).received, 1);
    assert_eq!(drain(&world, &world.payer).finalized, 1);

    let details = world
        .block_on(world.payer.wallet.transaction_details(sent.tx_id))
        .unwrap();
    assert_ne!(details.transaction.entry.state, TxState::Sent);
    assert_eq!(details.unanswered_at, None);
    refresh(&world);
    assert!(marks(&world).is_empty());
}

#[test]
fn a_send_over_the_file_method_is_not_marked() {
    let world = World::new();
    let sent = send(&world);
    set_transport(&world, &sent, "file");
    assert_not_marked(&world, &sent);
}

#[test]
fn a_send_over_http_is_not_marked() {
    let world = World::new();
    let sent = send(&world);
    set_transport(&world, &sent, "http");
    assert_not_marked(&world, &sent);
}

#[test]
fn a_send_the_contact_outbox_delivers_is_not_marked() {
    let world = World::new();
    let sent = send(&world);
    let now = world.payer.clock.now();
    world.payer.write(|repos| {
        repos.put_payment_delivery(&PaymentDelivery {
            payment_id: uuid(&sent),
            alias: None,
            state: Some(OutboxState::Posted),
            state_reason: None,
            updated_at: now,
        })
    });
    assert_not_marked(&world, &sent);
}

#[test]
fn a_send_finalized_within_the_day_is_not_marked() {
    let world = World::new();
    let sent = send_to(&world, &world.issuer.address);
    assert_eq!(drain(&world, &world.issuer).received, 1);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    assert_not_marked(&world, &sent);
}
