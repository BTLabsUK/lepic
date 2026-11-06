// SPDX-License-Identifier: Apache-2.0
//! Payments refused by a receiver that takes none it did not ask for (ADR 0045), over Epicbox
//! on the mock relay: the receiver refuses a new S1 and tells a LEPIC sender with `declined`;
//! the sender takes that notice only from the S1's receiver and only while the send waits for
//! its S2, cancels the send once and raises `PaymentDeclined`.
//!
//! The payer of `World` sends. Where a test needs to speak as the receiver, the payer sends to
//! the peer key 7, so the receiver is a key the test holds.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use lepic_epicbox::{EpicboxAddress, TRANSPORT_ID};
use lepic_primitives::amount::Amount;
use lepic_slate::model::SlateId;
use lepic_store::{TxDirection, TxState};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::event::DeclinedPayment;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Event, WalletPolicy};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

/// The peer key that stands for the receiver.
const RECEIVER: u8 = 7;
/// A key that has nothing to do with the payment.
const STRANGER: u8 = 9;

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn declined_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentDeclined(_)))
        .collect()
}

fn declined(slate_id: SlateId) -> String {
    format!(r#"{{"lepic":1,"type":"declined","slate_id":"{slate_id}"}}"#)
}

fn send_to(world: &World, to: &EpicboxAddress) -> SentSlate {
    world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
}

fn drain(world: &World, party: &Party) {
    world
        .block_on(party.wallet.epicbox_drain(&party.epicbox))
        .unwrap();
}

/// Takes the one message waiting for the peer key `byte`.
fn only_message(world: &World, byte: u8) -> String {
    let peer = world.peer_client(byte);
    world.block_on(async {
        let subscription = peer.drain().unwrap();
        let envelope = world
            .within(subscription.next_envelope())
            .await
            .unwrap()
            .unwrap();
        let text = envelope.wire().as_text().unwrap().to_owned();
        subscription
            .acknowledge(envelope.ack_token())
            .await
            .unwrap();
        subscription.stop().await.unwrap();
        text
    })
}

fn payer_state(world: &World, sent: &SentSlate) -> TxState {
    world
        .payer
        .read(|repos| repos.transaction(sent.tx_id))
        .unwrap()
        .state
}

fn declined_at_is_set(world: &World, sent: &SentSlate) -> bool {
    world
        .block_on(world.payer.wallet.transaction_details(sent.tx_id))
        .unwrap()
        .receiver_declined_at
        .is_some()
}

#[test]
fn a_declined_send_is_cancelled_once_with_one_event() {
    let world = World::new();
    let sent = send_to(&world, &World::address_of(RECEIVER));
    only_message(&world, RECEIVER);
    let mut events = world.payer.wallet.subscribe();

    world.post(RECEIVER, &world.payer.address, &declined(sent.slate_id), 1);
    drain(&world, &world.payer);
    world.post(RECEIVER, &world.payer.address, &declined(sent.slate_id), 1);
    drain(&world, &world.payer);

    assert_eq!(
        declined_events(&mut events),
        vec![Event::PaymentDeclined(DeclinedPayment {
            tx_id: sent.tx_id,
            slate_id: sent.slate_id,
        })]
    );
    assert_eq!(payer_state(&world, &sent), TxState::Cancelled);
    assert!(declined_at_is_set(&world, &sent));
}

#[test]
fn a_decline_from_another_key_is_ignored() {
    let world = World::new();
    let sent = send_to(&world, &World::address_of(RECEIVER));
    only_message(&world, RECEIVER);
    let mut events = world.payer.wallet.subscribe();

    world.post(STRANGER, &world.payer.address, &declined(sent.slate_id), 1);
    drain(&world, &world.payer);

    assert!(declined_events(&mut events).is_empty());
    assert_eq!(payer_state(&world, &sent), TxState::Sent);
    assert!(!declined_at_is_set(&world, &sent));
}

#[test]
fn a_decline_after_the_answer_cancels_nothing() {
    let world = World::new();
    let sent = send_to(&world, &World::address_of(RECEIVER));
    let s1 = only_message(&world, RECEIVER);
    world.post(RECEIVER, &world.issuer.address, &s1, 1);
    drain(&world, &world.issuer);
    let s2 = only_message(&world, RECEIVER);
    world.post(RECEIVER, &world.payer.address, &s2, 1);
    drain(&world, &world.payer);
    let answered = payer_state(&world, &sent);
    assert_ne!(answered, TxState::Sent);
    let mut events = world.payer.wallet.subscribe();

    world.post(RECEIVER, &world.payer.address, &declined(sent.slate_id), 1);
    drain(&world, &world.payer);

    assert!(declined_events(&mut events).is_empty());
    assert_eq!(payer_state(&world, &sent), answered);
    assert!(!declined_at_is_set(&world, &sent));
}

#[test]
fn a_receiver_that_refuses_payments_declines_a_lepic_send() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    let sent = send_to(&world, &world.issuer.address);
    let mut events = world.payer.wallet.subscribe();

    drain(&world, &world.issuer);
    drain(&world, &world.payer);

    let received = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming));
    assert!(received.is_none());
    assert_eq!(
        declined_events(&mut events),
        vec![Event::PaymentDeclined(DeclinedPayment {
            tx_id: sent.tx_id,
            slate_id: sent.slate_id,
        })]
    );
    assert_eq!(payer_state(&world, &sent), TxState::Cancelled);
}

#[test]
fn a_receiver_that_refuses_payments_still_takes_none_from_a_stock_wallet() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    let sent = send_to(&world, &World::address_of(RECEIVER));
    let s1 = only_message(&world, RECEIVER);
    let unmarked = s1.replace(
        &format!(
            ",\"lepic\":{{\"version\":1,\"f\":{}}}",
            lepic_epicbox::marker::features::LEPIC_FEATURES
        ),
        "",
    );
    assert_ne!(unmarked, s1);
    world.post(RECEIVER, &world.issuer.address, &unmarked, 1);

    drain(&world, &world.issuer);

    let received = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming));
    assert!(received.is_none());
    assert_eq!(
        world.relay.pending(&World::address_of(RECEIVER)),
        0,
        "a stock wallet gets no notice"
    );
}
