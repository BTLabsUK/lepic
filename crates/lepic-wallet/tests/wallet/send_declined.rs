// SPDX-License-Identifier: Apache-2.0
//! Payments refused by a receiver that takes none it did not ask for (ADR 0045), over Epicbox
//! on the mock relay: the receiver refuses a new S1 and posts nothing back, to a LEPIC sender
//! or any other.
//!
//! The payer of `World` sends. Where a test needs to speak as the sender, the payer sends to
//! the peer key 7, which then posts the S1 on.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::epicbox_world as world;

use lepic_epicbox::EpicboxAddress;
use lepic_primitives::amount::Amount;
use lepic_slate::model::SlateId;
use lepic_store::{TxDirection, TxState};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Event, WalletPolicy};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

/// The peer key that stands for the sender.
const SENDER: u8 = 7;

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn declined_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentDeclined(_)))
        .collect()
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

fn drain(world: &World, party: &Party) {
    world.block_on(party.epicbox.drain(&party.wallet)).unwrap();
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

fn refusing() -> World {
    World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    })
}

fn received(world: &World, sent: &SentSlate) -> bool {
    world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
        .is_some()
}

#[test]
fn a_receiver_that_refuses_payments_posts_nothing_to_a_lepic_sender() {
    let world = refusing();
    let sent = send_to(&world, &world.issuer.address);
    let mut events = world.payer.wallet.subscribe();

    drain(&world, &world.issuer);

    assert!(!received(&world, &sent));
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(
        world.relay.pending(&world.payer.address),
        0,
        "the refusing wallet posts nothing"
    );
    drain(&world, &world.payer);
    assert!(declined_events(&mut events).is_empty());
    let state = world
        .payer
        .read(|repos| repos.transaction(sent.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Sent);
}

#[test]
fn a_receiver_that_refuses_payments_posts_nothing_to_another_sender() {
    let world = refusing();
    let sent = send_to(&world, &World::address_of(SENDER));
    let s1 = only_message(&world, SENDER);
    world.post(SENDER, &world.issuer.address, &s1, 1);

    drain(&world, &world.issuer);

    assert!(!received(&world, &sent));
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(
        world.relay.pending(&World::address_of(SENDER)),
        0,
        "the refusing wallet posts nothing"
    );
}
