// SPDX-License-Identifier: Apache-2.0
//! Cancelled sends over Epicbox on the mock relay: a classic address gets stock slates only, so
//! the sender of a cancelled send posts nothing to its receiver, at the cancel or in answer to
//! a late S2, and the late S2 is refused without being finalized.
//!
//! The payer of `World` sends and the issuer receives. Where a test needs to speak as the
//! receiver, the payer sends to the peer key 7, whose messages the test reads and writes.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::epicbox_world as world;

use lepic_epicbox::{EpicboxAddress, EpicboxClient};
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::Amount;
use lepic_slate::model::SlateId;
use lepic_store::{TxDirection, TxId, TxState};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::Event;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

/// The peer key that stands for the receiver.
const PEER: u8 = 7;

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn cancelled_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentCancelled(_)))
        .collect()
}

fn drain(world: &World, party: &Party) -> InboxSummary {
    world.block_on(party.epicbox.drain(&party.wallet)).unwrap()
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

fn cancel(world: &World, tx_id: TxId) {
    world.block_on(world.payer.wallet.cancel(tx_id)).unwrap();
}

/// Takes every message waiting for `peer`, acknowledges it and returns its plaintext.
fn take(world: &World, peer: &EpicboxClient) -> Vec<String> {
    world.block_on(async {
        let subscription = peer.drain().unwrap();
        let mut received = Vec::new();
        while let Some(envelope) = world.within(subscription.next_envelope()).await.unwrap() {
            received.push(envelope.wire().as_text().unwrap().to_owned());
            subscription
                .acknowledge(envelope.ack_token())
                .await
                .unwrap();
        }
        subscription.stop().await.unwrap();
        received
    })
}

fn only(world: &World, peer: &EpicboxClient) -> String {
    let mut received = take(world, peer);
    assert_eq!(received.len(), 1, "{received:?}");
    received.remove(0)
}

fn state(party: &Party, tx_id: TxId) -> TxState {
    party.read(|repos| repos.transaction(tx_id)).unwrap().state
}

#[test]
fn a_send_cancelled_after_its_answer_was_finalized_posts_nothing() {
    let world = World::new();
    let mut receiver_events = world.issuer.wallet.subscribe();
    let sent = send_to(&world, &world.issuer.address);
    assert_eq!(drain(&world, &world.issuer).received, 1);
    let tx_id = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
        .unwrap()
        .id;
    // The sender finalizes the answer, and the node does not take the transaction.
    world
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    assert!(world.node.pushed_transactions().is_empty());

    cancel(&world, sent.tx_id);

    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(drain(&world, &world.issuer), InboxSummary::default());
    assert!(cancelled_events(&mut receiver_events).is_empty());
    assert_eq!(state(&world.issuer, tx_id), TxState::Received);
}

#[test]
fn a_late_answer_to_a_cancelled_send_is_refused_and_posts_nothing() {
    let world = World::new();
    let mut receiver_events = world.issuer.wallet.subscribe();
    let sent = send_to(&world, &world.issuer.address);
    cancel(&world, sent.tx_id);
    assert_eq!(drain(&world, &world.issuer).received, 1);

    let summary = drain(&world, &world.payer);

    assert_eq!((summary.rejected, summary.held), (1, 0), "{summary:?}");
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(drain(&world, &world.issuer), InboxSummary::default());
    assert!(cancelled_events(&mut receiver_events).is_empty());
    assert!(world.node.pushed_transactions().is_empty());
    assert_eq!(state(&world.payer, sent.tx_id), TxState::Cancelled);
}

#[test]
fn a_send_cancelled_before_any_answer_posts_nothing() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    let sent = send_to(&world, &World::address_of(PEER));
    only(&world, &peer);

    cancel(&world, sent.tx_id);

    assert!(take(&world, &peer).is_empty());
}
