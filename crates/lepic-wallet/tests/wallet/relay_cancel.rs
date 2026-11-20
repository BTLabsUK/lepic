// SPDX-License-Identifier: Apache-2.0
//! Cancelling a transaction on an Epicbox 3.1.0 relay, on the mock relay: the sender files its
//! S1 under a fresh relay transaction id kept before the post, a retry posts under the same id
//! and the receiver answers under it; either party can cancel it there, and the other party's
//! drain acknowledges the report and changes nothing. A relay older than 3.1.0 gets no id and
//! cannot cancel.
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

use std::sync::Arc;

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{ListenOptions, Nonce, Salt, SignedMessage};
use lepic_primitives::amount::{Amount, Height};
use lepic_slate::model::SlateId;
use lepic_store::{OutputStatus, TxDirection, TxId, TxState};
use lepic_transport::method::Method;
use lepic_transport::transport::{Destination, Inbound as _, RelayTxId};
use lepic_wallet::Event;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::namespace::Listing;
use lepic_wallet::relay_cancel::{
    RelayCancelApplied, RelayCancelResult, TXID_PREFIX, TXID_SLATE_PREFIX,
};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendError, SendRequest, SentSlate};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, TIP, World};

const CANCEL: &str = "3.1.0";
const NO_CANCEL: &str = "3.0.0";

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

/// A world whose relay reports `version`, both parties' registered methods posting under
/// relay transaction ids as the Epicbox method does.
fn world(version: &str) -> World {
    let world = World::new();
    world.relay.set_version(Some(version));
    world.issuer.set_relay_ids(true);
    world.payer.set_relay_ids(true);
    world
}

/// The party's Epicbox method itself, with relay transaction ids and cancel.
fn method(party: &Party) -> Arc<dyn Method> {
    Arc::new(party.epicbox.clone())
}

fn delivery(world: &World) -> Delivery {
    Delivery::Deliver {
        to: Destination::new(world.issuer.address.to_string()),
    }
}

fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

fn try_send(world: &World) -> Result<SentSlate, SendError> {
    world.block_on(
        world
            .payer
            .wallet
            .send(&method(&world.payer), request(), delivery(world)),
    )
}

fn send(world: &World) -> SentSlate {
    try_send(world).unwrap()
}

fn drain(world: &World, party: &Party) -> InboxSummary {
    world.block_on(party.epicbox.drain(&party.wallet)).unwrap()
}

/// The relay transaction id the party filed the slate under.
fn txid_of(party: &Party, slate_id: SlateId) -> Option<String> {
    party.read(|repos| repos.setting(&format!("{TXID_PREFIX}{}", uuid(slate_id))))
}

/// The slate the party filed under the relay transaction id `txid`.
fn slate_of(party: &Party, txid: &str) -> Option<String> {
    party.read(|repos| repos.setting(&format!("{TXID_SLATE_PREFIX}{txid}")))
}

fn state(party: &Party, tx_id: TxId) -> TxState {
    party.read(|repos| repos.transaction(tx_id)).unwrap().state
}

fn received_tx(party: &Party, slate_id: SlateId) -> TxId {
    party
        .read(|repos| repos.transaction_by_slate(uuid(slate_id), TxDirection::Incoming))
        .unwrap()
        .id
}

fn locked_outputs(party: &Party) -> usize {
    party
        .read(|repos| repos.outputs_by_touch(OutputStatus::Locked))
        .len()
}

/// Asks the relay to cancel `tx_id` of `party`, through its Epicbox method.
fn relay_cancel(world: &World, party: &Party, tx_id: TxId) -> RelayCancelResult {
    world
        .block_on(party.wallet.relay_cancel(&method(party), tx_id))
        .unwrap()
}

fn cancel_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| {
            matches!(
                event,
                Event::PaymentCancelled(_) | Event::PaymentDeclined(_)
            )
        })
        .collect()
}

/// A send to the issuer, received there and answered: both parties filed it under one id.
fn answered(world: &World) -> (SentSlate, String) {
    let sent = send(world);
    assert_eq!(drain(world, &world.issuer).received, 1);
    let txid = txid_of(&world.payer, sent.slate_id).unwrap();
    (sent, txid)
}

/// The relay transaction id the reply waiting for the payer was delivered with, read as the
/// payer's own drain would read it.
fn reply_txid(world: &World) -> Option<String> {
    let client = world.payer.client();
    world.block_on(async {
        let subscription = client
            .drain_with(ListenOptions {
                cancel: true,
                ..ListenOptions::default()
            })
            .unwrap();
        let envelope = world
            .within(subscription.next_envelope())
            .await
            .unwrap()
            .unwrap();
        subscription
            .epicbox_txid(envelope.ack_token())
            .map(|txid| txid.as_str().to_owned())
    })
}

#[test]
fn a_send_is_posted_under_a_kept_id_and_answered_under_the_same() {
    let world = world(CANCEL);

    let sent = send(&world);

    let txid = txid_of(&world.payer, sent.slate_id).unwrap();
    assert_eq!(world.relay.posted_txids(), vec![txid.clone()]);
    assert_eq!(
        slate_of(&world.payer, &txid),
        Some(uuid(sent.slate_id).to_string())
    );

    assert_eq!(drain(&world, &world.issuer).received, 1);

    assert_eq!(txid_of(&world.issuer, sent.slate_id), Some(txid.clone()));
    assert_eq!(world.relay.posted_txids(), vec![txid.clone()]);
    assert_eq!(reply_txid(&world), Some(txid));
}

#[test]
fn a_resend_posts_under_the_id_the_first_try_kept() {
    let world = world(CANCEL);
    world.relay.set_post_refused(&world.issuer.address);

    let Err(SendError::Undelivered {
        tx_id, slate_id, ..
    }) = try_send(&world)
    else {
        panic!("the refused post did not fail the send");
    };
    let txid = txid_of(&world.payer, slate_id).unwrap();
    world.relay.set_post_accepted(&world.issuer.address);
    world
        .block_on(
            world
                .payer
                .wallet
                .resend(&method(&world.payer), tx_id, delivery(&world)),
        )
        .unwrap();

    assert_eq!(world.relay.posted_txids().last(), Some(&txid));
    assert_eq!(txid_of(&world.payer, slate_id), Some(txid));
}

#[test]
fn a_relay_without_cancel_gets_no_id_and_cannot_cancel() {
    let world = world(NO_CANCEL);

    let sent = send(&world);
    assert_eq!(drain(&world, &world.issuer).received, 1);

    assert!(world.relay.posted_txids().is_empty());
    assert_eq!(txid_of(&world.issuer, sent.slate_id), None);
    let result = relay_cancel(&world, &world.payer, sent.tx_id);
    assert_eq!(result, RelayCancelResult::Unsupported);
    assert_eq!(state(&world.payer, sent.tx_id), TxState::Sent);
}

#[test]
fn a_relay_cancel_says_what_the_relay_did_and_changes_nothing_here() {
    let world = world(CANCEL);
    let (sent, txid) = answered(&world);

    assert_eq!(
        relay_cancel(&world, &world.payer, sent.tx_id),
        RelayCancelResult::Cancelled
    );

    assert!(world.relay.is_cancelled(&txid));
    assert_eq!(state(&world.payer, sent.tx_id), TxState::Sent);
}

#[test]
fn a_send_filed_under_no_id_has_nothing_to_cancel_on_the_relay() {
    let world = world(CANCEL);
    world.payer.set_relay_ids(false);
    let sent = world
        .block_on(
            world
                .payer
                .wallet
                .send(&world.payer.method, request(), delivery(&world)),
        )
        .unwrap();

    assert_eq!(txid_of(&world.payer, sent.slate_id), None);
    assert_eq!(
        relay_cancel(&world, &world.payer, sent.tx_id),
        RelayCancelResult::NoRelayId
    );
}

#[test]
fn a_relay_cancel_of_an_id_the_relay_never_saw_is_not_found() {
    let world = world(NO_CANCEL);
    let sent = send(&world);
    world.relay.set_version(Some(CANCEL));

    let result = relay_cancel(&world, &world.payer, sent.tx_id);

    assert_eq!(result, RelayCancelResult::NotFoundOrNotParticipant);
}

/// A transaction's state, its marks and the decline setting of its slate, all a relay's
/// cancellation report could have changed.
fn trace(party: &Party, tx_id: TxId, slate_id: SlateId) -> (TxState, bool, Option<String>) {
    let marks = party.read(|repos| repos.tx_marks(tx_id));
    let marked = marks.sender_cancelled_at.is_some();
    let declined =
        party.read(|repos| repos.setting(&format!("notice.send_declined.{}", uuid(slate_id))));
    (state(party, tx_id), marked, declined)
}

#[test]
fn a_payment_its_sender_cancelled_on_the_relay_stays_as_it_is() {
    let world = world(CANCEL);
    let (sent, _) = answered(&world);
    let received = received_tx(&world.issuer, sent.slate_id);
    let before = trace(&world.issuer, received, sent.slate_id);
    let mut issuer_events = world.issuer.wallet.subscribe();
    assert_eq!(
        relay_cancel(&world, &world.payer, sent.tx_id),
        RelayCancelResult::Cancelled
    );

    drain(&world, &world.issuer);

    assert_eq!(trace(&world.issuer, received, sent.slate_id), before);
    assert!(!before.1);
    assert!(cancel_events(&mut issuer_events).is_empty());
    assert_eq!(world.relay.unacked_cancels(&world.issuer.address), 0);
}

/// The report does not end the send, so the answer the receiver sent before it still
/// finalizes the payment.
#[test]
fn a_send_its_receiver_cancelled_on_the_relay_is_finalized_with_its_answer() {
    let world = world(CANCEL);
    let (sent, _) = answered(&world);
    let received = received_tx(&world.issuer, sent.slate_id);
    assert_ne!(locked_outputs(&world.payer), 0);
    assert_eq!(
        relay_cancel(&world, &world.issuer, received),
        RelayCancelResult::Cancelled
    );
    let mut payer_events = world.payer.wallet.subscribe();

    assert_eq!(drain(&world, &world.payer).finalized, 1);

    assert_eq!(
        trace(&world.payer, sent.tx_id, sent.slate_id),
        (TxState::Posted, false, None)
    );
    assert!(cancel_events(&mut payer_events).is_empty());
    assert_eq!(world.relay.unacked_cancels(&world.payer.address), 0);
}

#[test]
fn a_cancellation_of_a_posted_transaction_leaves_it_and_is_acknowledged() {
    let world = world(CANCEL);
    let (sent, _) = answered(&world);
    let received = received_tx(&world.issuer, sent.slate_id);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    assert_eq!(state(&world.payer, sent.tx_id), TxState::Posted);
    relay_cancel(&world, &world.issuer, received);
    let mut payer_events = world.payer.wallet.subscribe();

    drain(&world, &world.payer);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Posted);
    assert!(cancel_events(&mut payer_events).is_empty());
    assert_eq!(world.relay.unacked_cancels(&world.payer.address), 0);
}

#[test]
fn a_cancellation_of_no_transaction_here_is_acknowledged() {
    let world = world(CANCEL);
    let stranger = World::address_of(9);
    let txid = "0123456789ab4def8123456789abcdef";
    world.relay.store_with_txid(
        &stranger,
        &world.payer.address,
        &SignedMessage::seal(
            "{}",
            &world.payer.address,
            &world::key(9),
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap(),
        txid,
    );
    assert!(world.relay.cancel_as(&stranger, txid));

    drain(&world, &world.payer);

    assert_eq!(world.relay.unacked_cancels(&world.payer.address), 0);
    let applied = world
        .block_on(
            world
                .payer
                .wallet
                .apply_relay_cancellation(&RelayTxId::new(txid.to_owned())),
        )
        .unwrap();
    assert_eq!(applied, RelayCancelApplied::Unknown);
}

#[test]
fn a_reported_cancellation_is_kept_each_time() {
    let world = world(CANCEL);
    let (sent, txid) = answered(&world);
    let received = received_tx(&world.issuer, sent.slate_id);
    let before = trace(&world.issuer, received, sent.slate_id);
    let mut issuer_events = world.issuer.wallet.subscribe();
    let apply = || {
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .apply_relay_cancellation(&RelayTxId::new(txid.clone())),
            )
            .unwrap()
    };

    assert_eq!(apply(), RelayCancelApplied::Kept { tx_id: received });
    assert_eq!(apply(), RelayCancelApplied::Kept { tx_id: received });

    assert_eq!(trace(&world.issuer, received, sent.slate_id), before);
    assert!(cancel_events(&mut issuer_events).is_empty());
    assert!(
        world
            .relay
            .posted_txids()
            .iter()
            .all(|posted| *posted == txid)
    );
}

#[test]
fn a_listing_drain_acknowledges_a_cancellation_of_a_payment_to_the_listing() {
    let world = world(CANCEL);
    let secret = SecretKey::from_array([0x31; 32]).unwrap();
    let listing = Listing::new(PublicKey::from_secret_key(&secret).unwrap(), 0);
    let at_listing = world
        .issuer
        .epicbox
        .address_at(&world.issuer.wallet, &listing)
        .unwrap();
    let drain_listing = || {
        world
            .block_on(
                world
                    .issuer
                    .epicbox
                    .drain_at(&world.issuer.wallet, &listing),
            )
            .unwrap()
    };
    let sent = world.block_on(world.payer.wallet.send(
        &method(&world.payer),
        request(),
        Delivery::Deliver {
            to: Destination::new(at_listing.to_string()),
        },
    ));
    let sent = sent.unwrap();
    assert_eq!(drain_listing().received, 1);
    let received = received_tx(&world.issuer, sent.slate_id);
    let before = trace(&world.issuer, received, sent.slate_id);
    let mut issuer_events = world.issuer.wallet.subscribe();
    assert_eq!(
        relay_cancel(&world, &world.payer, sent.tx_id),
        RelayCancelResult::Cancelled
    );
    assert_eq!(world.relay.unacked_cancels(&at_listing), 1);

    drain_listing();

    assert_eq!(trace(&world.issuer, received, sent.slate_id), before);
    assert!(cancel_events(&mut issuer_events).is_empty());
    assert_eq!(world.relay.unacked_cancels(&at_listing), 0);
}

/// Blocks after the tip at which a send of [`send_expiring`] expires.
const TTL_BLOCKS: u64 = 10;

/// `CancelTx` frames the relay received.
fn cancels_received(world: &World) -> usize {
    world.relay.received("CancelTx")
}

/// A send to the issuer, never answered, that expires [`TTL_BLOCKS`] past the tip.
fn send_expiring(world: &World) -> SentSlate {
    let request = SendRequest {
        ttl_blocks: Some(TTL_BLOCKS),
        ..request()
    };
    world
        .block_on(
            world
                .payer
                .wallet
                .send(&method(&world.payer), request, delivery(world)),
        )
        .unwrap()
}

/// Moves the node's tip to the send's cutoff and refreshes the payer.
fn refresh_past_cutoff(world: &World) {
    world
        .node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + TTL_BLOCKS));
    world.block_on(world.payer.wallet.refresh()).unwrap();
}

/// Cancels `tx_id` of the payer here and on the relay.
fn cancel_with_relay(world: &World, tx_id: TxId) {
    world
        .block_on(world.payer.wallet.cancel_with_relay(tx_id))
        .unwrap();
}

#[test]
fn a_cancel_with_the_relay_cancels_there_once() {
    let world = world(CANCEL);
    let sent = send(&world);
    let txid = txid_of(&world.payer, sent.slate_id).unwrap();

    cancel_with_relay(&world, sent.tx_id);
    cancel_with_relay(&world, sent.tx_id);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Cancelled);
    assert!(world.relay.is_cancelled(&txid));
    assert_eq!(cancels_received(&world), 1);
}

#[test]
fn a_cancel_with_a_relay_without_cancel_sends_it_no_cancel() {
    let world = world(NO_CANCEL);
    let sent = send(&world);

    cancel_with_relay(&world, sent.tx_id);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Cancelled);
    assert_eq!(cancels_received(&world), 0);
}

#[test]
fn a_cancel_with_the_relay_stands_when_the_relay_fails_it() {
    let world = world(CANCEL);
    let sent = send(&world);
    let txid = txid_of(&world.payer, sent.slate_id).unwrap();
    world.relay.set_cancel_error(Some("Unauthorized"));

    cancel_with_relay(&world, sent.tx_id);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Cancelled);
    assert_eq!(locked_outputs(&world.payer), 0);
    assert!(!world.relay.is_cancelled(&txid));
}

#[test]
fn a_cancel_with_the_relay_stands_when_the_relay_cannot_be_reached() {
    let world = world(CANCEL);
    let sent = send(&world);
    world.relay.set_refusing(true);

    cancel_with_relay(&world, sent.tx_id);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Cancelled);
    assert_eq!(locked_outputs(&world.payer), 0);
}

#[test]
fn a_send_that_expires_is_cancelled_on_the_relay_once() {
    let world = world(CANCEL);
    let sent = send_expiring(&world);
    let txid = txid_of(&world.payer, sent.slate_id).unwrap();

    refresh_past_cutoff(&world);
    world.block_on(world.payer.wallet.refresh()).unwrap();

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Expired);
    assert!(world.relay.is_cancelled(&txid));
    assert_eq!(cancels_received(&world), 1);
}

#[test]
fn a_send_that_expires_on_a_relay_without_cancel_sends_it_no_cancel() {
    let world = world(NO_CANCEL);
    let sent = send_expiring(&world);

    refresh_past_cutoff(&world);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Expired);
    assert_eq!(cancels_received(&world), 0);
}

#[test]
fn a_send_that_expires_under_no_relay_id_connects_to_no_relay() {
    let world = world(CANCEL);
    world.payer.set_relay_ids(false);
    let sent = world
        .block_on(world.payer.wallet.send(
            &world.payer.method,
            SendRequest {
                ttl_blocks: Some(TTL_BLOCKS),
                ..request()
            },
            delivery(&world),
        ))
        .unwrap();
    assert_eq!(txid_of(&world.payer, sent.slate_id), None);
    let connections = world.relay.connections_made();

    refresh_past_cutoff(&world);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Expired);
    assert_eq!(world.relay.connections_made(), connections);
}

#[test]
fn a_send_that_expires_stays_expired_when_the_relay_fails_the_cancel() {
    let world = world(CANCEL);
    let sent = send_expiring(&world);
    let txid = txid_of(&world.payer, sent.slate_id).unwrap();
    world.relay.set_cancel_error(Some("Unauthorized"));

    refresh_past_cutoff(&world);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Expired);
    assert_eq!(locked_outputs(&world.payer), 0);
    assert!(!world.relay.is_cancelled(&txid));
}

#[test]
fn a_send_that_expires_stays_expired_when_the_relay_cannot_be_reached() {
    let world = world(CANCEL);
    let sent = send_expiring(&world);
    world.relay.set_refusing(true);

    refresh_past_cutoff(&world);

    assert_eq!(state(&world.payer, sent.tx_id), TxState::Expired);
    assert_eq!(locked_outputs(&world.payer), 0);
}

/// A world at relay version `version` whose payer sent two sends that expire together, and
/// the relay's count of connections made before the refresh that expires them.
fn two_expiring(version: &str) -> (World, [SentSlate; 2], usize) {
    let world = world(version);
    world.payer.fund(20, FUNDING);
    let sent = [send_expiring(&world), send_expiring(&world)];
    let connections = world.relay.connections_made();
    (world, sent, connections)
}

#[test]
fn two_sends_that_expire_together_are_cancelled_on_the_relay_each() {
    let (world, sent, _) = two_expiring(CANCEL);

    refresh_past_cutoff(&world);

    for each in &sent {
        assert_eq!(state(&world.payer, each.tx_id), TxState::Expired);
        let txid = txid_of(&world.payer, each.slate_id).unwrap();
        assert!(world.relay.is_cancelled(&txid));
    }
    assert_eq!(cancels_received(&world), 2);
}

#[test]
fn two_sends_that_expire_together_on_a_relay_without_cancel_cost_one_connection() {
    let (world, sent, connections) = two_expiring(NO_CANCEL);

    refresh_past_cutoff(&world);

    for each in &sent {
        assert_eq!(state(&world.payer, each.tx_id), TxState::Expired);
    }
    assert_eq!(world.relay.connections_made(), connections + 1);
    assert_eq!(cancels_received(&world), 0);
}

#[test]
fn two_sends_that_expire_together_ask_a_failing_relay_once() {
    let (world, sent, connections) = two_expiring(CANCEL);
    world.relay.set_cancel_error(Some("Unauthorized"));

    refresh_past_cutoff(&world);

    for each in &sent {
        assert_eq!(state(&world.payer, each.tx_id), TxState::Expired);
    }
    assert_eq!(world.relay.connections_made(), connections + 1);
    assert_eq!(cancels_received(&world), 1);
}

#[test]
fn two_sends_that_expire_together_stay_expired_when_the_relay_cannot_be_reached() {
    let (world, sent, _) = two_expiring(CANCEL);
    world.relay.set_refusing(true);

    refresh_past_cutoff(&world);

    for each in &sent {
        assert_eq!(state(&world.payer, each.tx_id), TxState::Expired);
    }
    assert_eq!(locked_outputs(&world.payer), 0);
    world.relay.set_refusing(false);
    let connections = world.relay.connections_made();
    world.block_on(world.payer.wallet.refresh()).unwrap();
    assert_eq!(world.relay.connections_made(), connections);
    assert_eq!(cancels_received(&world), 0);
}
