// SPDX-License-Identifier: Apache-2.0
//! The Epicbox 3.1.0 cancel protocol, classic: negotiation and the fallback to 3.0.0, the
//! transaction id on posts and slates, `CancelTx` on a short connection, and the cancellations a
//! listener is told of and acknowledges.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::client_support;

use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, client, sealed, secret, settings, until, within};
use lepic_crypto::PublicKey;
use lepic_epicbox::mock_relay::{CancelForm, MockRelay};
use lepic_epicbox::{
    CancelOutcome, ClientError, ClientFrame, EpicboxTxId, FrameError, Identity, ListenOptions,
    MailboxClient, MailboxError, Network, ProtocolVersion, RelayErrorKind, sign_text, verify_text,
};
use lepic_transport::transport::Inbound;

const LONG: Duration = Duration::from_secs(5);

fn relay_310() -> MockRelay {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_version(Some("3.1.0"));
    relay
}

fn public_key(byte: u8) -> PublicKey {
    PublicKey::from_secret_key(&secret(byte)).unwrap()
}

fn txid() -> EpicboxTxId {
    EpicboxTxId::generate().unwrap()
}

fn with_cancel() -> ListenOptions {
    ListenOptions {
        cancel: true,
        ..ListenOptions::default()
    }
}

/// Waits for the next cancellation a subscription reports.
async fn cancelled(subscription: &lepic_epicbox::Subscription) -> EpicboxTxId {
    within(LONG, async {
        loop {
            if let Some(txid) = subscription.next_cancelled() {
                return txid;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
}

// --- the transaction id and its signature ---------------------------------------------------

#[test]
fn a_generated_txid_is_a_version_4_uuid_in_simple_form() {
    let id = txid();
    assert_eq!(id.as_str().len(), 32);
    assert!(
        id.as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(id.as_str().as_bytes()[12], b'4');
    assert!(matches!(
        id.as_str().as_bytes()[16],
        b'8' | b'9' | b'a' | b'b'
    ));
    assert_eq!(EpicboxTxId::parse(id.as_str()).unwrap(), id);
    assert_eq!(EpicboxTxId::parse(&id.as_str().to_uppercase()).unwrap(), id);
}

#[test]
fn a_text_that_is_not_a_simple_v4_uuid_is_no_txid() {
    for bad in [
        "",
        "abc",
        "550e8400-e29b-41d4-a716-446655440000",
        "550e8400e29b11d4a716446655440000",
        "550e8400e29b41d4c716446655440000",
        "550e8400e29b41d4a71644665544000g",
        "550e8400e29b41d4a7164466554400000",
    ] {
        assert!(EpicboxTxId::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_cancel_signature_is_over_the_bare_txid_with_the_address_key() {
    let id = EpicboxTxId::parse("550e8400e29b41d4a716446655440000").unwrap();
    let ClientFrame::CancelTx {
        address: key,
        epicboxtxid,
        signature,
    } = ClientFrame::cancel_tx(&address(ALICE), &id, &secret(ALICE)).unwrap()
    else {
        panic!("not a CancelTx frame");
    };
    assert_eq!(key, address(ALICE).key_text());
    assert_eq!(epicboxtxid, id);
    let signature = lepic_crypto::EcdsaSignature::from_der_hex(&signature).unwrap();
    verify_text(id.as_str(), &signature, &public_key(ALICE)).unwrap();
    assert!(verify_text(id.as_str(), &signature, &public_key(BOB)).is_err());
    // The same bytes the reference computes: SHA-256 of the 32 characters, ECDSA, DER hex.
    let again = sign_text(id.as_str(), &secret(ALICE)).unwrap();
    assert_eq!(again.to_der_hex(), signature.to_der_hex());
}

#[test]
fn the_cancel_frame_has_the_reference_field_names() {
    let id = EpicboxTxId::parse("550e8400e29b41d4a716446655440000").unwrap();
    let json = ClientFrame::cancel_tx(&address(ALICE), &id, &secret(ALICE))
        .unwrap()
        .to_json()
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["type"], "CancelTx");
    assert_eq!(value["address"], address(ALICE).key_text());
    assert_eq!(value["epicboxtxid"], id.as_str());
    assert!(value["signature"].is_string());
    assert_eq!(value.as_object().unwrap().len(), 4);
}

#[test]
fn a_txid_shaped_challenge_is_still_never_signed() {
    for challenge in [
        "550e8400e29b41d4a716446655440000",
        "550e8400-e29b-41d4-a716-446655440000",
    ] {
        assert!(matches!(
            ClientFrame::subscribe(&address(ALICE), challenge, &secret(ALICE)),
            Err(FrameError::Challenge)
        ));
        assert!(matches!(
            ClientFrame::subscribe_negotiated(
                &address(ALICE),
                challenge,
                &secret(ALICE),
                Some(ProtocolVersion::CANCEL)
            ),
            Err(FrameError::Challenge)
        ));
    }
}

// --- posting -----------------------------------------------------------------------------------

#[tokio::test]
async fn a_post_to_a_3_1_0_relay_carries_a_signed_txid() {
    let relay = relay_310();
    let id = txid();
    let receipt = within(
        LONG,
        client(&relay, ALICE).post_tx(&address(BOB), "hello", &id),
    )
    .await
    .unwrap();
    assert!(receipt.txid_sent);
    assert_eq!(receipt.epicboxtxid.as_ref(), Some(&id));
    assert!(receipt.epicboxmsgid.is_some());
    // The relay only takes the id when the signature verifies against the `from` key.
    assert_eq!(relay.posted_txids(), vec![id.as_str().to_owned()]);
    assert_eq!(relay.pending(&address(BOB)), 1);
}

#[tokio::test]
async fn a_post_to_a_3_0_0_relay_has_no_txid_fields() {
    let relay = MockRelay::new(Network::Mainnet);
    let receipt = within(
        LONG,
        client(&relay, ALICE).post_tx(&address(BOB), "hello", &txid()),
    )
    .await
    .unwrap();
    assert!(!receipt.txid_sent);
    assert_eq!(receipt.epicboxtxid, None);
    assert!(relay.posted_txids().is_empty());
    assert_eq!(relay.pending(&address(BOB)), 1);
}

#[tokio::test]
async fn a_post_to_a_cancelled_transaction_is_refused_with_its_txid() {
    let relay = relay_310();
    let alice = client(&relay, ALICE);
    let id = txid();
    within(LONG, alice.post_tx(&address(BOB), "one", &id))
        .await
        .unwrap();
    let report = within(LONG, alice.cancel(&id)).await.unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);
    let refused = within(LONG, alice.post_tx(&address(BOB), "two", &id)).await;
    assert!(matches!(
        refused,
        Err(ClientError::TransactionCancelled { txid }) if txid == id
    ));
    assert_eq!(relay.pending(&address(BOB)), 1);
}

#[tokio::test]
async fn a_mailbox_post_names_its_txid_and_is_refused_once_cancelled() {
    let relay = relay_310();
    let mailbox = MailboxClient::new(settings(), relay.connector());
    let alice = Identity::new(secret(ALICE), address(ALICE)).unwrap();
    let id = txid();
    within(LONG, mailbox.post_tx(&alice, &address(BOB), "one", &id))
        .await
        .unwrap();
    assert_eq!(relay.posted_txids(), vec![id.as_str().to_owned()]);
    let report = within(LONG, client(&relay, ALICE).cancel(&id))
        .await
        .unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);
    let refused = within(LONG, mailbox.post_tx(&alice, &address(BOB), "two", &id)).await;
    assert!(matches!(
        refused,
        Err(MailboxError::Protocol(ClientError::TransactionCancelled { txid })) if txid == id
    ));
}

// --- negotiation on a listener -----------------------------------------------------------

#[tokio::test]
async fn a_listener_receives_the_txid_of_a_slate_on_3_1_0() {
    let relay = relay_310();
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let bob = client(&relay, BOB).listen_with(with_cancel()).unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(bob.epicbox_txid(envelope.ack_token()), Some(id));
    assert_eq!(bob.relay_version(), Some(ProtocolVersion::CANCEL));
    // `Made` carries the negotiated version: the relay refuses it otherwise.
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    relay
        .wait_until(|relay| relay.pending(&address(BOB)) == 0)
        .await;
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn a_listener_without_cancel_stays_on_3_0_0_and_sees_no_txid() {
    let relay = relay_310();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        txid().as_str(),
    );
    let bob = client(&relay, BOB).listen().unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(bob.epicbox_txid(envelope.ack_token()), None);
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    relay
        .wait_until(|relay| relay.pending(&address(BOB)) == 0)
        .await;
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn a_3_0_0_relay_never_sees_a_cancel_subscription() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "slate"));
    let bob = client(&relay, BOB).listen_with(with_cancel()).unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(bob.epicbox_txid(envelope.ack_token()), None);
    assert!(bob.next_cancelled().is_none());
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn a_cancelrequestid_from_the_relay_is_ignored() {
    let relay = relay_310();
    relay.set_relay_request_ids(true);
    let id = txid();
    let receipt = within(
        LONG,
        client(&relay, ALICE).post_tx(&address(BOB), "hello", &id),
    )
    .await
    .unwrap();
    assert_eq!(receipt.epicboxtxid.as_ref(), Some(&id));
    let bob = client(&relay, BOB).listen_with(with_cancel()).unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(bob.epicbox_txid(envelope.ack_token()), Some(id));
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    bob.stop().await.unwrap();
}

// --- the short cancel connection ---------------------------------------------------------

#[tokio::test]
async fn cancel_is_confirmed_by_transaction_cancelled() {
    let relay = relay_310();
    let alice = client(&relay, ALICE);
    let id = txid();
    within(LONG, alice.post_tx(&address(BOB), "hello", &id))
        .await
        .unwrap();
    let report = within(LONG, alice.cancel(&id)).await.unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);
    assert!(report.other_cancelled.is_empty());
    assert!(relay.is_cancelled(id.as_str()));
    assert_eq!(relay.unacked_cancels(&address(BOB)), 1);
    assert_eq!(relay.received("CancelTx"), 1);
    assert_eq!(relay.received("Made"), 0);
}

#[tokio::test]
async fn a_relay_that_advertises_the_separated_form_gets_the_separated_signature() {
    let relay = relay_310();
    relay.set_cancel_form(true);
    let alice = client(&relay, ALICE);
    let id = txid();
    within(LONG, alice.post_tx(&address(BOB), "hello", &id))
        .await
        .unwrap();
    let report = within(LONG, alice.cancel(&id)).await.unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);
    assert_eq!(relay.cancel_forms(), [CancelForm::Separated]);
}

#[tokio::test]
async fn a_relay_that_does_not_advertise_it_gets_the_bare_signature() {
    // The mock takes only the bare form here and refuses anything else, as a stock relay does.
    let relay = relay_310();
    let alice = client(&relay, ALICE);
    let id = txid();
    within(LONG, alice.post_tx(&address(BOB), "hello", &id))
        .await
        .unwrap();
    let report = within(LONG, alice.cancel(&id)).await.unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);
    assert_eq!(relay.cancel_forms(), [CancelForm::Bare]);
}

#[tokio::test]
async fn cancel_of_an_unknown_txid_is_the_ambiguous_ok() {
    let relay = relay_310();
    let report = within(LONG, client(&relay, ALICE).cancel(&txid()))
        .await
        .unwrap();
    assert_eq!(report.outcome, CancelOutcome::NotFoundOrNotParticipant);
}

#[tokio::test]
async fn cancel_by_a_stranger_is_the_ambiguous_ok_and_cancels_nothing() {
    let relay = relay_310();
    let id = txid();
    within(
        LONG,
        client(&relay, ALICE).post_tx(&address(BOB), "hello", &id),
    )
    .await
    .unwrap();
    let report = within(LONG, client(&relay, CAROL).cancel(&id))
        .await
        .unwrap();
    assert_eq!(report.outcome, CancelOutcome::NotFoundOrNotParticipant);
    assert!(!relay.is_cancelled(id.as_str()));
}

#[tokio::test]
async fn cancel_surfaces_a_relay_error() {
    let relay = relay_310();
    relay.set_cancel_error(Some("UnknownError"));
    let result = within(LONG, client(&relay, ALICE).cancel(&txid())).await;
    assert!(matches!(
        result,
        Err(ClientError::Relay {
            kind: RelayErrorKind::UnknownError
        })
    ));
}

#[tokio::test]
async fn cancel_on_a_3_0_0_relay_is_unsupported_and_sends_nothing() {
    let relay = MockRelay::new(Network::Mainnet);
    let report = within(LONG, client(&relay, ALICE).cancel(&txid()))
        .await
        .unwrap();
    assert!(matches!(
        report.outcome,
        CancelOutcome::Unsupported { relay: Some(version) } if !version.supports_cancel()
    ));
    assert_eq!(relay.received("CancelTx"), 0);
    assert_eq!(relay.received("Subscribe"), 0);
}

#[tokio::test]
async fn cancel_ignores_a_queued_slate_and_leaves_it_on_the_relay() {
    let relay = relay_310();
    let alice = client(&relay, ALICE);
    let id = txid();
    within(LONG, alice.post_tx(&address(BOB), "invoice", &id))
        .await
        .unwrap();
    // The receiver's reply waits for the sender, as a reference wallet would pick it up and
    // finalize before cancelling.
    let reply = relay.store_with_txid(
        &address(BOB),
        &address(ALICE),
        &sealed(BOB, ALICE, "reply"),
        id.as_str(),
    );
    assert_eq!(relay.pending(&address(ALICE)), 1);

    let report = within(LONG, alice.cancel(&id)).await.unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);

    // No `Made`, and no post: the slate was neither acknowledged nor processed.
    assert_eq!(relay.received("Made"), 0);
    assert_eq!(relay.received("PostSlate"), 1);
    assert_eq!(relay.pending(&address(ALICE)), 1);
    // It is still there for a listener of the sender, which decides what to do with it.
    let listener = alice.listen().unwrap();
    let envelope = within(LONG, listener.next_envelope())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        listener
            .relay_message_id(envelope.ack_token())
            .unwrap()
            .as_str(),
        reply
    );
    listener.stop().await.unwrap();
}

#[tokio::test]
async fn cancel_returns_cancellations_of_other_transactions_it_met() {
    let relay = relay_310();
    let (old, new) = (txid(), txid());
    let alice = client(&relay, ALICE);
    within(LONG, alice.post_tx(&address(BOB), "one", &old))
        .await
        .unwrap();
    within(LONG, alice.post_tx(&address(BOB), "two", &new))
        .await
        .unwrap();
    // Bob cancelled the first one earlier; alice's cancel of the second meets it.
    assert!(relay.cancel_as(&address(BOB), old.as_str()));
    let report = within(LONG, alice.cancel(&new)).await.unwrap();
    assert_eq!(report.outcome, CancelOutcome::Cancelled);
    assert_eq!(report.other_cancelled, vec![old.clone()]);
    // The short connection acknowledged nothing: the relay still holds it for a listener.
    assert_eq!(relay.unacked_cancels(&address(ALICE)), 1);
}

// --- cancellations on a listener -----------------------------------------------------------

#[tokio::test]
async fn a_listener_is_told_of_a_cancellation_and_it_is_acknowledged_only_on_request() {
    let relay = relay_310();
    let id = txid();
    let alice = client(&relay, ALICE);
    within(LONG, alice.post_tx(&address(BOB), "hello", &id))
        .await
        .unwrap();
    let bob = client(&relay, BOB).listen_with(with_cancel()).unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    relay
        .wait_until(|relay| relay.pending(&address(BOB)) == 0)
        .await;

    assert_eq!(
        within(LONG, alice.cancel(&id)).await.unwrap().outcome,
        CancelOutcome::Cancelled
    );
    // Alice cancelled, so bob is told.
    assert_eq!(cancelled(&bob).await, id);
    assert_eq!(bob.counters().cancelled, 1);
    assert_eq!(relay.unacked_cancels(&address(BOB)), 1);
    // A new slate waits behind the unacknowledged cancellation.
    let next = relay.store(&address(CAROL), &address(BOB), &sealed(CAROL, BOB, "later"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(relay.deliveries(&next), 0);
    assert_eq!(relay.unacked_cancels(&address(BOB)), 1);

    bob.ack_cancelled(&id).await.unwrap();
    until(|| relay.unacked_cancels(&address(BOB)) == 0).await;
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    // Acknowledging what was not handed out is refused.
    assert!(matches!(
        bob.ack_cancelled(&txid()).await,
        Err(ClientError::NotHandedOut)
    ));
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn an_unacknowledged_cancellation_is_delivered_again_on_the_next_connection() {
    let relay = relay_310();
    let id = txid();
    within(
        LONG,
        client(&relay, ALICE).post_tx(&address(BOB), "hello", &id),
    )
    .await
    .unwrap();
    assert!(relay.cancel_as(&address(ALICE), id.as_str()));
    let bob = client(&relay, BOB).listen_with(with_cancel()).unwrap();
    // The cancellation removed the stored slate: only the cancellation is delivered.
    let first = cancelled(&bob).await;
    assert_eq!(first, id);
    bob.stop().await.unwrap();
    assert_eq!(relay.unacked_cancels(&address(BOB)), 1);

    let again = client(&relay, BOB).listen_with(with_cancel()).unwrap();
    assert_eq!(cancelled(&again).await, id);
    assert_eq!(relay.cancel_deliveries(id.as_str()), 2);
    again.ack_cancelled(&id).await.unwrap();
    until(|| relay.unacked_cancels(&address(BOB)) == 0).await;
    again.stop().await.unwrap();
}

/// A txid of 32 hex digits that is not a version 4 UUID.
const NOT_A_TXID: &str = "0123456789abcdef0123456789abcdef";

/// A relay holding a message for bob and a cancellation of it under `NOT_A_TXID`.
fn relay_with_a_cancel_of_no_txid() -> (MockRelay, String) {
    let relay = relay_310();
    let message = relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "hello"),
        NOT_A_TXID,
    );
    assert!(relay.cancel_as(&address(ALICE), NOT_A_TXID));
    assert_eq!(relay.unacked_cancels(&address(BOB)), 1);
    (relay, message)
}

#[tokio::test]
async fn a_cancellation_without_a_valid_txid_is_dropped_and_the_listener_carries_on() {
    let (relay, message) = relay_with_a_cancel_of_no_txid();
    let bob = client(&relay, BOB).listen_with(with_cancel()).unwrap();

    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(
        bob.relay_message_id(envelope.ack_token()).unwrap().as_str(),
        message
    );
    bob.acknowledge(envelope.ack_token()).await.unwrap();

    assert_eq!(relay.cancel_deliveries(NOT_A_TXID), 1);
    assert_eq!(relay.unacked_cancels(&address(BOB)), 0);
    assert_eq!(bob.next_cancelled(), None);
    assert_eq!(bob.counters().cancelled, 0);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn a_drain_drops_a_cancellation_without_a_valid_txid_and_ends() {
    let (relay, message) = relay_with_a_cancel_of_no_txid();
    let bob = client(&relay, BOB).drain_with(with_cancel()).unwrap();

    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(
        bob.relay_message_id(envelope.ack_token()).unwrap().as_str(),
        message
    );
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    assert!(within(LONG, bob.next_envelope()).await.unwrap().is_none());

    assert_eq!(relay.unacked_cancels(&address(BOB)), 0);
    assert_eq!(bob.next_cancelled(), None);
    bob.stop().await.unwrap();
}
