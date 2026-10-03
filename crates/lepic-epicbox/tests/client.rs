//! The Epicbox client against the mock relay: subscribing, receiving, acknowledging, sending,
//! redelivery, robustness, stopping and draining.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::time::{Duration, Instant};

use client_support::{
    ALICE, BOB, CAROL, address, client, client_with, reach, sealed, settings, until, within,
};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{ClientError, ConnectionState, Network, RejectionReason};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{AckToken, Destination, Envelope, Inbound, Outbound};

const ONE_SECOND: Duration = Duration::from_secs(1);
const LONG: Duration = Duration::from_secs(5);

fn text(envelope: &Envelope) -> &str {
    envelope.wire().as_text().unwrap()
}

async fn next(inbound: &dyn Inbound) -> Option<Envelope> {
    within(LONG, inbound.next_envelope()).await.unwrap()
}

#[tokio::test]
async fn listener_subscribes_receives_and_acknowledges() {
    let relay = MockRelay::new(Network::Mainnet);
    let id = relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate one"),
    );
    let bob = client(&relay, BOB).listen().unwrap();

    let envelope = next(&bob).await.unwrap();
    assert_eq!(text(&envelope), "slate one");
    assert_eq!(envelope.wire().media_type(), MediaType::JSON);
    assert_eq!(envelope.ack_token().as_str(), id);
    assert_eq!(
        envelope.reply_to().unwrap().as_str(),
        address(ALICE).to_string()
    );
    assert_eq!(bob.relay_version().unwrap().to_string(), "3.0.0");
    assert_eq!(*bob.state().borrow(), ConnectionState::Subscribed);
    assert_eq!(relay.received("ClientDetails"), 1);

    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
    assert_eq!(relay.received("Made"), 1);
    // The relay answers `Made` with a new challenge, which the client signs.
    until(|| relay.received("Subscribe") >= 2).await;
    assert!(next(&bob).await.is_none());
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn sender_posts_and_live_listener_receives_it() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;

    let alice = client(&relay, ALICE);
    let wire = WireSlate::text(MediaType::JSON, "{\"slate\":1}".to_owned());
    let to = Destination::new(address(BOB).to_string());
    within(LONG, alice.deliver(&to, &wire)).await.unwrap();
    assert_eq!(relay.received("PostSlate"), 1);

    within(LONG, bob.delivery_available()).await;
    let envelope = next(&bob).await.unwrap();
    assert_eq!(text(&envelope), "{\"slate\":1}");
    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn sender_reports_an_unreachable_relay() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_refusing(true);
    let result = within(LONG, client(&relay, ALICE).post(&address(BOB), "slate")).await;
    assert!(matches!(result, Err(ClientError::Connect(_))));
}

#[tokio::test]
async fn sender_rejects_a_destination_on_another_network() {
    let relay = MockRelay::new(Network::Mainnet);
    let floonet = lepic_epicbox::EpicboxAddress::new(
        *address(BOB).public_key(),
        Network::Floonet,
        lepic_epicbox::Domain::default(),
        None,
    );
    let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());
    let to = Destination::new(floonet.to_string());
    let result = within(LONG, client(&relay, ALICE).deliver(&to, &wire)).await;
    let Err(TransportError::Backend { source, .. }) = result else {
        panic!("expected a backend error");
    };
    assert!(matches!(
        source.downcast_ref::<ClientError>(),
        Some(ClientError::Destination(_))
    ));
    assert_eq!(relay.received("PostSlate"), 0);
}

#[tokio::test]
async fn redelivery_after_reconnect_is_surfaced_once() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate one"),
    );
    let bob = client(&relay, BOB).listen().unwrap();
    let envelope = next(&bob).await.unwrap();

    relay.disconnect_all();
    until(|| relay.received("Subscribe") >= 2).await;
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    // The relay sent the unacknowledged message again on the new connection.
    assert!(next(&bob).await.is_none());

    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
    assert!(next(&bob).await.is_none());
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn redelivery_to_a_resubscription_is_surfaced_once() {
    let relay = MockRelay::new(Network::Mainnet);
    let id = relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate one"),
    );
    let bob = client(&relay, BOB).listen().unwrap();
    let envelope = next(&bob).await.unwrap();

    // A second session of the same wallet receives the message too, as relays do.
    let drain = client(&relay, BOB).drain().unwrap();
    let again = next(&drain).await.unwrap();
    assert_eq!(again.ack_token(), envelope.ack_token());
    drain.stop().await.unwrap();
    assert_eq!(relay.deliveries(&id), 2);

    // Bob's own socket gets it again after three subscribes while it is unacknowledged.
    for round in 1..=4 {
        relay.send_challenges();
        until(|| relay.received("Subscribe") >= 2 + round).await;
    }
    until(|| relay.deliveries(&id) == 3).await;
    assert!(next(&bob).await.is_none());
    assert_eq!(relay.received("Made"), 0);

    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn relay_discards_messages_left_unacknowledged_for_three_rounds() {
    let relay = MockRelay::new(Network::Mainnet);
    let id = relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "never acknowledged"),
    );
    let bob = client(&relay, BOB).listen().unwrap();
    let _held = next(&bob).await.unwrap();
    for round in 1..=12 {
        relay.send_challenges();
        until(|| relay.received("Subscribe") > round).await;
    }
    assert_eq!(relay.deliveries(&id), 3);
    assert_eq!(relay.pending(&address(BOB)), 0);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn unknown_frames_and_bare_pong_do_not_end_the_session() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;

    relay.broadcast("pong");
    relay.broadcast(r#"{"type":"Surprise","str":"later protocol"}"#);
    relay.broadcast(r#"{"no_type":true}"#);
    relay.broadcast("{ not json");
    relay.broadcast(r#"{"type":"Slate","from":7}"#);
    relay.broadcast(r#"{"type":"Ok"}"#);

    relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "after noise"),
    );
    within(LONG, bob.delivery_available()).await;
    let envelope = next(&bob).await.unwrap();
    assert_eq!(text(&envelope), "after noise");
    assert_eq!(*bob.state().borrow(), ConnectionState::Subscribed);
    assert_eq!(
        relay.received("Subscribe"),
        1,
        "the session was never redone"
    );
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn resubscribes_with_each_new_challenge() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    relay.send_challenges();
    relay.send_challenges();
    until(|| relay.received("Subscribe") == 3).await;
    // An invalid signature would have made the relay drop the subscription and live delivery.
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "live"));
    within(LONG, bob.delivery_available()).await;
    assert_eq!(text(&next(&bob).await.unwrap()), "live");
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn undecryptable_message_is_handed_out_as_a_rejection_and_acknowledged_on_confirmation() {
    let relay = MockRelay::new(Network::Mainnet);
    // Queued for Bob, but encrypted for Carol.
    let rejected = relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, CAROL, "not for bob"),
    );
    relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "for bob"),
    );
    let bob = client(&relay, BOB).drain().unwrap();

    // The relay holds back the next message until the rejection is acknowledged.
    assert!(next(&bob).await.is_none());
    let rejection = bob.next_rejection().unwrap();
    assert_eq!(rejection.reason(), RejectionReason::NotAddressedToUs);
    assert_eq!(rejection.msg_id(), Some(rejected.as_str()));
    assert_eq!(
        rejection.sender(),
        Some(address(ALICE).to_string().as_str())
    );
    assert!(bob.next_rejection().is_none());
    assert_eq!(relay.received("Made"), 0);
    assert_eq!(relay.pending(&address(BOB)), 2);
    assert_eq!(*bob.state().borrow(), ConnectionState::Subscribed);

    within(LONG, bob.acknowledge(rejection.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.pending(&address(BOB)), 1);
    let envelope = next(&bob).await.unwrap();
    assert_eq!(text(&envelope), "for bob");
    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert!(next(&bob).await.is_none());
    within(LONG, bob.finished()).await.unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
}

#[tokio::test]
async fn message_with_a_bad_signature_is_rejected_with_its_reason() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    let signed = sealed(ALICE, BOB, "slate");
    let other = sealed(ALICE, BOB, "another slate");
    let frame = serde_json::json!({
        "type": "Slate",
        "from": address(ALICE).to_string(),
        "str": signed.str,
        "signature": other.signature.to_der_hex(),
        "challenge": "",
        "epicboxmsgid": "forged1",
        "ver": "3.0.0",
    });
    relay.broadcast(&frame.to_string());
    within(LONG, bob.delivery_available()).await;
    let rejection = bob.next_rejection().unwrap();
    assert_eq!(rejection.reason(), RejectionReason::InvalidSignature);
    assert_eq!(rejection.ack_token().as_str(), "forged1");
    assert!(next(&bob).await.is_none());
    bob.stop().await.unwrap();
}

fn slate_frame(from: u8, to: u8, plaintext: &str, msg_id: &str) -> String {
    let sealed = sealed(from, to, plaintext);
    serde_json::json!({
        "type": "Slate",
        "from": address(from).to_string(),
        "str": sealed.str,
        "signature": sealed.signature.to_der_hex(),
        "challenge": "",
        "epicboxmsgid": msg_id,
        "ver": "3.0.0",
    })
    .to_string()
}

#[tokio::test]
async fn relay_id_shaped_like_a_local_token_is_still_acknowledged_to_the_relay() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    relay.broadcast(&slate_frame(ALICE, BOB, "slate", "local-1"));
    within(LONG, bob.delivery_available()).await;
    let envelope = next(&bob).await.unwrap();
    assert_eq!(
        lepic_epicbox::transport::relay_message_id(envelope.ack_token()),
        Some("local-1")
    );
    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.received("Made"), 1);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn a_message_without_an_id_and_a_relay_id_never_share_a_token() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    let unversioned = sealed(ALICE, BOB, "without id");
    let frame = serde_json::json!({
        "type": "Slate",
        "from": address(ALICE).to_string(),
        "str": unversioned.str,
        "signature": unversioned.signature.to_der_hex(),
        "challenge": "",
    });
    relay.broadcast(&frame.to_string());
    relay.broadcast(&slate_frame(ALICE, BOB, "with id", "local-1"));
    within(LONG, bob.delivery_available()).await;
    let without_id = next(&bob).await.unwrap();
    within(LONG, bob.delivery_available()).await;
    let with_id = next(&bob).await.unwrap();
    assert_eq!(text(&with_id), "with id");
    assert_ne!(without_id.ack_token(), with_id.ack_token());
    assert_eq!(
        lepic_epicbox::transport::relay_message_id(without_id.ack_token()),
        None
    );

    within(LONG, bob.acknowledge(without_id.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.received("Made"), 0);
    within(LONG, bob.acknowledge(with_id.ack_token()))
        .await
        .unwrap();
    assert_eq!(relay.received("Made"), 1);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn slate_with_an_oversized_message_id_is_ignored() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    let oversized = "x".repeat(lepic_epicbox::MAX_RELAY_MESSAGE_ID_LEN + 1);
    relay.broadcast(&slate_frame(ALICE, BOB, "oversized", &oversized));
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "valid"));
    within(LONG, bob.delivery_available()).await;
    assert_eq!(text(&next(&bob).await.unwrap()), "valid");
    assert!(bob.next_rejection().is_none());
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn acknowledging_an_unknown_token_fails() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    let result = bob
        .acknowledge(&AckToken::new("never-sent".to_owned()))
        .await;
    assert!(matches!(
        result,
        Err(TransportError::UnknownAcknowledgement { .. })
    ));
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn reconnects_with_backoff_after_the_relay_returns() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_refusing(true);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| {
        matches!(s, ConnectionState::Waiting { attempt: 2.., .. })
    })
    .await;
    // While reconnecting there is nothing to hand out, and acknowledging needs a connection.
    assert!(next(&bob).await.is_none());

    relay.set_refusing(false);
    relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "waited"),
    );
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    within(LONG, bob.delivery_available()).await;
    assert_eq!(text(&next(&bob).await.unwrap()), "waited");
    bob.stop().await.unwrap();
}

fn slow_backoff(ping_interval: Duration) -> lepic_epicbox::ClientSettings {
    let mut settings = settings();
    settings.ping_interval = ping_interval;
    settings.backoff = lepic_epicbox::Backoff {
        initial: Duration::from_millis(200),
        max: Duration::from_secs(2),
    };
    settings
}

#[tokio::test]
async fn backoff_keeps_growing_while_sessions_drop_right_after_subscribing() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client_with(&relay, BOB, slow_backoff(LONG))
        .listen()
        .unwrap();
    for subscribed in 1..=3 {
        until(|| relay.received("Subscribe") >= subscribed).await;
        reach(&bob, |s| s == ConnectionState::Subscribed).await;
        relay.disconnect_all();
    }
    reach(&bob, |s| {
        matches!(s, ConnectionState::Waiting { attempt: 3, .. })
    })
    .await;
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn backoff_starts_over_after_a_session_stays_up_for_a_ping_interval() {
    let relay = MockRelay::new(Network::Mainnet);
    let ping_interval = Duration::from_millis(100);
    let bob = client_with(&relay, BOB, slow_backoff(ping_interval))
        .listen()
        .unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    tokio::time::sleep(ping_interval * 3).await;
    relay.disconnect_all();
    reach(&bob, |s| {
        matches!(s, ConnectionState::Waiting { attempt: 0, .. })
    })
    .await;
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn stop_returns_within_a_second_during_connect() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_stalling(true);
    let mut slow = settings();
    slow.connect_timeout = Duration::from_secs(60);
    let bob = client_with(&relay, BOB, slow).listen().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        *bob.state().borrow(),
        ConnectionState::Connecting { .. }
    ));

    let started = Instant::now();
    within(ONE_SECOND, bob.stop()).await.unwrap();
    assert!(started.elapsed() < ONE_SECOND);
    assert_eq!(*bob.state().borrow(), ConnectionState::Stopped);
}

#[tokio::test]
async fn stop_returns_within_a_second_during_receive() {
    let relay = MockRelay::new(Network::Mainnet);
    let mut quiet = settings();
    quiet.ping_interval = Duration::from_secs(60);
    let bob = client_with(&relay, BOB, quiet).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    let waiting = async { bob.delivery_available().await };

    let started = Instant::now();
    let ((), stopped) = within(ONE_SECOND, async { tokio::join!(waiting, bob.stop()) }).await;
    stopped.unwrap();
    assert!(started.elapsed() < ONE_SECOND);
    assert!(next(&bob).await.is_none());
    until(|| relay.connections() == 0).await;
}

#[tokio::test]
async fn stop_returns_within_a_second_during_backoff() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_refusing(true);
    let mut patient = settings();
    patient.backoff.initial = Duration::from_secs(60);
    patient.backoff.max = Duration::from_secs(60);
    let bob = client_with(&relay, BOB, patient).listen().unwrap();
    reach(&bob, |s| matches!(s, ConnectionState::Waiting { .. })).await;

    let started = Instant::now();
    within(ONE_SECOND, bob.stop()).await.unwrap();
    assert!(started.elapsed() < ONE_SECOND);
}

#[tokio::test]
async fn drain_hands_out_oldest_first_and_returns_when_the_queue_is_empty() {
    let relay = MockRelay::new(Network::Mainnet);
    for plaintext in ["first", "second", "third"] {
        relay.store(
            &address(ALICE),
            &address(BOB),
            &sealed(ALICE, BOB, plaintext),
        );
    }
    let bob = client(&relay, BOB).drain().unwrap();

    let mut received = Vec::new();
    while let Some(envelope) = next(&bob).await {
        received.push(text(&envelope).to_owned());
        within(LONG, bob.acknowledge(envelope.ack_token()))
            .await
            .unwrap();
    }
    assert_eq!(received, ["first", "second", "third"]);
    within(LONG, bob.finished()).await.unwrap();
    assert_eq!(*bob.state().borrow(), ConnectionState::Drained);
    assert_eq!(relay.pending(&address(BOB)), 0);
    until(|| relay.connections() == 0).await;
}

#[tokio::test]
async fn drain_of_an_empty_queue_returns_at_once() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).drain().unwrap();
    assert!(next(&bob).await.is_none());
    within(LONG, bob.finished()).await.unwrap();
    assert_eq!(relay.received("Subscribe"), 1);
}

#[tokio::test]
async fn drain_waits_for_a_handed_out_message_and_leaves_it_on_the_relay_when_stopped() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "kept"));
    relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "behind it"),
    );
    let bob = client(&relay, BOB).drain().unwrap();
    let _held = next(&bob).await.unwrap();
    // The relay sends nothing else until the first message is acknowledged.
    assert!(next(&bob).await.is_none());
    assert_eq!(
        *bob.state().borrow(),
        ConnectionState::Subscribed,
        "a drain stays connected while a message may still be acknowledged"
    );
    within(ONE_SECOND, bob.stop()).await.unwrap();
    assert_eq!(relay.pending(&address(BOB)), 2);
}

#[tokio::test]
async fn drain_reports_an_unreachable_relay() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_refusing(true);
    let bob = client(&relay, BOB).drain().unwrap();
    assert!(matches!(
        within(LONG, bob.next_envelope()).await,
        Err(TransportError::Backend { .. })
    ));
    assert!(matches!(
        within(LONG, bob.finished()).await,
        Err(ClientError::Connect(_))
    ));
    assert!(matches!(bob.finished().await, Err(ClientError::Ended)));
}

#[tokio::test]
async fn messages_pushed_faster_than_consumed_are_bounded() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    // A relay may push without waiting for acknowledgements; the client keeps a bounded number.
    for index in 0..100 {
        let message = sealed(ALICE, BOB, &format!("pushed {index}"));
        let frame = serde_json::json!({
            "type": "Slate",
            "from": address(ALICE).to_string(),
            "str": message.str,
            "signature": message.signature.to_der_hex(),
            "challenge": "",
            "epicboxmsgid": format!("pushed{index}"),
            "ver": "3.0.0",
        });
        relay.broadcast(&frame.to_string());
    }
    relay.broadcast(r#"{"type":"Ok"}"#);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut handed_out = 0;
    while next(&bob).await.is_some() {
        handed_out += 1;
    }
    assert_eq!(handed_out, 64);
    assert_eq!(*bob.state().borrow(), ConnectionState::Subscribed);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn subscription_outside_a_runtime_is_an_error() {
    let relay = std::thread::spawn(|| {
        let relay = MockRelay::new(Network::Mainnet);
        let client = client(&relay, BOB);
        matches!(client.listen(), Err(ClientError::NoRuntime))
    });
    assert!(relay.join().unwrap());
}
