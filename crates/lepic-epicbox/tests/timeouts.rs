//! Every limit the client puts on a relay that goes quiet. Each test ends on the
//! `ClientError::Timeout` the limit produces, within twice the limit, on paused time.

#![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

mod client_support;

use std::time::Duration;

use client_support::{ALICE, BOB, address, client_with, reach, sealed, settings, within};
use lepic_epicbox::mock_relay::{MockRelay, Unanswered};
use lepic_epicbox::{Awaiting, ClientError, ClientSettings, ConnectionState, Network};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{Envelope, Inbound};
use tokio::time::Instant;

const CONNECT: Duration = Duration::from_secs(40);
const RESPONSE: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(30);
/// Longer than any limit here, so a missing limit shows as a hang, not a pass.
const HANG: Duration = Duration::from_secs(600);

/// Distinct limits, so each test shows which one ended it.
fn limits() -> ClientSettings {
    let mut limits = settings();
    limits.connect_timeout = CONNECT;
    limits.response_timeout = RESPONSE;
    limits.ping_interval = PING;
    limits
}

fn assert_timed_out(result: Result<(), ClientError>, awaiting: Awaiting) {
    match result {
        Err(ClientError::Timeout { awaiting: got }) => assert_eq!(got, awaiting),
        other => panic!("expected a timeout awaiting {awaiting:?}, got {other:?}"),
    }
}

/// The wait that started at `started` ended between `limit` and twice `limit` later.
fn assert_ended_within(started: Instant, limit: Duration) {
    let elapsed = started.elapsed();
    assert!(
        elapsed >= limit && elapsed <= limit * 2,
        "ended after {elapsed:?} for a limit of {limit:?}"
    );
}

async fn post_to_bob(relay: &MockRelay) -> Result<(), ClientError> {
    let alice = client_with(relay, ALICE, limits());
    within(HANG, alice.post(&address(BOB), "slate")).await
}

/// A drain holding one handed-out, unacknowledged message, which keeps it connected.
async fn drain_holding_a_message(relay: &MockRelay) -> (lepic_epicbox::Subscription, Envelope) {
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "slate"));
    let bob = client_with(relay, BOB, limits()).drain().unwrap();
    let envelope = within(HANG, bob.next_envelope()).await.unwrap().unwrap();
    (bob, envelope)
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_the_websocket_handshake_is_not_answered() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_stalling(true);
    let started = Instant::now();
    assert_timed_out(post_to_bob(&relay).await, Awaiting::Connection);
    assert_ended_within(started, CONNECT);
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_the_first_challenge_is_not_sent() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_unanswered(Unanswered::Challenge, true);
    let started = Instant::now();
    assert_timed_out(post_to_bob(&relay).await, Awaiting::Challenge);
    assert_ended_within(started, RESPONSE);
    assert_eq!(relay.received("ClientDetails"), 0);
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_client_details_are_not_answered() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_unanswered(Unanswered::ClientDetails, true);
    let started = Instant::now();
    assert_timed_out(post_to_bob(&relay).await, Awaiting::Answer);
    assert_ended_within(started, RESPONSE);
    assert_eq!(relay.received("GetVersion"), 0);
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_the_post_is_not_answered() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_unanswered(Unanswered::PostSlate, true);
    let started = Instant::now();
    assert_timed_out(post_to_bob(&relay).await, Awaiting::Answer);
    assert_ended_within(started, RESPONSE);
    assert_eq!(relay.received("PostSlate"), 1);
}

/// A post to a relay that reads `frames` frames on the connection and then stops reading, so
/// the next frame the client writes cannot leave.
async fn post_to_a_relay_that_stops_reading_after(frames: usize) -> MockRelay {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_stop_reading_after(Some(frames));
    let started = Instant::now();
    assert_timed_out(post_to_bob(&relay).await, Awaiting::Answer);
    // Writing a request and receiving its answer share one response timeout.
    assert_ended_within(started, RESPONSE);
    relay
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_client_details_cannot_be_written() {
    let relay = post_to_a_relay_that_stops_reading_after(0).await;
    assert_eq!(relay.received("ClientDetails"), 0);
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_the_version_request_cannot_be_written() {
    let relay = post_to_a_relay_that_stops_reading_after(1).await;
    assert_eq!(relay.received("ClientDetails"), 1);
    assert_eq!(relay.received("GetVersion"), 0);
}

#[tokio::test(start_paused = true)]
async fn post_ends_when_the_post_cannot_be_written() {
    let relay = post_to_a_relay_that_stops_reading_after(2).await;
    assert_eq!(relay.received("GetVersion"), 1);
    assert_eq!(relay.received("PostSlate"), 0);
}

#[tokio::test(start_paused = true)]
async fn drain_ends_when_the_subscribe_is_not_answered() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_unanswered(Unanswered::Subscribe, true);
    let started = Instant::now();
    let bob = client_with(&relay, BOB, limits()).drain().unwrap();
    assert_timed_out(within(HANG, bob.finished()).await, Awaiting::Answer);
    assert_ended_within(started, RESPONSE);
    assert_eq!(relay.received("Subscribe"), 1);
}

#[tokio::test(start_paused = true)]
async fn drain_ends_when_an_acknowledgement_is_not_answered() {
    let relay = MockRelay::new(Network::Mainnet);
    let (bob, envelope) = drain_holding_a_message(&relay).await;
    relay.set_unanswered(Unanswered::Made, true);
    let started = Instant::now();
    let acknowledged = within(HANG, bob.acknowledge(envelope.ack_token())).await;
    assert!(acknowledged.is_err());
    assert_timed_out(within(HANG, bob.finished()).await, Awaiting::Answer);
    assert_ended_within(started, RESPONSE);
}

#[tokio::test(start_paused = true)]
async fn drain_ends_when_no_challenge_follows_an_accepted_acknowledgement() {
    let relay = MockRelay::new(Network::Mainnet);
    let (bob, envelope) = drain_holding_a_message(&relay).await;
    relay.set_unanswered(Unanswered::Challenge, true);
    let started = Instant::now();
    within(HANG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    assert_timed_out(within(HANG, bob.finished()).await, Awaiting::Challenge);
    assert_ended_within(started, RESPONSE);
    assert_eq!(relay.pending(&address(BOB)), 0);
}

#[tokio::test(start_paused = true)]
async fn session_ends_when_the_relay_stops_reading_and_falls_silent() {
    let relay = MockRelay::new(Network::Mainnet);
    let (bob, _envelope) = drain_holding_a_message(&relay).await;
    relay.stop_reading_subscribed();
    let started = Instant::now();
    assert_timed_out(within(HANG, bob.finished()).await, Awaiting::Traffic);
    // Two ping intervals of silence is the limit, checked at each ping.
    assert_ended_within(started, PING * 2);
}

#[tokio::test(start_paused = true)]
async fn session_ends_when_a_ping_cannot_be_written() {
    let relay = MockRelay::new(Network::Mainnet);
    let (bob, _envelope) = drain_holding_a_message(&relay).await;
    let started = Instant::now();
    relay.stop_reading_subscribed();
    // Each relay ping is answered with a pong the relay never reads, so the connection fills up
    // while the relay keeps it from looking idle.
    relay.ping_subscribed(1024);
    assert_timed_out(within(HANG, bob.finished()).await, Awaiting::Traffic);
    // The first ping is due one interval after subscribing; writing it is limited to one
    // response timeout.
    let elapsed = started.elapsed();
    assert!(
        elapsed >= PING + RESPONSE && elapsed <= PING + RESPONSE * 2,
        "ended after {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn session_ends_when_a_request_cannot_be_written() {
    let relay = MockRelay::new(Network::Mainnet);
    let (bob, _envelope) = drain_holding_a_message(&relay).await;
    relay.stop_reading_subscribed();
    relay.ping_subscribed(1024);
    // A new challenge makes the client write a `Subscribe` into the full connection.
    relay.send_challenges();
    let started = Instant::now();
    assert_timed_out(within(HANG, bob.finished()).await, Awaiting::Answer);
    // Writing a request and receiving its answer share one response timeout.
    assert_ended_within(started, RESPONSE);
}

#[tokio::test(start_paused = true)]
async fn acknowledgement_ends_when_the_subscription_cannot_reconnect_in_time() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "slate"));
    let bob = client_with(&relay, BOB, limits()).listen().unwrap();
    let envelope = within(HANG, bob.next_envelope()).await.unwrap().unwrap();
    relay.set_stalling(true);
    relay.disconnect_all();
    reach(
        &bob,
        |state| matches!(state, ConnectionState::Connecting { attempt } if attempt >= 2),
    )
    .await;
    let started = Instant::now();
    let acknowledged = within(HANG, bob.acknowledge(envelope.ack_token())).await;
    let Err(TransportError::Backend { source, .. }) = acknowledged else {
        panic!("expected a backend error, got {acknowledged:?}");
    };
    let error = *source.downcast::<ClientError>().unwrap();
    assert_timed_out(Err(error), Awaiting::Answer);
    // The acknowledgement waits for two response timeouts, shorter than the stalled connect.
    assert_ended_within(started, RESPONSE * 2);
    bob.stop().await.unwrap();
}
