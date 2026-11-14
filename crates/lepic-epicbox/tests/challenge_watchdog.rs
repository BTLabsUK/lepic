// SPDX-License-Identifier: Apache-2.0
//! A listener leaves a socket the relay stopped challenging. Each test runs on paused time; the
//! mock relay challenges only when told to.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::time::Duration;

use client_support::{ALICE, BOB, address, client, reach, sealed, within};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{ConnectionState, ListenOptions, Network, Subscription};
use lepic_transport::transport::{Envelope, Inbound};
use tokio::time::sleep;

const LONG: Duration = Duration::from_secs(5);

fn seconds(count: u64) -> Duration {
    Duration::from_secs(count)
}

fn rounds(count: u32) -> ListenOptions {
    ListenOptions {
        challenge_rounds: Some(count),
        ..ListenOptions::default()
    }
}

async fn listener(relay: &MockRelay, options: ListenOptions) -> Subscription {
    let bob = client(relay, BOB).listen_with(options).unwrap();
    reach(&bob, |state| state == ConnectionState::Subscribed).await;
    bob
}

async fn next(inbound: &dyn Inbound) -> Envelope {
    within(LONG, inbound.next_envelope())
        .await
        .unwrap()
        .unwrap()
}

/// Two periodic challenges `gap` apart, so the listener learns that interval, then a moment for
/// it to answer.
async fn teach_interval(relay: &MockRelay, gap: u64) {
    for _ in 0..2 {
        sleep(seconds(gap)).await;
        relay.send_challenges();
        sleep(seconds(1)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_listener_reconnects_after_the_learned_interval_and_collects_the_waiting_message() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = listener(&relay, rounds(3)).await;
    teach_interval(&relay, 40).await;
    relay.stall_challenges();
    let id = relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "waiting"),
    );

    // The last challenge came at 81 s and the learned gap is 41 s, so the listener leaves at 204 s; we are at 197 s.
    sleep(seconds(115)).await;
    assert_eq!(relay.connections_made(), 1, "still on the stalled socket");
    assert_eq!(
        relay.deliveries(&id),
        0,
        "the stalled socket was not pushed to"
    );

    sleep(seconds(20)).await;
    assert_eq!(relay.connections_made(), 2);
    let envelope = next(&bob).await;
    assert_eq!(relay.deliveries(&id), 1);
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
    bob.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_listener_that_learned_no_interval_reconnects_after_three_minutes() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = listener(&relay, rounds(3)).await;
    relay.stall_challenges();

    sleep(seconds(170)).await;
    assert_eq!(relay.connections_made(), 1);
    sleep(seconds(20)).await;
    assert_eq!(relay.connections_made(), 2);
    reach(&bob, |state| state == ConnectionState::Subscribed).await;
    bob.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_greeting_does_not_teach_the_interval() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = listener(&relay, rounds(3)).await;
    // One periodic challenge 5 s after the greeting: that gap is not the relay's interval.
    sleep(seconds(5)).await;
    relay.send_challenges();
    sleep(seconds(1)).await;
    relay.stall_challenges();

    // The last challenge came at 5 s; the assumed 60 s gives 185 s. We are at 176 s.
    sleep(seconds(170)).await;
    assert_eq!(relay.connections_made(), 1);
    sleep(seconds(20)).await;
    assert_eq!(relay.connections_made(), 2);
    reach(&bob, |state| state == ConnectionState::Subscribed).await;
    bob.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_relay_that_challenges_on_time_is_never_left() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = listener(&relay, rounds(3)).await;
    for _ in 0..12 {
        sleep(seconds(40)).await;
        relay.send_challenges();
    }
    assert_eq!(relay.connections_made(), 1);
    assert_eq!(relay.received("Unsubscribe"), 0);
    bob.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_challenge_that_answers_a_made_does_not_shorten_the_learned_interval() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = listener(&relay, rounds(3)).await;
    teach_interval(&relay, 100).await;
    // Receiving and acknowledging a message makes the relay challenge at once, 1 s after the
    // periodic one; the learned interval stays 100 s.
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "one"));
    sleep(seconds(1)).await;
    let envelope = next(&bob).await;
    bob.acknowledge(envelope.ack_token()).await.unwrap();
    sleep(seconds(1)).await;
    relay.stall_challenges();

    // Three intervals of 100 s from the challenge at about 203 s end at about 503 s; with the
    // floor of 30 s the listener would have left at about 293 s.
    sleep(seconds(200)).await;
    assert_eq!(relay.connections_made(), 1);
    sleep(seconds(110)).await;
    assert_eq!(relay.connections_made(), 2);
    bob.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_listener_without_the_setting_keeps_its_stalled_socket() {
    let relay = MockRelay::new(Network::Mainnet);
    let bob = listener(&relay, ListenOptions::default()).await;
    relay.stall_challenges();
    sleep(seconds(3000)).await;
    assert_eq!(relay.connections_made(), 1);
    assert_eq!(relay.received("Unsubscribe"), 0);
    bob.stop().await.unwrap();
}
