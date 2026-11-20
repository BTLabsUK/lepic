// SPDX-License-Identifier: Apache-2.0
//! mux/1 on the plain mock relay: one store for mux/1 sessions and 3.0.0 clients, and
//! [`MuxSession::waiting`].

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::client_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, client, sealed, secret, settings, within};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    Handled, Identity, MailboxClient, MailboxContent, MailboxEnd, MailboxHandler, MailboxMessage,
    MuxCode, MuxError, MuxEvent, MuxOptions, MuxSession, MuxState, Network,
};
use lepic_transport::transport::BoxFuture;

const LONG: Duration = Duration::from_secs(10);

fn identity(byte: u8) -> Identity {
    Identity::new(secret(byte), address(byte)).unwrap()
}

/// Records what it is handed, and stores it unless told to keep it for later.
#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<String>>>,
    later: Arc<Mutex<bool>>,
}

impl Recorder {
    fn texts(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn set_later(&self, later: bool) {
        *self.later.lock().unwrap() = later;
    }
}

impl MailboxHandler for Recorder {
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            let text = match message.content() {
                MailboxContent::Opened(received) => received.plaintext.expose_str().to_owned(),
                _ => "unopened".to_owned(),
            };
            self.seen.lock().unwrap().push(text);
            if *self.later.lock().unwrap() {
                Handled::Later
            } else {
                Handled::Stored
            }
        })
    }
}

fn mux_relay() -> MockRelay {
    let relay = MockRelay::new(Network::Mainnet);
    relay.offer_mux(true);
    relay
}

fn options() -> MuxOptions {
    MuxOptions::default()
        .with_ack_window(Duration::from_millis(10))
        .with_waiting_every(None)
        .with_hold(Duration::from_secs(1))
}

fn start(relay: &MockRelay, identities: Vec<Identity>) -> (MuxSession, Recorder) {
    let recorder = Recorder::default();
    let session = MuxSession::start(
        settings(),
        relay.connector(),
        identities,
        recorder.clone(),
        options(),
    )
    .unwrap();
    (session, recorder)
}

async fn reaches(session: &MuxSession, wanted: MuxState) {
    let mut state = session.state();
    within(LONG, state.wait_for(|state| *state == wanted))
        .await
        .unwrap();
}

fn store(relay: &MockRelay, to: u8, text: &str) -> String {
    relay.store(&address(CAROL), &address(to), &sealed(CAROL, to, text))
}

/// Drains `mailbox` once over a 3.0.0 `Subscribe` and returns the texts it was handed.
async fn plain_drain(relay: &MockRelay, mailbox: u8) -> Vec<String> {
    let mut handler = Recorder::default();
    let report = within(
        LONG,
        MailboxClient::new(settings(), relay.connector())
            .drain_once(&[identity(mailbox)], &mut handler),
    )
    .await
    .unwrap();
    assert_eq!(report.mailboxes[0].end, MailboxEnd::Empty);
    handler.texts()
}

#[tokio::test]
async fn a_plain_post_is_pushed_to_an_attached_session_and_gone_once_stored() {
    let relay = mux_relay();
    let (session, recorder) = start(&relay, vec![identity(ALICE)]);
    reaches(&session, MuxState::Attached).await;
    within(
        LONG,
        client(&relay, CAROL).post(&address(ALICE), "plain post"),
    )
    .await
    .unwrap();
    relay
        .wait_until(|relay| relay.pending(&address(ALICE)) == 0 && relay.received("Ack") == 1)
        .await;
    assert_eq!(recorder.texts(), ["plain post"]);
    assert_eq!(relay.in_hand(&address(ALICE)), 0);
    assert!(plain_drain(&relay, ALICE).await.is_empty());
}

#[tokio::test]
async fn a_session_post_with_a_ref_lands_for_a_plain_drain() {
    let relay = mux_relay();
    let (session, _) = start(&relay, vec![identity(ALICE)]);
    reaches(&session, MuxState::Attached).await;
    within(
        LONG,
        session.post(&identity(ALICE), &address(BOB), "from the session"),
    )
    .await
    .unwrap();
    assert_eq!(relay.pending(&address(BOB)), 1);
    assert_eq!(plain_drain(&relay, BOB).await, ["from the session"]);
    assert_eq!(relay.pending(&address(BOB)), 0);
}

#[tokio::test]
async fn mail_stored_before_the_attach_arrives_in_full_past_the_in_flight_limit() {
    let relay = mux_relay();
    let ids: Vec<String> = (0..40)
        .map(|n| store(&relay, ALICE, &format!("message {n}")))
        .collect();
    let (session, recorder) = start(&relay, vec![identity(ALICE)]);
    relay
        .wait_until(|relay| relay.pending(&address(ALICE)) == 0)
        .await;
    let expected: Vec<String> = (0..40).map(|n| format!("message {n}")).collect();
    assert_eq!(recorder.texts(), expected);
    assert!(ids.iter().all(|id| relay.deliveries(id) == 1));
    assert_eq!(session.counters().acks, 40);
}

#[tokio::test]
async fn a_message_kept_for_later_is_held_and_survives_a_reconnect() {
    let relay = mux_relay();
    let (session, recorder) = start(&relay, vec![identity(ALICE)]);
    recorder.set_later(true);
    reaches(&session, MuxState::Attached).await;
    let id = store(&relay, ALICE, "not now");
    // Bounded: a message acknowledged instead of held would wait for ever.
    within(
        Duration::from_secs(5),
        relay.wait_until(|relay| relay.received("Hold") == 1),
    )
    .await;
    // The relay answers a hold and pushes in the same step, so a message offered again at once
    // would already show a second delivery.
    assert_eq!(relay.deliveries(&id), 1);
    assert_eq!(relay.pending(&address(ALICE)), 1);
    relay.disconnect_all();
    assert_eq!(relay.pending(&address(ALICE)), 1);
    recorder.set_later(false);
    within(
        Duration::from_secs(5),
        relay.wait_until(|relay| relay.pending(&address(ALICE)) == 0),
    )
    .await;
    assert_eq!(recorder.texts(), ["not now", "not now"]);
    assert_eq!(relay.deliveries(&id), 2);
    assert!(session.counters().sockets_opened >= 2);
}

#[tokio::test]
async fn with_the_switch_off_the_session_ends_as_not_offered() {
    let relay = MockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(ALICE)]);
    reaches(&session, MuxState::NotOffered).await;
    assert_eq!(relay.received("Attach"), 0);
    assert!(matches!(session.stop().await, Err(MuxError::NotOffered)));
}

#[tokio::test]
async fn a_second_socket_takes_the_mailbox_over_and_the_first_is_told() {
    let relay = mux_relay();
    let (first, first_seen) = start(&relay, vec![identity(ALICE)]);
    let mut events = first.events();
    reaches(&first, MuxState::Attached).await;
    let (second, second_seen) = start(&relay, vec![identity(ALICE)]);
    reaches(&second, MuxState::Attached).await;
    within(LONG, async {
        loop {
            if let MuxEvent::Replaced { mailbox: 0 } = events.recv().await.unwrap() {
                return;
            }
        }
    })
    .await;
    store(&relay, ALICE, "for the second");
    relay
        .wait_until(|relay| relay.pending(&address(ALICE)) == 0)
        .await;
    assert_eq!(second_seen.texts(), ["for the second"]);
    assert_eq!(first_seen.count(), 0);
}

#[tokio::test]
async fn waiting_after_a_fresh_claim_accounts_for_every_stored_message() {
    let relay = mux_relay();
    for n in 0..40 {
        store(&relay, ALICE, &format!("message {n}"));
    }
    let session =
        MuxSession::start_queued(settings(), relay.connector(), Vec::new(), options()).unwrap();
    reaches(&session, MuxState::Attached).await;
    let index = session.attach(identity(ALICE)).await.unwrap();
    // No wait in between: the claim's attach must precede the question, and the mail pushed
    // before the answer must be queued when it is returned.
    let answer = session.waiting().await.unwrap();
    let queued = session.take(&[index]).len();
    assert_eq!(answer.waiting.get(&index).copied(), Some(8));
    assert_eq!(answer.inflight, 32);
    assert_eq!(answer.held, 0);
    assert_eq!(queued, 32);
    let counters = session.counters();
    assert_eq!(counters.waiting_probes, 1);
    assert_eq!(counters.stall_reconnects, 0);
}

#[tokio::test]
async fn waiting_with_no_socket_up_fails_at_once() {
    let relay = mux_relay();
    relay.set_refusing(true);
    let (session, _) = start(&relay, vec![identity(ALICE)]);
    let answer = within(Duration::from_secs(1), session.waiting()).await;
    assert!(matches!(answer, Err(MuxError::NotConnected)));
    assert_eq!(session.counters().waiting_probes, 0);
}

#[tokio::test]
async fn waiting_sends_the_gathered_acks_before_it_asks() {
    let relay = mux_relay();
    let options = options().with_ack_window(Duration::from_secs(600));
    let session = MuxSession::start_queued(
        settings(),
        relay.connector(),
        vec![identity(ALICE)],
        options,
    )
    .unwrap();
    reaches(&session, MuxState::Attached).await;
    store(&relay, ALICE, "stored once");
    let mut queued = session.queued();
    within(LONG, queued.wait_for(|count| *count == 1))
        .await
        .unwrap();
    let taken = session.take(&[0]);
    assert_eq!(taken.len(), 1);
    session.settle(taken[0].msg_id(), Handled::Stored).unwrap();
    // The ack window is far off: only the question sends the ack.
    let answer = within(LONG, session.waiting()).await.unwrap();
    assert_eq!(answer.inflight, 0);
    assert_eq!(answer.waiting.get(&0).copied(), Some(0));
    assert_eq!(relay.received("Ack"), 1);
    assert_eq!(relay.pending(&address(ALICE)), 0);
}

/// An attached session on the mux relay with `options`, and nothing to read.
async fn attached_with(relay: &MockRelay, options: MuxOptions) -> MuxSession {
    let session = MuxSession::start_queued(
        settings(),
        relay.connector(),
        vec![identity(ALICE)],
        options,
    )
    .unwrap();
    reaches(&session, MuxState::Attached).await;
    session
}

#[tokio::test]
async fn waiting_past_the_budget_is_paced_and_sends_nothing() {
    let relay = mux_relay();
    let window = Duration::from_millis(400);
    let session = attached_with(&relay, options().with_waiting_budget(3, window)).await;
    for _ in 0..3 {
        within(LONG, session.waiting()).await.unwrap();
    }
    let paced = within(LONG, session.waiting()).await;
    let Err(MuxError::Paced { retry_after }) = paced else {
        panic!("{paced:?}");
    };
    assert!(retry_after <= window, "{retry_after:?}");
    assert_eq!(relay.received("Waiting"), 3);
    assert_eq!(session.counters().waiting_probes, 3);
    // Once the window has passed the requests leave it.
    tokio::time::sleep(window).await;
    within(LONG, session.waiting()).await.unwrap();
    assert_eq!(relay.received("Waiting"), 4);
}

#[tokio::test]
async fn the_session_checks_count_against_the_budget() {
    let relay = mux_relay();
    let options = options()
        .with_waiting_every(Some(Duration::from_millis(20)))
        .with_waiting_budget(2, Duration::from_secs(600));
    let session = attached_with(&relay, options).await;
    within(
        LONG,
        relay.wait_until(|relay| relay.received("Waiting") == 2),
    )
    .await;
    let paced = within(LONG, session.waiting()).await;
    assert!(matches!(paced, Err(MuxError::Paced { .. })), "{paced:?}");
    // More checks are due and skipped.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(relay.received("Waiting"), 2);
    assert_eq!(*session.state().borrow(), MuxState::Attached);
}

#[tokio::test]
async fn a_rate_limited_waiting_pauses_the_session_until_its_retry_after() {
    let relay = mux_relay();
    relay.limit_waiting(Some((2, Duration::from_secs(60))));
    let session = attached_with(&relay, options()).await;
    for _ in 0..2 {
        within(LONG, session.waiting()).await.unwrap();
    }
    let refused = within(LONG, session.waiting()).await;
    assert!(
        matches!(
            refused,
            Err(MuxError::Refused {
                code: Some(MuxCode::RateLimited)
            })
        ),
        "{refused:?}"
    );
    let paced = within(LONG, session.waiting()).await;
    let Err(MuxError::Paced { retry_after }) = paced else {
        panic!("{paced:?}");
    };
    assert!(retry_after > Duration::from_secs(50), "{retry_after:?}");
    assert_eq!(relay.received("Waiting"), 3);
    assert_eq!(relay.waiting_refused(), 1);
    // The refusal leaves the socket up.
    assert_eq!(*session.state().borrow(), MuxState::Attached);
    assert_eq!(relay.connections_made(), 1);
}

#[tokio::test]
async fn retry_now_ends_the_wait_before_the_next_attempt() {
    let relay = mux_relay();
    relay.set_refusing(true);
    let mut settings = settings();
    settings.backoff = lepic_epicbox::Backoff {
        initial: Duration::from_secs(600),
        max: Duration::from_secs(600),
    };
    let session = MuxSession::start_queued(
        settings,
        relay.connector(),
        vec![identity(ALICE)],
        options(),
    )
    .unwrap();
    let mut state = session.state();
    within(
        LONG,
        state.wait_for(|state| matches!(state, MuxState::Waiting { .. })),
    )
    .await
    .unwrap();
    relay.set_refusing(false);
    store(&relay, ALICE, "while away");
    assert_eq!(within(LONG, session.retry_now()).await, MuxState::Attached);
    // Mail pushed before the answer is queued when it comes.
    let answer = within(LONG, session.waiting()).await.unwrap();
    assert_eq!(answer.inflight, 1);
    assert_eq!(session.take(&[0]).len(), 1);
    // An attached session is left alone.
    let opened = session.counters().sockets_opened;
    assert_eq!(within(LONG, session.retry_now()).await, MuxState::Attached);
    assert_eq!(session.counters().sockets_opened, opened);
}
