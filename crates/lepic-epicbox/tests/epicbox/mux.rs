// SPDX-License-Identifier: Apache-2.0
//! The mux/1 session against the mock mux relay.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::client_support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{
    ALICE, BOB, CAROL, address, sealed, sealed_unbounded, secret, settings, until, within,
};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    ClientFrame, Domain, EpicboxAddress, Handled, Identity, MailboxClient, MailboxContent,
    MailboxHandler, MailboxMessage, MuxCode, MuxError, MuxEvent, MuxOptions, MuxSession, MuxState,
    Network, ProbeStep, WalletMode, probe_mailbox,
};
use lepic_transport::transport::BoxFuture;

fn identity(byte: u8) -> Identity {
    Identity::new(secret(byte), address(byte)).unwrap()
}

/// The `n`th of more mailboxes than a byte can number.
fn numbered(n: u16) -> Identity {
    let mut bytes = [1_u8; 32];
    bytes[..2].copy_from_slice(&n.to_be_bytes());
    bytes[0] = bytes[0].saturating_add(1);
    let secret = SecretKey::from_array(bytes).unwrap();
    let address = EpicboxAddress::new(
        PublicKey::from_secret_key(&secret).unwrap(),
        Network::Mainnet,
        Domain::parse("relay.test").unwrap(),
        Some(443),
    );
    Identity::new(secret, address).unwrap()
}

#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<(usize, String, String)>>>,
    later: Arc<Mutex<bool>>,
}

impl Recorder {
    fn texts(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, _, text)| text.clone())
            .collect()
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
            self.seen.lock().unwrap().push((
                message.mailbox(),
                message.msg_id().as_str().to_owned(),
                text,
            ));
            if *self.later.lock().unwrap() {
                Handled::Later
            } else {
                Handled::Stored
            }
        })
    }
}

fn options() -> MuxOptions {
    MuxOptions::default()
        .with_ack_window(Duration::from_millis(10))
        .with_waiting_every(None)
        .with_hold(Duration::from_secs(2))
}

fn start(
    relay: &MuxMockRelay,
    identities: Vec<Identity>,
    options: MuxOptions,
) -> (MuxSession, Recorder) {
    let recorder = Recorder::default();
    let session = MuxSession::start(
        settings(),
        relay.connector(),
        identities,
        recorder.clone(),
        options,
    )
    .unwrap();
    (session, recorder)
}

async fn attached(session: &MuxSession) {
    let mut state = session.state();
    within(
        Duration::from_secs(5),
        state.wait_for(|state| *state == MuxState::Attached),
    )
    .await
    .unwrap();
}

fn post(relay: &MuxMockRelay, to: u8, text: &str) -> String {
    relay.store(&address(CAROL), &address(to), &sealed(CAROL, to, text))
}

#[test]
fn client_details_bytes_are_unchanged_without_the_extension() {
    assert_eq!(
        ClientFrame::client_details("4.0.2", WalletMode::Listener)
            .to_json()
            .unwrap(),
        r#"{"type":"ClientDetails","wallet_version":"4.0.2","wallet_mode":"listener","protocol_version":"3.0.0"}"#
    );
    assert_eq!(
        ClientFrame::client_details_with_mux("4.0.2", WalletMode::Listener)
            .to_json()
            .unwrap(),
        r#"{"type":"ClientDetails","wallet_version":"4.0.2","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1","txcancel/1","epicbox-cancel/1","epicbox-attach/1"]}"#
    );
}

#[tokio::test]
async fn a_plain_ok_ends_the_session_as_not_offered() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_mux(false);
    let (session, _) = start(&relay, vec![identity(ALICE)], options());
    let mut state = session.state();
    within(
        Duration::from_secs(5),
        state.wait_for(|state| *state == MuxState::NotOffered),
    )
    .await
    .unwrap();
    assert_eq!(relay.received("Attach"), 0);
    assert_eq!(session.counters().signatures, 0);
    assert!(matches!(session.stop().await, Err(MuxError::NotOffered)));
}

#[tokio::test]
async fn an_error_answer_to_the_greeting_ends_a_new_session_as_not_offered() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.answer_greeting_with_error(true);
    let (session, _) = start(&relay, vec![identity(ALICE)], options());
    let mut state = session.state();
    within(
        Duration::from_secs(5),
        state.wait_for(|state| *state == MuxState::NotOffered),
    )
    .await
    .unwrap();
    // No retry: the greeting was sent once.
    assert_eq!(relay.received("ClientDetails"), 1);
    assert_eq!(relay.received("Attach"), 0);
    assert!(matches!(session.stop().await, Err(MuxError::NotOffered)));
}

#[tokio::test]
async fn a_relay_that_never_answers_the_greeting_ends_as_not_offered_after_three_tries() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.ignore_greeting(true);
    let mut quick = settings();
    quick.response_timeout = Duration::from_millis(100);
    let session = start_queued_with(&relay, vec![identity(ALICE)], quick);
    let mut state = session.state();
    within(
        Duration::from_secs(5),
        state.wait_for(|state| *state == MuxState::NotOffered),
    )
    .await
    .unwrap();
    assert_eq!(relay.received("ClientDetails"), 3);
}

#[tokio::test]
async fn a_session_that_attached_once_keeps_trying_when_the_greeting_goes_unanswered() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let mut quick = settings();
    quick.response_timeout = Duration::from_millis(100);
    let session = start_queued_with(&relay, vec![identity(ALICE)], quick);
    attached(&session).await;
    relay.ignore_greeting(true);
    relay.drop_sockets();
    // More than the three tries a new session gets.
    until(|| relay.received("ClientDetails") >= 6).await;
    assert!(!session.state().borrow().has_ended());
    relay.ignore_greeting(false);
    attached(&session).await;
}

#[tokio::test]
async fn a_session_that_attached_once_keeps_trying_when_the_greeting_gets_an_error() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    relay.answer_greeting_with_error(true);
    relay.drop_sockets();
    until(|| relay.received("ClientDetails") >= 3).await;
    assert!(!session.state().borrow().has_ended());
    relay.answer_greeting_with_error(false);
    attached(&session).await;
}

#[tokio::test]
async fn a_challenge_of_the_wrong_shape_is_refused() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_bad_challenge(true);
    let (session, _) = start(&relay, vec![identity(ALICE)], options());
    let mut state = session.state();
    within(
        Duration::from_secs(5),
        state.wait_for(|state| matches!(state, MuxState::Waiting { .. })),
    )
    .await
    .unwrap();
    assert_eq!(relay.received("Attach"), 0);
    assert_eq!(session.counters().signatures, 0);
}

#[tokio::test]
async fn mail_is_pushed_handled_and_acknowledged() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, recorder) = start(&relay, vec![identity(ALICE), identity(BOB)], options());
    attached(&session).await;
    let id = post(&relay, BOB, "hello bob");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.texts(), vec!["hello bob".to_owned()]);
    assert_eq!(recorder.seen.lock().unwrap()[0].0, 1);
    let counters = session.counters();
    assert_eq!(counters.sockets_opened, 1);
    assert_eq!(counters.signatures, 2);
    assert_eq!(counters.attaches, 1);
    assert_eq!((counters.mails, counters.acks), (1, 1));
}

#[tokio::test]
async fn mail_stored_before_the_attach_is_pushed_after_it() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = post(&relay, ALICE, "waiting for you");
    let (session, recorder) = start(&relay, vec![identity(ALICE)], options());
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.texts(), vec!["waiting for you".to_owned()]);
    drop(session);
}

#[tokio::test]
async fn a_message_kept_for_later_is_held_not_acknowledged() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, recorder) = start(&relay, vec![identity(ALICE)], options());
    recorder.set_later(true);
    attached(&session).await;
    let id = post(&relay, ALICE, "not now");
    // Bounded: a message acknowledged instead of held would wait for ever.
    within(
        Duration::from_secs(5),
        relay.wait_until(|relay| !relay.holds(&id).is_empty()),
    )
    .await;
    assert_eq!(relay.holds(&id), vec![2]);
    assert!(!relay.is_acked(&id));
    assert_eq!(session.counters().holds, 1);
    assert_eq!(session.counters().acks, 0);
}

#[tokio::test]
async fn a_dropped_socket_resumes_without_new_signatures() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, recorder) = start(
        &relay,
        vec![identity(ALICE), identity(BOB), identity(CAROL)],
        options(),
    );
    attached(&session).await;
    assert_eq!(session.counters().signatures, 3);
    relay.drop_sockets();
    relay
        .wait_until(|relay| relay.resumes_accepted() == 1)
        .await;
    let id = post(&relay, BOB, "after the drop");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.count(), 1);
    let counters = session.counters();
    assert_eq!(counters.sockets_opened, 2);
    assert_eq!(counters.signatures, 3);
    assert_eq!(counters.attaches, 1);
    assert_eq!(counters.resumes, 1);
    assert_eq!(counters.token_unknown, 0);
    assert_eq!(relay.signatures_checked(), 3);
}

#[tokio::test]
async fn a_relay_restart_falls_back_to_signed_attaches() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, recorder) = start(&relay, vec![identity(ALICE), identity(BOB)], options());
    attached(&session).await;
    relay.restart();
    relay
        .wait_until(|relay| relay.signatures_checked() == 4)
        .await;
    let id = post(&relay, ALICE, "after the restart");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.count(), 1);
    let counters = session.counters();
    assert_eq!(counters.resumes, 1);
    assert_eq!(counters.token_unknown, 1);
    assert_eq!(counters.signatures, 4);
    assert_eq!(counters.attaches, 2);
    assert_eq!(counters.sockets_opened, 2);
}

#[tokio::test]
async fn a_replaced_mailbox_is_left_alone_on_the_next_socket() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(ALICE), identity(BOB)], options());
    let mut events = session.events();
    attached(&session).await;
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    // The new socket resumes with bob alone and signs nothing for alice within the hold-off.
    relay.drop_sockets();
    relay
        .wait_until(|relay| relay.resumes_accepted() == 1)
        .await;
    let id = post(&relay, BOB, "still here");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(relay.attached().len(), 1);
    assert!(!relay.attached().contains(&alice_key));
    assert!(session.replaced_keys().contains(&alice_key));
    assert_eq!(session.counters().signatures, 2);
    assert_eq!(session.counters().attaches, 1);
}

#[tokio::test]
async fn a_replaced_mailbox_is_attached_again_once_the_hold_off_ends() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let options = options().with_replaced_hold_off(Duration::from_millis(300));
    let (session, recorder) = start(&relay, vec![identity(ALICE), identity(BOB)], options);
    let mut events = session.events();
    attached(&session).await;
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    let id = post(&relay, ALICE, "kept for the holder");
    relay
        .wait_until(|relay| relay.attached().contains(&alice_key))
        .await;
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.texts(), vec!["kept for the holder".to_owned()]);
    assert_eq!(session.counters().sockets_opened, 1);
}

#[tokio::test]
async fn retry_now_leaves_a_replaced_mailbox_with_the_other_socket() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    let mut events = session.events();
    attached(&session).await;
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    assert_eq!(session.retry_now().await, MuxState::Attached);
    // A read on the attached socket proves the session went past the retry.
    let id = post(&relay, BOB, "after the retry");
    let taken = take_some(&session, &[1]).await;
    assert_eq!(taken[0].msg_id().as_str(), id);
    assert!(!relay.attached().contains(&alice_key));
    assert_eq!(session.replaced_keys(), BTreeSet::from([alice_key]));
    assert_eq!(session.counters().attaches, 1);
}

#[tokio::test]
async fn take_back_now_takes_a_replaced_mailbox_back_at_once() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    let mut events = session.events();
    attached(&session).await;
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    session.take_back_now();
    relay
        .wait_until(|relay| relay.attached().contains(&alice_key))
        .await;
    assert!(session.replaced_keys().is_empty());
}

/// Waits for the `Replaced` event of `mailbox`.
async fn replaced(events: &mut tokio::sync::broadcast::Receiver<MuxEvent>, mailbox: usize) {
    within(Duration::from_secs(5), async {
        loop {
            if let MuxEvent::Replaced { mailbox: found } = events.recv().await.unwrap()
                && found == mailbox
            {
                return;
            }
        }
    })
    .await;
}

#[tokio::test]
async fn setting_the_claim_again_does_not_attach_a_replaced_mailbox() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    let mut events = session.events();
    attached(&session).await;
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    relay
        .wait_until(|relay| !relay.attached().contains(&alice_key))
        .await;
    // A reconcile with the same identities keeps the index and sends no new attach while the
    // other socket holds the mailbox.
    let claimed = session
        .set_claim("", vec![identity(ALICE), identity(BOB)])
        .await
        .unwrap();
    assert_eq!(claimed.indexes, vec![0, 1]);
    assert!(claimed.fresh.is_empty());
    let id = post(&relay, BOB, "still here");
    let taken = take_some(&session, &[1]).await;
    assert_eq!(taken[0].msg_id().as_str(), id);
    assert!(!relay.attached().contains(&alice_key));
    assert_eq!(session.counters().signatures, 2);
    assert_eq!(session.counters().attaches, 1);
}

#[tokio::test]
async fn a_replaced_mailbox_is_attached_again_once_it_was_let_go_and_claimed_afresh() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    let mut events = session.events();
    attached(&session).await;
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    session.set_mailboxes(vec![identity(BOB)]).await.unwrap();
    let again = session
        .set_mailboxes(vec![identity(ALICE), identity(BOB)])
        .await
        .unwrap();
    assert_ne!(again[0], 0, "a new index");
    relay
        .wait_until(|relay| relay.attached().contains(&alice_key))
        .await;
    let id = post(&relay, ALICE, "back again");
    let taken = take_some(&session, &[again[0]]).await;
    assert_eq!(taken[0].msg_id().as_str(), id);
}

#[tokio::test]
async fn the_session_names_the_mailboxes_it_was_replaced_on() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    let mut events = session.events();
    attached(&session).await;
    assert!(session.replaced_keys().is_empty());
    let alice_key = address(ALICE).key_text();
    relay.send_detached(&address(ALICE), "replaced");
    replaced(&mut events, 0).await;
    assert_eq!(session.replaced_keys(), BTreeSet::from([alice_key.clone()]));
    // Still claimed: still named.
    session
        .set_claim("", vec![identity(ALICE), identity(BOB)])
        .await
        .unwrap();
    assert_eq!(session.replaced_keys(), BTreeSet::from([alice_key]));
    // Let go: no longer named.
    session.set_claim("", vec![identity(BOB)]).await.unwrap();
    assert!(session.replaced_keys().is_empty());
}

#[tokio::test]
async fn mail_over_the_in_flight_limit_is_held_not_dropped() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.ignore_inflight_limit(true);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    relay.stall_pushes(true);
    let ids: Vec<String> = (0..34)
        .map(|n| post(&relay, ALICE, &format!("mail {n}")))
        .collect();
    relay.stall_pushes(false);
    relay
        .wait_until(|relay| ids[32..].iter().all(|id| !relay.holds(id).is_empty()))
        .await;
    assert_eq!(session.take(&[0]).len(), 32);
    assert!(ids[..32].iter().all(|id| relay.holds(id).is_empty()));
}

#[tokio::test]
async fn mail_past_the_in_flight_byte_cap_is_held_not_dropped() {
    // The client keeps at most 16 MiB of mail in flight on a socket; mail past it waits on
    // the relay, as mail past the count limit does.
    const CAP: usize = 16 * 1024 * 1024;
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    let large = sealed_unbounded(CAROL, ALICE, &"x".repeat(1536 * 1024));
    let size = large.str.len();
    let fit = CAP / size;
    assert!((2..8).contains(&fit), "{size} bytes a mail");
    relay.stall_pushes(true);
    let ids: Vec<String> = (0..8)
        .map(|_| relay.store(&address(CAROL), &address(ALICE), &large))
        .collect();
    relay.stall_pushes(false);
    relay
        .wait_until(|relay| ids.iter().filter(|id| !relay.holds(id).is_empty()).count() >= 8 - fit)
        .await;
    let taken = session.take(&[0]);
    assert!(
        !taken.is_empty() && taken.len() <= fit,
        "{} taken",
        taken.len()
    );
    assert!(session.counters().holds >= 1);
}

#[tokio::test]
async fn mail_that_is_never_pushed_makes_the_session_reconnect() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, recorder) = start(
        &relay,
        vec![identity(ALICE)],
        options().with_waiting_every(Some(Duration::from_millis(30))),
    );
    attached(&session).await;
    relay.stall_pushes(true);
    let id = post(&relay, ALICE, "stuck on the relay");
    until(|| session.counters().stall_reconnects >= 1).await;
    assert_eq!(recorder.count(), 0);
    assert!(session.counters().waiting_probes >= 2);
    relay.stall_pushes(false);
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.texts(), vec!["stuck on the relay".to_owned()]);
    assert!(session.counters().sockets_opened >= 2);
}

#[tokio::test]
async fn mailboxes_are_attached_and_detached_while_running() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, recorder) = start(&relay, vec![identity(ALICE)], options());
    attached(&session).await;
    let index = session.attach(identity(BOB)).await.unwrap();
    assert_eq!(index, 1);
    assert!(matches!(
        session.attach(identity(BOB)).await,
        Err(MuxError::DuplicateMailbox)
    ));
    let bob_key = address(BOB).key_text();
    relay
        .wait_until(|relay| relay.attached().contains(&bob_key))
        .await;
    let id = post(&relay, BOB, "to the new mailbox");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.seen.lock().unwrap()[0].0, 1);
    assert!(session.detach(&address(BOB)).await.unwrap());
    relay
        .wait_until(|relay| !relay.attached().contains(&bob_key))
        .await;
    assert!(!session.detach(&address(BOB)).await.unwrap());
    assert_eq!(session.counters().signatures, 2);
}

#[tokio::test]
async fn more_than_256_mailboxes_are_refused() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let too_many: Vec<Identity> = (0..257).map(numbered).collect();
    let refused = MuxSession::start(
        settings(),
        relay.connector(),
        too_many,
        Recorder::default(),
        options(),
    );
    assert!(matches!(
        refused,
        Err(MuxError::TooManyMailboxes {
            count: 257,
            max: 256
        })
    ));

    let full: Vec<Identity> = (0..256).map(numbered).collect();
    let (session, _) = start(&relay, full, options());
    attached(&session).await;
    // 256 mailboxes go out in frames of 64.
    assert_eq!(relay.received("Attach"), 4);
    assert_eq!(session.counters().signatures, 256);
    assert!(matches!(
        session.attach(numbered(256)).await,
        Err(MuxError::TooManyMailboxes { .. })
    ));
}

#[tokio::test]
async fn a_rate_limited_attach_waits_and_tries_again() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.rate_limit_attaches(1, 0);
    let (session, recorder) = start(&relay, vec![identity(ALICE)], options());
    let id = post(&relay, ALICE, "after the limit");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(recorder.count(), 1);
    assert_eq!(session.counters().sockets_opened, 2);
}

#[tokio::test]
async fn an_attach_entry_answered_internal_is_attached_again_on_the_same_socket() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let early = post(&relay, ALICE, "pushed before the attach held");
    relay.fail_attach_entries(2);
    let begun = std::time::Instant::now();
    let (session, recorder) = start(&relay, vec![identity(ALICE)], options());
    let mut events = session.events();
    // The relay attached the mailbox despite its answer and pushed the mail: it is held, so
    // it does not keep an in-flight place, and is not handed out.
    within(
        Duration::from_secs(5),
        relay.wait_until(|relay| !relay.holds(&early).is_empty()),
    )
    .await;
    assert_eq!(recorder.count(), 0);
    // Answered `internal` twice: asked again after 1 s, then after 2 s.
    within(Duration::from_secs(10), async {
        loop {
            match events.recv().await.unwrap() {
                MuxEvent::Attached { mailbox: 0, .. } => break,
                MuxEvent::Refused { mailbox, code } => {
                    panic!("mailbox {mailbox} refused with {code:?}")
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(begun.elapsed() >= Duration::from_millis(2900));
    assert_eq!(relay.received("Attach"), 3);
    assert_eq!(session.counters().sockets_opened, 1);
    let later = post(&relay, ALICE, "after the attach");
    within(
        Duration::from_secs(5),
        relay.wait_until(|relay| relay.is_acked(&later)),
    )
    .await;
    assert_eq!(recorder.texts(), vec!["after the attach".to_owned()]);
}

#[tokio::test]
async fn stopping_ends_the_session() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(ALICE)], options());
    attached(&session).await;
    let mut state = session.state();
    session.stop().await.unwrap();
    assert!(state.borrow_and_update().has_ended());
    relay.wait_until(|relay| relay.sockets_open() == 0).await;
}

fn start_queued(relay: &MuxMockRelay, identities: Vec<Identity>) -> MuxSession {
    start_queued_with(relay, identities, settings())
}

fn start_queued_with(
    relay: &MuxMockRelay,
    identities: Vec<Identity>,
    settings: lepic_epicbox::ClientSettings,
) -> MuxSession {
    MuxSession::start_queued(settings, relay.connector(), identities, options()).unwrap()
}

/// Waits for the queue to hold something for `mailboxes`, then takes it.
async fn take_some(session: &MuxSession, mailboxes: &[usize]) -> Vec<MailboxMessage> {
    let mut queued = session.queued();
    within(Duration::from_secs(5), async {
        loop {
            let taken = session.take(mailboxes);
            if !taken.is_empty() {
                return taken;
            }
            queued.changed().await.unwrap();
        }
    })
    .await
}

fn text_of(message: &MailboxMessage) -> String {
    match message.content() {
        MailboxContent::Opened(received) => received.plaintext.expose_str().to_owned(),
        _ => "unopened".to_owned(),
    }
}

#[tokio::test]
async fn queued_mail_is_opened_taken_and_acknowledged_when_settled() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    attached(&session).await;
    let id = post(&relay, BOB, "hello bob");
    let taken = take_some(&session, &[1]).await;
    assert_eq!(taken.len(), 1);
    assert_eq!(text_of(&taken[0]), "hello bob");
    assert_eq!(taken[0].mailbox(), 1);
    // Nothing is acknowledged before the consumer settles.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!relay.is_acked(&id));
    assert!(session.take(&[0, 1]).is_empty());
    session.settle(taken[0].msg_id(), Handled::Stored).unwrap();
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(session.counters().acks, 1);
    assert_eq!(session.counters().holds, 0);
}

#[tokio::test]
async fn queued_mail_can_be_posted_again_as_the_relay_sent_it() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(BOB)]);
    attached(&session).await;
    post(&relay, BOB, "hello again");
    let taken = take_some(&session, &[0]).await;
    let mail = taken[0].relayed().unwrap().clone();
    assert_eq!(mail.from, address(CAROL).to_string());
    assert_eq!(mail.str, sealed(CAROL, BOB, "hello again").str);

    let other = MockRelay::new(Network::Mainnet);
    let client = MailboxClient::new(settings(), other.connector());
    client.repost(&identity(BOB), &mail).await.unwrap();

    assert_eq!(other.pending(&address(BOB)), 1);
}

#[tokio::test]
async fn queued_mail_settled_later_is_held() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    let id = post(&relay, ALICE, "not now");
    let taken = take_some(&session, &[0]).await;
    session.settle(taken[0].msg_id(), Handled::Later).unwrap();
    within(
        Duration::from_secs(5),
        relay.wait_until(|relay| !relay.holds(&id).is_empty()),
    )
    .await;
    assert_eq!(relay.holds(&id), vec![2]);
    assert!(!relay.is_acked(&id));
    assert_eq!(session.counters().acks, 0);
}

#[tokio::test]
async fn take_hands_out_only_the_mailboxes_asked_for_in_arrival_order() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    attached(&session).await;
    post(&relay, ALICE, "first alice");
    post(&relay, BOB, "first bob");
    post(&relay, ALICE, "second alice");
    until(|| session.counters().mails == 3).await;
    let bob: Vec<String> = session.take(&[1]).iter().map(text_of).collect();
    assert_eq!(bob, vec!["first bob".to_owned()]);
    let alice: Vec<String> = session.take(&[0]).iter().map(text_of).collect();
    assert_eq!(
        alice,
        vec!["first alice".to_owned(), "second alice".to_owned()]
    );
    assert!(session.take(&[0, 1, 2]).is_empty());
}

#[tokio::test]
async fn unsettled_mail_is_forgotten_when_the_socket_drops_and_offered_again() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    let id = post(&relay, ALICE, "twice offered");
    until(|| session.counters().mails == 1).await;
    relay.drop_sockets();
    until(|| session.counters().mails == 2).await;
    // The first copy went with the first socket: exactly one copy is queued.
    let taken = take_some(&session, &[0]).await;
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].msg_id().as_str(), id);
    assert!(session.take(&[0]).is_empty());
    session.settle(taken[0].msg_id(), Handled::Stored).unwrap();
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(session.counters().sockets_opened, 2);
}

#[tokio::test]
async fn set_mailboxes_signs_only_for_the_new_ones() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE), identity(BOB)]);
    attached(&session).await;
    assert_eq!(session.counters().signatures, 2);
    let indexes = session
        .set_mailboxes(vec![identity(BOB), identity(CAROL)])
        .await
        .unwrap();
    assert_eq!(indexes, vec![1, 2]);
    let alice_key = address(ALICE).key_text();
    let carol_key = address(CAROL).key_text();
    relay
        .wait_until(|relay| {
            let attached = relay.attached();
            attached.contains(&carol_key) && !attached.contains(&alice_key)
        })
        .await;
    assert_eq!(session.counters().signatures, 3);
    // The same set again changes nothing and costs nothing.
    let again = session
        .set_mailboxes(vec![identity(CAROL), identity(BOB), identity(BOB)])
        .await
        .unwrap();
    assert_eq!(again, vec![2, 1]);
    assert_eq!(session.counters().signatures, 3);
    assert_eq!(session.counters().attaches, 2);
    // A mailbox that came back is new again.
    let back = session.set_mailboxes(vec![identity(ALICE)]).await.unwrap();
    assert_eq!(back, vec![3]);
    assert_eq!(session.counters().signatures, 4);
    let id = post(&relay, CAROL, "to nobody");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!relay.is_acked(&id));
    assert!(session.take(&[1, 2]).is_empty());
}

#[tokio::test]
async fn claims_of_two_owners_do_not_detach_each_other() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    // A second owner claims two mailboxes: only those cost a signature.
    let first = session
        .set_claim("contacts", vec![identity(BOB), identity(CAROL)])
        .await
        .unwrap();
    assert_eq!(first.indexes, vec![1, 2]);
    assert_eq!(first.fresh, vec![1, 2]);
    let carol_key = address(CAROL).key_text();
    relay
        .wait_until(|relay| relay.attached().contains(&carol_key))
        .await;
    assert_eq!(session.counters().signatures, 3);
    // The first owner sets its own mailboxes again: the contacts stay attached.
    let own = session.set_mailboxes(vec![identity(ALICE)]).await.unwrap();
    assert_eq!(own, vec![0]);
    // The second owner narrows its claim: only its own mailbox goes.
    let narrowed = session
        .set_claim("contacts", vec![identity(BOB)])
        .await
        .unwrap();
    assert_eq!(narrowed.indexes, vec![1]);
    assert!(narrowed.fresh.is_empty());
    let bob_key = address(BOB).key_text();
    let alice_key = address(ALICE).key_text();
    relay
        .wait_until(|relay| {
            let attached = relay.attached();
            !attached.contains(&carol_key)
                && attached.contains(&bob_key)
                && attached.contains(&alice_key)
        })
        .await;
    // Releasing the claim detaches what only it wanted. A mailbox both want stays.
    session
        .set_claim("other", vec![identity(BOB)])
        .await
        .unwrap();
    session.set_claim("contacts", Vec::new()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let attached_now = relay.attached();
    assert!(attached_now.contains(&bob_key) && attached_now.contains(&alice_key));
    session.set_claim("other", Vec::new()).await.unwrap();
    relay
        .wait_until(|relay| !relay.attached().contains(&bob_key))
        .await;
    assert!(relay.attached().contains(&alice_key));
    assert_eq!(session.counters().signatures, 3);
}

#[tokio::test]
async fn adding_to_a_claim_keeps_the_rest_of_it() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    session
        .set_claim("contacts", vec![identity(BOB)])
        .await
        .unwrap();
    let more = session
        .add_to_claim("contacts", vec![identity(CAROL)])
        .await
        .unwrap();
    assert_eq!(more.indexes, vec![2]);
    assert_eq!(more.fresh, vec![2]);
    let keys = [address(BOB).key_text(), address(CAROL).key_text()];
    relay
        .wait_until(|relay| keys.iter().all(|key| relay.attached().contains(key)))
        .await;
    // Releasing the claim detaches both.
    session.set_claim("contacts", Vec::new()).await.unwrap();
    relay
        .wait_until(|relay| keys.iter().all(|key| !relay.attached().contains(key)))
        .await;
    assert!(relay.attached().contains(&address(ALICE).key_text()));
}

#[tokio::test]
async fn claims_together_are_capped_at_256_and_nothing_changes() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    let many: Vec<Identity> = (1000..1256).map(numbered).collect();
    assert!(matches!(
        session.set_claim("contacts", many).await,
        Err(MuxError::TooManyMailboxes { count: 257, .. })
    ));
    assert_eq!(session.counters().signatures, 1);
}

#[tokio::test]
async fn the_room_for_an_owner_follows_the_claims_and_the_relay_limit() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_mailboxes_per_socket(3);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    // Before the relay names its limit, the session counts on the most a socket carries.
    assert_eq!(session.room_for("contacts"), 255);
    assert_eq!(session.room_for(""), 256);
    attached(&session).await;
    assert_eq!(session.room_for("contacts"), 2);
    session
        .set_claim("contacts", vec![identity(BOB)])
        .await
        .unwrap();
    assert_eq!(session.room_for("contacts"), 2);
    assert_eq!(session.room_for(""), 2);
    assert_eq!(session.room_for("payments"), 1);
    assert_eq!(
        session
            .claimed_keys("contacts")
            .into_iter()
            .collect::<Vec<_>>(),
        vec![address(BOB).key_text()]
    );
    assert!(session.claimed_keys("payments").is_empty());
    assert!(matches!(
        session
            .set_claim("payments", vec![identity(CAROL), numbered(7)])
            .await,
        Err(MuxError::TooManyMailboxes { count: 4, max: 3 })
    ));
    assert!(session.claimed_keys("payments").is_empty());
    session.set_claim("contacts", Vec::new()).await.unwrap();
    assert_eq!(session.room_for("payments"), 2);
}

#[tokio::test]
async fn the_mock_refuses_a_mailbox_past_its_limit_as_the_relay_does() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_mailboxes_per_socket(2);
    // Started with three before the relay names its limit, so all three go out in one attach.
    let session = start_queued(
        &relay,
        vec![identity(ALICE), identity(BOB), identity(CAROL)],
    );
    let mut events = session.events();
    attached(&session).await;
    let refused = within(Duration::from_secs(5), async {
        loop {
            if let Ok(MuxEvent::Refused { mailbox, code }) = events.recv().await {
                return (mailbox, code);
            }
        }
    })
    .await;
    assert_eq!(refused, (2, MuxCode::TooManyMailboxes));
    assert_eq!(relay.attached().len(), 2);
    assert!(!relay.attached().contains(&address(CAROL).key_text()));
}

#[tokio::test]
async fn set_mailboxes_refuses_more_than_256_and_changes_nothing() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start_queued(&relay, vec![identity(ALICE)]);
    attached(&session).await;
    let too_many: Vec<Identity> = (0..257).map(numbered).collect();
    assert!(matches!(
        session.set_mailboxes(too_many).await,
        Err(MuxError::TooManyMailboxes { count: 257, .. })
    ));
    assert_eq!(session.counters().signatures, 1);
    let id = post(&relay, ALICE, "still here");
    let taken = take_some(&session, &[0]).await;
    assert_eq!(taken[0].msg_id().as_str(), id);
}

#[tokio::test]
async fn the_session_keeps_pinging_while_mail_sits_unsettled() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let mut quick = settings();
    quick.ping_interval = Duration::from_millis(60);
    let session = start_queued_with(&relay, vec![identity(ALICE)], quick);
    attached(&session).await;
    post(&relay, ALICE, "one");
    post(&relay, ALICE, "two");
    until(|| session.counters().mails == 2).await;
    // Several silence limits pass with the mail untaken and unsettled.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(relay.pings_received() >= 3, "pings seen by the relay");
    assert_eq!(session.counters().sockets_opened, 1);
    assert_eq!(session.take(&[0]).len(), 2);
}

/// A connector that reaches nothing.
struct Unreachable;

impl lepic_epicbox::Connector for Unreachable {
    fn connect<'a>(
        &'a self,
        _endpoint: &'a lepic_epicbox::RelayEndpoint,
    ) -> BoxFuture<'a, std::io::Result<Box<dyn lepic_epicbox::RelayStream>>> {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            ))
        })
    }
}

#[tokio::test]
async fn a_probe_of_a_mailbox_that_offers_mux_passes_every_step() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let probe = probe_mailbox(&settings(), relay.connector().as_ref()).await;
    assert!(probe.passed(), "{probe:?}");
    assert_eq!(relay.received("ClientDetails"), 1);
    assert_eq!(relay.received("Attach"), 0);
}

#[tokio::test]
async fn a_probe_of_a_mailbox_without_mux_fails_only_the_push_step() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_mux(false);
    let probe = probe_mailbox(&settings(), relay.connector().as_ref()).await;
    assert_eq!(probe.tls, ProbeStep::Passed);
    assert_eq!(probe.greeting, ProbeStep::Passed);
    assert!(matches!(probe.push, ProbeStep::Failed(_)), "{probe:?}");
}

#[tokio::test]
async fn a_probe_of_a_mailbox_that_refuses_the_greeting_does_not_reach_push() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.answer_greeting_with_error(true);
    let probe = probe_mailbox(&settings(), relay.connector().as_ref()).await;
    assert_eq!(probe.tls, ProbeStep::Passed);
    assert!(matches!(probe.greeting, ProbeStep::Failed(_)), "{probe:?}");
    assert_eq!(probe.push, ProbeStep::NotReached);
}

#[tokio::test]
async fn a_probe_of_a_silent_mailbox_fails_the_greeting() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.ignore_greeting(true);
    let mut quick = settings();
    quick.response_timeout = Duration::from_millis(100);
    let probe = probe_mailbox(&quick, relay.connector().as_ref()).await;
    assert!(matches!(probe.greeting, ProbeStep::Failed(_)), "{probe:?}");
    assert_eq!(probe.push, ProbeStep::NotReached);
}

#[tokio::test]
async fn a_probe_of_a_mailbox_that_cannot_be_reached_fails_tls_and_tries_nothing_else() {
    let probe = probe_mailbox(&settings(), &Unreachable).await;
    assert!(matches!(probe.tls, ProbeStep::Failed(_)), "{probe:?}");
    assert_eq!(probe.greeting, ProbeStep::NotReached);
    assert_eq!(probe.push, ProbeStep::NotReached);
}
