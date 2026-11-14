// SPDX-License-Identifier: Apache-2.0
//! The mux/1 session against the mock mux relay.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, sealed, secret, settings, until, within};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    ClientFrame, Domain, EpicboxAddress, Handled, Identity, MailboxClient, MailboxContent,
    MailboxHandler, MailboxMessage, MuxError, MuxEvent, MuxOptions, MuxSession, MuxState, Network,
    WalletMode,
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
        r#"{"type":"ClientDetails","wallet_version":"4.0.2","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]}"#
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
    relay.wait_until(|relay| !relay.holds(&id).is_empty()).await;
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
async fn a_replaced_mailbox_is_not_attached_again() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(ALICE), identity(BOB)], options());
    let mut events = session.events();
    attached(&session).await;
    relay.send_detached(&address(ALICE), "replaced");
    let event = within(Duration::from_secs(5), async {
        loop {
            if let MuxEvent::Replaced { mailbox } = events.recv().await.unwrap() {
                return mailbox;
            }
        }
    })
    .await;
    assert_eq!(event, 0);
    // A new socket must carry only the other mailbox, with no new signature for the replaced one.
    relay.drop_sockets();
    relay
        .wait_until(|relay| relay.resumes_accepted() == 1)
        .await;
    let id = post(&relay, BOB, "still here");
    relay.wait_until(|relay| relay.is_acked(&id)).await;
    assert_eq!(relay.attached().len(), 1);
    assert_eq!(session.counters().signatures, 2);
    assert_eq!(session.counters().attaches, 1);
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
    // A reconcile with the same identities keeps the index and sends no new attach.
    let claimed = session
        .set_claim("", vec![identity(ALICE), identity(BOB)])
        .await
        .unwrap();
    assert_eq!(claimed.indexes, vec![0, 1]);
    assert!(claimed.fresh.is_empty());
    // The same after the socket was lost: the resume covers bob only.
    relay.drop_sockets();
    relay
        .wait_until(|relay| relay.resumes_accepted() == 1)
        .await;
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
    relay.wait_until(|relay| !relay.holds(&id).is_empty()).await;
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
