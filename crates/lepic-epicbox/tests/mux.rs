// SPDX-License-Identifier: Apache-2.0
//! The mux/1 session against the mock mux relay.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, sealed, secret, settings, until, within};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::{
    ClientFrame, Domain, EpicboxAddress, Handled, Identity, MailboxContent, MailboxHandler,
    MailboxMessage, MuxError, MuxEvent, MuxOptions, MuxSession, MuxState, Network, WalletMode,
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
