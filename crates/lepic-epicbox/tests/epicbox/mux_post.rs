// SPDX-License-Identifier: Apache-2.0
//! A post on an open mux/1 session against the mock mux relay.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::client_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, secret, settings, until, within};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::{
    ClientSettings, EpicboxTxId, Handled, Identity, MailboxContent, MailboxHandler, MailboxMessage,
    MuxCode, MuxOptions, MuxPostError, MuxPostNotSent, MuxSession, MuxState, Network,
};
use lepic_transport::transport::BoxFuture;

const LONG: Duration = Duration::from_secs(5);

fn identity(byte: u8) -> Identity {
    Identity::new(secret(byte), address(byte)).unwrap()
}

/// The plaintext and sender of every message the session opened.
#[derive(Clone, Default)]
struct Opened {
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl MailboxHandler for Opened {
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            let opened = match message.content() {
                MailboxContent::Opened(received) => (
                    received.plaintext.expose_str().to_owned(),
                    received.sender.to_string(),
                ),
                _ => ("unopened".to_owned(), String::new()),
            };
            self.seen.lock().unwrap().push(opened);
            Handled::Stored
        })
    }
}

fn start_with(
    relay: &MuxMockRelay,
    identities: Vec<Identity>,
    settings: ClientSettings,
) -> (MuxSession, Opened) {
    let handler = Opened::default();
    let options = MuxOptions::default()
        .with_ack_window(Duration::from_millis(10))
        .with_waiting_every(None)
        .with_hold(Duration::from_secs(2));
    let session = MuxSession::start(
        settings,
        relay.connector(),
        identities,
        handler.clone(),
        options,
    )
    .unwrap();
    (session, handler)
}

fn start(relay: &MuxMockRelay, identities: Vec<Identity>) -> (MuxSession, Opened) {
    start_with(relay, identities, settings())
}

async fn reached(session: &MuxSession, wanted: MuxState) {
    let mut state = session.state();
    within(LONG, state.wait_for(|state| *state == wanted))
        .await
        .unwrap();
}

async fn post(session: &MuxSession, text: &str) -> Result<(), MuxPostError> {
    within(LONG, session.post(&identity(ALICE), &address(BOB), text)).await
}

#[tokio::test]
async fn a_post_is_answered_ok_and_the_recipient_opens_it() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    // The sender's key signs the post; the session that carries it holds another mailbox.
    let (sender, _) = start(&relay, vec![identity(CAROL)]);
    reached(&sender, MuxState::Attached).await;

    post(&sender, "slate").await.unwrap();

    let frames = relay.frames("PostSlate");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["from"], address(ALICE).to_string());
    assert_eq!(frames[0]["to"], address(BOB).to_string());
    assert!(frames[0]["ref"].is_string());
    assert!(frames[0].get("epicboxtxid").is_none());
    assert!(frames[0].get("epicboxtxidsig").is_none());

    let (recipient, opened) = start(&relay, vec![identity(BOB)]);
    reached(&recipient, MuxState::Attached).await;
    until(|| !opened.seen.lock().unwrap().is_empty()).await;
    assert_eq!(
        opened.seen.lock().unwrap()[0],
        ("slate".to_owned(), address(ALICE).to_string())
    );
}

#[tokio::test]
async fn a_txid_goes_with_the_post_only_where_txcancel_was_negotiated() {
    const TXID: &str = "4f6b1c2d3e4f40718293a4b5c6d7e8f9";
    let txid = EpicboxTxId::parse(TXID).unwrap();
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    reached(&session, MuxState::Attached).await;

    within(
        LONG,
        session.post_tx(&identity(ALICE), &address(BOB), "slate", &txid),
    )
    .await
    .unwrap();
    let frames = relay.frames("PostSlate");
    assert_eq!(frames[0]["epicboxtxid"], TXID);
    assert!(frames[0]["epicboxtxidsig"].is_string());

    // The relay keeps the id: the payee may cancel it, and then a post with it is refused.
    assert!(relay.cancel_as(&address(BOB), TXID));
    let again = within(
        LONG,
        session.post_tx(&identity(ALICE), &address(BOB), "slate", &txid),
    )
    .await;
    assert!(
        matches!(
            again,
            Err(MuxPostError::Refused {
                code: Some(MuxCode::PostRefused),
                ..
            })
        ),
        "{again:?}"
    );

    let old = MuxMockRelay::new(Network::Mainnet);
    old.offer_cancel(false);
    let (session, _) = start(&old, vec![identity(CAROL)]);
    reached(&session, MuxState::Attached).await;
    within(
        LONG,
        session.post_tx(&identity(ALICE), &address(BOB), "slate", &txid),
    )
    .await
    .unwrap();
    let frames = old.frames("PostSlate");
    assert!(frames[0].get("epicboxtxid").is_none());
    assert!(frames[0].get("epicboxtxidsig").is_none());
}

#[tokio::test]
async fn a_post_refused_reaches_the_caller_with_its_code() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_post_error(Some("post_refused"), None);
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    reached(&session, MuxState::Attached).await;

    let result = post(&session, "slate").await;
    assert!(
        matches!(
            result,
            Err(MuxPostError::Refused {
                code: Some(MuxCode::PostRefused),
                retry_after: None,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(*session.state().borrow(), MuxState::Attached);
}

#[tokio::test]
async fn a_rate_limited_post_carries_the_retry_after() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_post_error(Some("rate_limited"), Some(7));
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    reached(&session, MuxState::Attached).await;

    let result = post(&session, "slate").await;
    assert!(
        matches!(
            result,
            Err(MuxPostError::Refused {
                code: Some(MuxCode::RateLimited),
                retry_after: Some(after),
                ..
            }) if after == Duration::from_secs(7)
        ),
        "{result:?}"
    );
    // A refused post keeps the socket.
    assert_eq!(session.counters().sockets_opened, 1);
    assert_eq!(*session.state().borrow(), MuxState::Attached);
}

#[tokio::test]
async fn a_refused_post_carries_the_mailboxs_reason_cut_to_size() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_post_refusal(
        "post_refused",
        None,
        "Recipient mailbox is full; try again later.",
    );
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    reached(&session, MuxState::Attached).await;

    let result = post(&session, "slate").await;
    let Err(MuxPostError::Refused { description, .. }) = result else {
        panic!("{result:?}");
    };
    assert_eq!(
        description.as_deref(),
        Some("Recipient mailbox is full; try again later.")
    );

    let long = format!("\u{7}{}", "x".repeat(400));
    relay.set_post_refusal("post_refused", None, &long);
    let result = post(&session, "slate").await;
    let Err(MuxPostError::Refused {
        description: Some(description),
        ..
    }) = result
    else {
        panic!("{result:?}");
    };
    assert!(description.chars().count() <= lepic_epicbox::MAX_REFUSAL_DESCRIPTION_LEN + 3);
    assert!(!description.chars().any(char::is_control));
}

#[tokio::test]
async fn without_a_socket_a_post_is_not_sent_at_once() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.ignore_greeting(true);
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    until(|| relay.received("ClientDetails") == 1).await;
    assert!(matches!(
        *session.state().borrow(),
        MuxState::Connecting { .. }
    ));

    let result = within(
        Duration::from_millis(500),
        session.post(&identity(ALICE), &address(BOB), "slate"),
    )
    .await;
    assert!(
        matches!(result, Err(MuxPostError::NotSent(MuxPostNotSent::NoSocket))),
        "{result:?}"
    );
    assert_eq!(relay.received("PostSlate"), 0);
}

#[tokio::test]
async fn a_post_whose_answer_never_comes_is_unanswered_and_not_sent_again() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.ignore_posts(true);
    let mut quick = settings();
    quick.response_timeout = Duration::from_secs(1);
    let (session, _) = start_with(&relay, vec![identity(CAROL)], quick);
    reached(&session, MuxState::Attached).await;

    let result = post(&session, "slate").await;
    assert!(
        matches!(result, Err(MuxPostError::Unanswered)),
        "{result:?}"
    );

    // The missed deadline costs the socket; the next one does not carry the post again.
    relay.wait_until(|relay| relay.sockets_made() == 2).await;
    reached(&session, MuxState::Attached).await;
    assert_eq!(relay.received("PostSlate"), 1);
}

#[tokio::test]
async fn a_post_whose_socket_drops_is_unanswered_and_not_sent_again() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.ignore_posts(true);
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    reached(&session, MuxState::Attached).await;

    let session = Arc::new(session);
    let posting = tokio::spawn({
        let session = Arc::clone(&session);
        async move { post(&session, "slate").await }
    });
    relay
        .wait_until(|relay| relay.received("PostSlate") == 1)
        .await;
    relay.drop_sockets();

    let result = posting.await.unwrap();
    assert!(
        matches!(result, Err(MuxPostError::Unanswered)),
        "{result:?}"
    );
    relay.wait_until(|relay| relay.sockets_made() == 2).await;
    reached(&session, MuxState::Attached).await;
    assert_eq!(relay.received("PostSlate"), 1);
}

#[tokio::test]
async fn on_a_relay_without_mux_a_post_is_not_sent() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_mux(false);
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    reached(&session, MuxState::NotOffered).await;

    let result = post(&session, "slate").await;
    assert!(
        matches!(
            result,
            Err(MuxPostError::NotSent(MuxPostNotSent::NotOffered))
        ),
        "{result:?}"
    );
    assert_eq!(relay.received("PostSlate"), 0);
}
