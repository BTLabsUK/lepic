// SPDX-License-Identifier: Apache-2.0
//! The `epicbox-attach/1` extension of the mux/1 session against the mock mux relay: attach
//! signatures bound to the mailbox's name where the relay offers it, the bare challenge where it
//! does not.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::client_support;

use std::time::Duration;

use client_support::{BOB, address, secret, settings, until, within};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::{
    ATTACH_HOST_EXTENSION, Handled, Identity, MailboxHandler, MailboxMessage, MuxCode, MuxEvent,
    MuxOptions, MuxSession, MuxState, Network,
};
use lepic_transport::transport::BoxFuture;

const LONG: Duration = Duration::from_secs(5);

struct Store;

impl MailboxHandler for Store {
    fn handle(&mut self, _message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async { Handled::Stored })
    }
}

fn start(relay: &MuxMockRelay) -> MuxSession {
    let options = MuxOptions::default()
        .with_ack_window(Duration::from_millis(10))
        .with_waiting_every(None)
        .with_hold(Duration::from_secs(2));
    MuxSession::start(
        settings(),
        relay.connector(),
        vec![Identity::new(secret(BOB), address(BOB)).unwrap()],
        Store,
        options,
    )
    .unwrap()
}

async fn attached(session: &MuxSession) {
    let mut state = session.state();
    within(LONG, state.wait_for(|state| *state == MuxState::Attached))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_client_asks_for_the_extension_in_its_greeting() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start(&relay);
    attached(&session).await;
    let greeting = &relay.frames("ClientDetails")[0];
    let ext = greeting["ext"].as_array().unwrap();
    assert!(ext.iter().any(|name| name == ATTACH_HOST_EXTENSION));
}

#[tokio::test]
async fn a_relay_without_the_extension_gets_the_bare_challenge_and_no_host() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let session = start(&relay);
    attached(&session).await;
    assert_eq!(relay.attach_forms(), [None]);
    let attach = &relay.frames("Attach")[0];
    assert!(attach["mailboxes"][0].get("host").is_none());
}

#[tokio::test]
async fn a_relay_with_the_extension_gets_the_signature_bound_to_its_name() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_attach_host(Some(vec!["relay.test".to_owned()]));
    relay.accept_bare_attach(false);
    let session = start(&relay);
    attached(&session).await;
    assert_eq!(relay.attach_forms(), [Some("relay.test".to_owned())]);
    assert_eq!(relay.received("Attach"), 1);
}

#[tokio::test]
async fn a_relay_that_does_not_answer_to_the_dialled_name_gets_the_bare_challenge_once() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_attach_host(Some(vec!["other.example".to_owned()]));
    let session = start(&relay);
    let mut events = session.events();
    until(|| !relay.attach_forms().is_empty()).await;
    attached(&session).await;
    assert_eq!(relay.attach_forms(), [None]);
    let attaches = relay.frames("Attach");
    assert_eq!(attaches.len(), 2);
    assert_eq!(attaches[0]["mailboxes"][0]["host"], "relay.test");
    assert!(attaches[1]["mailboxes"][0].get("host").is_none());
    while let Ok(event) = events.try_recv() {
        assert!(!matches!(event, MuxEvent::Refused { .. }), "{event:?}");
    }
}

#[tokio::test]
async fn a_wrong_host_and_no_bare_form_is_refused_without_a_loop() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_attach_host(Some(vec!["other.example".to_owned()]));
    relay.accept_bare_attach(false);
    let session = start(&relay);
    let mut events = session.events();
    let code = within(LONG, async {
        loop {
            if let MuxEvent::Refused { code, .. } = events.recv().await.unwrap() {
                return code;
            }
        }
    })
    .await;
    assert_eq!(code, MuxCode::BadSignature);
    assert_eq!(relay.received("Attach"), 2);
    assert!(relay.attach_forms().is_empty());
}

#[tokio::test]
async fn a_wrong_host_on_every_frame_of_many_mailboxes_attaches_them_all_bare_on_one_socket() {
    // More mailboxes than one frame carries: every frame goes out host-bound before the first
    // answer, so each `wrong_host` frame must be retried bare, not only the first.
    const COUNT: u8 = 150;
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_attach_host(Some(vec!["other.example".to_owned()]));
    let options = MuxOptions::default()
        .with_ack_window(Duration::from_millis(10))
        .with_waiting_every(None)
        .with_hold(Duration::from_secs(2));
    let identities = (1..=COUNT)
        .map(|byte| Identity::new(secret(byte), address(byte)).unwrap())
        .collect();
    let session =
        MuxSession::start(settings(), relay.connector(), identities, Store, options).unwrap();
    let mut events = session.events();
    until(|| relay.attached().len() == usize::from(COUNT)).await;
    attached(&session).await;
    assert_eq!(relay.sockets_made(), 1);
    let attaches = relay.frames("Attach");
    let (bound, bare): (Vec<_>, Vec<_>) = attaches
        .iter()
        .partition(|frame| frame["mailboxes"][0].get("host").is_some());
    assert_eq!(bound.len(), 3);
    assert_eq!(bare.len(), 3);
    assert_eq!(relay.attach_forms().len(), usize::from(COUNT));
    assert!(relay.attach_forms().iter().all(Option::is_none));
    while let Ok(event) = events.try_recv() {
        assert!(!matches!(event, MuxEvent::Refused { .. }), "{event:?}");
    }
}
