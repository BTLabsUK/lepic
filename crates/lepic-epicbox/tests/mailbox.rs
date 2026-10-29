// SPDX-License-Identifier: Apache-2.0
//! One-off drains of mailboxes that are not the wallet's address, and posts from their keys,
//! against the mock relay.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{CAROL, address, sealed, secret, settings, within};
use lepic_epicbox::mock_relay::{MockRelay, Unanswered};
use lepic_epicbox::tunnel::DialTarget;
use lepic_epicbox::{
    ClientSettings, Connector, DrainLimits, Handled, Identity, MailboxClient, MailboxContent,
    MailboxEnd, MailboxError, MailboxHandler, MailboxMessage, Network, RejectionReason,
    RelayEndpoint, RelayStream,
};
use lepic_transport::transport::BoxFuture;

const LONG: Duration = Duration::from_secs(10);

const PAIRING_BOX: u8 = 10;
const CONTACT_BOX: u8 = 11;
const THROWAWAY: u8 = 12;
const STRANGER: u8 = 13;

fn mailbox(byte: u8) -> Identity {
    Identity::new(secret(byte), address(byte)).unwrap()
}

fn mailbox_client(relay: &MockRelay) -> MailboxClient {
    MailboxClient::new(settings(), relay.connector())
}

fn post_stored(relay: &MockRelay, from: u8, to: u8, plaintext: &str) -> String {
    relay.store(&address(from), &address(to), &sealed(from, to, plaintext))
}

/// What the handler saw of one message, and of the relay at that moment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    mailbox: usize,
    text: String,
    acknowledgements_before: usize,
}

type OnMessage = Box<dyn FnMut(&MailboxMessage) + Send>;

/// Stores every message except those whose text is `keep`, and runs `on_message` first.
struct Recorder {
    relay: MockRelay,
    keep: Option<&'static str>,
    seen: Arc<Mutex<Vec<Seen>>>,
    on_message: Option<OnMessage>,
}

impl Recorder {
    fn new(relay: &MockRelay) -> Self {
        Self {
            relay: relay.clone(),
            keep: None,
            seen: Arc::default(),
            on_message: None,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn texts(&self) -> Vec<(usize, String)> {
        self.seen()
            .into_iter()
            .map(|seen| (seen.mailbox, seen.text))
            .collect()
    }
}

impl MailboxHandler for Recorder {
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            if let Some(on_message) = &mut self.on_message {
                on_message(&message);
            }
            let text = match message.content() {
                MailboxContent::Opened(received) => received.plaintext.expose_str().to_owned(),
                MailboxContent::Unopenable { reason, .. } => format!("unopenable {reason:?}"),
                _ => panic!("unexpected content"),
            };
            let handled = if self.keep == Some(text.as_str()) {
                Handled::Later
            } else {
                Handled::Stored
            };
            self.seen.lock().unwrap().push(Seen {
                mailbox: message.mailbox(),
                text,
                acknowledgements_before: self.relay.received("Made"),
            });
            handled
        })
    }
}

#[tokio::test]
async fn drains_two_mailboxes_on_one_relay_in_one_call() {
    let relay = MockRelay::new(Network::Mainnet);
    post_stored(&relay, CAROL, PAIRING_BOX, "reply");
    post_stored(&relay, CAROL, PAIRING_BOX, "reply again");
    post_stored(&relay, CAROL, CONTACT_BOX, "invoice");
    let mut handler = Recorder::new(&relay);

    let report = within(
        LONG,
        mailbox_client(&relay)
            .drain_once(&[mailbox(PAIRING_BOX), mailbox(CONTACT_BOX)], &mut handler),
    )
    .await
    .unwrap();

    assert_eq!(
        handler.texts(),
        [
            (0, "reply".to_owned()),
            (0, "reply again".to_owned()),
            (1, "invoice".to_owned())
        ]
    );
    let ends: Vec<_> = report.mailboxes.iter().map(|m| m.end).collect();
    assert_eq!(ends, [MailboxEnd::Empty, MailboxEnd::Empty]);
    assert_eq!(report.mailboxes[0].acknowledged, 2);
    assert_eq!(report.mailboxes[1].acknowledged, 1);
    assert_eq!(report.connections, 1);
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 0);
    assert_eq!(relay.pending(&address(CONTACT_BOX)), 0);
    relay.wait_until(|relay| relay.connections() == 0).await;
}

#[tokio::test]
async fn acknowledges_a_message_only_after_the_handler_stored_it() {
    let relay = MockRelay::new(Network::Mainnet);
    post_stored(&relay, CAROL, PAIRING_BOX, "one");
    post_stored(&relay, CAROL, PAIRING_BOX, "two");
    let mut handler = Recorder::new(&relay);
    let watched = relay.clone();
    handler.on_message = Some(Box::new(move |_| {
        assert!(watched.pending(&address(PAIRING_BOX)) > 0);
    }));

    within(
        LONG,
        mailbox_client(&relay).drain_once(&[mailbox(PAIRING_BOX)], &mut handler),
    )
    .await
    .unwrap();

    let before: Vec<_> = handler
        .seen()
        .iter()
        .map(|seen| seen.acknowledgements_before)
        .collect();
    assert_eq!(before, [0, 1]);
    assert_eq!(relay.received("Made"), 2);
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 0);
}

#[tokio::test]
async fn a_kept_message_stays_on_the_relay_and_the_next_mailbox_is_still_drained() {
    let relay = MockRelay::new(Network::Mainnet);
    post_stored(&relay, CAROL, PAIRING_BOX, "not yet");
    post_stored(&relay, CAROL, PAIRING_BOX, "behind it");
    post_stored(&relay, CAROL, CONTACT_BOX, "invoice");
    let mut handler = Recorder::new(&relay);
    handler.keep = Some("not yet");

    let report = within(
        LONG,
        mailbox_client(&relay)
            .drain_once(&[mailbox(PAIRING_BOX), mailbox(CONTACT_BOX)], &mut handler),
    )
    .await
    .unwrap();

    assert_eq!(report.mailboxes[0].end, MailboxEnd::Kept);
    assert_eq!(report.mailboxes[0].handed_out, 1);
    assert_eq!(report.mailboxes[0].acknowledged, 0);
    assert_eq!(report.mailboxes[1].end, MailboxEnd::Empty);
    assert_eq!(report.mailboxes[1].acknowledged, 1);
    // The relay holds back every address on a socket with a message in flight.
    assert_eq!(report.connections, 2);
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 2);
    assert_eq!(relay.pending(&address(CONTACT_BOX)), 0);

    let mut retry = Recorder::new(&relay);
    within(
        LONG,
        mailbox_client(&relay).drain_once(&[mailbox(PAIRING_BOX)], &mut retry),
    )
    .await
    .unwrap();
    assert_eq!(
        retry.texts(),
        [(0, "not yet".to_owned()), (0, "behind it".to_owned())]
    );
}

#[tokio::test]
async fn reads_at_most_the_cap_from_one_mailbox() {
    let relay = MockRelay::new(Network::Mainnet);
    for n in 0..5 {
        post_stored(&relay, CAROL, PAIRING_BOX, &format!("message {n}"));
    }
    post_stored(&relay, CAROL, CONTACT_BOX, "invoice");
    let mut handler = Recorder::new(&relay);
    let client = mailbox_client(&relay);
    let client = client.clone().with_limits(DrainLimits {
        messages_per_mailbox: 3,
        ..client.limits()
    });

    let report = within(
        LONG,
        client.drain_once(&[mailbox(PAIRING_BOX), mailbox(CONTACT_BOX)], &mut handler),
    )
    .await
    .unwrap();

    assert_eq!(report.mailboxes[0].end, MailboxEnd::Capped);
    assert_eq!(report.mailboxes[0].handed_out, 3);
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 2);
    assert_eq!(report.mailboxes[1].end, MailboxEnd::Empty);
    assert_eq!(report.connections, 1);
}

#[tokio::test]
async fn a_drain_that_runs_out_of_time_reports_the_mailboxes_it_did_not_finish() {
    let relay = MockRelay::new(Network::Mainnet);
    post_stored(&relay, CAROL, PAIRING_BOX, "reply");
    relay.set_unanswered(Unanswered::Subscribe, true);
    let mut handler = Recorder::new(&relay);
    let client = mailbox_client(&relay);
    let client = client.clone().with_limits(DrainLimits {
        timeout: Duration::from_millis(300),
        ..client.limits()
    });

    let report = within(
        LONG,
        client.drain_once(&[mailbox(PAIRING_BOX), mailbox(CONTACT_BOX)], &mut handler),
    )
    .await
    .unwrap();

    let ends: Vec<_> = report.mailboxes.iter().map(|m| m.end).collect();
    assert_eq!(ends, [MailboxEnd::TimedOut, MailboxEnd::NotReached]);
    assert!(handler.seen().is_empty());
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 1);
}

#[tokio::test]
async fn a_message_for_an_earlier_mailbox_that_arrives_later_is_left_pending() {
    let relay = MockRelay::new(Network::Mainnet);
    post_stored(&relay, CAROL, PAIRING_BOX, "reply");
    post_stored(&relay, CAROL, CONTACT_BOX, "invoice");
    let mut handler = Recorder::new(&relay);
    let poster = relay.clone();
    handler.on_message = Some(Box::new(move |message| {
        if message.mailbox() == 1 {
            post_stored(&poster, CAROL, PAIRING_BOX, "late reply");
        }
    }));

    let report = within(
        LONG,
        mailbox_client(&relay)
            .drain_once(&[mailbox(PAIRING_BOX), mailbox(CONTACT_BOX)], &mut handler),
    )
    .await
    .unwrap();

    assert_eq!(report.mailboxes[0].handed_out, 1);
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 1);

    let mut next = Recorder::new(&relay);
    within(
        LONG,
        mailbox_client(&relay).drain_once(&[mailbox(PAIRING_BOX)], &mut next),
    )
    .await
    .unwrap();
    assert_eq!(next.texts(), [(0, "late reply".to_owned())]);
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 0);
}

#[tokio::test]
async fn a_post_from_a_throwaway_key_is_drained_back_from_the_mailbox() {
    let relay = MockRelay::new(Network::Mainnet);
    let client = mailbox_client(&relay);

    within(
        LONG,
        client.post(&mailbox(THROWAWAY), &address(PAIRING_BOX), "pairing reply"),
    )
    .await
    .unwrap();

    let senders = Arc::new(Mutex::new(Vec::new()));
    let mut handler = Recorder::new(&relay);
    let recorded = Arc::clone(&senders);
    handler.on_message = Some(Box::new(move |message| {
        if let MailboxContent::Opened(received) = message.content() {
            recorded.lock().unwrap().push(*received.sender.public_key());
        }
    }));
    within(
        LONG,
        client.drain_once(&[mailbox(PAIRING_BOX)], &mut handler),
    )
    .await
    .unwrap();
    assert_eq!(handler.texts(), [(0, "pairing reply".to_owned())]);
    assert_eq!(*senders.lock().unwrap(), [*address(THROWAWAY).public_key()]);
}

#[tokio::test]
async fn a_message_that_does_not_open_is_handed_out_as_unopenable() {
    let relay = MockRelay::new(Network::Mainnet);
    // Queued for the mailbox, sealed for another key.
    relay.store(
        &address(CAROL),
        &address(PAIRING_BOX),
        &sealed(CAROL, STRANGER, "elsewhere"),
    );
    let mut handler = Recorder::new(&relay);

    within(
        LONG,
        mailbox_client(&relay).drain_once(&[mailbox(PAIRING_BOX)], &mut handler),
    )
    .await
    .unwrap();

    assert_eq!(
        handler.texts(),
        [(
            0,
            format!("unopenable {:?}", RejectionReason::NotAddressedToUs)
        )]
    );
    assert_eq!(relay.pending(&address(PAIRING_BOX)), 0);
}

#[tokio::test]
async fn an_unreachable_relay_is_told_apart_from_a_protocol_error() {
    let relay = MockRelay::new(Network::Mainnet);
    let mut handler = Recorder::new(&relay);
    relay.set_refusing(true);
    let refused = mailbox_client(&relay)
        .drain_once(&[mailbox(PAIRING_BOX)], &mut handler)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, MailboxError::Unreachable(_)),
        "{refused:?}"
    );
    let post = mailbox_client(&relay)
        .post(&mailbox(THROWAWAY), &address(PAIRING_BOX), "x")
        .await
        .unwrap_err();
    assert!(matches!(post, MailboxError::Unreachable(_)), "{post:?}");

    relay.set_refusing(false);
    relay.set_version(Some("2.0.0"));
    let old = mailbox_client(&relay)
        .drain_once(&[mailbox(PAIRING_BOX)], &mut handler)
        .await
        .unwrap_err();
    assert!(matches!(old, MailboxError::Protocol(_)), "{old:?}");
}

#[tokio::test]
async fn refuses_more_mailboxes_than_one_drain_takes() {
    let relay = MockRelay::new(Network::Mainnet);
    let mut handler = Recorder::new(&relay);
    let mailboxes: Vec<_> = (0..51).map(|_| mailbox(PAIRING_BOX)).collect();
    let error = mailbox_client(&relay)
        .drain_once(&mailboxes, &mut handler)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        MailboxError::TooManyMailboxes { count: 51 }
    ));
    assert_eq!(relay.connections(), 0);
}

/// Records how each connection was asked for, then connects to the mock relay.
struct Recording {
    inner: Arc<dyn Connector>,
    asked: Mutex<Vec<Option<DialTarget>>>,
}

impl Connector for Recording {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        self.asked.lock().unwrap().push(None);
        self.inner.connect(endpoint)
    }

    fn connect_to_onion<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
        onion: &'a DialTarget,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        self.asked.lock().unwrap().push(Some(onion.clone()));
        self.inner.connect(endpoint)
    }
}

#[tokio::test]
async fn an_onion_given_for_the_relay_is_passed_to_the_connector_for_every_connection() {
    let relay = MockRelay::new(Network::Mainnet);
    post_stored(&relay, CAROL, PAIRING_BOX, "reply");
    let recording = Arc::new(Recording {
        inner: relay.connector(),
        asked: Mutex::default(),
    });
    let onion = DialTarget {
        host: format!("{}.onion", "a".repeat(56)),
        port: 443,
    };
    let settings: ClientSettings = settings();
    let client = MailboxClient::new(
        settings.clone(),
        Arc::clone(&recording) as Arc<dyn Connector>,
    )
    .with_onion(onion.clone());
    let mut handler = Recorder::new(&relay);

    within(
        LONG,
        client.post(&mailbox(THROWAWAY), &address(CONTACT_BOX), "hello"),
    )
    .await
    .unwrap();
    within(
        LONG,
        client.drain_once(&[mailbox(PAIRING_BOX)], &mut handler),
    )
    .await
    .unwrap();
    assert_eq!(
        *recording.asked.lock().unwrap(),
        [Some(onion.clone()), Some(onion)]
    );

    let plain = MailboxClient::new(settings, Arc::clone(&recording) as Arc<dyn Connector>);
    within(
        LONG,
        plain.drain_once(&[mailbox(CONTACT_BOX)], &mut handler),
    )
    .await
    .unwrap();
    assert_eq!(recording.asked.lock().unwrap().last(), Some(&None));
}
