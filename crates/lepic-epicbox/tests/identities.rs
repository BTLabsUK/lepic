// SPDX-License-Identifier: Apache-2.0
//! Several identities of one wallet against the mock relay, and the prefilter that drops
//! messages from unknown senders before they are opened.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, client, sealed, within};
use lepic_crypto::PublicKey;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    Admission, Domain, EpicboxAddress, EpicboxClient, InboxCounters, Network, Prefilter,
    RejectionReason, Subscription,
};
use lepic_transport::transport::{Envelope, Inbound};

const LONG: Duration = Duration::from_secs(5);

/// Bob's second address beside his payments address, as a listing address is.
const BOB_SECOND: u8 = 4;

fn key(byte: u8) -> PublicKey {
    *address(byte).public_key()
}

/// Admits only `allowed` and counts how often it was asked.
struct Allowlist {
    allowed: PublicKey,
    asked: AtomicUsize,
}

impl Allowlist {
    fn new(allowed: u8) -> Arc<Self> {
        Arc::new(Self {
            allowed: key(allowed),
            asked: AtomicUsize::new(0),
        })
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Prefilter for Allowlist {
    fn admit(&self, sender: &PublicKey) -> Admission {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if *sender == self.allowed {
            Admission::Accept
        } else {
            Admission::Drop
        }
    }
}

fn filtered(relay: &MockRelay, byte: u8, prefilter: Arc<dyn Prefilter>) -> EpicboxClient {
    client(relay, byte).with_prefilter(prefilter)
}

fn counters(seen: u64, dropped: u64, opened: u64) -> InboxCounters {
    let mut counters = InboxCounters::default();
    counters.seen = seen;
    counters.dropped = dropped;
    counters.opened = opened;
    counters
}

async fn next(inbound: &Subscription) -> Option<Envelope> {
    within(LONG, inbound.next_envelope()).await.unwrap()
}

/// The next envelope a listener receives, waiting for it to arrive.
async fn arrival(listener: &Subscription) -> Envelope {
    within(LONG, listener.delivery_available()).await;
    next(listener).await.unwrap()
}

/// Drains everything, acknowledging each envelope and rejection, and returns the envelopes'
/// texts and the rejections' reasons.
async fn drain_all(subscription: &Subscription) -> (Vec<String>, Vec<RejectionReason>) {
    let mut texts = Vec::new();
    let mut reasons = Vec::new();
    loop {
        within(LONG, subscription.delivery_available()).await;
        if let Some(rejection) = subscription.next_rejection() {
            reasons.push(rejection.reason());
            within(LONG, subscription.acknowledge(rejection.ack_token()))
                .await
                .unwrap();
        } else if let Some(envelope) = next(subscription).await {
            texts.push(envelope.wire().as_text().unwrap().to_owned());
            within(LONG, subscription.acknowledge(envelope.ack_token()))
                .await
                .unwrap();
        } else {
            break;
        }
    }
    within(LONG, subscription.finished()).await.unwrap();
    (texts, reasons)
}

#[tokio::test]
async fn a_dropped_message_is_acknowledged_and_never_opened() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(CAROL), &address(BOB), &sealed(CAROL, BOB, "junk"));
    let allowlist = Allowlist::new(ALICE);
    let bob = filtered(&relay, BOB, allowlist.clone()).drain().unwrap();

    let (texts, reasons) = drain_all(&bob).await;

    assert!(texts.is_empty());
    assert!(reasons.is_empty());
    assert_eq!(bob.counters(), counters(1, 1, 0));
    assert_eq!(allowlist.asked(), 1);
    assert_eq!(relay.received("Made"), 1);
    assert_eq!(relay.pending(&address(BOB)), 0);
}

#[tokio::test]
async fn an_allowed_message_behind_many_dropped_ones_is_the_only_one_opened() {
    let relay = MockRelay::new(Network::Mainnet);
    for number in 0..100 {
        relay.store(
            &address(CAROL),
            &address(BOB),
            &sealed(CAROL, BOB, &format!("junk {number}")),
        );
    }
    relay.store(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "invoice"),
    );
    let bob = filtered(&relay, BOB, Allowlist::new(ALICE))
        .drain()
        .unwrap();

    let (texts, reasons) = drain_all(&bob).await;

    assert_eq!(texts, ["invoice"]);
    assert!(reasons.is_empty());
    assert_eq!(bob.counters(), counters(101, 100, 1));
    assert_eq!(relay.pending(&address(BOB)), 0);
}

#[tokio::test]
async fn the_prefilter_runs_before_the_signature_check() {
    // Signed by Alice but claiming to come from Carol, so the signature cannot verify.
    let forged = sealed(ALICE, BOB, "forged");

    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(CAROL), &address(BOB), &forged);
    let bob = filtered(&relay, BOB, Allowlist::new(ALICE))
        .drain()
        .unwrap();
    let (texts, reasons) = drain_all(&bob).await;
    assert!(texts.is_empty());
    assert!(reasons.is_empty());
    assert_eq!(bob.counters(), counters(1, 1, 0));

    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(CAROL), &address(BOB), &forged);
    let bob = client(&relay, BOB).drain().unwrap();
    let (texts, reasons) = drain_all(&bob).await;
    assert!(texts.is_empty());
    assert_eq!(reasons, [RejectionReason::InvalidSignature]);
    assert_eq!(bob.counters(), counters(1, 0, 1));
}

#[tokio::test]
async fn a_sender_that_is_not_an_address_on_the_network_is_dropped_without_asking() {
    let relay = MockRelay::new(Network::Mainnet);
    let elsewhere = EpicboxAddress::new(
        key(ALICE),
        Network::Floonet,
        Domain::parse("relay.test").unwrap(),
        Some(443),
    );
    relay.store(
        &elsewhere,
        &address(BOB),
        &sealed(ALICE, BOB, "other network"),
    );
    let allowlist = Allowlist::new(ALICE);
    let bob = filtered(&relay, BOB, allowlist.clone()).drain().unwrap();

    let (texts, reasons) = drain_all(&bob).await;

    assert!(texts.is_empty());
    assert!(reasons.is_empty());
    assert_eq!(allowlist.asked(), 0);
    assert_eq!(bob.counters(), counters(1, 1, 0));
    assert_eq!(relay.pending(&address(BOB)), 0);
}

#[tokio::test]
async fn without_a_prefilter_every_message_is_opened() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.store(&address(CAROL), &address(BOB), &sealed(CAROL, BOB, "one"));
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "two"));
    let bob = client(&relay, BOB).drain().unwrap();

    let (texts, reasons) = drain_all(&bob).await;

    assert_eq!(texts, ["one", "two"]);
    assert!(reasons.is_empty());
    assert_eq!(bob.counters(), counters(2, 0, 2));
}

#[tokio::test]
async fn two_identities_listen_at_once_each_on_its_own_connection() {
    let relay = MockRelay::new(Network::Mainnet);
    let payments = client(&relay, BOB).listen().unwrap();
    let invoices = filtered(&relay, BOB_SECOND, Allowlist::new(ALICE))
        .listen()
        .unwrap();
    within(
        LONG,
        relay.wait_until(|relay| relay.connections() == 2 && relay.received("Subscribe") == 2),
    )
    .await;

    relay.store(
        &address(CAROL),
        &address(BOB),
        &sealed(CAROL, BOB, "payment"),
    );
    relay.store(
        &address(CAROL),
        &address(BOB_SECOND),
        &sealed(CAROL, BOB_SECOND, "junk"),
    );
    relay.store(
        &address(ALICE),
        &address(BOB_SECOND),
        &sealed(ALICE, BOB_SECOND, "invoice"),
    );

    let payment = arrival(&payments).await;
    assert_eq!(payment.wire().as_text(), Some("payment"));
    let invoice = arrival(&invoices).await;
    assert_eq!(invoice.wire().as_text(), Some("invoice"));
    within(LONG, payments.acknowledge(payment.ack_token()))
        .await
        .unwrap();
    within(LONG, invoices.acknowledge(invoice.ack_token()))
        .await
        .unwrap();

    assert_eq!(relay.pending(&address(BOB)), 0);
    assert_eq!(relay.pending(&address(BOB_SECOND)), 0);
    assert_eq!(payments.counters(), counters(1, 0, 1));
    assert_eq!(invoices.counters(), counters(2, 1, 1));
    assert_eq!(relay.connections(), 2);
    payments.stop().await.unwrap();
    invoices.stop().await.unwrap();
}
