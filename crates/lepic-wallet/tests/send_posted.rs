// SPDX-License-Identifier: Apache-2.0
//! The `posted` notice for ordinary sends over Epicbox on the mock relay (ADR 0016, amendment
//! W-31): S1 and S2 between LEPIC wallets carry the marker, the sender tells the receiver once
//! it pushed the transaction, and the receiver keeps that report only from the payment's real
//! sender, with the kernel its own S2 implies, once per payment and while the payment waits.
//! Stock wallets never see the marker in a reply and never get a notice.
//!
//! The payer of `World` sends and the issuer receives. Where a test needs to speak as the
//! sender, the payer sends to the peer key 7, which forwards each slate, so the receiver's
//! counterparty is a key the test holds.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use lepic_crypto::Commitment;
use lepic_epicbox::marker::features::LEPIC_FEATURES;
use lepic_epicbox::marker::v3::{carries_lepic_marker, lepic_marker_features};
use lepic_epicbox::{EpicboxAddress, EpicboxClient};
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::Amount;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::SlateId;
use lepic_store::{PeerCompat, SlateStage, TxDirection, TxId, TxState, WalletStore};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::event::PostedPayment;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::notice::{Notice, NoticeKind, Payload, classify_text};
use lepic_wallet::peer_compat::PeerKind;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Clock, Event};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

/// The peer key that stands for the sender, forwarding the payer's slates.
const SENDER: u8 = 7;
/// A key that has nothing to do with the payment.
const STRANGER: u8 = 9;

/// The marker of a wallet whose host claims nothing: LEPIC's own feature bits.
/// The marker this build writes on Epicbox slates, with the features it claims.
fn marker() -> String {
    format!(
        ",\"lepic\":{{\"version\":1,\"f\":{}}}",
        lepic_epicbox::marker::features::LEPIC_FEATURES
    )
}

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn posted_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentPosted(_) | Event::InvoicePosted(_)))
        .collect()
}

fn posted_text(slate_id: SlateId, excess: Commitment) -> String {
    let wire = Notice {
        slate_id,
        kind: NoticeKind::Posted { excess },
    }
    .encode();
    wire.as_text().unwrap().to_owned()
}

/// `json` as a stock wallet writes it back: without the marker.
fn unmarked(json: &str) -> String {
    assert!(json.contains(&marker()), "no marker in {json}");
    json.replace(&marker(), "")
}

fn wire(json: &str) -> WireSlate {
    WireSlate::text(MediaType::JSON, json.to_owned())
}

/// A payment the payer sent through the peer key [`SENDER`], which the issuer received and
/// answered. `s2` is the issuer's answer as the peer received it.
struct Receipt {
    sent: SentSlate,
    /// The issuer's transaction.
    tx_id: TxId,
    s2: String,
}

impl World {
    fn sender(&self) -> &Party {
        &self.payer
    }

    fn receiver(&self) -> &Party {
        &self.issuer
    }

    fn drain(&self, party: &Party) -> InboxSummary {
        self.block_on(party.wallet.epicbox_drain(&party.epicbox))
            .unwrap()
    }

    fn send_to(&self, to: &EpicboxAddress) -> SentSlate {
        self.block_on(self.sender().wallet.send(
            &self.sender().method,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
    }

    /// Takes every message waiting for `peer`, acknowledges it and returns its plaintext.
    fn drain_peer(&self, peer: &EpicboxClient) -> Vec<String> {
        self.block_on(async {
            let subscription = peer.drain().unwrap();
            let mut received = Vec::new();
            while let Some(envelope) = self.within(subscription.next_envelope()).await.unwrap() {
                received.push(envelope.wire().as_text().unwrap().to_owned());
                subscription
                    .acknowledge(envelope.ack_token())
                    .await
                    .unwrap();
            }
            subscription.stop().await.unwrap();
            received
        })
    }

    fn only_message(&self, peer: &EpicboxClient) -> String {
        let mut received = self.drain_peer(peer);
        assert_eq!(received.len(), 1, "{received:?}");
        received.remove(0)
    }

    /// The payer sends to [`SENDER`], which hands the S1 on to the issuer as `forward` writes
    /// it; the issuer answers to [`SENDER`].
    fn receipt_through_sender(&self, forward: impl FnOnce(String) -> String) -> Receipt {
        let peer = self.peer_client(SENDER);
        let sent = self.send_to(&World::address_of(SENDER));
        let s1 = self.only_message(&peer);
        assert!(carries_lepic_marker(&wire(&s1)));
        assert_eq!(lepic_marker_features(&wire(&s1)), Some(LEPIC_FEATURES));
        self.post(SENDER, &self.receiver().address, &forward(s1), 1);
        assert_eq!(self.drain(self.receiver()).received, 1);
        let s2 = self.only_message(&peer);
        let tx_id = self
            .receiver()
            .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
            .unwrap()
            .id;
        Receipt { sent, tx_id, s2 }
    }

    /// [`World::receipt_through_sender`] with the S1 handed on as it came, then the S2 handed
    /// back to the payer from [`SENDER`], which finalizes and posts it. Returns the receipt and
    /// the `posted` notice the payer sent to [`SENDER`].
    fn posted_through_sender(&self) -> (Receipt, String) {
        let receipt = self.receipt_through_sender(|s1| s1);
        self.post(SENDER, &self.sender().address, &receipt.s2, 1);
        assert_eq!(self.drain(self.sender()).finalized, 1);
        let notice = self.only_message(&self.peer_client(SENDER));
        (receipt, notice)
    }

    fn kernel_excess(&self) -> Commitment {
        let pushed = self.node.pushed_transactions();
        assert_eq!(pushed.len(), 1);
        pushed[0].kernels()[0].excess
    }

    fn receiver_state(&self, tx_id: TxId) -> TxState {
        self.receiver()
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .state
    }

    fn reported(&self, slate_id: SlateId) -> bool {
        self.receiver().read(|repos| {
            let Some(stored) = repos.transaction_by_slate(uuid(slate_id), TxDirection::Incoming)?
            else {
                return Ok(false);
            };
            Ok(repos.tx_marks(stored.id)?.sender_posted_at.is_some())
        })
    }

    fn report_shown(&self, tx_id: TxId) -> Option<jiff::Timestamp> {
        self.block_on(self.receiver().wallet.transaction_details(tx_id))
            .unwrap()
            .sender_reported_posted_at
    }

    fn set_receiver_transaction(
        &self,
        tx_id: TxId,
        change: impl FnOnce(&mut lepic_store::TransactionEntry),
    ) {
        self.receiver()
            .store()
            .write(|repos| {
                let mut entry = repos.transaction(tx_id)?.unwrap();
                change(&mut entry);
                repos.update_transaction(tx_id, &entry)
            })
            .unwrap();
    }
}

#[test]
fn a_send_between_lepic_wallets_tells_the_receiver_it_was_posted() {
    let world = World::new();
    let mut receiver_events = world.receiver().wallet.subscribe();
    let sent = world.send_to(&world.receiver().address);

    assert_eq!(world.drain(world.receiver()).received, 1);
    let s2 = world
        .receiver()
        .read(|repos| repos.slate(uuid(sent.slate_id), SlateStage::Standard2))
        .unwrap();
    assert!(carries_lepic_marker(&WireSlate::binary(
        MediaType::JSON,
        s2.bytes
    )));
    let sender_key = world.sender().address.key_text();
    assert_eq!(
        world.receiver().peer_kind(&sender_key),
        Some(PeerKind::Lepic)
    );
    assert_eq!(world.drain(world.sender()).finalized, 1);
    let receiver_key = world.receiver().address.key_text();
    assert_eq!(
        world.sender().peer_kind(&receiver_key),
        Some(PeerKind::Lepic)
    );
    let excess = world.kernel_excess();
    let tx_id = world
        .receiver()
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
        .unwrap()
        .id;
    let _ = posted_events(&mut receiver_events);

    let summary = world.drain(world.receiver());

    assert_eq!(
        summary,
        InboxSummary {
            notices: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        posted_events(&mut receiver_events),
        vec![Event::PaymentPosted(PostedPayment {
            tx_id,
            slate_id: sent.slate_id,
            excess,
        })]
    );
    // Advisory: the payment waits for a refresh to see the kernel.
    assert_eq!(world.receiver_state(tx_id), TxState::Received);
    assert_eq!(
        world.report_shown(tx_id),
        Some(world.receiver().clock.now())
    );
}

#[test]
fn the_report_is_shown_for_an_hour_while_the_payment_waits() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    world.post(SENDER, &world.receiver().address, &notice, 1);
    assert_eq!(world.drain(world.receiver()).notices, 1);
    assert!(world.report_shown(receipt.tx_id).is_some());

    world.receiver().clock.advance(Duration::from_secs(59 * 60));
    assert!(world.report_shown(receipt.tx_id).is_some());
    world.receiver().clock.advance(Duration::from_secs(60));

    assert_eq!(world.report_shown(receipt.tx_id), None);
}

#[test]
fn the_report_is_not_shown_once_the_payment_confirmed() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    world.post(SENDER, &world.receiver().address, &notice, 1);
    world.drain(world.receiver());

    world.set_receiver_transaction(receipt.tx_id, |entry| entry.state = TxState::Confirmed);

    assert_eq!(world.report_shown(receipt.tx_id), None);
}

#[test]
fn a_posted_notice_from_another_key_is_dropped() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    let mut receiver_events = world.receiver().wallet.subscribe();

    world.post(STRANGER, &world.receiver().address, &notice, 1);
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 1));
    assert!(posted_events(&mut receiver_events).is_empty());
    assert!(!world.reported(receipt.sent.slate_id));
    assert_eq!(world.report_shown(receipt.tx_id), None);
    let stranger = World::address_of(STRANGER).key_text();
    assert!(world.receiver().peer_kind(&stranger).is_none());
}

#[test]
fn a_posted_notice_with_another_excess_is_dropped() {
    let world = World::new();
    let (receipt, _) = world.posted_through_sender();
    let mut receiver_events = world.receiver().wallet.subscribe();
    let lie = posted_text(receipt.sent.slate_id, Commitment::commit_value(1).unwrap());

    world.post(SENDER, &world.receiver().address, &lie, 1);
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 1));
    assert!(posted_events(&mut receiver_events).is_empty());
    assert!(!world.reported(receipt.sent.slate_id));
    assert_eq!(world.receiver_state(receipt.tx_id), TxState::Received);
}

#[test]
fn a_replayed_posted_notice_raises_one_event() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    let mut receiver_events = world.receiver().wallet.subscribe();

    // Three copies under three relay message ids, then one more in a later drain.
    world.post(SENDER, &world.receiver().address, &notice, 3);
    let first = world.drain(world.receiver());
    world.receiver().clock.advance(Duration::from_secs(10 * 60));
    world.post(SENDER, &world.receiver().address, &notice, 1);
    let second = world.drain(world.receiver());

    assert_eq!((first.notices, second.notices), (3, 1));
    let events = posted_events(&mut receiver_events);
    assert_eq!(events.len(), 1, "{events:?}");
    // The report keeps the time of the first notice.
    let shown = world.report_shown(receipt.tx_id).unwrap();
    world.receiver().clock.advance(Duration::from_secs(50 * 60));
    assert_eq!(
        world.report_shown(receipt.tx_id),
        None,
        "first report at {shown}"
    );
}

#[test]
fn a_flood_of_posted_notices_raises_at_most_one_event() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    let mut receiver_events = world.receiver().wallet.subscribe();
    let excess = world.kernel_excess();
    let lie = posted_text(receipt.sent.slate_id, Commitment::commit_value(2).unwrap());

    for byte in 20..120 {
        world.post(byte, &world.receiver().address, &notice, 1);
    }
    world.post(SENDER, &world.receiver().address, &lie, 50);
    world.post(SENDER, &world.receiver().address, &notice, 100);
    let summary = world.drain(world.receiver());

    assert_eq!(world.relay.pending(&world.receiver().address), 0);
    assert_eq!((summary.notices, summary.dropped), (100, 150));
    assert_eq!(
        posted_events(&mut receiver_events),
        vec![Event::PaymentPosted(PostedPayment {
            tx_id: receipt.tx_id,
            slate_id: receipt.sent.slate_id,
            excess,
        })]
    );
    assert_eq!(world.receiver_state(receipt.tx_id), TxState::Received);
}

#[test]
fn a_posted_notice_for_an_unknown_or_unanswered_slate_is_dropped() {
    let world = World::new();
    let peer = world.peer_client(SENDER);
    let sent = world.send_to(&World::address_of(SENDER));
    let s1 = world.only_message(&peer);
    let mut receiver_events = world.receiver().wallet.subscribe();
    let excess = Commitment::commit_value(3).unwrap();

    // Before the receiver holds the slate at all, and for a slate id nobody used.
    world.post(
        SENDER,
        &world.receiver().address,
        &posted_text(sent.slate_id, excess),
        1,
    );
    world.post(
        SENDER,
        &world.receiver().address,
        &posted_text(SlateId::from_bytes([0x42; 16]), excess),
        1,
    );
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 2));
    assert!(posted_events(&mut receiver_events).is_empty());
    assert!(!world.reported(sent.slate_id));
    // The payment itself is still received normally afterwards.
    world.post(SENDER, &world.receiver().address, &s1, 1);
    assert_eq!(world.drain(world.receiver()).received, 1);
}

#[test]
fn a_posted_notice_after_the_payment_confirmed_or_ended_is_only_noted() {
    for end in [TxState::Confirmed, TxState::Cancelled, TxState::Expired] {
        let world = World::new();
        let (receipt, notice) = world.posted_through_sender();
        world.set_receiver_transaction(receipt.tx_id, |entry| entry.state = end);
        let mut receiver_events = world.receiver().wallet.subscribe();

        world.post(SENDER, &world.receiver().address, &notice, 1);
        let summary = world.drain(world.receiver());

        assert_eq!((summary.notices, summary.dropped), (1, 0), "{end:?}");
        assert!(posted_events(&mut receiver_events).is_empty(), "{end:?}");
        assert!(!world.reported(receipt.sent.slate_id), "{end:?}");
        assert_eq!(world.receiver_state(receipt.tx_id), end);
    }
}

#[test]
fn a_posted_notice_for_a_payment_over_another_transport_is_dropped() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    world.set_receiver_transaction(receipt.tx_id, |entry| {
        entry.transport = Some("file".to_owned());
    });
    let mut receiver_events = world.receiver().wallet.subscribe();

    world.post(SENDER, &world.receiver().address, &notice, 1);
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 1));
    assert!(posted_events(&mut receiver_events).is_empty());
    assert!(!world.reported(receipt.sent.slate_id));
}

#[test]
fn an_unmarked_s1_is_answered_without_the_marker_and_counts_as_another_wallet() {
    let world = World::new();

    let receipt = world.receipt_through_sender(|s1| unmarked(&s1));

    assert!(!carries_lepic_marker(&wire(&receipt.s2)));
    assert!(!receipt.s2.contains("lepic"));
    let sender = World::address_of(SENDER).key_text();
    assert_eq!(world.receiver().peer_kind(&sender), Some(PeerKind::Epic));
}

#[test]
fn an_unmarked_reply_gets_no_notice() {
    let world = World::new();
    let receipt = world.receipt_through_sender(|s1| unmarked(&s1));

    world.post(SENDER, &world.sender().address, &receipt.s2, 1);
    assert_eq!(world.drain(world.sender()).finalized, 1);

    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert!(world.drain_peer(&world.peer_client(SENDER)).is_empty());
    let sender = World::address_of(SENDER).key_text();
    assert_eq!(world.sender().peer_kind(&sender), Some(PeerKind::Epic));
}

/// Marks `key` as heard from with the marker at `at`, as an earlier exchange or a migrated
/// record leaves it.
fn proven_at(party: &Party, key: &str, at: jiff::Timestamp) {
    party
        .store()
        .write(|repos| {
            repos.put_peer_compat(
                key,
                &PeerCompat {
                    last_marked_at: Some(at),
                    claimed: 1,
                    works: 1,
                    ..PeerCompat::default()
                },
            )
        })
        .unwrap();
}

/// The shipping bug: a key that ran LEPIC once answers from another wallet now. Its unmarked
/// answer is recorded before the notice is decided, and no `posted` goes to its queue.
#[test]
fn a_key_proven_before_that_answers_unmarked_gets_no_posted() {
    let world = World::new();
    let (_, notice) = world.posted_through_sender();
    assert!(matches!(classify_text(&notice), Payload::Notice(_)));
    let sender = World::address_of(SENDER).key_text();
    assert_eq!(world.sender().peer_kind(&sender), Some(PeerKind::Lepic));
    world.sender().fund(20, world::FUNDING);

    let receipt = world.receipt_through_sender(|s1| s1);
    world.post(SENDER, &world.sender().address, &unmarked(&receipt.s2), 1);
    assert_eq!(world.drain(world.sender()).finalized, 1);

    assert_eq!(world.node.pushed_transactions().len(), 2);
    assert!(world.drain_peer(&world.peer_client(SENDER)).is_empty());
    let compat = world.sender().peer_compat(&sender).unwrap();
    assert_eq!(compat.last_unmarked_at, Some(world.sender().clock.now()));
    assert_eq!(world.sender().peer_kind(&sender), Some(PeerKind::Epic));
}

/// Two wallets on one recovery phrase: a LEPIC one made the key look LEPIC just now, and the
/// other answers this send. The exchange itself came unmarked, so nothing goes.
#[test]
fn a_twin_answering_unmarked_gets_no_posted() {
    let world = World::new();
    let sender = World::address_of(SENDER).key_text();
    proven_at(world.sender(), &sender, world.sender().clock.now());

    let receipt = world.receipt_through_sender(|s1| s1);
    world.post(SENDER, &world.sender().address, &unmarked(&receipt.s2), 1);
    assert_eq!(world.drain(world.sender()).finalized, 1);

    assert!(world.drain_peer(&world.peer_client(SENDER)).is_empty());
    let compat = world.sender().peer_compat(&sender).unwrap();
    assert!(compat.last_marked_at.is_some() && compat.last_unmarked_at.is_some());
}

/// A key last heard from with the marker 60 days ago, as a record migrated from an older store
/// can be, is LEPIC by its dates but gets no notice for a new unmarked exchange.
#[test]
fn a_key_proven_sixty_days_ago_gets_no_notice_for_an_unmarked_exchange() {
    let world = World::new();
    let sender = World::address_of(SENDER).key_text();
    let sixty_days = Duration::from_secs(60 * 24 * 60 * 60);
    let long_ago = world.sender().clock.now() - jiff::SignedDuration::try_from(sixty_days).unwrap();
    proven_at(world.sender(), &sender, long_ago);
    let facts = world
        .sender()
        .wallet
        .peer_compat(&World::address_of(SENDER).to_string())
        .unwrap();
    assert_eq!(facts.kind, PeerKind::Lepic);
    assert!(!facts.notices);

    let receipt = world.receipt_through_sender(|s1| s1);
    world.post(SENDER, &world.sender().address, &unmarked(&receipt.s2), 1);
    assert_eq!(world.drain(world.sender()).finalized, 1);

    assert!(world.drain_peer(&world.peer_client(SENDER)).is_empty());
}

/// The same old key that answers marked is LEPIC again at once, and is told.
#[test]
fn a_key_proven_sixty_days_ago_that_answers_marked_is_told_again() {
    let world = World::new();
    let sender = World::address_of(SENDER).key_text();
    let sixty_days = jiff::SignedDuration::from_hours(60 * 24);
    proven_at(
        world.sender(),
        &sender,
        world.sender().clock.now() - sixty_days,
    );

    let (_, notice) = world.posted_through_sender();

    assert!(matches!(
        classify_text(&notice),
        Payload::Notice(Notice {
            kind: NoticeKind::Posted { .. },
            ..
        })
    ));
}

#[test]
fn a_marked_reply_from_another_key_proves_nothing() {
    let world = World::new();
    let receipt = world.receipt_through_sender(|s1| s1);
    assert!(carries_lepic_marker(&wire(&receipt.s2)));
    assert_eq!(
        lepic_marker_features(&wire(&receipt.s2)),
        Some(LEPIC_FEATURES)
    );

    world.post(STRANGER, &world.sender().address, &receipt.s2, 1);
    world.drain(world.sender());

    for byte in [SENDER, STRANGER] {
        let key = World::address_of(byte).key_text();
        assert!(world.sender().peer_kind(&key).is_none(), "{byte}");
        assert!(
            world.drain_peer(&world.peer_client(byte)).is_empty(),
            "{byte}"
        );
    }
}

#[test]
fn the_sender_tells_the_receiver_once_with_the_kernel_it_posted() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();

    assert_eq!(
        classify_text(&notice),
        Payload::Notice(Notice {
            slate_id: receipt.sent.slate_id,
            kind: NoticeKind::Posted {
                excess: world.kernel_excess(),
            },
        })
    );
    // The same S2 again pushes nothing and tells nobody.
    world.post(SENDER, &world.sender().address, &receipt.s2, 1);
    assert_eq!(world.drain(world.sender()).repeated, 1);
    assert!(world.drain_peer(&world.peer_client(SENDER)).is_empty());
}

#[test]
fn a_send_whose_reply_is_posted_on_a_second_try_tells_the_receiver_then() {
    let world = World::new();
    let receipt = world.receipt_through_sender(|s1| s1);
    world
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    world.post(SENDER, &world.sender().address, &receipt.s2, 1);
    world.drain(world.sender());
    let peer = world.peer_client(SENDER);
    assert!(world.drain_peer(&peer).is_empty());

    // The receiver sends its S2 again; finalizing it again pushes the transaction this time.
    world.post(SENDER, &world.sender().address, &receipt.s2, 1);
    assert_eq!(world.drain(world.sender()).repeated, 1);

    let notice = world.only_message(&peer);
    assert!(matches!(
        classify_text(&notice),
        Payload::Notice(Notice {
            kind: NoticeKind::Posted { .. },
            ..
        })
    ));
}

#[test]
fn a_host_post_of_a_send_sends_no_notice() {
    let world = World::new();
    let receipt = world.receipt_through_sender(|s1| s1);
    world
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    world.post(SENDER, &world.sender().address, &receipt.s2, 1);
    world.drain(world.sender());
    let deliveries = world.sender().delivered_to().len();

    world
        .block_on(
            world
                .sender()
                .wallet
                .post(receipt.sent.tx_id, lepic_node::Propagation::Stem),
        )
        .unwrap();

    // Outside a listen or drain nothing goes to the relay, so an Epicbox switch the host
    // turned off holds.
    assert_eq!(world.sender().delivered_to().len(), deliveries);
    assert!(world.drain_peer(&world.peer_client(SENDER)).is_empty());
}

#[test]
fn a_posted_notice_for_an_invoice_this_wallet_issued_is_dropped() {
    let world = World::new();
    let issued = world.issue_to(&World::address_of(SENDER), None);
    let mut receiver_events = world.receiver().wallet.subscribe();

    // The invoice went to the key that now claims to have posted it: the issuer stored its I1
    // and that key as the counterparty, and no S2.
    world.post(
        SENDER,
        &world.receiver().address,
        &posted_text(issued.slate_id, Commitment::commit_value(4).unwrap()),
        1,
    );
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 1));
    assert!(posted_events(&mut receiver_events).is_empty());
    assert!(!world.reported(issued.slate_id));
    assert_eq!(world.report_shown(issued.tx_id), None);
}

#[test]
fn a_report_dated_ahead_of_the_clock_is_not_shown() {
    let world = World::new();
    let (receipt, notice) = world.posted_through_sender();
    world.post(SENDER, &world.receiver().address, &notice, 1);
    world.drain(world.receiver());
    assert!(world.report_shown(receipt.tx_id).is_some());
    let ahead = world
        .receiver()
        .clock
        .now()
        .checked_add(jiff::SignedDuration::from_mins(10))
        .unwrap();

    world
        .receiver()
        .store()
        .write(|repos| {
            let mut marks = repos.tx_marks(receipt.tx_id)?;
            marks.sender_posted_at = Some(ahead);
            repos.put_tx_marks(receipt.tx_id, &marks)
        })
        .unwrap();

    assert_eq!(world.report_shown(receipt.tx_id), None);
}

/// The host forgets keys not heard from for 180 days; one heard from a day later stays, and a
/// forgotten key is unknown again.
#[test]
fn forget_peers_drops_keys_older_than_the_limit() {
    let world = World::new();
    let day = jiff::SignedDuration::from_hours(24);
    let now = world.sender().clock.now();
    let old = World::address_of(SENDER);
    let recent = World::address_of(STRANGER);
    proven_at(world.sender(), &old.key_text(), now - day * 181);
    proven_at(world.sender(), &recent.key_text(), now - day * 179);

    let forgotten = world
        .sender()
        .wallet
        .forget_peers(Duration::from_secs(180 * 24 * 60 * 60))
        .unwrap();

    assert_eq!(forgotten, 1);
    assert_eq!(world.sender().peer_compat(&old.key_text()), None);
    assert!(world.sender().peer_compat(&recent.key_text()).is_some());
    let facts = world.sender().wallet.peer_compat(&old.to_string()).unwrap();
    assert_eq!(facts.kind, PeerKind::Unknown);
    assert!(!facts.notices);
}
