// SPDX-License-Identifier: Apache-2.0
//! The `cancelled` notice for ordinary sends over Epicbox on the mock relay (ADR 0016): the
//! sender of a payment whose receiver answered tells the receiver once it cancelled or released
//! the send, at the cancel when it finalized the answer, and otherwise in answer to the late
//! S2. The receiver keeps that report only from the payment's real sender, for a payment it
//! answered, once per payment and while the payment waits, and changes nothing else.
//!
//! The payer of `World` sends and the issuer receives. Where a test needs to speak as one
//! side, the other side talks to the peer key 7, whose messages the test reads and writes.

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

use lepic_epicbox::marker::v3::carries_lepic_marker;
use lepic_epicbox::{EpicboxAddress, EpicboxClient, TRANSPORT_ID};
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::Amount;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::SlateId;
use lepic_store::{PeerCompat, SlateStage, TxDirection, TxId, TxState, WalletStore};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::event::CancelledPayment;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::notice::{Notice, NoticeKind, Payload, classify_text};
use lepic_wallet::peer_compat::PeerKind;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Clock, Event};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

/// The peer key that stands for the other side of the payment.
const PEER: u8 = 7;
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

fn cancelled_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentCancelled(_)))
        .collect()
}

fn cancelled_text(slate_id: SlateId) -> String {
    let wire = Notice {
        slate_id,
        kind: NoticeKind::Cancelled,
    }
    .encode();
    wire.as_text().unwrap().to_owned()
}

fn is_cancelled_notice(text: &str, slate_id: SlateId) -> bool {
    classify_text(text)
        == Payload::Notice(Notice {
            slate_id,
            kind: NoticeKind::Cancelled,
        })
}

/// `json` as a stock wallet writes it back: without the marker.
fn unmarked(json: &str) -> String {
    assert!(json.contains(&marker()), "no marker in {json}");
    json.replace(&marker(), "")
}

fn wire(json: &str) -> WireSlate {
    WireSlate::text(MediaType::JSON, json.to_owned())
}

/// A payment the receiver answered to the peer key [`PEER`], which stands for its sender.
struct Receipt {
    slate_id: SlateId,
    /// The receiver's transaction.
    tx_id: TxId,
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
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
    }

    fn cancel(&self, party: &Party, tx_id: TxId) {
        self.block_on(party.wallet.cancel(tx_id)).unwrap();
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

    fn incoming(&self, slate_id: SlateId) -> TxId {
        self.receiver()
            .read(|repos| repos.transaction_by_slate(uuid(slate_id), TxDirection::Incoming))
            .unwrap()
            .id
    }

    /// The payer sends to [`PEER`], which hands the S1 on to the receiver as `forward` writes
    /// it; the receiver answers to [`PEER`]. Returns the receipt and the S2.
    fn receipt_through_peer(&self, forward: impl FnOnce(String) -> String) -> (Receipt, String) {
        let peer = self.peer_client(PEER);
        let sent = self.send_to(&World::address_of(PEER));
        let s1 = self.only_message(&peer);
        self.post(PEER, &self.receiver().address, &forward(s1), 1);
        assert_eq!(self.drain(self.receiver()).received, 1);
        let s2 = self.only_message(&peer);
        let receipt = Receipt {
            slate_id: sent.slate_id,
            tx_id: self.incoming(sent.slate_id),
        };
        (receipt, s2)
    }

    fn receiver_state(&self, tx_id: TxId) -> TxState {
        self.receiver()
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .state
    }

    fn report_shown(&self, tx_id: TxId) -> Option<jiff::Timestamp> {
        self.block_on(self.receiver().wallet.transaction_details(tx_id))
            .unwrap()
            .sender_reported_cancelled_at
    }

    fn cancel_answered(&self, tx_id: TxId) -> bool {
        self.sender()
            .read(|repos| repos.tx_marks(tx_id))
            .cancelled_answered
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
fn a_send_cancelled_after_its_answer_was_finalized_tells_the_receiver() {
    let world = World::new();
    let mut receiver_events = world.receiver().wallet.subscribe();
    let sent = world.send_to(&world.receiver().address);
    assert_eq!(world.drain(world.receiver()).received, 1);
    let tx_id = world.incoming(sent.slate_id);
    // The sender finalizes the answer, and the node does not take the transaction.
    world
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    assert_eq!(world.drain(world.sender()).finalized, 1);
    assert!(world.node.pushed_transactions().is_empty());

    world.cancel(world.sender(), sent.tx_id);
    assert!(world.cancel_answered(sent.tx_id));
    let summary = world.drain(world.receiver());

    assert_eq!(
        summary,
        InboxSummary {
            notices: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        cancelled_events(&mut receiver_events),
        vec![Event::PaymentCancelled(CancelledPayment {
            tx_id,
            slate_id: sent.slate_id,
        })]
    );
    // Advisory: the payment still waits, holding what it held.
    assert_eq!(world.receiver_state(tx_id), TxState::Received);
    assert_eq!(
        world.report_shown(tx_id),
        Some(world.receiver().clock.now())
    );
}

#[test]
fn a_late_answer_to_a_cancelled_send_is_answered_with_cancelled_once() {
    let world = World::new();
    let mut receiver_events = world.receiver().wallet.subscribe();
    let sent = world.send_to(&world.receiver().address);
    // The sender cancels before the receiver answered: nothing is due yet.
    world.cancel(world.sender(), sent.tx_id);
    assert!(!world.cancel_answered(sent.tx_id));
    assert_eq!(world.drain(world.receiver()).received, 1);
    let tx_id = world.incoming(sent.slate_id);
    assert_eq!(world.receiver_state(tx_id), TxState::Received);

    let summary = world.drain(world.sender());

    assert_eq!((summary.rejected, summary.held), (1, 0), "{summary:?}");
    assert!(world.cancel_answered(sent.tx_id));
    assert_eq!(world.drain(world.receiver()).notices, 1);
    assert_eq!(
        cancelled_events(&mut receiver_events),
        vec![Event::PaymentCancelled(CancelledPayment {
            tx_id,
            slate_id: sent.slate_id,
        })]
    );
    assert!(world.report_shown(tx_id).is_some());
    assert_eq!(world.receiver_state(tx_id), TxState::Received);
    // The late answer was never finalized or posted.
    assert!(world.node.pushed_transactions().is_empty());
}

#[test]
fn an_answer_left_on_the_relay_over_a_cancel_brings_the_receiver_the_notice() {
    let world = World::new();
    let mut receiver_events = world.receiver().wallet.subscribe();
    // The sender's listener is off: the receiver's answer waits on the relay.
    let sent = world.send_to(&world.receiver().address);
    assert_eq!(world.drain(world.receiver()).received, 1);
    let tx_id = world.incoming(sent.slate_id);

    world.cancel(world.sender(), sent.tx_id);
    assert!(!world.cancel_answered(sent.tx_id));
    // The sender's listener starts and reads the answer for the cancelled send.
    let summary = world.drain(world.sender());

    assert_eq!((summary.finalized, summary.rejected), (0, 1), "{summary:?}");
    assert!(world.node.pushed_transactions().is_empty());
    let sender_state = world
        .sender()
        .read(|repos| repos.transaction(sent.tx_id))
        .unwrap()
        .state;
    assert_eq!(sender_state, TxState::Cancelled);
    assert_eq!(world.drain(world.receiver()).notices, 1);
    assert_eq!(
        cancelled_events(&mut receiver_events),
        vec![Event::PaymentCancelled(CancelledPayment {
            tx_id,
            slate_id: sent.slate_id,
        })]
    );
    assert_eq!(world.receiver_state(tx_id), TxState::Received);
}

#[test]
fn a_repeated_late_answer_sends_nothing_more() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    let sent = world.send_to(&World::address_of(PEER));
    let s1 = world.only_message(&peer);
    world.cancel(world.sender(), sent.tx_id);
    // The receiver answers the forwarded S1 to the peer key, which hands the answer back.
    world.post(PEER, &world.receiver().address, &s1, 1);
    assert_eq!(world.drain(world.receiver()).received, 1);
    let s2 = world.only_message(&peer);
    assert!(carries_lepic_marker(&wire(&s2)));

    world.post(PEER, &world.sender().address, &s2, 2);
    world.drain(world.sender());
    world.post(PEER, &world.sender().address, &s2, 1);
    world.drain(world.sender());

    let told = world.drain_peer(&peer);
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(is_cancelled_notice(&told[0], sent.slate_id));
    let key = World::address_of(PEER).key_text();
    assert_eq!(world.sender().peer_kind(&key), Some(PeerKind::Lepic));
}

/// The receiver's key ran LEPIC lately, but the answer to this send came unmarked: another
/// wallet on that key may be the one waiting, so the cancel tells nobody.
#[test]
fn a_cancel_after_an_unmarked_answer_sends_no_cancelled() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    let key = World::address_of(PEER).key_text();
    world
        .sender()
        .store()
        .write(|repos| {
            repos.put_peer_compat(
                &key,
                &PeerCompat {
                    last_marked_at: Some(world.sender().clock.now()),
                    ..PeerCompat::default()
                },
            )
        })
        .unwrap();
    let (receipt, s2) = world.receipt_through_peer(|s1| s1);
    world
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    world.post(PEER, &world.sender().address, &unmarked(&s2), 1);
    assert_eq!(world.drain(world.sender()).finalized, 1);
    let sent = world
        .sender()
        .read(|repos| repos.transaction_by_slate(uuid(receipt.slate_id), TxDirection::Outgoing))
        .unwrap();
    assert!(
        !world
            .sender()
            .read(|repos| repos.tx_marks(sent.id))
            .answer_marked
    );

    world.cancel(world.sender(), sent.id);

    assert!(world.drain_peer(&peer).is_empty());
    assert!(!world.cancel_answered(sent.id));
}

#[test]
fn a_send_cancelled_before_any_answer_sends_nothing() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    // Even a receiver proven to run LEPIC is told only once it answered.
    let key = World::address_of(PEER).key_text();
    world
        .sender()
        .store()
        .write(|repos| {
            repos.put_peer_compat(
                &key,
                &PeerCompat {
                    last_marked_at: Some(world.sender().clock.now()),
                    ..PeerCompat::default()
                },
            )
        })
        .unwrap();
    let sent = world.send_to(&World::address_of(PEER));
    let s1 = world.only_message(&peer);

    world.cancel(world.sender(), sent.tx_id);

    assert!(carries_lepic_marker(&wire(&s1)));
    assert!(world.drain_peer(&peer).is_empty());
    assert!(!world.cancel_answered(sent.tx_id));
}

#[test]
fn an_unmarked_late_answer_gets_no_notice() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    let sent = world.send_to(&World::address_of(PEER));
    let s1 = world.only_message(&peer);
    world.cancel(world.sender(), sent.tx_id);
    // A stock receiver answers without the marker.
    world.post(PEER, &world.receiver().address, &unmarked(&s1), 1);
    assert_eq!(world.drain(world.receiver()).received, 1);
    let s2 = world.only_message(&peer);
    assert!(!carries_lepic_marker(&wire(&s2)));

    world.post(PEER, &world.sender().address, &s2, 1);
    let summary = world.drain(world.sender());

    assert_eq!(summary.rejected, 1);
    assert!(world.drain_peer(&peer).is_empty());
    assert!(!world.cancel_answered(sent.tx_id));
}

#[test]
fn a_late_answer_from_another_key_gets_no_notice() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    let sent = world.send_to(&World::address_of(PEER));
    let s1 = world.only_message(&peer);
    world.cancel(world.sender(), sent.tx_id);
    world.post(PEER, &world.receiver().address, &s1, 1);
    world.drain(world.receiver());
    let s2 = world.only_message(&peer);

    world.post(STRANGER, &world.sender().address, &s2, 1);
    world.drain(world.sender());

    for byte in [PEER, STRANGER] {
        assert!(
            world.drain_peer(&world.peer_client(byte)).is_empty(),
            "{byte}"
        );
    }
    assert!(!world.cancel_answered(sent.tx_id));
}

#[test]
fn a_cancelled_notice_from_another_key_is_dropped() {
    let world = World::new();
    let (receipt, _) = world.receipt_through_peer(|s1| s1);
    let mut receiver_events = world.receiver().wallet.subscribe();

    world.post(
        STRANGER,
        &world.receiver().address,
        &cancelled_text(receipt.slate_id),
        1,
    );
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 1));
    assert!(cancelled_events(&mut receiver_events).is_empty());
    assert_eq!(world.report_shown(receipt.tx_id), None);
    let stranger = World::address_of(STRANGER).key_text();
    assert!(world.receiver().peer_kind(&stranger).is_none());

    // The same notice from the payment's sender is taken.
    world.post(
        PEER,
        &world.receiver().address,
        &cancelled_text(receipt.slate_id),
        1,
    );
    assert_eq!(world.drain(world.receiver()).notices, 1);
    assert_eq!(cancelled_events(&mut receiver_events).len(), 1);
}

#[test]
fn a_cancelled_notice_for_an_unknown_or_unanswered_slate_is_dropped() {
    let world = World::new();
    let peer = world.peer_client(PEER);
    let sent = world.send_to(&World::address_of(PEER));
    let s1 = world.only_message(&peer);
    let mut receiver_events = world.receiver().wallet.subscribe();

    // Before the receiver holds the slate at all, and for a slate id nobody used.
    world.post(
        PEER,
        &world.receiver().address,
        &cancelled_text(sent.slate_id),
        1,
    );
    world.post(
        PEER,
        &world.receiver().address,
        &cancelled_text(SlateId::from_bytes([0x42; 16])),
        1,
    );
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 2));
    assert!(cancelled_events(&mut receiver_events).is_empty());
    // The payment itself is still received normally afterwards.
    world.post(PEER, &world.receiver().address, &s1, 1);
    assert_eq!(world.drain(world.receiver()).received, 1);
    assert_eq!(world.report_shown(world.incoming(sent.slate_id)), None);
}

#[test]
fn a_cancelled_notice_for_an_invoice_this_wallet_issued_is_dropped() {
    let world = World::new();
    let issued = world.issue_to(&World::address_of(PEER), None);
    let mut receiver_events = world.receiver().wallet.subscribe();

    world.post(
        PEER,
        &world.receiver().address,
        &cancelled_text(issued.slate_id),
        1,
    );
    let summary = world.drain(world.receiver());

    assert_eq!((summary.notices, summary.dropped), (0, 1));
    assert!(cancelled_events(&mut receiver_events).is_empty());
    assert_eq!(world.report_shown(issued.tx_id), None);
}

#[test]
fn a_replayed_cancelled_notice_raises_one_event_and_keeps_the_first_time() {
    let world = World::new();
    let (receipt, _) = world.receipt_through_peer(|s1| s1);
    let mut receiver_events = world.receiver().wallet.subscribe();
    let notice = cancelled_text(receipt.slate_id);

    world.post(PEER, &world.receiver().address, &notice, 3);
    let first = world.drain(world.receiver());
    let at = world.receiver().clock.now();
    world.receiver().clock.advance(Duration::from_secs(10 * 60));
    world.post(PEER, &world.receiver().address, &notice, 1);
    let second = world.drain(world.receiver());

    assert_eq!((first.notices, second.notices), (3, 1));
    assert_eq!(cancelled_events(&mut receiver_events).len(), 1);
    assert_eq!(world.report_shown(receipt.tx_id), Some(at));
    // No window: the report stays while the payment is not confirmed.
    world
        .receiver()
        .clock
        .advance(Duration::from_secs(48 * 3_600));
    assert_eq!(world.report_shown(receipt.tx_id), Some(at));
}

#[test]
fn a_cancelled_notice_after_the_payment_confirmed_or_ended_is_only_noted() {
    for end in [TxState::Confirmed, TxState::Cancelled, TxState::Expired] {
        let world = World::new();
        let (receipt, _) = world.receipt_through_peer(|s1| s1);
        world.set_receiver_transaction(receipt.tx_id, |entry| entry.state = end);
        let mut receiver_events = world.receiver().wallet.subscribe();

        world.post(
            PEER,
            &world.receiver().address,
            &cancelled_text(receipt.slate_id),
            1,
        );
        let summary = world.drain(world.receiver());

        assert_eq!((summary.notices, summary.dropped), (1, 0), "{end:?}");
        assert!(cancelled_events(&mut receiver_events).is_empty(), "{end:?}");
        assert_eq!(world.report_shown(receipt.tx_id), None, "{end:?}");
        assert_eq!(world.receiver_state(receipt.tx_id), end);
    }
}

#[test]
fn the_report_is_cleared_once_the_payment_confirmed() {
    let world = World::new();
    let (receipt, _) = world.receipt_through_peer(|s1| s1);
    world.post(
        PEER,
        &world.receiver().address,
        &cancelled_text(receipt.slate_id),
        1,
    );
    world.drain(world.receiver());
    assert!(world.report_shown(receipt.tx_id).is_some());

    world.set_receiver_transaction(receipt.tx_id, |entry| entry.state = TxState::Confirmed);

    assert_eq!(world.report_shown(receipt.tx_id), None);
}

#[test]
fn the_receivers_own_cancel_after_the_report_keeps_its_rules() {
    let world = World::new();
    let (receipt, _) = world.receipt_through_peer(|s1| s1);
    world.post(
        PEER,
        &world.receiver().address,
        &cancelled_text(receipt.slate_id),
        1,
    );
    world.drain(world.receiver());
    let reported = world.report_shown(receipt.tx_id);

    // A node that cannot be asked refuses the cancel, as without the report.
    let s2 = world
        .receiver()
        .read(|repos| repos.slate(uuid(receipt.slate_id), SlateStage::Standard2));
    assert!(s2.is_some());
    world
        .node
        .fail_next("get_unconfirmed_transactions", MockFailure::Unreachable);
    assert!(
        world
            .block_on(world.receiver().wallet.cancel(receipt.tx_id))
            .is_err()
    );
    assert_eq!(world.receiver_state(receipt.tx_id), TxState::Received);

    world.cancel(world.receiver(), receipt.tx_id);

    assert_eq!(world.receiver_state(receipt.tx_id), TxState::Cancelled);
    // The kernel stays watched, so a late post by the sender still confirms the payment.
    assert!(
        world
            .receiver()
            .read(|repos| repos.tx_watch(receipt.tx_id))
            .is_some()
    );
    assert_eq!(world.report_shown(receipt.tx_id), reported);
}
