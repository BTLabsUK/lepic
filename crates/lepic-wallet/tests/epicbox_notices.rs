// SPDX-License-Identifier: Apache-2.0
//! Notices between LEPIC wallets over Epicbox on the mock relay (ADR 0016): the payer hears
//! that its payment was posted or the invoice withdrawn, also from an issuer that withdrew it
//! offline and answers the payment once it arrives, the issuer hears a decline, notices
//! from anyone but the counterparty of their slate are dropped, and no notice is ever posted to
//! a peer that has not proved it runs LEPIC.

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

use lepic_epicbox::EpicboxClient;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, EncodeContext};
use lepic_slate::model::SlateId;
use lepic_store::{PendingInvoiceStatus, TxDirection, TxState};
use lepic_transport::transport::Inbound;
use lepic_wallet::Event;
use lepic_wallet::event::{DeclinedInvoice, PostedInvoice, WithdrawnInvoice};
use lepic_wallet::inbox::{InboxSummary, ListenHandle};
use lepic_wallet::invoice::{IssuedInvoice, PaidInvoice};
use lepic_wallet::notice::{MAX_NOTICE_LEN, Notice, NoticeKind, Payload, classify_text};
use lepic_wallet::peer_compat::PeerKind;
use std::time::Duration;
use tokio::sync::broadcast::Receiver;

use uuid::Uuid;
use world::{World, pay_request};

/// Tries of a held message in one listen, as the inbox bounds them.
const MAX_HOLD_ATTEMPTS: usize = 3;

/// How long a drain holds a message after it first arrived, as the inbox bounds it.
const HOLD_PATIENCE: Duration = Duration::from_secs(3 * 60);

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok()).collect()
}

fn notice_events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    events(receiver)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                Event::InvoicePosted(_) | Event::InvoiceDeclined(_) | Event::InvoiceWithdrawn(_)
            )
        })
        .collect()
}

fn notice(kind: &str, slate_id: SlateId) -> String {
    format!(r#"{{"lepic":1,"type":"{kind}","slate_id":"{slate_id}"}}"#)
}

impl World {
    /// Parks the invoices waiting for the payer, then drains its payments address, where the
    /// issuer's notices arrive.
    fn drain_payer_invoices(&self) -> InboxSummary {
        let parked = self.deliver_invoices();
        let mut summary = self
            .block_on(self.payer.wallet.epicbox_drain(&self.payer.epicbox))
            .unwrap();
        summary.parked = u32::try_from(parked).unwrap();
        world::add(self.take_carried(), summary)
    }

    fn drain_issuer(&self) -> InboxSummary {
        self.block_on(self.issuer.wallet.epicbox_drain(&self.issuer.epicbox))
            .unwrap()
    }

    fn pay(&self, issued: &IssuedInvoice) -> PaidInvoice {
        self.block_on(
            self.payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap()
    }

    /// An invoice issued, parked, paid, finalized and posted, after which each side holds
    /// proof that the other runs LEPIC.
    fn settle_one_invoice(&self) -> (IssuedInvoice, PaidInvoice) {
        let issued = self.issue(None);
        let paid = self.pay(&issued);
        assert_eq!(self.drain_issuer().finalized, 1);
        (issued, paid)
    }

    fn listen_issuer_until_empty(&self) -> InboxSummary {
        let handle = ListenHandle::new();
        self.block_on(async {
            let listen = self
                .issuer
                .wallet
                .epicbox_listen(&self.issuer.epicbox, &handle);
            let script = async {
                self.within(
                    self.relay
                        .wait_until(|relay| relay.pending(&self.issuer.address) == 0),
                )
                .await;
                handle.stop();
            };
            tokio::join!(listen, script).0
        })
        .unwrap()
    }

    /// Whether the issuer recorded that the payer of the withdrawn invoice `slate_id` was told.
    fn withdrawn_answered(&self, slate_id: SlateId) -> bool {
        self.issuer.read(|repos| {
            let Some(stored) = repos.transaction_by_slate(uuid(slate_id), TxDirection::Incoming)?
            else {
                return Ok(false);
            };
            Ok(repos.tx_marks(stored.id)?.withdrawn_answered)
        })
    }

    fn issuer_capability(&self, key: &str) -> Option<PeerKind> {
        self.issuer.peer_kind(key)
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

    /// The issuer's I1 as `peer` received it, written again without the marker, as a stock
    /// wallet would write it.
    fn unmarked_i1(&self, peer: &EpicboxClient) -> String {
        let received = self.drain_peer(peer);
        assert_eq!(received.len(), 1);
        unmarked(&received[0])
    }

    /// The issuer invoices `peer`, which forwards the I1 unmarked under its own key to the
    /// payer, where it is parked; the payer pays it to `peer`. Returns the
    /// invoice, the payment and the I2 as `peer` received it.
    fn pay_through(&self, peer: &EpicboxClient, byte: u8) -> (IssuedInvoice, PaidInvoice, String) {
        let issued = self.issue_to(peer.address(), None);
        let i1 = self.unmarked_i1(peer);
        self.post(byte, &self.payer.address, &i1, 1);
        assert_eq!(self.drain_payer_invoices().parked, 1);
        let paid = self.pay(&issued);
        let received = self.drain_peer(peer);
        assert_eq!(received.len(), 1);
        (issued, paid, received[0].clone())
    }
}

/// `json`, a V3 slate, written again without the marker, as a stock wallet would write it.
fn unmarked(json: &str) -> String {
    let codec = V3JsonCodec::new(
        lepic_primitives::params::Network::Floonet
            .params()
            .default_base_fee(),
    );
    let wire =
        lepic_wallet::slate::WireSlate::text(lepic_wallet::slate::MediaType::JSON, json.to_owned());
    let slate = codec.decode(&wire).unwrap();
    codec
        .encode(
            &slate,
            &EncodeContext {
                block_header_version: 6,
            },
        )
        .unwrap()
        .as_text()
        .unwrap()
        .to_owned()
}

#[test]
fn the_payer_receives_posted_with_the_kernel_excess() {
    let world = World::new();
    let mut payer_events = world.payer.wallet.subscribe();
    let (issued, paid) = world.settle_one_invoice();
    let pushed = world.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    let excess = pushed[0].kernels()[0].excess;
    // The marked payment proved the payer's key.
    let payments = world.payer.address.key_text();
    assert_eq!(world.issuer_capability(&payments), Some(PeerKind::Lepic));
    let _ = events(&mut payer_events);

    let summary = world.drain_payer_invoices();

    assert_eq!(
        summary,
        InboxSummary {
            notices: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert_eq!(
        notice_events(&mut payer_events),
        vec![Event::InvoicePosted(PostedInvoice {
            tx_id: paid.tx_id,
            slate_id: issued.slate_id,
            excess,
        })]
    );
    // Advisory: the payment waits for a refresh to see the kernel.
    let state = world
        .payer
        .read(|repos| repos.transaction(paid.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Sent);
}

#[test]
fn an_unpaid_payer_receives_withdrawn_for_a_cancelled_invoice() {
    let world = World::new();
    world.settle_one_invoice();
    let issued = world.issue(None);
    let summary = world.drain_payer_invoices();
    assert_eq!(summary.notices, 1);
    let mut payer_events = world.payer.wallet.subscribe();

    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();
    let summary = world.drain_payer_invoices();

    assert_eq!(
        summary,
        InboxSummary {
            notices: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        notice_events(&mut payer_events),
        vec![Event::InvoiceWithdrawn(WithdrawnInvoice {
            slate_id: issued.slate_id,
            tx_id: None,
        })]
    );
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoice(uuid(issued.slate_id)))
            .is_none()
    );
}

#[test]
fn a_withdrawn_paid_invoice_raises_an_event_and_moves_nothing() {
    let world = World::new();
    world.settle_one_invoice();
    // The first payment locked the only output; a second one pays this time.
    world.payer.fund(10, world::FUNDING);
    let issued = world.issue(None);
    world.drain_payer_invoices();
    let paid = world.pay(&issued);
    let locked_before = world
        .payer
        .read(|repos| repos.outputs_of_transaction(paid.tx_id));
    let mut payer_events = world.payer.wallet.subscribe();

    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();
    let summary = world.drain_payer_invoices();

    assert_eq!(summary.notices, 1);
    assert_eq!(
        notice_events(&mut payer_events),
        vec![Event::InvoiceWithdrawn(WithdrawnInvoice {
            slate_id: issued.slate_id,
            tx_id: Some(paid.tx_id),
        })]
    );
    let state = world
        .payer
        .read(|repos| repos.transaction(paid.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Sent);
    assert_eq!(
        world
            .payer
            .read(|repos| repos.outputs_of_transaction(paid.tx_id)),
        locked_before
    );
    assert_eq!(
        world
            .payer
            .read(|repos| repos.pending_invoice(uuid(issued.slate_id)))
            .unwrap()
            .status,
        PendingInvoiceStatus::Paid
    );
}

#[test]
fn a_payment_of_an_invoice_withdrawn_offline_is_answered_with_withdrawn() {
    let world = World::new();
    world.settle_one_invoice();
    world.payer.fund(10, world::FUNDING);
    let issued = world.issue(None);
    world.drain_payer_invoices();
    let paid = world.pay(&issued);
    // The issuer withdraws while it cannot reach the relay: its notice is lost.
    world.relay.set_refusing(true);
    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();
    world.relay.set_refusing(false);
    assert_eq!(world.drain_payer_invoices().notices, 0);
    let mut payer_events = world.payer.wallet.subscribe();

    let summary = world.drain_issuer();
    let payer_summary = world.drain_payer_invoices();

    assert_eq!((summary.finalized, summary.rejected), (0, 1));
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(payer_summary.notices, 1);
    assert_eq!(
        notice_events(&mut payer_events),
        vec![Event::InvoiceWithdrawn(WithdrawnInvoice {
            slate_id: issued.slate_id,
            tx_id: Some(paid.tx_id),
        })]
    );
}

#[test]
fn a_payment_of_a_withdrawn_invoice_is_kept_while_its_answer_fails() {
    let world = World::new();
    world.settle_one_invoice();
    world.payer.fund(10, world::FUNDING);
    let issued = world.issue(None);
    world.drain_payer_invoices();
    world.pay(&issued);
    world.relay.set_refusing(true);
    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();
    world.relay.set_refusing(false);
    world.issuer.set_deliveries_failing(true);

    let summary = world.drain_issuer();

    assert_eq!(
        (summary.finalized, summary.rejected, summary.held),
        (0, 0, 1)
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 1);
}

#[test]
fn a_withdrawn_answer_the_relay_refuses_settles_the_payment_at_once() {
    let world = World::new();
    let issued = withdrawn_offline_with_a_message_behind(&world);
    world.relay.set_post_refused(&world.payer.address);

    let summary = world.drain_issuer();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert!(!world.withdrawn_answered(issued.slate_id));
}

/// The payer pays an invoice that the issuer then withdraws while it cannot reach the relay, and
/// a message the issuer can handle is queued behind the payment. Returns the invoice.
fn withdrawn_offline_with_a_message_behind(world: &World) -> IssuedInvoice {
    world.settle_one_invoice();
    world.payer.fund(10, world::FUNDING);
    let issued = world.issue(None);
    world.drain_payer_invoices();
    world.pay(&issued);
    world.relay.set_refusing(true);
    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();
    world.relay.set_refusing(false);
    world.post(
        9,
        &world.issuer.address,
        &notice("thanks", issued.slate_id),
        1,
    );
    issued
}

fn deliveries_to(world: &World, address: &lepic_epicbox::EpicboxAddress) -> usize {
    let address = address.to_string();
    world
        .issuer
        .delivered_to()
        .iter()
        .filter(|to| **to == address)
        .count()
}

#[test]
fn a_listen_gives_up_an_undeliverable_withdrawn_answer_at_the_hold_bound() {
    let world = World::new();
    let issued = withdrawn_offline_with_a_message_behind(&world);
    let invoiced = world.payer.address.clone();
    let before = deliveries_to(&world, &invoiced);
    world.issuer.set_deliveries_failing(true);

    let summary = world.listen_issuer_until_empty();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(deliveries_to(&world, &invoiced) - before, MAX_HOLD_ATTEMPTS);
    assert!(!world.withdrawn_answered(issued.slate_id));
}

#[test]
fn a_drain_gives_up_an_undeliverable_withdrawn_answer_after_the_hold_patience() {
    let world = World::new();
    let issued = withdrawn_offline_with_a_message_behind(&world);
    world.issuer.set_deliveries_failing(true);

    let held = world.drain_issuer();
    world
        .issuer
        .clock
        .advance(HOLD_PATIENCE - Duration::from_secs(1));
    let still_held = world.drain_issuer();
    world.issuer.clock.advance(Duration::from_secs(1));
    let settled = world.drain_issuer();

    for summary in [held, still_held] {
        assert_eq!(
            summary,
            InboxSummary {
                held: 1,
                ..InboxSummary::default()
            }
        );
    }
    assert_eq!(
        settled,
        InboxSummary {
            rejected: 1,
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert!(!world.withdrawn_answered(issued.slate_id));
}

#[test]
fn a_payment_repeated_after_its_answer_was_given_up_is_answered() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, i2) = withdrawn_offline_through(&world, &peer);
    world.issuer.set_deliveries_failing(true);
    world.post(9, &world.issuer.address, &i2, 1);
    assert_eq!(world.drain_issuer().held, 1);
    world.issuer.clock.advance(HOLD_PATIENCE);
    assert_eq!(world.drain_issuer().rejected, 1);
    assert!(world.drain_peer(&peer).is_empty());
    assert!(!world.withdrawn_answered(issued.slate_id));

    world.issuer.set_deliveries_failing(false);
    world.post(9, &world.issuer.address, &i2, 1);
    let summary = world.drain_issuer();

    assert_eq!(summary.rejected, 1);
    assert_eq!(
        world
            .drain_peer(&peer)
            .iter()
            .map(|text| classify_text(text))
            .collect::<Vec<_>>(),
        vec![Payload::Notice(Notice {
            slate_id: issued.slate_id,
            kind: NoticeKind::Withdrawn,
        })]
    );
    assert!(world.withdrawn_answered(issued.slate_id));
}

/// The issuer invoices `peer` and withdraws it while it cannot reach the relay, after the payer
/// paid it to `peer`. Returns the invoice and the marked I2 as `peer` received it.
fn withdrawn_offline_through(world: &World, peer: &EpicboxClient) -> (IssuedInvoice, String) {
    let (issued, _, i2) = world.pay_through(peer, 9);
    world.relay.set_refusing(true);
    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();
    world.relay.set_refusing(false);
    (issued, i2)
}

#[test]
fn a_repeated_payment_of_a_withdrawn_invoice_is_answered_once() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, i2) = withdrawn_offline_through(&world, &peer);

    world.post(9, &world.issuer.address, &i2, 3);
    let summary = world.drain_issuer();

    assert_eq!(summary.rejected, 3);
    let received = world.drain_peer(&peer);
    assert_eq!(
        received
            .iter()
            .map(|text| classify_text(text))
            .collect::<Vec<_>>(),
        vec![Payload::Notice(Notice {
            slate_id: issued.slate_id,
            kind: NoticeKind::Withdrawn,
        })]
    );
}

#[test]
fn a_payment_of_a_withdrawn_invoice_proves_only_the_invoiced_key() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, i2) = withdrawn_offline_through(&world, &peer);

    world.post(8, &world.issuer.address, &i2, 1);
    let summary = world.drain_issuer();

    assert_eq!(summary.rejected, 1);
    assert_eq!(world.drain_peer(&peer).len(), 1);
    let sender = World::address_of(8).key_text();
    assert_eq!(world.issuer_capability(&sender), None);
    let invoiced = World::address_of(9).key_text();
    assert_eq!(world.issuer_capability(&invoiced), Some(PeerKind::Lepic));
    assert!(world.withdrawn_answered(issued.slate_id));
}

#[test]
fn a_payment_whose_payer_signature_fails_gets_no_withdrawn() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, i2) = withdrawn_offline_through(&world, &peer);
    let mut slate: serde_json::Value = serde_json::from_str(&i2).unwrap();
    let participants = slate["participant_data"].as_array_mut().unwrap();
    let signed = participants
        .iter()
        .position(|participant| !participant["part_sig"].is_null())
        .unwrap();
    let other_nonce = participants[1 - signed]["public_nonce"].clone();
    participants[signed]["public_nonce"] = other_nonce;

    world.post(9, &world.issuer.address, &slate.to_string(), 1);
    let summary = world.drain_issuer();

    assert_eq!(summary.rejected, 1);
    assert!(world.drain_peer(&peer).is_empty());
    assert!(!world.withdrawn_answered(issued.slate_id));
    let invoiced = World::address_of(9).key_text();
    assert_eq!(world.issuer_capability(&invoiced), None);
}

#[test]
fn a_payment_of_another_amount_gets_no_withdrawn() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (_, i2) = withdrawn_offline_through(&world, &peer);
    let mut slate: serde_json::Value = serde_json::from_str(&i2).unwrap();
    slate["amount"] = serde_json::Value::String((world::AMOUNT + 1).to_string());

    world.post(9, &world.issuer.address, &slate.to_string(), 1);
    let summary = world.drain_issuer();

    assert_eq!(summary.rejected, 1);
    assert!(world.drain_peer(&peer).is_empty());
}

#[test]
fn the_issuer_hears_a_decline_from_the_invoiced_address() {
    let world = World::new();
    let issued = world.issue(None);
    world.drain_payer_invoices();
    let mut issuer_events = world.issuer.wallet.subscribe();

    world
        .block_on(world.payer.wallet.decline_invoice(issued.slate_id))
        .unwrap();
    let summary = world.drain_issuer();

    assert_eq!(
        summary,
        InboxSummary {
            notices: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        notice_events(&mut issuer_events),
        vec![Event::InvoiceDeclined(DeclinedInvoice {
            tx_id: issued.tx_id,
            slate_id: issued.slate_id,
        })]
    );
    // Advisory: the invoice stays open until the user cancels it or it expires.
    let state = world
        .issuer
        .read(|repos| repos.transaction(issued.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Received);
    let invoiced = world.payer.address.clone().key_text();
    assert_eq!(world.issuer_capability(&invoiced), Some(PeerKind::Lepic));
}

#[test]
fn a_decline_after_the_invoice_was_finalized_raises_no_event() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, _, i2) = world.pay_through(&peer, 9);
    world.post(9, &world.issuer.address, &i2, 1);
    assert_eq!(world.drain_issuer().finalized, 1);
    let mut issuer_events = world.issuer.wallet.subscribe();
    world.post(
        9,
        &world.issuer.address,
        &notice("declined", issued.slate_id),
        1,
    );

    let summary = world.drain_issuer();

    assert_eq!(summary.notices, 1);
    assert!(notice_events(&mut issuer_events).is_empty());
    let state = world
        .issuer
        .read(|repos| repos.transaction(issued.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Posted);
}

#[test]
fn a_peer_proven_by_its_notice_is_sent_withdrawn() {
    let world = World::new();
    let peer = world.peer_client(9);
    let issued = world.issue_to(peer.address(), None);
    world.drain_peer(&peer);
    world.post(
        9,
        &world.issuer.address,
        &notice("declined", issued.slate_id),
        1,
    );
    assert_eq!(world.drain_issuer().notices, 1);

    world
        .block_on(world.issuer.wallet.cancel(issued.tx_id))
        .unwrap();

    let received = world.drain_peer(&peer);
    assert_eq!(received.len(), 1);
    assert_eq!(
        classify_text(&received[0]),
        Payload::Notice(Notice {
            slate_id: issued.slate_id,
            kind: NoticeKind::Withdrawn,
        })
    );
}

#[test]
fn a_notice_from_another_key_is_dropped() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let peer = world.peer_client(9);
    let issued = world.issue_to(peer.address(), None);
    world.post(
        8,
        &world.issuer.address,
        &notice("declined", issued.slate_id),
        1,
    );

    let summary = world.drain_issuer();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert!(notice_events(&mut issuer_events).is_empty());
    let key = World::address_of(8).key_text();
    assert_eq!(world.issuer_capability(&key), None);

    // A sender that did not issue the invoice cannot withdraw it.
    let parked = world.issue(None);
    let mut payer_events = world.payer.wallet.subscribe();
    world.post(
        8,
        &world.payer.address,
        &notice("withdrawn", parked.slate_id),
        1,
    );

    let summary = world.drain_payer_invoices();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert!(notice_events(&mut payer_events).is_empty());
    assert_eq!(
        world
            .payer
            .read(|repos| repos.pending_invoice(uuid(parked.slate_id)))
            .unwrap()
            .status,
        PendingInvoiceStatus::Parked
    );
}

#[test]
fn an_unknown_notice_type_or_version_is_acknowledged_and_ignored() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let peer = world.peer_client(9);
    let issued = world.issue_to(peer.address(), None);
    world.post(
        9,
        &world.issuer.address,
        &notice("thanks", issued.slate_id),
        1,
    );
    let newer = format!(
        r#"{{"lepic":2,"type":"declined","slate_id":"{}"}}"#,
        issued.slate_id
    );
    world.post(9, &world.issuer.address, &newer, 1);

    let summary = world.drain_issuer();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 2,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert!(notice_events(&mut issuer_events).is_empty());
    let key = World::address_of(9).key_text();
    assert_eq!(world.issuer_capability(&key), None);
}

#[test]
fn an_oversize_notice_is_dropped() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let peer = world.peer_client(9);
    let issued = world.issue_to(peer.address(), None);
    let padding = "a".repeat(MAX_NOTICE_LEN);
    let oversize = format!(
        r#"{{"lepic":1,"type":"declined","slate_id":"{}","pad":"{padding}"}}"#,
        issued.slate_id
    );
    world.post(9, &world.issuer.address, &oversize, 1);

    let summary = world.drain_issuer();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert!(notice_events(&mut issuer_events).is_empty());
    let key = World::address_of(9).key_text();
    assert_eq!(world.issuer_capability(&key), None);
}

#[test]
fn no_notice_is_posted_to_a_peer_without_proof() {
    let world = World::new();
    let posts = || world.relay.received("PostSlate");

    // A peer that never answered: cancelling its invoice posts nothing.
    let silent = world.peer_client(7);
    let unanswered = world.issue_to(silent.address(), None);
    let i1 = world.unmarked_i1(&silent);
    let before = posts();
    world
        .block_on(world.issuer.wallet.cancel(unanswered.tx_id))
        .unwrap();
    assert_eq!(posts(), before);
    assert!(world.drain_peer(&silent).is_empty());

    // A peer that sent an invoice back unchanged: cancelling posts nothing either.
    let stock = world.peer_client(6);
    let bounced = world.issue_to(stock.address(), None);
    let echo = world.unmarked_i1(&stock);
    world.post(6, &world.issuer.address, &echo, 1);
    assert_eq!(world.drain_issuer().bounced, 1);
    let before = posts();
    world
        .block_on(world.issuer.wallet.cancel(bounced.tx_id))
        .unwrap();
    assert_eq!(posts(), before);
    assert!(world.drain_peer(&stock).is_empty());

    // A payer declining an unmarked invoice from an allowed sender posts nothing.
    world.post(7, &world.payer.address, &i1, 1);
    assert_eq!(world.drain_payer_invoices().parked, 1);
    let before = posts();
    world
        .block_on(world.payer.wallet.decline_invoice(unanswered.slate_id))
        .unwrap();
    assert_eq!(posts(), before);
    assert!(world.drain_peer(&silent).is_empty());
    let key = World::address_of(7).key_text();
    assert_eq!(world.payer.peer_kind(&key), None);
    assert!(
        world
            .issuer
            .read(|repos| repos
                .transaction_by_slate(uuid(unanswered.slate_id), TxDirection::Incoming))
            .is_some()
    );
}

#[test]
fn a_posted_notice_with_another_excess_is_dropped() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, paid, _) = world.pay_through(&peer, 9);
    let expected = world
        .block_on(world.payer.wallet.transaction_details(paid.tx_id))
        .unwrap()
        .kernel_excess
        .unwrap();
    let other = lepic_crypto::Commitment::commit_value(1).unwrap();
    assert_ne!(other, expected);
    let posted = |excess: lepic_crypto::Commitment| {
        Notice {
            slate_id: issued.slate_id,
            kind: NoticeKind::Posted { excess },
        }
        .encode()
        .as_text()
        .unwrap()
        .to_owned()
    };
    let mut payer_events = world.payer.wallet.subscribe();
    world.post(9, &world.payer.address, &posted(other), 1);

    let summary = world.drain_payer_invoices();

    assert_eq!(
        summary,
        InboxSummary {
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert!(notice_events(&mut payer_events).is_empty());

    // The same sender with the excess the payment implies is heard.
    world.post(9, &world.payer.address, &posted(expected), 1);
    assert_eq!(world.drain_payer_invoices().notices, 1);
    assert_eq!(
        notice_events(&mut payer_events),
        vec![Event::InvoicePosted(PostedInvoice {
            tx_id: paid.tx_id,
            slate_id: issued.slate_id,
            excess: expected,
        })]
    );
}

#[test]
fn an_unmarked_payment_proves_nothing_and_gets_no_notice() {
    let world = World::new();
    let peer = world.peer_client(9);
    let (issued, _, i2) = world.pay_through(&peer, 9);
    world.post(9, &world.issuer.address, &unmarked(&i2), 1);
    let before = world.relay.received("PostSlate");

    let summary = world.drain_issuer();

    assert_eq!(summary.finalized, 1);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let state = world
        .issuer
        .read(|repos| repos.transaction(issued.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Posted);
    // The key it came from is also the key the invoice went to; it answered unmarked.
    let key = World::address_of(9).key_text();
    assert_eq!(world.issuer_capability(&key), Some(PeerKind::Epic));
    assert_eq!(world.relay.received("PostSlate"), before);
    assert!(world.drain_peer(&peer).is_empty());
}
