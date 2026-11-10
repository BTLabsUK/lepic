// SPDX-License-Identifier: Apache-2.0
//! Native slates over Epicbox payments addresses (RFC 0003 11.1): a LEPIC wallet with
//! `native_direct` claims them in its marker with its kind `03` seal key, and sends an S1 as a
//! type `0A` envelope sealed to that key once the peer's latest marked slate claimed them. The
//! answer goes back sealed to the request's reply key. Everything else goes as legacy JSON, and
//! a native slate that does not open, or an invoice, is refused with nothing stored.
//!
//! The payer of `World` sends and the issuer receives.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use lepic_contact::{EncPublicKey, Network as ContactNetwork, TxContent, TxKey, armor_tx, dearmor};
use lepic_epicbox::EpicboxClient;
use lepic_methods::epicbox::{NATIVE_NOTICE_LENGTHS, NOTICE_LENGTHS};
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{PeerCompat, TxDirection, TxState};
use lepic_transport::marker::features::NATIVE_SLATES;
use lepic_transport::marker::v3::lepic_marker_features;
use lepic_transport::transport::{Destination, Envelope, Inbound};
use lepic_wallet::inbox::{Arrival, Handled, Hold, Outcome};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{SlateFormat, WalletPolicy};
use rand::SeedableRng;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, World};

/// The armor of a native slate.
const TX_ARMOR: &str = "BEGINEPICTX.";

/// The child of the second funding output, clear of the keys the first send used.
const SECOND_FUNDING: u32 = 10;

fn native(issuer: bool, payer: bool) -> World {
    World::with_native(issuer, payer, WalletPolicy::default())
}

fn send(world: &World) -> SentSlate {
    world
        .block_on(world.payer.wallet.send(
            &world.payer.method,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                to: Destination::new(world.issuer.address.to_string()),
            },
        ))
        .unwrap()
}

/// Takes every message waiting at `client`'s address and acknowledges it.
fn take(world: &World, client: &EpicboxClient) -> Vec<Envelope> {
    world.block_on(async {
        let subscription = client.drain().unwrap();
        let mut taken = Vec::new();
        while let Some(envelope) = world.within(subscription.next_envelope()).await.unwrap() {
            subscription
                .acknowledge(envelope.ack_token())
                .await
                .unwrap();
            taken.push(envelope);
        }
        subscription.stop().await.unwrap();
        taken
    })
}

/// The one message waiting at `party`'s payments address.
fn only(world: &World, party: &Party) -> Envelope {
    let mut taken = take(world, &party.client());
    assert_eq!(taken.len(), 1);
    taken.remove(0)
}

fn text(envelope: &Envelope) -> &str {
    envelope.wire().as_text().unwrap()
}

/// `envelope` with its text replaced by `text`.
fn rewritten(envelope: &Envelope, text: String) -> Envelope {
    Envelope::new(
        envelope.ack_token().clone(),
        envelope.reply_to().cloned(),
        WireSlate::text(MediaType::JSON, text),
    )
}

fn arrive(world: &World, party: &Party, envelope: &Envelope) -> Handled {
    world
        .block_on(party.wallet.arrived(
            &party.method,
            Arrival {
                msg_id: None,
                envelope,
                attempt: 1,
                listing: None,
            },
        ))
        .unwrap()
}

/// A first payment from the payer to the issuer, received and finalized as legacy JSON, after
/// which each side holds the other's latest marked slate. The payer is funded again for the
/// next send.
fn first_payment(world: &World) -> SentSlate {
    let sent = send(world);
    assert_eq!(sent.format, SlateFormat::Legacy);
    let s1 = only(world, &world.issuer);
    assert!(text(&s1).starts_with('{'));
    assert_eq!(arrive(world, &world.issuer, &s1), Handled::Received);
    let s2 = only(world, &world.payer);
    assert!(text(&s2).starts_with('{'));
    assert_eq!(arrive(world, &world.payer, &s2), Handled::Finalized);
    take(world, &world.issuer.client());
    world.payer.fund(SECOND_FUNDING, FUNDING);
    sent
}

fn uuid(sent: &SentSlate) -> Uuid {
    Uuid::from_bytes(*sent.slate_id.as_bytes())
}

fn state(party: &Party, sent: &SentSlate, direction: TxDirection) -> Option<TxState> {
    party
        .read(|repos| repos.transaction_by_slate(uuid(sent), direction))
        .map(|stored| stored.entry.state)
}

/// What the payer stores about the issuer.
fn issuer_row(world: &World) -> PeerCompat {
    world
        .payer
        .peer_compat(&world.issuer.address.key_text())
        .unwrap()
}

fn set_issuer_row(world: &World, change: impl FnOnce(&mut PeerCompat)) {
    let mut row = issuer_row(world);
    change(&mut row);
    world
        .payer
        .write(|repos| repos.put_peer_compat(&world.issuer.address.key_text(), &row));
}

#[test]
fn a_marked_slate_with_native_direct_claims_native_slates_with_a_key() {
    let world = native(true, true);
    send(&world);
    let s1 = only(&world, &world.issuer);
    let features = lepic_marker_features(s1.wire()).unwrap();
    assert_ne!(features & NATIVE_SLATES, 0);
    assert!(text(&s1).contains("\"reply\":"));
}

#[test]
fn a_marked_slate_without_native_direct_claims_none() {
    let world = native(false, false);
    send(&world);
    let s1 = only(&world, &world.issuer);
    let features = lepic_marker_features(s1.wire()).unwrap();
    assert_eq!(features & NATIVE_SLATES, 0);
    assert!(!text(&s1).contains("\"reply\":"));
}

/// The length of the notice the payer sends the issuer once it has finalized a first payment.
fn posted_notice_length(world: &World) -> usize {
    send(world);
    let s1 = only(world, &world.issuer);
    assert_eq!(arrive(world, &world.issuer, &s1), Handled::Received);
    let s2 = only(world, &world.payer);
    assert_eq!(arrive(world, &world.payer, &s2), Handled::Finalized);
    text(&only(world, &world.issuer)).len()
}

#[test]
fn a_notice_is_padded_as_a_first_slate_with_the_marker_the_wallet_writes() {
    let plain = posted_notice_length(&native(false, false));
    assert!(NOTICE_LENGTHS.contains(&plain), "{plain}");
    let claimed = posted_notice_length(&native(true, true));
    assert!(NATIVE_NOTICE_LENGTHS.contains(&claimed), "{claimed}");
}

#[test]
fn the_payment_after_a_claim_goes_native_and_is_answered_native() {
    let world = native(true, true);
    let first = first_payment(&world);
    assert_eq!(
        state(&world.payer, &first, TxDirection::Outgoing),
        Some(TxState::Posted)
    );
    assert!(issuer_row(&world).native_key.is_some());

    let sent = send(&world);
    assert_eq!(sent.format, SlateFormat::Native);
    assert_eq!(sent.amount, Amount::new(AMOUNT));
    let s1 = only(&world, &world.issuer);
    assert!(text(&s1).starts_with(TX_ARMOR), "{}", text(&s1));
    assert_eq!(arrive(&world, &world.issuer, &s1), Handled::Received);
    let received = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(&sent), TxDirection::Incoming))
        .unwrap();
    assert_eq!(received.entry.state, TxState::Received);
    assert_eq!(received.entry.amount_credited, Amount::new(AMOUNT));

    let s2 = only(&world, &world.payer);
    assert!(text(&s2).starts_with(TX_ARMOR), "{}", text(&s2));
    assert_eq!(arrive(&world, &world.payer, &s2), Handled::Finalized);
    let paid = world
        .payer
        .read(|repos| repos.transaction_by_slate(uuid(&sent), TxDirection::Outgoing))
        .unwrap();
    assert_eq!(paid.entry.state, TxState::Posted);
    assert_eq!(
        paid.entry.amount_debited.value() - paid.entry.amount_credited.value(),
        AMOUNT + sent.fee.value()
    );
    assert_eq!(world.node.pushed_transactions().len(), 2);
}

/// The payer's second payment, after a first that went as legacy JSON.
fn second_format(world: &World) -> SlateFormat {
    let sent = send(world);
    let s1 = only(world, &world.issuer);
    assert_eq!(
        text(&s1).starts_with(TX_ARMOR),
        sent.format == SlateFormat::Native
    );
    sent.format
}

#[test]
fn a_payer_without_native_direct_always_sends_legacy() {
    let world = native(true, false);
    first_payment(&world);
    assert_eq!(second_format(&world), SlateFormat::Legacy);
}

#[test]
fn a_payee_without_native_direct_always_gets_legacy() {
    let world = native(false, true);
    first_payment(&world);
    assert_eq!(issuer_row(&world).native_key, None);
    assert_eq!(second_format(&world), SlateFormat::Legacy);
}

#[test]
fn a_payee_not_lepic_lately_gets_legacy() {
    let world = native(true, true);
    first_payment(&world);
    set_issuer_row(&world, |row| {
        row.last_unmarked_at = row
            .last_marked_at
            .map(|at| at + jiff::SignedDuration::from_secs(1));
    });
    assert_eq!(second_format(&world), SlateFormat::Legacy);
}

#[test]
fn a_claim_without_a_valid_key_gets_legacy() {
    for key in [None, Some([0; 32])] {
        let world = native(true, true);
        first_payment(&world);
        set_issuer_row(&world, |row| row.native_key = key);
        assert_eq!(second_format(&world), SlateFormat::Legacy, "{key:?}");
    }
}

#[test]
fn a_tampered_native_slate_is_refused_and_nothing_is_stored() {
    let world = native(true, true);
    first_payment(&world);
    let sent = send(&world);
    assert_eq!(sent.format, SlateFormat::Native);
    let s1 = only(&world, &world.issuer);
    let mut bytes = dearmor(text(&s1)).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let tampered = rewritten(&s1, armor_tx(&bytes));
    let before = world.issuer.writes();

    assert_eq!(arrive(&world, &world.issuer, &tampered), Handled::Rejected);
    assert_eq!(state(&world.issuer, &sent, TxDirection::Incoming), None);
    assert_eq!(world.issuer.writes(), before);
    assert_eq!(world.relay.pending(&world.payer.address), 0);
}

#[test]
fn a_native_invoice_to_a_payments_address_is_refused() {
    let world = native(true, true);
    first_payment(&world);
    let payer_key = world
        .issuer
        .peer_compat(&world.payer.address.key_text())
        .unwrap()
        .native_key
        .unwrap();
    let issued = world.issue_to(&world.payer.address, None);
    let i1 = only(&world, &world.payer);
    let body = world
        .payer
        .wallet
        .native_slates()
        .unwrap()
        .body(Network::Floonet, text(&i1).as_bytes())
        .unwrap();
    let sealed = lepic_contact::seal_tx(
        ContactNetwork::Floonet,
        &EncPublicKey::from_bytes(payer_key).unwrap(),
        TxKey::Epicbox,
        &TxContent::new(body),
        None,
        &mut rand::rngs::StdRng::seed_from_u64(31),
    )
    .unwrap();
    let before = world.payer.writes();

    assert_eq!(
        arrive(&world, &world.payer, &rewritten(&i1, armor_tx(&sealed))),
        Handled::Rejected
    );
    let issued = Uuid::from_bytes(*issued.slate_id.as_bytes());
    assert_eq!(
        world.payer.read(|repos| repos.pending_invoice(issued)),
        None
    );
    assert_eq!(world.payer.writes(), before);
}

/// A native answer that a payment's payer sent, before it reached `world`'s payer.
fn native_answer(world: &World) -> (SentSlate, Envelope) {
    first_payment(world);
    let sent = send(world);
    assert_eq!(sent.format, SlateFormat::Native);
    let s1 = only(world, &world.issuer);
    assert_eq!(arrive(world, &world.issuer, &s1), Handled::Received);
    let s2 = only(world, &world.payer);
    assert!(text(&s2).starts_with(TX_ARMOR), "{}", text(&s2));
    (sent, s2)
}

#[test]
fn a_native_answer_for_a_send_of_another_install_is_held_for_it() {
    let world = native(true, true);
    let (sent, s2) = native_answer(&world);
    let twin = world.payer_twin();
    let before = world.node.pushed_transactions().len();

    let held = world.block_on(twin.wallet.arrived(
        &twin.method,
        Arrival {
            msg_id: Some("7"),
            envelope: &s2,
            attempt: 1,
            listing: None,
        },
    ));
    assert!(
        matches!(held, Err(Outcome::Hold(Hold::UnknownSlate))),
        "{held:?}"
    );
    let requeued = world.block_on(twin.wallet.arrived(
        &twin.method,
        Arrival {
            msg_id: None,
            envelope: &s2,
            attempt: 1,
            listing: None,
        },
    ));
    assert!(matches!(requeued, Err(Outcome::Requeue(_))), "{requeued:?}");

    // The install that made the send still finalizes it.
    assert_eq!(arrive(&world, &world.payer, &s2), Handled::Finalized);
    assert_eq!(
        state(&world.payer, &sent, TxDirection::Outgoing),
        Some(TxState::Posted)
    );
    assert_eq!(world.node.pushed_transactions().len(), before + 1);
}

#[test]
fn a_native_answer_for_a_cancelled_send_is_settled_by_the_cancel() {
    let world = native(true, true);
    let (sent, s2) = native_answer(&world);
    world
        .block_on(world.payer.wallet.cancel(sent.tx_id))
        .unwrap();
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    let before = world.node.pushed_transactions().len();

    assert_eq!(arrive(&world, &world.payer, &s2), Handled::Rejected);
    assert_eq!(
        state(&world.payer, &sent, TxDirection::Outgoing),
        Some(TxState::Cancelled)
    );
    assert_eq!(world.node.pushed_transactions().len(), before);
    // The payee is told the payment was cancelled.
    assert_eq!(world.relay.pending(&world.issuer.address), 1);
}
