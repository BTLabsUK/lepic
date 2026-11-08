// SPDX-License-Identifier: Apache-2.0
//! A contact's notice that comes before its slate stays in the buffer while the host keeps one
//! (ADR 0049), and applies when the slate arrives under the rules of a notice just received.

use std::time::Duration;

use lepic_slate::model::SlateId;
use lepic_wallet::WalletPolicy;
use lepic_wallet::notice::{Notice, NoticeKind};
use uuid::Uuid;

use super::quarantine::{dated, s1_text};
use super::*;

const BUFFER: WalletPolicy = WalletPolicy {
    early_notice_max_count: Some(8),
    early_notice_max_age: Some(Duration::from_secs(3_600)),
    ..WalletPolicy::DEFAULT
};

/// The payer's S1 not sent to anyone, as a file's text, and its slate id.
fn s1(world: &World) -> (String, SlateId) {
    let text = s1_text(world);
    let slate: serde_json::Value = serde_json::from_str(&text).unwrap();
    let id = Uuid::parse_str(slate["id"].as_str().unwrap()).unwrap();
    (text, SlateId::from_bytes(id.into_bytes()))
}

fn post_s1(world: &World, ben_side: ContactId, text: &str) {
    post_signed(
        world,
        &world.payer,
        ben_side,
        &Content {
            purpose: Some(Purpose::Withdrawal),
            ..dated(world, MessageType::Slate, text.as_bytes().to_vec())
        },
    );
}

fn post_notice(
    world: &World,
    from: &Party,
    contact: ContactId,
    slate_id: SlateId,
    kind: NoticeKind,
) {
    let notice = Notice { slate_id, kind };
    let wire = notice.encode_to(&lepic_methods::epicbox::NOTICE_LENGTHS, 0);
    post_signed(
        world,
        from,
        contact,
        &dated(
            world,
            MessageType::Notice,
            wire.as_text().unwrap().as_bytes().to_vec(),
        ),
    );
}

fn rows(party: &Party) -> usize {
    party
        .read(|repos| repos.settings_with_prefix("notice.early."))
        .len()
}

fn incoming(world: &World, slate_id: SlateId) -> lepic_store::TxId {
    world
        .issuer
        .read(|repos| {
            repos.transaction_by_slate(
                Uuid::from_bytes(*slate_id.as_bytes()),
                lepic_store::TxDirection::Incoming,
            )
        })
        .unwrap()
        .id
}

fn cancelled_report(world: &World, tx_id: lepic_store::TxId) -> bool {
    world
        .issuer
        .read(|repos| repos.tx_marks(tx_id))
        .sender_cancelled_at
        .is_some()
}

/// The notice comes first: the S1 is received, the cancel recorded, and no answer goes out,
/// also when the S1 is delivered again.
#[test]
fn a_cancelled_before_its_payment_stops_the_answer() {
    let world = World::with_issuer_policy(BUFFER);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let (text, slate_id) = s1(&world);
    let mut told = world.issuer.wallet.subscribe();

    post_notice(
        &world,
        &world.payer,
        ben_side,
        slate_id,
        NoticeKind::Cancelled,
    );
    assert_eq!(world.collect(&world.issuer).buffered, 1);
    assert_eq!(rows(&world.issuer), 1);

    post_s1(&world, ben_side, &text);
    let report = world.collect(&world.issuer);
    assert_eq!(report.buffered, 0);
    let tx_id = incoming(&world, slate_id);
    assert!(cancelled_report(&world, tx_id));
    assert_eq!(rows(&world.issuer), 0);
    assert_eq!(super::payment_cancelled(events(&mut told)).len(), 1);
    assert_eq!(world.collect(&world.payer).messages, 0);

    post_s1(&world, ben_side, &text);
    world.collect(&world.issuer);
    assert!(super::payment_cancelled(events(&mut told)).is_empty());
    assert_eq!(world.collect(&world.payer).messages, 0);
}

/// The other order takes the normal path and leaves nothing in the buffer.
#[test]
fn a_cancelled_after_its_payment_is_applied_at_once() {
    let world = World::with_issuer_policy(BUFFER);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let (text, slate_id) = s1(&world);

    post_s1(&world, ben_side, &text);
    world.collect(&world.issuer);
    assert_eq!(world.collect(&world.payer).messages, 1);
    post_notice(
        &world,
        &world.payer,
        ben_side,
        slate_id,
        NoticeKind::Cancelled,
    );
    let report = world.collect(&world.issuer);

    assert_eq!(report.buffered, 0);
    assert!(cancelled_report(&world, incoming(&world, slate_id)));
    assert_eq!(rows(&world.issuer), 0);
}

/// One contact's notice for a slate another contact sends changes nothing, and does not stand
/// in the way of the real sender's.
#[test]
fn a_notice_from_another_contact_has_no_effect() {
    let world = World::with_issuer_policy(BUFFER);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mallory = world.stranger();
    let (on_mallory, _) = world.pair(&mallory, &world.issuer);
    let (text, slate_id) = s1(&world);

    post_notice(
        &world,
        &mallory,
        on_mallory,
        slate_id,
        NoticeKind::Cancelled,
    );
    assert_eq!(world.collect(&world.issuer).buffered, 1);
    post_s1(&world, ben_side, &text);
    world.collect(&world.issuer);

    assert!(!cancelled_report(&world, incoming(&world, slate_id)));
    assert_eq!(rows(&world.issuer), 0);
    assert_eq!(world.collect(&world.payer).messages, 1);
}

#[test]
fn two_contacts_notices_for_one_slate_stand_side_by_side() {
    let world = World::with_issuer_policy(BUFFER);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mallory = world.stranger();
    let (on_mallory, _) = world.pair(&mallory, &world.issuer);
    let (text, slate_id) = s1(&world);

    post_notice(
        &world,
        &mallory,
        on_mallory,
        slate_id,
        NoticeKind::Cancelled,
    );
    post_notice(
        &world,
        &world.payer,
        ben_side,
        slate_id,
        NoticeKind::Cancelled,
    );
    assert_eq!(world.collect(&world.issuer).buffered, 2);
    assert_eq!(rows(&world.issuer), 2);
    post_s1(&world, ben_side, &text);
    world.collect(&world.issuer);

    assert!(cancelled_report(&world, incoming(&world, slate_id)));
    assert_eq!(rows(&world.issuer), 0);
    assert_eq!(world.collect(&world.payer).messages, 0);
}

/// A notice past the age cap does not apply.
#[test]
fn a_notice_past_its_age_is_not_applied() {
    let world = World::with_issuer_policy(BUFFER);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let (text, slate_id) = s1(&world);

    post_notice(
        &world,
        &world.payer,
        ben_side,
        slate_id,
        NoticeKind::Cancelled,
    );
    assert_eq!(world.collect(&world.issuer).buffered, 1);
    world.issuer.clock.advance(2 * HOUR);
    post_s1(&world, ben_side, &text);
    world.collect(&world.issuer);

    assert!(!cancelled_report(&world, incoming(&world, slate_id)));
    assert_eq!(rows(&world.issuer), 0);
    assert_eq!(world.collect(&world.payer).messages, 1);
}

/// A `withdrawn` that overtakes its invoice removes the invoice as it parks.
#[test]
fn a_withdrawn_before_its_invoice_removes_it_on_parking() {
    let world = World::with_payer_policy(BUFFER);
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    world.relay.set_refusing(true);
    let issued = world.invoice_contact(shop_side, "overtaken");
    world.relay.set_refusing(false);
    let mut told = world.payer.wallet.subscribe();

    post_notice(
        &world,
        &world.issuer,
        shop_side,
        issued.slate_id,
        NoticeKind::Withdrawn,
    );
    assert_eq!(world.collect(&world.payer).buffered, 1);
    world.collect(&world.issuer);
    world.collect(&world.payer);

    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );
    assert_eq!(rows(&world.payer), 0);
    let withdrawn = events(&mut told)
        .into_iter()
        .filter(|event| matches!(event, Event::InvoiceWithdrawn(_)))
        .count();
    assert_eq!(withdrawn, 1);
}

/// Without the caps the notice goes as it always did.
#[test]
fn with_no_caps_nothing_is_kept() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let (text, slate_id) = s1(&world);

    post_notice(
        &world,
        &world.payer,
        ben_side,
        slate_id,
        NoticeKind::Cancelled,
    );
    assert_eq!(world.collect(&world.issuer).buffered, 0);
    assert_eq!(rows(&world.issuer), 0);
    post_s1(&world, ben_side, &text);
    world.collect(&world.issuer);

    assert!(!cancelled_report(&world, incoming(&world, slate_id)));
    assert_eq!(world.collect(&world.payer).messages, 1);
}
