// SPDX-License-Identifier: Apache-2.0
//! Contact messages that open and cannot be taken stay in local quarantine while the host keeps
//! one (ADR 0049), and everything is as before while it does not.

use lepic_wallet::WalletPolicy;
use lepic_wallet::ports::Clock as _;
use lepic_wallet_contacts::{QuarantineReason, QuarantineRetry, QuarantinedMessage};

use super::*;

/// A cap with room for every message these tests keep.
const ROOM: u64 = 1024 * 1024;

fn world_keeping(cap: u64) -> World {
    World::with_issuer_policy(WalletPolicy {
        quarantine_max_bytes: Some(cap),
        ..WalletPolicy::default()
    })
}

fn kept(world: &World) -> Vec<QuarantinedMessage> {
    world
        .block_on(world.issuer.wallet.contact_book().contact_quarantine())
        .unwrap()
}

fn retry(world: &World, id: Option<&str>) -> QuarantineRetry {
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contact_quarantine_retry(&relays(&world.issuer), id),
        )
        .unwrap()
}

fn rows(world: &World) -> usize {
    world
        .issuer
        .read(|repos| repos.settings_with_prefix("contact.quarantine."))
        .len()
}

pub(super) fn dated(world: &World, kind: MessageType, body: Vec<u8>) -> Content {
    Content {
        sent_at: Some(u64::try_from(world.issuer.clock.now().as_second()).unwrap()),
        ..Content::new(kind, body)
    }
}

fn post_notice_text(world: &World, ben_side: ContactId, text: &str) {
    post_signed(
        world,
        &world.payer,
        ben_side,
        &dated(world, MessageType::Notice, text.as_bytes().to_vec()),
    );
}

/// The payer's S1 as a file's text, the payment not sent to anyone yet.
pub(super) fn s1_text(world: &World) -> String {
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(file.clone()),
            },
        ))
        .unwrap();
    std::fs::read_to_string(&file).unwrap()
}

/// Without a cap nothing is kept and the message goes as it always did.
#[test]
fn with_no_cap_nothing_is_kept() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");

    let report = world.collect(&world.issuer);

    assert_eq!(report.quarantined, 0);
    assert_eq!(report.quarantine_dropped, 0);
    assert!(kept(&world).is_empty());
    assert_eq!(rows(&world), 0);
}

/// A slate that does not decode is kept with what the host needs to show it and not its bytes.
#[test]
fn an_undecodable_slate_is_kept_and_listed() {
    let world = world_keeping(ROOM);
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_signed(
        &world,
        &world.payer,
        ben_side,
        &dated(&world, MessageType::Slate, b"no slate".to_vec()),
    );

    let report = world.collect(&world.issuer);

    assert_eq!(report.quarantined, 1);
    let list = kept(&world);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].contact_id, shop_side);
    assert_eq!(list[0].reason, QuarantineReason::UndecodableSlate);
    assert_eq!(list[0].attempts, 0);
    assert!(list[0].size > 0);
    assert_eq!(list[0].first_seen, world.issuer.clock.now());
}

#[test]
fn a_slate_of_no_utf8_is_kept() {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_signed(
        &world,
        &world.payer,
        ben_side,
        &dated(&world, MessageType::Slate, vec![0xff, 0xfe]),
    );

    assert_eq!(world.collect(&world.issuer).quarantined, 1);
    assert_eq!(kept(&world)[0].reason, QuarantineReason::UndecodableSlate);
}

/// A notice this wallet does not know is kept, and a retry that cannot take it counts an attempt.
#[test]
fn an_unknown_notice_is_kept_and_a_failed_retry_counts() {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");
    assert_eq!(world.collect(&world.issuer).quarantined, 1);
    let id = kept(&world)[0].id.clone();
    assert_eq!(kept(&world)[0].reason, QuarantineReason::UnknownNotice);

    let retried = retry(&world, Some(&id));

    assert_eq!(
        retried,
        QuarantineRetry {
            retried: 1,
            cleared: 0,
            kept: 1
        }
    );
    assert_eq!(kept(&world)[0].attempts, 1);
    assert_eq!(retry(&world, None).kept, 1);
    assert_eq!(kept(&world)[0].attempts, 2);
    assert_eq!(retry(&world, Some("00")), QuarantineRetry::default());
}

/// Nothing retries on its own: a collect leaves an entry as it was.
#[test]
fn a_collect_does_not_retry() {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");
    world.collect(&world.issuer);

    let report = world.collect(&world.issuer);

    assert_eq!(report.quarantined, 0);
    assert_eq!(kept(&world).len(), 1);
    assert_eq!(kept(&world)[0].attempts, 0);
}

/// The relay sending the same envelope again adds nothing.
#[test]
fn a_message_delivered_again_is_not_taken_twice() {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");
    world.collect(&world.issuer);
    post_notice_text(&world, ben_side, "no notice this wallet knows");

    let report = world.collect(&world.issuer);

    assert_eq!(report.quarantined, 0);
    assert_eq!(kept(&world).len(), 1);
}

#[test]
fn discarding_forgets_a_message_once() {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");
    world.collect(&world.issuer);
    let id = kept(&world)[0].id.clone();
    let discard = || {
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_quarantine_discard(&id),
            )
            .unwrap()
    };

    assert!(discard());
    assert!(!discard());
    assert!(kept(&world).is_empty());
    assert_eq!(rows(&world), 0);
}

/// A payment over the open receipt caps is kept, and taken once the host retries with room.
#[test]
fn a_payment_over_the_receipt_cap_is_kept_and_taken_on_retry() {
    let world = World::with_issuer_policy(WalletPolicy {
        quarantine_max_bytes: Some(ROOM),
        max_open_receipts_per_sender: 1,
        ..WalletPolicy::default()
    });
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    world.payer.fund(1, world::FUNDING);
    let mut issuer_events = world.issuer.wallet.subscribe();
    send_through_mailbox(&world, &relays(&world.payer), ben_side);
    send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let taken = |events: Vec<Event>| {
        events
            .into_iter()
            .filter_map(|event| match event {
                Event::WithdrawalFromContact(news) => Some(news.tx_id),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(world.collect(&world.issuer).quarantined, 1);
    let first = taken(events(&mut issuer_events));
    assert_eq!(first.len(), 1);
    assert_eq!(kept(&world)[0].reason, QuarantineReason::ReceiptCap);
    assert_eq!(retry(&world, None).kept, 1);

    world
        .block_on(world.issuer.wallet.cancel(first[0]))
        .unwrap();
    let retried = retry(&world, None);

    assert_eq!(retried.cleared, 1);
    assert!(kept(&world).is_empty());
    assert_eq!(rows(&world), 0);
    let second = taken(events(&mut issuer_events));
    assert_eq!(second.len(), 1);
    assert_eq!(world.tx_state(&world.issuer, second[0]), TxState::Received);
}

/// An S1 the receive refuses for good is kept.
#[test]
fn a_refused_receive_is_kept() {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut slate: serde_json::Value = serde_json::from_str(&s1_text(&world)).unwrap();
    slate["height"] = serde_json::Value::String("99999999".to_owned());
    post_signed(
        &world,
        &world.payer,
        ben_side,
        &Content {
            purpose: Some(Purpose::Withdrawal),
            ..dated(&world, MessageType::Slate, slate.to_string().into_bytes())
        },
    );

    assert_eq!(world.collect(&world.issuer).quarantined, 1);
    assert_eq!(kept(&world)[0].reason, QuarantineReason::ReceiveRefused);
}

/// A message that keeps failing is kept once the hold bound is reached, its hold count goes, and
/// a retry takes it after the cause is gone.
#[test]
fn a_message_past_the_hold_bound_is_kept_and_taken_on_retry() {
    let world = World::with_issuer_policy(WalletPolicy {
        quarantine_max_bytes: Some(ROOM),
        contact_hold_attempts: 1,
        ..WalletPolicy::default()
    });
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    world
        .issuer
        .write(|repos| repos.put_setting("contact.payloads", "damaged"));
    world
        .block_on(world.payer.wallet.contact_book().contact_post_payload(
            &relays(&world.payer),
            ben_side,
            b"bytes".to_vec(),
        ))
        .unwrap();
    world.collect(&world.payer);

    assert_eq!(world.collect(&world.issuer).quarantined, 0);
    assert_eq!(world.collect(&world.issuer).quarantined, 1);
    assert_eq!(kept(&world)[0].reason, QuarantineReason::HoldBound);
    assert!(
        world
            .issuer
            .read(|repos| repos.settings_with_prefix("contact.held."))
            .is_empty()
    );

    world
        .issuer
        .write(|repos| repos.delete_setting("contact.payloads"));
    assert_eq!(retry(&world, None).cleared, 1);
    assert_eq!(
        world
            .block_on(world.issuer.wallet.contact_book().contact_payloads())
            .unwrap()
            .len(),
        1
    );
}

/// With no cap the same message is settled at the bound as before.
#[test]
fn with_no_cap_a_message_past_the_hold_bound_is_settled() {
    let world = World::with_issuer_policy(WalletPolicy {
        contact_hold_attempts: 1,
        ..WalletPolicy::default()
    });
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    world
        .issuer
        .write(|repos| repos.put_setting("contact.payloads", "damaged"));
    world
        .block_on(world.payer.wallet.contact_book().contact_post_payload(
            &relays(&world.payer),
            ben_side,
            b"bytes".to_vec(),
        ))
        .unwrap();
    world.collect(&world.payer);

    world.collect(&world.issuer);
    world.collect(&world.issuer);
    world
        .issuer
        .write(|repos| repos.delete_setting("contact.payloads"));
    world.collect(&world.issuer);

    assert!(kept(&world).is_empty());
    assert!(
        world
            .block_on(world.issuer.wallet.contact_book().contact_payloads())
            .unwrap()
            .is_empty()
    );
}

/// While a quarantine is kept a hold count outlives the relay's week; any other wallet forgets
/// it as before.
#[test]
fn a_hold_count_outlives_the_relay_while_a_quarantine_is_kept() {
    let world = world_keeping(ROOM);
    world.pair_for_invoices(ContactKind::Exchange);
    let now = u64::try_from(world.issuer.clock.now().as_second()).unwrap();
    let day = 24 * 60 * 60;
    let rows = [
        ("contact.held.01", format!("{}:1", now - 8 * day)),
        ("contact.held.02", format!("{}:1", now - 15 * day)),
    ];
    world.issuer.write(|repos| {
        for (key, value) in &rows {
            repos.put_setting(key, value)?;
        }
        Ok(())
    });

    world.collect(&world.issuer);

    assert_eq!(
        world
            .issuer
            .read(|repos| repos.settings_with_prefix("contact.held.")),
        vec![("contact.held.01".to_owned(), rows[0].1.clone())]
    );
}

/// The envelope's size, from one message kept in a world of its own.
fn one_envelope() -> u64 {
    let world = world_keeping(ROOM);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "message 1");
    world.collect(&world.issuer);
    kept(&world)[0].size
}

/// Over the cap the contact's own oldest goes, and a message no cap can hold is dropped with a
/// count.
#[test]
fn over_the_cap_the_contacts_oldest_goes_first() {
    let size = one_envelope();
    let world = world_keeping(size * 2);
    let (shop, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let stranger = world.stranger();
    let (on_stranger, on_issuer) = world.pair(&stranger, &world.issuer);
    let post = |party: &Party, side, text: &str| {
        post_signed(
            &world,
            party,
            side,
            &dated(&world, MessageType::Notice, text.as_bytes().to_vec()),
        );
        world.collect(&world.issuer)
    };

    post(&world.payer, ben_side, "message 1");
    post(&stranger, on_stranger, "message 2");
    world.issuer.clock.advance(Duration::from_secs(1));
    let report = post(&stranger, on_stranger, "message 3");

    assert_eq!(report.quarantined, 1);
    assert_eq!(report.quarantine_dropped, 1);
    let list = kept(&world);
    assert_eq!(list.len(), 2);
    assert_eq!(list.iter().filter(|m| m.contact_id == shop).count(), 1);
    assert_eq!(list.iter().filter(|m| m.contact_id == on_issuer).count(), 1);
}

/// A contact with nothing kept makes room from the wallet's oldest.
#[test]
fn over_the_cap_the_wallets_oldest_goes_next() {
    let size = one_envelope();
    let world = world_keeping(size * 2);
    let (shop, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let stranger = world.stranger();
    let (on_stranger, on_issuer) = world.pair(&stranger, &world.issuer);
    let post = |party: &Party, side, text: &str| {
        post_signed(
            &world,
            party,
            side,
            &dated(&world, MessageType::Notice, text.as_bytes().to_vec()),
        );
        world.collect(&world.issuer)
    };

    post(&world.payer, ben_side, "message 1");
    world.issuer.clock.advance(Duration::from_secs(1));
    post(&world.payer, ben_side, "message 2");
    world.issuer.clock.advance(Duration::from_secs(1));
    let report = post(&stranger, on_stranger, "message 3");

    assert_eq!(report.quarantine_dropped, 1);
    let list = kept(&world);
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].contact_id, shop);
    assert_eq!(list[1].contact_id, on_issuer);
}

#[test]
fn a_message_larger_than_the_cap_is_not_kept() {
    let world = world_keeping(1);
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");

    let report = world.collect(&world.issuer);

    assert_eq!(report.quarantined, 0);
    assert_eq!(report.quarantine_dropped, 1);
    assert!(kept(&world).is_empty());
    assert_eq!(rows(&world), 0);
}

/// Removing a contact takes its kept messages with it.
#[test]
fn removing_a_contact_removes_its_messages() {
    let world = world_keeping(ROOM);
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    post_notice_text(&world, ben_side, "no notice this wallet knows");
    world.collect(&world.issuer);
    assert_eq!(rows(&world), 2);

    world
        .block_on(world.issuer.wallet.contact_book().contact_remove(shop_side))
        .unwrap();

    assert!(kept(&world).is_empty());
    assert_eq!(rows(&world), 0);
}
