// SPDX-License-Identifier: Apache-2.0
//! Two installs of one wallet on its epic1 address. The relay hands the address's mailbox to
//! one socket at a time; the install that holds it reads the payment and answers it, and the
//! other learns of it from the chain.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;

use lepic_epicbox::MuxOptions;
use lepic_epicbox::sessions::PushedConfig;
use lepic_primitives::amount::Amount;
use lepic_store::{TxDirection, TxState};
use lepic_wallet_contacts::{CollectTrigger, WalletContacts};

use crate::epic1::{collect_on, mailbox_of};
use crate::epicbox_world::{AMOUNT, Party, World};
use crate::pairing_helpers::{ACK_GROUP, queued_after, wait_gone};
use crate::twins::{incoming_count, mine_pushed, on_chain, other_wallet_entries, refresh_and_scan};

/// The relay of the wallets' own mailboxes.
const HOME: &str = "relay.test:80";

/// Waits until another socket of the wallet has taken a mailbox from `party`'s contacts socket.
fn wait_replaced(world: &World, party: &Party) {
    let session = party.epicbox.pushed().get(HOME, ACK_GROUP).unwrap();
    let mut events = session.events();
    world.block_on(world.within(async {
        while session.replaced_keys().is_empty() {
            let _ = events.recv().await.unwrap();
        }
    }));
}

/// The issuer opens, then a second install of it opens and takes the address. Returns the
/// second install and how many mailboxes each watches.
fn both_open(world: &World) -> (Party, usize) {
    let watched = collect_on(world, &world.issuer, CollectTrigger::Open).mailboxes;
    assert!(watched >= 1);
    let twin = world.issuer_twin();
    let opened = collect_on(world, &twin, CollectTrigger::Open);
    assert_eq!(opened.mailboxes, watched);
    wait_replaced(world, &world.issuer);
    (twin, watched)
}

/// The epic1 answers `party` holds.
fn answers(world: &World, party: &Party) -> usize {
    world
        .block_on(party.wallet.contact_book().epic1_answers())
        .unwrap()
        .len()
}

/// `party`, the install that did not read the payment, holds one incoming entry: the one its
/// scan recorded from the chain, from another wallet, confirmed.
fn assert_received_by_another_wallet(world: &World, party: &Party) {
    let entries = other_wallet_entries(world, party);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0].transaction.entry;
    assert_eq!(
        (entry.direction, entry.state, entry.amount_credited),
        (
            TxDirection::Incoming,
            TxState::Confirmed,
            Amount::new(AMOUNT)
        )
    );
    assert_eq!(incoming_count(party), 1);
}

/// Both installs online: the one that attached last holds the address, reads the payment and
/// answers it once. The other counts the mailbox replaced, reads nothing, and shows the payment
/// as received by another wallet once it is mined.
#[test]
fn both_installs_online_one_reads_and_the_other_learns_from_the_chain() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let (twin, watched) = both_open(&world);
    let issued = world.issue_link(&world.issuer);

    queued_after(&world, &twin, HOME, || {
        world.pay_link(&issued.link).unwrap();
    });
    assert_eq!(collect_on(&world, &twin, CollectTrigger::Push).epic1, 1);
    let left = collect_on(&world, &world.issuer, CollectTrigger::Push);
    assert_eq!(left.replaced, watched);
    assert_eq!(left.not_reached, 0);
    assert_eq!(left.epic1, 0);
    wait_gone(&world, &mailbox_of(&issued.link));
    assert_eq!(
        (answers(&world, &twin), answers(&world, &world.issuer)),
        (1, 0)
    );

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    mine_pushed(&world, true);
    refresh_and_scan(&world, &twin);
    assert_eq!(incoming_count(&twin), 1);
    assert!(other_wallet_entries(&world, &twin).is_empty());
    refresh_and_scan(&world, &world.issuer);
    assert_received_by_another_wallet(&world, &world.issuer);
    twin.wallet.close();
}

/// Both installs pull again and again: neither takes the address from the other, so the relay
/// sees no new attach. An open takes it back once, and the pulls after it trade nothing either.
#[test]
fn installs_that_both_pull_do_not_trade_the_address() {
    let world = World::new();
    let (twin, watched) = both_open(&world);
    let attaches = world.relay.received("Attach");

    for _ in 0..3 {
        assert_eq!(
            collect_on(&world, &world.issuer, CollectTrigger::Pull).replaced,
            watched
        );
        assert_eq!(collect_on(&world, &twin, CollectTrigger::Pull).replaced, 0);
    }
    assert_eq!(world.relay.received("Attach"), attaches);

    assert_eq!(
        collect_on(&world, &world.issuer, CollectTrigger::Open).replaced,
        0
    );
    wait_replaced(&world, &twin);
    let attaches = world.relay.received("Attach");
    for _ in 0..3 {
        assert_eq!(
            collect_on(&world, &twin, CollectTrigger::Pull).replaced,
            watched
        );
        assert_eq!(
            collect_on(&world, &world.issuer, CollectTrigger::Pull).replaced,
            0
        );
    }
    assert_eq!(world.relay.received("Attach"), attaches);

    let issued = world.issue_link(&world.issuer);
    queued_after(&world, &world.issuer, HOME, || {
        world.pay_link(&issued.link).unwrap();
    });
    assert_eq!(
        collect_on(&world, &world.issuer, CollectTrigger::Push).epic1,
        1
    );
    assert_eq!(collect_on(&world, &twin, CollectTrigger::Push).epic1, 0);
    twin.wallet.close();
}

/// The install whose address the other took attaches it again when its hold-off ends (a short
/// one stands in for the ten minutes). The other goes offline; the payment that comes meanwhile
/// is read by the install that stayed. The other, back, takes the address at its open, reads
/// nothing twice, and shows the payment as received by another wallet once it is mined.
#[test]
fn an_install_offline_and_back_reads_nothing_twice_and_learns_from_the_chain() {
    let world = World::new();
    on_chain(&world, &world.payer);
    world
        .issuer
        .epicbox
        .pushed()
        .set_contacts(Some(PushedConfig {
            group: ACK_GROUP.to_owned(),
            options: MuxOptions::default().with_replaced_hold_off(Duration::from_millis(200)),
        }));
    let watched = collect_on(&world, &world.issuer, CollectTrigger::Open).mailboxes;
    let twin = world.issuer_twin();
    collect_on(&world, &twin, CollectTrigger::Open);
    // The issuer's hold-off ends and it attaches the address again.
    wait_replaced(&world, &twin);

    twin.epicbox.pushed().clear();
    let issued = world.issue_link(&world.issuer);
    queued_after(&world, &world.issuer, HOME, || {
        world.pay_link(&issued.link).unwrap();
    });
    assert_eq!(
        collect_on(&world, &world.issuer, CollectTrigger::Push).epic1,
        1
    );
    wait_gone(&world, &mailbox_of(&issued.link));
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);

    let back = twin.reopened(&world.node, &world.relay, &world.runtime);
    twin.wallet.close();
    let attaches = world.relay.received("Attach");
    let opened = collect_on(&world, &back, CollectTrigger::Open);
    assert_eq!(opened.epic1, 0);
    assert_eq!(opened.replaced, 0);
    assert_eq!(opened.mailboxes, watched);
    assert!(world.relay.received("Attach") > attaches);
    assert_eq!(
        (answers(&world, &world.issuer), answers(&world, &back)),
        (1, 0)
    );

    mine_pushed(&world, true);
    refresh_and_scan(&world, &back);
    assert_received_by_another_wallet(&world, &back);
    refresh_and_scan(&world, &world.issuer);
    assert_eq!(incoming_count(&world.issuer), 1);
    assert!(other_wallet_entries(&world, &world.issuer).is_empty());
    back.wallet.close();
}

/// Either install, started again, takes the address at its first pass whatever the trigger:
/// a new process holds no replaced state. The one it took the address from reads nothing.
#[test]
fn either_install_started_again_takes_the_address() {
    let mut world = World::new();
    let (twin, watched) = both_open(&world);

    let restarted = world
        .issuer
        .reopened(&world.node, &world.relay, &world.runtime);
    world.issuer.epicbox.pushed().clear();
    let old = std::mem::replace(&mut world.issuer, restarted);
    old.wallet.close();
    let first = collect_on(&world, &world.issuer, CollectTrigger::Foreground);
    assert_eq!((first.replaced, first.mailboxes), (0, watched));
    wait_replaced(&world, &twin);

    let twin_again = twin.reopened(&world.node, &world.relay, &world.runtime);
    twin.epicbox.pushed().clear();
    twin.wallet.close();
    let first = collect_on(&world, &twin_again, CollectTrigger::Foreground);
    assert_eq!((first.replaced, first.mailboxes), (0, watched));
    wait_replaced(&world, &world.issuer);

    let issued = world.issue_link(&world.issuer);
    queued_after(&world, &twin_again, HOME, || {
        world.pay_link(&issued.link).unwrap();
    });
    assert_eq!(
        collect_on(&world, &twin_again, CollectTrigger::Push).epic1,
        1
    );
    let left = collect_on(&world, &world.issuer, CollectTrigger::Push);
    assert_eq!((left.replaced, left.epic1), (watched, 0));
    twin_again.wallet.close();
}
