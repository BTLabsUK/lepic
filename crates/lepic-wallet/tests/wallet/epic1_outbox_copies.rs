// SPDX-License-Identifier: Apache-2.0
//! The copies of an epic1 payment, one per mailbox of the payer's list: the payment is posted
//! when one mailbox took it, the others are posted to again on the outbox's schedule, and once
//! the answer is read the cancel goes to the mailboxes that took a copy, again until one
//! answers it (ADR 0065 §3).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::epic1_outbox::{LATER, due_over, pay_over, quick, rows};
use crate::epicbox_world as world;
use crate::pairing_helpers::{adding, on, relays};

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::{Domain, RelayEndpoint, Security};
use lepic_methods::epicbox::Epicbox;
use lepic_store::{CopyState, NativeOutboxId, OutboxState};
use lepic_wallet_contacts::epic1_testing::delivery_mailbox;
use lepic_wallet_contacts::{CollectTrigger, ContactRelays, WalletContacts};
use world::{Party, World};

fn tls(domain: &str) -> RelayEndpoint {
    RelayEndpoint::new(Domain::parse(domain).unwrap(), None, Security::Tls)
}

/// `party`'s relays with `shop.test` and `far.test` listed after its own, on a client that
/// gives up on an unanswered post soon.
fn three(world: &World, party: &Party) -> ContactRelays {
    adding(quick(world, party), vec![tls("shop.test"), tls("far.test")])
}

/// `party`'s relays with `domain` as its own relay and no other.
fn alone_on(world: &World, party: &Party, domain: &str) -> ContactRelays {
    let mut settings = world::settings();
    settings.endpoint = tls(domain);
    on(
        Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        relays(party),
    )
}

/// The copies of row `id`: mailbox, state and attempts, by mailbox.
fn copies(party: &Party, id: NativeOutboxId) -> Vec<(String, CopyState, u32)> {
    party
        .read(|repos| repos.outbox_copies(id))
        .into_iter()
        .map(|copy| (copy.mailbox, copy.state, copy.attempts))
        .collect()
}

fn copy(mailbox: &str, state: CopyState, attempts: u32) -> (String, CopyState, u32) {
    (mailbox.to_owned(), state, attempts)
}

/// A payment to three mailboxes of which two refuse is posted at once, on the one that took
/// it, and the two are stored as owed. The next outbox run posts to them again: the one that
/// takes it now is stored as a taker, the one that still refuses is owed again on a longer
/// back-off and is not asked before it.
#[test]
fn a_payment_two_of_three_mailboxes_refuse_is_posted_and_tried_again_on_the_two() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    world.relay.set_domain_refused("shop.test");
    world.relay.set_domain_refused("far.test");
    let relays = three(&world, &world.payer);

    let paid = pay_over(&world, &relays, &issued.link);

    assert_eq!(paid.posted, Some(0));
    let row = rows(&world.payer, paid.slate_id).remove(0);
    assert_eq!(row.entry.state, OutboxState::Posted);
    assert_eq!(
        copies(&world.payer, row.id),
        [
            copy("far.test:443", CopyState::Owed, 1),
            copy("relay.test:80", CopyState::Taken, 1),
            copy("shop.test:443", CopyState::Owed, 1),
        ]
    );
    let shop = delivery_mailbox(&issued.link, "shop.test").unwrap();
    let far = delivery_mailbox(&issued.link, "far.test").unwrap();
    assert_eq!(world.relay.pending(&shop), 0);
    let far_posts = world.relay.received_on("far.test", "PostSlate");

    world.relay.set_domain_accepted("shop.test");
    world.payer.clock.advance(LATER);
    due_over(&world, &world.payer, &relays);

    assert_eq!(
        copies(&world.payer, row.id),
        [
            copy("far.test:443", CopyState::Owed, 2),
            copy("relay.test:80", CopyState::Taken, 1),
            copy("shop.test:443", CopyState::Taken, 1),
        ]
    );
    assert_eq!(world.relay.pending(&shop), 1);
    assert_eq!(world.relay.pending(&far), 0);
    assert_eq!(
        world.relay.received_on("far.test", "PostSlate"),
        far_posts + 1
    );
    let posted = rows(&world.payer, paid.slate_id);
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].entry.state, OutboxState::Posted);

    // Before its back-off the refusing mailbox is not asked again.
    due_over(&world, &world.payer, &relays);
    assert_eq!(
        world.relay.received_on("far.test", "PostSlate"),
        far_posts + 1
    );
}

/// A payment answered on one mailbox cancels its copy on the other mailbox that took one, and
/// on no other: not on the mailbox the answer was read on, and not on the mailbox that refused
/// the post. A cancel the mailbox fails is stored and sent again on the next outbox run, and
/// once it is taken nothing is left to send.
#[test]
fn a_cancel_goes_to_the_mailboxes_that_took_a_copy_and_is_sent_again_after_a_failure() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_version(Some("3.1.0"));
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    world.relay.set_domain_refused("far.test");
    let relays = three(&world, &world.payer);
    let paid = pay_over(&world, &relays, &issued.link);
    assert_eq!(paid.posted, Some(0));
    let txids = world.relay.posted_txids();
    assert_eq!(txids.len(), 1, "every copy goes under one transaction id");
    let taken = world
        .block_on(world.issuer.wallet.contact_book().contacts_collect(
            &alone_on(&world, &world.issuer, "shop.test"),
            CollectTrigger::Open,
        ))
        .unwrap()
        .epic1;
    assert_eq!(taken, 1);

    world.relay.set_cancel_error(Some("Unauthorized"));
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_collect(&relays, CollectTrigger::Open),
        )
        .unwrap();

    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.relay.received_on("relay.test", "CancelTx"), 1);
    assert_eq!(world.relay.received_on("shop.test", "CancelTx"), 0);
    assert_eq!(world.relay.received_on("far.test", "CancelTx"), 0);
    assert!(!world.relay.is_cancelled(&txids[0]));
    let row = rows(&world.payer, paid.slate_id).remove(0);
    assert_eq!(
        copies(&world.payer, row.id),
        [copy("relay.test:80", CopyState::Cancel, 1)]
    );

    world.relay.set_cancel_error(None);
    world.payer.clock.advance(LATER);
    due_over(&world, &world.payer, &relays);

    assert!(world.relay.is_cancelled_on("relay.test", &txids[0]));
    assert_eq!(world.relay.received_on("relay.test", "CancelTx"), 2);
    assert_eq!(world.relay.received_on("shop.test", "CancelTx"), 0);
    assert_eq!(world.relay.received_on("far.test", "CancelTx"), 0);
    assert_eq!(copies(&world.payer, row.id), []);

    due_over(&world, &world.payer, &relays);
    assert_eq!(world.relay.received("CancelTx"), 2);
}
