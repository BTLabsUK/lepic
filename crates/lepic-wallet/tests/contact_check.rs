// SPDX-License-Identifier: Apache-2.0
//! The contact check and the move of a wallet's own home relay (ADR 0040, RFC 0002 8.5) between
//! two LEPIC wallets on the mock relay.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "pairing/helpers.rs"]
mod helpers;
mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use helpers::{HOUR, MINUTE, accept, events, invite_request, relays};
use lepic_contact::{ContactCard, Network as ContactNetwork};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_store::ContactId;
use lepic_wallet::Event;
use lepic_wallet_contacts::{
    AcceptRequest, ContactError, ContactRelays, InviteRequest, PairingClass, WalletContacts,
};
use world::{Party, World};

/// The seq of the card the party shows its contact `contact`.
fn own_seq(party: &Party, contact: ContactId) -> u32 {
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    ContactCard::decode(&record.own_card, ContactNetwork::Floonet)
        .unwrap()
        .fields()
        .seq
}

/// The seq of the contact's card the party holds.
fn peer_seq(party: &Party, contact: ContactId) -> u32 {
    party
        .read(|repos| repos.contact(contact))
        .unwrap()
        .peer
        .unwrap()
        .seq
}

fn check(world: &World, party: &Party, contact: ContactId) -> Result<(), ContactError> {
    world.block_on(
        party
            .wallet
            .contact_book()
            .contact_check(&relays(party), contact),
    )
}

fn advance(world: &World, by: Duration) {
    world.issuer.clock.advance(by);
    world.payer.clock.advance(by);
}

/// The party's relays with `relay2.test:80` built in, as a host that offers it would pass them.
fn with_relay2(party: &Party) -> ContactRelays {
    ContactRelays {
        meeting: vec![RelayEndpoint::new(
            Domain::parse("relay2.test").unwrap(),
            Some(80),
            Security::Plain,
        )],
        ..relays(party)
    }
}

fn move_requests(events: Vec<Event>) -> Vec<String> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::ContactRelayMoveRequested(request) => Some(request.host),
            _ => None,
        })
        .collect()
}

/// A check is answered with the current card, seq raised by one, which the asking wallet takes
/// as an update; answers are paced at one an hour and three a day per contact.
#[test]
fn a_contact_check_is_answered_with_the_current_card_within_the_pace() {
    let world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    let first = own_seq(&world.issuer, issuer_side);
    advance(&world, 10 * MINUTE);
    let heard = world
        .payer
        .read(|repos| repos.contact(payer_side))
        .unwrap()
        .last_sealed_in;

    check(&world, &world.payer, payer_side).unwrap();
    world.collect(&world.issuer);
    assert_eq!(own_seq(&world.issuer, issuer_side), first + 1);
    world.collect(&world.payer);
    assert_eq!(peer_seq(&world.payer, payer_side), first + 1);
    let heard_now = world
        .payer
        .read(|repos| repos.contact(payer_side))
        .unwrap()
        .last_sealed_in;
    assert!(heard_now > heard, "{heard:?} then {heard_now:?}");

    // A second check within the hour is taken and dropped.
    advance(&world, 10 * MINUTE);
    check(&world, &world.payer, payer_side).unwrap();
    world.collect(&world.issuer);
    assert_eq!(own_seq(&world.issuer, issuer_side), first + 1);

    // An hour later each is answered, up to three in the day.
    for answered in 2..=3 {
        advance(&world, HOUR);
        check(&world, &world.payer, payer_side).unwrap();
        world.collect(&world.issuer);
        assert_eq!(own_seq(&world.issuer, issuer_side), first + answered);
    }
    advance(&world, HOUR);
    check(&world, &world.payer, payer_side).unwrap();
    world.collect(&world.issuer);
    assert_eq!(own_seq(&world.issuer, issuer_side), first + 3);

    // A day after the first answer, checks are answered again.
    advance(&world, 22 * HOUR);
    check(&world, &world.payer, payer_side).unwrap();
    world.collect(&world.issuer);
    assert_eq!(own_seq(&world.issuer, issuer_side), first + 4);
}

/// An ended pairing and a missing contact take no check and do not move; the side that ended
/// it has no record left to check.
#[test]
fn an_ended_pairing_takes_no_check_and_does_not_move() {
    let world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_unpair(&relays(&world.issuer), issuer_side)
            )
            .unwrap()
    );
    world.collect(&world.payer);
    world.collect(&world.payer);

    assert!(matches!(
        check(&world, &world.payer, payer_side),
        Err(ContactError::Ended)
    ));
    assert!(matches!(
        check(&world, &world.issuer, issuer_side),
        Err(ContactError::UnknownContact)
    ));
    assert!(matches!(
        check(&world, &world.payer, ContactId([7; 16])),
        Err(ContactError::UnknownContact)
    ));
    let moved = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_move_home(&with_relay2(&world.payer), "relay2.test:80"),
        )
        .unwrap();
    assert_eq!(moved, 0);
    let mailbox = world
        .payer
        .read(|repos| repos.contact_mailbox(payer_side))
        .unwrap();
    assert_eq!(mailbox.home_relay, "relay.test:80");
}

/// A private pairing carries no check and keeps its relay when the wallet moves.
#[test]
fn a_private_pairing_carries_no_check_and_keeps_its_relay() {
    let world = World::new();
    let invite = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                class: PairingClass::Private,
                ..invite_request("Phone")
            },
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.contact_book().pairing_accept(
            &relays(&world.payer),
            AcceptRequest {
                class: PairingClass::Private,
                ..accept(&invite.link, "Desk", false)
            },
        ))
        .unwrap();
    assert_eq!(world.collect(&world.issuer).paired, 1);
    assert_eq!(world.collect(&world.payer).paired, 1);

    assert!(matches!(
        check(&world, &world.issuer, invite.contact_id),
        Err(ContactError::WrongClass)
    ));
    let moved = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_move_home(&with_relay2(&world.issuer), "relay2.test:80"),
        )
        .unwrap();
    assert_eq!(moved, 0);
    let mailbox = world
        .issuer
        .read(|repos| repos.contact_mailbox(invite.contact_id))
        .unwrap();
    assert_eq!(mailbox.home_relay, "relay.test:80");
}

/// The mover tells each contact once and reads only its new mailbox from then on; a contact that
/// follows reaches it there, and the mover takes the follower's card without being asked to move.
#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_wallet_moving_its_home_relay_tells_each_contact_once_and_does_not_drain() {
    let world = World::new();
    // relay.test and relay2.test are separate relays, so the old mailbox is a queue of its own.
    world.relay.set_relays_apart(true);
    let (issuer_side, payer_side) = world.pair_by_link();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let mut payer_events = world.payer.wallet.subscribe();
    let moving = with_relay2(&world.issuer);
    let before = world
        .issuer
        .read(|repos| repos.contact_mailbox(issuer_side))
        .unwrap();
    let seq = own_seq(&world.issuer, issuer_side);
    let collect_issuer = || {
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contacts_collect(&moving, lepic_wallet_contacts::CollectTrigger::Open),
            )
            .unwrap()
    };
    let read = collect_issuer().mailboxes;

    assert!(matches!(
        world.block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_move_home(&moving, "relay2.test:0")
        ),
        Err(ContactError::RelayAddress)
    ));
    let moved = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_move_home(&moving, " Relay2.test:80 "),
        )
        .unwrap();
    assert_eq!(moved, 1);
    let after = world
        .issuer
        .read(|repos| repos.contact_mailbox(issuer_side))
        .unwrap();
    assert_eq!(after.home_relay, "relay2.test:80");
    assert!(after.our_mailbox.ends_with("@relay2.test:80"), "{after:?}");
    assert_eq!(after.peer_mailbox, before.peer_mailbox);
    assert_eq!(after.previous, None);
    assert_eq!(own_seq(&world.issuer, issuer_side), seq + 1);
    // Moved once, a second move to the same relay tells nobody.
    assert_eq!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contacts_move_home(&moving, "relay2.test:80")
            )
            .unwrap(),
        0
    );

    // A check sent before the contact follows goes to the old mailbox, which nobody reads.
    let old = EpicboxAddress::parse(&before.our_mailbox, RelayNetwork::Floonet).unwrap();
    let left = world.relay.pending(&old);
    check(&world, &world.payer, payer_side).unwrap();
    assert_eq!(world.relay.pending(&old), left + 1);
    // The mover reads as many mailboxes as before, none of them the old one.
    assert_eq!(collect_issuer().mailboxes, read);
    assert_eq!(world.relay.pending(&old), left + 1);

    // The contact takes the update and is asked to follow; once its host applies it, its card
    // reaches the mover's new mailbox.
    let follower = with_relay2(&world.payer);
    let collect_payer = || {
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .contacts_collect(&follower, lepic_wallet_contacts::CollectTrigger::Open),
            )
            .unwrap()
    };
    collect_payer();
    assert_eq!(
        move_requests(events(&mut payer_events)),
        vec!["relay2.test:80".to_owned()]
    );
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .apply_relay_move(payer_side, "relay2.test:80"),
        )
        .unwrap();
    let followed = world
        .payer
        .read(|repos| repos.contact_mailbox(payer_side))
        .unwrap();
    assert_eq!(followed.peer_mailbox, after.our_mailbox);
    assert!(followed.our_mailbox.ends_with("@relay2.test:80"));
    collect_payer();

    collect_issuer();
    let met = world
        .issuer
        .read(|repos| repos.contact_mailbox(issuer_side))
        .unwrap();
    assert_eq!(met.peer_mailbox, followed.our_mailbox);
    assert_eq!(met.home_relay, "relay2.test:80");
    assert_eq!(met.previous, None);
    assert!(move_requests(events(&mut issuer_events)).is_empty());
    // The old mailbox still holds the check nobody read.
    assert_eq!(world.relay.pending(&old), left + 1);
}
