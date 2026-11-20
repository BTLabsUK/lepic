// SPDX-License-Identifier: Apache-2.0
//! The contact, pairing and previous-home mailboxes as the watch set carries them: read by push
//! only, each row kept equal to the records it comes from, mail stored before its
//! acknowledgement was lost handled once when the relay offers it again, how many mailboxes
//! each contact and pairing takes on a socket, and a pairing kept in progress while its mailbox
//! has mail on hold or is carried by another socket.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::epicbox_world as world;
use crate::pairing_helpers as helpers;

use std::time::{Duration, Instant};

use helpers::{HOUR, MINUTE, accept, events, invite_request, relays};
use lepic_contact::{ContactCard, Invite, Network as ContactNetwork};
use lepic_epicbox::sessions::PushedConfig;
use lepic_epicbox::{
    Backoff, ClientSettings, Domain, EpicboxAddress, MuxOptions, MuxState, Network as RelayNetwork,
    RelayEndpoint, Security,
};
use lepic_store::{ContactId, MailClass, PairingRole, WatchRow};
use lepic_wallet::{Clock as _, Event};
use lepic_wallet_contacts::{
    CLOCK_SKEW, CollectReport, CollectTrigger, ContactRelays, LATE_DRAIN_WAIT, PairingEndReason,
    UPDATES_PER_CONTACT_PER_DAY, WalletContacts,
};
use rand::SeedableRng;
use world::{Party, World};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const HOME: &str = "relay.test:80";
const OTHER: &str = "relay2.test:80";
const GROUP: &str = "contacts";
const CONTACT_CLASSES: [MailClass; 3] = [
    MailClass::Contact,
    MailClass::Pairing,
    MailClass::PreviousHome,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The party's relays with `relay2.test:80` built in, as a host that offers it would pass them.
fn with_relay2(party: &Party) -> ContactRelays {
    helpers::adding(
        relays(party),
        vec![RelayEndpoint::new(
            Domain::parse("relay2.test").unwrap(),
            Some(80),
            Security::Plain,
        )],
    )
}

fn collect(
    world: &World,
    party: &Party,
    relays: &ContactRelays,
    trigger: CollectTrigger,
) -> CollectReport {
    world
        .block_on(
            party
                .wallet
                .contact_book()
                .contacts_collect(relays, trigger),
        )
        .unwrap()
}

/// Has the party's contact sessions started from now on hold each acknowledgement for an hour,
/// so a test can lose it with the socket.
fn hold_acks(party: &Party) {
    party.epicbox.pushed().clear();
    party.epicbox.pushed().set_contacts(Some(PushedConfig {
        group: GROUP.to_owned(),
        options: MuxOptions::default().with_ack_window(HOUR),
    }));
}

/// Runs `post` and waits until the party's contact session on `relay` has queued what it
/// brought.
fn queued_after(world: &World, party: &Party, relay: &str, post: impl FnOnce()) {
    let session = party
        .epicbox
        .pushed()
        .get(relay, GROUP)
        .expect("a contacts session on the relay");
    let mut queued = session.queued();
    post();
    world.block_on(world.within(queued.changed())).unwrap();
}

/// The relay closes every socket before the issuer's held acknowledgements leave, and the
/// issuer's wallet is opened again on its store with Epicbox built from `settings`.
fn lose_acks_and_reopen(world: &mut World, settings: ClientSettings) {
    // No task runs between the two: the sessions stop with the acknowledgements unsent.
    world.relay.disconnect_all();
    world.issuer.epicbox.pushed().clear();
    let reopened = world
        .issuer
        .reopened_with(settings, &world.node, &world.relay, &world.runtime);
    let old = std::mem::replace(&mut world.issuer, reopened);
    old.wallet.close();
}

fn wait_gone(world: &World, mailbox: &EpicboxAddress) {
    world.block_on(world.within(world.relay.wait_until(|relay| relay.pending(mailbox) == 0)));
}

fn our_mailbox(party: &Party, contact: ContactId) -> EpicboxAddress {
    let mailbox = party
        .read(|repos| repos.contact_mailbox(contact))
        .unwrap()
        .our_mailbox;
    EpicboxAddress::parse(&mailbox, RelayNetwork::Floonet).unwrap()
}

fn peer_seq(party: &Party, contact: ContactId) -> u32 {
    party
        .read(|repos| repos.contact(contact))
        .unwrap()
        .peer
        .unwrap()
        .seq
}

fn count(events: &[Event], wanted: fn(&Event) -> bool) -> usize {
    events.iter().filter(|event| wanted(event)).count()
}

/// The payer's card for its pairing with the issuer, made again with `seq`, sealed as a contact
/// update and posted to the mailbox the payer's stored card of the issuer names.
fn post_update(world: &World, ben_side: ContactId, seq: u32) {
    let record = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    let keys = lepic_wallet_contacts::contact_root(
        &world.payer.keychain(),
        &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
        lepic_primitives::params::Network::Floonet,
    )
    .unwrap()
    .contact_keys(record.slot, record.box_salt)
    .unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let mut fields = own.fields().clone();
    fields.seq = seq;
    let card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(u64::from(seq));
    let envelope = lepic_contact::seal_contact_update(&peer, &card, &signer, &mut rng).unwrap();
    let from = lepic_epicbox::Identity::new(
        keys.expose_box_secret().clone(),
        EpicboxAddress::new(
            *keys.box_public_key(),
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        ),
    )
    .unwrap();
    let to = EpicboxAddress::parse(peer.fields().mailbox.as_str(), RelayNetwork::Floonet).unwrap();
    world
        .block_on(
            lepic_epicbox::MailboxClient::new(world::settings(), world.relay.connector()).post(
                &from,
                &to,
                &lepic_contact::armor(&envelope),
            ),
        )
        .unwrap();
}

/// The reply mailbox of an invite on the test relay.
fn reply_mailbox(link: &str) -> EpicboxAddress {
    let invite = Invite::from_link(link, ContactNetwork::Floonet).unwrap();
    let (box_sk, _) = lepic_wallet_contacts::pairing_mailbox_keys(
        invite.fields().code.expose_bytes(),
        lepic_primitives::params::Network::Floonet,
    )
    .unwrap();
    EpicboxAddress::new(
        lepic_crypto::PublicKey::from_secret_key(&box_sk).unwrap(),
        RelayNetwork::Floonet,
        Domain::parse("relay.test").unwrap(),
        Some(80),
    )
}

fn old_salt_key(contact: ContactId) -> String {
    format!("contact.oldsalt.{}", hex(&contact.0))
}

/// Records an old box salt for the contact, as moving an in-person pairing's mailbox does.
fn set_old_salt(party: &Party, contact: ContactId) {
    party.write(|repos| {
        repos.put_setting(
            &old_salt_key(contact),
            &format!("{{\"salt\":\"{}\"}}", hex(&[7; 16])),
        )
    });
}

/// The contact rows of the party's watch set.
fn contact_rows(party: &Party) -> Vec<WatchRow> {
    let mut rows: Vec<WatchRow> = party
        .read(|repos| repos.watch_set())
        .into_iter()
        .filter(|row| CONTACT_CLASSES.contains(&row.class))
        .collect();
    rows.sort_by_key(|row| {
        (
            row.relay.clone(),
            row.key_ref.clone(),
            format!("{:?}", row.class),
        )
    });
    rows
}

/// The rows of the other classes in the party's watch set, past those of the public address,
/// which an issuing install watches on every relay.
fn other_rows(party: &Party) -> Vec<WatchRow> {
    party
        .read(|repos| repos.watch_set())
        .into_iter()
        .filter(|row| !CONTACT_CLASSES.contains(&row.class) && row.key_ref != PUBLIC_ADDRESS)
        .collect()
}

/// The key of the watch rows of account 0's public address.
const PUBLIC_ADDRESS: &str = "address:0.0";

/// The relays a pairing or contact mailbox is watched on, as the rows name them: every relay of
/// `relays`' list, and `hint`, the relay the invite or the card names, when the list lacks it.
fn places(relays: &ContactRelays, hint: &str) -> Vec<String> {
    let mut places: Vec<String> = relays
        .list()
        .iter()
        .map(|endpoint| format!("{}:{}", endpoint.domain(), endpoint.port()))
        .collect();
    if !places.iter().any(|place| place == hint) {
        places.push(hint.to_owned());
    }
    places
}

/// The contact rows the party's records call for now, written out from the records: per
/// pairing in progress one on each of its [`places`] until its late drain ends, and per paired
/// contact one for its current mailbox and one for an old box salt on each of its places, and
/// one for the previous home while it is drained and the list does not hold it.
fn expected_rows(party: &Party, relays: &ContactRelays) -> Vec<WatchRow> {
    let now = party.clock.now();
    let mut rows = Vec::new();
    for pending in party.read(|repos| repos.pending_pairings()) {
        let (seed, deadline) = match pending.role {
            PairingRole::Inviter => (
                pending.secrets.code,
                pending.expires_at.checked_add(CLOCK_SKEW).unwrap(),
            ),
            PairingRole::Invitee => (pending.secrets.rc, pending.expires_at),
        };
        if seed.is_none() {
            continue;
        }
        let invite = Invite::decode(&pending.invite, ContactNetwork::Floonet).unwrap();
        for relay in places(relays, invite.fields().home_relay.as_str()) {
            rows.push(WatchRow {
                key_ref: format!("pairing:{}", hex(&pending.pairing_id.0)),
                relay,
                class: MailClass::Pairing,
                expires_at: Some(deadline.checked_add(LATE_DRAIN_WAIT).unwrap()),
            });
        }
    }
    for record in party.read(|repos| repos.contacts()) {
        if record.peer.is_none() || record.facts.ended_reason == Some(PairingEndReason::Mismatch) {
            continue;
        }
        let Some(mailbox) = party.read(|repos| repos.contact_mailbox(record.contact_id)) else {
            continue;
        };
        let id = hex(&record.contact_id.0);
        let places = places(relays, &mailbox.home_relay);
        let old_salt = party
            .read(|repos| repos.setting(&old_salt_key(record.contact_id)))
            .is_some();
        for relay in &places {
            rows.push(WatchRow {
                key_ref: format!("contact:{id}"),
                relay: relay.clone(),
                class: MailClass::Contact,
                expires_at: None,
            });
            if old_salt {
                rows.push(WatchRow {
                    key_ref: format!("contact-old-salt:{id}"),
                    relay: relay.clone(),
                    class: MailClass::Contact,
                    expires_at: None,
                });
            }
        }
        if let Some(previous) = mailbox
            .previous
            .filter(|previous| previous.until > now && !places.contains(&previous.relay))
        {
            rows.push(WatchRow {
                key_ref: format!("contact:{id}"),
                relay: previous.relay,
                class: MailClass::PreviousHome,
                expires_at: Some(previous.until),
            });
        }
    }
    rows.sort_by_key(|row| {
        (
            row.relay.clone(),
            row.key_ref.clone(),
            format!("{:?}", row.class),
        )
    });
    rows
}

/// Has the party watch its mailboxes again, which makes the rows equal the records, and checks
/// that the contact rows do and that no row of another class is left: the party holds no link,
/// payment or in-person record.
fn reconciled(world: &World, party: &Party, relays: &ContactRelays) {
    world.block_on(party.wallet.contact_book().claim_pushed(relays));
    assert_eq!(contact_rows(party), expected_rows(party, relays));
    assert_eq!(other_rows(party), []);
}

fn relays_of(rows: &[WatchRow]) -> Vec<&str> {
    rows.iter().map(|row| row.relay.as_str()).collect()
}

fn rows_of(party: &Party, class: MailClass) -> Vec<WatchRow> {
    contact_rows(party)
        .into_iter()
        .filter(|row| row.class == class)
        .collect()
}

/// Rows of the other classes that no record backs, as an earlier schema's fill could write
/// them: one on each relay, one expiring.
fn put_other_rows(party: &Party) {
    let rows = vec![
        WatchRow {
            key_ref: "link:0".to_owned(),
            relay: HOME.to_owned(),
            class: MailClass::Address,
            expires_at: None,
        },
        WatchRow {
            key_ref: "in-person:0".to_owned(),
            relay: OTHER.to_owned(),
            class: MailClass::InPerson,
            expires_at: Some(party.clock.now().checked_add(400 * DAY).unwrap()),
        },
    ];
    for row in &rows {
        party.write(|repos| repos.put_watch(row));
    }
    assert_eq!(other_rows(party).len(), rows.len());
}

/// A contact update the issuer stored before its acknowledgement was lost is offered again
/// when the wallet is opened again, and taken once: no second event, the card as it was, and
/// the relay ends with the mail gone.
#[test]
fn a_contact_update_stored_before_its_ack_was_lost_is_handled_once() {
    let mut world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    hold_acks(&world.issuer);
    collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );
    let mailbox = our_mailbox(&world.issuer, issuer_side);
    let mut issuer_events = world.issuer.wallet.subscribe();

    queued_after(&world, &world.issuer, HOME, || {
        post_update(&world, payer_side, 2);
    });
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Push,
    );
    assert_eq!(report.messages, 1);
    let taken = events(&mut issuer_events);
    assert_eq!(
        count(&taken, |event| matches!(event, Event::ContactUpdated(_))),
        1
    );
    assert_eq!(peer_seq(&world.issuer, issuer_side), 2);
    assert_eq!(world.relay.pending(&mailbox), 1, "the ack is held");

    lose_acks_and_reopen(&mut world, world::settings());
    let mut reopened_events = world.issuer.wallet.subscribe();
    collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );
    wait_gone(&world, &mailbox);

    let session = world.issuer.epicbox.pushed().get(HOME, GROUP).unwrap();
    assert_eq!(session.counters().mails, 1, "the relay offered it again");
    assert!(events(&mut reopened_events).is_empty());
    assert_eq!(peer_seq(&world.issuer, issuer_side), 2);
}

/// A pairing reply the inviter stored before its acknowledgement was lost is offered again
/// after the wallet is opened again and pairs nothing more; the pairing then completes.
#[test]
fn a_pairing_reply_stored_before_its_ack_was_lost_is_handled_once() {
    let mut world = World::new();
    hold_acks(&world.issuer);
    let link = world.invite(&world.issuer, "Anna");
    collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );
    let mailbox = reply_mailbox(&link);
    let mut issuer_events = world.issuer.wallet.subscribe();

    queued_after(&world, &world.issuer, HOME, || {
        let answered = world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert!(answered.posted);
    });
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Push,
    );
    assert_eq!(report.paired, 1);
    let taken = events(&mut issuer_events);
    assert_eq!(
        count(&taken, |event| matches!(event, Event::PairingReplied(_))),
        1
    );
    assert_eq!(world.relay.pending(&mailbox), 1, "the ack is held");
    let contacts = world.contact_ids(&world.issuer);
    assert_eq!(contacts.len(), 1);

    lose_acks_and_reopen(&mut world, world::settings());
    let mut reopened_events = world.issuer.wallet.subscribe();
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );
    assert_eq!(report.paired, 0);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    wait_gone(&world, &mailbox);
    let session = world.issuer.epicbox.pushed().get(HOME, GROUP).unwrap();
    assert!(session.counters().mails >= 1, "the relay offered it again");
    assert!(events(&mut reopened_events).is_empty());
    assert_eq!(world.contact_ids(&world.issuer), contacts);

    // The pairing completes as if nothing had come twice.
    assert_eq!(world.collect(&world.payer).paired, 1);
    world.collect(&world.issuer);
    let ben_side = world.only_contact(&world.payer);
    assert_eq!(
        world.sas(&world.issuer, contacts[0]),
        world.sas(&world.payer, ben_side)
    );
}

/// A contact update that reached the previous home while it is drained, stored before its
/// acknowledgement was lost, is offered again there after the wallet is opened again and taken
/// once.
#[test]
fn a_contact_update_at_the_previous_home_stored_before_its_ack_was_lost_is_handled_once() {
    let mut world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_side, payer_side) = world.pair_by_link();
    let old = our_mailbox(&world.issuer, issuer_side);
    hold_acks(&world.issuer);
    let moving = with_relay2(&world.issuer);
    let moved =
        world
            .block_on(world.issuer.wallet.contact_book().contacts_move_home(
                &moving,
                OTHER,
                30 * DAY,
            ))
            .unwrap();
    assert_eq!(moved, 1);
    // The contact misses the move and still writes to the old mailbox.
    world.relay.expire_all();
    collect(&world, &world.issuer, &moving, CollectTrigger::Open);
    let mut issuer_events = world.issuer.wallet.subscribe();

    queued_after(&world, &world.issuer, HOME, || {
        post_update(&world, payer_side, 2);
    });
    let report = collect(&world, &world.issuer, &moving, CollectTrigger::Push);
    assert_eq!(report.messages, 1);
    let taken = events(&mut issuer_events);
    assert_eq!(
        count(&taken, |event| matches!(event, Event::ContactUpdated(_))),
        1
    );
    assert_eq!(peer_seq(&world.issuer, issuer_side), 2);
    assert_eq!(world.relay.pending(&old), 1, "the ack is held");

    lose_acks_and_reopen(&mut world, world::settings());
    let mut reopened_events = world.issuer.wallet.subscribe();
    collect(
        &world,
        &world.issuer,
        &with_relay2(&world.issuer),
        CollectTrigger::Open,
    );
    wait_gone(&world, &old);
    let session = world.issuer.epicbox.pushed().get(HOME, GROUP).unwrap();
    assert_eq!(session.counters().mails, 1, "the relay offered it again");
    assert!(events(&mut reopened_events).is_empty());
    assert_eq!(peer_seq(&world.issuer, issuer_side), 2);
}

/// The contact rows follow the records through a pairing's whole life, an old box salt set
/// and forgotten, a move of the wallet's own home to another relay of its list, a contact's
/// move followed, the end of the drain and an unpair; rows of other classes that no record
/// backs are removed.
#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn the_contact_rows_follow_the_records() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issuer_relays = with_relay2(&world.issuer);
    let payer_relays = with_relay2(&world.payer);
    put_other_rows(&world.issuer);
    put_other_rows(&world.payer);
    let advance = |by: Duration| {
        world.issuer.clock.advance(by);
        world.payer.clock.advance(by);
    };

    // A pairing made: the reply mailbox on each relay of the list, until the inviter's
    // deadline and the late drain.
    let link = world.invite(&world.issuer, "Anna");
    reconciled(&world, &world.issuer, &issuer_relays);
    let pending = world.issuer.read(|repos| repos.pending_pairings());
    let rows = rows_of(&world.issuer, MailClass::Pairing);
    assert_eq!(relays_of(&rows), [HOME, OTHER]);
    assert!(
        rows.iter()
            .all(|row| row.expires_at == Some(pending[0].expires_at + CLOCK_SKEW + LATE_DRAIN_WAIT))
    );

    // Answered: the confirm mailbox on the invitee's side.
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&payer_relays, accept(&link, "Ben", false)),
        )
        .unwrap();
    reconciled(&world, &world.payer, &payer_relays);
    assert_eq!(
        relays_of(&rows_of(&world.payer, MailClass::Pairing)),
        [HOME, OTHER]
    );

    // Completed on both sides: each has its contact's mailbox.
    assert_eq!(
        collect(&world, &world.issuer, &issuer_relays, CollectTrigger::Open).paired,
        1
    );
    reconciled(&world, &world.issuer, &issuer_relays);
    assert_eq!(
        collect(&world, &world.payer, &payer_relays, CollectTrigger::Open).paired,
        1
    );
    reconciled(&world, &world.payer, &payer_relays);
    collect(&world, &world.issuer, &issuer_relays, CollectTrigger::Open);
    reconciled(&world, &world.issuer, &issuer_relays);
    let issuer_side = world.only_contact(&world.issuer);
    let payer_side = answered.contact_id;
    let contact_ref = format!("contact:{}", hex(&issuer_side.0));
    let rows = rows_of(&world.issuer, MailClass::Contact);
    assert_eq!(relays_of(&rows), [HOME, OTHER]);
    assert!(rows.iter().all(|row| row.key_ref == contact_ref));
    assert_eq!(
        relays_of(&rows_of(&world.payer, MailClass::Contact)),
        [HOME, OTHER]
    );

    // Past every deadline and late drain no pairing row is left.
    advance(DAY + CLOCK_SKEW + LATE_DRAIN_WAIT + MINUTE);
    collect(&world, &world.issuer, &issuer_relays, CollectTrigger::Open);
    collect(&world, &world.payer, &payer_relays, CollectTrigger::Open);
    reconciled(&world, &world.issuer, &issuer_relays);
    reconciled(&world, &world.payer, &payer_relays);
    assert!(rows_of(&world.issuer, MailClass::Pairing).is_empty());
    assert!(rows_of(&world.payer, MailClass::Pairing).is_empty());

    // A pairing made and ended takes its row with it.
    let invited = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&issuer_relays, invite_request("Anna")),
        )
        .unwrap();
    reconciled(&world, &world.issuer, &issuer_relays);
    assert_eq!(
        relays_of(&rows_of(&world.issuer, MailClass::Pairing)),
        [HOME, OTHER]
    );
    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_remove(invited.contact_id)
            )
            .unwrap()
    );
    reconciled(&world, &world.issuer, &issuer_relays);
    assert!(rows_of(&world.issuer, MailClass::Pairing).is_empty());

    // An old box salt is read beside the current mailbox until the contact writes to the
    // current one.
    set_old_salt(&world.issuer, issuer_side);
    reconciled(&world, &world.issuer, &issuer_relays);
    let old_salt_ref = format!("contact-old-salt:{}", hex(&issuer_side.0));
    assert!(
        rows_of(&world.issuer, MailClass::Contact)
            .iter()
            .any(|row| row.key_ref == old_salt_ref && row.relay == HOME)
    );
    post_update(&world, payer_side, 2);
    collect(&world, &world.issuer, &issuer_relays, CollectTrigger::Open);
    assert_eq!(peer_seq(&world.issuer, issuer_side), 2);
    reconciled(&world, &world.issuer, &issuer_relays);
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.setting(&old_salt_key(issuer_side))),
        None
    );
    assert_eq!(rows_of(&world.issuer, MailClass::Contact).len(), 2);

    // The wallet's own move: the old home is still on the list, so it is read as before and
    // the drain adds no row.
    assert_eq!(
        world
            .block_on(world.issuer.wallet.contact_book().contacts_move_home(
                &issuer_relays,
                OTHER,
                30 * DAY
            ))
            .unwrap(),
        1
    );
    reconciled(&world, &world.issuer, &issuer_relays);
    let rows = contact_rows(&world.issuer);
    assert!(rows.contains(&WatchRow {
        key_ref: contact_ref.clone(),
        relay: OTHER.to_owned(),
        class: MailClass::Contact,
        expires_at: None,
    }));
    assert!(rows.contains(&WatchRow {
        key_ref: contact_ref.clone(),
        relay: HOME.to_owned(),
        class: MailClass::Contact,
        expires_at: None,
    }));
    assert!(rows_of(&world.issuer, MailClass::PreviousHome).is_empty());

    // The contact follows: its mailbox moves to the new relay, still read on both.
    collect(&world, &world.payer, &payer_relays, CollectTrigger::Open);
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .apply_relay_move(payer_side, OTHER),
        )
        .unwrap();
    reconciled(&world, &world.payer, &payer_relays);
    assert_eq!(
        relays_of(&rows_of(&world.payer, MailClass::Contact)),
        [HOME, OTHER]
    );

    // The drain ends: still no previous home's row.
    advance(31 * DAY);
    reconciled(&world, &world.issuer, &issuer_relays);
    assert!(rows_of(&world.issuer, MailClass::PreviousHome).is_empty());

    // Unpaired: nothing of the contact is watched.
    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_unpair(&issuer_relays, issuer_side)
            )
            .unwrap()
    );
    reconciled(&world, &world.issuer, &issuer_relays);
    assert!(contact_rows(&world.issuer).is_empty());
}

/// A pairing row an earlier schema's fill wrote with the invite's own expiry, too early for the
/// inviter's late drain, is corrected by the next collect; rows of other classes that no record
/// backs are removed.
#[test]
fn a_pairing_row_filled_with_the_invite_expiry_is_corrected() {
    let world = World::new();
    put_other_rows(&world.issuer);
    world.invite(&world.issuer, "Anna");
    let pending = world.issuer.read(|repos| repos.pending_pairings());
    let early = WatchRow {
        key_ref: format!("pairing:{}", hex(&pending[0].pairing_id.0)),
        relay: HOME.to_owned(),
        class: MailClass::Pairing,
        expires_at: Some(pending[0].expires_at),
    };
    world.issuer.write(|repos| repos.put_watch(&early));

    collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );

    assert_eq!(
        contact_rows(&world.issuer),
        vec![WatchRow {
            expires_at: Some(pending[0].expires_at + CLOCK_SKEW + LATE_DRAIN_WAIT),
            ..early
        }]
    );
    assert_eq!(other_rows(&world.issuer), []);
}

/// A contact with every kind of mailbox in use and a pairing in progress: the contact takes
/// three watched mailboxes and the pairing one. The wallet moved off a list that now holds only
/// the new home, so the previous home is read by the drain's row, the pairing on the list's
/// relay and on the relay its invite names.
#[test]
fn a_contact_with_every_mailbox_kind_and_a_pairing_take_four_watched_mailboxes() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_side, _) = world.pair_by_link();
    // The finished pairing's reply mailbox is watched until its late drain ends.
    world
        .issuer
        .clock
        .advance(DAY + CLOCK_SKEW + LATE_DRAIN_WAIT + MINUTE);
    world.collect(&world.issuer);
    assert!(rows_of(&world.issuer, MailClass::Pairing).is_empty());
    let moving = helpers::only_relay2(&world, &world.issuer);
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_move_home(&moving, OTHER, 30 * DAY),
        )
        .unwrap();
    set_old_salt(&world.issuer, issuer_side);
    world.invite(&world.issuer, "Anna");

    let report = collect(&world, &world.issuer, &moving, CollectTrigger::Open);

    // And the public address's delivery mailbox on the one relay of the list.
    assert_eq!(report.mailboxes, 5 + 1);
    let watched = |relay: &str| {
        moving
            .epicbox
            .pushed()
            .get(relay, GROUP)
            .unwrap()
            .claimed_keys("contacts")
            .len()
    };
    // The current mailbox, the old salt's, the pairing's reply mailbox and the public address's
    // delivery mailbox on the new home; the previous home and the pairing's reply mailbox again
    // on the relay the invite names.
    assert_eq!(watched(OTHER), 4);
    assert_eq!(watched(HOME), 2);
    let rows = contact_rows(&world.issuer);
    let contact_ref = format!("contact:{}", hex(&issuer_side.0));
    assert_eq!(
        rows.iter()
            .filter(|row| row.key_ref.ends_with(&contact_ref[8..]))
            .count(),
        3
    );
    assert_eq!(rows_of(&world.issuer, MailClass::Pairing).len(), 2);
}

/// A relay that does not offer mux/1 is not read: it is reported unreachable, no `Subscribe`
/// reaches it, and its mail stays where it is.
#[test]
fn a_relay_without_mux_is_reported_unreachable_and_not_read() {
    let world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    let mailbox = our_mailbox(&world.issuer, issuer_side);
    world.relay.offer_mux(false);
    world.issuer.epicbox.pushed().clear();
    post_update(&world, payer_side, 2);
    let subscribes = world.relay.received("Subscribe");

    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );

    assert_eq!(report.unreachable, vec![HOME.to_owned()]);
    assert_eq!(report.messages, 0);
    assert_eq!(world.relay.received("Subscribe"), subscribes);
    assert_eq!(world.relay.pending(&mailbox), 1);
    assert_eq!(peer_seq(&world.issuer, issuer_side), 1);
}

/// With the relay refusing, the session waits an hour to reconnect. Once the relay is back, a
/// foreground tick keeps that wait, and a pull from the user reads the mail at once.
#[test]
fn a_pull_reads_at_once_from_a_relay_that_came_back() {
    let mut world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    let mailbox = our_mailbox(&world.issuer, issuer_side);
    let mut slow = world::settings();
    slow.backoff = Backoff {
        initial: HOUR,
        max: HOUR,
    };
    world.issuer.epicbox.pushed().clear();
    world.relay.set_refusing(true);
    lose_acks_and_reopen(&mut world, slow);

    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );
    assert_eq!(report.unreachable, vec![HOME.to_owned()]);
    let session = world.issuer.epicbox.pushed().get(HOME, GROUP).unwrap();
    assert!(
        matches!(*session.state().borrow(), MuxState::Waiting { .. }),
        "{:?}",
        *session.state().borrow()
    );

    world.relay.set_refusing(false);
    post_update(&world, payer_side, 2);
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Foreground,
    );
    assert_eq!(report.messages, 0);
    assert_eq!(world.relay.pending(&mailbox), 1);

    let mut issuer_events = world.issuer.wallet.subscribe();
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Pull,
    );
    assert_eq!(report.messages, 1);
    assert!(report.unreachable.is_empty(), "{:?}", report.unreachable);
    assert_eq!(peer_seq(&world.issuer, issuer_side), 2);
    assert_eq!(
        count(&events(&mut issuer_events), |event| matches!(
            event,
            Event::ContactUpdated(_)
        )),
        1
    );
    wait_gone(&world, &mailbox);
}

/// Store writes a push cycle makes before it takes its first mail. The test that fails the next
/// one checks that the reply was kept, so a cycle that writes more or less fails there.
const WRITES_BEFORE_MAIL: usize = 7;

/// An invite of the issuer's, with its reply mailbox, claimed by a first collect. Its deadline
/// is a day and [`CLOCK_SKEW`] away; a minute past it the late drain still runs.
fn invite_claimed(world: &World) -> (String, EpicboxAddress) {
    let link = world.invite(&world.issuer, "Anna");
    collect(
        world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Open,
    );
    let mailbox = reply_mailbox(&link);
    (link, mailbox)
}

fn pending_count(party: &Party) -> usize {
    party.read(|repos| repos.pending_pairings()).len()
}

/// A pairing reply the inviter kept on a failure that passes is on hold at the relay. A drain
/// past the invite's deadline while the hold lasts reads nothing of it and so does not end the
/// pairing; once the hold ends the reply is taken and the pairing completes.
#[test]
fn a_pairing_reply_on_hold_keeps_its_pairing_past_the_deadline() {
    let world = World::new();
    let (link, mailbox) = invite_claimed(&world);
    queued_after(&world, &world.issuer, HOME, || {
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
    });
    world.issuer.fail_write_after(WRITES_BEFORE_MAIL);
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Push,
    );
    assert_eq!(report.paired, 0);
    assert_eq!(world.relay.pending(&mailbox), 1, "the reply is kept");
    let pending = world.issuer.read(|repos| repos.pending_pairings());
    assert!(pending[0].secrets.na.is_some(), "the reply was not taken");

    world.issuer.clock.advance(DAY + CLOCK_SKEW + MINUTE);
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Foreground,
    );
    assert_eq!(report.messages, 0);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!((report.capped, report.not_reached), (0, 0));
    assert_eq!(pending_count(&world.issuer), 1);

    world.relay.end_holds();
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Foreground,
    );
    assert_eq!(report.paired, 1);
    assert_eq!(world.collect(&world.payer).paired, 1);
}

/// A second Epicbox of the same wallet claims the inviter's reply mailbox, so the relay takes it
/// off the first socket. A drain on the first past the invite's deadline counts the mailbox
/// replaced, not unreached, and leaves the pairing in progress.
#[test]
fn a_mailbox_taken_by_another_socket_is_counted_replaced_and_its_pairing_waits() {
    let world = World::new();
    invite_claimed(&world);
    let second =
        world
            .issuer
            .reopened_with(world::settings(), &world.node, &world.relay, &world.runtime);
    collect(&world, &second, &relays(&second), CollectTrigger::Open);

    world.issuer.clock.advance(DAY + CLOCK_SKEW + MINUTE);
    let report = collect(
        &world,
        &world.issuer,
        &relays(&world.issuer),
        CollectTrigger::Foreground,
    );
    // The reply mailbox and the public address's delivery mailbox.
    assert_eq!(report.replaced, 2);
    assert_eq!(report.not_reached, 0);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(pending_count(&world.issuer), 1);
    second.wallet.close();
}

/// A mailbox added to the list is watched on the next claim of the running wallet, and one
/// removed is let go, without a new process or a restart of the sessions.
#[test]
fn a_list_change_applies_to_the_running_sessions() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    world.pair_by_link();
    let claimed = |relays: &ContactRelays, relay: &str| {
        relays
            .epicbox
            .pushed()
            .get(relay, GROUP)
            .map_or(0, |session| session.claimed_keys(GROUP).len())
    };
    let home_only = relays(&world.issuer);
    let both = with_relay2(&world.issuer);

    reconciled(&world, &world.issuer, &home_only);
    assert!(claimed(&home_only, HOME) > 0);
    assert_eq!(claimed(&home_only, OTHER), 0);

    reconciled(&world, &world.issuer, &both);
    assert_eq!(claimed(&both, OTHER), claimed(&both, HOME));

    reconciled(&world, &world.issuer, &home_only);
    assert_eq!(claimed(&home_only, OTHER), 0);
    assert!(claimed(&home_only, HOME) > 0);
}

/// Contact updates that wait past what a few `Waiting` answers bring, read over back-to-back
/// foreground ticks by a session that may ask twice a window, from a relay that takes three a
/// window per socket, as Epicmail takes 60 a minute. No question is refused `rate_limited`, the
/// session keeps to its budget, the relay is never reported unreachable or its mailboxes not
/// reached, and every update is read.
#[test]
fn a_backlog_is_read_over_ticks_without_tripping_the_waiting_limit() {
    const UPDATES: u32 = 120;
    const BUDGET: u32 = 2;
    // The first ticks follow each other faster than a window: the session holds back the
    // questions past its budget and the tick reports those mailboxes capped.
    const RAPID_TICKS: u32 = 4;
    // Longer than the read rounds of a tick take, so the budget binds within one.
    let window = Duration::from_secs(3);
    let deadline = Instant::now() + Duration::from_secs(60);
    let world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    let mailbox = our_mailbox(&world.issuer, issuer_side);
    world.relay.limit_waiting(Some((BUDGET + 1, window)));
    world.issuer.epicbox.pushed().clear();
    world
        .issuer
        .epicbox
        .pushed()
        .set_contacts(Some(PushedConfig {
            group: GROUP.to_owned(),
            options: MuxOptions::default().with_waiting_budget(BUDGET, window),
        }));
    for seq in 2..UPDATES.saturating_add(2) {
        post_update(&world, payer_side, seq);
    }

    let mut capped = 0;
    let mut ticks = 0;
    loop {
        let report = collect(
            &world,
            &world.issuer,
            &relays(&world.issuer),
            CollectTrigger::Foreground,
        );
        assert!(report.unreachable.is_empty(), "{:?}", report.unreachable);
        assert_eq!(report.not_reached, 0, "tick {ticks}");
        capped += report.capped;
        ticks += 1;
        if ticks >= RAPID_TICKS && world.relay.pending(&mailbox) == 0 && report.capped == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{} still waiting after {ticks} ticks",
            world.relay.pending(&mailbox)
        );
    }

    assert!(
        capped > 0,
        "the session held back a question past its budget"
    );
    assert_eq!(world.relay.waiting_refused(), 0);
    let most = world.relay.most_waiting_within(window);
    assert!(most <= BUDGET as usize, "{most} Waiting within a window");
    // Every update was read; the card takes the first ones within the day's update limit.
    let limit = u32::try_from(UPDATES_PER_CONTACT_PER_DAY).unwrap();
    assert_eq!(peer_seq(&world.issuer, issuer_side), limit + 1);
}
