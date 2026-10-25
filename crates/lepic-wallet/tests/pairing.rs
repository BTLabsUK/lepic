//! Contact pairing between LEPIC wallets on the mock relay (RFC 0002 section 7 and the cases
//! file): by link through the pairing mailboxes, by hand, and in person, the SAS check, expiry,
//! removal, backup, and what a changed invite or reply does.

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

use helpers::{HOUR, MINUTE, accept, events, invite_request, relays, relays_with_words};
use lepic_contact::{
    ContactCard, ContactKind, EncSecretKey, Invite, InviteFields, Network as ContactNetwork,
    PairingLink, SealedEnvelope, open_reply, pairing_envelope_from_link, seal_reply,
};
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{Domain, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_store::{AccountIndex, ContactId, ContactState, WalletStore};
use lepic_wallet::Event;
use lepic_wallet::contact::{
    CardRequest, CollectTrigger, ContactError, ContactRelays, InviteExpiry, InviteRequest,
    KeysDecision, LinkOutcome, PairingFailure, RelayMode, SasDecision,
};
use lepic_wallet::event::{ContactEvent, FailedPairing};
use rand::SeedableRng;
use world::{Party, World};

#[test]
fn two_wallets_pair_by_link_through_the_relay_and_see_one_sas() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let mut payer_events = world.payer.wallet.subscribe();

    let (anna_side, ben_side) = world.pair_by_link();

    let issuer_view = world
        .block_on(world.issuer.wallet.contact(anna_side))
        .unwrap();
    let payer_view = world
        .block_on(world.payer.wallet.contact(ben_side))
        .unwrap();
    assert_eq!(issuer_view.state, ContactState::Paired);
    assert_eq!(payer_view.state, ContactState::Paired);
    assert_eq!(issuer_view.claimed_name.as_deref(), Some("Ben"));
    assert_eq!(payer_view.claimed_name.as_deref(), Some("Anna"));
    assert_eq!(
        world.sas(&world.issuer, anna_side),
        world.sas(&world.payer, ben_side)
    );
    // Both mailboxes live on the inviter's relay.
    assert_eq!(issuer_view.home_relay.as_deref(), Some("relay.test:80"));
    assert_eq!(payer_view.home_relay.as_deref(), Some("relay.test:80"));
    assert!(
        events(&mut issuer_events).contains(&Event::PairingReplied(ContactEvent {
            contact_id: anna_side
        }))
    );
    assert!(
        events(&mut payer_events).contains(&Event::PairingConfirmed(ContactEvent {
            contact_id: ben_side
        }))
    );
    // Nothing is left to collect, and pairing never touched the payments addresses.
    assert_eq!(world.collect(&world.issuer).messages, 0);
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(world.relay.pending(&world.payer.address), 0);
}

#[test]
fn a_pairing_by_hand_needs_no_relay() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", true)),
        )
        .unwrap();
    assert!(!answered.posted);
    world.relay.set_refusing(true);

    let confirm = world
        .block_on(
            world
                .issuer
                .wallet
                .pairing_enter_link(&relays(&world.issuer), &answered.reply_link),
        )
        .unwrap();
    let LinkOutcome::Confirm { contact_id, link } = confirm else {
        panic!("unexpected {confirm:?}");
    };
    let paired = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_enter_link(&relays(&world.payer), &link),
        )
        .unwrap();

    assert_eq!(
        paired,
        LinkOutcome::Paired {
            contact_id: answered.contact_id
        }
    );
    assert_eq!(
        world.sas(&world.issuer, contact_id),
        world.sas(&world.payer, answered.contact_id)
    );
}

#[test]
fn two_phones_pair_in_person_by_scanning_each_others_card() {
    let world = World::new();
    let show = |party: &Party, name: &str| {
        world
            .block_on(party.wallet.pairing_show_card(
                &relays(party),
                CardRequest {
                    account: AccountIndex(0),
                    name: name.to_owned(),
                    kind: ContactKind::Person,
                },
            ))
            .unwrap()
    };
    let anna = show(&world.issuer, "Anna");
    let ben = show(&world.payer, "Ben");

    let on_issuer = world
        .block_on(world.issuer.wallet.pairing_scan_card(
            &relays(&world.issuer),
            anna.contact_id,
            &ben.link,
        ))
        .unwrap();
    let on_payer = world
        .block_on(world.payer.wallet.pairing_scan_card(
            &relays(&world.payer),
            ben.contact_id,
            &anna.link,
        ))
        .unwrap();

    assert_eq!(on_issuer.state, ContactState::Paired);
    assert_eq!(on_issuer.sas, on_payer.sas);
    assert!(on_issuer.sas.is_some());
    // A card already paired is not taken twice.
    let again = show(&world.issuer, "Anna");
    assert!(matches!(
        world.block_on(world.issuer.wallet.pairing_scan_card(
            &relays(&world.issuer),
            again.contact_id,
            &ben.link,
        )),
        Err(ContactError::AlreadyPaired)
    ));
    // Nor is a wallet's own card.
    assert!(matches!(
        world.block_on(world.issuer.wallet.pairing_scan_card(
            &relays(&world.issuer),
            again.contact_id,
            &again.link,
        )),
        Err(ContactError::AlreadyPaired)
    ));
}

#[test]
fn the_sas_check_verifies_or_deletes_and_only_verified_contacts_send_invoices() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let wallet = &world.issuer.wallet;

    assert!(matches!(
        world.block_on(wallet.contact_set_allow_invoices(anna_side, true)),
        Err(ContactError::NotVerified)
    ));
    world
        .block_on(wallet.pairing_sas(&relays(&world.issuer), anna_side, SasDecision::Skip))
        .unwrap();
    assert_eq!(
        world.block_on(wallet.contact(anna_side)).unwrap().state,
        ContactState::Paired
    );
    world
        .block_on(wallet.pairing_sas(&relays(&world.issuer), anna_side, SasDecision::Match))
        .unwrap();
    let view = world.block_on(wallet.contact(anna_side)).unwrap();
    assert_eq!(view.state, ContactState::Verified);
    assert!(view.verified_at.is_some());
    world
        .block_on(wallet.contact_set_allow_invoices(anna_side, true))
        .unwrap();
    assert!(
        world
            .block_on(wallet.contact(anna_side))
            .unwrap()
            .allow_invoices
    );

    world
        .block_on(world.payer.wallet.pairing_sas(
            &relays(&world.payer),
            ben_side,
            SasDecision::Mismatch,
        ))
        .unwrap();
    assert!(
        world
            .block_on(world.payer.wallet.contacts())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn an_expired_invite_is_refused_after_the_skew_and_ends_on_the_inviter() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let link = world
        .block_on(world.issuer.wallet.pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                expiry: InviteExpiry::OneHour,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;

    // Within ten minutes of skew the invite still opens.
    world.payer.clock.advance(HOUR + 5 * MINUTE);
    assert!(world.payer.wallet.pairing_preview(&link).is_ok());
    world.payer.clock.advance(10 * MINUTE);
    assert!(matches!(
        world.payer.wallet.pairing_preview(&link),
        Err(ContactError::InviteExpired)
    ));
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false))
        ),
        Err(ContactError::InviteExpired)
    ));

    world.issuer.clock.advance(HOUR + 11 * MINUTE);
    let report = world.collect(&world.issuer);

    assert_eq!(report.mailboxes, 0);
    let ended: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::PairingFailed(FailedPairing { reason, .. }) => Some(reason),
            _ => None,
        })
        .collect();
    assert_eq!(ended, vec![PairingFailure::Expired]);
    assert!(
        world
            .issuer
            .read(|repos| repos.pending_pairings())
            .is_empty()
    );
}

#[test]
fn an_invite_answered_twice_pairs_once() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    let first = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let twin = world.payer_twin();
    let second = world
        .block_on(
            twin.wallet
                .pairing_accept(&relays(&twin), accept(&link, "Ben again", false)),
        )
        .unwrap();
    assert!(first.posted && second.posted);

    assert_eq!(world.collect(&world.issuer).paired, 1);

    let contacts = world.block_on(world.issuer.wallet.contacts()).unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].claimed_name.as_deref(), Some("Ben"));
    assert_eq!(world.collect(&world.payer).paired, 1);
    // The second answer is refused, and its pairing ends on the twin.
    let mut twin_events = twin.wallet.subscribe();
    assert_eq!(world.collect(&twin).paired, 0);
    assert!(
        events(&mut twin_events).contains(&Event::PairingFailed(FailedPairing {
            contact_id: second.contact_id,
            reason: PairingFailure::Refused(lepic_contact::Refusal::AlreadyUsed),
        }))
    );
    assert!(twin.read(|repos| repos.contacts()).is_empty());
}

#[test]
fn an_answer_whose_confirm_never_comes_ends_after_an_hour() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    // The inviter cancels before it collects.
    let pending = world.issuer.read(|repos| repos.pending_pairings());
    world
        .block_on(world.issuer.wallet.contact_remove(pending[0].contact_id))
        .unwrap();
    let mut payer_events = world.payer.wallet.subscribe();

    world.payer.clock.advance(HOUR + MINUTE);
    world.collect(&world.payer);

    assert!(events(&mut payer_events).iter().any(|event| matches!(
        event,
        Event::PairingFailed(FailedPairing {
            reason: PairingFailure::Expired,
            ..
        })
    )));
    assert!(world.payer.read(|repos| repos.contacts()).is_empty());
}

#[test]
fn a_removed_contact_is_no_longer_collected() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    // The contact mailbox, and the reply mailbox until the invite ends.
    assert_eq!(world.collect(&world.issuer).mailboxes, 2);

    assert!(
        world
            .block_on(world.issuer.wallet.contact_remove(anna_side))
            .unwrap()
    );

    assert_eq!(world.collect(&world.issuer).mailboxes, 0);
    assert!(
        world
            .block_on(world.issuer.wallet.contacts())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn an_answer_stored_before_its_post_survives_a_relay_that_fails() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    world.relay.set_refusing(true);

    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();

    assert!(!answered.posted);
    assert_eq!(world.payer.read(|repos| repos.pending_pairings()).len(), 1);
    // The reply link still finishes the pairing by hand.
    world.relay.set_refusing(false);
    let outcome = world
        .block_on(
            world
                .issuer
                .wallet
                .pairing_enter_link(&relays(&world.issuer), &answered.reply_link),
        )
        .unwrap();
    assert!(matches!(outcome, LinkOutcome::Confirm { .. }));
}

#[test]
fn offline_and_epicbox_off_refuse_to_collect_without_connecting() {
    let world = World::new();
    world.invite(&world.issuer, "Anna");
    let subscribes = world.relay.received("Subscribe");
    for (mode, expected) in [
        (RelayMode::Offline, "offline"),
        (RelayMode::EpicboxOff, "epicbox off"),
    ] {
        let error = world
            .block_on(world.issuer.wallet.contacts_collect(
                &ContactRelays {
                    mode,
                    ..relays(&world.issuer)
                },
                CollectTrigger::Pull,
            ))
            .unwrap_err();
        match (error, expected) {
            (ContactError::Offline, "offline") | (ContactError::EpicboxOff, "epicbox off") => {}
            (error, _) => panic!("unexpected {error:?}"),
        }
    }
    assert_eq!(world.relay.received("Subscribe"), subscribes);
    // An invite by hand still works with Epicbox off.
    let offline = ContactRelays {
        mode: RelayMode::EpicboxOff,
        ..relays(&world.payer)
    };
    let link = world.invite(&world.issuer, "Anna");
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&offline, accept(&link, "Ben", true)),
        )
        .unwrap();
    assert!(!answered.posted);
}

#[test]
fn a_pairing_works_when_the_invitee_uses_another_relay() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    // The payer's own relay is elsewhere; the pairing lives on the inviter's.
    let mut settings = world::settings();
    settings.endpoint = RelayEndpoint::new(
        Domain::parse("elsewhere.test").unwrap(),
        None,
        Security::Plain,
    );
    let elsewhere = ContactRelays {
        epicbox: EpicboxTransport::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        built_in: vec![world.issuer.epicbox.settings().endpoint.clone()],
        mode: RelayMode::Online,
    };
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&elsewhere, accept(&link, "Ben", false)),
        )
        .unwrap();
    assert!(answered.posted);
    assert_eq!(world.collect(&world.issuer).paired, 1);

    let report = world
        .block_on(
            world
                .payer
                .wallet
                .contacts_collect(&elsewhere, CollectTrigger::Open),
        )
        .unwrap();

    assert_eq!(report.paired, 1);
    let view = world
        .block_on(world.payer.wallet.contact(answered.contact_id))
        .unwrap();
    assert_eq!(view.home_relay.as_deref(), Some("relay.test:80"));
}

#[test]
fn twin_installs_on_one_seed_forced_into_one_slot_keep_their_mailboxes_apart() {
    let world = World::new();
    let twin = world.issuer_twin();
    for party in [&world.issuer, &twin] {
        party
            .store()
            .write(|repos| repos.raise_contact_slot_counter(AccountIndex(0), 7))
            .unwrap();
    }
    let first = world.invite(&world.issuer, "Anna");
    let second = world.invite(&twin, "Anna");
    let ben_twin = world.payer_twin();
    world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&first, "Ben", false)),
        )
        .unwrap();
    world
        .block_on(
            ben_twin
                .wallet
                .pairing_accept(&relays(&ben_twin), accept(&second, "Cleo", false)),
        )
        .unwrap();

    assert_eq!(world.collect(&world.issuer).paired, 1);
    assert_eq!(world.collect(&twin).paired, 1);

    let record = |party: &Party| {
        let records = party.read(|repos| repos.contacts());
        assert_eq!(records.len(), 1);
        let mailbox = party
            .read(|repos| repos.contact_mailbox(records[0].contact_id))
            .unwrap();
        (
            records[0].slot,
            mailbox.our_mailbox,
            records[0].peer.clone().unwrap().claimed_name,
        )
    };
    let (slot, mailbox, peer) = record(&world.issuer);
    let (twin_slot, twin_mailbox, twin_peer) = record(&twin);
    assert_eq!(slot, 7);
    assert_eq!(twin_slot, 7);
    assert_ne!(mailbox, twin_mailbox);
    assert_eq!((peer.as_str(), twin_peer.as_str()), ("Ben", "Cleo"));
}

#[test]
fn a_backup_restores_the_same_keys_and_pairings_on_another_install() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    world
        .block_on(world.issuer.wallet.pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    let document = world
        .block_on(world.issuer.wallet.contacts_export())
        .unwrap();
    let restored = world.issuer_twin();

    let summary = world
        .block_on(restored.wallet.contacts_import(document))
        .unwrap();

    assert_eq!(summary.imported, 1);
    let original = world.issuer.read(|repos| repos.contacts());
    let copy = restored.read(|repos| repos.contacts());
    assert_eq!(copy[0].own_card, original[0].own_card);
    assert_eq!(copy[0].slot, original[0].slot);
    assert_eq!(copy[0].box_salt, original[0].box_salt);
    assert_eq!(copy[0].state, ContactState::Verified);
    assert!(copy[0].imported_from_backup);
    let mailbox = |party: &Party| {
        party
            .read(|repos| repos.contact_mailbox(anna_side))
            .unwrap()
            .our_mailbox
    };
    assert_eq!(mailbox(&restored), mailbox(&world.issuer));
    // A new pairing on the restored install never reuses a slot from the backup.
    world.invite(&restored, "Anna");
    let slots: Vec<u32> = restored
        .read(|repos| repos.contacts())
        .iter()
        .map(|record| record.slot)
        .collect();
    assert_ne!(slots[0], slots[1]);
}

/// Mallory swaps the enc key in the invite on its way to the payer and passes the reply on to
/// the issuer under the original key. The issuer pairs, but the confirm reveals a card whose
/// enc key is not the invite's, so the payer stores nothing.
#[test]
fn a_swapped_invite_key_is_caught_by_the_commitment() {
    let world = World::new();
    let mut payer_events = world.payer.wallet.subscribe();
    let link = world.invite(&world.issuer, "Anna");
    let original = Invite::from_link(&link, ContactNetwork::Floonet).unwrap();
    let mallory = EncSecretKey::from_bytes([42; 32]);
    let swapped = Invite::new(
        ContactNetwork::Floonet,
        InviteFields {
            enc_key: mallory.public_key(),
            ..original.fields().clone()
        },
    )
    .unwrap();
    let answered = world
        .block_on(world.payer.wallet.pairing_accept(
            &relays(&world.payer),
            accept(&swapped.to_link(), "Ben", true),
        ))
        .unwrap();
    let envelope = pairing_envelope_from_link(&answered.reply_link, PairingLink::Reply).unwrap();
    let sealed = SealedEnvelope::decode(&envelope, ContactNetwork::Floonet).unwrap();
    let body = open_reply(&sealed, &mallory).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let forwarded = seal_reply(&original, &body, &mut rng).unwrap();
    let forwarded_link = lepic_contact::pairing_envelope_link(PairingLink::Reply, &forwarded);
    let LinkOutcome::Confirm { link: confirm, .. } = world
        .block_on(
            world
                .issuer
                .wallet
                .pairing_enter_link(&relays(&world.issuer), &forwarded_link),
        )
        .unwrap()
    else {
        panic!("the issuer did not pair");
    };

    let outcome = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_enter_link(&relays(&world.payer), &confirm),
        )
        .unwrap();

    assert_eq!(outcome, LinkOutcome::Ignored);
    assert!(world.payer.read(|repos| repos.contacts()).is_empty());
    assert!(events(&mut payer_events).iter().any(|event| matches!(
        event,
        Event::PairingFailed(FailedPairing {
            reason: PairingFailure::ChangedOnTheWay,
            ..
        })
    )));
}

/// Mallory answers the invite with her own card in place of the payer's. The issuer pairs with
/// Mallory, and its SAS differs from what the payer computes from its own card.
#[test]
fn a_swapped_reply_gives_different_sas_on_the_two_sides() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", true)),
        )
        .unwrap();
    let mallory = world.payer_twin();
    let mallory_answer = world
        .block_on(
            mallory
                .wallet
                .pairing_accept(&relays(&mallory), accept(&link, "Ben", true)),
        )
        .unwrap();
    let LinkOutcome::Confirm {
        contact_id,
        link: confirm,
    } = world
        .block_on(
            world
                .issuer
                .wallet
                .pairing_enter_link(&relays(&world.issuer), &mallory_answer.reply_link),
        )
        .unwrap()
    else {
        panic!("the issuer did not pair");
    };
    let issuer_sas = world.sas(&world.issuer, contact_id);

    // The confirm is sealed to Mallory's key, so the payer cannot even open it.
    let outcome = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_enter_link(&relays(&world.payer), &confirm),
        )
        .unwrap();
    assert_eq!(outcome, LinkOutcome::Ignored);
    let paired = world
        .block_on(
            mallory
                .wallet
                .pairing_enter_link(&relays(&mallory), &confirm),
        )
        .unwrap();
    assert!(matches!(paired, LinkOutcome::Paired { .. }));
    // The issuer and Mallory agree; the payer, which never paired, has nothing to compare, and
    // its own card is not the one the issuer holds.
    assert_eq!(
        issuer_sas,
        world.sas(&mallory, world.only_contact(&mallory))
    );
    let held = world
        .issuer
        .read(|repos| repos.contact(contact_id))
        .unwrap()
        .peer
        .unwrap()
        .bytes;
    let payer_card = world
        .payer
        .read(|repos| repos.contact(answered.contact_id))
        .unwrap()
        .own_card;
    assert_ne!(held, payer_card);
    assert!(ContactCard::decode(&held, ContactNetwork::Floonet).is_ok());
}

/// The payer's card for its pairing with the issuer, made again with `seq` and `mailbox`, sealed
/// as a contact update (type 05) and posted to the issuer's mailbox from the payer's.
fn post_update(world: &World, ben_side: ContactId, seq: u32, mailbox_host: &str) {
    let record = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    let keys = world
        .payer
        .keychain()
        .contact_root(
            &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
            lepic_primitives::params::Network::Floonet,
        )
        .unwrap()
        .contact_keys(record.slot, record.box_salt)
        .unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let key_text = own.fields().mailbox.as_str().split('@').next().unwrap();
    let mut fields = own.fields().clone();
    fields.seq = seq;
    fields.mailbox =
        lepic_contact::MailboxAddress::new(&format!("{key_text}@{mailbox_host}")).unwrap();
    let card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(u64::from(seq));
    let envelope = lepic_contact::seal_contact_update(&peer, &card, &signer, &mut rng).unwrap();
    let from = lepic_epicbox::Identity::new(
        keys.expose_box_secret().clone(),
        lepic_epicbox::EpicboxAddress::new(
            *keys.box_public_key(),
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        ),
    )
    .unwrap();
    let to =
        lepic_epicbox::EpicboxAddress::parse(peer.fields().mailbox.as_str(), RelayNetwork::Floonet)
            .unwrap();
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

#[test]
fn contact_updates_refresh_the_card_within_three_a_day() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let peer_mailbox = || {
        world
            .issuer
            .read(|repos| repos.contact_mailbox(anna_side))
            .unwrap()
            .peer_mailbox
    };

    let shown = peer_mailbox();
    let seq = || {
        world
            .issuer
            .read(|repos| repos.contact(anna_side))
            .unwrap()
            .peer
            .unwrap()
            .seq
    };
    for seq in 2..=5 {
        post_update(&world, ben_side, seq, "relay.test:80");
    }
    // An older card than the stored one changes nothing.
    post_update(&world, ben_side, 1, "relay.test:80");
    world.collect(&world.issuer);

    let updates = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::ContactUpdated(_)))
        .count();
    assert_eq!(updates, 3);
    assert_eq!(seq(), 4);

    // A day later the next one is taken, but a person's mailbox stays on its relay: an update
    // naming another relay is refused (RFC 0002 8.5).
    world.issuer.clock.advance(24 * HOUR + MINUTE);
    post_update(&world, ben_side, 6, "relay.test:8006");
    world.collect(&world.issuer);
    assert_eq!(seq(), 4);
    assert_eq!(peer_mailbox(), shown);
    post_update(&world, ben_side, 7, "relay.test:80");
    world.collect(&world.issuer);
    assert_eq!(seq(), 7);
}

/// The party's keys for its contact `contact`, as the wallet derives them.
fn contact_keys(party: &Party, contact: ContactId) -> lepic_keychain::ContactKeys {
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    party
        .keychain()
        .contact_root(
            &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
            lepic_primitives::params::Network::Floonet,
        )
        .unwrap()
        .contact_keys(record.slot, record.box_salt)
        .unwrap()
}

/// Posts `envelope` from the party's mailbox for `contact` to the contact's mailbox, as the
/// party's wallet would.
fn post_sealed(world: &World, party: &Party, contact: ContactId, envelope: &[u8]) {
    let keys = contact_keys(party, contact);
    let mailbox = party.read(|repos| repos.contact_mailbox(contact)).unwrap();
    let from = lepic_epicbox::Identity::new(
        keys.expose_box_secret().clone(),
        lepic_epicbox::EpicboxAddress::parse(&mailbox.our_mailbox, RelayNetwork::Floonet).unwrap(),
    )
    .unwrap();
    let to =
        lepic_epicbox::EpicboxAddress::parse(&mailbox.peer_mailbox, RelayNetwork::Floonet).unwrap();
    world
        .block_on(
            lepic_epicbox::MailboxClient::new(world::settings(), world.relay.connector()).post(
                &from,
                &to,
                &lepic_contact::armor(envelope),
            ),
        )
        .unwrap();
}

/// The contacts whose keys came back and those whose keys changed, by the events.
fn key_news(events: &[Event]) -> (Vec<ContactId>, Vec<ContactId>) {
    let restored = events
        .iter()
        .filter_map(|event| match event {
            Event::ContactKeysRestored(ContactEvent { contact_id }) => Some(*contact_id),
            _ => None,
        })
        .collect();
    let changed = events
        .iter()
        .filter_map(|event| match event {
            Event::ContactKeysChanged(ContactEvent { contact_id }) => Some(*contact_id),
            _ => None,
        })
        .collect();
    (restored, changed)
}

fn key_check(world: &World, party: &Party, new: ContactId, old: ContactId) {
    world
        .block_on(party.wallet.contact_key_check(&relays(party), new, old))
        .unwrap();
}

/// Runs both sides' collecting until the check, its answers and the folding are done.
fn settle(world: &World, x: &Party, y: &Party) {
    for _ in 0..3 {
        world.collect(y);
        world.collect(x);
    }
}

/// C-12 without the backup: the payer's phrase on a new install pairs with the issuer again, and
/// the issuer adds the new pairing to the old contact. The new install finds its old slot, and
/// both keep the old keys: the issuer its record with its trust, the payer the old slot.
#[test]
fn a_re_pairing_without_the_backup_brings_the_old_keys_back() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    world
        .block_on(world.issuer.wallet.pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    let before = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    let restored = world.payer_twin();
    let (new_on_issuer, _) = world.pair(&world.issuer, &restored);
    let mut issuer_events = world.issuer.wallet.subscribe();
    let mut restored_events = restored.wallet.subscribe();

    key_check(&world, &world.issuer, new_on_issuer, anna_side);
    settle(&world, &world.issuer, &restored);

    assert_eq!(world.contact_ids(&world.issuer), vec![anna_side]);
    let after = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    assert_eq!(after.state, ContactState::Verified);
    assert_eq!(after.verified_at, before.verified_at);
    let (old_peer, new_peer) = (before.peer.unwrap(), after.peer.unwrap());
    assert_eq!(new_peer.sig_key, old_peer.sig_key);
    assert!(new_peer.seq > old_peer.seq);
    let kept = restored.read(|repos| repos.contacts());
    assert_eq!(kept.len(), 1);
    let original = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    assert_eq!(kept[0].slot, original.slot);
    assert_eq!(kept[0].peer.as_ref().unwrap().bytes, after.own_card);
    // The issuer now delivers to the restored install's new mailbox.
    let mailbox = restored
        .read(|repos| repos.contact_mailbox(kept[0].contact_id))
        .unwrap();
    let issuer_mailbox = world
        .issuer
        .read(|repos| repos.contact_mailbox(anna_side))
        .unwrap();
    assert_eq!(issuer_mailbox.peer_mailbox, mailbox.our_mailbox);
    assert_eq!(mailbox.peer_mailbox, issuer_mailbox.our_mailbox);
    assert_eq!(
        key_news(&events(&mut issuer_events)),
        (vec![anna_side], vec![])
    );
    assert_eq!(
        key_news(&events(&mut restored_events)),
        (vec![kept[0].contact_id], vec![])
    );
    // One check per slot a day.
    let (again, _) = world.pair(&world.issuer, &restored);
    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_key_check(
            &relays(&world.issuer),
            again,
            anna_side
        )),
        Err(ContactError::KeyCheckRefused)
    ));
}

/// C-12 with the backup: the restored install holds the record already, so a re-pairing anyway
/// folds into it and nothing changes on either side.
#[test]
fn a_re_pairing_with_the_backup_folds_into_the_restored_record() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let document = world
        .block_on(world.payer.wallet.contacts_export())
        .unwrap();
    let restored = world.payer_twin();
    world
        .block_on(restored.wallet.contacts_import(document))
        .unwrap();
    let before = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    let (new_on_issuer, _) = world.pair(&world.issuer, &restored);

    key_check(&world, &world.issuer, new_on_issuer, anna_side);
    settle(&world, &world.issuer, &restored);

    assert_eq!(world.contact_ids(&world.issuer), vec![anna_side]);
    assert_eq!(restored.read(|repos| repos.contacts()).len(), 1);
    let kept = restored.read(|repos| repos.contact(ben_side)).unwrap();
    let after = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    assert_eq!(after.peer.as_ref().unwrap().bytes, kept.own_card);
    assert_eq!(after.peer.unwrap().sig_key, before.peer.unwrap().sig_key);
    assert_eq!(after.state, before.state);
}

/// C-12 with another seed: nothing is found, the old record stays as it was, and the new
/// pairing shows keys-changed until the user picks the old keys or the new ones.
#[test]
fn a_re_pairing_with_another_seed_shows_keys_changed_on_the_new_pairing() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    world
        .block_on(world.issuer.wallet.pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    let before = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    let stranger = world.stranger();
    let (new_on_issuer, _) = world.pair(&world.issuer, &stranger);
    let mut issuer_events = world.issuer.wallet.subscribe();

    key_check(&world, &world.issuer, new_on_issuer, anna_side);
    // One check per pairing.
    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_key_check(
            &relays(&world.issuer),
            new_on_issuer,
            anna_side
        )),
        Err(ContactError::KeyCheckRefused)
    ));
    settle(&world, &world.issuer, &stranger);

    assert_eq!(
        world.issuer.read(|repos| repos.contact(anna_side)).unwrap(),
        before
    );
    let changed = world
        .issuer
        .read(|repos| repos.contact(new_on_issuer))
        .unwrap();
    assert_eq!(changed.state, ContactState::KeysChanged);
    assert!(!changed.allow_invoices);
    assert_eq!(
        key_news(&events(&mut issuer_events)),
        (vec![], vec![new_on_issuer])
    );

    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_keys_resolve(new_on_issuer, KeysDecision::UseNew),
        )
        .unwrap();
    assert_eq!(world.contact_ids(&world.issuer), vec![new_on_issuer]);
    let used = world
        .issuer
        .read(|repos| repos.contact(new_on_issuer))
        .unwrap();
    assert_eq!(used.state, ContactState::Paired);
    world
        .block_on(world.issuer.wallet.pairing_sas(
            &relays(&world.issuer),
            new_on_issuer,
            SasDecision::Match,
        ))
        .unwrap();
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.contact(new_on_issuer))
            .unwrap()
            .state,
        ContactState::Verified
    );
}

/// C-12 without an answer: a day later the new pairing shows keys-changed, a found answer
/// arriving after that is refused, and keeping the old keys deletes the new pairing.
#[test]
fn a_key_check_unanswered_for_a_day_shows_keys_changed() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let before = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    let restored = world.payer_twin();
    let (new_on_issuer, _) = world.pair(&world.issuer, &restored);
    let mut issuer_events = world.issuer.wallet.subscribe();

    key_check(&world, &world.issuer, new_on_issuer, anna_side);
    world.issuer.clock.advance(24 * HOUR + MINUTE);
    world.collect(&world.issuer);
    assert_eq!(
        key_news(&events(&mut issuer_events)),
        (vec![], vec![new_on_issuer])
    );
    // The restored install answers found too late.
    settle(&world, &world.issuer, &restored);
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.contact(new_on_issuer))
            .unwrap()
            .state,
        ContactState::KeysChanged
    );
    assert_eq!(
        world.issuer.read(|repos| repos.contact(anna_side)).unwrap(),
        before
    );
    assert_eq!(key_news(&events(&mut issuer_events)), (vec![], vec![]));

    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_keys_resolve(new_on_issuer, KeysDecision::KeepOld),
        )
        .unwrap();
    assert_eq!(world.contact_ids(&world.issuer), vec![anna_side]);
}

/// An ordinary contact update on the old pairing while a check is open refreshes the old card
/// and completes nothing; a found answer without a proof by the old key is refused.
#[test]
fn only_a_proven_found_answer_completes_a_key_check() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let stranger = world.stranger();
    let (new_on_issuer, new_on_stranger) = world.pair(&world.issuer, &stranger);
    let mut issuer_events = world.issuer.wallet.subscribe();
    key_check(&world, &world.issuer, new_on_issuer, anna_side);

    post_update(&world, ben_side, 2, "relay.test:80");
    // The stranger claims the old keys with a card and a proof of its own.
    let keys = contact_keys(&stranger, new_on_stranger);
    let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = stranger
        .read(|repos| repos.contact(new_on_stranger))
        .unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let mut fields = own.fields().clone();
    fields.seq += 1;
    let refreshed = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    let issuer_card =
        ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let forged = lepic_contact::seal_found(
        &issuer_card,
        &signer,
        b"a check never seen",
        &refreshed,
        &signer,
        &mut rand::rngs::StdRng::seed_from_u64(7),
    )
    .unwrap();
    post_sealed(&world, &stranger, new_on_stranger, &forged);
    world.collect(&world.issuer);

    let news = events(&mut issuer_events);
    assert!(news.contains(&Event::ContactUpdated(ContactEvent {
        contact_id: anna_side
    })));
    assert_eq!(key_news(&news), (vec![], vec![]));
    let old = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    assert_eq!(old.peer.unwrap().seq, 2);
    assert_eq!(world.contact_ids(&world.issuer).len(), 2);
    // The check stays open, and the stranger's own answer ends it.
    settle(&world, &world.issuer, &stranger);
    assert_eq!(
        key_news(&events(&mut issuer_events)),
        (vec![], vec![new_on_issuer])
    );
}

/// C-17: both invite each other at once. The second pairing is added to the first contact, the
/// other side finds the first among its own records, and one record remains on each side, with
/// the older keys.
#[test]
fn cross_invites_fold_into_the_older_pairing() {
    let world = World::new();
    let (first_on_issuer, first_on_payer) = world.pair_by_link();
    let (second_on_payer, second_on_issuer) = world.pair(&world.payer, &world.issuer);
    let before = world
        .issuer
        .read(|repos| repos.contact(first_on_issuer))
        .unwrap();

    key_check(&world, &world.issuer, second_on_issuer, first_on_issuer);
    settle(&world, &world.issuer, &world.payer);

    assert_eq!(world.contact_ids(&world.issuer), vec![first_on_issuer]);
    assert_eq!(world.contact_ids(&world.payer), vec![first_on_payer]);
    assert!(
        world
            .payer
            .read(|repos| repos.contact(second_on_payer))
            .is_none()
    );
    let after = world
        .issuer
        .read(|repos| repos.contact(first_on_issuer))
        .unwrap();
    assert_eq!(
        after.peer.as_ref().unwrap().sig_key,
        before.peer.unwrap().sig_key
    );
    let payer_record = world
        .payer
        .read(|repos| repos.contact(first_on_payer))
        .unwrap();
    assert_eq!(after.peer.unwrap().bytes, payer_record.own_card);
    assert_eq!(payer_record.peer.unwrap().bytes, after.own_card);
}

/// 7.4: a card QR is seen by anyone nearby, so each side's first collect moves its mailbox to a
/// new box salt and tells the other with a contact update; the old mailbox is still read.
#[test]
fn an_in_person_pairing_moves_both_mailboxes_on_the_first_collect() {
    let world = World::new();
    let show = |party: &Party, name: &str| {
        world
            .block_on(party.wallet.pairing_show_card(
                &relays(party),
                CardRequest {
                    account: AccountIndex(0),
                    name: name.to_owned(),
                    kind: ContactKind::Person,
                },
            ))
            .unwrap()
    };
    let anna = show(&world.issuer, "Anna");
    let ben = show(&world.payer, "Ben");
    world
        .block_on(world.issuer.wallet.pairing_scan_card(
            &relays(&world.issuer),
            anna.contact_id,
            &ben.link,
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.pairing_scan_card(
            &relays(&world.payer),
            ben.contact_id,
            &anna.link,
        ))
        .unwrap();
    let mailbox = |party: &Party, contact: ContactId| {
        party.read(|repos| repos.contact_mailbox(contact)).unwrap()
    };
    let shown = mailbox(&world.issuer, anna.contact_id).our_mailbox;
    let hint = world
        .payer
        .read(|repos| repos.contact(ben.contact_id))
        .unwrap();

    // The payer moves before it reads the issuer's update, so its own update goes to the
    // issuer's old mailbox, which the issuer still drains.
    for _ in 0..2 {
        world.collect(&world.issuer);
        world.collect(&world.payer);
    }

    let issuer_side = mailbox(&world.issuer, anna.contact_id);
    let payer_side = mailbox(&world.payer, ben.contact_id);
    assert_ne!(issuer_side.our_mailbox, shown);
    assert_eq!(payer_side.peer_mailbox, issuer_side.our_mailbox);
    assert_eq!(issuer_side.peer_mailbox, payer_side.our_mailbox);
    assert_ne!(
        world
            .payer
            .read(|repos| repos.contact(ben.contact_id))
            .unwrap()
            .box_salt,
        hint.box_salt
    );
    // The move happens once; the old mailbox is drained beside the new one.
    assert_eq!(world.collect(&world.issuer).mailboxes, 2);
    assert_eq!(
        mailbox(&world.issuer, anna.contact_id).our_mailbox,
        issuer_side.our_mailbox
    );
}

fn invite_with_words(world: &World, party: &Party) -> Vec<&'static str> {
    world
        .block_on(party.wallet.pairing_invite(
            &relays_with_words(party),
            InviteRequest {
                offer_words: true,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .words
        .unwrap()
        .iter()
        .map(|symbol| symbol.name)
        .collect()
}

fn find_words(world: &World, party: &Party, words: &[&str]) -> Result<String, ContactError> {
    world.block_on(
        party
            .wallet
            .pairing_find_words(&relays_with_words(party), words),
    )
}

/// C-33: words are offered only on a built-in relay; wrong words find nothing; the right words
/// open the invite and pairing completes; a second use finds nothing.
#[test]
fn pairing_words_find_the_invite_once() {
    let world = World::new();
    assert!(matches!(
        world.block_on(world.issuer.wallet.pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                offer_words: true,
                ..invite_request("Anna")
            },
        )),
        Err(ContactError::WordsUnavailable)
    ));
    let words = invite_with_words(&world, &world.issuer);
    let mut wrong = words.clone();
    wrong.rotate_left(1);
    assert!(matches!(
        find_words(&world, &world.payer, &wrong),
        Err(ContactError::WordsNotFound)
    ));

    let link = find_words(&world, &world.payer, &words).unwrap();
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    assert!(answered.posted);
    assert_eq!(world.collect(&world.issuer).paired, 1);
    assert_eq!(world.collect(&world.payer).paired, 1);

    let second = world.payer_twin();
    assert!(matches!(
        find_words(&world, &second, &words),
        Err(ContactError::WordsNotFound)
    ));
}

/// C-33, the window edge: an invite made just before a 10-minute window ends is still found in
/// the next one.
#[test]
fn pairing_words_are_found_in_the_next_window() {
    let world = World::new();
    // The test clock starts 200 s into a window.
    world.issuer.clock.advance(Duration::from_secs(390));
    let words = invite_with_words(&world, &world.issuer);
    world.payer.clock.advance(Duration::from_secs(420));

    let link = find_words(&world, &world.payer, &words).unwrap();
    assert!(link.starts_with("epiccash://pair/1/"));
}

/// Pairings in progress are listed on both sides until they complete, and removing one cancels
/// it.
#[test]
fn pairings_in_progress_are_listed_until_they_complete() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    let pending = world
        .block_on(world.issuer.wallet.pairings_pending())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].role, lepic_wallet::contact::PairingRole::Inviter);
    assert_eq!(pending[0].invite_name, "Anna");
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let waiting = world
        .block_on(world.payer.wallet.pairings_pending())
        .unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].role, lepic_wallet::contact::PairingRole::Invitee);
    assert_eq!(waiting[0].contact_id, answered.contact_id);
    assert_eq!(waiting[0].invite_name, "Anna");

    world.collect(&world.issuer);
    world.collect(&world.payer);
    for party in [&world.issuer, &world.payer] {
        assert!(
            world
                .block_on(party.wallet.pairings_pending())
                .unwrap()
                .is_empty()
        );
    }

    let cancelled = world.invite(&world.issuer, "Anna");
    assert!(!cancelled.is_empty());
    let id = world
        .block_on(world.issuer.wallet.pairings_pending())
        .unwrap()[0]
        .contact_id;
    assert!(
        world
            .block_on(world.issuer.wallet.contact_remove(id))
            .unwrap()
    );
    assert!(
        world
            .block_on(world.issuer.wallet.pairings_pending())
            .unwrap()
            .is_empty()
    );
}

/// The read and post identities of the pairing mailbox of `seed` on the test relay.
fn pairing_identities(seed: [u8; 16]) -> (lepic_epicbox::Identity, lepic_epicbox::Identity) {
    let (box_sk, from_sk) =
        lepic_keychain::pairing_mailbox_keys(seed, lepic_primitives::params::Network::Floonet)
            .unwrap();
    let identity = |secret: lepic_crypto::SecretKey| {
        let public = lepic_crypto::PublicKey::from_secret_key(&secret).unwrap();
        let address = lepic_epicbox::EpicboxAddress::new(
            public,
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        );
        lepic_epicbox::Identity::new(secret, address).unwrap()
    };
    (identity(box_sk), identity(from_sk))
}

/// Takes every message in a mailbox as text.
struct Collected(Vec<String>);

impl lepic_epicbox::MailboxHandler for Collected {
    fn handle(
        &mut self,
        message: lepic_epicbox::MailboxMessage,
    ) -> lepic_transport::transport::BoxFuture<'_, lepic_epicbox::Handled> {
        Box::pin(async move {
            if let lepic_epicbox::MailboxContent::Opened(received) = message.into_content() {
                self.0.push(received.plaintext.expose_str().to_owned());
            }
            lepic_epicbox::Handled::Stored
        })
    }
}

/// A contact the issuer already pairs with answers a new invite with the card the issuer holds
/// for it. The issuer refuses it with the anonymous one-byte refusal only: no confirm, so no nA
/// and no card, leaves, and the invite stays open for the one it was made for.
#[test]
fn a_reply_with_a_card_already_paired_gets_no_confirm() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let link = world.invite(&world.issuer, "Anna");
    let invite = Invite::from_link(&link, ContactNetwork::Floonet).unwrap();
    let held = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    let card = ContactCard::decode(&held.own_card, ContactNetwork::Floonet).unwrap();
    let rc = [9; 16];
    let body = lepic_contact::ReplyBody {
        code: invite.fields().code.clone(),
        nonce: lepic_contact::Nonce::from_bytes([7; 16]),
        confirm_code: lepic_contact::ConfirmCode::from_bytes(rc),
        card,
    };
    let reply = seal_reply(&invite, &body, &mut rand::rngs::StdRng::seed_from_u64(3)).unwrap();
    let (reply_box, reply_from) = pairing_identities(*invite.fields().code.expose_bytes());
    let client = lepic_epicbox::MailboxClient::new(world::settings(), world.relay.connector());
    world
        .block_on(client.post(
            &reply_from,
            reply_box.address(),
            &lepic_contact::armor(&reply),
        ))
        .unwrap();

    world.collect(&world.issuer);

    let (confirm_box, _) = pairing_identities(rc);
    let mut collected = Collected(Vec::new());
    world
        .block_on(client.drain_once(&[confirm_box], &mut collected))
        .unwrap();
    assert_eq!(collected.0.len(), 1, "{:?}", collected.0);
    let keys = contact_keys(&world.payer, ben_side);
    let sealed_bytes = lepic_contact::dearmor(&collected.0[0]).unwrap();
    let sealed = SealedEnvelope::decode(&sealed_bytes, ContactNetwork::Floonet).unwrap();
    let opened = lepic_contact::open_confirm(
        &sealed,
        &EncSecretKey::from_bytes(*keys.expose_enc_secret()),
    )
    .unwrap();
    assert!(
        matches!(
            opened,
            lepic_contact::Confirm::Refused(lepic_contact::Refusal::AlreadyUsed)
        ),
        "{opened:?}"
    );
    assert_eq!(world.contact_ids(&world.issuer), vec![anna_side]);
    // The invite is still open: the one it was made for pairs with it.
    let stranger = world.stranger();
    world
        .block_on(
            stranger
                .wallet
                .pairing_accept(&relays(&stranger), accept(&link, "Cleo", false)),
        )
        .unwrap();
    assert_eq!(world.collect(&world.issuer).paired, 1);
    assert_eq!(world.collect(&stranger).paired, 1);
}

/// A stranger who knows the payer's card for its contact Anna pairs with the payer, starts a
/// key check for that card and answers the payer's found answer with a card and proof of its
/// own. The payer's record for Anna keeps Anna's keys: a restored card must carry the keys the
/// record holds.
#[test]
fn a_restored_answer_cannot_replace_the_keys_of_a_kept_record() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    world
        .block_on(world.payer.wallet.pairing_sas(
            &relays(&world.payer),
            ben_side,
            SasDecision::Match,
        ))
        .unwrap();
    let before = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    let stranger = world.stranger();
    let (on_payer, on_stranger) = world.pair(&world.payer, &stranger);
    let mut payer_events = world.payer.wallet.subscribe();

    let keys = contact_keys(&stranger, on_stranger);
    let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = stranger.read(|repos| repos.contact(on_stranger)).unwrap();
    let payer_new =
        ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let payer_for_anna = ContactCard::decode(&before.own_card, ContactNetwork::Floonet).unwrap();
    let check = lepic_contact::seal_key_check(
        &payer_new,
        &payer_for_anna,
        &signer,
        &mut rand::rngs::StdRng::seed_from_u64(11),
    )
    .unwrap();
    post_sealed(&world, &stranger, on_stranger, &check);
    world.collect(&world.payer);

    // The stranger reads the found answer from its mailbox by hand.
    let mailbox = stranger
        .read(|repos| repos.contact_mailbox(on_stranger))
        .unwrap();
    let inbox = lepic_epicbox::Identity::new(
        keys.expose_box_secret().clone(),
        lepic_epicbox::EpicboxAddress::parse(&mailbox.our_mailbox, RelayNetwork::Floonet).unwrap(),
    )
    .unwrap();
    let client = lepic_epicbox::MailboxClient::new(world::settings(), world.relay.connector());
    let mut collected = Collected(Vec::new());
    world
        .block_on(client.drain_once(&[inbox], &mut collected))
        .unwrap();
    let found = collected
        .0
        .iter()
        .map(|text| lepic_contact::dearmor(text).unwrap())
        .find(|bytes| {
            let sealed = SealedEnvelope::decode(bytes, ContactNetwork::Floonet).unwrap();
            lepic_contact::open_key_check_answer(
                &sealed,
                &EncSecretKey::from_bytes(*keys.expose_enc_secret()),
                payer_new.sig_key(),
            )
            .is_ok_and(|answer| matches!(answer, lepic_contact::KeyCheckAnswer::Found(_)))
        })
        .expect("the payer answered found");
    // A card under a key of the stranger's that no record holds, with a valid proof by it.
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let forged_key = lepic_contact::SigningKey::from_bytes(&[77; 32]);
    let mut fields = own.fields().clone();
    fields.sig_key = forged_key.verifying_key();
    let forged = ContactCard::sign(ContactNetwork::Floonet, fields, &forged_key).unwrap();
    let restored = lepic_contact::seal_restored(
        &payer_new,
        &signer,
        &found,
        &forged,
        &forged_key,
        &mut rand::rngs::StdRng::seed_from_u64(12),
    )
    .unwrap();
    post_sealed(&world, &stranger, on_stranger, &restored);
    world.collect(&world.payer);

    let after = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    assert_eq!(after.peer, before.peer);
    assert_eq!(after.state, ContactState::Verified);
    let (restored_news, _) = key_news(&events(&mut payer_events));
    assert!(restored_news.is_empty(), "{restored_news:?}");
    assert!(world.contact_ids(&world.payer).contains(&on_payer));
    let _ = anna_side;
}

fn assert_send<T: Send>(_: T) {}

/// The futures of every contact call a host runs on another thread are `Send`, so the binding
/// can spawn them. Built and dropped, never polled.
#[test]
fn every_contact_future_is_send() {
    let world = World::new();
    let wallet = &world.issuer.wallet;
    let relays = relays(&world.issuer);
    let id = ContactId([1; 16]);
    let slate_id = lepic_wallet::event::SlateId::from_bytes([2; 16]);
    let tx_id = lepic_store::TxId(1);
    let words: [&str; 5] = ["a", "b", "c", "d", "e"];
    assert_send(wallet.pairing_invite(&relays, invite_request("Anna")));
    assert_send(wallet.pairing_accept(&relays, accept("link", "Ben", false)));
    assert_send(wallet.pairing_enter_link(&relays, "link"));
    assert_send(wallet.pairing_show_card(
        &relays,
        CardRequest {
            account: AccountIndex(0),
            name: "Anna".to_owned(),
            kind: ContactKind::Person,
        },
    ));
    assert_send(wallet.pairing_scan_card(&relays, id, "link"));
    assert_send(wallet.pairing_sas(&relays, id, SasDecision::Match));
    assert_send(wallet.pairing_find_words(&relays, &words));
    assert_send(wallet.pairings_pending());
    assert_send(wallet.contacts_collect(&relays, CollectTrigger::Open));
    assert_send(wallet.contact_key_check(&relays, id, id));
    assert_send(wallet.contact_keys_resolve(id, KeysDecision::KeepOld));
    assert_send(wallet.contacts_outbox_deliver(&relays));
    assert_send(wallet.contact_outbox_resend(&relays, lepic_store::ContactOutboxId(1)));
    assert_send(wallet.contact_outbox(id));
    assert_send(wallet.contacts());
    assert_send(wallet.contact(id));
    assert_send(wallet.contact_remove(id));
    assert_send(wallet.contact_set_label(id, "Anna".to_owned()));
    assert_send(wallet.contact_set_seal(id, true));
    assert_send(wallet.contact_set_allow_invoices(id, true));
    assert_send(wallet.contact_attach(id, None));
    assert_send(wallet.contacts_export());
    assert_send(wallet.contacts_import(String::new()));
    assert_send(wallet.contact_issue_invoice(
        &relays,
        id,
        lepic_wallet::invoice::InvoiceRequest {
            account: AccountIndex(0),
            amount: lepic_primitives::amount::Amount::new(1),
            message: None,
        },
        lepic_wallet::contact::InvoiceDetails {
            purpose: lepic_contact::Purpose::Request,
            reference: None,
            expires: None,
        },
    ));
    assert_send(wallet.contact_invoices());
    assert_send(wallet.contact_pay_invoice(
        &relays,
        slate_id,
        lepic_wallet::invoice::PayRequest::new(
            AccountIndex(0),
            lepic_primitives::amount::Amount::new(1),
        ),
    ));
    assert_send(wallet.contact_decline_invoice(slate_id));
    assert_send(wallet.contact_seal_slate(id, tx_id, None));
    assert_send(wallet.contact_post_slate(&relays, id, tx_id, None));
    assert_send(wallet.sealed_open("text"));
    assert_send(wallet.sealed_receive("text", lepic_wallet::ReceiveRequest::default()));
    assert_send(wallet.sealed_pay(
        "text",
        lepic_wallet::invoice::PayRequest::new(
            AccountIndex(0),
            lepic_primitives::amount::Amount::new(1),
        ),
    ));
    assert_send(wallet.sealed_finalize("text", lepic_node::Propagation::Stem));
    assert_send(wallet.contact_plain_fallback(tx_id));
    assert_send(wallet.contact_of_transaction(tx_id));
}
