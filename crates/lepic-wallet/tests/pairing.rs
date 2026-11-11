// SPDX-License-Identifier: Apache-2.0
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


use helpers::{HOUR, MINUTE, accept, events, invite_request, relays};
use lepic_contact::{
    ContactCard, ContactKind, EncSecretKey, Invite, InviteFields, Network as ContactNetwork,
    PairingLink, SealedEnvelope, open_reply, pairing_envelope_from_link, seal_reply,
};
use lepic_epicbox::{Domain, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_methods::epicbox::Epicbox;
use lepic_store::{AccountIndex, ContactId, ContactState, WalletStore};
use lepic_wallet::Event;
use lepic_wallet::event::{ContactChange, ContactEvent, ContactUpdate, FailedPairing};
use lepic_wallet_contacts::{
    AcceptRequest, CollectTrigger, ContactError, ContactRelays, InviteExpiry,
    InviteRequest, KeyCheckStart, KeysDecision, LinkOutcome, PairingClass, PairingEndReason,
    PairingFailure, PairingStatus, PayloadId, RelayMode, SasDecision, WalletContacts,
};
use rand::SeedableRng;
use world::{Party, World};

#[test]
fn two_wallets_pair_by_link_through_the_relay_and_see_one_sas() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let mut payer_events = world.payer.wallet.subscribe();

    let (anna_side, ben_side) = world.pair_by_link();

    let issuer_view = world
        .block_on(world.issuer.wallet.contact_book().contact(anna_side))
        .unwrap();
    let payer_view = world
        .block_on(world.payer.wallet.contact_book().contact(ben_side))
        .unwrap();
    assert_eq!(issuer_view.state, ContactState::Paired);
    assert_eq!(payer_view.state, ContactState::Paired);
    assert_eq!(issuer_view.claimed_name.as_deref(), Some("Ben"));
    assert_eq!(payer_view.claimed_name.as_deref(), Some("Anna"));
    // The claimed name is never taken as the user's own name for the contact (R2-10).
    assert!(issuer_view.label.is_empty() && payer_view.label.is_empty());
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
                .contact_book()
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
                .contact_book()
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
                .contact_book()
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
fn the_sas_check_verifies_or_ends_and_only_verified_contacts_send_invoices() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let wallet = &world.issuer.wallet;

    assert!(matches!(
        world.block_on(
            wallet
                .contact_book()
                .contact_set_allow_invoices(anna_side, true)
        ),
        Err(ContactError::NotVerified)
    ));
    world
        .block_on(wallet.contact_book().pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Skip,
        ))
        .unwrap();
    assert_eq!(
        world
            .block_on(wallet.contact_book().contact(anna_side))
            .unwrap()
            .state,
        ContactState::Paired
    );
    world
        .block_on(wallet.contact_book().pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    let view = world
        .block_on(wallet.contact_book().contact(anna_side))
        .unwrap();
    assert_eq!(view.state, ContactState::Verified);
    assert!(view.verified_at.is_some());
    world
        .block_on(
            wallet
                .contact_book()
                .contact_set_allow_invoices(anna_side, true),
        )
        .unwrap();
    assert!(
        world
            .block_on(wallet.contact_book().contact(anna_side))
            .unwrap()
            .allow_invoices
    );

    world
        .block_on(world.payer.wallet.contact_book().pairing_sas(
            &relays(&world.payer),
            ben_side,
            SasDecision::Mismatch,
        ))
        .unwrap();
    // A mismatch ends the pairing and keeps it, ended.
    let ended = world
        .block_on(world.payer.wallet.contact_book().contacts())
        .unwrap();
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].status, PairingStatus::Ended);
    assert_eq!(ended[0].ended_reason, Some(PairingEndReason::Mismatch));
}

#[test]
fn an_expired_invite_is_refused_after_the_skew_and_ends_on_the_inviter() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
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
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().pairing_preview(&link))
            .is_ok()
    );
    world.payer.clock.advance(10 * MINUTE);
    assert!(matches!(
        world.block_on(world.payer.wallet.contact_book().pairing_preview(&link)),
        Err(ContactError::InviteExpired)
    ));
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false))
        ),
        Err(ContactError::InviteExpired)
    ));

    world.issuer.clock.advance(HOUR + 11 * MINUTE);
    let report = world.collect(&world.issuer);

    // Its reply mailbox is drained once more, for a reply that waited there, then it ends.
    assert_eq!(report.mailboxes, 1);
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
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let twin = world.payer_twin();
    let second = world
        .block_on(
            twin.wallet
                .contact_book()
                .pairing_accept(&relays(&twin), accept(&link, "Ben again", false)),
        )
        .unwrap();
    assert!(first.posted && second.posted);

    assert_eq!(world.collect(&world.issuer).paired, 1);

    let contacts = world
        .block_on(world.issuer.wallet.contact_book().contacts())
        .unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].claimed_name.as_deref(), Some("Ben"));
    assert_eq!(world.collect(&world.payer).paired, 1);
    // The second answer is refused, and its pairing ends on the twin.
    let mut twin_events = twin.wallet.subscribe();
    let report = world.collect(&twin);
    assert_eq!(report.paired, 0);
    // The cycle's report names the pairing that ended too.
    assert_eq!(
        report.failed,
        vec![FailedPairing {
            contact_id: second.contact_id,
            reason: PairingFailure::Refused(lepic_contact::Refusal::AlreadyUsed),
        }]
    );
    assert!(
        events(&mut twin_events).contains(&Event::PairingFailed(FailedPairing {
            contact_id: second.contact_id,
            reason: PairingFailure::Refused(lepic_contact::Refusal::AlreadyUsed),
        }))
    );
    assert!(twin.read(|repos| repos.contacts()).is_empty());
}

#[test]
fn an_answer_whose_confirm_never_comes_ends_as_not_confirmed_after_the_invites_window() {
    let world = World::new();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                expiry: InviteExpiry::OneHour,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    // The inviter cancels before it collects.
    let pending = world.issuer.read(|repos| repos.pending_pairings());
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contact_remove(pending[0].contact_id),
        )
        .unwrap();
    let mut payer_events = world.payer.wallet.subscribe();

    // The inviter may take the reply until an hour after the invite's skew: still waiting.
    world.payer.clock.advance(2 * HOUR);
    world.collect(&world.payer);
    assert_eq!(world.payer.read(|repos| repos.pending_pairings()).len(), 1);

    world.payer.clock.advance(21 * MINUTE);
    world.collect(&world.payer);

    assert!(events(&mut payer_events).iter().any(|event| matches!(
        event,
        Event::PairingFailed(FailedPairing {
            reason: PairingFailure::NotConfirmed,
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
            .block_on(world.issuer.wallet.contact_book().contact_remove(anna_side))
            .unwrap()
    );

    assert_eq!(world.collect(&world.issuer).mailboxes, 0);
    assert!(
        world
            .block_on(world.issuer.wallet.contact_book().contacts())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_collect_limited_to_contacts_drains_only_their_mailboxes() {
    let world = World::new();
    let stranger = world.stranger();
    let (with_payer, _) = world.pair(&world.issuer, &world.payer);
    let (with_stranger, _) = world.pair(&world.issuer, &stranger);
    let only = |ids: &[ContactId]| {
        world
            .block_on(world.issuer.wallet.contact_book().contacts_collect_only(
                &relays(&world.issuer),
                CollectTrigger::Open,
                Some(ids),
            ))
            .unwrap()
            .mailboxes
    };
    // Each contact's mailbox, and its reply mailbox until the invite ends.
    assert_eq!(world.collect(&world.issuer).mailboxes, 4);
    assert_eq!(only(&[with_payer]), 2);
    assert_eq!(only(&[with_stranger, with_payer]), 4);
    assert_eq!(only(&[]), 0);
}

/// More reply mailboxes than one drain takes are collected in turn: each cycle drains at most
/// 50, and every invite's answer is taken within two cycles.
#[test]
fn more_invites_than_one_drain_takes_are_collected_in_turn() {
    let world = World::new();
    let stranger = world.stranger();
    let links: Vec<String> = (0..60)
        .map(|_| world.invite(&world.issuer, "Anna"))
        .collect();
    for (invitee, link) in [(&world.payer, &links[0]), (&stranger, &links[59])] {
        let answered = world
            .block_on(
                invitee
                    .wallet
                    .contact_book()
                    .pairing_accept(&relays(invitee), accept(link, "Ben", false)),
            )
            .unwrap();
        assert!(answered.posted);
    }
    let first = world.collect(&world.issuer);
    let second = world.collect(&world.issuer);
    assert_eq!(first.mailboxes, lepic_epicbox::MAX_MAILBOXES_PER_DRAIN);
    assert_eq!(second.mailboxes, lepic_epicbox::MAX_MAILBOXES_PER_DRAIN);
    assert_eq!(first.paired + second.paired, 2);
}

/// A relay that cannot be reached leaves its mailboxes not reached, and nothing else counts.
#[test]
fn collect_counts_the_mailboxes_of_a_failing_relay_as_not_reached() {
    let world = World::new();
    world.invite(&world.issuer, "Anna");
    world.relay.set_refusing(true);
    let report = world.collect(&world.issuer);
    assert!(report.mailboxes > 0);
    assert_eq!(report.not_reached, report.mailboxes);
    assert_eq!(report.unreachable.len(), 1);
    assert_eq!(
        (report.capped, report.kept, report.refused, report.timed_out),
        (0, 0, 0, 0)
    );
    world.relay.set_refusing(false);
    let report = world.collect(&world.issuer);
    assert_eq!(report.not_reached, 0);
}

/// A mailbox with more messages than one drain takes ends capped; the rest wait.
#[test]
fn collect_counts_a_mailbox_that_hit_the_message_limit_as_capped() {
    let world = World::new();
    let (_, ben_side) = world.pair_by_link();
    let limit = u32::try_from(lepic_epicbox::MAX_MESSAGES_PER_MAILBOX).unwrap();
    for seq in 2..2 + limit {
        post_update(&world, ben_side, seq, "relay.test:80");
    }
    let report = world.collect(&world.issuer);
    assert_eq!(report.capped, 1);
    assert_eq!(
        (
            report.kept,
            report.refused,
            report.timed_out,
            report.not_reached
        ),
        (0, 0, 0, 0)
    );
    let report = world.collect(&world.issuer);
    assert_eq!(report.capped, 0, "the next collect finds the mailbox empty");
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
                .contact_book()
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
                .contact_book()
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
            .block_on(world.issuer.wallet.contact_book().contacts_collect(
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
                .contact_book()
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
        epicbox: Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        meeting: vec![world.issuer.epicbox.settings().endpoint.clone()],
        mode: RelayMode::Online,
    };
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
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
                .contact_book()
                .contacts_collect(&elsewhere, CollectTrigger::Open),
        )
        .unwrap();

    assert_eq!(report.paired, 1);
    let view = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact(answered.contact_id),
        )
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
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&first, "Ben", false)),
        )
        .unwrap();
    world
        .block_on(
            ben_twin
                .wallet
                .contact_book()
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
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    let document = world
        .block_on(world.issuer.wallet.contact_book().contacts_export())
        .unwrap();
    let restored = world.issuer_twin();

    let summary = world
        .block_on(restored.wallet.contact_book().contacts_import(document))
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
        .block_on(world.payer.wallet.contact_book().pairing_accept(
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
                .contact_book()
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
                .contact_book()
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

/// The issuer invites as `card_kind`; the payer answers an invite that says `invite_kind`
/// instead (the kind in an invite is not signed). Returns the payer's events and whether the
/// payer ended up holding the contact.
fn pair_with_invite_kind(card_kind: ContactKind, invite_kind: ContactKind) -> (Vec<Event>, bool) {
    let world = World::new();
    let mut payer_events = world.payer.wallet.subscribe();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                kind: card_kind,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;
    let original = Invite::from_link(&link, ContactNetwork::Floonet).unwrap();
    let relabelled = Invite::new(
        ContactNetwork::Floonet,
        InviteFields {
            kind: invite_kind,
            ..original.fields().clone()
        },
    )
    .unwrap();
    let answered = world
        .block_on(world.payer.wallet.contact_book().pairing_accept(
            &relays(&world.payer),
            accept(&relabelled.to_link(), "Ben", true),
        ))
        .unwrap();
    let LinkOutcome::Confirm { link: confirm, .. } = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_enter_link(&relays(&world.issuer), &answered.reply_link),
        )
        .unwrap()
    else {
        panic!("the issuer did not pair");
    };
    // A refused pairing returns the failure as well as raising the event.
    let outcome = world.block_on(
        world
            .payer
            .wallet
            .contact_book()
            .pairing_enter_link(&relays(&world.payer), &confirm),
    );
    assert_eq!(
        matches!(outcome, Err(ContactError::KindDiffers)),
        card_kind != invite_kind
    );
    let paired = !world.payer.read(|repos| repos.contacts()).is_empty();
    (events(&mut payer_events), paired)
}

#[test]
fn a_card_of_another_kind_than_its_invite_is_refused() {
    let (events, paired) = pair_with_invite_kind(ContactKind::Person, ContactKind::Shop);
    assert!(!paired, "nothing is stored");
    assert!(events.iter().any(|event| matches!(
        event,
        Event::PairingFailed(FailedPairing {
            reason: PairingFailure::KindDiffers,
            ..
        })
    )));
}

#[test]
fn a_card_of_the_kind_its_invite_says_pairs() {
    let (events, paired) = pair_with_invite_kind(ContactKind::Person, ContactKind::Person);
    assert!(paired);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::PairingFailed(_)))
    );
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
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", true)),
        )
        .unwrap();
    let mallory = world.payer_twin();
    let mallory_answer = world
        .block_on(
            mallory
                .wallet
                .contact_book()
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
                .contact_book()
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
                .contact_book()
                .pairing_enter_link(&relays(&world.payer), &confirm),
        )
        .unwrap();
    assert_eq!(outcome, LinkOutcome::Ignored);
    let paired = world
        .block_on(
            mallory
                .wallet
                .contact_book()
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

    // A day later the next one is taken. One naming another relay is stored and reported, and
    // the mailbox stays until the host applies the move (RFC 0002 8.5).
    world.issuer.clock.advance(24 * HOUR + MINUTE);
    post_update(&world, ben_side, 6, "relay.test:8006");
    world.collect(&world.issuer);
    assert_eq!(seq(), 6);
    assert_eq!(peer_mailbox(), shown);
    let moves = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::ContactRelayMoveRequested(request) => Some(request),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(moves.len(), 1, "{moves:?}");
    assert_eq!(moves[0].contact_id, anna_side);
    assert_eq!(moves[0].host, "relay.test:8006");
    // A newer card back on the relay asks for nothing more.
    post_update(&world, ben_side, 7, "relay.test:80");
    world.collect(&world.issuer);
    assert_eq!(seq(), 7);
    assert_eq!(peer_mailbox(), shown);
    assert_eq!(
        world
            .block_on(world.issuer.wallet.contact_book().contact(anna_side))
            .unwrap()
            .requested_relay,
        None
    );
}

/// The party's keys for its contact `contact`, as the wallet derives them.
fn contact_keys(party: &Party, contact: ContactId) -> lepic_wallet_contacts::ContactKeys {
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    lepic_wallet_contacts::contact_root(
        &party.keychain(),
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
        .block_on(
            party
                .wallet
                .contact_book()
                .contact_key_check(&relays(party), new, old),
        )
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
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
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
    // One check per slot a day: another re-pairing that day shows keys-changed at once, so
    // the contact never stays on a pairing nobody may read.
    let (again, _) = world.pair(&world.issuer, &restored);
    let mut issuer_events = world.issuer.wallet.subscribe();
    assert_eq!(
        world
            .block_on(world.issuer.wallet.contact_book().contact_key_check(
                &relays(&world.issuer),
                again,
                anna_side
            ))
            .unwrap(),
        KeyCheckStart::KeysChanged
    );
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.contact(again))
            .unwrap()
            .state,
        ContactState::KeysChanged
    );
    assert_eq!(key_news(&events(&mut issuer_events)), (vec![], vec![again]));
    // The user decides as after an unanswered check.
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contact_keys_resolve(again, KeysDecision::UseNew),
        )
        .unwrap();
    assert_eq!(world.contact_ids(&world.issuer), vec![again]);
}

/// C-12 with the backup: the restored install holds the record already, so a re-pairing anyway
/// folds into it and nothing changes on either side.
#[test]
fn a_re_pairing_with_the_backup_folds_into_the_restored_record() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let document = world
        .block_on(world.payer.wallet.contact_book().contacts_export())
        .unwrap();
    let restored = world.payer_twin();
    world
        .block_on(restored.wallet.contact_book().contacts_import(document))
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
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
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
    // One check per pairing: asked again while it is on its way, nothing more is sent.
    let queued = world
        .issuer
        .read(|repos| repos.contact_outbox(new_on_issuer))
        .len();
    assert_eq!(
        world
            .block_on(world.issuer.wallet.contact_book().contact_key_check(
                &relays(&world.issuer),
                new_on_issuer,
                anna_side
            ))
            .unwrap(),
        KeyCheckStart::Sent
    );
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.contact_outbox(new_on_issuer))
            .len(),
        queued
    );
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
                .contact_book()
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
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
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
                .contact_book()
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
    assert!(news.contains(&Event::ContactUpdated(ContactUpdate::of(
        anna_side,
        ContactChange::Card
    ))));
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

#[test]
fn meeting_relays_are_validated_lowercased_and_deduplicated() {
    use lepic_wallet_contacts::{MAX_MEETING_RELAYS, meeting_host, meeting_relays};
    let parsed = meeting_relays(&["A.test", "a.test:443", "b.test:7443"]).unwrap();
    let hosts: Vec<String> = parsed.iter().map(meeting_host).collect();
    assert_eq!(hosts, ["a.test", "b.test:7443"]);
    assert!(parsed.iter().all(|relay| relay.security() == Security::Tls));
    let none: [&str; 0] = [];
    assert!(matches!(
        meeting_relays(&none),
        Err(ContactError::WordsUnavailable)
    ));
    for bad in [
        "",
        "a.test:",
        "a.test:0",
        "a.test:99999",
        "wss://a.test",
        "a_b.test",
    ] {
        assert!(
            matches!(meeting_relays(&[bad]), Err(ContactError::RelayAddress)),
            "{bad}"
        );
    }
    let many = vec!["a.test"; MAX_MEETING_RELAYS + 1];
    assert!(matches!(
        meeting_relays(&many),
        Err(ContactError::RelayAddress)
    ));
}

/// Pairings in progress are listed on both sides until they complete, and removing one cancels
/// it.
#[test]
fn pairings_in_progress_are_listed_until_they_complete() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    let pending = world
        .block_on(world.issuer.wallet.contact_book().pairings_pending())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].role, lepic_wallet_contacts::PairingRole::Inviter);
    assert_eq!(pending[0].invite_name, "Anna");
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let waiting = world
        .block_on(world.payer.wallet.contact_book().pairings_pending())
        .unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].role, lepic_wallet_contacts::PairingRole::Invitee);
    assert_eq!(waiting[0].contact_id, answered.contact_id);
    assert_eq!(waiting[0].invite_name, "Anna");

    world.collect(&world.issuer);
    world.collect(&world.payer);
    for party in [&world.issuer, &world.payer] {
        assert!(
            world
                .block_on(party.wallet.contact_book().pairings_pending())
                .unwrap()
                .is_empty()
        );
    }

    let cancelled = world.invite(&world.issuer, "Anna");
    assert!(!cancelled.is_empty());
    let id = world
        .block_on(world.issuer.wallet.contact_book().pairings_pending())
        .unwrap()[0]
        .contact_id;
    assert!(
        world
            .block_on(world.issuer.wallet.contact_book().contact_remove(id))
            .unwrap()
    );
    assert!(
        world
            .block_on(world.issuer.wallet.contact_book().pairings_pending())
            .unwrap()
            .is_empty()
    );
}

/// The read and post identities of the pairing mailbox of `seed` on the test relay.
fn pairing_identities(seed: [u8; 16]) -> (lepic_epicbox::Identity, lepic_epicbox::Identity) {
    let (box_sk, from_sk) = lepic_wallet_contacts::pairing_mailbox_keys(
        &seed,
        lepic_primitives::params::Network::Floonet,
    )
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
                .contact_book()
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
        .block_on(world.payer.wallet.contact_book().pairing_sas(
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
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn every_contact_future_is_send() {
    let world = World::new();
    let wallet = &world.issuer.wallet;
    let relays = relays(&world.issuer);
    let id = ContactId([1; 16]);
    let slate_id = lepic_wallet::event::SlateId::from_bytes([2; 16]);
    let tx_id = lepic_store::TxId(1);
    assert_send(
        wallet
            .contact_book()
            .pairing_invite(&relays, invite_request("Anna")),
    );
    assert_send(
        wallet
            .contact_book()
            .pairing_accept(&relays, accept("link", "Ben", false)),
    );
    assert_send(wallet.contact_book().pairing_enter_link(&relays, "link"));
    assert_send(
        wallet
            .contact_book()
            .pairing_sas(&relays, id, SasDecision::Match),
    );
    assert_send(wallet.contact_book().pairings_pending());
    assert_send(
        wallet
            .contact_book()
            .contacts_collect(&relays, CollectTrigger::Open),
    );
    assert_send(wallet.contact_book().contact_key_check(&relays, id, id));
    assert_send(
        wallet
            .contact_book()
            .contact_keys_resolve(id, KeysDecision::KeepOld),
    );
    assert_send(wallet.contact_book().contacts_outbox_deliver(&relays));
    assert_send(
        wallet
            .contact_book()
            .contact_outbox_resend(&relays, lepic_store::ContactOutboxId(1)),
    );
    assert_send(wallet.contact_book().contact_outbox(id));
    assert_send(wallet.contact_book().contacts());
    assert_send(wallet.contact_book().contact(id));
    assert_send(wallet.contact_book().contact_remove(id));
    assert_send(
        wallet
            .contact_book()
            .contact_set_label(id, "Anna".to_owned()),
    );
    assert_send(wallet.contact_book().contact_set_seal(id, true));
    assert_send(wallet.contact_book().contact_set_allow_invoices(id, true));
    assert_send(wallet.contact_book().contact_attach(id, None, None));
    assert_send(wallet.contact_book().contacts_export());
    assert_send(wallet.contact_book().contacts_import(String::new()));
    assert_send(wallet.contact_book().contact_issue_invoice(
        &relays,
        id,
        lepic_wallet::invoice::InvoiceRequest {
            account: AccountIndex(0),
            amount: lepic_primitives::amount::Amount::new(1),
            message: None,
            ttl_blocks: None,
        },
        lepic_wallet_contacts::InvoiceDetails {
            purpose: lepic_contact::Purpose::Request,
            reference: None,
            expires: None,
        },
    ));
    assert_send(wallet.contact_book().contact_invoices());
    assert_send(wallet.contact_book().contact_pay_invoice(
        &relays,
        slate_id,
        lepic_wallet::invoice::PayRequest::new(
            AccountIndex(0),
            lepic_primitives::amount::Amount::new(1),
        ),
    ));
    assert_send(wallet.contact_book().contact_decline_invoice(slate_id));
    assert_send(wallet.contact_book().contact_seal_slate(id, tx_id, None));
    assert_send(
        wallet
            .contact_book()
            .contact_post_slate(&relays, id, tx_id, None),
    );
    assert_send(wallet.contact_book().sealed_open("text"));
    assert_send(
        wallet
            .contact_book()
            .sealed_receive("text", lepic_wallet::ReceiveRequest::default()),
    );
    assert_send(wallet.contact_book().sealed_pay(
        "text",
        lepic_wallet::invoice::PayRequest::new(
            AccountIndex(0),
            lepic_primitives::amount::Amount::new(1),
        ),
    ));
    assert_send(
        wallet
            .contact_book()
            .sealed_finalize("text", lepic_node::Propagation::Stem),
    );
    assert_send(wallet.contact_book().contact_plain_fallback(tx_id));
    assert_send(wallet.contact_book().contact_of_transaction(tx_id));
}

/// R2-07: two collecting cycles started at once run one after the other, so a reply pairs once
/// and raises one event.
#[test]
fn collecting_cycles_started_at_once_take_a_reply_once() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let relays = relays(&world.issuer);

    let book = world.issuer.wallet.contact_book();
    let (first, second) = world.block_on(async {
        tokio::join!(
            book.contacts_collect(&relays, CollectTrigger::Open),
            book.contacts_collect(&relays, CollectTrigger::Open),
        )
    });

    assert_eq!(first.unwrap().paired + second.unwrap().paired, 1);
    let replied = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::PairingReplied(_)))
        .count();
    assert_eq!(replied, 1);
    assert_eq!(world.collect(&world.payer).paired, 1);
}

/// R2-08: once a check ended as not found, a found answer for it is refused, and the user's
/// choice still finds the old record.
#[test]
fn a_found_answer_after_not_found_is_refused() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let before = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    let restored = world.payer_twin();
    let (new_on_issuer, new_on_twin) = world.pair(&world.issuer, &restored);
    let mut issuer_events = world.issuer.wallet.subscribe();
    key_check(&world, &world.issuer, new_on_issuer, anna_side);
    // A not-found reaches the issuer before the restored install's own answer.
    let keys = contact_keys(&restored, new_on_twin);
    let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = restored.read(|repos| repos.contact(new_on_twin)).unwrap();
    let issuer_card =
        ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let not_found = lepic_contact::seal_not_found(
        &issuer_card,
        &signer,
        &mut rand::rngs::StdRng::seed_from_u64(31),
    )
    .unwrap();
    post_sealed(&world, &restored, new_on_twin, &not_found);
    world.collect(&world.issuer);

    settle(&world, &world.issuer, &restored);

    assert_eq!(
        key_news(&events(&mut issuer_events)),
        (vec![], vec![new_on_issuer])
    );
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
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contact_keys_resolve(new_on_issuer, KeysDecision::UseNew),
        )
        .unwrap();
    assert_eq!(world.contact_ids(&world.issuer), vec![new_on_issuer]);
}

/// R2-11: junk in a contact's mailbox raises one event a cycle, however much there is.
#[test]
fn junk_in_a_contact_mailbox_raises_one_event_a_cycle() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let stranger_key = EncSecretKey::from_bytes([9; 32]).public_key();
    for seed in 0..3 {
        let junk = lepic_contact::seal(
            ContactNetwork::Floonet,
            &stranger_key,
            lepic_contact::HintRule::ReplyKey,
            &lepic_contact::Content::new(lepic_contact::MessageType::Notice, b"junk".to_vec()),
            None,
            &mut rand::rngs::StdRng::seed_from_u64(seed),
        )
        .unwrap();
        post_sealed(&world, &world.payer, ben_side, &junk);
    }

    world.collect(&world.issuer);

    let told: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::SealedUnopenable(ContactEvent { contact_id }) => Some(contact_id),
            _ => None,
        })
        .collect();
    assert_eq!(told, vec![anna_side]);
}

/// R2-12: a used invite answers later replies with at most three refusals, so a leaked invite
/// does not make the inviter post to mailboxes of the repliers' choosing without end.
#[test]
fn a_used_invite_sends_at_most_three_refusals() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    assert_eq!(world.collect(&world.issuer).paired, 1);
    let invite = Invite::from_link(&link, ContactNetwork::Floonet).unwrap();
    // Replies to the used invite carry another wallet's card; the stranger answers by hand, which
    // sends nothing, and its record holds the card.
    let stranger = world.stranger();
    let by_hand = world
        .block_on(
            stranger
                .wallet
                .contact_book()
                .pairing_accept(&relays(&stranger), accept(&link, "Cleo", true)),
        )
        .unwrap();
    let record = stranger
        .read(|repos| repos.contact(by_hand.contact_id))
        .unwrap();
    let card = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let (reply_box, reply_from) = pairing_identities(*invite.fields().code.expose_bytes());
    let client = lepic_epicbox::MailboxClient::new(world::settings(), world.relay.connector());
    let codes: Vec<[u8; 16]> = (0..5u8).map(|n| [40 + n; 16]).collect();
    for (n, rc) in (0u8..).zip(&codes) {
        let body = lepic_contact::ReplyBody {
            code: invite.fields().code.clone(),
            nonce: lepic_contact::Nonce::from_bytes([n; 16]),
            confirm_code: lepic_contact::ConfirmCode::from_bytes(*rc),
            card: card.clone(),
        };
        let reply = seal_reply(
            &invite,
            &body,
            &mut rand::rngs::StdRng::seed_from_u64(50 + u64::from(n)),
        )
        .unwrap();
        world
            .block_on(client.post(
                &reply_from,
                reply_box.address(),
                &lepic_contact::armor(&reply),
            ))
            .unwrap();
    }

    world.collect(&world.issuer);

    let mut refused = 0;
    for rc in codes {
        let (confirm_box, _) = pairing_identities(rc);
        let mut collected = Collected(Vec::new());
        world
            .block_on(client.drain_once(&[confirm_box], &mut collected))
            .unwrap();
        refused += collected.0.len();
    }
    assert_eq!(refused, 3);
}

/// R2-14: a backup restores only records whose own card this seed derives, and their mailbox
/// comes from the cards, never from the document's mailbox fields.
#[test]
fn a_backup_restores_only_this_seeds_records_with_mailboxes_from_the_cards() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let expected = world
        .issuer
        .read(|repos| repos.contact_mailbox(anna_side))
        .unwrap();
    let document = world
        .block_on(world.issuer.wallet.contact_book().contacts_export())
        .unwrap();
    // The document's mailbox fields name other mailboxes.
    let mut tampered: serde_json::Value = serde_json::from_str(&document).unwrap();
    for contact in tampered["contacts"].as_array_mut().unwrap() {
        contact["mailbox"]["peer_mailbox"] = serde_json::Value::from("elsewhere@evil.test:443");
        contact["mailbox"]["home_relay"] = serde_json::Value::from("evil.test:443");
        contact["mailbox"]["onion"] = serde_json::Value::from("evil.onion");
    }
    let restored = world.issuer_twin();
    let summary = world
        .block_on(
            restored
                .wallet
                .contact_book()
                .contacts_import(tampered.to_string()),
        )
        .unwrap();
    assert_eq!(summary.imported, 1);
    let mailbox = restored
        .read(|repos| repos.contact_mailbox(anna_side))
        .unwrap();
    assert_eq!(mailbox.peer_mailbox, expected.peer_mailbox);
    assert_eq!(mailbox.our_mailbox, expected.our_mailbox);
    assert_eq!(mailbox.home_relay, expected.home_relay);
    assert_eq!(mailbox.onion, None);

    // Another seed's backup brings nothing in.
    let stranger = world.stranger();
    let summary = world
        .block_on(stranger.wallet.contact_book().contacts_import(document))
        .unwrap();
    assert_eq!(summary.imported, 0);
    assert!(stranger.read(|repos| repos.contacts()).is_empty());
}

/// R3-02: a pairing that ends leaves nothing of it behind: the confirm kept for a repeat goes
/// with the pending pairing.
#[test]
fn an_ended_pairing_keeps_no_confirm() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let pending = world.issuer.read(|repos| repos.pending_pairings());
    assert_eq!(pending.len(), 1);
    let hex: String = pending[0]
        .pairing_id
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let confirm = format!("contact.confirm.{hex}");
    assert!(world.issuer.read(|repos| repos.setting(&confirm)).is_some());

    world
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Mismatch,
        ))
        .unwrap();

    assert!(
        world
            .issuer
            .read(|repos| repos.pending_pairings())
            .is_empty()
    );
    assert_eq!(world.issuer.read(|repos| repos.setting(&confirm)), None);
}

/// R3-04: a label follows the rule of card names, and an address-book id is bounded.
#[test]
fn labels_and_address_book_ids_are_checked() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let wallet = &world.issuer.wallet;
    for bad in [
        "Ben\u{202E}gnp.exe".to_owned(),
        "Ben\nBen".to_owned(),
        "x".repeat(49),
    ] {
        assert!(matches!(
            world.block_on(wallet.contact_book().contact_set_label(anna_side, bad)),
            Err(ContactError::Name(_))
        ));
    }
    world
        .block_on(
            wallet
                .contact_book()
                .contact_set_label(anna_side, "Ben".to_owned()),
        )
        .unwrap();
    world
        .block_on(
            wallet
                .contact_book()
                .contact_set_label(anna_side, String::new()),
        )
        .unwrap();
    assert!(matches!(
        world.block_on(wallet.contact_book().contact_attach(
            anna_side,
            Some("a\u{7}b".to_owned()),
            None
        )),
        Err(ContactError::Name(_))
    ));
    assert!(matches!(
        world.block_on(wallet.contact_book().contact_attach(
            anna_side,
            Some("x".repeat(257)),
            None
        )),
        Err(ContactError::Name(_))
    ));
    world
        .block_on(wallet.contact_book().contact_attach(
            anna_side,
            Some("contact-7".to_owned()),
            None,
        ))
        .unwrap();
}

/// The confirm mailbox the invitee's answer waits on, on the test relay.
fn confirm_mailbox(party: &Party) -> lepic_epicbox::EpicboxAddress {
    let pending = party.read(|repos| repos.pending_pairings());
    let rc = pending[0].secrets.rc.unwrap();
    pairing_identities(rc).0.address().clone()
}

fn failures(events: &[Event]) -> Vec<PairingFailure> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::PairingFailed(FailedPairing { reason, .. }) => Some(*reason),
            _ => None,
        })
        .collect()
}

/// The inviter's confirm could not be posted when it took the reply: it is paired, says so
/// once, and the confirm goes out when the kept reply is taken again, so both sides pair.
#[test]
fn a_confirm_that_did_not_leave_still_tells_the_inviter_and_goes_out_later() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let confirm_box = confirm_mailbox(&world.payer);
    world.relay.set_post_refused(&confirm_box);
    let mut issuer_events = world.issuer.wallet.subscribe();

    world.collect(&world.issuer);
    let anna_side = world.only_contact(&world.issuer);
    let replied = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::PairingReplied(_)))
        .count();
    assert_eq!(replied, 1);
    assert_eq!(world.collect(&world.payer).paired, 0);

    world.relay.set_post_accepted(&confirm_box);
    world.collect(&world.issuer);
    assert_eq!(world.collect(&world.payer).paired, 1);
    assert_eq!(world.only_contact(&world.issuer), anna_side);
    // Told once only.
    assert!(
        !events(&mut issuer_events)
            .iter()
            .any(|event| matches!(event, Event::PairingReplied(_)))
    );
}

/// A confirm that never leaves within the wait after the deadline: the invitee cannot have
/// paired, so the inviter removes its half too, as not confirmed.
#[test]
fn a_confirm_that_never_leaves_ends_the_inviters_half_as_not_confirmed() {
    let world = World::new();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                expiry: InviteExpiry::OneHour,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.relay.set_post_refused(&confirm_mailbox(&world.payer));
    world.collect(&world.issuer);
    assert_eq!(world.contact_ids(&world.issuer).len(), 1);
    let mut issuer_events = world.issuer.wallet.subscribe();

    // Past the deadline its relay answers, but the confirm still does not leave: kept.
    world.issuer.clock.advance(HOUR + 11 * MINUTE);
    world.collect(&world.issuer);
    assert_eq!(world.contact_ids(&world.issuer).len(), 1);

    world.issuer.clock.advance(HOUR);
    world.collect(&world.issuer);
    assert!(world.contact_ids(&world.issuer).is_empty());
    assert_eq!(
        failures(&events(&mut issuer_events)),
        vec![PairingFailure::NotConfirmed]
    );
}

/// The half removed when a confirm never left is the new pairing's record alone: an older
/// pairing with the same contact, attached to the same address-book entry, stays as it was.
#[test]
fn a_confirm_that_never_leaves_removes_only_its_own_pairing() {
    let world = World::new();
    let (old_side, _) = world.pair_by_link();
    world
        .block_on(world.issuer.wallet.contact_book().contact_attach(
            old_side,
            Some("book-1".to_owned()),
            None,
        ))
        .unwrap();
    let old = world.issuer.read(|repos| repos.contact(old_side)).unwrap();
    let twin = world.payer_twin();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                expiry: InviteExpiry::OneHour,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;
    world
        .block_on(
            twin.wallet
                .contact_book()
                .pairing_accept(&relays(&twin), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.relay.set_post_refused(&confirm_mailbox(&twin));
    world.collect(&world.issuer);
    let fresh = world.only_new(&world.issuer, old_side);
    world
        .block_on(world.issuer.wallet.contact_book().contact_attach(
            fresh,
            Some("book-1".to_owned()),
            None,
        ))
        .unwrap();

    world.issuer.clock.advance(2 * HOUR + 11 * MINUTE);
    world.collect(&world.issuer);

    assert_eq!(world.contact_ids(&world.issuer), vec![old_side]);
    let kept = world.issuer.read(|repos| repos.contact(old_side)).unwrap();
    assert_eq!(kept.app_contact.as_deref(), Some("book-1"));
    assert_eq!(kept.peer, old.peer);
    assert!(
        world
            .issuer
            .read(|repos| repos.contact_mailbox(old_side))
            .is_some()
    );
}

/// A reply that reached the relay in time while the inviter could not drain it is taken by
/// the first drain after the deadline, even after failures put the relay in backoff.
#[test]
fn a_reply_waiting_on_a_relay_that_was_down_completes_the_pairing_late() {
    let world = World::new();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                expiry: InviteExpiry::OneHour,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.relay.set_refusing(true);
    let mut issuer_events = world.issuer.wallet.subscribe();
    let foreground = |party: &Party| {
        world
            .block_on(
                party
                    .wallet
                    .contact_book()
                    .contacts_collect(&relays(party), CollectTrigger::Foreground),
            )
            .unwrap()
    };

    world.issuer.clock.advance(HOUR + 15 * MINUTE);
    for _ in 0..3 {
        assert_eq!(foreground(&world.issuer).unreachable.len(), 1);
        world
            .issuer
            .clock
            .advance(31 * std::time::Duration::from_secs(1));
    }
    assert!(failures(&events(&mut issuer_events)).is_empty());
    assert_eq!(world.issuer.read(|repos| repos.pending_pairings()).len(), 1);

    world.relay.set_refusing(false);
    assert_eq!(foreground(&world.issuer).paired, 1);
    assert_eq!(world.collect(&world.payer).paired, 1);
    assert!(
        world
            .issuer
            .read(|repos| repos.pending_pairings())
            .is_empty()
    );
    assert_eq!(
        world.sas(&world.issuer, world.only_contact(&world.issuer)),
        world.sas(&world.payer, world.only_contact(&world.payer))
    );
}

/// Removing a pairing tells the contact in a signed notice: its side is marked removed by the
/// contact, once, and kept until its user removes it.
#[test]
fn removing_a_pairing_tells_the_contact_once() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let mut payer_events = world.payer.wallet.subscribe();

    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_unpair(&relays(&world.issuer), anna_side)
            )
            .unwrap()
    );
    assert!(world.contact_ids(&world.issuer).is_empty());
    assert!(
        !world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
            .removed_by_peer
    );

    world.collect(&world.payer);
    world.collect(&world.payer);

    let view = world
        .block_on(world.payer.wallet.contact_book().contact(ben_side))
        .unwrap();
    assert!(view.removed_by_peer);
    assert_eq!(view.state, ContactState::Paired);
    let unpaired: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::ContactUnpaired(_)))
        .collect();
    assert_eq!(
        unpaired,
        vec![Event::ContactUnpaired(ContactEvent {
            contact_id: ben_side
        })]
    );
    // Removed on this side too, nothing is sent back to a contact that removed it first.
    let posted = world.relay.received("PostSlate");
    assert!(
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .contact_unpair(&relays(&world.payer), ben_side)
            )
            .unwrap()
    );
    assert_eq!(world.relay.received("PostSlate"), posted);
}

/// The unpaired notice counts only signed by the contact's own key: the same text sealed
/// anonymously into the contact's mailbox changes nothing.
#[test]
fn an_unsigned_unpaired_notice_is_dropped() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let issuer_card = ContactCard::decode(
        &world
            .issuer
            .read(|repos| repos.contact(anna_side))
            .unwrap()
            .own_card,
        ContactNetwork::Floonet,
    )
    .unwrap();
    let envelope = lepic_contact::seal(
        ContactNetwork::Floonet,
        issuer_card.enc_key(),
        issuer_card.hint_rule(),
        &lepic_contact::Content::new(
            lepic_contact::MessageType::Notice,
            lepic_wallet::notice::unpaired_notice_to(
                &lepic_methods::epicbox::NOTICE_LENGTHS,
                lepic_methods::epicbox::NOTICE_LENGTHS[0],
            )
            .into_bytes(),
        ),
        None,
        &mut rand::rngs::StdRng::seed_from_u64(7),
    )
    .unwrap();
    post_sealed(&world, &world.payer, ben_side, &envelope);

    world.collect(&world.issuer);

    assert!(
        !world
            .block_on(world.issuer.wallet.contact_book().contact(anna_side))
            .unwrap()
            .removed_by_peer
    );
}

/// `inviter` and `joiner` make a private pairing by link, collect, and both match the words.
/// Returns the two record ids, the inviter's first.
fn private_pair(world: &World, inviter: &Party, joiner: &Party) -> (ContactId, ContactId) {
    let invite = world
        .block_on(inviter.wallet.contact_book().pairing_invite(
            &relays(inviter),
            InviteRequest {
                class: PairingClass::Private,
                ..invite_request("Phone")
            },
        ))
        .unwrap();
    let preview = world
        .block_on(joiner.wallet.contact_book().pairing_preview(&invite.link))
        .unwrap();
    assert_eq!(preview.class, PairingClass::Private);
    assert!(matches!(
        world.block_on(
            joiner
                .wallet
                .contact_book()
                .pairing_accept(&relays(joiner), accept(&invite.link, "Desk", false))
        ),
        Err(ContactError::WrongClass)
    ));
    let answered = world
        .block_on(joiner.wallet.contact_book().pairing_accept(
            &relays(joiner),
            AcceptRequest {
                class: PairingClass::Private,
                ..accept(&invite.link, "Desk", false)
            },
        ))
        .unwrap();
    assert!(answered.posted);
    assert_eq!(world.collect(inviter).paired, 1);
    assert_eq!(world.collect(joiner).paired, 1);
    let sas = |party: &Party| {
        let pairings = world
            .block_on(party.wallet.contact_book().private_pairings())
            .unwrap();
        assert_eq!(pairings.len(), 1, "{pairings:?}");
        pairings[0].sas.unwrap()
    };
    assert_eq!(
        sas(inviter),
        sas(joiner),
        "both screens show the same words"
    );
    for (party, id) in [(inviter, invite.contact_id), (joiner, answered.contact_id)] {
        world
            .block_on(party.wallet.contact_book().pairing_sas(
                &relays(party),
                id,
                SasDecision::Match,
            ))
            .unwrap();
    }
    (invite.contact_id, answered.contact_id)
}

fn payloads(world: &World, party: &Party) -> Vec<lepic_wallet_contacts::ContactPayload> {
    world
        .block_on(party.wallet.contact_book().contact_payloads())
        .unwrap()
}

/// Two installs of one recovery phrase pair privately and pass payloads both ways; the
/// pairing stays out of every contact list and call.
#[test]
fn two_installs_of_one_phrase_pair_privately_and_pass_payloads_both_ways() {
    let world = World::new();
    let twin = world.issuer_twin();
    let (phone, desk) = private_pair(&world, &world.issuer, &twin);

    let to_desk = world
        .block_on(world.issuer.wallet.contact_book().contact_post_payload(
            &relays(&world.issuer),
            phone,
            b"to the desk".to_vec(),
        ))
        .unwrap()
        .id;
    world.collect(&twin);
    let kept = payloads(&world, &twin);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].id, kept[0].contact_id, kept[0].payload.as_slice()),
        (to_desk, desk, b"to the desk".as_slice())
    );
    world
        .block_on(twin.wallet.contact_book().contact_post_payload(
            &relays(&twin),
            desk,
            b"back".to_vec(),
        ))
        .unwrap();
    world.collect(&world.issuer);
    let kept = payloads(&world, &world.issuer);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].payload, b"back");

    for party in [&world.issuer, &twin] {
        assert!(
            world
                .block_on(party.wallet.contact_book().contacts())
                .unwrap()
                .is_empty()
        );
        assert!(
            world
                .block_on(party.wallet.contact_book().pairings_pending())
                .unwrap()
                .is_empty()
        );
    }
    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_book().contact_post_slate(
            &relays(&world.issuer),
            phone,
            lepic_store::TxId(1),
            None
        )),
        Err(ContactError::WrongClass)
    ));
}

#[test]
fn payloads_over_a_private_pairing_wait_for_the_words_check() {
    let world = World::new();
    let twin = world.issuer_twin();
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
        .block_on(twin.wallet.contact_book().pairing_accept(
            &relays(&twin),
            AcceptRequest {
                class: PairingClass::Private,
                ..accept(&invite.link, "Desk", false)
            },
        ))
        .unwrap();
    world.collect(&world.issuer);
    world.collect(&twin);
    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_book().contact_post_payload(
            &relays(&world.issuer),
            invite.contact_id,
            vec![1],
        )),
        Err(ContactError::NotVerified)
    ));
}

#[test]
fn a_payload_reaches_the_paired_contact_once_and_stays_until_acknowledged() {
    let world = World::new();
    let twin = world.issuer_twin();
    let (anna_side, ben_side) = private_pair(&world, &world.issuer, &twin);
    let mut ben_events = twin.wallet.subscribe();
    let id = world
        .block_on(world.issuer.wallet.contact_book().contact_post_payload(
            &relays(&world.issuer),
            anna_side,
            b"opaque bytes".to_vec(),
        ))
        .unwrap()
        .id;
    // The outbox posts it once more, as a retry would.
    let outbox = world
        .block_on(world.issuer.wallet.contact_book().contact_outbox(anna_side))
        .unwrap();
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contact_outbox_resend(&relays(&world.issuer), outbox[0].id),
        )
        .unwrap();

    world.collect(&twin);

    let kept = payloads(&world, &twin);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].id, kept[0].contact_id, kept[0].payload.as_slice()),
        (id, ben_side, b"opaque bytes".as_slice())
    );
    let arrived = events(&mut ben_events)
        .into_iter()
        .filter(|event| matches!(event, Event::ContactPayload(_)))
        .count();
    assert_eq!(arrived, 1);
    assert_eq!(
        world
            .block_on(twin.wallet.contact_book().contact_payloads_ack(&[id, id]))
            .unwrap(),
        1
    );
    assert!(payloads(&world, &twin).is_empty());
    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_book().contact_post_payload(
            &relays(&world.issuer),
            anna_side,
            vec![0; lepic_wallet_contacts::MAX_APP_PAYLOAD_LEN + 1],
        )),
        Err(ContactError::TooLarge { .. })
    ));
}

/// The issuer and the payer pair by link and both match the words. Returns the two contact
/// ids, the issuer's first.
fn verified_pair(world: &World) -> (ContactId, ContactId) {
    let (anna_side, ben_side) = world.pair_by_link();
    for (party, id) in [(&world.issuer, anna_side), (&world.payer, ben_side)] {
        world
            .block_on(party.wallet.contact_book().pairing_sas(
                &relays(party),
                id,
                SasDecision::Match,
            ))
            .unwrap();
    }
    world.collect(&world.issuer);
    world.collect(&world.payer);
    (anna_side, ben_side)
}

fn post_payload(world: &World, party: &Party, contact: ContactId, payload: &[u8]) -> PayloadId {
    world
        .block_on(party.wallet.contact_book().contact_post_payload(
            &relays(party),
            contact,
            payload.to_vec(),
        ))
        .unwrap()
        .id
}

#[test]
fn verified_contacts_pass_payloads_both_ways() {
    let world = World::new();
    let (anna_side, ben_side) = verified_pair(&world);
    let mut ben_events = world.payer.wallet.subscribe();

    let to_ben = post_payload(&world, &world.issuer, anna_side, b"name service hello");
    world.collect(&world.payer);
    let kept = payloads(&world, &world.payer);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].id, kept[0].contact_id, kept[0].payload.as_slice()),
        (to_ben, ben_side, b"name service hello".as_slice())
    );
    let arrived = events(&mut ben_events)
        .into_iter()
        .filter(|event| matches!(event, Event::ContactPayload(_)))
        .count();
    assert_eq!(arrived, 1);
    // A kept payload shows that app payloads work with Anna's proven key.
    let anna_key = payments_address(&world, &world.payer, ben_side).unwrap();
    let works = world
        .payer
        .wallet
        .peer_compat(&world.payer.method, &anna_key)
        .unwrap()
        .stored
        .unwrap()
        .works;
    assert_ne!(works & lepic_transport::marker::features::APP_PAYLOADS, 0);

    let to_anna = post_payload(&world, &world.payer, ben_side, b"back");
    world.collect(&world.issuer);
    let kept = payloads(&world, &world.issuer);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].id, kept[0].contact_id, kept[0].payload.as_slice()),
        (to_anna, anna_side, b"back".as_slice())
    );
    assert_eq!(
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .contact_payloads_ack(&[to_ben])
            )
            .unwrap(),
        1
    );
    assert!(payloads(&world, &world.payer).is_empty());
}

/// A name service's first record reaches the wallet right after the pairing, before either side
/// compared the words, and the wallet can answer over it.
#[test]
fn a_contact_payload_passes_once_paired_before_any_words_check() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    for (party, id) in [(&world.issuer, anna_side), (&world.payer, ben_side)] {
        assert_eq!(world_view(&world, party, id).state, ContactState::Paired);
    }

    let hello = post_payload(&world, &world.issuer, anna_side, b"dir-hello");
    world.collect(&world.payer);
    let kept = payloads(&world, &world.payer);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].id, kept[0].contact_id, kept[0].payload.as_slice()),
        (hello, ben_side, b"dir-hello".as_slice())
    );
    post_payload(&world, &world.payer, ben_side, b"answer");
    world.collect(&world.issuer);
    let kept = payloads(&world, &world.issuer);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].payload, b"answer");
}

/// A contact pairing still in progress carries no payloads.
#[test]
fn a_contact_payload_is_refused_while_the_pairing_is_pending() {
    let world = World::new();
    let invite = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&relays(&world.issuer), invite_request("Anna")),
        )
        .unwrap();
    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_book().contact_post_payload(
            &relays(&world.issuer),
            invite.contact_id,
            vec![1],
        )),
        Err(ContactError::NotVerified)
    ));
}

/// One contact fills only its own share: past it, its payloads stay on the relay while a
/// linked device's still arrive, and they come in once the host acknowledges some.
#[test]
fn a_contact_over_its_payload_cap_waits_on_the_relay_and_leaves_room_for_linked_devices() {
    let cap = lepic_wallet_contacts::MAX_KEPT_PAYLOADS_PER_CONTACT;
    let world = World::new();
    let (anna_side, ben_side) = verified_pair(&world);
    let twin = world.issuer_twin();
    let (_, desk) = private_pair(&world, &world.issuer, &twin);

    for n in 0..=cap {
        post_payload(&world, &world.payer, ben_side, &[u8::try_from(n).unwrap()]);
    }
    let linked = post_payload(&world, &twin, desk, b"linked");
    world.collect(&world.issuer);
    let kept = payloads(&world, &world.issuer);
    assert_eq!(kept.len(), cap.checked_add(1).unwrap());
    let from_contact: Vec<_> = kept
        .iter()
        .filter(|payload| payload.contact_id == anna_side)
        .collect();
    assert_eq!(from_contact.len(), cap);
    assert!(kept.iter().any(|payload| payload.id == linked));

    let first = from_contact[0].id;
    assert_eq!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_payloads_ack(&[first])
            )
            .unwrap(),
        1
    );
    world.collect(&world.issuer);
    let mut bytes: Vec<u8> = payloads(&world, &world.issuer)
        .into_iter()
        .filter(|payload| payload.contact_id == anna_side)
        .flat_map(|payload| payload.payload)
        .collect();
    bytes.sort_unstable();
    assert_eq!(bytes.len(), cap);
    assert_eq!(bytes.last(), Some(&u8::try_from(cap).unwrap()));
}

/// A payload left on the relay for its cap is not opened again while the cap holds, and each
/// collecting cycle tells the host once that payloads wait.
#[test]
fn a_payload_left_for_its_cap_is_not_opened_again_and_is_reported_each_cycle() {
    let cap = lepic_wallet_contacts::MAX_KEPT_PAYLOADS_PER_CONTACT;
    let world = World::new();
    let (anna_side, ben_side) = verified_pair(&world);
    for n in 0..cap.checked_add(2).unwrap() {
        post_payload(&world, &world.payer, ben_side, &[u8::try_from(n).unwrap()]);
    }
    let parked_told = |news: Vec<Event>| {
        news.into_iter()
            .filter(|event| {
                *event
                    == Event::ContactPayloadsParked(ContactEvent {
                        contact_id: anna_side,
                    })
            })
            .count()
    };
    let parked = |party: &Party| party.read(|repos| repos.settings_with_prefix("contact.parked."));

    // A cycle takes a batch from the relay, so the one over the cap may come in a later one.
    let mut issuer_events = world.issuer.wallet.subscribe();
    let mut cycles = 0;
    while parked(&world.issuer).is_empty() && cycles < 3 {
        world.collect(&world.issuer);
        cycles += 1;
    }
    assert_eq!(parked_told(events(&mut issuer_events)), 1);
    let marks = parked(&world.issuer);
    assert_eq!(marks.len(), 1);

    // Opening the message again would take it to the cap once more and mark it anew.
    world.issuer.clock.advance(HOUR);
    world.collect(&world.issuer);
    assert_eq!(parked_told(events(&mut issuer_events)), 1);
    assert_eq!(parked(&world.issuer), marks);
    assert_eq!(payloads(&world, &world.issuer).len(), cap);

    let first = payloads(&world, &world.issuer)[0].id;
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contact_payloads_ack(&[first]),
        )
        .unwrap();
    assert!(parked(&world.issuer).is_empty());
    world.collect(&world.issuer);
    assert_eq!(payloads(&world, &world.issuer).len(), cap);
    assert_eq!(parked_told(events(&mut issuer_events)), 1);
}

/// The key of an Epicbox address text.
fn key_of(address: &str) -> [u8; 33] {
    lepic_epicbox::EpicboxAddress::parse(address, RelayNetwork::Floonet)
        .unwrap()
        .public_key()
        .to_bytes()
}

fn payments_address(world: &World, party: &Party, contact: ContactId) -> Option<String> {
    world_view(world, party, contact).payments_address
}

fn world_view(
    world: &World,
    party: &Party,
    contact: ContactId,
) -> lepic_wallet_contacts::ContactView {
    world
        .block_on(party.wallet.contact_book().contact(contact))
        .unwrap()
}

#[test]
fn a_pairing_by_link_proves_both_payments_addresses() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();

    let on_issuer = payments_address(&world, &world.issuer, anna_side).unwrap();
    let on_payer = payments_address(&world, &world.payer, ben_side).unwrap();
    assert_eq!(
        key_of(&on_issuer),
        world.payer.address.public_key().to_bytes()
    );
    assert_eq!(
        key_of(&on_payer),
        world.issuer.address.public_key().to_bytes()
    );
    // Both cards name the address, and the record keeps its key for lookups.
    let record = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    assert_eq!(
        record.facts.payments_key,
        Some(world.payer.address.public_key().to_bytes())
    );
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    assert_eq!(
        key_of(own.fields().payments_address.as_ref().unwrap().as_str()),
        world.issuer.address.public_key().to_bytes()
    );
    // The invite carried the inviter's mailbox key, the one its card names.
    let record = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let link = world.invite(&world.issuer, "Anna");
    let invite = Invite::from_link(&link, ContactNetwork::Floonet).unwrap();
    assert!(invite.fields().mailbox_key.is_some());
    assert_ne!(
        invite.fields().mailbox_key,
        Some(key_of(peer.fields().mailbox.as_str()))
    );
}

#[test]
fn attaching_to_an_entry_needs_the_proven_address() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let book = world.issuer.wallet.contact_book();
    let attach = |address: Option<String>| {
        world.block_on(book.contact_attach(anna_side, Some("book-1".to_owned()), address))
    };
    assert!(matches!(
        attach(Some(world.issuer.address.to_string())),
        Err(ContactError::OtherAddress)
    ));
    assert_eq!(
        world_view(&world, &world.issuer, anna_side).app_contact,
        None
    );
    // The same key on another relay is the same address.
    let same_key = format!("{}@elsewhere.test", world.payer.address.key_text());
    attach(Some(same_key)).unwrap();
    assert_eq!(
        world_view(&world, &world.issuer, anna_side)
            .app_contact
            .as_deref(),
        Some("book-1")
    );
    attach(None).unwrap();
}

#[test]
fn a_pairing_without_a_proof_cannot_be_attached_to_an_entry_with_an_address() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    world.issuer.write(|repos| {
        let mut record = repos.contact(anna_side)?.unwrap();
        record.facts.payments_address = None;
        record.facts.payments_key = None;
        repos.put_contact(&record)
    });
    let result = world.block_on(world.issuer.wallet.contact_book().contact_attach(
        anna_side,
        Some("book-1".to_owned()),
        Some(world.payer.address.to_string()),
    ));
    assert!(matches!(result, Err(ContactError::AddressProofMissing)));
    assert_eq!(
        world_view(&world, &world.issuer, anna_side).app_contact,
        None
    );
}

/// Posts the payer's card for its pairing with the issuer, seq `seq`, naming `address` in tag
/// 09, as a contact update carrying `proof`.
fn post_address_update(
    world: &World,
    ben_side: ContactId,
    seq: u32,
    address: &str,
    proof: Option<[u8; 32]>,
) {
    let record = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    let keys = contact_keys(&world.payer, ben_side);
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let mut fields = own.fields().clone();
    fields.seq = seq;
    fields.payments_address = Some(lepic_contact::MailboxAddress::new(address).unwrap());
    let card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let envelope = lepic_contact::seal_contact_update_with(
        &peer,
        &card,
        &signer,
        &lepic_contact::PairingExtras {
            address_proof: proof,
            features: Some(5),
            domain: None,
        },
        &mut rand::rngs::StdRng::seed_from_u64(u64::from(seq)),
    )
    .unwrap();
    post_sealed(world, &world.payer, ben_side, &envelope);
}

#[test]
fn an_update_whose_proof_fails_keeps_the_proven_address() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let proven = payments_address(&world, &world.issuer, anna_side).unwrap();
    let stranger = format!("{}@relay.test:80", world.issuer.address.key_text());

    post_address_update(&world, ben_side, 2, &stranger, Some([7; 32]));
    world.collect(&world.issuer);
    post_address_update(&world, ben_side, 3, &stranger, None);
    world.collect(&world.issuer);

    let record = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    // The cards were taken, the address was not.
    assert_eq!(record.peer.unwrap().seq, 3);
    assert_eq!(
        payments_address(&world, &world.issuer, anna_side),
        Some(proven)
    );
    assert_eq!(record.facts.peer_features, 5);
}

/// Leaves `party`'s pairing `contact` as a build before address proofs left it: no payments
/// address in either card, none proven, no features heard.
fn as_paired_before_address_proofs(party: &Party, contact: ContactId) {
    let keys = contact_keys(party, contact);
    party.write(|repos| {
        let mut record = repos.contact(contact)?.unwrap();
        let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
        let mut fields = own.fields().clone();
        fields.payments_address = None;
        let signer = lepic_contact::SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
        record.own_card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer)
            .unwrap()
            .as_bytes()
            .to_vec();
        record.facts.payments_address = None;
        record.facts.payments_key = None;
        record.facts.peer_features = 0;
        repos.put_contact(&record)?;
        repos.delete_setting("contact.address-cards")
    });
}

#[test]
fn a_pairing_from_before_address_proofs_stays_unproven_and_cannot_be_attached_by_address() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    as_paired_before_address_proofs(&world.issuer, anna_side);
    as_paired_before_address_proofs(&world.payer, ben_side);
    let peer_seq = |party: &Party, contact| {
        party
            .read(|repos| repos.contact(contact))
            .unwrap()
            .peer
            .unwrap()
            .seq
    };
    let seqs = (
        peer_seq(&world.issuer, anna_side),
        peer_seq(&world.payer, ben_side),
    );
    let states = (
        world_view(&world, &world.issuer, anna_side).state,
        world_view(&world, &world.payer, ben_side).state,
    );

    world.collect(&world.issuer);
    world.collect(&world.payer);
    world.collect(&world.issuer);

    // No card goes to such a pairing, and nothing claims an address for it.
    assert_eq!(
        (
            peer_seq(&world.issuer, anna_side),
            peer_seq(&world.payer, ben_side)
        ),
        seqs
    );
    for (party, contact) in [(&world.issuer, anna_side), (&world.payer, ben_side)] {
        assert_eq!(payments_address(&world, party, contact), None);
    }
    assert_eq!(
        (
            world_view(&world, &world.issuer, anna_side).state,
            world_view(&world, &world.payer, ben_side).state,
        ),
        states
    );
    let attach = world.block_on(world.issuer.wallet.contact_book().contact_attach(
        anna_side,
        Some("book-1".to_owned()),
        Some(world.payer.address.to_string()),
    ));
    assert!(matches!(attach, Err(ContactError::AddressProofMissing)));
    assert_eq!(
        world_view(&world, &world.issuer, anna_side).app_contact,
        None
    );
}
