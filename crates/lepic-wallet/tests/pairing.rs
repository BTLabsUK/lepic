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

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use lepic_contact::{
    ContactCard, ContactKind, EncSecretKey, Invite, InviteFields, Network as ContactNetwork,
    PairingLink, SealedEnvelope, open_reply, pairing_envelope_from_link, seal_reply,
};
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{Domain, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_store::{AccountIndex, ContactId, ContactState, WalletStore};
use lepic_wallet::Event;
use lepic_wallet::contact::{
    AcceptRequest, CardRequest, CollectTrigger, ContactError, ContactRelays, InviteExpiry,
    InviteRequest, LinkOutcome, PairingFailure, RelayMode, SasDecision,
};
use lepic_wallet::event::{ContactEvent, FailedPairing};
use rand::SeedableRng;
use tokio::sync::broadcast::Receiver;
use world::{Party, World};

const HOUR: Duration = Duration::from_secs(60 * 60);
const MINUTE: Duration = Duration::from_secs(60);

fn relays(party: &Party) -> ContactRelays {
    ContactRelays {
        epicbox: party.epicbox.clone(),
        built_in: Vec::new(),
        mode: RelayMode::Online,
    }
}

fn invite_request(name: &str) -> InviteRequest {
    InviteRequest {
        account: AccountIndex(0),
        name: name.to_owned(),
        kind: ContactKind::Person,
        expiry: InviteExpiry::OneDay,
        offer_words: false,
    }
}

fn accept(link: &str, name: &str, by_hand: bool) -> AcceptRequest {
    AcceptRequest {
        link: link.to_owned(),
        account: AccountIndex(0),
        name: name.to_owned(),
        by_hand,
    }
}

fn events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok()).collect()
}

impl World {
    fn invite(&self, party: &Party, name: &str) -> String {
        self.block_on(
            party
                .wallet
                .pairing_invite(&relays(party), invite_request(name)),
        )
        .unwrap()
        .link
    }

    fn collect(&self, party: &Party) -> lepic_wallet::contact::CollectReport {
        self.block_on(
            party
                .wallet
                .contacts_collect(&relays(party), CollectTrigger::Open),
        )
        .unwrap()
    }

    /// The issuer invites, the payer answers through the relay, and both collect.
    fn pair_by_link(&self) -> (ContactId, ContactId) {
        let link = self.invite(&self.issuer, "Anna");
        let answered = self
            .block_on(
                self.payer
                    .wallet
                    .pairing_accept(&relays(&self.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert!(answered.posted);
        assert_eq!(self.collect(&self.issuer).paired, 1);
        assert_eq!(self.collect(&self.payer).paired, 1);
        let issuer_contact = self.only_contact(&self.issuer);
        assert_eq!(answered.contact_id, self.only_contact(&self.payer));
        (issuer_contact, answered.contact_id)
    }

    fn only_contact(&self, party: &Party) -> ContactId {
        let contacts = self.block_on(party.wallet.contacts()).unwrap();
        assert_eq!(contacts.len(), 1, "{contacts:?}");
        contacts[0].contact_id
    }

    fn sas(&self, party: &Party, contact: ContactId) -> Vec<&'static str> {
        self.block_on(party.wallet.contact(contact))
            .unwrap()
            .sas
            .unwrap()
            .iter()
            .map(|symbol| symbol.name)
            .collect()
    }
}

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
        .block_on(wallet.pairing_sas(anna_side, SasDecision::Skip))
        .unwrap();
    assert_eq!(
        world.block_on(wallet.contact(anna_side)).unwrap().state,
        ContactState::Paired
    );
    world
        .block_on(wallet.pairing_sas(anna_side, SasDecision::Match))
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
        .block_on(
            world
                .payer
                .wallet
                .pairing_sas(ben_side, SasDecision::Mismatch),
        )
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
    assert_eq!(world.collect(&twin).paired, 0);
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
        .block_on(
            world
                .issuer
                .wallet
                .pairing_sas(anna_side, SasDecision::Match),
        )
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

    for seq in 2..=5 {
        post_update(&world, ben_side, seq, &format!("relay.test:{}", 8000 + seq));
    }
    // An older card than the stored one changes nothing.
    post_update(&world, ben_side, 1, "old.test");
    world.collect(&world.issuer);

    let updates = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::ContactUpdated(_)))
        .count();
    assert_eq!(updates, 3);
    assert!(
        peer_mailbox().ends_with("@relay.test:8004"),
        "{}",
        peer_mailbox()
    );
    let seq = world
        .issuer
        .read(|repos| repos.contact(anna_side))
        .unwrap()
        .peer
        .unwrap()
        .seq;
    assert_eq!(seq, 4);

    // A day later the next one is taken.
    world.issuer.clock.advance(24 * HOUR + MINUTE);
    post_update(&world, ben_side, 6, "relay.test:8006");
    world.collect(&world.issuer);
    assert!(peer_mailbox().ends_with("@relay.test:8006"));
}
