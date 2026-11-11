// SPDX-License-Identifier: Apache-2.0
//! The contact kind is deprecated (ADR 0041): new pairings write person whatever a request says,
//! and a pairing that started with another kind keeps it.

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

use helpers::{accept, invite_request, relays};
use lepic_contact::{ContactCard, ContactKind, Invite, Network as ContactNetwork, SigningKey};
use lepic_primitives::params::Network;
use lepic_store::ContactId;
use lepic_wallet::account::parent_key_id;
use lepic_wallet_contacts::{InviteRequest, WalletContacts, contact_root};
use world::{Party, World};

fn store_kind(kind: ContactKind) -> lepic_store::ContactKind {
    match kind {
        ContactKind::Person => lepic_store::ContactKind::Person,
        ContactKind::Shop => lepic_store::ContactKind::Shop,
        ContactKind::Exchange => lepic_store::ContactKind::Exchange,
    }
}

fn view_kind(world: &World, party: &Party, contact: ContactId) -> Option<ContactKind> {
    world
        .block_on(party.wallet.contact_book().contact(contact))
        .unwrap()
        .kind
}

/// Makes the pairing between `owner` and `peer` one that started with `kind`, as an older wallet
/// wrote it: the owner's stored card is signed again as `kind` (same keys, same seq) and the peer
/// holds that card.
fn as_started_with(
    owner: &Party,
    owner_side: ContactId,
    peer: &Party,
    peer_side: ContactId,
    kind: ContactKind,
) {
    let net = ContactNetwork::Floonet;
    let record = owner.read(|repos| repos.contact(owner_side)).unwrap();
    let root = contact_root(
        &owner.keychain(),
        &parent_key_id(record.account).unwrap(),
        Network::Floonet,
    )
    .unwrap();
    let keys = root.contact_keys(record.slot, record.box_salt).unwrap();
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let mut fields = ContactCard::decode(&record.own_card, net)
        .unwrap()
        .fields()
        .clone();
    fields.kind = kind;
    let card = ContactCard::sign(net, fields, &signer).unwrap();
    owner.write(|repos| {
        let mut record = record.clone();
        record.own_card = card.as_bytes().to_vec();
        repos.put_contact(&record)
    });
    peer.write(|repos| {
        let mut record = repos.contact(peer_side)?.unwrap();
        let held = record.peer.as_mut().unwrap();
        held.bytes = card.as_bytes().to_vec();
        held.kind = store_kind(kind);
        repos.put_contact(&record)
    });
}

#[test]
fn a_new_invite_and_its_answer_write_person_whatever_the_request_says() {
    let world = World::new();
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            InviteRequest {
                kind: ContactKind::Exchange,
                ..invite_request("Anna")
            },
        ))
        .unwrap()
        .link;
    let invite = Invite::from_link(&link, ContactNetwork::Floonet).unwrap();
    assert_eq!(invite.fields().kind, ContactKind::Person);
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.collect(&world.issuer);
    world.collect(&world.payer);
    world.collect(&world.issuer);
    let issuer_side = world.only_contact(&world.issuer);
    let payer_side = world.only_contact(&world.payer);
    // Each side holds the other's card: both say person.
    assert_eq!(
        view_kind(&world, &world.issuer, issuer_side),
        Some(ContactKind::Person)
    );
    assert_eq!(
        view_kind(&world, &world.payer, payer_side),
        Some(ContactKind::Person)
    );
}

#[test]
fn a_stored_shop_and_exchange_pairing_is_viewed_and_its_backup_imports() {
    for kind in [ContactKind::Shop, ContactKind::Exchange] {
        let world = World::new();
        let (issuer_side, payer_side) = world.pair_by_link();
        as_started_with(&world.issuer, issuer_side, &world.payer, payer_side, kind);
        assert_eq!(view_kind(&world, &world.payer, payer_side), Some(kind));
        let document = world
            .block_on(world.payer.wallet.contact_book().contacts_export())
            .unwrap();
        let restored = world.payer_twin();
        world
            .block_on(restored.wallet.contact_book().contacts_import(document))
            .unwrap();
        let contact = world.only_contact(&restored);
        assert_eq!(view_kind(&world, &restored, contact), Some(kind));
    }
}

#[test]
fn a_pairing_that_started_as_exchange_keeps_its_kind_in_a_card_update() {
    let world = World::new();
    let (issuer_side, payer_side) = world.pair_by_link();
    as_started_with(
        &world.issuer,
        issuer_side,
        &world.payer,
        payer_side,
        ContactKind::Exchange,
    );
    let before = world
        .payer
        .read(|repos| repos.contact(payer_side))
        .unwrap()
        .peer
        .unwrap()
        .seq;

    let queued = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_set_own_profile(&relays(&world.issuer), 3),
        )
        .unwrap();
    assert_eq!(queued, 1);
    world.collect(&world.issuer);
    world.collect(&world.payer);

    let record = world.payer.read(|repos| repos.contact(payer_side)).unwrap();
    let held = record.peer.unwrap();
    assert_eq!(held.seq, before + 1, "the peer took the updated card");
    assert_eq!(held.kind, lepic_store::ContactKind::Exchange);
    let own = world
        .issuer
        .read(|repos| repos.contact(issuer_side))
        .unwrap();
    let sent = ContactCard::decode(&own.own_card, ContactNetwork::Floonet).unwrap();
    assert_eq!(sent.fields().kind, ContactKind::Exchange);
}
