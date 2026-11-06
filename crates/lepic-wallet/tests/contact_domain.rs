// SPDX-License-Identifier: Apache-2.0
//! The domain claim of a pairing (ADR 0043, RFC 0002 extension 0x83) between two LEPIC wallets
//! on the mock relay: the claim the reply and the confirm carry, the update that replaces it,
//! and the verdict of a well-known file the host fetched.

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

use helpers::{MINUTE, relays};
use lepic_contact::{Network as ContactNetwork, VerifyingKey};
use lepic_store::{ContactId, DomainClaimBytes};
use lepic_wallet_contacts::{
    ContactError, DomainFile, DomainRefused, DomainVerdict, WalletContacts,
};
use world::{Party, World};

const ANNA: &str = "anna.example";
const BEN: &str = "ben.example";

/// What the party shows of the contact's claim: the domain and the attestation, as the view has
/// them.
fn peer_claim(
    world: &World,
    party: &Party,
    contact: ContactId,
) -> (Option<String>, Option<Vec<u8>>) {
    let view = world
        .block_on(party.wallet.contact_book().contact(contact))
        .unwrap();
    (view.peer_domain, view.peer_domain_attestation)
}

/// The well-known file of a domain that lists `keys` for Floonet.
fn file(keys: &[VerifyingKey]) -> Vec<u8> {
    DomainFile::render(ContactNetwork::Floonet, keys, &[]).into_bytes()
}

fn verify(
    world: &World,
    party: &Party,
    contact: ContactId,
    file: &[u8],
) -> Result<DomainVerdict, ContactError> {
    world.block_on(party.wallet.contact_book().domain_verify(contact, file))
}

fn advance(world: &World, by: std::time::Duration) {
    world.issuer.clock.advance(by);
    world.payer.clock.advance(by);
}

/// The reply carries the invitee's claim and the confirm the inviter's: each side stores the
/// other's, unverified, and a file that lists the other's domain key proves it.
#[test]
fn reply_and_confirm_store_received_claim() {
    let world = World::with_domains(Some(ANNA), Some(BEN));
    let (issuer_side, payer_side) = world.pair_by_link();

    let (domain, attestation) = peer_claim(&world, &world.issuer, issuer_side);
    assert_eq!(domain.as_deref(), Some(BEN));
    assert!(attestation.is_some_and(|bytes| !bytes.is_empty()));
    let (domain, attestation) = peer_claim(&world, &world.payer, payer_side);
    assert_eq!(domain.as_deref(), Some(ANNA));
    assert!(attestation.is_some_and(|bytes| !bytes.is_empty()));

    let issuer_key = world.issuer.wallet.contact_book().own_domain_key().unwrap();
    let payer_key = world.payer.wallet.contact_book().own_domain_key().unwrap();
    assert_ne!(issuer_key, payer_key);

    // The payer proves the issuer's claim with the issuer's key, and the issuer the payer's.
    assert_eq!(
        verify(&world, &world.payer, payer_side, &file(&[issuer_key])).unwrap(),
        DomainVerdict::Proven
    );
    assert_eq!(
        verify(&world, &world.issuer, issuer_side, &file(&[payer_key])).unwrap(),
        DomainVerdict::Proven
    );
    // One of several listed keys is enough.
    let other = lepic_contact::SigningKey::from_bytes(&[9; 32]).verifying_key();
    assert_eq!(
        verify(
            &world,
            &world.payer,
            payer_side,
            &file(&[other, issuer_key])
        )
        .unwrap(),
        DomainVerdict::Proven
    );
    // A file that lists the other's key is no proof of this side's.
    assert_eq!(
        verify(&world, &world.payer, payer_side, &file(&[payer_key])).unwrap(),
        DomainVerdict::Refused(DomainRefused::NoKeyMatches)
    );
    assert_eq!(
        verify(&world, &world.payer, payer_side, b"not json").unwrap(),
        DomainVerdict::Refused(DomainRefused::FileMalformed)
    );
    // The claim stays unverified in the record whatever the verdict.
    assert_eq!(
        peer_claim(&world, &world.payer, payer_side).0.as_deref(),
        Some(ANNA)
    );
}

/// A wallet that claims no domain shows none, and there is nothing to verify.
#[test]
fn a_pairing_without_a_claim_shows_none() {
    let world = World::with_domains(Some(ANNA), None);
    let (issuer_side, payer_side) = world.pair_by_link();

    assert_eq!(peer_claim(&world, &world.issuer, issuer_side), (None, None));
    assert_eq!(
        peer_claim(&world, &world.payer, payer_side).0.as_deref(),
        Some(ANNA)
    );
    let key = world.payer.wallet.contact_book().own_domain_key().unwrap();
    assert!(matches!(
        verify(&world, &world.issuer, issuer_side, &file(&[key])),
        Err(ContactError::NoDomainClaim)
    ));
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .domain_verify(ContactId([7; 16]), &file(&[key]))
        ),
        Err(ContactError::UnknownContact)
    ));
}

/// `contacts_tell_domain` sends a fresh claim, which replaces the stored one: the attestation
/// changes with the time it was issued and still verifies. An update from a wallet with no
/// claim clears the stored one.
#[test]
fn update_replaces_claim() {
    let world = World::with_domains(Some(ANNA), Some(BEN));
    let (_issuer_side, payer_side) = world.pair_by_link();
    let issuer_key = world.issuer.wallet.contact_book().own_domain_key().unwrap();
    let (_, before) = peer_claim(&world, &world.payer, payer_side);
    let before = before.unwrap();

    advance(&world, 10 * MINUTE);
    let told = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_tell_domain(&relays(&world.issuer)),
        )
        .unwrap();
    assert_eq!(told, 1);
    world.collect(&world.issuer);
    world.collect(&world.payer);

    let (domain, after) = peer_claim(&world, &world.payer, payer_side);
    assert_eq!(domain.as_deref(), Some(ANNA));
    let after = after.unwrap();
    assert_ne!(after, before);
    assert_eq!(
        verify(&world, &world.payer, payer_side, &file(&[issuer_key])).unwrap(),
        DomainVerdict::Proven
    );

    // A contact update that carries no claim clears the stored one: the payer holds a claim the
    // issuer never made, and the issuer's next update takes it away.
    let world = World::with_domains(None, Some(BEN));
    let (issuer_side, payer_side) = world.pair_by_link();
    assert_eq!(peer_claim(&world, &world.payer, payer_side), (None, None));
    world.payer.write(|repos| {
        let mut record = repos.contact(payer_side)?.unwrap();
        record.facts.peer_domain = Some(DomainClaimBytes {
            domain: ANNA.to_owned(),
            attestation: vec![1; 8],
        });
        repos.put_contact(&record)
    });
    assert_eq!(
        peer_claim(&world, &world.payer, payer_side).0.as_deref(),
        Some(ANNA)
    );
    advance(&world, 10 * MINUTE);
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_set_own_profile(&relays(&world.issuer), 1),
        )
        .unwrap();
    world.collect(&world.issuer);
    world.collect(&world.payer);
    assert_eq!(peer_claim(&world, &world.payer, payer_side), (None, None));
    assert_eq!(
        peer_claim(&world, &world.issuer, issuer_side).0.as_deref(),
        Some(BEN)
    );
}

/// A wallet opened without a domain cannot tell one.
#[test]
fn telling_a_domain_needs_a_configured_one() {
    let world = World::new();
    let result = world.block_on(
        world
            .issuer
            .wallet
            .contact_book()
            .contacts_tell_domain(&relays(&world.issuer)),
    );
    assert!(matches!(result, Err(ContactError::NoDomainConfigured)));
}
