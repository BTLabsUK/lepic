// SPDX-License-Identifier: Apache-2.0
//! Payments to a listing address on the mock relay: the payer sends an ordinary marked S1 to
//! the issuer's listing address, the issuer drains that address on its own connection and
//! answers from it, the transaction names the listing, and nothing about the payment ever
//! leaves the issuer's payments address. A payment that asks for a payment proof is refused
//! and nothing is signed for it.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{EpicboxAddress, TRANSPORT_ID};
use lepic_keychain::Identifier;
use lepic_primitives::amount::Amount;
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_store::{ReceiveListing, TxDirection, TxState};
use lepic_transport::transport::Destination;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::namespace::Listing;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn directory() -> Listing {
    let secret = SecretKey::from_array([0x31; 32]).unwrap();
    Listing::new(PublicKey::from_secret_key(&secret).unwrap(), 0)
}

impl World {
    fn listing_address(&self, party: &Party, listing: &Listing) -> EpicboxAddress {
        party
            .wallet
            .epicbox_address_at(listing, &party.epicbox)
            .unwrap()
    }

    fn drain_listing(&self, party: &Party, listing: &Listing) -> InboxSummary {
        self.block_on(party.wallet.drain_epicbox_at(listing, &party.epicbox))
            .unwrap()
    }

    fn drain_payments(&self, party: &Party) -> InboxSummary {
        self.block_on(party.wallet.epicbox_drain(&party.epicbox))
            .unwrap()
    }

    fn pay(&self, to: &EpicboxAddress) -> SentSlate {
        self.block_on(self.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
    }
}

#[test]
fn a_payment_to_a_listing_is_answered_from_it_and_names_it() {
    let world = World::new();
    let listing = directory();
    let address = world.listing_address(&world.issuer, &listing);
    assert_ne!(address.public_key(), world.issuer.address.public_key());

    let sent = world.pay(&address);
    // The payments address holds nothing; the payment waits at the listing.
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(world.drain_payments(&world.issuer).received, 0);
    assert_eq!(world.drain_listing(&world.issuer, &listing).received, 1);

    let tx = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
        .unwrap();
    assert_eq!(
        world.issuer.read(|repos| repos.receive_listing(tx.id)),
        Some(ReceiveListing {
            dkey: listing.dkey().to_bytes(),
            generation: 0,
        })
    );
    let details = world
        .block_on(world.issuer.wallet.transaction_details(tx.id))
        .unwrap();
    assert_eq!(details.receive_listing, Some(listing));

    // The answer came from the listing: the payer finalizes it as an answer from there.
    assert_eq!(world.drain_payments(&world.payer).finalized, 1);
    let paid = world
        .payer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Outgoing))
        .unwrap();
    assert!(matches!(
        paid.entry.state,
        TxState::Posted | TxState::Finalized | TxState::Confirmed
    ));
    // The payer's posted notice went to the listing, and only a listing drain takes it.
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    let notices = world.drain_listing(&world.issuer, &listing);
    assert_eq!(notices.notices + notices.dropped, 1);
}

/// An S1 asking for a payment proof by `proof`, as a file slate carries it, in V3.
fn s1_with_proof(world: &World, proof: ProofAddress) -> (SentSlate, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s1.tx");
    let sent = world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                payment_proof_recipient: Some(proof),
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(path.clone()),
            },
        ))
        .unwrap();
    (sent, std::fs::read_to_string(path).unwrap())
}

#[test]
fn a_listing_payment_that_asks_for_a_proof_is_refused_and_nothing_is_signed() {
    let world = World::new();
    let listing = directory();
    let address = world.listing_address(&world.issuer, &listing);
    // A proof by the issuer's own payments key, which the payments address would sign.
    let payments_proof_key = world
        .issuer
        .keychain()
        .payment_proof_key(&Identifier::new(2, [0, 0, 0, 0]).unwrap(), 0)
        .unwrap();
    let proof = ProofAddress::from_bytes(payments_proof_key.public_key()).unwrap();
    let (sent, s1) = s1_with_proof(&world, proof);

    world.post(7, &address, &s1, 1);
    let summary = world.drain_listing(&world.issuer, &listing);
    assert_eq!((summary.received, summary.rejected), (0, 1));
    assert!(
        world
            .issuer
            .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
            .is_none()
    );
    // Nothing was answered: no S2 left the listing or the payments address.
    assert_eq!(world.relay.pending(&World::address_of(7)), 0);

    // The same S1 at the payments address is signed there, which is what the listing refuses.
    world.post(7, &world.issuer.address, &s1, 1);
    assert_eq!(world.drain_payments(&world.issuer).received, 1);
    assert_eq!(world.relay.pending(&World::address_of(7)), 1);
}

#[test]
fn a_listing_payment_arriving_at_the_payments_address_gets_no_answer_from_there() {
    let world = World::new();
    let listing = directory();
    let address = world.listing_address(&world.issuer, &listing);
    let sent = world.pay(&address);
    assert_eq!(world.drain_listing(&world.issuer, &listing).received, 1);
    assert_eq!(world.drain_payments(&world.payer).finalized, 1);

    // The same S1, sent again to the payments address, is answered by nobody.
    let s1 = world
        .payer
        .read(|repos| repos.slate(uuid(sent.slate_id), lepic_store::SlateStage::Standard1))
        .unwrap();
    let text = String::from_utf8(s1.bytes).unwrap();
    world.post(7, &world.issuer.address, &text, 1);
    let summary = world.drain_payments(&world.issuer);
    assert_eq!(summary.repeated, 1);
    assert_eq!(world.relay.pending(&World::address_of(7)), 0);
}

#[test]
fn listing_keys_come_back_from_the_phrase_and_differ_by_listing() {
    let world = World::new();
    let listing = directory();
    let first = world.listing_address(&world.issuer, &listing);
    let next = world.listing_address(
        &world.issuer,
        &Listing::new(*listing.dkey(), listing.generation() + 1),
    );
    assert_ne!(first.public_key(), next.public_key());
    // Another install of the phrase derives the same key.
    let twin = world.issuer_twin();
    assert_eq!(world.listing_address(&twin, &listing), first);
    // No address key of the BIP32 tree is a listing key.
    let keychain = world.issuer.keychain();
    let parent = Identifier::new(2, [0, 0, 0, 0]).unwrap();
    for index in [0, 1, 0x8000_0000, 0x8000_0001, u32::MAX] {
        let key = keychain.address_key(&parent, index).unwrap();
        assert_ne!(
            &PublicKey::from_secret_key(&key).unwrap(),
            first.public_key()
        );
    }
}
