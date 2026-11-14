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
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork};
use lepic_keychain::Identifier;
use lepic_methods::epicbox::Epicbox;
use lepic_primitives::amount::Amount;
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_store::{ReceiveListing, TxDirection, TxState};
use lepic_transport::transport::Destination;
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::namespace::Listing;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use std::time::Duration;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn name_service() -> Listing {
    let secret = SecretKey::from_array([0x31; 32]).unwrap();
    Listing::new(PublicKey::from_secret_key(&secret).unwrap(), 0)
}

impl World {
    fn listing_address(&self, party: &Party, listing: &Listing) -> EpicboxAddress {
        party.epicbox.address_at(&party.wallet, listing).unwrap()
    }

    fn drain_listing(&self, party: &Party, listing: &Listing) -> InboxSummary {
        self.block_on(party.epicbox.drain_at(&party.wallet, listing))
            .unwrap()
    }

    fn drain_listings(&self, party: &Party, listings: &[Listing]) -> Vec<InboxSummary> {
        self.block_on(party.epicbox.drain_many_at(&party.wallet, listings))
            .into_iter()
            .map(|result| result.unwrap())
            .collect()
    }

    /// As [`Self::drain_listings`] through `epicbox`, a client of its own.
    fn drain_listings_through(
        &self,
        epicbox: &Epicbox,
        party: &Party,
        listings: &[Listing],
    ) -> Vec<InboxSummary> {
        self.block_on(epicbox.drain_many_at(&party.wallet, listings))
            .into_iter()
            .map(|result| result.unwrap())
            .collect()
    }

    /// Three listings of one service, each with a payment waiting at the relay; the payer is
    /// funded for three sends.
    fn three_listings_with_a_payment_each(&self) -> Vec<Listing> {
        let service = name_service();
        self.payer.fund(10, world::FUNDING);
        self.payer.fund(11, world::FUNDING);
        let listings: Vec<Listing> = (0..3)
            .map(|generation| Listing::new(*service.service_key(), generation))
            .collect();
        for listing in &listings {
            self.pay(&self.listing_address(&self.issuer, listing));
        }
        listings
    }

    fn drain_payments(&self, party: &Party) -> InboxSummary {
        self.block_on(party.epicbox.drain(&party.wallet)).unwrap()
    }

    fn pay(&self, to: &EpicboxAddress) -> SentSlate {
        self.block_on(self.payer.wallet.send(
            &self.payer.method,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
    }
}

#[test]
fn a_payment_to_a_listing_is_answered_from_it_and_names_it() {
    let world = World::new();
    let listing = name_service();
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
            service_key: listing.service_key().to_bytes(),
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
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                payment_proof_recipient: Some(proof),
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(path.clone()),
            },
        ))
        .unwrap();
    (sent, std::fs::read_to_string(path).unwrap())
}

#[test]
fn a_listing_payment_that_asks_for_a_proof_is_refused_and_nothing_is_signed() {
    let world = World::new();
    let listing = name_service();
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
    let listing = name_service();
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
    let listing = name_service();
    let first = world.listing_address(&world.issuer, &listing);
    let next = world.listing_address(
        &world.issuer,
        &Listing::new(*listing.service_key(), listing.generation() + 1),
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

#[test]
fn three_listings_are_drained_on_one_relay_connection() {
    let world = World::new();
    let listings = world.three_listings_with_a_payment_each();
    let subscribed = world.relay.subscribing_connections();

    let summaries = world.drain_listings(&world.issuer, &listings);

    assert_eq!(
        summaries
            .iter()
            .map(|summary| summary.received)
            .collect::<Vec<_>>(),
        [1, 1, 1]
    );
    assert_eq!(world.relay.subscribing_connections() - subscribed, 1);
    for listing in &listings {
        let address = world.listing_address(&world.issuer, listing);
        assert_eq!(world.relay.pending(&address), 0);
    }
    // Each payment was answered from its own listing: the payer finalizes all three.
    assert_eq!(world.drain_payments(&world.payer).finalized, 3);
}

#[test]
fn listings_after_a_kept_message_continue_on_a_new_connection() {
    let world = World::new();
    let service = name_service();
    let listings: Vec<Listing> = (0..3)
        .map(|generation| Listing::new(*service.service_key(), generation))
        .collect();
    world.pay(&world.listing_address(&world.issuer, &listings[0]));
    // The relay does not answer the post of the reply, so the wallet keeps the payment for
    // another try.
    world.relay.set_unroutable(&world.payer.address);
    // A client that gives up on the unanswered post after a second.
    let mut settings = world::settings();
    settings.response_timeout = Duration::from_secs(1);
    let epicbox = Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector());
    let subscribed = world.relay.subscribing_connections();

    let summaries = world.drain_listings_through(&epicbox, &world.issuer, &listings);

    assert_eq!(summaries[0].held, 1);
    assert_eq!((summaries[1].held, summaries[2].held), (0, 0));
    // The first listing's connection was closed with the kept message; the other two share one.
    assert_eq!(world.relay.subscribing_connections() - subscribed, 2);
    assert_eq!(
        world
            .relay
            .pending(&world.listing_address(&world.issuer, &listings[0])),
        1
    );

    // Once answers can go out again the kept payment is answered; the wallet had stored it.
    world.relay.set_routable(&world.payer.address);
    let again = world.drain_listings_through(&epicbox, &world.issuer, &listings[..1]);
    assert_eq!((again[0].held, again[0].repeated), (0, 1));
    assert_eq!(
        world
            .relay
            .pending(&world.listing_address(&world.issuer, &listings[0])),
        0
    );
}

#[test]
fn an_empty_list_of_listings_opens_no_connection() {
    let world = World::new();
    assert!(world.drain_listings(&world.issuer, &[]).is_empty());
    assert_eq!(world.relay.connections_made(), 0);
}
