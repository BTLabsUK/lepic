// SPDX-License-Identifier: Apache-2.0
//! Sealed slates between paired contacts in files and pastes (RFC 0002 sections 5 and 9): a
//! payment sealed and signed both ways, the plain fallback, and text sealed for another wallet
//! or install.

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

use helpers::HOUR;
use lepic_contact::{
    ContactCard, Content, MessageType, Network as ContactNetwork, Purpose, SigningKey, armor, seal,
};
use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::stage::Stage;
use lepic_store::{SlateStage, TxId};
use lepic_transport::transport::Location;
use lepic_wallet::ReceiveRequest;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet_contacts::{ContactError, SealedAnswer, WalletContacts};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, World};

impl World {
    /// The payer sends `AMOUNT` and writes the plain S1 to a file; returns the transaction.
    fn payer_sends(&self) -> TxId {
        self.payer_sends_file().0
    }

    /// The payer sends `AMOUNT` by file; returns the transaction and the file's slate.
    fn payer_sends_file(&self) -> (TxId, WireSlate) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s1.tx");
        let sent = self
            .block_on(self.payer.wallet.send(
                &crate::support::file(),
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Export {
                    to: Location::File(path.clone()),
                },
            ))
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        (sent.tx_id, WireSlate::text(MediaType::JSON, text))
    }

    fn stored(&self, party: &world::Party, tx_id: TxId, stage: SlateStage) -> WireSlate {
        let slate_id = party
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .slate_id
            .unwrap();
        let bytes = party
            .read(|repos| repos.slate(slate_id, stage))
            .unwrap()
            .bytes;
        WireSlate::text(MediaType::JSON, String::from_utf8(bytes).unwrap())
    }
}

#[test]
fn a_payment_goes_sealed_and_signed_both_ways_and_is_attributed() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    // Paired; nothing sealed from the inviter opened on the invitee yet.
    let view = world
        .block_on(world.payer.wallet.contact_book().contact(ben_side))
        .unwrap();
    assert_eq!(view.last_sealed_in, None);
    let tx_id = world.payer_sends();

    let sealed = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_seal_slate(ben_side, tx_id, None),
        )
        .unwrap();
    assert!(sealed.starts_with("BEGINEPICSEALED. "));
    let opened = world
        .block_on(world.issuer.wallet.contact_book().sealed_open(&sealed))
        .unwrap();
    assert_eq!(opened.contact_id, Some(anna_side));
    assert_eq!(opened.stage, Stage::S1);
    assert_eq!(opened.purpose, Some(Purpose::Payment));

    let received = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .sealed_receive(&sealed, ReceiveRequest::default()),
        )
        .unwrap();
    let SealedAnswer::Sealed(answer) = received.answer else {
        panic!("the answer went plain");
    };
    assert_eq!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_of_transaction(received.received.tx_id)
            )
            .unwrap(),
        Some(anna_side)
    );
    let answer_opened = world
        .block_on(world.payer.wallet.contact_book().sealed_open(&answer))
        .unwrap();
    assert_eq!(answer_opened.contact_id, Some(ben_side));
    assert_eq!(answer_opened.stage, Stage::S2);

    let finalized = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .sealed_finalize(&answer, Propagation::Fluff),
        )
        .unwrap();

    assert_eq!(finalized.tx_id, tx_id);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    // Opening the contact's envelopes marks it heard from, and says when.
    let view = world
        .block_on(world.issuer.wallet.contact_book().contact(anna_side))
        .unwrap();
    assert!(!view.lapsed);
    assert!(view.last_sealed_in.is_some());
}

#[test]
fn a_peek_at_sealed_text_stores_nothing() {
    let world = World::new();
    let (_, ben_side) = world.pair_by_link();
    let tx_id = world.payer_sends();
    let sealed = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_seal_slate(ben_side, tx_id, None),
        )
        .unwrap();
    let received = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .sealed_receive(&sealed, ReceiveRequest::default()),
        )
        .unwrap();
    let SealedAnswer::Sealed(answer) = received.answer else {
        panic!("the answer went plain");
    };
    // The payer has not opened anything sealed from the issuer yet.
    let book = world.payer.wallet.contact_book();
    let heard = || {
        world
            .block_on(book.contact(ben_side))
            .unwrap()
            .last_sealed_in
    };
    assert_eq!(heard(), None);

    let peeked = world.block_on(book.sealed_peek(&answer)).unwrap();
    assert_eq!(peeked.contact_id, Some(ben_side));
    assert_eq!(peeked.stage, Stage::S2);
    assert_eq!(heard(), None, "a peek marked the contact heard from");

    let opened = world.block_on(book.sealed_open(&answer)).unwrap();
    assert_eq!(opened.wire, peeked.wire);
    assert!(heard().is_some());
}

#[test]
fn a_removed_contacts_sealed_text_is_for_another_wallet_or_install() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let tx_id = world.payer_sends();
    let sealed = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_seal_slate(ben_side, tx_id, None),
        )
        .unwrap();
    world
        .block_on(world.issuer.wallet.contact_book().contact_remove(anna_side))
        .unwrap();

    assert!(matches!(
        world.block_on(world.issuer.wallet.contact_book().sealed_open(&sealed)),
        Err(ContactError::NotForThisInstall)
    ));
}

#[test]
fn a_signature_by_another_key_in_a_contacts_slot_is_for_another_install() {
    let world = World::new();
    let (anna_side, _) = world.pair_by_link();
    let record = world.issuer.read(|repos| repos.contact(anna_side)).unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    // Another contact of a twin install in the same slot, signing with its own key.
    let stranger = SigningKey::from_bytes(&[9; 32]);
    let s1 = world.stored(&world.payer, world.payer_sends(), SlateStage::Standard1);
    let envelope = seal(
        ContactNetwork::Floonet,
        own.enc_key(),
        own.hint_rule(),
        &Content::new(MessageType::Slate, s1.as_bytes().to_vec()),
        Some(&stranger),
        &mut rand::rngs::StdRng::seed_from_u64(3),
    )
    .unwrap();

    assert!(matches!(
        world.block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .sealed_open(&armor(&envelope))
        ),
        Err(ContactError::NotForThisInstall)
    ));
}

#[test]
fn a_contact_not_heard_from_in_ninety_days_is_lapsed_and_seal_off_refuses() {
    let world = World::new();
    let (_, ben_side) = world.pair_by_link();
    world.payer.clock.advance(91 * 24 * HOUR);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
            .lapsed
    );

    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_set_seal(ben_side, false),
        )
        .unwrap();
    let tx_id = world.payer_sends();
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_seal_slate(ben_side, tx_id, None)
        ),
        Err(ContactError::SealOff)
    ));
}
