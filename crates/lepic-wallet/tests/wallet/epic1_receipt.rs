// SPDX-License-Identifier: Apache-2.0
//! Receipts of payments to an epic1 address: the payee signs one into its answer, the payer
//! checks it and keeps it with the payment, and a payer that requires one refuses an answer
//! without a receipt that holds.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::epic1::{refusal, send};
use crate::epicbox_world::{AMOUNT, World};

use lepic_contact::{
    EncSecretKey, HintRule, KeyClass, SealedEnvelope, TxContent, TxKey, armor_tx, dearmor, seal_tx,
};
use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_slate::model::SlateId;
use lepic_store::TxState;
use lepic_wallet::ReceiveRequest;
use lepic_wallet::finalize::Finalized;
use lepic_wallet_contacts::epic1_testing::sealed_asking_receipt;
use lepic_wallet_contacts::{
    ContactError, Epic1Paid, Epic1Receipt, Epic1Refusal, ReceiptVerdict, SealedAnswer,
    WalletContacts,
};
use rand::SeedableRng;

impl World {
    /// Takes the payee's answer to the payment `slate_id` off the payer's reply mailbox,
    /// changes its content with `change`, seals it again to the payment's reply key and posts it
    /// back.
    fn change_answer(&self, slate_id: SlateId, change: impl FnOnce(&mut TxContent)) {
        let text = self.changed_answer(slate_id, change);
        self.post(7, &self.reply_mailbox(slate_id), &text, 1);
    }

    /// Takes the payee's answer to the payment `slate_id` off the payer's reply mailbox,
    /// changes its content with `change` and returns it sealed again to the payment's reply
    /// key, as text a user would paste.
    fn changed_answer(&self, slate_id: SlateId, change: impl FnOnce(&mut TxContent)) -> String {
        let texts = self.drain_reply(slate_id);
        assert_eq!(texts.len(), 1);
        let secret = self.reply_secret(slate_id);
        let bytes = dearmor(&texts[0]).unwrap();
        let envelope = SealedEnvelope::decode(&bytes, lepic_contact::Network::Floonet).unwrap();
        let mut content = envelope.open_tx(&secret, KeyClass::Seal).unwrap().content;
        change(&mut content);
        let resealed = seal_tx(
            lepic_contact::Network::Floonet,
            &secret.public_key(),
            TxKey::Seal(HintRule::ReplyKey),
            &content,
            None,
            &mut rand::rngs::StdRng::seed_from_u64(41),
        )
        .unwrap();
        armor_tx(&resealed)
    }

    /// Finalizes the sealed answer `text` as a pasted one, by `sealed_finalize`.
    fn paste_answer(&self, text: &str) -> Result<Finalized, ContactError> {
        self.block_on(
            self.payer
                .wallet
                .contact_book()
                .sealed_finalize(text, Propagation::Stem),
        )
    }

    fn receipt_of(&self, paid: &Epic1Paid) -> Option<Epic1Receipt> {
        self.block_on(self.payer.wallet.contact_book().epic1_receipt(paid.tx_id))
            .unwrap()
    }

    /// Pays a fresh link of the issuer and lets the issuer answer.
    fn pay_and_answer(&self, require_receipt: bool) -> Epic1Paid {
        let issued = self.issue_link(&self.issuer);
        let paid = self
            .pay_epic1_with(&issued.link, send(), require_receipt)
            .unwrap();
        assert_eq!(self.taken(&self.issuer), 1);
        paid
    }

    /// The payment `paid` was refused when its answer came: not finalized, cancelled, and
    /// with no receipt kept.
    fn assert_refused(&self, paid: &Epic1Paid) {
        assert_eq!(self.payer_state(paid.tx_id), TxState::Cancelled);
        assert_eq!(self.payer_locked(), Amount::ZERO);
        assert!(self.node.pushed_transactions().is_empty());
        assert_eq!(self.receipt_of(paid), None);
    }
}

#[test]
fn a_paid_link_leaves_the_payer_a_receipt_that_holds() {
    let world = World::new();
    let paid = world.pay_and_answer(false);
    world.collect(&world.payer);

    let pushed = world.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    let receipt = world.receipt_of(&paid).expect("a receipt is kept");
    assert_eq!(receipt.check(None), ReceiptVerdict::Valid);
    assert_eq!(
        receipt.check(Some(lepic_epicbox::Network::Floonet)),
        ReceiptVerdict::Valid
    );
    assert_eq!(
        receipt.check(Some(lepic_epicbox::Network::Mainnet)),
        ReceiptVerdict::WrongNetwork
    );
    assert_eq!(receipt.address, paid.address);
    assert_eq!(receipt.amount, AMOUNT);
    assert_eq!(receipt.slate_id, paid.slate_id.to_string());
    assert_eq!(
        receipt.kernel_excess,
        pushed[0].kernels()[0].excess.to_hex()
    );

    // The file reads back as itself; one changed fact fails.
    let text = receipt.to_text();
    assert_eq!(Epic1Receipt::parse(&text), Some(receipt.clone()));
    let changed = Epic1Receipt {
        amount: receipt.amount + 1,
        ..receipt
    };
    assert_eq!(changed.check(None), ReceiptVerdict::BadSignature);
}

#[test]
fn a_required_receipt_that_comes_is_kept() {
    let world = World::new();
    let paid = world.pay_and_answer(true);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(
        world.receipt_of(&paid).unwrap().check(None),
        ReceiptVerdict::Valid
    );
}

#[test]
fn an_answer_without_a_receipt_is_finalized_unless_one_is_required() {
    let world = World::new();
    let paid = world.pay_and_answer(false);
    world.change_answer(paid.slate_id, |content| content.receipt = None);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.receipt_of(&paid), None);
}

#[test]
fn a_changed_receipt_is_not_kept() {
    let world = World::new();
    let paid = world.pay_and_answer(false);
    world.change_answer(paid.slate_id, |content| {
        content.receipt.as_mut().unwrap()[40] ^= 1;
    });
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.receipt_of(&paid), None);
}

#[test]
fn a_payer_that_requires_a_receipt_refuses_an_answer_without_one() {
    let world = World::new();
    let paid = world.pay_and_answer(true);
    world.change_answer(paid.slate_id, |content| content.receipt = None);
    world.collect(&world.payer);
    world.assert_refused(&paid);
}

#[test]
fn a_payer_that_requires_a_receipt_refuses_a_changed_one() {
    let world = World::new();
    let paid = world.pay_and_answer(true);
    world.change_answer(paid.slate_id, |content| {
        content.receipt.as_mut().unwrap()[40] ^= 1;
    });
    world.collect(&world.payer);
    world.assert_refused(&paid);
}

/// An answer pasted as sealed text has its receipt checked and kept as one from the reply
/// mailbox has.
#[test]
fn a_pasted_answer_keeps_its_receipt() {
    let world = World::new();
    let paid = world.pay_and_answer(false);
    let text = world.changed_answer(paid.slate_id, |_| {});
    let finalized = world.paste_answer(&text).unwrap();
    assert_eq!(finalized.tx_id, paid.tx_id);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(
        world.receipt_of(&paid).unwrap().check(None),
        ReceiptVerdict::Valid
    );
}

#[test]
fn a_payer_that_requires_a_receipt_refuses_a_pasted_answer_without_one() {
    let world = World::new();
    let paid = world.pay_and_answer(true);
    let text = world.changed_answer(paid.slate_id, |content| content.receipt = None);
    assert_eq!(refusal(world.paste_answer(&text)), Epic1Refusal::NoReceipt);
    world.assert_refused(&paid);
    // The mailbox brings nothing more to finish.
    world.collect(&world.payer);
    world.assert_refused(&paid);
}

#[test]
fn a_payer_that_requires_a_receipt_refuses_a_pasted_changed_one() {
    let world = World::new();
    let paid = world.pay_and_answer(true);
    let text = world.changed_answer(paid.slate_id, |content| {
        content.receipt.as_mut().unwrap()[40] ^= 1;
    });
    assert_eq!(refusal(world.paste_answer(&text)), Epic1Refusal::BadReceipt);
    world.assert_refused(&paid);
}

/// A file sealed to an epic1 address that asks a receipt is answered with one, sealed to the
/// reply key it named.
#[test]
fn a_file_payment_that_asks_a_receipt_is_answered_with_one() {
    let world = World::new();
    world.payer.fund(20, crate::epicbox_world::FUNDING);
    let book = world.issuer.wallet.contact_book();
    let address = book
        .epic1_address(crate::epicbox_world::ACCOUNT)
        .unwrap()
        .encode();
    let reply = EncSecretKey::from_bytes([0x33; 32]);
    let payer_key = lepic_crypto::PublicKey::from_secret_key(
        &lepic_crypto::SecretKey::from_bytes(&[0x71; 32]).unwrap(),
    )
    .unwrap()
    .to_bytes();
    let sealed = sealed_asking_receipt(
        lepic_primitives::params::Network::Floonet,
        &address,
        world.s1_body(send()),
        &reply.public_key(),
        payer_key,
        &mut rand::rngs::StdRng::seed_from_u64(5),
    )
    .unwrap();

    let answered = world
        .block_on(book.sealed_receive(&armor_tx(&sealed), ReceiveRequest::default()))
        .unwrap();
    let SealedAnswer::Sealed(text) = answered.answer else {
        panic!("a sealed answer");
    };
    let bytes = dearmor(&text).unwrap();
    let content = SealedEnvelope::decode(&bytes, lepic_contact::Network::Floonet)
        .unwrap()
        .open_tx(&reply, KeyClass::Seal)
        .unwrap()
        .content;
    assert_eq!(content.receipt.map(|signature| signature.len()), Some(64));
}
