// SPDX-License-Identifier: Apache-2.0
//! Epic1 links (EPICTX step 8): a link to the payee's epic1 address names link mailboxes; the
//! payer seals an S1 to the address and posts it there, the payee answers with an S2 through
//! the reply mailbox the payment names, and the payer finalizes.

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

use helpers::relays;
use lepic_contact::{Content, HintRule, MessageType, armor, seal};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork};
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_store::{TxDirection, TxState};
use lepic_transport::host_rule::HostClass;
use lepic_transport::transport::Location;
use lepic_wallet::epic1_index::RESTORE_GAP;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, ReceiveRequest};
use lepic_wallet_contacts::epic1_testing::{
    for_other_network, link_mailboxes, native_body_of, sealed_to_epic1, with_proof_key_of,
    without_amount, without_transports,
};
use lepic_wallet_contacts::in_person_testing::{armored, without_tail};
use lepic_wallet_contacts::{
    ContactError, Epic1LinkIssued, Epic1LinkKind, Epic1LinkRequest, Epic1Paid, Epic1PayRequest,
    Epic1Refusal, InPersonInvoiceRequest, PaymentFile, WalletContacts, payment_file,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, World};

fn refusal<T: std::fmt::Debug>(result: Result<T, ContactError>) -> Epic1Refusal {
    match result {
        Err(ContactError::Epic1(refusal)) => refusal,
        other => panic!("not an epic1 refusal: {other:?}"),
    }
}

fn link_request(kind: Epic1LinkKind, link_relays: &[&str]) -> Epic1LinkRequest {
    Epic1LinkRequest {
        account: ACCOUNT,
        index: 0,
        amount: Some(Amount::new(AMOUNT)),
        message: Some("coffee".to_owned()),
        kind,
        relays: link_relays
            .iter()
            .map(|relay| (*relay).to_owned())
            .collect(),
    }
}

fn send() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

impl World {
    fn issue_link(
        &self,
        party: &Party,
        kind: Epic1LinkKind,
        link_relays: &[&str],
    ) -> Epic1LinkIssued {
        self.try_issue_link(party, kind, link_relays).unwrap()
    }

    fn try_issue_link(
        &self,
        party: &Party,
        kind: Epic1LinkKind,
        link_relays: &[&str],
    ) -> Result<Epic1LinkIssued, ContactError> {
        self.block_on(
            party
                .wallet
                .contact_book()
                .epic1_link(&relays(party), link_request(kind, link_relays)),
        )
    }

    fn pay_link(&self, link: &str, proof: bool) -> Result<Epic1Paid, ContactError> {
        self.pay(link, proof, send(), true)
    }

    fn pay(
        &self,
        link: &str,
        proof: bool,
        send: SendRequest,
        hosts_ok: bool,
    ) -> Result<Epic1Paid, ContactError> {
        let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
        self.block_on(self.payer.wallet.contact_book().epic1_pay(
            &relays(&self.payer),
            Epic1PayRequest {
                link: link.to_owned(),
                send,
                proof,
                slate_file: file,
            },
            hosts_ok,
        ))
    }

    fn taken(&self, party: &Party) -> usize {
        self.collect(party).epic1
    }

    /// The answers the payee holds, all posted by collecting; returns how many.
    fn answers_posted(&self) -> usize {
        let book = self.issuer.wallet.contact_book();
        let answers = self
            .block_on(book.epic1_answers(&relays(&self.issuer)))
            .unwrap();
        assert!(answers.iter().all(|answer| answer.posted));
        answers.len()
    }

    /// The refusal of the payment `slate_id` as the payee seals it: `body` as a notice sealed
    /// to the payer's reply key for the slate, armored.
    fn refusal_of(&self, slate_id: SlateId, body: &str) -> String {
        let reply = lepic_wallet_contacts::contact_root(
            &self.payer.keychain(),
            &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
            Network::Floonet,
        )
        .unwrap()
        .reply_key(*slate_id.as_bytes())
        .unwrap();
        let key =
            lepic_contact::EncSecretKey::from_bytes(*reply.expose_x25519_secret()).public_key();
        let mut rng = rand::rngs::StdRng::seed_from_u64(31);
        let envelope = seal(
            lepic_contact::Network::Floonet,
            &key,
            HintRule::ReplyKey,
            &Content::new(MessageType::Notice, body.as_bytes().to_vec()),
            None,
            &mut rng,
        )
        .unwrap();
        armor(&envelope)
    }

    /// The payer's reply mailbox of the payment `slate_id`.
    fn reply_mailbox(&self, slate_id: SlateId) -> EpicboxAddress {
        let secret = self
            .payer
            .wallet
            .reply_mailbox_key(
                ACCOUNT,
                lepic_contact::Network::Floonet,
                slate_id.as_bytes(),
            )
            .unwrap();
        EpicboxAddress::new(
            lepic_crypto::PublicKey::from_secret_key(&secret).unwrap(),
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        )
    }

    fn payer_state(&self, tx_id: lepic_store::TxId) -> TxState {
        self.payer
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .state
    }

    fn payer_locked(&self) -> Amount {
        self.payer.wallet.balance(ACCOUNT).unwrap().locked
    }

    /// Posts `text` to the first mailbox of `link` from a peer key.
    fn post_to_link(&self, link: &str, text: &str) {
        let mailbox = &link_mailboxes(link).unwrap()[0];
        self.post(7, mailbox, text, 1);
    }
}

#[test]
fn a_link_paid_is_answered_through_the_reply_mailbox_and_finalized() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    assert_eq!(issued.n, 0);
    let address = world
        .issuer
        .wallet
        .contact_book()
        .epic1_address(ACCOUNT)
        .unwrap()
        .encode();
    assert_eq!(issued.address, address);

    let read = world
        .payer
        .wallet
        .contact_book()
        .epic1_read(&relays(&world.payer), &issued.link)
        .unwrap();
    assert_eq!(read.address, address);
    assert_eq!(read.amount, Some(Amount::new(AMOUNT)));
    assert_eq!(read.message.as_deref(), Some("coffee"));
    assert_eq!(read.hosts.len(), 1);
    assert_eq!(read.hosts[0].host, "relay.test");
    assert_eq!(read.hosts[0].class, HostClass::Public);

    // A relay outside the relay list needs the user's word.
    let elsewhere = world.issue_link(&world.issuer, Epic1LinkKind::Printed, &["shop.test"]);
    assert_eq!(
        refusal(world.pay(&elsewhere.link, true, send(), false)),
        Epic1Refusal::RelayNotConfirmed
    );
    assert_eq!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );

    // The wallet's own relay needs none.
    let paid = world.pay(&issued.link, true, send(), false).unwrap();
    assert_eq!(paid.address, address);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(paid.attempts[0].error, None);

    assert_eq!(world.taken(&world.issuer), 1);
    let links = world
        .block_on(world.issuer.wallet.contact_book().epic1_links())
        .unwrap();
    assert_eq!(links.len(), 2);
    assert_eq!(
        links.iter().filter(|link| link.used_at.is_some()).count(),
        1
    );
    // Collecting posted the answer; the payer finalizes by collecting alone.
    assert_eq!(world.answers_posted(), 1);
    assert!(world.node.pushed_transactions().is_empty());

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    // The payment is answered once; collecting again takes nothing new.
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(
        refusal(
            world.block_on(world.payer.wallet.contact_book().epic1_post_next(
                &relays(&world.payer),
                paid.slate_id,
                true,
            ))
        ),
        Epic1Refusal::Finalized
    );
}

#[test]
fn a_payment_is_posted_to_the_next_entry_when_the_first_refuses() {
    let world = World::new();
    world.relay.set_domain_refused("down.test");
    let issued = world.issue_link(
        &world.issuer,
        Epic1LinkKind::OnScreen,
        &["down.test", "relay.test", "shop.test"],
    );
    assert_eq!(link_mailboxes(&issued.link).unwrap().len(), 3);

    let paid = world.pay_link(&issued.link, false).unwrap();

    assert_eq!(paid.posted, Some(1));
    assert_eq!(paid.attempts.len(), 2);
    assert_eq!(paid.attempts[0].host, "down.test");
    assert!(paid.attempts[0].error.is_some());
    assert_eq!(paid.attempts[1].host, "relay.test");
    assert_eq!(paid.attempts[1].error, None);
    assert_eq!(world.taken(&world.issuer), 1);
}

#[test]
fn post_next_posts_the_same_payment_to_the_second_mailbox_answered_once() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(
        &world.issuer,
        Epic1LinkKind::Printed,
        &["relay.test", "shop.test"],
    );
    let paid = world.pay_link(&issued.link, false).unwrap();
    assert_eq!(paid.posted, Some(0));

    let next = world
        .block_on(world.payer.wallet.contact_book().epic1_post_next(
            &relays(&world.payer),
            paid.slate_id,
            true,
        ))
        .unwrap();
    assert_eq!(next.slate_id, paid.slate_id);
    assert_eq!(next.posted, Some(1));
    assert_eq!(
        refusal(
            world.block_on(world.payer.wallet.contact_book().epic1_post_next(
                &relays(&world.payer),
                paid.slate_id,
                true,
            ))
        ),
        Epic1Refusal::NoMoreEntries
    );
    let mailboxes = link_mailboxes(&issued.link).unwrap();
    assert_eq!(world.relay.pending(&mailboxes[0]), 1);
    assert_eq!(world.relay.pending(&mailboxes[1]), 1);

    // The payee drains its own relay; the copy at the second mailbox is the same slate.
    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.answers_posted(), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn a_proof_names_the_epic1_proof_key_and_another_key_is_refused() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let stranger = world.stranger();
    let other = stranger
        .wallet
        .contact_book()
        .epic1_address(ACCOUNT)
        .unwrap()
        .encode();
    let foreign = with_proof_key_of(&issued.link, &other).unwrap();

    let paid = world.pay_link(&foreign, true).unwrap();
    assert_eq!(paid.posted, Some(0));
    assert_eq!(world.taken(&world.issuer), 0);
    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .epic1_answers(&relays(&world.issuer))
            )
            .unwrap()
            .is_empty()
    );
    let mailbox = &link_mailboxes(&issued.link).unwrap()[0];
    assert_eq!(world.relay.pending(mailbox), 0);

    // The link as issued, with the proof, is taken.
    world.payer.fund(20, FUNDING);
    world.pay_link(&issued.link, true).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
}

#[test]
fn a_plain_slate_at_a_link_mailbox_is_acknowledged_and_dropped() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    world.post_to_link(
        &issued.link,
        r#"{"version_info":{"version":3,"block_header_version":6}}"#,
    );

    assert_eq!(world.taken(&world.issuer), 0);
    let mailbox = &link_mailboxes(&issued.link).unwrap()[0];
    assert_eq!(world.relay.pending(mailbox), 0);
}

/// An in-person code's I1 with no tail, for a body the link refuses.
fn invoice_body(world: &World) -> Vec<u8> {
    let code = world
        .block_on(world.payer.wallet.contact_book().in_person_invoice(
            &relays(&world.payer),
            InPersonInvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
        ))
        .unwrap();
    without_tail(Network::Floonet, &code.bytes).unwrap()
}

#[test]
fn an_anonymous_invoice_at_a_link_mailbox_is_refused() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let body = invoice_body(&world);
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);
    let sealed = sealed_to_epic1(
        Network::Floonet,
        &issued.address,
        body,
        true,
        true,
        &mut rng,
    )
    .unwrap();
    world.post_to_link(&issued.link, &armored(&sealed));

    assert_eq!(world.taken(&world.issuer), 0);
    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .epic1_answers(&relays(&world.issuer))
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_payment_without_a_reply_mailbox_is_refused() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let body = invoice_body(&world);
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);
    let sealed = sealed_to_epic1(
        Network::Floonet,
        &issued.address,
        body,
        true,
        false,
        &mut rng,
    )
    .unwrap();
    world.post_to_link(&issued.link, &armored(&sealed));

    assert_eq!(world.taken(&world.issuer), 0);
    let mailbox = &link_mailboxes(&issued.link).unwrap()[0];
    assert_eq!(world.relay.pending(mailbox), 0);
}

#[test]
fn a_link_for_another_network_or_without_transports_cannot_be_paid() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let book = world.payer.wallet.contact_book();

    let other = for_other_network(&issued.link).unwrap();
    assert_eq!(
        refusal(book.epic1_read(&relays(&world.payer), &other)),
        Epic1Refusal::WrongNetwork
    );
    assert_eq!(
        refusal(world.pay_link(&other, false)),
        Epic1Refusal::WrongNetwork
    );

    let bare = without_transports(&issued.link).unwrap();
    let refused = refusal(book.epic1_read(&relays(&world.payer), &bare));
    assert_eq!(refused, Epic1Refusal::CannotPay);
    assert_eq!(refused.to_string(), "cannot pay this code");

    assert!(matches!(
        book.epic1_read(&relays(&world.payer), "epic1:nothing"),
        Err(ContactError::Epic1Link(_))
    ));
    // Nothing was sent.
    assert_eq!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );
}

#[test]
fn the_ring_of_on_screen_links_wraps_at_fifty_and_printed_links_stop_at_thirty_two() {
    let world = World::new();
    for n in 0..50 {
        assert_eq!(
            world
                .issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[])
                .n,
            n
        );
    }
    assert_eq!(
        world
            .issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[])
            .n,
        0
    );

    for n in 0..32 {
        assert_eq!(
            world
                .issue_link(&world.issuer, Epic1LinkKind::Printed, &[])
                .n,
            n
        );
    }
    assert_eq!(
        refusal(world.try_issue_link(&world.issuer, Epic1LinkKind::Printed, &[])),
        Epic1Refusal::PrintedFull
    );
    let book = world.issuer.wallet.contact_book();
    world.block_on(book.epic1_retire(ACCOUNT, 5)).unwrap();
    assert_eq!(
        refusal(world.block_on(book.epic1_retire(ACCOUNT, 5))),
        Epic1Refusal::NotIssued
    );
    assert_eq!(
        world
            .issue_link(&world.issuer, Epic1LinkKind::Printed, &[])
            .n,
        5
    );
    assert_eq!(
        refusal(world.try_issue_link(&world.issuer, Epic1LinkKind::Printed, &[])),
        Epic1Refusal::PrintedFull
    );
}

#[test]
fn a_restore_finds_payments_at_the_last_printed_and_on_screen_links() {
    let world = World::new();
    let mut printed = None;
    for _ in 0..32 {
        printed = Some(world.issue_link(&world.issuer, Epic1LinkKind::Printed, &[]));
    }
    let mut on_screen = None;
    for _ in 0..50 {
        on_screen = Some(world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]));
    }
    let (printed, on_screen) = (printed.unwrap(), on_screen.unwrap());
    assert_eq!((printed.n, on_screen.n), (31, 49));

    world.payer.fund(20, FUNDING);
    world.pay_link(&printed.link, false).unwrap();
    world.pay_link(&on_screen.link, false).unwrap();

    let twin = world.issuer_twin();
    let book = twin.wallet.contact_book();
    assert_eq!(
        world.block_on(book.epic1_restore(&relays(&twin))).unwrap(),
        2
    );
    let links = world.block_on(book.epic1_links()).unwrap();
    assert!(
        links
            .iter()
            .any(|link| link.kind == Epic1LinkKind::Printed && link.n == 31)
    );
    assert!(
        links
            .iter()
            .any(|link| link.kind == Epic1LinkKind::OnScreen && link.n == 49)
    );
    assert_eq!(
        world
            .block_on(book.epic1_answers(&relays(&twin)))
            .unwrap()
            .len(),
        2
    );
    // The ring goes on past the link found.
    assert_eq!(world.issue_link(&twin, Epic1LinkKind::OnScreen, &[]).n, 0);
    assert_eq!(world.issue_link(&twin, Epic1LinkKind::Printed, &[]).n, 0);
}

#[test]
fn the_payment_file_classifier_tells_armour_json_saved_transactions_and_garbage_apart() {
    assert!(matches!(
        payment_file(b"0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
        Err(ContactError::SavedTransaction)
    ));
    assert_eq!(
        payment_file(br#"{"version_info":{"version":3}}"#).unwrap(),
        PaymentFile::LegacyJson
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);
    let world = World::new();
    let address = world
        .issuer
        .wallet
        .contact_book()
        .epic1_address(ACCOUNT)
        .unwrap()
        .encode();
    let sealed = sealed_to_epic1(
        Network::Floonet,
        &address,
        vec![1, 2, 3],
        true,
        true,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        payment_file(armored(&sealed).as_bytes()).unwrap(),
        PaymentFile::Armour
    );
    assert!(matches!(
        payment_file(b"not a slate at all"),
        Err(ContactError::NotPaymentFile)
    ));
}

fn half() -> SendRequest {
    SendRequest {
        amount: Amount::new(AMOUNT / 2),
        ..send()
    }
}

#[test]
fn a_payment_of_another_amount_than_the_link_asks_is_refused_before_it_is_sent() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);

    assert_eq!(
        refusal(world.pay(&issued.link, false, half(), false)),
        Epic1Refusal::AmountMismatch
    );
    assert_eq!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );
    let mailbox = &link_mailboxes(&issued.link).unwrap()[0];
    assert_eq!(world.relay.pending(mailbox), 0);

    // A link that asks no amount takes the one the payer names.
    let open = without_amount(&issued.link).unwrap();
    world.pay(&open, false, half(), false).unwrap();
}

#[test]
fn the_payee_refuses_a_payment_that_is_not_the_amount_it_issued() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    // A payer that does not read the amount from the link.
    let open = without_amount(&issued.link).unwrap();
    world.pay(&open, false, half(), false).unwrap();

    assert_eq!(world.taken(&world.issuer), 0);
    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .epic1_answers(&relays(&world.issuer))
            )
            .unwrap()
            .is_empty()
    );
    assert!(
        world
            .block_on(world.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .is_empty()
    );
    // The refused payment is taken off the mailbox and the link stays usable.
    let mailbox = &link_mailboxes(&issued.link).unwrap()[0];
    assert_eq!(world.relay.pending(mailbox), 0);
    let links = world
        .block_on(world.issuer.wallet.contact_book().epic1_links())
        .unwrap();
    assert!(links.iter().all(|link| link.used_at.is_none()));
    world.collect(&world.payer);
    assert!(world.node.pushed_transactions().is_empty());
}

fn declined_events(events: &mut tokio::sync::broadcast::Receiver<Event>) -> usize {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentDeclined(_)))
        .count()
}

fn declined_body(slate_id: SlateId) -> String {
    format!(r#"{{"lepic":1,"type":"declined","slate_id":"{slate_id}","reason":"amount"}}"#)
}

#[test]
fn a_payer_whose_payment_the_payee_refuses_gets_its_inputs_back() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let open = without_amount(&issued.link).unwrap();
    let paid = world.pay(&open, false, half(), false).unwrap();
    assert_ne!(world.payer_locked(), Amount::ZERO);
    let mut events = world.payer.wallet.subscribe();

    // The payee refuses and tells the payer through the reply mailbox the payment named.
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&world.reply_mailbox(paid.slate_id)), 1);
    assert_eq!(world.payer_state(paid.tx_id), TxState::Sent);

    world.collect(&world.payer);
    assert_eq!(world.payer_state(paid.tx_id), TxState::Cancelled);
    assert_eq!(world.payer_locked(), Amount::ZERO);
    assert_eq!(declined_events(&mut events), 1);
    let details = world
        .block_on(world.payer.wallet.transaction_details(paid.tx_id))
        .unwrap();
    assert!(details.receiver_declined_at.is_some());
    assert_eq!(world.relay.pending(&world.reply_mailbox(paid.slate_id)), 0);

    // Collecting again changes nothing, and the payee still holds nothing of the payment.
    world.collect(&world.issuer);
    world.collect(&world.payer);
    assert_eq!(declined_events(&mut events), 0);
    assert_eq!(world.payer_state(paid.tx_id), TxState::Cancelled);
    assert!(
        world
            .block_on(world.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .is_empty()
    );
    assert!(world.node.pushed_transactions().is_empty());
}

#[test]
fn a_refusal_that_is_not_for_the_payment_leaves_it_waiting() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let paid = world.pay(&issued.link, false, send(), false).unwrap();
    let mailbox = world.reply_mailbox(paid.slate_id);
    let other = SlateId::from_bytes([9; 16]);
    let not_refusals = [
        // Names another slate.
        world.refusal_of(paid.slate_id, &declined_body(other)),
        // Another notice of the family.
        world.refusal_of(
            paid.slate_id,
            &format!(
                r#"{{"lepic":1,"type":"cancelled","slate_id":"{}"}}"#,
                paid.slate_id
            ),
        ),
        // Not a notice.
        world.refusal_of(paid.slate_id, "no"),
        // Sealed to a key that is not the payment's reply key.
        world.refusal_of(other, &declined_body(paid.slate_id)),
    ];
    for text in &not_refusals {
        world.post(7, &mailbox, text, 1);
    }
    let mut events = world.payer.wallet.subscribe();

    world.collect(&world.payer);
    assert_eq!(world.relay.pending(&mailbox), 0);
    assert_eq!(world.payer_state(paid.tx_id), TxState::Sent);
    assert_ne!(world.payer_locked(), Amount::ZERO);
    assert_eq!(declined_events(&mut events), 0);

    // The payment goes on: the payee answers and the payer finalizes.
    assert_eq!(world.taken(&world.issuer), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn a_refusal_that_comes_after_the_answer_does_not_cancel_the_payment() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let paid = world.pay(&issued.link, false, send(), false).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    world.post(
        7,
        &world.reply_mailbox(paid.slate_id),
        &world.refusal_of(paid.slate_id, &declined_body(paid.slate_id)),
        1,
    );
    let mut events = world.payer.wallet.subscribe();

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Cancelled);
    assert_eq!(declined_events(&mut events), 0);
    let details = world
        .block_on(world.payer.wallet.transaction_details(paid.tx_id))
        .unwrap();
    assert_eq!(details.receiver_declined_at, None);
}

impl World {
    /// Issues `count` new epic1 addresses of the issuer's account, which follow on from each
    /// other, and returns them with their indexes. The issuer's wallet was restored from its
    /// phrase, so it is made the install that issues, and the first one comes after the
    /// restore gap.
    fn new_addresses(&self, count: u32) -> Vec<(u32, String)> {
        let book = self.issuer.wallet.contact_book();
        self.block_on(book.epic1_issue_here()).unwrap();
        let mut issued: Vec<(u32, String)> = Vec::new();
        for _ in 0..count {
            let (index, address) = self.block_on(book.epic1_new_address(ACCOUNT)).unwrap();
            match issued.last() {
                Some((previous, _)) => assert_eq!(index, previous + 1),
                None => assert_eq!(index, RESTORE_GAP + 1),
            }
            issued.push((index, address.encode()));
        }
        issued
    }

    /// The epic1 index the issuer's only incoming transaction shows.
    fn received_index(&self) -> Option<u32> {
        let received: Vec<_> = self
            .block_on(self.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .into_iter()
            .filter(|details| details.transaction.entry.direction == TxDirection::Incoming)
            .collect();
        assert_eq!(received.len(), 1);
        received[0].epic1_index
    }

    /// The issuer's epic1 address `index`, and its proof key.
    fn address_at(&self, index: u32) -> (String, [u8; 32]) {
        let address = self
            .block_on(
                self.issuer
                    .wallet
                    .contact_book()
                    .epic1_address_at(ACCOUNT, index),
            )
            .unwrap();
        (address.encode(), address.proof_key().to_bytes())
    }

    /// An S1 from the payer with a payment proof to the proof key `proof`, sealed to the epic1
    /// `address` as a file is, armored.
    fn s1_file(&self, address: &str, proof: [u8; 32], seed: u64) -> String {
        let path = tempfile::tempdir().unwrap().keep().join("s1.json");
        self.block_on(self.payer.wallet.send(
            &support::file(),
            SendRequest {
                payment_proof_recipient: Some(ProofAddress::from_bytes(proof).unwrap()),
                ..send()
            },
            Delivery::Export {
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
        let body = native_body_of(Network::Floonet, &std::fs::read(&path).unwrap()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let sealed =
            sealed_to_epic1(Network::Floonet, address, body, true, false, &mut rng).unwrap();
        armored(&sealed)
    }
}

#[test]
fn a_restored_wallet_issues_new_addresses_only_once_made_the_issuer() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    assert!(!world.block_on(book.epic1_issuing()).unwrap());
    assert_eq!(
        refusal(world.block_on(book.epic1_new_address(ACCOUNT))),
        Epic1Refusal::NotIssuingInstall
    );
    // Index 0 is there all the same.
    let first = book.epic1_address(ACCOUNT).unwrap().encode();
    assert_eq!(
        world
            .block_on(book.epic1_address_at(ACCOUNT, 0))
            .unwrap()
            .encode(),
        first
    );
    world.block_on(book.epic1_issue_here()).unwrap();
    assert!(world.block_on(book.epic1_issuing()).unwrap());
    let (index, _) = world.block_on(book.epic1_new_address(ACCOUNT)).unwrap();
    assert_eq!(index, RESTORE_GAP + 1);
}

#[test]
fn a_link_to_a_new_address_is_paid_and_proved_at_its_index() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    let first = book.epic1_address(ACCOUNT).unwrap().encode();
    let (n, address) = world.new_addresses(3).pop().unwrap();
    assert_ne!(address, first);
    // The listing runs from index 0 to the last one issued, through the restore gap.
    let listed = world
        .block_on(book.epic1_addresses(ACCOUNT, 0, 100))
        .unwrap();
    assert_eq!(listed.highest, n);
    assert_eq!(listed.addresses.len(), n as usize + 1);
    assert_eq!(listed.addresses[0].address, first);
    assert_eq!(listed.addresses[n as usize].address, address);
    assert_eq!(
        world
            .block_on(book.epic1_address_at(ACCOUNT, n))
            .unwrap()
            .encode(),
        address
    );
    // An address the account did not issue is not handed out.
    assert_eq!(
        refusal(world.block_on(book.epic1_address_at(ACCOUNT, n + 1))),
        Epic1Refusal::AddressNotIssued
    );
    let mut unissued = link_request(Epic1LinkKind::OnScreen, &[]);
    unissued.index = n + 1;
    assert_eq!(
        refusal(world.block_on(book.epic1_link(&relays(&world.issuer), unissued))),
        Epic1Refusal::AddressNotIssued
    );

    let mut request = link_request(Epic1LinkKind::OnScreen, &[]);
    request.index = n;
    let issued = world
        .block_on(book.epic1_link(&relays(&world.issuer), request))
        .unwrap();
    assert_eq!(issued.address, address);

    // The payment proof names the proof key of address n, which the payee signs with.
    let paid = world.pay_link(&issued.link, true).unwrap();
    assert_eq!(paid.address, address);
    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.received_index(), Some(n));
    assert_eq!(world.answers_posted(), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let sent = world
        .block_on(world.payer.wallet.transaction_details(paid.tx_id))
        .unwrap();
    assert_eq!(sent.epic1_index, None);
}

#[test]
fn a_file_sealed_to_an_issued_address_is_received_at_its_index() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    let n = world.new_addresses(4)[1].0;
    let (address, proof) = world.address_at(n);

    // Sealed to address n with a proof to address 0: address n's proof key does not match.
    let (_, first) = world.address_at(0);
    let mismatched = world.s1_file(&address, first, 1);
    assert!(
        world
            .block_on(book.sealed_receive(&mismatched, ReceiveRequest::default()))
            .is_err()
    );

    world.payer.fund(20, FUNDING);
    let text = world.s1_file(&address, proof, 2);
    let received = world
        .block_on(book.sealed_receive(&text, ReceiveRequest::default()))
        .unwrap();
    assert_eq!(world.received_index(), Some(n));
    let details = world
        .block_on(
            world
                .issuer
                .wallet
                .transaction_details(received.received.tx_id),
        )
        .unwrap();
    assert_eq!(details.epic1_index, Some(n));
}

#[test]
fn trial_decryption_finds_the_address_tried_last_among_a_thousand_and_one() {
    let world = World::new();
    // Indexes 1 to 50 are the restore gap; the addresses issued after it reach index 1,000.
    let started = std::time::Instant::now();
    let issued = world.new_addresses(1_000 - RESTORE_GAP);
    assert_eq!(issued.last().unwrap().0, 1_000);
    eprintln!(
        "issuing {} addresses took {:?}",
        issued.len(),
        started.elapsed()
    );
    let book = world.issuer.wallet.contact_book();
    // Tried first: index 0, then from the highest down, so index 1 is tried last.
    let (address, proof) = world.address_at(1);
    let text = world.s1_file(&address, proof, 3);

    let started = std::time::Instant::now();
    let keys = world
        .block_on(
            world
                .issuer
                .wallet
                .epic1_trial_keys(ACCOUNT, lepic_contact::Network::Floonet),
        )
        .unwrap();
    let derived = started.elapsed();
    assert_eq!(keys.len(), 1_001);
    assert_eq!(keys.last().unwrap().0, 1);

    let started = std::time::Instant::now();
    world.block_on(book.sealed_open(&text)).unwrap();
    let opened = started.elapsed();
    eprintln!(
        "deriving 1,001 seal keys took {derived:?}; opening at the last of them, with the \
         derivation, took {opened:?}"
    );

    world
        .block_on(book.sealed_receive(&text, ReceiveRequest::default()))
        .unwrap();
    assert_eq!(world.received_index(), Some(1));
    // The index of the most recent payment is tried first from then on.
    let keys = world
        .block_on(
            world
                .issuer
                .wallet
                .epic1_trial_keys(ACCOUNT, lepic_contact::Network::Floonet),
        )
        .unwrap();
    assert_eq!(keys[0].0, 1);
}

#[test]
fn a_file_sealed_to_another_accounts_address_is_received_into_that_account() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    let savings = world.issuer.wallet.create_account("savings").unwrap();
    let address = world
        .block_on(book.epic1_address_at(savings.index, 0))
        .unwrap();
    world.payer.fund(20, FUNDING);
    let text = world.s1_file(&address.encode(), address.proof_key().to_bytes(), 4);

    let received = world
        .block_on(book.sealed_receive(&text, ReceiveRequest::default()))
        .unwrap();
    let details = world
        .block_on(
            world
                .issuer
                .wallet
                .transaction_details(received.received.tx_id),
        )
        .unwrap();
    assert_eq!(details.transaction.entry.account, savings.index);
    assert_eq!(details.epic1_index, Some(0));
    let into_first = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert!(
        into_first
            .iter()
            .all(|details| details.transaction.entry.direction != TxDirection::Incoming)
    );
}

#[test]
fn a_link_payment_past_the_open_receipt_cap_is_refused_and_leaves_its_link_unused() {
    let world = World::with_issuer_policy(lepic_wallet::WalletPolicy {
        max_open_receipts: 1,
        ..lepic_wallet::WalletPolicy::default()
    });
    let first = world.issue_link(&world.issuer, Epic1LinkKind::OnScreen, &[]);
    let second = world.issue_link(&world.issuer, Epic1LinkKind::Printed, &[]);
    world.pay_link(&first.link, false).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    world.payer.fund(20, FUNDING);
    let refused = world.pay_link(&second.link, false).unwrap();
    assert_eq!(refused.posted, Some(0));

    // The second payment finds the cap full and is dropped.
    assert_eq!(world.taken(&world.issuer), 0);
    let received = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(received.len(), 1);
    let mailbox = &link_mailboxes(&second.link).unwrap()[0];
    assert_eq!(world.relay.pending(mailbox), 0);
    let links = world
        .block_on(world.issuer.wallet.contact_book().epic1_links())
        .unwrap();
    let used: Vec<_> = links
        .iter()
        .map(|link| (link.kind, link.used_at.is_some()))
        .collect();
    assert!(used.contains(&(Epic1LinkKind::OnScreen, true)));
    assert!(used.contains(&(Epic1LinkKind::Printed, false)));
    assert_eq!(world.answers_posted(), 1);
}
