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
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_transport::host_rule::HostClass;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::SendRequest;
use lepic_wallet_contacts::epic1_testing::{
    for_other_network, link_mailboxes, sealed_to_epic1, with_proof_key_of, without_transports,
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
        let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
        self.block_on(self.payer.wallet.contact_book().epic1_pay(
            &relays(&self.payer),
            Epic1PayRequest {
                link: link.to_owned(),
                send: send(),
                proof,
                slate_file: file,
            },
            true,
        ))
    }

    fn taken(&self, party: &Party) -> usize {
        self.collect(party).epic1
    }

    /// The payee posts every answer it holds; returns how many.
    fn answer_all(&self) -> usize {
        let book = self.issuer.wallet.contact_book();
        let answers = self
            .block_on(book.epic1_answers(&relays(&self.issuer)))
            .unwrap();
        for answer in &answers {
            assert!(!answer.posted);
            self.block_on(book.epic1_post_answer(&relays(&self.issuer), answer.slate_id, true))
                .unwrap();
        }
        answers.len()
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

    let unconfirmed = world.block_on(world.payer.wallet.contact_book().epic1_pay(
        &relays(&world.payer),
        Epic1PayRequest {
            link: issued.link.clone(),
            send: send(),
            proof: true,
            slate_file: tempfile::tempdir().unwrap().keep().join("s1.tx"),
        },
        false,
    ));
    assert_eq!(refusal(unconfirmed), Epic1Refusal::RelayNotConfirmed);

    let paid = world.pay_link(&issued.link, true).unwrap();
    assert_eq!(paid.address, address);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(paid.attempts[0].error, None);

    assert_eq!(world.taken(&world.issuer), 1);
    let links = world
        .block_on(world.issuer.wallet.contact_book().epic1_links())
        .unwrap();
    assert_eq!(links.len(), 1);
    assert!(links[0].used_at.is_some());
    assert_eq!(world.answer_all(), 1);
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
    assert_eq!(world.answer_all(), 1);
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
