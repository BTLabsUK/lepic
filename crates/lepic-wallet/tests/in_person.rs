// SPDX-License-Identifier: Apache-2.0
//! In-person invoices (RFC 0003 §9): a code shown as raw `lepic.v1`, paid by a scan, answered
//! through the code's reply mailbox or shown back, and finalized only when the payee picks the
//! answer by its check code.

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

use std::sync::Arc;

use helpers::{events, relays};
use lepic_epicbox::{Domain, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_methods::epicbox::Epicbox;
use lepic_node::Propagation;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::stage::Stage;
use lepic_slate::ur_slate::{BINARY_FRAGMENT_LEN, encode_ur_binary};
use lepic_store::TxState;
use lepic_transport::host_rule::HostClass;
use lepic_transport::method::Method;
use lepic_wallet::Event;
use lepic_wallet::epicbox_invoice::InvoiceExpiry;
use lepic_wallet::invoice::{INVOICE_TTL_MARGIN_BLOCKS, InvoiceError};
use lepic_wallet::selection::SelectionOptions;
use lepic_wallet_contacts::in_person_testing::{
    armored, for_network, sealed_to_code, with_mailbox_host, with_proof, without_tail,
};
use lepic_wallet_contacts::{
    CollectTrigger, ContactError, ContactRelays, IN_PERSON_TTL_BLOCKS, InPersonCode,
    InPersonInvoiceRequest, InPersonRefusal, RelayMode, WalletContacts,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, TIP, World, pay_request};

/// The selection [`pay_request`] makes.
fn options() -> SelectionOptions {
    SelectionOptions {
        minimum_confirmations: 1,
        ..SelectionOptions::new(ACCOUNT)
    }
}

fn request() -> InPersonInvoiceRequest {
    InPersonInvoiceRequest {
        account: ACCOUNT,
        amount: Amount::new(AMOUNT),
        message: Some("coffee".to_owned()),
        ttl_blocks: None,
    }
}

/// `party`'s relays, with its own relay on `domain`.
fn relays_on(world: &World, party: &Party, domain: &str) -> ContactRelays {
    let mut settings = world::settings();
    settings.endpoint = RelayEndpoint::new(Domain::parse(domain).unwrap(), None, Security::Plain);
    ContactRelays {
        epicbox: Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        ..relays(party)
    }
}

fn offline(party: &Party) -> ContactRelays {
    ContactRelays {
        mode: RelayMode::Offline,
        ..relays(party)
    }
}

impl World {
    fn show(&self, relays: &ContactRelays) -> InPersonCode {
        self.block_on(
            self.issuer
                .wallet
                .contact_book()
                .in_person_invoice(relays, request()),
        )
        .unwrap()
    }

    fn collect_with(&self, party: &Party, relays: &ContactRelays) -> usize {
        self.block_on(
            party
                .wallet
                .contact_book()
                .contacts_collect(relays, CollectTrigger::Open),
        )
        .unwrap()
        .in_person
    }
}

fn refusal<T: std::fmt::Debug>(result: Result<T, ContactError>) -> InPersonRefusal {
    match result {
        Err(ContactError::InPerson(refusal)) => refusal,
        other => panic!("not an in-person refusal: {other:?}"),
    }
}

/// `body` sealed to the code's reply key as an answer is, for `network`.
fn sealed_to(network: Network, code: &[u8], body: Vec<u8>, tagged: bool) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);
    sealed_to_code(Network::Floonet, network, code, body, tagged, &mut rng).unwrap()
}

#[test]
fn a_code_paid_face_to_face_is_answered_through_its_mailbox_and_finalized_when_picked() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let code = world.show(&relays(&world.issuer));
    assert!(code.mailbox.is_some());
    assert_eq!(code.ttl_cutoff, TIP + IN_PERSON_TTL_BLOCKS);

    let read = world
        .block_on(world.payer.wallet.contact_book().in_person_read(
            &relays(&world.payer),
            options(),
            &code.bytes,
        ))
        .unwrap();

    assert_eq!(read.slate_id, code.slate_id);
    assert_eq!(read.stage, Stage::I1);
    assert_eq!(read.amount, Amount::new(AMOUNT));
    assert_eq!(read.message.as_deref(), Some("coffee"));
    assert_eq!(read.ttl_cutoff, code.ttl_cutoff);
    assert!(read.fee.is_some());
    let mailbox = read.mailbox.unwrap();
    assert_eq!(mailbox.host, "relay.test");
    assert!(mailbox.in_relay_list);
    assert_eq!(mailbox.class, HostClass::Public);

    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    assert_eq!(paid.slate_id, code.slate_id);
    assert_eq!(paid.check_code.len(), 4);
    assert_eq!(
        refusal(
            world.block_on(world.payer.wallet.contact_book().in_person_post(
                &relays(&world.payer),
                paid.slate_id,
                false,
            ))
        ),
        InPersonRefusal::RelayNotConfirmed
    );
    world
        .block_on(world.payer.wallet.contact_book().in_person_post(
            &relays(&world.payer),
            paid.slate_id,
            true,
        ))
        .unwrap();
    // The payer's inputs stay locked until the payee finalizes or the TTL passes.
    assert!(world.payer.wallet.balance(ACCOUNT).unwrap().locked > Amount::ZERO);

    assert_eq!(world.collect_with(&world.issuer, &relays(&world.issuer)), 1);

    let answered: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InPersonAnswer(answer) => Some(answer),
            _ => None,
        })
        .collect();
    assert_eq!(answered.len(), 1);
    assert_eq!(answered[0].slate_id, code.slate_id);
    assert_eq!(answered[0].stage, Stage::I2);
    assert_eq!(answered[0].answer, 1);
    assert_eq!(answered[0].check_code, paid.check_code);
    assert!(!answered[0].same_code);
    // Nothing is finalized until the payee picks the answer.
    assert!(world.node.pushed_transactions().is_empty());
    let view = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap();
    assert!(view.closed);
    assert_eq!(view.finalized, None);
    assert_eq!(view.answers.len(), 1);
    assert_eq!(view.answers[0].check_code, paid.check_code);

    let finalized = world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();

    assert!(finalized.pushed);
    assert_eq!(finalized.tx_id, code.tx_id);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let view = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap();
    assert_eq!(view.finalized, Some(1));
    assert_eq!(world.collect_with(&world.issuer, &relays(&world.issuer)), 0);
}

#[test]
fn a_code_shown_offline_names_no_mailbox_and_takes_the_answer_shown_back() {
    let world = World::new();
    let code = world.show(&offline(&world.issuer));
    assert_eq!(code.mailbox, None);
    let read = world
        .block_on(world.payer.wallet.contact_book().in_person_read(
            &relays(&world.payer),
            options(),
            &code.bytes,
        ))
        .unwrap();
    assert!(read.mailbox.is_none());
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    assert_eq!(
        refusal(
            world.block_on(world.payer.wallet.contact_book().in_person_post(
                &relays(&world.payer),
                paid.slate_id,
                true,
            ))
        ),
        InPersonRefusal::NoMailbox
    );

    let taken = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_take(&paid.envelope),
        )
        .unwrap();

    assert_eq!(taken.tx_id, code.tx_id);
    assert_eq!(taken.stage, Stage::I2);
    assert_eq!(taken.answer, 1);
    assert_eq!(taken.check_code, paid.check_code);
    assert!(!taken.duplicate);
    // The same answer, armoured or scanned from its animated code, is the same answer.
    let armoured = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_take(armored(&paid.envelope).as_bytes()),
        )
        .unwrap();
    assert!(armoured.duplicate);
    assert_eq!(armoured.answer, 1);
    let parts = encode_ur_binary(&paid.envelope, BINARY_FRAGMENT_LEN).unwrap();
    let scanned = world
        .block_on(world.issuer.wallet.contact_book().in_person_take_ur(&parts))
        .unwrap();
    assert!(scanned.duplicate);
    assert_eq!(
        refusal(
            world.block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .in_person_take_ur(&parts[..1])
            )
        ),
        InPersonRefusal::UrIncomplete
    );
    world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn a_paypoint_on_another_relay_is_answered_on_its_own_relay() {
    let world = World::new();
    let shop = relays_on(&world, &world.issuer, "shop.test");
    let code = world.show(&shop);
    assert!(code.mailbox.as_deref().unwrap().starts_with("shop.test"));

    let read = world
        .block_on(world.payer.wallet.contact_book().in_person_read(
            &relays(&world.payer),
            options(),
            &code.bytes,
        ))
        .unwrap();
    let mailbox = read.mailbox.unwrap();
    assert_eq!(mailbox.host, "shop.test");
    assert!(!mailbox.in_relay_list);
    assert_eq!(mailbox.class, HostClass::Public);
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.contact_book().in_person_post(
            &relays(&world.payer),
            paid.slate_id,
            true,
        ))
        .unwrap();

    assert_eq!(world.collect_with(&world.issuer, &shop), 1);
    let view = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap();
    assert_eq!(view.answers.len(), 1);
    assert_eq!(view.answers[0].check_code, paid.check_code);
}

#[test]
fn a_second_answer_with_the_same_check_code_is_flagged_and_the_payee_picks_one() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let code = world.show(&relays(&world.issuer));
    // A second install of the payer's wallet spends the same coin into the same change: its
    // answer has the payer's public excess, so the same check code, and another signature.
    let twin = world.payer_twin();
    twin.fund(0, FUNDING);
    let mut paid = Vec::new();
    for party in [&world.payer, &twin] {
        let answer = world
            .block_on(party.wallet.contact_book().in_person_pay(
                &relays(party),
                &code.bytes,
                pay_request(),
            ))
            .unwrap();
        world
            .block_on(party.wallet.contact_book().in_person_post(
                &relays(party),
                answer.slate_id,
                true,
            ))
            .unwrap();
        paid.push(answer);
    }
    assert_eq!(paid[0].check_code, paid[1].check_code);
    assert_ne!(paid[0].envelope, paid[1].envelope);

    assert_eq!(world.collect_with(&world.issuer, &relays(&world.issuer)), 2);

    let flags: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InPersonAnswer(answer) => Some((answer.answer, answer.same_code)),
            _ => None,
        })
        .collect();
    assert_eq!(flags, vec![(1, false), (2, true)]);
    let view = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap();
    assert_eq!(view.answers.len(), 2);
    assert!(!view.answers[0].same_code);
    assert!(view.answers[1].same_code);
    assert!(world.node.pushed_transactions().is_empty());
    assert_eq!(
        refusal(
            world.block_on(world.issuer.wallet.contact_book().in_person_finalize(
                code.slate_id,
                3,
                Propagation::Stem,
            ))
        ),
        InPersonRefusal::NoAnswer
    );

    world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            2,
            Propagation::Stem,
        ))
        .unwrap();

    assert_eq!(world.node.pushed_transactions().len(), 1);
    let view = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap();
    assert_eq!(view.finalized, Some(2));
}

#[test]
fn raw_codes_are_read_only_from_a_scan() {
    let world = World::new();
    let code = world.show(&relays(&world.issuer));
    let file: Arc<dyn Method> = Arc::new(lepic_transport::file::FileTransport::new());

    // A file import or a paste never reads raw lepic.v1.
    let imported = world.block_on(world.payer.wallet.pay_invoice(
        &file,
        &WireSlate::binary(MediaType::OCTET_STREAM, code.bytes.clone()),
        pay_request(),
    ));
    assert!(
        matches!(imported, Err(InvoiceError::Decode(_))),
        "{imported:?}"
    );
    let pasted = world.block_on(
        world
            .payer
            .wallet
            .contact_book()
            .sealed_open(&String::from_utf8_lossy(&code.bytes)),
    );
    assert!(matches!(pasted, Err(ContactError::Decode(_))), "{pasted:?}");
    let taken = world.block_on(
        world
            .issuer
            .wallet
            .contact_book()
            .in_person_take(&code.bytes),
    );
    assert!(matches!(taken, Err(ContactError::Decode(_))), "{taken:?}");

    // An I1 sealed to the reply key is not an answer, nor a way round the scan.
    let sealed = sealed_to(Network::Floonet, &code.bytes, code.bytes.clone(), false);
    assert_eq!(
        refusal(world.block_on(world.issuer.wallet.contact_book().in_person_take(&sealed))),
        InPersonRefusal::WrongStage
    );
    let opened = world.block_on(
        world
            .payer
            .wallet
            .contact_book()
            .sealed_open(&armored(&sealed)),
    );
    assert!(opened.is_err(), "{opened:?}");
    let opened = world.block_on(world.payer.wallet.contact_book().in_person_take(&sealed));
    assert!(
        matches!(opened, Err(ContactError::NotForThisInstall)),
        "{opened:?}"
    );
}

#[test]
fn codes_and_answers_outside_the_rules_are_refused() {
    let world = World::new();
    let code = world.show(&relays(&world.issuer));
    let book = world.payer.wallet.contact_book();
    let read =
        |bytes: &[u8]| world.block_on(book.in_person_read(&relays(&world.payer), options(), bytes));

    // A payment proof in an invoice.
    let proof = with_proof(&code.bytes);
    assert_eq!(refusal(read(&proof)), InPersonRefusal::Proof);
    // No reply key.
    let keyless = without_tail(Network::Floonet, &code.bytes).unwrap();
    assert_eq!(refusal(read(&keyless)), InPersonRefusal::NoReplyKey);
    // Another network.
    let mainnet = for_network(Network::Floonet, Network::Mainnet, &code.bytes).unwrap();
    assert!(matches!(read(&mainnet), Err(ContactError::Native(_))));
    // A reply mailbox on a loopback or unspecified host.
    for host in ["127.0.0.1:7000", "localhost", "relay.localhost", "0.0.0.0"] {
        let looped = with_mailbox_host(Network::Floonet, &code.bytes, host).unwrap();
        assert_eq!(refusal(read(&looped)), InPersonRefusal::Loopback, "{host}");
        assert_eq!(
            refusal(world.block_on(book.in_person_pay(
                &relays(&world.payer),
                &looped,
                pay_request(),
            ))),
            InPersonRefusal::Loopback,
            "{host}"
        );
    }
    assert_eq!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );

    let issuer = world.issuer.wallet.contact_book();
    let take = |envelope: &[u8]| world.block_on(issuer.in_person_take(envelope));
    let paid = world
        .block_on(book.in_person_pay(&relays(&world.payer), &code.bytes, pay_request()))
        .unwrap();
    // An answer naming a reply mailbox of its own.
    let tagged = sealed_to(Network::Floonet, &code.bytes, code.bytes.clone(), true);
    assert_eq!(refusal(take(&tagged)), InPersonRefusal::ReplyMailboxTag);
    // An answer sealed for another network.
    let mainnet = sealed_to(Network::Mainnet, &code.bytes, code.bytes.clone(), false);
    assert!(
        matches!(take(&mainnet), Err(ContactError::Decode(_))),
        "{:?}",
        take(&mainnet)
    );
    // Nothing refused was taken: the payer's answer is still the first.
    assert_eq!(take(&paid.envelope).unwrap().answer, 1);
}

#[test]
fn a_wallet_on_this_device_relay_shows_codes_without_a_mailbox() {
    let world = World::new();
    let code = world.show(&relays_on(&world, &world.issuer, "localhost"));
    assert_eq!(code.mailbox, None);
}

#[test]
fn a_payment_past_the_ttl_frees_its_inputs_when_cancelled_and_the_code_is_forgotten() {
    let world = World::new();
    let code = world.show(&relays(&world.issuer));
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    assert!(world.payer.wallet.balance(ACCOUNT).unwrap().locked > Amount::ZERO);

    let offered_at = code.ttl_cutoff + INVOICE_TTL_MARGIN_BLOCKS;
    world
        .node
        .update_chain(|chain| chain.tip.height = Height::new(offered_at));
    world.block_on(world.payer.wallet.refresh()).unwrap();
    let sweep = world
        .block_on(world.payer.wallet.sweep_invoices(InvoiceExpiry::default()))
        .unwrap();
    assert_eq!(sweep.cancellable, vec![paid.tx_id]);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();

    // The world funds the store only, so the refresh at the new tip drops the output: the
    // cancel shows as nothing locked and the payment cancelled.
    assert_eq!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );
    let paid_state = world
        .payer
        .read(|repos| repos.transaction(paid.tx_id))
        .unwrap()
        .state;
    assert_eq!(paid_state, TxState::Cancelled);

    world
        .block_on(world.issuer.wallet.cancel(code.tx_id))
        .unwrap();
    let state = world
        .issuer
        .read(|repos| repos.transaction(code.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Cancelled);
    assert_eq!(world.collect_with(&world.issuer, &relays(&world.issuer)), 0);
    assert_eq!(
        refusal(
            world.block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .in_person_answers(code.slate_id)
            )
        ),
        InPersonRefusal::NoCode
    );
}
