// SPDX-License-Identifier: Apache-2.0
//! In-person invoices and sends (RFC 0003 §9): a code shown as raw `lepic.v1`, paid or received
//! by a scan, answered through the code's reply mailbox or shown back, and finalized only when
//! the wallet that showed it picks the answer by its check code.

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

use std::sync::Arc;

use helpers::{
    ACK_GROUP, events, hold_acks, lose_acks_and_reopen, queued_after, relays, wait_gone,
};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_keychain::Identifier;
use lepic_methods::epicbox::Epicbox;
use lepic_node::Propagation;
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::ProofAddress;
use lepic_slate::stage::Stage;
use lepic_slate::ur_slate::{BINARY_FRAGMENT_LEN, encode_ur_binary};
use lepic_store::{MailClass, TxState, WatchRow};
use lepic_transport::host_rule::HostClass;
use lepic_transport::method::Method;
use lepic_wallet::Event;
use lepic_wallet::epicbox_invoice::InvoiceExpiry;
use lepic_wallet::invoice::{INVOICE_TTL_MARGIN_BLOCKS, InvoiceError};
use lepic_wallet::receive::ReceiveRequest;
use lepic_wallet::selection::{SelectionOptions, SelectionStrategy};
use lepic_wallet::send::SendRequest;
use lepic_wallet_contacts::in_person_testing::{
    armored, for_network, sealed_to_code, with_mailbox_host, with_proof, without_tail,
};
use lepic_wallet_contacts::{
    ClaimSigner, CollectTrigger, ContactError, ContactRelays, IN_PERSON_TTL_BLOCKS, InPersonCode,
    InPersonDirect, InPersonInvoiceRequest, InPersonPaid, InPersonRefusal, MethodId, RelayMode,
    RouteEntry, WalletContacts,
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
        slate_id: None,
        direct: Vec::new(),
        claim: None,
        shared_slot: false,
    }
}

/// `party`'s relays, with its own relay on `domain`.
fn relays_on(world: &World, party: &Party, domain: &str) -> ContactRelays {
    let mut settings = world::settings();
    settings.endpoint = RelayEndpoint::new(Domain::parse(domain).unwrap(), None, Security::Plain);
    helpers::on(
        Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        relays(party),
    )
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

    /// The payer shows an in-person send code to the issuer.
    fn show_send(&self, relays: &ContactRelays) -> InPersonCode {
        self.block_on(
            self.payer
                .wallet
                .contact_book()
                .in_person_send(relays, send_request()),
        )
        .unwrap()
    }

    fn receive_with(&self, party: &Party, code: &InPersonCode) -> InPersonPaid {
        self.block_on(party.wallet.contact_book().in_person_receive(
            &relays(party),
            &code.bytes,
            ReceiveRequest::default(),
        ))
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

fn send_request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        message: Some("change".to_owned()),
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
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
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .in_person_post(&relays(&world.payer), paid.slate_id),
        )
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

/// The party's watch rows of in-person codes.
fn code_rows(party: &Party) -> Vec<WatchRow> {
    party
        .read(|repos| repos.watch_set())
        .into_iter()
        .filter(|row| row.class == MailClass::InPerson)
        .collect()
}

/// A code that waits for answers has a row on its mailbox's relay, a code shown without a
/// mailbox has none, and the row goes when the payee finalizes an answer.
#[test]
fn an_in_person_row_follows_its_code() {
    let world = World::new();
    let issuer_relays = relays(&world.issuer);
    let code = world.show(&issuer_relays);
    world.show(&offline(&world.issuer));
    world.block_on(
        world
            .issuer
            .wallet
            .contact_book()
            .claim_pushed(&issuer_relays),
    );
    assert_eq!(
        code_rows(&world.issuer),
        [WatchRow {
            key_ref: format!("inperson:{}", code.slate_id),
            relay: code.mailbox.clone().unwrap(),
            class: MailClass::InPerson,
            expires_at: None,
        }]
    );

    let book = world.payer.wallet.contact_book();
    let paid = world
        .block_on(book.in_person_pay(&relays(&world.payer), &code.bytes, pay_request()))
        .unwrap();
    world
        .block_on(book.in_person_post(&relays(&world.payer), paid.slate_id))
        .unwrap();
    assert_eq!(world.collect_with(&world.issuer, &issuer_relays), 1);
    world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();
    world.block_on(
        world
            .issuer
            .wallet
            .contact_book()
            .claim_pushed(&issuer_relays),
    );
    assert_eq!(code_rows(&world.issuer), []);
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
            world.block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .in_person_post(&relays(&world.payer), paid.slate_id)
            )
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
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .in_person_post(&relays(&world.payer), paid.slate_id),
        )
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
            .block_on(
                party
                    .wallet
                    .contact_book()
                    .in_person_post(&relays(party), answer.slate_id),
            )
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
    assert!(
        matches!(pasted, Err(ContactError::NotPaymentFile)),
        "{pasted:?}"
    );
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
    // The issuer forgets a cancelled code once its own tip is past the code's TTL.
    world.block_on(world.issuer.wallet.refresh()).unwrap();
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

#[test]
fn a_send_code_received_face_to_face_is_answered_through_its_mailbox_and_finalized_when_picked() {
    let world = World::new();
    let mut payer_events = world.payer.wallet.subscribe();
    let code = world.show_send(&relays(&world.payer));
    assert!(code.mailbox.is_some());
    assert_eq!(code.ttl_cutoff, TIP + IN_PERSON_TTL_BLOCKS);
    // The send is stored and its inputs locked from the moment the code is shown.
    let sent = world
        .payer
        .read(|repos| repos.transaction(code.tx_id))
        .unwrap();
    assert_eq!(sent.state, TxState::Sent);
    assert!(world.payer.wallet.balance(ACCOUNT).unwrap().locked > Amount::ZERO);

    let read = world
        .block_on(world.issuer.wallet.contact_book().in_person_read(
            &relays(&world.issuer),
            options(),
            &code.bytes,
        ))
        .unwrap();
    assert_eq!(read.slate_id, code.slate_id);
    assert_eq!(read.stage, Stage::S1);
    assert_eq!(read.amount, Amount::new(AMOUNT));
    assert_eq!(read.message.as_deref(), Some("change"));
    assert_eq!(read.ttl_cutoff, code.ttl_cutoff);
    assert!(
        read.fee
            .is_some_and(|fee| fee > lepic_primitives::amount::Fee::ZERO)
    );
    let mailbox = read.mailbox.unwrap();
    assert_eq!(mailbox.host, "relay.test");
    assert!(mailbox.in_relay_list);

    let received = world.receive_with(&world.issuer, &code);
    assert_eq!(received.slate_id, code.slate_id);
    assert_eq!(received.check_code.len(), 4);
    // Receiving the same code again gives the same answer back.
    let again = world.receive_with(&world.issuer, &code);
    assert_eq!(again.tx_id, received.tx_id);
    assert_eq!(again.check_code, received.check_code);
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .in_person_post(&relays(&world.issuer), received.slate_id),
        )
        .unwrap();

    assert_eq!(world.collect_with(&world.payer, &relays(&world.payer)), 1);
    let answered: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InPersonAnswer(answer) => Some(answer),
            _ => None,
        })
        .collect();
    assert_eq!(answered.len(), 1);
    assert_eq!(answered[0].slate_id, code.slate_id);
    assert_eq!(answered[0].stage, Stage::S2);
    assert_eq!(answered[0].answer, 1);
    assert_eq!(answered[0].check_code, received.check_code);
    assert!(!answered[0].same_code);
    // Nothing is finalized until the sender picks the answer.
    assert!(world.node.pushed_transactions().is_empty());

    let finalized = world
        .block_on(world.payer.wallet.contact_book().in_person_finalize(
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
                .payer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap();
    assert_eq!(view.stage, Stage::S1);
    assert_eq!(view.finalized, Some(1));
    assert_eq!(world.collect_with(&world.payer, &relays(&world.payer)), 0);
}

#[test]
fn a_send_code_shown_offline_takes_the_answer_shown_back() {
    let world = World::new();
    let code = world.show_send(&offline(&world.payer));
    assert_eq!(code.mailbox, None);
    let received = world.receive_with(&world.issuer, &code);
    assert_eq!(
        refusal(
            world.block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .in_person_post(&relays(&world.issuer), received.slate_id)
            )
        ),
        InPersonRefusal::NoMailbox
    );

    let taken = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .in_person_take(&received.envelope),
        )
        .unwrap();
    assert_eq!(taken.tx_id, code.tx_id);
    assert_eq!(taken.stage, Stage::S2);
    assert_eq!(taken.answer, 1);
    assert_eq!(taken.check_code, received.check_code);
    assert!(!taken.duplicate);
    let armoured = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .in_person_take(armored(&received.envelope).as_bytes()),
        )
        .unwrap();
    assert!(armoured.duplicate);

    world
        .block_on(world.payer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let sent = world
        .payer
        .read(|repos| repos.transaction(code.tx_id))
        .unwrap();
    assert_eq!(sent.state, TxState::Posted);
}

#[test]
fn a_second_answer_to_a_send_with_the_same_check_code_is_flagged_and_the_sender_picks_one() {
    let world = World::new();
    let mut payer_events = world.payer.wallet.subscribe();
    let code = world.show_send(&relays(&world.payer));
    // A second install of the issuer's wallet, its key counter where the issuer's is, receives
    // into the same output: its answer has the issuer's public excess, so the same check code,
    // and another signature.
    let twin = world.issuer_twin();
    let next_child = world
        .issuer
        .read(|repos| repos.account(ACCOUNT))
        .unwrap()
        .next_child;
    twin.write(|repos| {
        let mut account = repos.account(ACCOUNT)?.unwrap();
        account.next_child = next_child;
        repos.put_account(&account)
    });
    let mut received = Vec::new();
    for party in [&world.issuer, &twin] {
        let answer = world.receive_with(party, &code);
        world
            .block_on(
                party
                    .wallet
                    .contact_book()
                    .in_person_post(&relays(party), answer.slate_id),
            )
            .unwrap();
        received.push(answer);
    }
    assert_eq!(received[0].check_code, received[1].check_code);
    assert_ne!(received[0].envelope, received[1].envelope);

    assert_eq!(world.collect_with(&world.payer, &relays(&world.payer)), 2);
    let flags: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InPersonAnswer(answer) => Some((answer.answer, answer.same_code)),
            _ => None,
        })
        .collect();
    assert_eq!(flags, vec![(1, false), (2, true)]);
    assert!(world.node.pushed_transactions().is_empty());
    assert_eq!(
        refusal(
            world.block_on(world.payer.wallet.contact_book().in_person_finalize(
                code.slate_id,
                3,
                Propagation::Stem,
            ))
        ),
        InPersonRefusal::NoAnswer
    );

    world
        .block_on(world.payer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            2,
            Propagation::Stem,
        ))
        .unwrap();
    assert_eq!(world.node.pushed_transactions().len(), 1);
    // The other answer can no longer be finalized.
    let other = world.block_on(world.payer.wallet.contact_book().in_person_finalize(
        code.slate_id,
        1,
        Propagation::Stem,
    ));
    assert!(other.is_err(), "{other:?}");
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn send_codes_and_invoice_codes_are_answered_only_as_what_they_are() {
    let world = World::new();
    let send = world.show_send(&relays(&world.payer));
    let invoice = world.show(&relays(&world.issuer));
    let stranger = world.stranger();

    // An S1 is not paid, nor an I1 received.
    assert_eq!(
        refusal(world.block_on(stranger.wallet.contact_book().in_person_pay(
            &relays(&stranger),
            &send.bytes,
            pay_request(),
        ))),
        InPersonRefusal::WrongStage
    );
    assert_eq!(
        refusal(
            world.block_on(world.payer.wallet.contact_book().in_person_receive(
                &relays(&world.payer),
                &invoice.bytes,
                ReceiveRequest::default(),
            ))
        ),
        InPersonRefusal::WrongStage
    );
    // A send code flagged for a payment proof, without a reply key, or with a loopback mailbox.
    let book = world.issuer.wallet.contact_book();
    let receive = |bytes: &[u8]| {
        world.block_on(book.in_person_receive(
            &relays(&world.issuer),
            bytes,
            ReceiveRequest::default(),
        ))
    };
    // An S1 with the proof flag and no proof does not decode.
    let proved = receive(&with_proof(&send.bytes));
    assert!(matches!(proved, Err(ContactError::Native(_))), "{proved:?}");
    let keyless = without_tail(Network::Floonet, &send.bytes).unwrap();
    assert_eq!(refusal(receive(&keyless)), InPersonRefusal::NoReplyKey);
    let looped = with_mailbox_host(Network::Floonet, &send.bytes, "127.0.0.1:7000").unwrap();
    assert_eq!(refusal(receive(&looped)), InPersonRefusal::Loopback);
    // Nothing refused was received.
    let open = world
        .issuer
        .read(|repos| repos.transactions(ACCOUNT))
        .into_iter()
        .filter(|tx| tx.entry.slate_id.map(|id| *id.as_bytes()) == Some(*send.slate_id.as_bytes()))
        .count();
    assert_eq!(open, 0);

    // The S1 sealed to its own reply key is not an answer.
    let sealed = sealed_to(Network::Floonet, &send.bytes, send.bytes.clone(), false);
    assert_eq!(
        refusal(world.block_on(world.payer.wallet.contact_book().in_person_take(&sealed))),
        InPersonRefusal::WrongStage
    );

    // A send code never asks for a payment proof.
    let key = world
        .payer
        .keychain()
        .payment_proof_key(&Identifier::new(2, [0, 0, 0, 0]).unwrap(), 0)
        .unwrap();
    let proved = world.block_on(world.payer.wallet.contact_book().in_person_send(
        &relays(&world.payer),
        SendRequest {
            payment_proof_recipient: Some(ProofAddress::from_bytes(key.public_key()).unwrap()),
            ..send_request()
        },
    ));
    assert_eq!(refusal(proved), InPersonRefusal::Proof);
}

#[test]
fn a_send_code_past_its_ttl_expires_at_refresh_and_frees_its_inputs() {
    let world = World::new();
    let code = world.show_send(&relays(&world.payer));
    let received = world.receive_with(&world.issuer, &code);
    assert!(world.payer.wallet.balance(ACCOUNT).unwrap().locked > Amount::ZERO);

    world
        .node
        .update_chain(|chain| chain.tip.height = Height::new(code.ttl_cutoff));
    world.block_on(world.payer.wallet.refresh()).unwrap();
    world.block_on(world.issuer.wallet.refresh()).unwrap();

    let sent = world
        .payer
        .read(|repos| repos.transaction(code.tx_id))
        .unwrap();
    assert_eq!(sent.state, TxState::Expired);
    assert_eq!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );
    let answer = world
        .issuer
        .read(|repos| repos.transaction(received.tx_id))
        .unwrap();
    assert_eq!(answer.state, TxState::Expired);

    // The expired code is forgotten, and an answer to it is not taken.
    assert_eq!(world.collect_with(&world.payer, &relays(&world.payer)), 0);
    assert_eq!(
        refusal(
            world.block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .in_person_answers(code.slate_id)
            )
        ),
        InPersonRefusal::NoCode
    );
    let late = world.block_on(
        world
            .payer
            .wallet
            .contact_book()
            .in_person_take(&received.envelope),
    );
    assert!(late.is_err(), "{late:?}");
}

#[test]
fn a_ttl_at_or_under_the_margin_is_refused_and_the_default_is_thirty_blocks() {
    assert_eq!(IN_PERSON_TTL_BLOCKS, 30);
    let world = World::new();
    let expected = InPersonRefusal::TtlTooShort {
        margin: INVOICE_TTL_MARGIN_BLOCKS,
    };
    let invoice_with = |ttl: u64| {
        world.block_on(world.issuer.wallet.contact_book().in_person_invoice(
            &relays(&world.issuer),
            InPersonInvoiceRequest {
                ttl_blocks: Some(ttl),
                ..request()
            },
        ))
    };
    let send_with = |ttl: u64| {
        world.block_on(world.payer.wallet.contact_book().in_person_send(
            &relays(&world.payer),
            SendRequest {
                ttl_blocks: Some(ttl),
                ..send_request()
            },
        ))
    };
    for ttl in [0, 1, INVOICE_TTL_MARGIN_BLOCKS] {
        assert_eq!(refusal(invoice_with(ttl)), expected, "invoice ttl {ttl}");
        assert_eq!(refusal(send_with(ttl)), expected, "send ttl {ttl}");
    }
    // One block over the margin is accepted, on both paths.
    let ttl = INVOICE_TTL_MARGIN_BLOCKS + 1;
    assert_eq!(invoice_with(ttl).unwrap().ttl_cutoff, TIP + ttl);
    assert_eq!(send_with(ttl).unwrap().ttl_cutoff, TIP + ttl);
}

#[test]
fn an_answer_to_a_cancelled_payment_is_not_posted() {
    let world = World::new();
    let code = world.show(&relays(&world.issuer));
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();

    assert_eq!(
        refusal(
            world.block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .in_person_post(&relays(&world.payer), paid.slate_id)
            )
        ),
        InPersonRefusal::Ended
    );
    assert_eq!(world.collect_with(&world.issuer, &relays(&world.issuer)), 0);
}

#[test]
fn an_answer_to_a_code_is_not_finalized_as_plain_sealed_text() {
    let world = World::new();
    let code = world.show_send(&offline(&world.payer));
    let received = world.receive_with(&world.issuer, &code);
    let text = armored(&received.envelope);

    assert_eq!(
        refusal(
            world.block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .sealed_finalize(&text, Propagation::Stem)
            )
        ),
        InPersonRefusal::AnswerToCode
    );
    assert!(world.node.pushed_transactions().is_empty());
    let sent = world
        .payer
        .read(|repos| repos.transaction(code.tx_id))
        .unwrap();
    assert_eq!(sent.state, TxState::Sent);
}

/// The issuer's mailbox of the code `slate_id` on the wallets' own relay.
fn code_mailbox(party: &Party, slate_id: lepic_slate::model::SlateId) -> EpicboxAddress {
    let secret = party
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

fn in_person_answers(answers: &[Event]) -> usize {
    answers
        .iter()
        .filter(|event| matches!(event, Event::InPersonAnswer(_)))
        .count()
}

/// An answer to a code, stored before its acknowledgement was lost, is offered again after the
/// wallet is opened again and taken as handled: no second answer, no event, and the relay ends
/// with the mail gone.
#[test]
fn an_in_person_answer_stored_before_its_ack_was_lost_is_handled_once() {
    const HOME: &str = "relay.test:80";
    let mut world = World::new();
    hold_acks(&world.issuer);
    let code = world.show(&relays(&world.issuer));
    assert_eq!(code.mailbox.as_deref(), Some(HOME));
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_collect(&relays(&world.issuer), CollectTrigger::Open),
        )
        .unwrap();
    let mailbox = code_mailbox(&world.issuer, code.slate_id);
    let mut issuer_events = world.issuer.wallet.subscribe();

    queued_after(&world, &world.issuer, HOME, || {
        let book = world.payer.wallet.contact_book();
        let paid = world
            .block_on(book.in_person_pay(&relays(&world.payer), &code.bytes, pay_request()))
            .unwrap();
        world
            .block_on(book.in_person_post(&relays(&world.payer), paid.slate_id))
            .unwrap();
    });
    let report = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_collect(&relays(&world.issuer), CollectTrigger::Push),
        )
        .unwrap();
    assert_eq!(report.in_person, 1);
    assert_eq!(in_person_answers(&events(&mut issuer_events)), 1);
    assert_eq!(world.relay.pending(&mailbox), 1, "the ack is held");

    let reopened = lose_acks_and_reopen(&world, &world.issuer);
    let old = std::mem::replace(&mut world.issuer, reopened);
    old.wallet.close();
    let mut reopened_events = world.issuer.wallet.subscribe();
    assert_eq!(world.collect_with(&world.issuer, &relays(&world.issuer)), 0);
    wait_gone(&world, &mailbox);
    let session = world.issuer.epicbox.pushed().get(HOME, ACK_GROUP).unwrap();
    assert!(session.counters().mails >= 1, "the relay offered it again");
    assert!(events(&mut reopened_events).is_empty());
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
    assert_eq!(view.finalized, None);
}

impl World {
    /// The issuer shows a code made from `request`.
    fn show_with(&self, relays: &ContactRelays, request: InPersonInvoiceRequest) -> InPersonCode {
        self.block_on(
            self.issuer
                .wallet
                .contact_book()
                .in_person_invoice(relays, request),
        )
        .unwrap()
    }

    /// `party` pays `code` and posts the answer.
    fn pay_and_post(&self, party: &Party, code: &InPersonCode) -> InPersonPaid {
        let book = party.wallet.contact_book();
        let paid = self
            .block_on(book.in_person_pay(&relays(party), &code.bytes, pay_request()))
            .unwrap();
        self.block_on(book.in_person_post(&relays(party), paid.slate_id))
            .unwrap();
        paid
    }

    fn take_direct(&self, envelope: &[u8]) -> InPersonDirect {
        self.block_on(
            self.issuer
                .wallet
                .contact_book()
                .in_person_take_direct(envelope),
        )
    }

    fn answers_to(&self, code: &InPersonCode) -> usize {
        self.block_on(
            self.issuer
                .wallet
                .contact_book()
                .in_person_answers(code.slate_id),
        )
        .unwrap()
        .answers
        .len()
    }
}

/// The reasons of the in-person answers refused among `events`.
fn refused_reasons(events: &[Event]) -> Vec<&'static str> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::InPersonAnswerRefused(refused) => Some(refused.reason),
            _ => None,
        })
        .collect()
}

/// An answer whose inputs the node does not hold as unspent could never be posted: it is
/// refused for good, told once, and not counted.
#[test]
fn an_in_person_answer_whose_inputs_are_spent_is_refused_and_not_counted() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let code = world.show(&offline(&world.issuer));
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    world.node.update_chain(|chain| {
        for output in &mut chain.outputs {
            output.spent = true;
        }
    });

    assert_eq!(
        world.take_direct(&paid.envelope),
        InPersonDirect::Refused("inputs_spent")
    );
    let taken = world.block_on(
        world
            .issuer
            .wallet
            .contact_book()
            .in_person_take(&paid.envelope),
    );
    assert!(
        matches!(
            taken,
            Err(ContactError::Invoice(InvoiceError::AnswerInputsSpent { slate_id }))
                if slate_id == code.slate_id
        ),
        "{taken:?}"
    );

    let events = events(&mut issuer_events);
    assert_eq!(refused_reasons(&events), ["inputs_spent", "inputs_spent"]);
    assert_eq!(in_person_answers(&events), 0);
    assert_eq!(world.answers_to(&code), 0);
}

/// When the node cannot say whether an answer's inputs are unspent, the answer is neither
/// counted nor refused: it is taken once the node answers.
#[test]
fn an_in_person_answer_is_taken_later_when_the_node_cannot_check_its_inputs() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let code = world.show(&offline(&world.issuer));
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    world
        .node
        .fail_every("get_outputs", MockFailure::Unreachable);

    assert_eq!(world.take_direct(&paid.envelope), InPersonDirect::Transient);
    assert_eq!(world.answers_to(&code), 0);
    assert_eq!(
        refused_reasons(&events(&mut issuer_events)),
        Vec::<&str>::new()
    );

    world.node.stop_failing("get_outputs");
    assert_eq!(world.take_direct(&paid.envelope), InPersonDirect::Accepted);
    assert_eq!(world.answers_to(&code), 1);
    assert_eq!(in_person_answers(&events(&mut issuer_events)), 1);
}

/// Once an answer is finalized, another answer to the same code is refused for good and never
/// finalized; the one finalized, coming again, is still the same answer.
#[test]
fn a_second_in_person_answer_after_finalize_is_refused_and_never_finalized() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let code = world.show(&offline(&world.issuer));
    let twin = world.payer_twin();
    twin.fund(0, FUNDING);
    let mut paid = Vec::new();
    for party in [&world.payer, &twin] {
        paid.push(
            world
                .block_on(party.wallet.contact_book().in_person_pay(
                    &relays(party),
                    &code.bytes,
                    pay_request(),
                ))
                .unwrap(),
        );
    }
    assert_eq!(
        world.take_direct(&paid[0].envelope),
        InPersonDirect::Accepted
    );
    world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            code.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();
    assert_eq!(world.node.pushed_transactions().len(), 1);

    assert_eq!(
        world.take_direct(&paid[1].envelope),
        InPersonDirect::Refused("already_finalized")
    );
    assert_eq!(
        world.take_direct(&paid[0].envelope),
        InPersonDirect::Accepted
    );
    assert_eq!(
        refusal(
            world.block_on(world.issuer.wallet.contact_book().in_person_finalize(
                code.slate_id,
                2,
                Propagation::Stem,
            ))
        ),
        InPersonRefusal::NoAnswer
    );

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
    assert_eq!(view.answers.len(), 1);
    assert_eq!(
        refused_reasons(&events(&mut issuer_events)),
        ["already_finalized"]
    );
}

/// Codes made for the account's shared slot name one reply mailbox and share one watch row,
/// kept while any of them waits; a code made without it keeps its own slot.
#[test]
fn in_person_codes_on_the_shared_slot_share_one_row_until_the_last_ends() {
    let world = World::new();
    let issuer_relays = relays(&world.issuer);
    let shared = || InPersonInvoiceRequest {
        shared_slot: true,
        ..request()
    };
    let first = world.show_with(&issuer_relays, shared());
    let second = world.show_with(&issuer_relays, shared());
    let own = world.show(&issuer_relays);
    let slot = WatchRow {
        key_ref: format!("inperson-slot:{}", ACCOUNT.0),
        relay: first.mailbox.clone().unwrap(),
        class: MailClass::InPerson,
        expires_at: None,
    };
    let rows = |world: &World| {
        world.block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .claim_pushed(&issuer_relays),
        );
        let mut rows = code_rows(&world.issuer);
        rows.sort_by(|a, b| a.key_ref.cmp(&b.key_ref));
        rows
    };
    let own_row = WatchRow {
        key_ref: format!("inperson:{}", own.slate_id),
        ..slot.clone()
    };
    assert_eq!(rows(&world), [slot.clone(), own_row.clone()]);

    let paid = world.pay_and_post(&world.payer, &first);
    assert_eq!(paid.slate_id, first.slate_id);
    assert_eq!(world.collect_with(&world.issuer, &issuer_relays), 1);
    world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            first.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();
    // The second code still waits on the slot.
    assert_eq!(rows(&world), [slot, own_row.clone()]);

    let twin = world.payer_twin();
    twin.fund(0, FUNDING);
    world.pay_and_post(&twin, &second);
    assert_eq!(world.collect_with(&world.issuer, &issuer_relays), 1);
    assert_eq!(world.answers_to(&second), 1);
    world
        .block_on(world.issuer.wallet.contact_book().in_person_finalize(
            second.slate_id,
            1,
            Propagation::Stem,
        ))
        .unwrap();
    assert_eq!(rows(&world), [own_row]);
}

/// Issuing a code again for the same slate id returns the code stored, without a second
/// invoice.
#[test]
fn an_in_person_code_issued_again_for_its_slate_id_is_the_same_code() {
    let world = World::new();
    let slate_id = lepic_slate::model::SlateId::from_bytes([5; 16]);
    let ask = || InPersonInvoiceRequest {
        slate_id: Some(slate_id),
        ..request()
    };
    let entries = || world.issuer.read(|repos| repos.transactions(ACCOUNT)).len();
    let before = entries();
    let first = world.show_with(&relays(&world.issuer), ask());
    let again = world.show_with(&relays(&world.issuer), ask());

    assert_eq!(first.slate_id, slate_id);
    assert_eq!(again, first);
    assert_eq!(entries(), before + 1);

    for other in [
        InPersonInvoiceRequest {
            amount: Amount::new(AMOUNT + 1),
            ..ask()
        },
        InPersonInvoiceRequest {
            message: Some("tea".to_owned()),
            ..ask()
        },
    ] {
        assert_eq!(
            refusal(
                world.block_on(
                    world
                        .issuer
                        .wallet
                        .contact_book()
                        .in_person_invoice(&relays(&world.issuer), other)
                )
            ),
            InPersonRefusal::RepeatDiffers
        );
    }
    assert_eq!(entries(), before + 1);
}

/// An answer to a code the issuer cancelled is refused as `cancelled`, also after the
/// issuer's upkeep ran, until the code's TTL passes.
#[test]
fn an_answer_to_a_cancelled_code_is_refused_as_cancelled() {
    let world = World::new();
    let mut issuer_events = world.issuer.wallet.subscribe();
    let code = world.show(&offline(&world.issuer));
    let paid = world
        .block_on(world.payer.wallet.contact_book().in_person_pay(
            &relays(&world.payer),
            &code.bytes,
            pay_request(),
        ))
        .unwrap();
    world
        .block_on(world.issuer.wallet.cancel(code.tx_id))
        .unwrap();
    world.collect_with(&world.issuer, &relays(&world.issuer));

    assert_eq!(
        world.take_direct(&paid.envelope),
        InPersonDirect::Refused("cancelled")
    );
    let events = events(&mut issuer_events);
    assert_eq!(refused_reasons(&events), ["cancelled"]);
}

/// A code with direct routes and a domain claim is read with both; a direct route of the
/// mailbox method is refused when the code is made.
#[test]
fn an_in_person_code_with_direct_routes_and_a_claim_is_read_with_them() {
    let world = World::new();
    let routes = vec![
        RouteEntry {
            method: MethodId::Http,
            value: "shop-1.test:8443".to_owned(),
        },
        RouteEntry {
            method: MethodId::Tor,
            value: "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion".to_owned(),
        },
    ];
    let code = world.show_with(
        &offline(&world.issuer),
        InPersonInvoiceRequest {
            direct: routes.clone(),
            claim: Some(ClaimSigner {
                domain: "shop.test".to_owned(),
            }),
            ..request()
        },
    );

    let read = world
        .block_on(world.payer.wallet.contact_book().in_person_read(
            &relays(&world.payer),
            options(),
            &code.bytes,
        ))
        .unwrap();
    assert_eq!(read.direct, routes);
    let claim = read.claim.unwrap();
    assert_eq!(claim.domain.as_str(), "shop.test");
    assert_eq!(
        lepic_wallet_contacts::request_claim(&code.bytes),
        Some(claim)
    );

    assert_eq!(
        refusal(
            world.block_on(world.issuer.wallet.contact_book().in_person_invoice(
                &offline(&world.issuer),
                InPersonInvoiceRequest {
                    direct: vec![RouteEntry {
                        method: MethodId::Epicbox,
                        value: "relay.test".to_owned(),
                    }],
                    ..request()
                },
            ))
        ),
        InPersonRefusal::DirectRoute
    );
}
