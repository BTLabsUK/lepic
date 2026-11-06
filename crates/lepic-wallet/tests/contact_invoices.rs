// SPDX-License-Identifier: Apache-2.0
//! Invoices, withdrawals and notices between paired contacts through their mailboxes and the
//! outbox (RFC 0002 sections 11 and 12, cases C-03, C-07, C-20, C-23 and C-25).

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

use std::time::Duration;

use helpers::{HOUR, MINUTE, accept, events, invite_request, relays};
use lepic_contact::{
    ContactCard, ContactKind, Content, MessageType, Network as ContactNetwork, Purpose, SigningKey,
    armor, seal,
};
use lepic_epicbox::{Domain, EpicboxAddress, Identity, MailboxClient, Network as RelayNetwork};
use lepic_primitives::amount::Amount;
use lepic_store::{ContactId, ContactOutboxState, SlateStage, TxState, WalletStore};
use lepic_wallet::Event;
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet_contacts::{
    ContactRelays, InviteRequest, InvoiceDetails, RelayMode, SasDecision, WalletContacts,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, Party, World, pay_request};

impl World {
    /// The issuer, as a service of `kind`, and the payer pair; the payer verifies the SAS and
    /// allows the issuer's invoices. Returns the issuer's and the payer's contact ids.
    fn pair_for_invoices(&self, kind: ContactKind) -> (ContactId, ContactId) {
        let link = self
            .block_on(self.issuer.wallet.contact_book().pairing_invite(
                &relays(&self.issuer),
                InviteRequest {
                    kind,
                    ..invite_request("Shop")
                },
            ))
            .unwrap()
            .link;
        let answered = self
            .block_on(
                self.payer
                    .wallet
                    .contact_book()
                    .pairing_accept(&relays(&self.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert_eq!(self.collect(&self.issuer).paired, 1);
        assert_eq!(self.collect(&self.payer).paired, 1);
        // The inviter hears that the invitee finished.
        self.collect(&self.issuer);
        let shop_side = self.only_contact(&self.issuer);
        let ben_side = answered.contact_id;
        self.block_on(self.payer.wallet.contact_book().pairing_sas(
            &relays(&self.payer),
            ben_side,
            SasDecision::Match,
        ))
        .unwrap();
        self.block_on(
            self.payer
                .wallet
                .contact_book()
                .contact_set_allow_invoices(ben_side, true),
        )
        .unwrap();
        // The issuer takes the payer's verdict.
        self.collect(&self.issuer);
        (shop_side, ben_side)
    }

    fn invoice_contact(&self, shop_side: ContactId, reference: &str) -> IssuedInvoice {
        self.block_on(self.issuer.wallet.contact_book().contact_issue_invoice(
            &relays(&self.issuer),
            shop_side,
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
            InvoiceDetails {
                purpose: Purpose::DepositRequest,
                reference: Some(reference.to_owned()),
                expires: Some(1_800_000_000),
            },
        ))
        .unwrap()
    }

    fn pay_contact(&self, issued: &IssuedInvoice) -> lepic_wallet::invoice::PaidInvoice {
        self.block_on(self.payer.wallet.contact_book().contact_pay_invoice(
            &relays(&self.payer),
            issued.slate_id,
            pay_request(),
        ))
        .unwrap()
    }

    fn tx_state(&self, party: &Party, tx_id: lepic_store::TxId) -> TxState {
        party.read(|repos| repos.transaction(tx_id)).unwrap().state
    }
}

#[test]
fn a_contact_invoice_is_parked_paid_through_the_outbox_and_posted() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut payer_events = world.payer.wallet.subscribe();

    let issued = world.invoice_contact(shop_side, "deposit-17");
    world.collect(&world.payer);

    let parked = world
        .block_on(world.payer.wallet.contact_book().contact_invoices())
        .unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].slate_id, issued.slate_id);
    assert_eq!(parked[0].contact_id, ben_side);
    assert_eq!(parked[0].purpose, Some(Purpose::DepositRequest));
    assert_eq!(parked[0].reference.as_deref(), Some("deposit-17"));
    assert!(events(&mut payer_events).iter().any(|event| matches!(
        event,
        Event::InvoiceFromContact(invoice) if invoice.slate_id == issued.slate_id
    )));
    // Parking pays nothing; paying is the user's call.
    assert!(
        world
            .payer
            .read(|repos| repos.transactions(ACCOUNT))
            .is_empty()
    );

    let paid = world.pay_contact(&issued);
    let outbox = world
        .block_on(world.payer.wallet.contact_book().contact_outbox(ben_side))
        .unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].stage, SlateStage::Invoice2);
    assert_eq!(outbox[0].state, ContactOutboxState::Delivered);

    world.collect(&world.issuer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.tx_state(&world.issuer, issued.tx_id), TxState::Posted);

    // The posted notice comes back sealed.
    world.collect(&world.payer);
    assert!(events(&mut payer_events).iter().any(|event| matches!(
        event,
        Event::InvoicePosted(posted) if posted.tx_id == paid.tx_id
    )));
    // A contact invoice is never paid over the payments address.
    assert!(world.payer.delivered_to().is_empty());
}

#[test]
fn invoices_from_unverified_contacts_strangers_and_plain_text_never_park() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Shop");
    let answered = world
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
    let shop_side = world.only_contact(&world.issuer);

    // Paired but not verified, and invoices not allowed.
    world.invoice_contact(shop_side, "one");
    world.collect(&world.payer);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );

    // A stranger who guessed the mailbox, signing with its own key, and a plain I1.
    let record = world
        .payer
        .read(|repos| repos.contact(answered.contact_id))
        .unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let mailbox =
        EpicboxAddress::parse(own.fields().mailbox.as_str(), RelayNetwork::Floonet).unwrap();
    let issued = world.issue_to(&World::address_of(99), None);
    let i1 = world
        .issuer
        .read(|repos| {
            repos.slate(
                uuid::Uuid::from_bytes(*issued.slate_id.as_bytes()),
                SlateStage::Invoice1,
            )
        })
        .unwrap()
        .bytes;
    let envelope = seal(
        ContactNetwork::Floonet,
        own.enc_key(),
        own.hint_rule(),
        &Content::new(MessageType::Slate, i1.clone()),
        Some(&SigningKey::from_bytes(&[7; 32])),
        &mut rand::rngs::StdRng::seed_from_u64(5),
    )
    .unwrap();
    let stranger = Identity::new(world::key(77), World::address_of(77)).unwrap();
    let client = MailboxClient::new(world::settings(), world.relay.connector());
    world
        .block_on(client.post(&stranger, &mailbox, &armor(&envelope)))
        .unwrap();
    world
        .block_on(client.post(&stranger, &mailbox, &String::from_utf8(i1).unwrap()))
        .unwrap();

    world.collect(&world.payer);

    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoices())
            .is_empty()
    );
    assert_eq!(world.relay.pending(&mailbox), 0);
}

#[test]
fn turning_invoices_off_declines_the_unpaid_ones_and_lets_the_paid_one_finish() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let first = world.invoice_contact(shop_side, "a");
    let second = world.invoice_contact(shop_side, "b");
    let third = world.invoice_contact(shop_side, "c");
    world.collect(&world.payer);
    assert_eq!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .len(),
        3
    );
    world.pay_contact(&third);
    let mut issuer_events = world.issuer.wallet.subscribe();

    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_set_allow_invoices(ben_side, false),
        )
        .unwrap();
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_outbox_deliver(&relays(&world.payer)),
        )
        .unwrap();

    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );
    world.collect(&world.issuer);
    let mut declined: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InvoiceDeclined(declined) => Some(declined.tx_id),
            _ => None,
        })
        .collect();
    declined.sort();
    let mut expected = vec![first.tx_id, second.tx_id];
    expected.sort();
    assert_eq!(declined, expected);
    // The paid one finishes.
    assert_eq!(world.tx_state(&world.issuer, third.tx_id), TxState::Posted);
    // New invoices are dropped while the switch is off.
    world.invoice_contact(shop_side, "d");
    world.collect(&world.payer);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );
}

/// An issuer's next collecting cycle prunes its outbox before it posts anything: the
/// `withdrawn` of the invoice just cancelled must survive that and reach the payer, who then no
/// longer offers it for payment.
#[test]
fn a_withdrawn_reaches_the_payer_through_the_issuers_next_collect() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    let withdrawn = world.invoice_contact(shop_side, "withdrawn");
    let kept = world.invoice_contact(shop_side, "kept");
    world.collect(&world.payer);
    let mut payer_events = world.payer.wallet.subscribe();

    world
        .block_on(world.issuer.wallet.cancel(withdrawn.tx_id))
        .unwrap();
    world.collect(&world.issuer);
    world.collect(&world.payer);

    let told: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InvoiceWithdrawn(told) => Some(told.slate_id),
            _ => None,
        })
        .collect();
    assert_eq!(told, vec![withdrawn.slate_id]);
    let left: Vec<_> = world
        .block_on(world.payer.wallet.contact_book().contact_invoices())
        .unwrap()
        .into_iter()
        .map(|invoice| invoice.slate_id)
        .collect();
    assert_eq!(left, vec![kept.slate_id]);
}

#[test]
fn a_signed_withdrawn_for_a_paid_invoice_cancels_the_payment() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    let unpaid = world.invoice_contact(shop_side, "unpaid");
    let paid_invoice = world.invoice_contact(shop_side, "paid");
    world.collect(&world.payer);
    // The shop is offline when the payment comes, so the payment waits on its relay.
    let paid = world.pay_contact(&paid_invoice);
    let mut payer_events = world.payer.wallet.subscribe();

    for issued in [&unpaid, &paid_invoice] {
        world
            .block_on(world.issuer.wallet.cancel(issued.tx_id))
            .unwrap();
    }
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_outbox_deliver(&relays(&world.issuer)),
        )
        .unwrap();
    world.collect(&world.payer);

    let withdrawn: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InvoiceWithdrawn(withdrawn) => Some(withdrawn.tx_id),
            _ => None,
        })
        .collect();
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&None));
    assert!(withdrawn.contains(&Some(paid.tx_id)));
    assert_eq!(world.tx_state(&world.payer, paid.tx_id), TxState::Cancelled);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_outbox_retries_reaches_the_home_relay_from_another_relay_and_gets_stuck() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let issued = world.invoice_contact(shop_side, "x");
    world.collect(&world.payer);
    world.relay.set_refusing(true);
    world.pay_contact(&issued);
    let entry = |world: &World| {
        world
            .block_on(world.payer.wallet.contact_book().contact_outbox(ben_side))
            .unwrap()
            .remove(0)
    };
    assert_eq!(entry(&world).state, ContactOutboxState::Queued);
    assert_eq!(entry(&world).attempts, 1);
    world.relay.set_refusing(false);
    // Not due yet.
    let report = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_outbox_deliver(&relays(&world.payer)),
        )
        .unwrap();
    assert_eq!(report.delivered, 0);

    // The user switched to another relay; the outbox still posts to the home relay.
    world.payer.clock.advance(Duration::from_secs(31));
    let mut settings = world::settings();
    settings.endpoint = lepic_epicbox::RelayEndpoint::new(
        Domain::parse("elsewhere.test").unwrap(),
        None,
        lepic_epicbox::Security::Plain,
    );
    let elsewhere = ContactRelays {
        epicbox: lepic_epicbox::transport::EpicboxTransport::new(
            settings,
            RelayNetwork::Floonet,
            world.relay.connector(),
        ),
        meeting: vec![world.payer.epicbox.settings().endpoint.clone()],
        mode: RelayMode::Online,
    };
    let report = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_outbox_deliver(&elsewhere),
        )
        .unwrap();
    assert_eq!(report.delivered, 1);
    world.collect(&world.issuer);
    assert_eq!(world.tx_state(&world.issuer, issued.tx_id), TxState::Posted);

    // Another payment that never gets through is stuck after a day.
    world.payer.fund(10, world::FUNDING);
    let issued = world.invoice_contact(shop_side, "y");
    world.collect(&world.payer);
    world.relay.set_refusing(true);
    world.pay_contact(&issued);
    let mut payer_events = world.payer.wallet.subscribe();
    world.payer.clock.advance(24 * HOUR + MINUTE);
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_outbox_deliver(&relays(&world.payer)),
        )
        .unwrap();
    assert!(
        events(&mut payer_events)
            .iter()
            .any(|event| matches!(event, Event::OutboxStuck(_)))
    );
}

#[test]
fn same_amount_requests_within_ten_minutes_are_grouped() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    let first = world.invoice_contact(shop_side, "a");
    let second = world.invoice_contact(shop_side, "b");
    world.collect(&world.payer);

    let parked = world
        .block_on(world.payer.wallet.contact_book().contact_invoices())
        .unwrap();

    let of = |slate_id| {
        parked
            .iter()
            .find(|invoice| invoice.slate_id == slate_id)
            .unwrap()
    };
    assert_eq!(of(first.slate_id).same_amount, vec![second.slate_id]);
    assert_eq!(of(second.slate_id).same_amount, vec![first.slate_id]);
}

#[test]
fn a_withdrawal_through_the_mailbox_is_received_and_answered_through_the_outbox() {
    let world = World::new();
    // The payer plays the exchange here: it holds the funds and pays out.
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut issuer_events = world.issuer.wallet.subscribe();
    let sent = world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("s1.tx"),
                ),
            },
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.contact_book().contact_post_slate(
            &relays(&world.payer),
            ben_side,
            sent.tx_id,
            Some(Purpose::Withdrawal),
        ))
        .unwrap();

    world.collect(&world.issuer);

    assert!(events(&mut issuer_events).iter().any(|event| matches!(
        event,
        Event::WithdrawalFromContact(withdrawal)
            if withdrawal.contact_id == shop_side && withdrawal.amount == Amount::new(AMOUNT)
    )));
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.tx_state(&world.payer, sent.tx_id), TxState::Posted);
}

/// A service and a person ask for a move the same way: the update is stored and reported, and
/// our mailbox stays until the host applies the move.
#[test]
fn a_service_moving_its_home_relay_moves_our_mailbox_once_applied() {
    a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(ContactKind::Exchange);
}

#[test]
fn a_person_moving_its_home_relay_moves_our_mailbox_once_applied() {
    a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(ContactKind::Person);
}

#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(kind: ContactKind) {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(kind);
    let mut payer_events = world.payer.wallet.subscribe();
    let shown = world
        .payer
        .read(|repos| repos.contact_mailbox(ben_side))
        .unwrap();
    // The shop's update: its card for this pairing with its mailbox on a new relay.
    let keys = keys_for(&world.issuer, shop_side);
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = world.issuer.read(|repos| repos.contact(shop_side)).unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let key_text = own.fields().mailbox.as_str().split('@').next().unwrap();
    let mut fields = own.fields().clone();
    fields.seq = 2;
    fields.mailbox =
        lepic_contact::MailboxAddress::new(&format!("{key_text}@relay2.test:80")).unwrap();
    let card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    post_signed(
        &world,
        &world.issuer,
        shop_side,
        &Content::new(MessageType::ContactUpdate, card.as_bytes().to_vec()),
    );
    let built_in = ContactRelays {
        meeting: vec![lepic_epicbox::RelayEndpoint::new(
            Domain::parse("relay2.test").unwrap(),
            Some(80),
            lepic_epicbox::Security::Plain,
        )],
        ..relays(&world.payer)
    };
    let collect = || {
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .contacts_collect(&built_in, lepic_wallet_contacts::CollectTrigger::Open),
            )
            .unwrap()
    };
    let view = || {
        world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
    };
    let requests = |events: Vec<Event>| {
        events
            .into_iter()
            .filter_map(|event| match event {
                Event::ContactRelayMoveRequested(request) => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    collect();
    // The card is stored and the move reported once; nothing moved yet.
    let moves = requests(events(&mut payer_events));
    assert_eq!(moves.len(), 1, "{moves:?}");
    assert_eq!(moves[0].contact_id, ben_side);
    assert_eq!(moves[0].host, "relay2.test:80");
    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact(ben_side))
            .unwrap()
            .peer
            .unwrap()
            .seq,
        2
    );
    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact_mailbox(ben_side))
            .unwrap(),
        shown
    );
    assert_eq!(view().requested_relay.as_deref(), Some("relay2.test:80"));
    collect();
    assert!(requests(events(&mut payer_events)).is_empty());

    // Only the host the card names is applied.
    for other in ["relay3.test:80", "relay.test:80", ""] {
        assert!(matches!(
            world.block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .apply_relay_move(ben_side, other)
            ),
            Err(lepic_wallet_contacts::ContactError::RelayMoveNotRequested)
        ));
    }
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .apply_relay_move(ben_side, "relay2.test:80"),
        )
        .unwrap();
    assert_eq!(view().requested_relay, None);
    // Applied once, the move is no longer asked for.
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .apply_relay_move(ben_side, "relay2.test:80")
        ),
        Err(lepic_wallet_contacts::ContactError::RelayMoveNotRequested)
    ));

    let mailbox = world
        .payer
        .read(|repos| repos.contact_mailbox(ben_side))
        .unwrap();
    assert_eq!(mailbox.home_relay, "relay2.test:80");
    assert!(mailbox.peer_mailbox.ends_with("@relay2.test:80"));
    assert!(mailbox.our_mailbox.ends_with("@relay2.test:80"));
    let previous = mailbox.previous.unwrap();
    assert_eq!(previous.relay, "relay.test:80");
    // Our new card goes to the shop in a contact update.
    let outbox = world.payer.read(|repos| repos.contact_outbox(ben_side));
    assert!(
        outbox
            .iter()
            .any(|stored| stored.entry.destination.ends_with("@relay2.test:80")),
        "{outbox:?}"
    );
    // Both mailboxes are collected while the old one is kept.
    assert_eq!(collect().mailboxes, 2);
    world.payer.clock.advance(7 * 24 * HOUR + MINUTE);
    assert_eq!(collect().mailboxes, 1);
    // Our card for the shop moved with it.
    let own = world
        .payer
        .read(|repos| repos.contact(ben_side))
        .unwrap()
        .own_card;
    let own = ContactCard::decode(&own, ContactNetwork::Floonet).unwrap();
    assert!(own.fields().mailbox.as_str().ends_with("@relay2.test:80"));
    assert_eq!(own.fields().seq, 2);
}

/// Only a contact update asks for a move, whatever relay it names; a card in any other envelope
/// never names another mailbox, an update may not change what the contact is, and a pairing
/// nobody asked to move keeps its mailbox.
#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_relay_move_is_asked_only_by_an_update_and_never_by_a_plain_card() {
    let world = World::new();
    // The kind is deprecated: a new pairing is a person whatever its request says (ADR 0041), and
    // a card of another kind than the pairing's is refused.
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Person);
    let mut payer_events = world.payer.wallet.subscribe();
    let keys = keys_for(&world.issuer, shop_side);
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = world.issuer.read(|repos| repos.contact(shop_side)).unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let key_text = own
        .fields()
        .mailbox
        .as_str()
        .split('@')
        .next()
        .unwrap()
        .to_owned();
    let card = |seq: u32, host: &str, kind: ContactKind| {
        let mut fields = own.fields().clone();
        fields.seq = seq;
        fields.kind = kind;
        fields.mailbox = lepic_contact::MailboxAddress::new(&format!("{key_text}@{host}")).unwrap();
        ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap()
    };
    let shown = world
        .payer
        .read(|repos| repos.contact_mailbox(ben_side))
        .unwrap();
    let seq = || {
        world
            .payer
            .read(|repos| repos.contact(ben_side))
            .unwrap()
            .peer
            .unwrap()
            .seq
    };
    let view = || {
        world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
    };
    let apply = |host: &str| {
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .apply_relay_move(ben_side, host),
        )
    };
    let moved = |events: Vec<Event>| {
        events
            .iter()
            .filter(|event| matches!(event, Event::ContactRelayMoveRequested(_)))
            .count()
    };

    // A pairing nobody asked to move: nothing to apply, the mailbox stays as it was.
    world.collect(&world.payer);
    assert_eq!(view().requested_relay, None);
    assert!(matches!(
        apply("relay.test:80"),
        Err(lepic_wallet_contacts::ContactError::RelayMoveNotRequested)
    ));

    // A notice carrying a newer card for another relay in its tag 07.
    let mut notice = Content::new(MessageType::Notice, b"{}".to_vec());
    notice.card = Some(card(2, "relay4.test:443", ContactKind::Person));
    post_signed(&world, &world.issuer, shop_side, &notice);
    // An update that changes what the contact is.
    post_signed(
        &world,
        &world.issuer,
        shop_side,
        &Content::new(
            MessageType::ContactUpdate,
            card(3, "relay3.test:8443", ContactKind::Exchange)
                .as_bytes()
                .to_vec(),
        ),
    );
    world.collect(&world.payer);
    assert_eq!(seq(), 1);
    assert_eq!(moved(events(&mut payer_events)), 0);
    assert_eq!(view().requested_relay, None);

    // An update naming an address and port of its own is reported like any other.
    post_signed(
        &world,
        &world.issuer,
        shop_side,
        &Content::new(
            MessageType::ContactUpdate,
            card(4, "10.0.0.7:443", ContactKind::Person)
                .as_bytes()
                .to_vec(),
        ),
    );
    world.collect(&world.payer);
    assert_eq!(seq(), 4);
    assert_eq!(moved(events(&mut payer_events)), 1);
    assert_eq!(view().requested_relay.as_deref(), Some("10.0.0.7:443"));
    assert!(matches!(
        apply("relay4.test:443"),
        Err(lepic_wallet_contacts::ContactError::RelayMoveNotRequested)
    ));
    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact_mailbox(ben_side))
            .unwrap(),
        shown
    );
}

/// A collect forgets the hold counts of messages first held more than a day ago, and any it
/// cannot read, and keeps the rest.
#[test]
fn a_collect_forgets_hold_counts_a_day_old() {
    let world = World::new();
    world.pair_for_invoices(ContactKind::Exchange);
    let now =
        u64::try_from(lepic_wallet::ports::Clock::now(&world.payer.clock).as_second()).unwrap();
    let rows = [
        ("contact.held.01", format!("{now}:1")),
        ("contact.held.02", format!("{}:3", now - 2 * 24 * 60 * 60)),
        ("contact.held.03", "damaged".to_owned()),
    ];
    world.payer.write(|repos| {
        for (key, value) in &rows {
            repos.put_setting(key, value)?;
        }
        Ok(())
    });

    world.collect(&world.payer);

    let kept = world
        .payer
        .read(|repos| repos.settings_with_prefix("contact.held."));
    assert_eq!(
        kept,
        vec![("contact.held.01".to_owned(), format!("{now}:1"))]
    );
}

/// The party's keys for its contact `contact`, as the wallet derives them.
fn keys_for(party: &Party, contact: ContactId) -> lepic_wallet_contacts::ContactKeys {
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    lepic_wallet_contacts::contact_root(
        &party.keychain(),
        &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
        lepic_primitives::params::Network::Floonet,
    )
    .unwrap()
    .contact_keys(record.slot, record.box_salt)
    .unwrap()
}

/// Seals `content` from the party to its contact `contact`, signed, and posts it from the
/// party's mailbox for that contact to the contact's.
fn post_signed(world: &World, party: &Party, contact: ContactId, content: &Content) {
    let keys = keys_for(party, contact);
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let envelope = seal(
        ContactNetwork::Floonet,
        peer.enc_key(),
        peer.hint_rule(),
        content,
        Some(&signer),
        &mut rand::rngs::StdRng::seed_from_u64(21),
    )
    .unwrap();
    let mailbox = party.read(|repos| repos.contact_mailbox(contact)).unwrap();
    let from = Identity::new(
        keys.expose_box_secret().clone(),
        EpicboxAddress::parse(&mailbox.our_mailbox, RelayNetwork::Floonet).unwrap(),
    )
    .unwrap();
    let to = EpicboxAddress::parse(&mailbox.peer_mailbox, RelayNetwork::Floonet).unwrap();
    world
        .block_on(
            MailboxClient::new(world::settings(), world.relay.connector()).post(
                &from,
                &to,
                &armor(&envelope),
            ),
        )
        .unwrap();
}

/// R2-03: a paired contact names the issuer's payments address as its mailbox and sends a
/// signed `withdrawn` for an invoice the payer paid to that issuer over plain Epicbox. A notice
/// from a contact counts only for a slate exchanged with that contact, so nothing is cancelled.
#[test]
fn a_contact_notice_counts_only_for_slates_exchanged_with_that_contact() {
    let world = World::new();
    let issued = world.issue(None);
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    let mallory = world.stranger();
    let (on_mallory, on_payer) = world.pair(&mallory, &world.payer);
    // Mallory's card now names the issuer's payments address as her mailbox.
    let keys = keys_for(&mallory, on_mallory);
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = mallory.read(|repos| repos.contact(on_mallory)).unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let mut fields = own.fields().clone();
    fields.seq += 1;
    fields.mailbox = lepic_contact::MailboxAddress::new(&world.issuer.address.to_string()).unwrap();
    let card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(MessageType::ContactUpdate, card.as_bytes().to_vec()),
    );
    world.collect(&world.payer);
    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact_mailbox(on_payer))
            .unwrap()
            .peer_mailbox,
        world.issuer.address.to_string()
    );
    let mut payer_events = world.payer.wallet.subscribe();

    let notice = lepic_wallet::notice::Notice {
        slate_id: issued.slate_id,
        kind: lepic_wallet::notice::NoticeKind::Withdrawn,
    };
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Notice,
            notice.encode().as_text().unwrap().as_bytes().to_vec(),
        ),
    );
    world.collect(&world.payer);

    assert_eq!(world.tx_state(&world.payer, paid.tx_id), TxState::Sent);
    assert!(
        !events(&mut payer_events)
            .iter()
            .any(|event| matches!(event, Event::InvoiceWithdrawn(_)))
    );
}

/// R2-04: an invoice parked under a contact's trust is paid only while that trust holds, and
/// goes when the contact goes.
#[test]
fn a_parked_invoice_is_paid_only_while_its_contact_is_trusted() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let first = world.invoice_contact(shop_side, "first");
    world.collect(&world.payer);
    assert_eq!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .len(),
        1
    );

    // The contact is no longer verified, as after a new SAS check that did not match.
    let mut record = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    record.state = lepic_store::ContactState::Paired;
    world
        .payer
        .store()
        .write(|repos| repos.put_contact(&record))
        .unwrap();
    let transactions = world.payer.read(|repos| repos.transactions(ACCOUNT)).len();
    assert!(matches!(
        world.block_on(world.payer.wallet.contact_book().contact_pay_invoice(
            &relays(&world.payer),
            first.slate_id,
            pay_request(),
        )),
        Err(lepic_wallet_contacts::ContactError::NotVerified)
    ));
    assert_eq!(
        world.payer.read(|repos| repos.transactions(ACCOUNT)).len(),
        transactions
    );

    // Removing the contact deletes what it left parked.
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_remove(ben_side))
            .unwrap()
    );
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .is_empty()
    );
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoice(uuid::Uuid::from_bytes(*first.slate_id.as_bytes())))
            .is_none()
    );
}

/// Declining one invoice from a contact deletes it and tells the contact with a sealed
/// `declined`; an invoice that does not wait cannot be declined.
#[test]
fn one_contact_invoice_is_declined_and_the_contact_told() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    let declined = world.invoice_contact(shop_side, "declined");
    let kept = world.invoice_contact(shop_side, "kept");
    world.collect(&world.payer);
    let mut issuer_events = world.issuer.wallet.subscribe();

    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_decline_invoice(declined.slate_id),
        )
        .unwrap();
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_decline_invoice(declined.slate_id)
        ),
        Err(lepic_wallet_contacts::ContactError::Invoice(
            lepic_wallet::invoice::InvoiceError::NotParked { .. }
        ))
    ));
    let left: Vec<_> = world
        .block_on(world.payer.wallet.contact_book().contact_invoices())
        .unwrap()
        .into_iter()
        .map(|invoice| invoice.slate_id)
        .collect();
    assert_eq!(left, vec![kept.slate_id]);
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_outbox_deliver(&relays(&world.payer)),
        )
        .unwrap();
    world.collect(&world.issuer);
    let told: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InvoiceDeclined(declined) => Some(declined.tx_id),
            _ => None,
        })
        .collect();
    assert_eq!(told, vec![declined.tx_id]);
}

/// The payer sends an S1 for `AMOUNT` through its contact's mailbox.
fn send_through_mailbox(
    world: &World,
    relays: &ContactRelays,
    contact: ContactId,
) -> lepic_store::TxId {
    let sent = world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("s1.tx"),
                ),
            },
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.contact_book().contact_post_slate(
            relays,
            contact,
            sent.tx_id,
            Some(Purpose::Withdrawal),
        ))
        .unwrap();
    sent.tx_id
}

/// R2-06: a contact's S1s fall under the open receipt caps the inbox keeps per sender.
#[test]
fn payments_from_one_contact_stop_at_the_open_receipt_cap() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    for child in 1..=11 {
        world.payer.fund(child, world::FUNDING);
    }
    let mut issuer_events = world.issuer.wallet.subscribe();
    for _ in 0..11 {
        send_through_mailbox(&world, &relays(&world.payer), ben_side);
    }

    world.collect(&world.issuer);

    let received = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::WithdrawalFromContact(_)))
        .count();
    assert_eq!(
        received,
        lepic_wallet::WalletPolicy::DEFAULT.max_open_receipts_per_sender
    );
}

/// R2-06: an outbox entry whose transaction ended is deleted, never sent.
#[test]
fn the_outbox_forgets_entries_whose_transaction_ended() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let offline = ContactRelays {
        mode: RelayMode::Offline,
        ..relays(&world.payer)
    };
    let tx_id = send_through_mailbox(&world, &offline, ben_side);
    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact_outbox(ben_side))
            .len(),
        1
    );
    world.block_on(world.payer.wallet.cancel(tx_id)).unwrap();

    world.collect(&world.payer);

    assert!(
        world
            .payer
            .read(|repos| repos.contact_outbox(ben_side))
            .is_empty()
    );
    assert_eq!(world.collect(&world.issuer).messages, 0);
}

/// Only the contact calls act on a contact's invoice: the payments-address calls neither list,
/// pay nor decline it, and its payment is never delivered again outside the outbox.
#[test]
fn address_invoice_calls_never_act_on_a_contact_invoice() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    let unpaid = world.invoice_contact(shop_side, "unpaid");
    let to_pay = world.invoice_contact(shop_side, "paid");
    world.collect(&world.payer);
    let wallet = &world.payer.wallet;

    assert!(
        wallet
            .pending_invoices(lepic_wallet::epicbox_invoice::InvoiceExpiry::default())
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        world.block_on(wallet.pay_parked_invoice(unpaid.slate_id, pay_request())),
        Err(lepic_wallet::invoice::InvoiceError::NotParked { .. })
    ));
    assert!(matches!(
        world.block_on(wallet.decline_invoice(unpaid.slate_id)),
        Err(lepic_wallet::invoice::InvoiceError::NotParked { .. })
    ));
    assert_eq!(
        world
            .block_on(wallet.contact_book().contact_invoices())
            .unwrap()
            .len(),
        2
    );

    let paid = world.pay_contact(&to_pay);
    assert!(matches!(
        world.block_on(wallet.resend(
            paid.tx_id,
            Delivery::Deliver {
                transport: lepic_epicbox::TRANSPORT_ID,
                to: lepic_transport::transport::Destination::new(world.issuer.address.to_string()),
            },
        )),
        Err(lepic_wallet::send::SendError::NotResendable { .. })
    ));
}

/// R2-15: "Send again" refuses a payment that was cancelled meanwhile.
#[test]
fn send_again_refuses_a_cancelled_payment() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let issued = world.invoice_contact(shop_side, "paid");
    world.collect(&world.payer);
    let paid = world.pay_contact(&issued);
    let entry = world
        .payer
        .read(|repos| repos.contact_outbox(ben_side))
        .into_iter()
        .find(|stored| stored.entry.slate_id.as_bytes() == issued.slate_id.as_bytes())
        .unwrap();
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();

    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_outbox_resend(&relays(&world.payer), entry.id)
        ),
        Err(lepic_wallet_contacts::ContactError::UnknownTransaction)
    ));
}

/// The issuer hears that a contact paid its invoice, as for one paid over Epicbox.
#[test]
fn a_paid_contact_invoice_raises_invoice_finalized_on_the_issuer() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    let issued = world.invoice_contact(shop_side, "paid");
    world.collect(&world.payer);
    world.pay_contact(&issued);
    let mut issuer_events = world.issuer.wallet.subscribe();

    world.collect(&world.issuer);

    let finalized: Vec<_> = events(&mut issuer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InvoiceFinalized(finalized) => Some((finalized.tx_id, finalized.slate_id)),
            _ => None,
        })
        .collect();
    assert_eq!(finalized, vec![(issued.tx_id, issued.slate_id)]);
}

/// An explicit trigger delivers what the outbox holds at once, whatever its next try, and the
/// cycle reports what it delivered; the foreground tick keeps the retry waits.
#[test]
fn an_explicit_collect_delivers_the_outbox_at_once_and_reports_it() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let offline = ContactRelays {
        mode: RelayMode::Offline,
        ..relays(&world.payer)
    };
    send_through_mailbox(&world, &offline, ben_side);
    // A failed try puts the entry's next try in the future.
    let mut entry = world
        .payer
        .read(|repos| repos.contact_outbox(ben_side))
        .remove(0);
    entry.entry.attempts = 2;
    entry.entry.next_try_at = entry.entry.next_try_at.checked_add(10 * MINUTE).unwrap();
    world
        .payer
        .store()
        .write(|repos| repos.update_contact_outbox(entry.id, &entry.entry))
        .unwrap();

    let tick = world
        .block_on(world.payer.wallet.contact_book().contacts_collect(
            &relays(&world.payer),
            lepic_wallet_contacts::CollectTrigger::Foreground,
        ))
        .unwrap();
    assert_eq!(tick.delivered, 0);
    let push = world
        .block_on(world.payer.wallet.contact_book().contacts_collect(
            &relays(&world.payer),
            lepic_wallet_contacts::CollectTrigger::Push,
        ))
        .unwrap();
    assert_eq!(push.delivered, 0);
    assert_eq!(world.collect(&world.payer).delivered, 1);
}

/// M5: slates exchanged through a contact's mailbox are recorded as over Epicbox on both sides;
/// one sealed to a file stays a file.
#[test]
fn mailbox_slates_are_recorded_as_epicbox_and_sealed_files_as_files() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let issued = world.invoice_contact(shop_side, "paid");
    world.collect(&world.payer);
    let paid = world.pay_contact(&issued);
    let transport = |party: &Party, tx_id| {
        party
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .transport
    };
    let epicbox = Some(lepic_epicbox::TRANSPORT_ID.as_str().to_owned());
    assert_eq!(transport(&world.issuer, issued.tx_id), epicbox);
    assert_eq!(transport(&world.payer, paid.tx_id), epicbox);

    world.payer.fund(1, world::FUNDING);
    let sent = world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("s1.tx"),
                ),
            },
        ))
        .unwrap();
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_seal_slate(ben_side, sent.tx_id, None),
        )
        .unwrap();
    assert_eq!(
        transport(&world.payer, sent.tx_id),
        Some(lepic_transport::file::FILE.as_str().to_owned())
    );
}

/// R3-01, the reviewer's proof of concept: a paired contact sends an S1 under the slate id of a
/// payment the payer made to someone else, then a signed `withdrawn` for it. The S1 is refused,
/// the slate id stays with nobody, and the payment is not cancelled.
#[test]
fn a_contact_cannot_take_over_another_payment_by_its_slate_id() {
    let world = World::new();
    let issued = world.issue(None);
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    let mallory = world.stranger();
    mallory.fund(1, world::FUNDING);
    let (on_mallory, _) = world.pair(&mallory, &world.payer);

    // Mallory builds an S1 and gives it the slate id of the payer's payment to the issuer.
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    world
        .block_on(mallory.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(file.clone()),
            },
        ))
        .unwrap();
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let target = uuid::Uuid::from_bytes(*issued.slate_id.as_bytes());
    json["id"] = serde_json::Value::String(target.hyphenated().to_string());
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Slate,
            serde_json::to_string(&json).unwrap().into_bytes(),
        ),
    );
    world.collect(&world.payer);
    assert!(
        world
            .payer
            .read(|repos| repos.transaction_by_slate(target, lepic_store::TxDirection::Incoming))
            .is_none()
    );

    let notice = lepic_wallet::notice::Notice {
        slate_id: issued.slate_id,
        kind: lepic_wallet::notice::NoticeKind::Withdrawn,
    };
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Notice,
            notice.encode().as_text().unwrap().as_bytes().to_vec(),
        ),
    );
    world.collect(&world.payer);

    assert_eq!(world.tx_state(&world.payer, paid.tx_id), TxState::Sent);
    assert_eq!(
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .contact_of_transaction(paid.tx_id)
            )
            .unwrap(),
        None
    );
}

/// The payer sees the issuer's message on a contact invoice only when its signature verifies,
/// made safe to display.
#[test]
fn a_contact_invoice_carries_the_issuers_message_only_when_it_verifies() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut payer_events = world.payer.wallet.subscribe();
    let signed = world
        .block_on(world.issuer.wallet.contact_book().contact_issue_invoice(
            &relays(&world.issuer),
            shop_side,
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: Some("deposit\u{202E} 17".to_owned()),
                ttl_blocks: None,
            },
            InvoiceDetails {
                purpose: Purpose::DepositRequest,
                reference: None,
                expires: None,
            },
        ))
        .unwrap();

    // An I1 whose message text changed after it was signed, sealed by the contact itself.
    let file = tempfile::tempdir().unwrap().keep().join("i1.tx");
    let unsigned = world
        .block_on(world.issuer.wallet.issue_invoice(
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: Some("refund 9".to_owned()),
                ttl_blocks: None,
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(file.clone()),
            },
        ))
        .unwrap();
    let tampered = std::fs::read_to_string(&file)
        .unwrap()
        .replace("refund 9", "refund 8");
    post_signed(
        &world,
        &world.issuer,
        shop_side,
        &Content {
            purpose: Some(Purpose::Request),
            // As the contact's own wallet seals it, once it sent one with its send time.
            sent_at: u64::try_from(
                lepic_wallet::ports::Clock::now(&world.issuer.clock).as_second(),
            )
            .ok(),
            ..Content::new(MessageType::Slate, tampered.into_bytes())
        },
    );
    world.collect(&world.payer);

    let parked = world
        .block_on(world.payer.wallet.contact_book().contact_invoices())
        .unwrap();
    assert_eq!(parked.len(), 2);
    let message_of = |slate_id| {
        parked
            .iter()
            .find(|invoice| invoice.slate_id == slate_id)
            .unwrap()
            .message
            .clone()
    };
    assert_eq!(message_of(signed.slate_id).as_deref(), Some("deposit 17"));
    assert_eq!(message_of(unsigned.slate_id), None);
    assert!(parked.iter().all(|invoice| invoice.contact_id == ben_side));
    let announced: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::InvoiceFromContact(invoice) => Some((invoice.slate_id, invoice.message)),
            _ => None,
        })
        .collect();
    assert!(announced.contains(&(signed.slate_id, Some("deposit 17".to_owned()))));
    assert!(announced.contains(&(unsigned.slate_id, None)));
}

/// A contact quiet for more than a day is left out of the foreground tick when contacts sit on
/// more than three relays, but not while a payment sent through its mailbox waits for its
/// answer (RFC 0002 8.4).
#[test]
fn a_contact_waiting_on_a_mailbox_payment_is_collected_on_the_foreground_tick() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let stranger = world.stranger();
    let (_, on_payer) = world.pair(&stranger, &world.payer);
    // Four relays between the two contacts: each has a home and a previous one.
    let until = lepic_wallet::ports::Clock::now(&world.payer.clock)
        .checked_add(30 * 24 * HOUR)
        .unwrap();
    for (contact, home, previous) in [
        (ben_side, None, "relay2.test:80"),
        (on_payer, Some("relay3.test:80"), "relay4.test:80"),
    ] {
        let mut mailbox = world
            .payer
            .read(|repos| repos.contact_mailbox(contact))
            .unwrap();
        if let Some(home) = home {
            mailbox.home_relay = home.to_owned();
        }
        mailbox.previous = Some(lepic_store::PreviousHome {
            relay: previous.to_owned(),
            peer_mailbox: mailbox.peer_mailbox.clone(),
            our_mailbox: mailbox.our_mailbox.clone(),
            until,
        });
        world
            .payer
            .store()
            .write(|repos| repos.put_contact_mailbox(&mailbox))
            .unwrap();
    }
    world.payer.clock.advance(Duration::from_secs(25 * 60 * 60));
    let tick = || {
        world
            .block_on(world.payer.wallet.contact_book().contacts_collect(
                &relays(&world.payer),
                lepic_wallet_contacts::CollectTrigger::Foreground,
            ))
            .unwrap()
    };
    // Both previous homes are still drained, so they are read even while quiet.
    assert_eq!(tick().mailboxes, 2);

    send_through_mailbox(&world, &relays(&world.payer), ben_side);
    // Ben's current mailbox joins; the quiet stranger's current one stays out.
    assert_eq!(tick().mailboxes, 3);
}

/// The S2 of a payment sent through a contact's mailbox finalizes it with an event naming that
/// contact; the same S2 sealed by another contact finishes nothing.
#[test]
fn an_answer_counts_only_from_the_contact_the_payment_went_to() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let stranger = world.stranger();
    let (on_stranger, _) = world.pair(&stranger, &world.payer);
    let mut payer_events = world.payer.wallet.subscribe();
    let tx_id = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let slate_id = world
        .payer
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .slate_id
        .unwrap();
    world.collect(&world.issuer);
    let s2 = world
        .issuer
        .read(|repos| repos.slate(slate_id, SlateStage::Standard2))
        .unwrap();
    post_signed(
        &world,
        &stranger,
        on_stranger,
        &Content::new(MessageType::Slate, s2.bytes),
    );

    world.collect(&world.payer);
    assert_eq!(world.tx_state(&world.payer, tx_id), TxState::Posted);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let finalized: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::ContactPaymentFinalized(slate) => Some((slate.contact_id, slate.tx_id)),
            _ => None,
        })
        .collect();
    assert_eq!(finalized, vec![(ben_side, tx_id)]);
}

/// A contact's answer that finalizes the payment while the node refuses the push is kept and
/// retried: the host hears of it at once, and the next collect posts it.
#[test]
fn an_answer_finalized_but_not_posted_is_reported_and_posted_on_the_next_collect() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut payer_events = world.payer.wallet.subscribe();
    let tx_id = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    world.collect(&world.issuer);
    world.node.fail_next(
        "push_transaction",
        lepic_node::mock::MockFailure::Rejected(lepic_node::RejectionKind::Internal),
    );
    world.collect(&world.payer);
    let finalized_events = |events: Vec<Event>| {
        events
            .into_iter()
            .filter(|event| matches!(event, Event::ContactPaymentFinalized(_)))
            .count()
    };
    assert_eq!(world.tx_state(&world.payer, tx_id), TxState::Finalized);
    assert!(finalized_events(events(&mut payer_events)) >= 1);
    assert!(world.node.pushed_transactions().is_empty());

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.tx_state(&world.payer, tx_id), TxState::Finalized);
}

/// A contact's message sealed long ago, or ahead of our clock, is not taken when a relay hands
/// it over; once a contact sent its send time, a message without one is not taken either.
#[test]
fn a_contact_message_sealed_long_ago_or_without_its_send_time_is_not_taken() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let unsigned_invoice = |message: &str| {
        let file = tempfile::tempdir().unwrap().keep().join("i1.tx");
        world
            .block_on(world.issuer.wallet.issue_invoice(
                InvoiceRequest {
                    account: ACCOUNT,
                    amount: Amount::new(AMOUNT),
                    message: Some(message.to_owned()),
                    ttl_blocks: None,
                },
                Delivery::Export {
                    transport: lepic_transport::file::FILE,
                    to: lepic_transport::transport::Location::File(file.clone()),
                },
            ))
            .unwrap();
        std::fs::read_to_string(&file).unwrap().into_bytes()
    };
    let now =
        u64::try_from(lepic_wallet::ports::Clock::now(&world.payer.clock).as_second()).unwrap();
    let parked = || {
        world
            .block_on(world.payer.wallet.contact_book().contact_invoices())
            .unwrap()
            .len()
    };
    let post = |sent_at: Option<u64>, message: &str| {
        post_signed(
            &world,
            &world.issuer,
            shop_side,
            &Content {
                purpose: Some(Purpose::Request),
                sent_at,
                ..Content::new(MessageType::Slate, unsigned_invoice(message))
            },
        );
        world.collect(&world.payer);
    };

    post(Some(now - 31 * 24 * 3600), "old");
    post(Some(now + 2 * 24 * 3600), "ahead");
    assert_eq!(parked(), 0);
    // A contact that never sent a send time is still heard, as an older wallet is.
    post(None, "older wallet");
    assert_eq!(parked(), 1);
    post(Some(now - 3600), "recent");
    assert_eq!(parked(), 2);
    post(None, "unstamped after a stamped one");
    assert_eq!(parked(), 2);
    let invoices = world
        .block_on(world.payer.wallet.contact_book().contact_invoices())
        .unwrap();
    assert!(
        invoices
            .iter()
            .all(|invoice| invoice.contact_id == ben_side)
    );
}

fn payment_cancelled(events: Vec<Event>) -> Vec<lepic_wallet::event::CancelledPayment> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::PaymentCancelled(cancelled) => Some(cancelled),
            _ => None,
        })
        .collect()
}

/// The sender of a payment through a contact's mailbox cancels it while the contact's answer
/// waits in its own mailbox: the answer it collects later is answered with a `cancelled`
/// through the pairing, and the receiver records it, raises the event, reports it in the
/// details and releases the payment with its own cancel.
#[test]
fn a_mailbox_payment_cancelled_before_its_answer_is_collected_tells_the_contact() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut receiver_events = world.issuer.wallet.subscribe();
    let sent = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let slate_id = world
        .payer
        .read(|repos| repos.transaction(sent))
        .unwrap()
        .slate_id
        .unwrap();
    // The receiver answers; the sender is not listening, so the S2 waits in its mailbox.
    world.collect(&world.issuer);
    let received = world
        .issuer
        .read(|repos| repos.transaction_by_slate(slate_id, lepic_store::TxDirection::Incoming))
        .unwrap();
    assert_eq!(received.entry.state, TxState::Received);

    world.block_on(world.payer.wallet.cancel(sent)).unwrap();
    assert_eq!(world.tx_state(&world.payer, sent), TxState::Cancelled);
    // The sender comes back: its late answer is not posted, and the contact is told.
    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(world.tx_state(&world.payer, sent), TxState::Cancelled);
    assert!(world.node.pushed_transactions().is_empty());
    assert!(
        world
            .payer
            .read(|repos| repos.tx_marks(sent))
            .cancelled_answered
    );
    let reported_at = lepic_wallet::ports::Clock::now(&world.issuer.clock);
    world.collect(&world.issuer);

    let cancelled = payment_cancelled(events(&mut receiver_events));
    assert_eq!(cancelled.len(), 1, "{cancelled:?}");
    assert_eq!(cancelled[0].tx_id, received.id);
    assert_eq!(*cancelled[0].slate_id.as_bytes(), slate_id.into_bytes());
    let marks = world.issuer.read(|repos| repos.tx_marks(received.id));
    assert_eq!(marks.sender_cancelled_at, Some(reported_at));
    let details = world
        .block_on(world.issuer.wallet.transaction_details(received.id))
        .unwrap();
    assert_eq!(details.sender_reported_cancelled_at, Some(reported_at));
    assert_eq!(
        world.tx_state(&world.issuer, received.id),
        TxState::Received
    );

    // The host releases the payment with its normal cancel; another collect tells nothing more.
    world
        .block_on(world.issuer.wallet.cancel(received.id))
        .unwrap();
    assert_eq!(
        world.tx_state(&world.issuer, received.id),
        TxState::Cancelled
    );
    world.collect(&world.payer);
    world.collect(&world.issuer);
    assert!(payment_cancelled(events(&mut receiver_events)).is_empty());
}

/// A signed `cancelled` for a payment received through one contact's mailbox, sent by another
/// paired contact, changes nothing.
#[test]
fn a_cancelled_notice_from_another_contact_is_ignored() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mallory = world.stranger();
    let (on_mallory, _) = world.pair(&mallory, &world.issuer);
    let mut receiver_events = world.issuer.wallet.subscribe();
    let sent = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let slate_id = world
        .payer
        .read(|repos| repos.transaction(sent))
        .unwrap()
        .slate_id
        .unwrap();
    world.collect(&world.issuer);
    let received = world
        .issuer
        .read(|repos| repos.transaction_by_slate(slate_id, lepic_store::TxDirection::Incoming))
        .unwrap();

    let notice = lepic_wallet::notice::Notice {
        slate_id: lepic_slate::model::SlateId::from_bytes(slate_id.into_bytes()),
        kind: lepic_wallet::notice::NoticeKind::Cancelled,
    };
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Notice,
            notice.encode().as_text().unwrap().as_bytes().to_vec(),
        ),
    );
    assert_eq!(world.collect(&world.issuer).messages, 1);

    assert!(payment_cancelled(events(&mut receiver_events)).is_empty());
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.tx_marks(received.id))
            .sender_cancelled_at,
        None
    );
    assert_eq!(
        world
            .block_on(world.issuer.wallet.transaction_details(received.id))
            .unwrap()
            .sender_reported_cancelled_at,
        None
    );
    assert_eq!(
        world.tx_state(&world.issuer, received.id),
        TxState::Received
    );
}
