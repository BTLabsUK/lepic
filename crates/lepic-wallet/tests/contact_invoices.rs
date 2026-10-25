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
use lepic_wallet::contact::{ContactRelays, InviteRequest, InvoiceDetails, RelayMode, SasDecision};
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, Party, World, pay_request};

impl World {
    /// The issuer, as a service of `kind`, and the payer pair; the payer verifies the SAS and
    /// allows the issuer's invoices. Returns the issuer's and the payer's contact ids.
    fn pair_for_invoices(&self, kind: ContactKind) -> (ContactId, ContactId) {
        let link = self
            .block_on(self.issuer.wallet.pairing_invite(
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
                    .pairing_accept(&relays(&self.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert_eq!(self.collect(&self.issuer).paired, 1);
        assert_eq!(self.collect(&self.payer).paired, 1);
        let shop_side = self.only_contact(&self.issuer);
        let ben_side = answered.contact_id;
        self.block_on(self.payer.wallet.pairing_sas(
            &relays(&self.payer),
            ben_side,
            SasDecision::Match,
        ))
        .unwrap();
        self.block_on(self.payer.wallet.contact_set_allow_invoices(ben_side, true))
            .unwrap();
        (shop_side, ben_side)
    }

    fn invoice_contact(&self, shop_side: ContactId, reference: &str) -> IssuedInvoice {
        self.block_on(self.issuer.wallet.contact_issue_invoice(
            &relays(&self.issuer),
            shop_side,
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
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
        self.block_on(self.payer.wallet.contact_pay_invoice(
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
        .block_on(world.payer.wallet.contact_invoices())
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
        .block_on(world.payer.wallet.contact_outbox(ben_side))
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
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.collect(&world.issuer);
    world.collect(&world.payer);
    let shop_side = world.only_contact(&world.issuer);

    // Paired but not verified, and invoices not allowed.
    world.invoice_contact(shop_side, "one");
    world.collect(&world.payer);
    assert!(
        world
            .block_on(world.payer.wallet.contact_invoices())
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
            .block_on(world.payer.wallet.contact_invoices())
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
            .block_on(world.payer.wallet.contact_invoices())
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
                .contact_set_allow_invoices(ben_side, false),
        )
        .unwrap();
    world
        .block_on(
            world
                .payer
                .wallet
                .contacts_outbox_deliver(&relays(&world.payer)),
        )
        .unwrap();

    assert!(
        world
            .block_on(world.payer.wallet.contact_invoices())
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
            .block_on(world.payer.wallet.contact_invoices())
            .unwrap()
            .is_empty()
    );
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
            .block_on(world.payer.wallet.contact_invoices())
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
            .block_on(world.payer.wallet.contact_outbox(ben_side))
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
        built_in: vec![world.payer.epicbox.settings().endpoint.clone()],
        mode: RelayMode::Online,
    };
    let report = world
        .block_on(world.payer.wallet.contacts_outbox_deliver(&elsewhere))
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
        .block_on(world.payer.wallet.contact_invoices())
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
        .block_on(world.payer.wallet.contact_post_slate(
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

#[test]
fn a_service_moving_its_home_relay_moves_our_mailbox_and_keeps_the_old_one_a_week() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    // The shop's update: its card for this pairing with its mailbox on a new relay.
    let record = world.issuer.read(|repos| repos.contact(shop_side)).unwrap();
    let keys = world
        .issuer
        .keychain()
        .contact_root(
            &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
            lepic_primitives::params::Network::Floonet,
        )
        .unwrap()
        .contact_keys(record.slot, record.box_salt)
        .unwrap();
    let own = ContactCard::decode(&record.own_card, ContactNetwork::Floonet).unwrap();
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let key_text = own.fields().mailbox.as_str().split('@').next().unwrap();
    let mut fields = own.fields().clone();
    fields.seq = 2;
    fields.mailbox =
        lepic_contact::MailboxAddress::new(&format!("{key_text}@relay2.test:80")).unwrap();
    let card = ContactCard::sign(ContactNetwork::Floonet, fields, &signer).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let envelope = lepic_contact::seal_contact_update(
        &peer,
        &card,
        &signer,
        &mut rand::rngs::StdRng::seed_from_u64(9),
    )
    .unwrap();
    let from = Identity::new(
        keys.expose_box_secret().clone(),
        EpicboxAddress::new(
            *keys.box_public_key(),
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        ),
    )
    .unwrap();
    let to = EpicboxAddress::parse(peer.fields().mailbox.as_str(), RelayNetwork::Floonet).unwrap();
    world
        .block_on(
            MailboxClient::new(world::settings(), world.relay.connector()).post(
                &from,
                &to,
                &armor(&envelope),
            ),
        )
        .unwrap();
    let built_in = ContactRelays {
        built_in: vec![lepic_epicbox::RelayEndpoint::new(
            Domain::parse("relay2.test").unwrap(),
            Some(80),
            lepic_epicbox::Security::Plain,
        )],
        ..relays(&world.payer)
    };

    world
        .block_on(
            world
                .payer
                .wallet
                .contacts_collect(&built_in, lepic_wallet::contact::CollectTrigger::Open),
        )
        .unwrap();

    let mailbox = world
        .payer
        .read(|repos| repos.contact_mailbox(ben_side))
        .unwrap();
    assert_eq!(mailbox.home_relay, "relay2.test:80");
    assert!(mailbox.peer_mailbox.ends_with("@relay2.test:80"));
    assert!(mailbox.our_mailbox.ends_with("@relay2.test:80"));
    let previous = mailbox.previous.unwrap();
    assert_eq!(previous.relay, "relay.test:80");
    // Our new card went to the shop at once, in a contact update.
    let outbox = world.payer.read(|repos| repos.contact_outbox(ben_side));
    assert!(
        outbox
            .iter()
            .any(|stored| stored.entry.destination.ends_with("@relay2.test:80")),
        "{outbox:?}"
    );
    // Both mailboxes are collected while the old one is kept.
    let report = world
        .block_on(
            world
                .payer
                .wallet
                .contacts_collect(&built_in, lepic_wallet::contact::CollectTrigger::Open),
        )
        .unwrap();
    assert_eq!(report.mailboxes, 2);
    world.payer.clock.advance(7 * 24 * HOUR + MINUTE);
    let report = world
        .block_on(
            world
                .payer
                .wallet
                .contacts_collect(&built_in, lepic_wallet::contact::CollectTrigger::Open),
        )
        .unwrap();
    assert_eq!(report.mailboxes, 1);
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

/// R2-05: a service's update may not move its home relay to an IP address or another port
/// unless the relay is built in, nor change what the contact is; a card in any envelope but an
/// update never names another mailbox.
#[test]
fn a_home_relay_moves_only_to_a_named_relay_and_never_by_a_plain_card() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
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
    for (seq, host, kind) in [
        (2, "10.0.0.7:443", ContactKind::Exchange),
        (3, "relay3.test:8443", ContactKind::Exchange),
        (4, "relay.test:80", ContactKind::Person),
    ] {
        post_signed(
            &world,
            &world.issuer,
            shop_side,
            &Content::new(
                MessageType::ContactUpdate,
                card(seq, host, kind).as_bytes().to_vec(),
            ),
        );
    }
    // A notice carrying a newer card for another relay in its tag 07.
    let mut notice = Content::new(MessageType::Notice, b"{}".to_vec());
    notice.card = Some(card(5, "relay4.test:443", ContactKind::Exchange));
    post_signed(&world, &world.issuer, shop_side, &notice);
    world.collect(&world.payer);

    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact_mailbox(ben_side))
            .unwrap(),
        shown
    );
    assert_eq!(
        world
            .payer
            .read(|repos| repos.contact(ben_side))
            .unwrap()
            .peer
            .unwrap()
            .seq,
        1
    );
}

/// The party's keys for its contact `contact`, as the wallet derives them.
fn keys_for(party: &Party, contact: ContactId) -> lepic_keychain::ContactKeys {
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    party
        .keychain()
        .contact_root(
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
            .block_on(world.payer.wallet.contact_invoices())
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
        world.block_on(world.payer.wallet.contact_pay_invoice(
            &relays(&world.payer),
            first.slate_id,
            pay_request(),
        )),
        Err(lepic_wallet::contact::ContactError::NotVerified)
    ));
    assert_eq!(
        world.payer.read(|repos| repos.transactions(ACCOUNT)).len(),
        transactions
    );

    // Removing the contact deletes what it left parked.
    assert!(
        world
            .block_on(world.payer.wallet.contact_remove(ben_side))
            .unwrap()
    );
    assert!(
        world
            .block_on(world.payer.wallet.contact_invoices())
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
                .contact_decline_invoice(declined.slate_id),
        )
        .unwrap();
    assert!(matches!(
        world.block_on(
            world
                .payer
                .wallet
                .contact_decline_invoice(declined.slate_id)
        ),
        Err(lepic_wallet::contact::ContactError::Invoice(
            lepic_wallet::invoice::InvoiceError::NotParked { .. }
        ))
    ));
    let left: Vec<_> = world
        .block_on(world.payer.wallet.contact_invoices())
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
        .block_on(world.payer.wallet.contact_post_slate(
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
    assert_eq!(received, lepic_wallet::inbox::MAX_OPEN_RECEIPTS_PER_SENDER);
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
    assert_eq!(world.block_on(wallet.contact_invoices()).unwrap().len(), 2);

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
                .contact_outbox_resend(&relays(&world.payer), entry.id)
        ),
        Err(lepic_wallet::contact::ContactError::UnknownTransaction)
    ));
}
