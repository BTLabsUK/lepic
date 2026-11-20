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

#[path = "contact_invoices/early_notices.rs"]
mod early_notices;
use crate::pairing_helpers as helpers;
#[path = "contact_invoices/notice_table.rs"]
mod notice_table;
#[path = "contact_invoices/quarantine.rs"]
mod quarantine;
use crate::epicbox_world as world;

use std::time::Duration;

use helpers::{HOUR, MINUTE, accept, events, invite_request, relays};
use lepic_contact::{
    Capabilities, ContactCard, ContactKind, Content, MessageType, Network as ContactNetwork,
    Purpose, SigningKey, armor, seal,
};
use lepic_epicbox::{Domain, EpicboxAddress, Identity, MailboxClient, Network as RelayNetwork};
use lepic_primitives::amount::Amount;
use lepic_store::{ContactId, ContactOutboxState, MailClass, SlateStage, TxState, WalletStore};
use lepic_wallet::Event;
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet_contacts::{
    ContactError, ContactRelays, InviteRequest, InvoiceDetails, RelayMode, SasDecision,
    WalletContacts,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, Party, World, pay_request};

impl World {
    /// The issuer, as a service of `kind`, and the payer pair; both verify the SAS and the payer
    /// allows the issuer's invoices. Returns the issuer's and the payer's contact ids.
    fn pair_for_invoices(&self, kind: ContactKind) -> (ContactId, ContactId) {
        let (shop_side, ben_side) = self.pair_unverified(kind);
        self.issuer_verifies(shop_side);
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

    /// The issuer, as a service of `kind`, and the payer pair; neither verifies. Returns the
    /// issuer's and the payer's contact ids.
    fn pair_unverified(&self, kind: ContactKind) -> (ContactId, ContactId) {
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
        (shop_side, answered.contact_id)
    }

    /// The issuer confirms the SAS of the payer, and the payer takes its verdict.
    fn issuer_verifies(&self, shop_side: ContactId) {
        self.block_on(self.issuer.wallet.contact_book().pairing_sas(
            &relays(&self.issuer),
            shop_side,
            SasDecision::Match,
        ))
        .unwrap();
        self.collect(&self.payer);
    }

    fn invoice_contact(&self, shop_side: ContactId, reference: &str) -> IssuedInvoice {
        self.try_invoice_contact(shop_side, reference).unwrap()
    }

    fn try_invoice_contact(
        &self,
        shop_side: ContactId,
        reference: &str,
    ) -> Result<IssuedInvoice, ContactError> {
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
            None,
        ))
    }

    fn pay_contact(&self, issued: &IssuedInvoice) -> lepic_wallet::invoice::PaidInvoice {
        self.block_on(self.payer.wallet.contact_book().contact_pay_invoice(
            &relays(&self.payer),
            issued.slate_id,
            pay_request(),
        ))
        .unwrap()
        .0
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

    // Verified by the issuer only: the payer has not verified it or allowed its invoices.
    world.issuer_verifies(shop_side);
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
    let issued = issue_by_file(&world);
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
fn an_invoice_to_a_paired_unverified_contact_is_refused() {
    let world = World::new();
    let (shop_side, _) = world.pair_unverified(ContactKind::Exchange);

    assert!(matches!(
        world.try_invoice_contact(shop_side, "unverified"),
        Err(ContactError::NotVerified)
    ));
    assert!(
        world
            .issuer
            .read(|repos| repos.transactions(ACCOUNT))
            .is_empty()
    );
    assert!(helpers::contact_rows(&world.issuer, shop_side).is_empty());
}

/// The notice rows `party` queued for `contact` about the invoice `slate_id`: its `declined`.
fn declined_rows(
    party: &Party,
    contact: ContactId,
    slate_id: lepic_slate::model::SlateId,
) -> usize {
    let payment_id = uuid::Uuid::from_bytes(*slate_id.as_bytes());
    helpers::mail_rows(party, contact)
        .into_iter()
        .filter(|row| row.entry.notice && row.entry.payment_id == payment_id)
        .count()
}

#[test]
fn an_invoice_from_an_unverified_contact_is_refused_and_the_issuer_is_told() {
    for allowed_but_switched_off in [false, true] {
        let world = World::new();
        let (shop_side, ben_side) = if allowed_but_switched_off {
            let sides = world.pair_for_invoices(ContactKind::Exchange);
            world
                .block_on(
                    world
                        .payer
                        .wallet
                        .contact_book()
                        .contact_set_allow_invoices(sides.1, false),
                )
                .unwrap();
            sides
        } else {
            let sides = world.pair_unverified(ContactKind::Exchange);
            world.issuer_verifies(sides.0);
            sides
        };
        let mut issuer_events = world.issuer.wallet.subscribe();

        let issued = world.invoice_contact(shop_side, "refused");
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
        assert!(
            world
                .payer
                .read(|repos| repos.transactions(ACCOUNT))
                .is_empty()
        );
        let declined = declined_rows(&world.payer, ben_side, issued.slate_id);
        assert_eq!(declined, 1, "switched off: {allowed_but_switched_off}");

        world.collect(&world.issuer);
        let told: Vec<_> = events(&mut issuer_events)
            .into_iter()
            .filter_map(|event| match event {
                Event::InvoiceDeclined(declined) => Some(declined.tx_id),
                _ => None,
            })
            .collect();
        assert_eq!(
            told,
            vec![issued.tx_id],
            "switched off: {allowed_but_switched_off}"
        );
        // A declined invoice stays open on the issuer until it expires or is cancelled.
        assert_eq!(
            world.tx_state(&world.issuer, issued.tx_id),
            TxState::Received
        );
    }
}

#[test]
fn a_second_copy_of_a_refused_invoice_queues_no_second_declined() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_unverified(ContactKind::Exchange);
    world.issuer_verifies(shop_side);
    let mut issuer_events = world.issuer.wallet.subscribe();

    let issued = world.invoice_contact(shop_side, "twice");
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
    // The same I1 sealed again with a send time, so both copies are opened in one collect.
    let now =
        u64::try_from(lepic_wallet::ports::Clock::now(&world.issuer.clock).as_second()).unwrap();
    post_signed(
        &world,
        &world.issuer,
        shop_side,
        &Content {
            sent_at: Some(now),
            ..Content::new(MessageType::Slate, i1)
        },
    );
    world.collect(&world.payer);

    assert_eq!(declined_rows(&world.payer, ben_side, issued.slate_id), 1);
    world.collect(&world.issuer);
    let told = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::InvoiceDeclined(_)))
        .count();
    assert_eq!(told, 1);
}

/// A contact whose keys changed is sent nothing until the user decides, a `declined` included.
#[test]
fn an_invoice_from_a_contact_whose_keys_changed_is_dropped_without_a_declined() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut record = world.payer.read(|repos| repos.contact(ben_side)).unwrap();
    record.state = lepic_store::ContactState::KeysChanged;
    world
        .payer
        .store()
        .write(|repos| repos.put_contact(&record))
        .unwrap();

    let issued = world.invoice_contact(shop_side, "keys changed");
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
    assert_eq!(declined_rows(&world.payer, ben_side, issued.slate_id), 0);
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
fn a_signed_withdrawn_for_a_paid_invoice_is_told_and_leaves_the_payment() {
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
    // No notice changes a payment (ADR 0067): its host decides whether to cancel it.
    assert_eq!(world.tx_state(&world.payer, paid.tx_id), TxState::Sent);
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
    let elsewhere = helpers::adding(
        ContactRelays::new(
            lepic_methods::epicbox::Epicbox::new(
                settings,
                RelayNetwork::Floonet,
                world.relay.connector(),
            ),
            RelayMode::Online,
        ),
        vec![world.payer.epicbox.settings().endpoint.clone()],
    );
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
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
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

/// A wallet that refuses payments nobody asked for (ADR 0045) receives nothing from a contact's
/// S1 and answers with a sealed `declined`. The send never happened: the sender erases it, frees
/// its inputs, raises one event and tells no one.
#[test]
fn a_payment_through_the_mailbox_to_a_wallet_that_refuses_them_is_declined() {
    let world = World::with_issuer_policy(lepic_wallet::WalletPolicy {
        refuse_unsolicited_payments: true,
        ..lepic_wallet::WalletPolicy::default()
    });
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let mut payer_events = world.payer.wallet.subscribe();
    let tx_id = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let slate_id = world
        .payer
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .slate_id
        .unwrap();
    assert_ne!(
        world.payer.wallet.balance(ACCOUNT).unwrap().locked,
        Amount::ZERO
    );

    world.collect(&world.issuer);
    world.collect(&world.payer);

    assert!(
        world
            .issuer
            .read(|repos| repos.transaction_by_slate(slate_id, lepic_store::TxDirection::Incoming))
            .is_none()
    );
    let declined: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::PaymentDeclined(_)))
        .collect();
    assert_eq!(declined.len(), 1);
    assert_send_erased(&world.payer, tx_id);
    assert_eq!(
        declined_rows(
            &world.payer,
            ben_side,
            lepic_slate::model::SlateId::from_bytes(slate_id.into_bytes())
        ),
        0,
        "no notice goes back"
    );
    assert!(
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .send_declined_at(lepic_slate::model::SlateId::from_bytes(
                        slate_id.into_bytes()
                    ))
            )
            .unwrap()
            .is_some()
    );
    assert!(world.node.pushed_transactions().is_empty());
}

/// An answer that comes after its receiver declined the send finds nothing to finish: the
/// send stays erased, its inputs free, and nothing is posted.
#[test]
fn an_answer_to_a_send_its_receiver_declined_is_not_finalized() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let tx_id = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let slate_id = world
        .payer
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .slate_id
        .unwrap();
    let slate_id = lepic_slate::model::SlateId::from_bytes(slate_id.into_bytes());
    // The receiver answers; its decline reaches the sender first.
    world.collect(&world.issuer);
    assert!(
        world
            .issuer
            .read(|repos| repos.transaction_by_slate(
                uuid::Uuid::from_bytes(*slate_id.as_bytes()),
                lepic_store::TxDirection::Incoming
            ))
            .is_some()
    );
    let taken = world
        .block_on(world.payer.wallet.take_notice(
            lepic_wallet::notice::Notice::Declined {
                slate_id,
                reason: None,
            },
            lepic_wallet::NoticeFrom::Pairing(ben_side),
        ))
        .unwrap();
    assert_eq!(taken, lepic_wallet::Taken::Raised);
    assert_send_erased(&world.payer, tx_id);

    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_send_erased(&world.payer, tx_id);
    assert!(world.node.pushed_transactions().is_empty());
    assert_eq!(declined_rows(&world.payer, ben_side, slate_id), 0);
}

/// `party` holds nothing of the send `tx_id`: no entry, no output that names it, and no coins
/// locked or awaiting finalization.
fn assert_send_erased(party: &Party, tx_id: lepic_store::TxId) {
    assert!(party.read(|repos| repos.transaction(tx_id)).is_none());
    assert!(
        party
            .read(|repos| repos.outputs_of_transaction(tx_id))
            .is_empty()
    );
    let balance = party.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(balance.locked, Amount::ZERO);
    assert_eq!(balance.awaiting_finalization, Amount::ZERO);
}

/// A service and a person ask for a move the same way: the update is stored and reported, and
/// our mailbox stays until the host applies the move. The old relay stays in our list, so our
/// old mailbox is read as any mailbox there, during the drain and after it.
#[test]
fn a_service_moving_its_home_relay_moves_our_mailbox_once_applied() {
    a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(ContactKind::Exchange, true);
}

#[test]
fn a_person_moving_its_home_relay_moves_our_mailbox_once_applied() {
    a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(ContactKind::Person, true);
}

/// A move to a relay of our list from one outside it: our old mailbox is read only until its
/// drain ends, then its row is gone and one mailbox fewer is read.
#[test]
fn a_contact_moving_off_our_list_drains_our_old_mailbox_until_the_drain_ends() {
    a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(ContactKind::Person, false);
}

/// `old_listed`: whether the relay the contact moves away from is in our list.
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_contact_moving_its_home_relay_moves_our_mailbox_once_applied(
    kind: ContactKind,
    old_listed: bool,
) {
    let world = World::new();
    // relay.test and relay2.test are separate relays, so the old and new mailboxes do not share
    // a key on one relay, where the second socket would take the first one's mailbox over.
    world.relay.set_relays_apart(true);
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
    let built_in = if old_listed {
        helpers::adding(
            relays(&world.payer),
            vec![lepic_epicbox::RelayEndpoint::new(
                Domain::parse("relay2.test").unwrap(),
                Some(80),
                lepic_epicbox::Security::Plain,
            )],
        )
    } else {
        helpers::only_relay2(&world, &world.payer)
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
    // Our new card goes to the shop in a contact update, to its key: the carrier adds the
    // mailbox its card names, now on relay2.test.
    let outbox = helpers::contact_rows(&world.payer, ben_side);
    let (peer_key, _) = mailbox.peer_mailbox.split_once('@').unwrap();
    assert!(
        outbox
            .iter()
            .any(|stored| stored.entry.route_value == peer_key),
        "{outbox:?}"
    );
    // Our mailbox is read on each relay of the list, the old relay among them while the list
    // holds it, and on the old relay by the drain's row while the list does not; besides, the
    // public address's delivery mailbox on each relay of the list.
    let own_seq = || {
        let own = world
            .payer
            .read(|repos| repos.contact(ben_side))
            .unwrap()
            .own_card;
        ContactCard::decode(&own, ContactNetwork::Floonet)
            .unwrap()
            .fields()
            .seq
    };
    let read = collect();
    let (drained, contact) = if old_listed {
        (4, MailClass::Contact)
    } else {
        (3, MailClass::PreviousHome)
    };
    assert_eq!((read.mailboxes, read.replaced), (drained, 0));
    assert_eq!(
        helpers::watched(&world.payer, ben_side),
        vec![
            helpers::row("relay.test:80", contact),
            helpers::row("relay2.test:80", MailClass::Contact),
        ]
    );
    // A check the shop sends to our old mailbox before it takes our new card, and a copy of it
    // on the new relay, is answered once.
    // Sealed as the shop's wallet seals it, with its send time; the payer's clock stands in for
    // the shop's, which the drain's days below do not move.
    let check = || Content {
        sent_at: u64::try_from(lepic_wallet::ports::Clock::now(&world.payer.clock).as_second())
            .ok(),
        ..Content::new(MessageType::ContactCheck, Vec::new())
    };
    let answered = own_seq();
    // Our card for the shop moved with it; off the list, the list also gave the public address
    // another relay, which the first collect told the shop in an update.
    assert_eq!(answered, 2 + u32::from(!old_listed));
    let check_now = check();
    post_signed(&world, &world.issuer, shop_side, &check_now);
    post_signed_to(
        &world,
        &world.issuer,
        shop_side,
        &check_now,
        &mailbox.our_mailbox,
    );
    collect();
    collect();
    assert_eq!(own_seq(), answered + 1);

    // After the drain the old relay is read while the list holds it; off the list its row is
    // gone, and a check there stays unread.
    world.payer.clock.advance(7 * 24 * HOUR + MINUTE);
    let (after, rows) = if old_listed {
        (
            4,
            vec![
                helpers::row("relay.test:80", MailClass::Contact),
                helpers::row("relay2.test:80", MailClass::Contact),
            ],
        )
    } else {
        (2, vec![helpers::row("relay2.test:80", MailClass::Contact)])
    };
    assert_eq!(collect().mailboxes, after);
    assert_eq!(helpers::watched(&world.payer, ben_side), rows);
    post_signed(&world, &world.issuer, shop_side, &check());
    collect();
    assert_eq!(own_seq(), answered + 1 + u32::from(old_listed));
    // Our card for the shop moved with it.
    let own = world
        .payer
        .read(|repos| repos.contact(ben_side))
        .unwrap()
        .own_card;
    let own = ContactCard::decode(&own, ContactNetwork::Floonet).unwrap();
    assert!(own.fields().mailbox.as_str().ends_with("@relay2.test:80"));
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
    let mailbox = party.read(|repos| repos.contact_mailbox(contact)).unwrap();
    post_signed_to(world, party, contact, content, &mailbox.peer_mailbox);
}

/// [`post_signed`] to the mailbox `to`, `key@domain:port`, through its relay. The same content
/// seals to the same message each time.
fn post_signed_to(world: &World, party: &Party, contact: ContactId, content: &Content, to: &str) {
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
    let to = EpicboxAddress::parse(to, RelayNetwork::Floonet).unwrap();
    let mut settings = world::settings();
    settings.endpoint = lepic_epicbox::RelayEndpoint::new(
        to.domain().clone(),
        to.port(),
        lepic_epicbox::Security::Plain,
    );
    world
        .block_on(MailboxClient::new(settings, world.relay.connector()).post(
            &from,
            &to,
            &armor(&envelope),
        ))
        .unwrap();
}

/// The issuer issues an invoice by file.
fn issue_by_file(world: &World) -> IssuedInvoice {
    world
        .block_on(world.issuer.wallet.issue_invoice(
            &crate::support::file(),
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("i1.tx"),
                ),
            },
        ))
        .unwrap()
}

/// The payer sends a payment to the issuer's payments address over plain Epicbox.
fn send_to_issuer(world: &World) -> lepic_wallet::send::SentSlate {
    world
        .block_on(world.payer.wallet.send(
            &world.payer.method,
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                to: lepic_transport::transport::Destination::new(world.issuer.address.to_string()),
            },
        ))
        .unwrap()
}

/// R2-03: a paired contact names the issuer's payments address as its mailbox and sends a
/// signed `withdrawn` for a payment the payer sent to that issuer over plain Epicbox. A notice
/// from a contact counts only for a slate exchanged with that contact, so nothing is cancelled.
#[test]
fn a_contact_notice_counts_only_for_slates_exchanged_with_that_contact() {
    let world = World::new();
    let paid = send_to_issuer(&world);
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

    let notice = lepic_wallet::notice::Notice::Withdrawn {
        slate_id: paid.slate_id,
    };
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Notice,
            notice
                .encode_to(&lepic_methods::epicbox::NOTICE_LENGTHS, 0)
                .as_text()
                .unwrap()
                .as_bytes()
                .to_vec(),
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
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
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
    assert_eq!(helpers::contact_rows(&world.payer, ben_side).len(), 1);
    world.block_on(world.payer.wallet.cancel(tx_id)).unwrap();

    world.collect(&world.payer);

    assert!(helpers::contact_rows(&world.payer, ben_side).is_empty());
    assert_eq!(world.collect(&world.issuer).messages, 0);
}

/// A store upgraded from 0.6.0 holds a queued contact post as the outbox row its migration
/// made, and has not run the outbox's fill yet. When the payment has ended, the first collect
/// deletes the row and posts nothing.
#[test]
fn an_upgraded_store_posts_nothing_for_an_ended_payment() {
    let world = World::new();
    let (_, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let offline = ContactRelays {
        mode: RelayMode::Offline,
        ..relays(&world.payer)
    };
    let tx_id = send_through_mailbox(&world, &offline, ben_side);
    world
        .payer
        .write(|repos| repos.delete_setting("outbox.filled"));
    world.block_on(world.payer.wallet.cancel(tx_id)).unwrap();

    world.collect(&world.payer);

    assert!(helpers::contact_rows(&world.payer, ben_side).is_empty());
    assert_eq!(world.collect(&world.issuer).messages, 0);
}

/// Only the contact calls act on a contact's invoice: the payments-address list does not show
/// it, and its payment is never delivered again outside the outbox.
#[test]
fn address_invoice_calls_never_act_on_a_contact_invoice() {
    let world = World::new();
    let (shop_side, _) = world.pair_for_invoices(ContactKind::Exchange);
    world.invoice_contact(shop_side, "unpaid");
    let to_pay = world.invoice_contact(shop_side, "paid");
    world.collect(&world.payer);
    let wallet = &world.payer.wallet;

    assert!(
        wallet
            .pending_invoices(lepic_wallet::epicbox_invoice::InvoiceExpiry::default())
            .unwrap()
            .is_empty()
    );
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
            &world.payer.method,
            paid.tx_id,
            Delivery::Deliver {
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
    let entry = helpers::contact_rows(&world.payer, ben_side)
        .into_iter()
        .find(|stored| stored.entry.payment_id.as_bytes() == issued.slate_id.as_bytes())
        .unwrap();
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();

    assert!(matches!(
        world.block_on(world.payer.wallet.contact_book().contact_outbox_resend(
            &relays(&world.payer),
            lepic_store::ContactOutboxId(entry.id.0)
        )),
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
    let mut entry = helpers::contact_rows(&world.payer, ben_side).remove(0);
    entry.entry.attempts = 2;
    entry.entry.next_at = entry.entry.next_at.checked_add(10 * MINUTE).unwrap();
    world
        .payer
        .store()
        .write(|repos| repos.update_native_outbox(entry.id, &entry.entry))
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
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
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
    let paid = send_to_issuer(&world);
    let mallory = world.stranger();
    mallory.fund(1, world::FUNDING);
    let (on_mallory, _) = world.pair(&mallory, &world.payer);

    // Mallory builds an S1 and gives it the slate id of the payer's payment to the issuer.
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    world
        .block_on(mallory.wallet.send(
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(file.clone()),
            },
        ))
        .unwrap();
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let target = uuid::Uuid::from_bytes(*paid.slate_id.as_bytes());
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

    let notice = lepic_wallet::notice::Notice::Withdrawn {
        slate_id: paid.slate_id,
    };
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Notice,
            notice
                .encode_to(&lepic_methods::epicbox::NOTICE_LENGTHS, 0)
                .as_text()
                .unwrap()
                .as_bytes()
                .to_vec(),
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
            None,
        ))
        .unwrap();

    // An I1 whose message text changed after it was signed, sealed by the contact itself.
    let file = tempfile::tempdir().unwrap().keep().join("i1.tx");
    let unsigned = world
        .block_on(world.issuer.wallet.issue_invoice(
            &crate::support::file(),
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: Some("refund 9".to_owned()),
                ttl_blocks: None,
            },
            Delivery::Export {
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

/// Every contact mailbox is watched on the foreground tick, those of contacts quiet for more
/// than a day on more than three relays too.
#[test]
fn quiet_contacts_on_many_relays_are_read_on_the_foreground_tick() {
    let world = World::new();
    // The four relays are separate, so a mailbox kept on two of them is two mailboxes.
    world.relay.set_relays_apart(true);
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
    // Each contact's current mailbox on its card's relay and on the wallet's relay where those
    // differ, its previous home, and the public address's delivery mailbox on the wallet's
    // relay: 2 + 3 + 1.
    let all = tick();
    assert_eq!((all.mailboxes, all.replaced), (6, 0));
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
/// retried: the host hears of it at once, and the next collect posts it. The receiver is told
/// `posted` once, when it is posted, and not at finalize (ADR 0067).
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
    let slate_id = world
        .payer
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .slate_id;
    let notices = || {
        helpers::mail_rows(&world.payer, ben_side)
            .into_iter()
            .filter(|row| row.entry.notice && Some(row.entry.payment_id) == slate_id)
            .count()
    };
    assert_eq!(notices(), 0);

    world.relay.end_holds();
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.tx_state(&world.payer, tx_id), TxState::Finalized);
    world.collect(&world.payer);
    assert_eq!(notices(), 1);
}

/// A contact's message sealed long ago, or ahead of our clock, is not taken when a relay hands
/// it over; once a contact sent its send time, a message without one is not taken either.
#[test]
fn a_contact_message_sealed_long_ago_or_without_its_send_time_is_not_taken() {
    let world = World::new();
    // Only the payer verifies: after one stamped message from a contact every unstamped one is
    // refused, and the issuer's verdict is stamped.
    let (shop_side, ben_side) = world.pair_unverified(ContactKind::Exchange);
    world
        .block_on(world.payer.wallet.contact_book().pairing_sas(
            &relays(&world.payer),
            ben_side,
            SasDecision::Match,
        ))
        .unwrap();
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_set_allow_invoices(ben_side, true),
        )
        .unwrap();
    world.collect(&world.issuer);
    let unsigned_invoice = |message: &str| {
        let file = tempfile::tempdir().unwrap().keep().join("i1.tx");
        world
            .block_on(world.issuer.wallet.issue_invoice(
                &crate::support::file(),
                InvoiceRequest {
                    account: ACCOUNT,
                    amount: Amount::new(AMOUNT),
                    message: Some(message.to_owned()),
                    ttl_blocks: None,
                },
                Delivery::Export {
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

    let notice = lepic_wallet::notice::Notice::Cancelled {
        slate_id: lepic_slate::model::SlateId::from_bytes(slate_id.into_bytes()),
    };
    post_signed(
        &world,
        &mallory,
        on_mallory,
        &Content::new(
            MessageType::Notice,
            notice
                .encode_to(&lepic_methods::epicbox::NOTICE_LENGTHS, 0)
                .as_text()
                .unwrap()
                .as_bytes()
                .to_vec(),
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

/// The view shows the caps on the contact's card; a contact whose card does not pay invoices
/// shows it there, and issuing it an invoice fails with `DoesNotPayInvoices`.
#[test]
fn a_contact_view_shows_the_peer_cards_caps_and_no_pays_invoices_is_refused() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    let caps = |party: &Party, contact: ContactId| {
        world
            .block_on(party.wallet.contact_book().contact(contact))
            .unwrap()
            .peer_caps
    };
    // LEPIC cards open sealed files, pay invoices and issue them.
    assert_eq!(caps(&world.issuer, shop_side), 0b111);
    assert_eq!(caps(&world.payer, ben_side), 0b111);

    // The stored card of a service that opens sealed files and issues invoices, as the shop of
    // the pairing kit does, with no pays-invoices bit.
    world.issuer.write(|repos| {
        let mut record = repos.contact(shop_side)?.unwrap();
        let peer = record.peer.as_mut().unwrap();
        let card = ContactCard::decode(&peer.bytes, ContactNetwork::Floonet).unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut fields = card.fields().clone();
        fields.sig_key = key.verifying_key();
        fields.caps = Capabilities::OPENS_SEALED_FILES
            .with(Capabilities::ISSUES_INVOICES)
            .with(Capabilities::FIXED_HINT);
        peer.bytes = ContactCard::sign(ContactNetwork::Floonet, fields, &key)
            .unwrap()
            .as_bytes()
            .to_vec();
        repos.put_contact(&record)
    });
    assert_eq!(caps(&world.issuer, shop_side), 0b1101);

    let refused = world.block_on(world.issuer.wallet.contact_book().contact_issue_invoice(
        &relays(&world.issuer),
        shop_side,
        InvoiceRequest {
            account: ACCOUNT,
            amount: Amount::new(AMOUNT),
            message: None,
            ttl_blocks: None,
        },
        InvoiceDetails {
            purpose: Purpose::DepositRequest,
            reference: None,
            expires: None,
        },
        None,
    ));
    assert!(matches!(refused, Err(ContactError::DoesNotPayInvoices)));
}
