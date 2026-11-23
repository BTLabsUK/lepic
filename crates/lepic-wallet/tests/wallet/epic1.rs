// SPDX-License-Identifier: Apache-2.0
//! Epic1 links: a link is the account's one epic1 address with what it asks. The payer seals an
//! S1 to the address and posts it to the address's delivery mailbox, the payee answers with an
//! S2 through the reply mailbox the payment names, and the payer finalizes.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::epic1_outbox::{
    LATER, answer_again, due_over, on_shop, pay_over, pay_unanswered, quick, quick_on_shop, rows,
    taken_on_shop,
};
use crate::epicbox_world as world;
use crate::pairing_helpers as helpers;
use crate::support;

use helpers::{
    ACK_GROUP, events, hold_acks, lose_acks_and_reopen, queued_after, relays, wait_gone,
};
use lepic_contact::{
    Content, EncSecretKey, HintRule, MessageType, SealedEnvelope, armor, dearmor, seal,
};
use lepic_epicbox::{
    Domain, EpicboxAddress, EpicboxClient, Identity, MuxState, Network as RelayNetwork,
    RelayEndpoint, Security,
};
use lepic_node::Propagation;
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_store::{
    AccountIndex, MailClass, NativeOutboxEntry, OutboxState, OutboxStatus, TxDirection, TxState,
    WatchRow,
};
use lepic_transport::transport::{Inbound, Location};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, ReceiveRequest, WalletPolicy};
use lepic_wallet_contacts::epic1_testing::{
    address_any, delivery_mailbox, for_other_network, native_body_of, sealed_notice,
    sealed_payment, sealed_to_epic1, without_transports,
};
use lepic_wallet_contacts::in_person_testing::{armored, without_tail};
use lepic_wallet_contacts::{
    CollectReport, CollectTrigger, ContactError, ContactRelays, Epic1LinkIssued, Epic1LinkRequest,
    Epic1Paid, Epic1PayRequest, Epic1Refusal, InPersonInvoiceRequest, MethodId, PaymentFile,
    RouteEntry, WalletContacts, payment_file,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, World};

pub(crate) fn refusal<T: std::fmt::Debug>(result: Result<T, ContactError>) -> Epic1Refusal {
    match result {
        Err(ContactError::Epic1(refusal)) => refusal,
        other => panic!("not an epic1 refusal: {other:?}"),
    }
}

fn link_request(entries: Vec<RouteEntry>) -> Epic1LinkRequest {
    Epic1LinkRequest {
        account: ACCOUNT,
        amount: Some(Amount::new(AMOUNT)),
        message: Some("coffee".to_owned()),
        entries,
    }
}

/// An `http` entry of a link.
pub(crate) fn http_entry(value: &str) -> RouteEntry {
    RouteEntry {
        method: MethodId::Http,
        value: value.to_owned(),
    }
}

pub(crate) fn send() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

/// The delivery mailbox on the wallets' own relay of the address `text` pays.
pub(crate) fn mailbox_of(text: &str) -> EpicboxAddress {
    delivery_mailbox(text, "relay.test").unwrap()
}

impl World {
    /// Makes a link without entries on the address of `party`'s account.
    pub(crate) fn issue_link(&self, party: &Party) -> Epic1LinkIssued {
        self.try_issue_link(party, Vec::new()).unwrap()
    }

    /// Makes a link with `entries` on the address of `party`'s account.
    pub(crate) fn try_issue_link(
        &self,
        party: &Party,
        entries: Vec<RouteEntry>,
    ) -> Result<Epic1LinkIssued, ContactError> {
        party
            .wallet
            .contact_book()
            .epic1_link(&relays(party), link_request(entries))
    }

    pub(crate) fn pay_link(&self, link: &str) -> Result<Epic1Paid, ContactError> {
        self.pay_epic1(link, send())
    }

    pub(crate) fn pay_epic1(
        &self,
        link: &str,
        send: SendRequest,
    ) -> Result<Epic1Paid, ContactError> {
        self.pay_epic1_with(link, send, false)
    }

    /// Pays `link` with `send`, refusing an answer without a receipt that holds when
    /// `require_receipt`.
    pub(crate) fn pay_epic1_with(
        &self,
        link: &str,
        send: SendRequest,
        require_receipt: bool,
    ) -> Result<Epic1Paid, ContactError> {
        let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
        self.block_on(self.payer.wallet.contact_book().epic1_pay(
            &relays(&self.payer),
            Epic1PayRequest {
                link: link.to_owned(),
                send,
                slate_file: file,
                mailboxes: Vec::new(),
                require_receipt,
            },
        ))
    }

    pub(crate) fn taken(&self, party: &Party) -> usize {
        self.collect(party).epic1
    }

    /// The answers the payee holds, all posted by collecting; returns how many.
    pub(crate) fn answers_posted(&self) -> usize {
        let book = self.issuer.wallet.contact_book();
        let answers = self.block_on(book.epic1_answers()).unwrap();
        assert!(answers.iter().all(|answer| answer.posted));
        answers.len()
    }

    /// The payer's reply secret of the payment `slate_id`, which notices to it are sealed to.
    pub(crate) fn reply_secret(&self, slate_id: SlateId) -> EncSecretKey {
        let reply = lepic_wallet_contacts::contact_root(
            &self.payer.keychain(),
            &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
            Network::Floonet,
        )
        .unwrap()
        .reply_key(*slate_id.as_bytes())
        .unwrap();
        EncSecretKey::from_bytes(*reply.expose_x25519_secret())
    }

    /// The refusal of the payment `slate_id` as the payee seals it: `body` as a notice sealed
    /// to the payer's reply key for the slate, armored.
    fn refusal_of(&self, slate_id: SlateId, body: &str) -> String {
        let key = self.reply_secret(slate_id).public_key();
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

    /// Reads and acknowledges every text waiting at the payer's reply mailbox of the payment
    /// `slate_id`, in the order the relay gives them.
    pub(crate) fn drain_reply(&self, slate_id: SlateId) -> Vec<String> {
        let mailbox = self.reply_mailbox(slate_id);
        let secret = self
            .payer
            .wallet
            .reply_mailbox_key(
                ACCOUNT,
                lepic_contact::Network::Floonet,
                slate_id.as_bytes(),
            )
            .unwrap();
        let client = EpicboxClient::new(
            world::settings(),
            Identity::new(secret, mailbox).unwrap(),
            self.relay.connector(),
        );
        self.block_on(async {
            let subscription = client.drain().unwrap();
            let mut texts = Vec::new();
            while let Some(envelope) = self.within(subscription.next_envelope()).await.unwrap() {
                subscription
                    .acknowledge(envelope.ack_token())
                    .await
                    .unwrap();
                texts.push(envelope.wire().as_text().unwrap().to_owned());
            }
            subscription.stop().await.unwrap();
            texts
        })
    }

    /// The reasons of the refusals of the payment `slate_id` waiting at the payer's reply
    /// mailbox, read off the relay: each a `declined` notice of the slate, sealed to its reply
    /// key.
    fn refusal_reasons(&self, slate_id: SlateId) -> Vec<String> {
        let secret = self.reply_secret(slate_id);
        self.drain_reply(slate_id)
            .iter()
            .map(|text| {
                let bytes = dearmor(text).unwrap();
                let envelope =
                    SealedEnvelope::decode(&bytes, lepic_contact::Network::Floonet).unwrap();
                let content = envelope.open(&secret).unwrap().content;
                assert_eq!(content.kind, MessageType::Notice);
                let body: serde_json::Value = serde_json::from_slice(&content.body).unwrap();
                assert_eq!(body["type"], "declined");
                assert_eq!(body["slate_id"], slate_id.to_string());
                body["reason"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    /// The payer's reply mailbox of the payment `slate_id` on the payer's own relay.
    pub(crate) fn reply_mailbox(&self, slate_id: SlateId) -> EpicboxAddress {
        self.reply_mailbox_on(slate_id, "relay.test")
    }

    /// The payer's reply mailbox of the payment `slate_id` on the relay `domain`.
    pub(crate) fn reply_mailbox_on(&self, slate_id: SlateId, domain: &str) -> EpicboxAddress {
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
            Domain::parse(domain).unwrap(),
            Some(80),
        )
    }

    pub(crate) fn payer_state(&self, tx_id: lepic_store::TxId) -> TxState {
        self.payer
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .state
    }

    pub(crate) fn payer_locked(&self) -> Amount {
        self.payer.wallet.balance(ACCOUNT).unwrap().locked
    }

    /// Posts `text` to the delivery mailbox of the address `link` pays from a peer key.
    fn post_to_link(&self, link: &str, text: &str) {
        self.post(7, &mailbox_of(link), text, 1);
    }
}

#[test]
fn a_link_paid_is_answered_through_the_reply_mailbox_and_finalized() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    assert_eq!(issued.address, world.address());

    let read = world
        .payer
        .wallet
        .contact_book()
        .epic1_read(&relays(&world.payer), &issued.link)
        .unwrap();
    assert_eq!(read.address, issued.address);
    assert_eq!(read.amount, Some(Amount::new(AMOUNT)));
    assert_eq!(read.message.as_deref(), Some("coffee"));
    // A link without entries goes to the mailbox: no host to name.
    assert_eq!(read.http_host, None);

    let paid = world.pay_epic1(&issued.link, send()).unwrap();
    assert_eq!(paid.address, issued.address);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(paid.attempts[0].error, None);

    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.received_index(), Some(0));
    // Collecting posted the answer; the payer finalizes by collecting alone.
    assert_eq!(world.answers_posted(), 1);
    assert!(world.node.pushed_transactions().is_empty());

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    // The payment is answered once; collecting again takes nothing new.
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(
        refusal(
            world.block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .epic1_post_next(&relays(&world.payer), paid.slate_id)
            )
        ),
        Epic1Refusal::Finalized
    );
}

/// A payment is stored with its send in one write. Whichever write of the paying call fails,
/// the call fails with no send stored and nothing locked, or the payment is stored with its
/// post.
#[test]
fn a_payment_is_stored_with_its_send_or_not_at_all() {
    let probe = World::new();
    let issued = probe.issue_link(&probe.issuer);
    let before = probe.payer.writes();
    probe.pay_link(&issued.link).unwrap();
    let writes = probe.payer.writes() - before;
    let mut failed = 0;
    for succeeding in 0..writes {
        let world = World::new();
        let issued = world.issue_link(&world.issuer);
        world.payer.fail_write_after(succeeding);
        match world.pay_link(&issued.link) {
            Ok(paid) => assert!(
                !rows(&world.payer, paid.slate_id).is_empty(),
                "write {succeeding}: the payment has its post"
            ),
            Err(error) => {
                failed += 1;
                let sent = world.payer.read(|repos| repos.transactions(ACCOUNT));
                assert!(
                    sent.iter()
                        .all(|tx| tx.entry.direction != TxDirection::Outgoing),
                    "write {succeeding} ({error:?}): no send is stored"
                );
                assert_eq!(world.payer_locked(), Amount::ZERO);
            }
        }
    }
    assert!(failed > 0, "a write of the paying call failed");
}

/// A payment the payee received with no answer stored, as a stop between the two left it, is
/// answered when it arrives again: the stored S2 is sealed and posted, and the payer finalizes.
#[test]
fn a_payment_received_again_without_its_answer_is_answered() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    let s1 = rows(&world.payer, paid.slate_id).remove(0).entry.envelope;
    assert_eq!(world.taken(&world.issuer), 1);
    // The stop: the receive is stored, its answer and the answer's post are not.
    let payment = uuid::Uuid::from_bytes(*paid.slate_id.as_bytes());
    world.issuer.write(|repos| {
        repos.delete_setting(&format!("epic1.answer.{}", paid.slate_id))?;
        for row in repos.native_outbox_of(payment)? {
            repos.delete_native_outbox(row.id)?;
        }
        Ok(())
    });
    assert_eq!(world.drain_reply(paid.slate_id).len(), 1);

    world.post_to_link(&issued.link, &s1);
    assert_eq!(world.taken(&world.issuer), 0, "received before");
    assert_eq!(world.answers_posted(), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn a_plain_slate_at_a_delivery_mailbox_is_acknowledged_and_dropped() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    world.post_to_link(
        &issued.link,
        r#"{"version_info":{"version":3,"block_header_version":6}}"#,
    );

    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
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
                slate_id: None,
                direct: Vec::new(),
                claim: None,
                shared_slot: false,
            },
        ))
        .unwrap();
    without_tail(Network::Floonet, &code.bytes).unwrap()
}

#[test]
fn an_anonymous_invoice_at_a_delivery_mailbox_is_refused() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
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
            .block_on(world.issuer.wallet.contact_book().epic1_answers())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_payment_without_a_reply_mailbox_is_refused() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
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
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
}

/// A link's `mailbox=` entries are counted as ignored when it is read, and the payment goes
/// through the payer's list: no post reaches the host they name.
#[test]
fn a_link_with_mailbox_entries_is_read_with_them_ignored_and_paid_on_the_list() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let link = format!(
        "{}&mailbox=elsewhere.test&mailbox=elsewhere.test:80",
        issued.link
    );
    let read = world
        .payer
        .wallet
        .contact_book()
        .epic1_read(&relays(&world.payer), &link)
        .unwrap();
    assert_eq!(read.address, issued.address);
    assert_eq!(read.ignored_mailboxes, 2);
    assert_eq!(read.http_host, None);

    let plain = world
        .payer
        .wallet
        .contact_book()
        .epic1_read(&relays(&world.payer), &issued.link)
        .unwrap();
    assert_eq!(plain.ignored_mailboxes, 0);

    world.pay_link(&link).unwrap();
    assert_eq!(world.relay.received_on("elsewhere.test", "PostSlate"), 0);
    assert_eq!(world.taken(&world.issuer), 1);
}

#[test]
fn a_bare_address_is_paid_and_one_for_another_network_is_not() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let book = world.payer.wallet.contact_book();

    let other = for_other_network(&issued.link).unwrap();
    assert_eq!(
        refusal(book.epic1_read(&relays(&world.payer), &other)),
        Epic1Refusal::WrongNetwork
    );
    assert_eq!(refusal(world.pay_link(&other)), Epic1Refusal::WrongNetwork);

    // An address alone is paid through its delivery mailbox on the payer's relays.
    for bare in [
        format!("epic:{}", issued.address),
        without_transports(&issued.link).unwrap(),
    ] {
        let read = book.epic1_read(&relays(&world.payer), &bare).unwrap();
        assert_eq!(read.address, issued.address);
        assert_eq!(read.http_host, None);
    }
    assert_eq!(
        book.epic1_read(&relays(&world.payer), &format!("epic:{}", issued.address))
            .unwrap()
            .amount,
        None
    );

    assert!(matches!(
        book.epic1_read(&relays(&world.payer), "epic1:nothing"),
        Err(ContactError::Epic1Link(_))
    ));
    // Nothing was sent.
    assert_eq!(world.payer_locked(), Amount::ZERO);
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

fn declined_events(events: &mut tokio::sync::broadcast::Receiver<Event>) -> usize {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::PaymentDeclined(_)))
        .count()
}

fn declined_body(slate_id: SlateId) -> String {
    format!(r#"{{"lepic":1,"type":"declined","slate_id":"{slate_id}","reason":"declined"}}"#)
}

#[test]
fn a_payment_the_payee_refuses_never_happened_for_the_payer() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_ne!(world.payer_locked(), Amount::ZERO);
    let mut events = world.payer.wallet.subscribe();

    // The payee refuses and tells the payer through the reply mailbox the payment named.
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&world.reply_mailbox(paid.slate_id)), 1);
    assert_eq!(world.payer_state(paid.tx_id), TxState::Sent);

    // The payer erases the payment: its inputs are free, its change is gone, and only the
    // time of the refusal is kept.
    world.collect(&world.payer);
    assert_payment_erased(&world, paid.tx_id);
    assert_eq!(declined_events(&mut events), 1);
    assert!(
        world
            .block_on(world.payer.wallet.send_declined_at(paid.slate_id))
            .unwrap()
            .is_some()
    );
    assert_eq!(world.relay.pending(&world.reply_mailbox(paid.slate_id)), 0);

    // No one is told, and collecting again changes nothing.
    assert!(
        world
            .payer
            .read(|repos| repos.outbox(OutboxStatus::Pending))
            .is_empty()
    );
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
    world.collect(&world.issuer);
    world.collect(&world.payer);
    assert_eq!(declined_events(&mut events), 0);
    assert_eq!(pay_record(&world, paid.slate_id), None);
    assert!(rows(&world.payer, paid.slate_id).is_empty());
    assert!(
        world
            .block_on(world.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .is_empty()
    );
    assert!(world.node.pushed_transactions().is_empty());
}

/// The payer holds nothing of the send `tx_id`: no entry, no output that names it, and no
/// coins locked or awaiting finalization.
fn assert_payment_erased(world: &World, tx_id: lepic_store::TxId) {
    assert!(world.payer.read(|repos| repos.transaction(tx_id)).is_none());
    assert!(
        world
            .payer
            .read(|repos| repos.outputs_of_transaction(tx_id))
            .is_empty()
    );
    let balance = world.payer.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(balance.locked, Amount::ZERO);
    assert_eq!(balance.awaiting_finalization, Amount::ZERO);
}

#[test]
fn a_refusal_that_is_not_for_the_payment_leaves_it_waiting() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_epic1(&issued.link, send()).unwrap();
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
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_epic1(&issued.link, send()).unwrap();
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

    /// The issuer's epic1 address.
    fn address(&self) -> String {
        self.issuer
            .wallet
            .contact_book()
            .epic1_address(ACCOUNT)
            .unwrap()
            .encode()
    }

    /// An S1 from the payer, asking for a payment proof by `proof` if given, sealed to the
    /// epic1 `address` as a file is, armored.
    fn s1_file(&self, address: &str, proof: Option<[u8; 32]>, seed: u64) -> String {
        self.s1_file_of(
            address,
            SendRequest {
                payment_proof_recipient: proof.map(|key| ProofAddress::from_bytes(key).unwrap()),
                ..send()
            },
            seed,
        )
    }

    /// The S1 of `send` from the payer as a file holds it, in the native form.
    pub(crate) fn s1_body(&self, send: SendRequest) -> Vec<u8> {
        let path = tempfile::tempdir().unwrap().keep().join("s1.json");
        self.block_on(self.payer.wallet.send(
            &support::file(),
            send,
            Delivery::Export {
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
        native_body_of(Network::Floonet, &std::fs::read(&path).unwrap()).unwrap()
    }

    /// The S1 of `send` from the payer, sealed to the epic1 `address` as a file is, armored.
    fn s1_file_of(&self, address: &str, send: SendRequest, seed: u64) -> String {
        let body = self.s1_body(send);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let sealed =
            sealed_to_epic1(Network::Floonet, address, body, true, false, &mut rng).unwrap();
        armored(&sealed)
    }
}

#[test]
fn a_file_sealed_to_an_address_that_asks_for_a_proof_is_refused_and_nothing_is_signed() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    // A proof by the issuer's own payments key, which an epic1 address must not sign with.
    let payments = *world
        .issuer
        .wallet
        .previous_onion_key()
        .unwrap()
        .public_key();
    world.payer.fund(20, FUNDING);
    let text = world.s1_file(&world.address(), Some(payments), 5);

    let error = world
        .block_on(book.sealed_receive(&text, ReceiveRequest::default()))
        .unwrap_err();

    assert!(
        matches!(
            error,
            ContactError::Receive(lepic_wallet::receive::ReceiveError::ForeignProofAddress)
        ),
        "{error:?}"
    );
    let received = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap()
        .into_iter()
        .filter(|details| details.transaction.entry.direction == TxDirection::Incoming)
        .count();
    assert_eq!(received, 0);
}

#[test]
fn a_file_sealed_to_another_accounts_address_is_received_into_that_account() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    let savings = world.issuer.wallet.create_account("savings").unwrap();
    let address = book.epic1_address(savings.index).unwrap();
    world.payer.fund(20, FUNDING);
    let text = world.s1_file(&address.encode(), None, 4);

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

/// A text sealed to the payer's reply key of a slate is opened only while the payment waits
/// for the answer: once the payer finalized or cancelled, it is for another install.
#[test]
fn a_text_to_a_reply_key_is_opened_only_while_its_payment_waits() {
    for finalize in [true, false] {
        let world = World::new();
        let issued = world.issue_link(&world.issuer);
        let paid = world.pay_link(&issued.link).unwrap();
        let text = world.refusal_of(paid.slate_id, "{}");
        let contacts = world.payer.wallet.contact_book();
        let waiting = world.block_on(contacts.sealed_peek(&text));
        assert!(
            !matches!(waiting, Err(ContactError::NotForThisInstall)),
            "{waiting:?}"
        );

        if finalize {
            world.collect(&world.issuer);
            world.collect(&world.payer);
            assert_eq!(world.node.pushed_transactions().len(), 1);
        } else {
            world
                .block_on(world.payer.wallet.cancel(paid.tx_id))
                .unwrap();
        }

        let ended = world.block_on(contacts.sealed_peek(&text));
        assert!(
            matches!(ended, Err(ContactError::NotForThisInstall)),
            "finalized {finalize}: {ended:?}"
        );
    }
}

/// A payment that finds the open receipt cap full is refused and its payer is told, as for a
/// payment refused for any other reason; the open receipt stays as it was.
#[test]
fn a_link_payment_past_the_open_receipt_cap_is_refused_and_leaves_its_link_unused() {
    let world = World::with_issuer_policy(WalletPolicy {
        max_open_receipts: 1,
        ..WalletPolicy::default()
    });
    let issued = world.issue_link(&world.issuer);
    world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    let open = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(open.len(), 1);
    let open = open[0].transaction.id;
    world.payer.fund(20, FUNDING);
    let refused = world.pay_link(&issued.link).unwrap();
    assert_eq!(refused.posted, Some(0));
    let mut events = world.payer.wallet.subscribe();

    // The second payment finds the cap full: nothing is received or cancelled, and the
    // refusal goes to the reply mailbox the payment named.
    assert_eq!(world.taken(&world.issuer), 0);
    let received = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.transaction(open))
            .unwrap()
            .state,
        TxState::Received
    );
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
    assert_eq!(
        world.relay.pending(&world.reply_mailbox(refused.slate_id)),
        1
    );
    assert_eq!(world.answers_posted(), 1);

    // The payer erases the refused payment.
    world.collect(&world.payer);
    assert_eq!(declined_events(&mut events), 1);
    assert!(
        world
            .payer
            .read(|repos| repos.transaction(refused.tx_id))
            .is_none()
    );
}

/// A second payment to an address whose first payment still waits for its answer is posted
/// and taken: each payment has its own id, and the payee answers both.
#[test]
fn a_second_payment_to_an_address_is_taken_while_the_first_waits() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let first = world.pay_link(&issued.link).unwrap();
    assert_eq!(first.posted, Some(0));
    assert_eq!(world.payer_state(first.tx_id), TxState::Sent);

    world.payer.fund(20, FUNDING);
    let second = world.pay_link(&format!("epic:{}", issued.address)).unwrap();
    assert_eq!(second.posted, Some(0));
    assert_ne!(second.slate_id, first.slate_id);

    assert_eq!(world.taken(&world.issuer), 2);
    assert_eq!(world.answers_posted(), 2);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 2);
}

/// The party's watch rows of `class`.
pub(crate) fn rows_of(party: &Party, class: MailClass) -> Vec<WatchRow> {
    let mut rows: Vec<WatchRow> = party
        .read(|repos| repos.watch_set())
        .into_iter()
        .filter(|row| row.class == class)
        .collect();
    rows.sort_by(|a, b| (&a.key_ref, &a.relay).cmp(&(&b.key_ref, &b.relay)));
    rows
}

/// The address rows of `accounts`: the delivery mailbox of each account's address on the
/// wallets' own relay, the only relay of the list, with no expiry.
fn expected_address_rows(accounts: &[u32]) -> Vec<WatchRow> {
    accounts
        .iter()
        .map(|account| WatchRow {
            key_ref: format!("address:{account}.0"),
            relay: HOME.to_owned(),
            class: MailClass::Address,
            expires_at: None,
        })
        .collect()
}

pub(crate) fn reconciled(world: &World, party: &Party) {
    world.block_on(party.wallet.contact_book().claim_pushed(&relays(party)));
}

/// The address row of each account stays as it is through links made and payments taken; a
/// payment's reply row lasts until its transaction confirms.
#[test]
fn address_and_reply_rows_follow_the_records() {
    let world = World::new();
    let linked = world.issue_link(&world.issuer);
    world.issue_link(&world.issuer);
    reconciled(&world, &world.issuer);
    let rows = rows_of(&world.issuer, MailClass::Address);
    assert_eq!(rows, expected_address_rows(&[0]));

    // A payment opens the payer's reply row on its own relay.
    let paid = world.pay_link(&linked.link).unwrap();
    reconciled(&world, &world.payer);
    assert_eq!(
        rows_of(&world.payer, MailClass::Reply),
        [WatchRow {
            key_ref: format!("reply:{}", paid.slate_id),
            relay: HOME.to_owned(),
            class: MailClass::Reply,
            expires_at: None,
        }]
    );

    // Taking the payment leaves the address open and its row as it was.
    assert_eq!(world.taken(&world.issuer), 1);
    reconciled(&world, &world.issuer);
    assert_eq!(rows_of(&world.issuer, MailClass::Address), rows);

    // The payer finalizes: its reply row stays until the transaction confirms.
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    reconciled(&world, &world.payer);
    assert_eq!(rows_of(&world.payer, MailClass::Reply).len(), 1);
    world.payer.write(|repos| {
        let mut entry = repos.transaction(paid.tx_id)?.unwrap();
        entry.state = TxState::Confirmed;
        repos.update_transaction(paid.tx_id, &entry)
    });
    reconciled(&world, &world.payer);
    assert_eq!(rows_of(&world.payer, MailClass::Reply), []);
}

#[test]
fn a_payment_is_finalized_from_the_relay_it_named_after_the_relay_setting_changes() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.answers_posted(), 1);
    assert_eq!(world.relay.pending(&world.reply_mailbox(paid.slate_id)), 1);

    // The payer's wallet now uses another relay; the answer waits on the one the payment named.
    let mut settings = world::settings();
    settings.endpoint = lepic_epicbox::RelayEndpoint::new(
        Domain::parse("moved.test").unwrap(),
        None,
        lepic_epicbox::Security::Plain,
    );
    let moved = helpers::on(
        lepic_methods::epicbox::Epicbox::new(
            settings,
            RelayNetwork::Floonet,
            world.relay.connector(),
        ),
        relays(&world.payer),
    );
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_collect(&moved, lepic_wallet_contacts::CollectTrigger::Open),
        )
        .unwrap();

    assert_eq!(world.relay.pending(&world.reply_mailbox(paid.slate_id)), 0);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

/// The relay of the wallets' own mailboxes.
const HOME: &str = "relay.test:80";

pub(crate) fn collect_on(world: &World, party: &Party, trigger: CollectTrigger) -> CollectReport {
    world
        .block_on(
            party
                .wallet
                .contact_book()
                .contacts_collect(&relays(party), trigger),
        )
        .unwrap()
}

/// The issuer's incoming transactions.
pub(crate) fn received(world: &World) -> usize {
    world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap()
        .into_iter()
        .filter(|details| details.transaction.entry.direction == TxDirection::Incoming)
        .count()
}

/// The issuer takes a payment to a link with its acknowledgement held, answers it,
/// loses the acknowledgement with the socket and is opened again on its store. Returns the
/// payment and the delivery mailbox of the link's address, where the payment still waits.
fn link_payment_with_lost_ack(world: &mut World) -> (Epic1Paid, EpicboxAddress) {
    hold_acks(&world.issuer);
    let issued = world.issue_link(&world.issuer);
    collect_on(world, &world.issuer, CollectTrigger::Open);
    let mailbox = mailbox_of(&issued.link);
    let mut paid = None;
    queued_after(world, &world.issuer, HOME, || {
        paid = Some(world.pay_link(&issued.link).unwrap());
    });
    let report = collect_on(world, &world.issuer, CollectTrigger::Push);
    assert_eq!(report.epic1, 1);
    assert_eq!(world.answers_posted(), 1);
    assert_eq!(world.relay.pending(&mailbox), 1, "the ack is held");

    let reopened = lose_acks_and_reopen(world, &world.issuer);
    let old = std::mem::replace(&mut world.issuer, reopened);
    old.wallet.close();
    (paid.unwrap(), mailbox)
}

/// A payment to a link, stored before its acknowledgement was lost, is offered again
/// after the wallet is opened again and taken as handled: no second receipt, no event, one
/// answer, and the payer finalizes once.
#[test]
fn a_link_payment_stored_before_its_ack_was_lost_is_handled_once() {
    let mut world = World::new();
    let (paid, mailbox) = link_payment_with_lost_ack(&mut world);
    let mut issuer_events = world.issuer.wallet.subscribe();

    let report = collect_on(&world, &world.issuer, CollectTrigger::Open);
    assert_eq!(report.epic1, 0);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    wait_gone(&world, &mailbox);
    let session = world.issuer.epicbox.pushed().get(HOME, ACK_GROUP).unwrap();
    assert!(session.counters().mails >= 1, "the relay offered it again");
    assert!(events(&mut issuer_events).is_empty());
    assert_eq!(received(&world), 1);
    assert_eq!(world.answers_posted(), 1);

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
}

/// A payment delivered twice is answered both times with the answer stored the first time:
/// one receipt, and the same answer posted twice to the reply mailbox, read by push. The
/// second post goes from the answer's row, made due again: a repeat stores no new row.
#[test]
fn a_payment_delivered_twice_is_answered_with_the_stored_answer_both_times() {
    let mut world = World::new();
    let (paid, mailbox) = link_payment_with_lost_ack(&mut world);
    let reply = world.reply_mailbox(paid.slate_id);
    assert_eq!(world.relay.pending(&reply), 1);
    let answer = rows(&world.issuer, paid.slate_id);
    assert_eq!(answer.len(), 1);

    collect_on(&world, &world.issuer, CollectTrigger::Open);
    wait_gone(&world, &mailbox);
    assert_eq!(received(&world), 1);
    assert_eq!(world.relay.pending(&reply), 2);
    let again = rows(&world.issuer, paid.slate_id);
    assert_eq!(again.len(), 1, "the repeat reuses the answer's row");
    assert_eq!(again[0].id, answer[0].id);
    assert_eq!(again[0].entry.envelope, answer[0].entry.envelope);
    assert_eq!(again[0].entry.state, OutboxState::Posted);

    let secret = world
        .payer
        .wallet
        .reply_mailbox_key(
            ACCOUNT,
            lepic_contact::Network::Floonet,
            paid.slate_id.as_bytes(),
        )
        .unwrap();
    let client = EpicboxClient::new(
        world::settings(),
        Identity::new(secret, reply).unwrap(),
        world.relay.connector(),
    );
    let texts: Vec<String> = world.block_on(async {
        let subscription = client.drain().unwrap();
        let mut texts = Vec::new();
        while let Some(envelope) = world.within(subscription.next_envelope()).await.unwrap() {
            subscription
                .acknowledge(envelope.ack_token())
                .await
                .unwrap();
            texts.push(envelope.wire().as_text().unwrap().to_owned());
        }
        subscription.stop().await.unwrap();
        texts
    });
    assert_eq!(texts.len(), 2);
    assert_eq!(texts[0], texts[1]);
}

/// The answer to a payment, stored before its acknowledgement was lost, is offered again after
/// the payer's wallet is opened again. The payment is finalized by then; the reply row stays
/// until the transaction ends, so the answer is read, taken as handled and leaves the relay.
#[test]
fn an_answer_offered_again_after_finalize_is_handled_once() {
    let mut world = World::new();
    let issued = world.issue_link(&world.issuer);
    hold_acks(&world.payer);
    let paid = world.pay_link(&issued.link).unwrap();
    collect_on(&world, &world.payer, CollectTrigger::Open);
    let mailbox = world.reply_mailbox(paid.slate_id);
    let mut payer_events = world.payer.wallet.subscribe();

    queued_after(&world, &world.payer, HOME, || {
        assert_eq!(world.taken(&world.issuer), 1);
    });
    collect_on(&world, &world.payer, CollectTrigger::Push);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert!(!events(&mut payer_events).is_empty());
    assert_eq!(world.relay.pending(&mailbox), 1, "the ack is held");
    let state = world.payer_state(paid.tx_id);

    let reopened = lose_acks_and_reopen(&world, &world.payer);
    let old = std::mem::replace(&mut world.payer, reopened);
    old.wallet.close();
    let mut reopened_events = world.payer.wallet.subscribe();
    let report = collect_on(&world, &world.payer, CollectTrigger::Open);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    wait_gone(&world, &mailbox);
    let session = world.payer.epicbox.pushed().get(HOME, ACK_GROUP).unwrap();
    assert!(session.counters().mails >= 1, "the relay offered it again");
    assert!(events(&mut reopened_events).is_empty());
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.payer_state(paid.tx_id), state);
}

/// Another socket of the same wallet takes the issuer's mailboxes over. Timed passes and pulls
/// leave them with it and count them replaced, not unreached, so the two do not trade them; an
/// open takes them back at once and reads the payment the other socket left waiting.
#[test]
fn a_mailbox_another_socket_took_over_stays_with_it_until_an_open() {
    let world = World::new();
    let (issued, watched, other) = taken_over(&world);
    let attaches = world.relay.received("Attach");

    // The payment reaches the other socket, which does not read it.
    let mailbox = mailbox_of(&issued.link);
    world.pay_link(&issued.link).unwrap();
    assert_eq!(world.relay.pending(&mailbox), 1);
    for trigger in [
        CollectTrigger::Foreground,
        CollectTrigger::Pull,
        CollectTrigger::Push,
    ] {
        let left = collect_on(&world, &world.issuer, trigger);
        assert_eq!(left.replaced, watched, "{trigger:?}");
        assert_eq!(left.not_reached, 0, "{trigger:?}");
        assert_eq!(left.epic1, 0, "{trigger:?}");
    }
    assert_eq!(world.relay.received("Attach"), attaches);
    assert_eq!(world.relay.pending(&mailbox), 1);

    let opened = collect_on(&world, &world.issuer, CollectTrigger::Open);
    assert_eq!(opened.replaced, 0);
    assert_eq!(opened.mailboxes, watched);
    assert_eq!(opened.epic1, 1);
    other.wallet.close();
}

/// A session that loses its socket and opens another attaches nothing the other socket took
/// over, and the next pass counts those mailboxes replaced and keeps the session.
#[test]
fn a_session_that_reconnects_leaves_a_replaced_mailbox_alone() {
    let world = World::new();
    let (_, watched, other) = taken_over(&world);
    let session = world.issuer.epicbox.pushed().get(HOME, ACK_GROUP).unwrap();
    let before = session.counters();
    let mut state = session.state();

    world.relay.disconnect_all();
    world.block_on(world.within(async {
        while session.counters().sockets_opened == before.sockets_opened
            || *state.borrow_and_update() != MuxState::Attached
        {
            state.changed().await.unwrap();
        }
    }));
    assert_eq!(session.counters().attaches, before.attaches);
    assert_eq!(session.counters().resumes, before.resumes);

    let left = collect_on(&world, &world.issuer, CollectTrigger::Foreground);
    assert_eq!(left.replaced, watched);
    assert_eq!(left.not_reached, 0);
    assert!(world.issuer.epicbox.pushed().get(HOME, ACK_GROUP).is_some());
    other.wallet.close();
}

/// A wallet started again on its store holds no replaced state: its first pass, whatever its
/// trigger, attaches the mailboxes and takes them from the other socket.
#[test]
fn a_wallet_started_again_takes_its_mailboxes_back() {
    for trigger in [CollectTrigger::Foreground, CollectTrigger::Push] {
        let world = World::new();
        let (_, watched, other) = taken_over(&world);
        let reopened = world
            .issuer
            .reopened(&world.node, &world.relay, &world.runtime);
        let attaches = world.relay.received("Attach");

        let report = collect_on(&world, &reopened, trigger);
        assert_eq!(report.replaced, 0, "{trigger:?}");
        assert_eq!(report.mailboxes, watched, "{trigger:?}");
        assert_eq!(report.not_reached, 0, "{trigger:?}");
        assert!(world.relay.received("Attach") > attaches, "{trigger:?}");
        reopened.wallet.close();
        other.wallet.close();
    }
}

/// Issues a link, lets a second instance of the issuer on the same store claim
/// its mailboxes, and runs a push pass that counts them replaced. Returns the link, the number of
/// mailboxes the issuer watched and the second instance.
fn taken_over(world: &World) -> (Epic1LinkIssued, usize, Party) {
    hold_acks(&world.issuer);
    let issued = world.issue_link(&world.issuer);
    let watched = collect_on(world, &world.issuer, CollectTrigger::Open).mailboxes;
    assert!(watched >= 1);
    let session = world.issuer.epicbox.pushed().get(HOME, ACK_GROUP).unwrap();
    let mut mux_events = session.events();

    // A second instance on the same store claims the same rows on a socket of its own.
    let other = world
        .issuer
        .reopened(&world.node, &world.relay, &world.runtime);
    collect_on(world, &other, CollectTrigger::Open);
    world.block_on(world.within(async {
        while session.replaced_keys().len() < watched {
            let _ = mux_events.recv().await.unwrap();
        }
    }));

    let marked = collect_on(world, &world.issuer, CollectTrigger::Push);
    assert_eq!(marked.replaced, watched);
    assert_eq!(marked.not_reached, 0);
    (issued, watched, other)
}

/// Pays the issuer's address of `account` by its bare text; returns the payment.
fn pay_address(world: &World, account: u32) -> Epic1Paid {
    let address = world
        .issuer
        .wallet
        .contact_book()
        .epic1_address(AccountIndex(account))
        .unwrap();
    world.pay_link(&format!("epic:{address}")).unwrap()
}

/// A restore against a relay that does not offer mux/1 fails with the pass's error, sends no
/// `Subscribe` and leaves the payment where it is.
#[test]
fn a_restore_against_a_relay_without_mux_fails_and_subscribes_nothing() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    world.pay_link(&issued.link).unwrap();
    let mailbox = mailbox_of(&issued.link);
    world.relay.offer_mux(false);
    let subscribes = world.relay.received("Subscribe");

    let twin = world.issuer_twin();
    let restored = world.block_on(twin.wallet.contact_book().epic1_restore(&relays(&twin)));
    assert!(
        matches!(restored, Err(ContactError::RelayNotRead(ref relay)) if relay == HOME),
        "{restored:?}"
    );
    assert_eq!(world.relay.received("Subscribe"), subscribes);
    assert_eq!(world.relay.pending(&mailbox), 1);
}

/// With the refuse switch on, a payment to the address is declined with the reason
/// `declined`, by its bare text and by a link the wallet made alike: a link is no request the
/// wallet keeps, so it opens no way past the switch.
#[test]
fn the_refuse_switch_declines_the_address() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    let issued = world.issue_link(&world.issuer);

    let bare = world
        .pay_link(&format!("epic:{}", world.address()))
        .unwrap();
    world.payer.fund(20, FUNDING);
    let linked = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 0);
    for paid in [bare, linked] {
        assert_eq!(world.refusal_reasons(paid.slate_id), ["declined"]);
    }
    assert_eq!(received(&world), 0);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
}

/// A file the user opens by hand is not unsolicited: with the refuse switch on, one sealed to
/// the public address, index 0, is taken.
#[test]
fn a_file_to_the_public_address_is_taken_with_the_refuse_switch_on() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    let book = world.issuer.wallet.contact_book();
    world.payer.fund(20, FUNDING);

    let text = world.s1_file(&world.address(), None, 2);
    world
        .block_on(book.sealed_receive(&text, ReceiveRequest::default()))
        .unwrap();
    assert_eq!(world.received_index(), Some(0));
}

/// The bare address asks no amount: a payment of any amount to it is taken, by mailbox and by
/// file.
#[test]
fn a_bare_address_takes_any_amount_by_mailbox_and_by_file() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    let address = world.address();
    world.payer.fund(20, FUNDING);

    world.pay_epic1(&format!("epic:{address}"), half()).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);

    let text = world.s1_file_of(&address, half(), 2);
    world
        .block_on(book.sealed_receive(&text, ReceiveRequest::default()))
        .unwrap();
    assert_eq!(received(&world), 2);
}

/// A link's `http` host keeps the link rule (letters and digits in each label): a hyphenated
/// one is refused when the link is made, since every reader would drop it.
#[test]
fn a_hyphenated_http_host_is_refused_in_a_link() {
    let world = World::new();
    assert_eq!(
        refusal(world.try_issue_link(&world.issuer, vec![http_entry("shop-demo.example.com")])),
        Epic1Refusal::LinkRelay
    );
}

/// A link may not carry an `http` entry on the local network unless the host is in the
/// wallet's relay list, on any port; a payer leaves such an entry out, and with no entry left
/// it cannot pay.
#[test]
fn a_local_network_http_host_is_refused() {
    let world = World::new();
    for host in ["192.168.1.5:8080", "printer.local:8080"] {
        assert_eq!(
            refusal(world.try_issue_link(&world.issuer, vec![http_entry(host)])),
            Epic1Refusal::LinkRelay,
            "{host}"
        );
    }

    let listed = helpers::adding(
        relays(&world.issuer),
        vec![RelayEndpoint::new(
            Domain::parse("printer.local").unwrap(),
            None,
            Security::Tls,
        )],
    );
    let issued = world
        .issuer
        .wallet
        .contact_book()
        .epic1_link(
            &listed,
            link_request(vec![http_entry("printer.local:8080")]),
        )
        .unwrap();
    assert!(
        issued.link.contains("http=printer.local"),
        "{}",
        issued.link
    );

    let local = format!("epic:{}?http=192.168.1.5%3A8080", issued.address);
    assert_eq!(refusal(world.pay_link(&local)), Epic1Refusal::CannotPay);
}

/// The events of `events` that `wanted` picks.
fn events_where(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    wanted: impl Fn(&Event) -> bool,
) -> usize {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| wanted(event))
        .count()
}

/// Queues `party`'s notice rows of the payment `slate_id` again, as a wallet stopped before it
/// marked them posted, and runs its outbox over `relays`: every relay gets each notice twice.
/// No outbox report counts a notice (ADR 0067), so the rows say that it went.
fn notices_again(world: &World, party: &Party, slate_id: SlateId, relays: &ContactRelays) {
    let notices: Vec<_> = rows(party, slate_id)
        .into_iter()
        .filter(|row| row.entry.notice)
        .collect();
    assert_eq!(notices.len(), 1);
    for row in notices {
        assert_eq!(row.entry.state, OutboxState::Posted);
        let entry = NativeOutboxEntry {
            state: OutboxState::Queued,
            attempts: 0,
            posted_at: None,
            ..row.entry
        };
        party.write(|repos| repos.update_native_outbox(row.id, &entry));
    }
    assert_eq!(due_over(world, party, relays).delivered, 0);
    assert!(
        rows(party, slate_id)
            .iter()
            .filter(|row| row.entry.notice)
            .all(|row| row.entry.state == OutboxState::Posted)
    );
}

/// Nothing went by the classic lane: no frame waits at `reader`'s index-0 mailbox, and
/// `writer` handed nothing to its classic Epicbox transport.
fn no_classic_frame(world: &World, reader: &Party, writer: &Party) {
    assert_eq!(world.relay.pending(&reader.address), 0);
    assert!(
        writer.delivered_to().is_empty(),
        "{:?}",
        writer.delivered_to()
    );
}

/// The payer's collect over its own relay and `shop.test`.
fn payer_collect_on_shop(world: &World) -> CollectReport {
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_collect(&on_shop(&world.payer), CollectTrigger::Open),
        )
        .unwrap()
}

/// The payment record the payer keeps for the payment `slate_id`, if any.
fn pay_record(world: &World, slate_id: SlateId) -> Option<String> {
    world
        .payer
        .read(|repos| repos.setting(&format!("epic1.pay.{slate_id}")))
}

/// A payer that finalizes tells the payee by a `posted` notice at the delivery mailbox of the
/// address it paid, on every relay of its list. The payee reads two copies on each relay and
/// raises one event, and its details show the report; the index-0 mailbox gets nothing.
#[test]
fn a_finalized_payment_is_told_once_at_the_delivery_mailbox_it_was_paid_at() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    let both = on_shop(&world.payer);
    let paid = pay_over(&world, &both, &issued.link);
    assert_eq!(taken_on_shop(&world), 1);
    let mut events = world.issuer.wallet.subscribe();

    payer_collect_on_shop(&world);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [1, 1]
    );
    notices_again(&world, &world.payer, paid.slate_id, &both);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [2, 2]
    );
    no_classic_frame(&world, &world.issuer, &world.payer);

    assert_eq!(taken_on_shop(&world), 0);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [0, 0]
    );
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentPosted(_)
        )),
        1
    );
    let receipts = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert!(receipts[0].sender_reported_posted_at.is_some());
    taken_on_shop(&world);
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentPosted(_)
        )),
        0
    );
}

/// The payee's details of an epic1 payment show the payer's `posted` report, taken from the
/// address key, whatever transport the payment is stored with (ADR 0067).
#[test]
fn an_epic1_payment_shows_its_payers_posted_report_in_its_details() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let both = on_shop(&world.payer);
    let paid = pay_over(&world, &both, &issued.link);
    assert_eq!(taken_on_shop(&world), 1);
    let receipt = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap()[0]
        .transaction
        .id;

    payer_collect_on_shop(&world);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    notices_again(&world, &world.payer, paid.slate_id, &both);
    taken_on_shop(&world);

    let details = world
        .block_on(world.issuer.wallet.transaction_details(receipt))
        .unwrap();
    assert_eq!(details.epic1_index, Some(0));
    assert_eq!(details.transaction.entry.state, TxState::Received);
    assert!(details.sender_reported_posted_at.is_some());
}

/// A payer that cancels a payment the payee answered tells the payee by a `cancelled` notice
/// at the delivery mailbox of the address it paid, on every relay of its list. The payee reads
/// two copies on each relay and raises one event; the index-0 mailbox gets nothing. The
/// collect after the one that sent the notice keeps nothing of the payment.
#[test]
fn a_cancelled_payment_is_told_once_at_the_delivery_mailbox_it_was_paid_at() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    let both = on_shop(&world.payer);
    let paid = pay_over(&world, &both, &issued.link);
    assert_eq!(taken_on_shop(&world), 1);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();
    let mut events = world.issuer.wallet.subscribe();

    payer_collect_on_shop(&world);
    assert!(world.node.pushed_transactions().is_empty());
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [1, 1]
    );
    notices_again(&world, &world.payer, paid.slate_id, &both);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [2, 2]
    );
    no_classic_frame(&world, &world.issuer, &world.payer);

    assert_eq!(taken_on_shop(&world), 0);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [0, 0]
    );
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentCancelled(_)
        )),
        1
    );
    let receipts = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].sender_reported_cancelled_at.is_some());
    taken_on_shop(&world);
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentCancelled(_)
        )),
        0
    );

    payer_collect_on_shop(&world);
    assert!(rows(&world.payer, paid.slate_id).is_empty());
    assert_eq!(pay_record(&world, paid.slate_id), None);
}

/// A payment whose post may have arrived keeps its S1 row through the cancel and an outbox
/// run before the next collect: the collect sends one `cancelled` to each relay, and the
/// collect after it keeps nothing of the payment.
#[test]
fn an_uncertain_payment_cancelled_before_an_outbox_run_is_still_told() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    let both = quick_on_shop(&world, &world.payer);
    let paid = pay_unanswered(&world, &both, &issued.link);
    assert_eq!(paid.uncertain, Some(0));
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();

    world.payer.clock.advance(LATER);
    due_over(&world, &world.payer, &both);
    let held = rows(&world.payer, paid.slate_id);
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].entry.state, OutboxState::Uncertain);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [0, 0]
    );

    payer_collect_on_shop(&world);
    assert_eq!(
        mailboxes
            .each_ref()
            .map(|mailbox| world.relay.pending(mailbox)),
        [1, 1]
    );
    let notices = rows(&world.payer, paid.slate_id)
        .into_iter()
        .filter(|row| row.entry.notice)
        .count();
    assert_eq!(notices, 1);

    payer_collect_on_shop(&world);
    assert!(rows(&world.payer, paid.slate_id).is_empty());
    assert_eq!(pay_record(&world, paid.slate_id), None);
}

/// The notice `body` sealed to the address `link` pays as a payer seals one, armored.
fn notice_to(link: &str, body: &str) -> String {
    let mut rng = rand::rngs::StdRng::seed_from_u64(31);
    armor(&sealed_notice(Network::Floonet, link, body.as_bytes(), &mut rng).unwrap())
}

/// A `posted` notice of the payment `slate_id` naming a kernel excess that is not the one its
/// S2 implies.
fn posted_body(slate_id: SlateId) -> String {
    format!(r#"{{"lepic":1,"type":"posted","slate_id":"{slate_id}","excess":"{OTHER_EXCESS}"}}"#)
}

fn cancelled_body(slate_id: SlateId) -> String {
    format!(r#"{{"lepic":1,"type":"cancelled","slate_id":"{slate_id}"}}"#)
}

/// A kernel excess no payment of these tests implies.
const OTHER_EXCESS: &str = "0950929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// The payer's notice rows of the payment `slate_id`.
fn notice_rows(party: &Party, slate_id: SlateId) -> usize {
    rows(party, slate_id)
        .into_iter()
        .filter(|row| row.entry.notice)
        .count()
}

/// A `posted` whose kernel excess is not the one the payee's S2 implies is dropped: no event,
/// no mark on the receipt, nothing left at the mailbox.
#[test]
fn a_posted_notice_with_another_excess_is_dropped() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    world.post_to_link(
        &issued.link,
        &notice_to(&issued.link, &posted_body(paid.slate_id)),
    );
    let mut events = world.issuer.wallet.subscribe();

    world.collect(&world.issuer);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentPosted(_)
        )),
        0
    );
    let receipts = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].sender_reported_posted_at, None);
}

/// A notice of a payment the payee never took is dropped: nothing stored, no event.
#[test]
fn a_notice_of_a_payment_never_taken_is_dropped() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let other = SlateId::from_bytes([9; 16]);
    for body in [posted_body(other), cancelled_body(other)] {
        world.post_to_link(&issued.link, &notice_to(&issued.link, &body));
    }
    let mut events = world.issuer.wallet.subscribe();

    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
    assert_eq!(events_where(&mut events, |_| true), 0);
    assert!(
        world
            .block_on(world.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .is_empty()
    );
}

/// A `cancelled` read before its payment arrived is dropped, and the payment is answered and
/// finalized as usual when it comes.
#[test]
fn a_cancelled_notice_read_before_its_payment_leaves_the_payment_alone() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let over = quick(&world, &world.payer);
    let paid = pay_unanswered(&world, &over, &issued.link);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
    world.post_to_link(
        &issued.link,
        &notice_to(&issued.link, &cancelled_body(paid.slate_id)),
    );
    let mut events = world.issuer.wallet.subscribe();

    assert_eq!(world.taken(&world.issuer), 0);
    assert!(
        world
            .block_on(world.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .is_empty()
    );

    world.confirm_tips();
    world.payer.clock.advance(LATER);
    assert_eq!(due_over(&world, &world.payer, &over).delivered, 1);
    assert_eq!(world.taken(&world.issuer), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentCancelled(_)
        )),
        0
    );
    let receipts = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(receipts[0].sender_reported_cancelled_at, None);
}

/// A payment the node could not take when it was finalized stays finalized and not posted: the
/// payer sends no `posted` then. It queues exactly one when the wallet posts it later, and none
/// when it is posted again (ADR 0067).
#[test]
fn a_payment_not_posted_at_finalize_is_told_posted_once_when_it_is_posted_later() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    world
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);

    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(world.payer_state(paid.tx_id), TxState::Finalized);
    assert_eq!(notice_rows(&world.payer, paid.slate_id), 0);

    world
        .block_on(world.payer.wallet.post(paid.tx_id, Propagation::Stem))
        .unwrap();
    assert_eq!(world.payer_state(paid.tx_id), TxState::Posted);
    world
        .block_on(world.payer.wallet.post(paid.tx_id, Propagation::Stem))
        .unwrap();
    world.collect(&world.payer);
    assert_eq!(notice_rows(&world.payer, paid.slate_id), 1);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 1);
}

/// A payer stopped between finalizing and marking the payment finalized only marks it when the
/// answer comes again: its `posted` went when the payment was posted, and no second one goes.
#[test]
fn a_payment_finalized_before_a_restart_is_told_posted_once() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let mailbox = mailbox_of(&issued.link);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(notice_rows(&world.payer, paid.slate_id), 1);
    assert_eq!(world.relay.pending(&mailbox), 1);

    // The write that marks the payment never happened.
    let key = format!("epic1.pay.{}", paid.slate_id);
    let mut record: serde_json::Value =
        serde_json::from_str(&pay_record(&world, paid.slate_id).unwrap()).unwrap();
    record["finalized"] = false.into();
    world
        .payer
        .write(|repos| repos.put_setting(&key, &record.to_string()));

    answer_again(&world, paid.slate_id);
    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(notice_rows(&world.payer, paid.slate_id), 1);
    assert_eq!(world.relay.pending(&mailbox), 1);
}

/// What comes to a delivery mailbox is read by its armor's marker: a payment armored as a notice
/// and a notice armored as a payment are dropped. Nothing is taken or stored and no event is
/// raised; the same payment armored as a payment is taken.
#[test]
fn a_payment_and_a_notice_under_each_others_marker_are_dropped() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let mailbox = mailbox_of(&issued.link);
    let paid = pay_unanswered(&world, &quick(&world, &world.payer), &issued.link);
    assert_eq!(world.relay.pending(&mailbox), 0);
    let s1 = dearmor(&rows(&world.payer, paid.slate_id)[0].entry.envelope).unwrap();
    let mut events = world.issuer.wallet.subscribe();

    world.post_to_link(&issued.link, &armor(&s1));
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&mailbox), 0);
    assert!(
        world
            .block_on(world.issuer.wallet.transactions(ACCOUNT))
            .unwrap()
            .is_empty()
    );

    world.post_to_link(&issued.link, &armored(&s1));
    assert_eq!(world.taken(&world.issuer), 1);
    let notice = dearmor(&notice_to(&issued.link, &cancelled_body(paid.slate_id))).unwrap();
    world.post_to_link(&issued.link, &armored(&notice));
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&mailbox), 0);
    assert_eq!(
        events_where(&mut events, |event| matches!(
            event,
            Event::PaymentCancelled(_)
        )),
        0
    );
    let receipts = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].sender_reported_cancelled_at, None);
}

/// An answer that reaches the payer after it cancelled the payment and forgot it is not read:
/// the cancel takes the payment's reply mailbox out of the watch set, so the answer waits at
/// the relay until the relay drops it. Nothing is finalized, no coins move, and the payer keeps
/// nothing of the payment.
#[test]
fn an_answer_after_the_payer_cancelled_and_forgot_the_payment_is_not_read() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    let reply = world.reply_mailbox(paid.slate_id);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();
    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(pay_record(&world, paid.slate_id), None);

    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.relay.pending(&reply), 1);
    world.collect(&world.payer);
    reconciled(&world, &world.payer);
    assert_eq!(rows_of(&world.payer, MailClass::Reply), []);
    assert_eq!(world.relay.pending(&reply), 1);
    assert!(world.node.pushed_transactions().is_empty());
    assert_eq!(world.payer_state(paid.tx_id), TxState::Cancelled);
    assert_eq!(world.payer_locked(), Amount::ZERO);
    assert!(rows(&world.payer, paid.slate_id).is_empty());
}

/// A payee that refuses a payment tells the payer by a `declined` notice at the reply mailbox
/// the payment named, on every relay of its list. The notice posted twice, the payer reads two
/// copies on each relay, erases the payment and raises one event. Its index-0 mailbox gets
/// nothing, it sends no `cancelled` back, and the collects that follow keep nothing of the
/// payment.
#[test]
fn a_declined_payment_is_told_once_by_its_reply_route_and_not_cancelled_back() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let both = on_shop(&world.payer);
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    let paid = world
        .block_on(world.payer.wallet.contact_book().epic1_pay(
            &both,
            Epic1PayRequest {
                link: issued.link.clone(),
                send: send(),
                slate_file: file,
                mailboxes: Vec::new(),
                require_receipt: false,
            },
        ))
        .unwrap();
    let replies = |world: &World| {
        ["relay.test", "shop.test"].map(|domain| {
            world
                .relay
                .pending(&world.reply_mailbox_on(paid.slate_id, domain))
        })
    };
    assert_eq!(taken_on_shop(&world), 0);
    assert_eq!(
        replies(&world),
        [1, 1],
        "answered on each relay of the list"
    );
    notices_again(
        &world,
        &world.issuer,
        paid.slate_id,
        &on_shop(&world.issuer),
    );
    assert_eq!(replies(&world), [2, 2]);
    no_classic_frame(&world, &world.payer, &world.issuer);
    let mut events = world.payer.wallet.subscribe();

    payer_collect_on_shop(&world);
    assert_eq!(replies(&world), [0, 0]);
    assert_payment_erased(&world, paid.tx_id);
    assert_eq!(declined_events(&mut events), 1);

    payer_collect_on_shop(&world);
    payer_collect_on_shop(&world);
    assert_eq!(declined_events(&mut events), 0);
    assert!(rows(&world.payer, paid.slate_id).is_empty());
    assert_eq!(pay_record(&world, paid.slate_id), None);
    assert_eq!(
        world.relay.pending(&mailbox_of(&issued.link)),
        0,
        "no cancelled goes back to the payee"
    );
    assert_eq!(
        world
            .relay
            .pending(&delivery_mailbox(&issued.link, "shop.test").unwrap()),
        0
    );
}

/// A payment that asks the payee for a payment proof by a key, sealed to an epic1 address and
/// posted to its delivery mailbox, is declined with the reason `declined` at the reply mailbox
/// it names; the payee signs nothing.
#[test]
fn a_payment_asking_for_a_proof_at_an_address_is_declined() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let slate_id = world.pay_asking_for_a_proof(&issued, 8);

    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 0);
    assert_eq!(world.refusal_reasons(slate_id), ["declined"]);
    assert_eq!(received(&world), 0);
}

impl World {
    /// Pays the address of `issued` with a payment that asks the payee for a payment proof by
    /// the payee's own payments key, sealed with the payer's reply route and posted to the
    /// address's delivery mailbox, which a payee declines. Returns the payment's slate id.
    pub(crate) fn pay_asking_for_a_proof(&self, issued: &Epic1LinkIssued, seed: u64) -> SlateId {
        let payments = *self
            .issuer
            .wallet
            .previous_onion_key()
            .unwrap()
            .public_key();
        let path = tempfile::tempdir().unwrap().keep().join("s1.json");
        let sent = self
            .block_on(self.payer.wallet.send(
                &support::file(),
                SendRequest {
                    payment_proof_recipient: Some(ProofAddress::from_bytes(payments).unwrap()),
                    ..send()
                },
                Delivery::Export {
                    to: Location::File(path.clone()),
                },
            ))
            .unwrap();
        let body = native_body_of(Network::Floonet, &std::fs::read(&path).unwrap()).unwrap();
        let reply = (
            self.reply_secret(sent.slate_id).public_key(),
            self.reply_mailbox(sent.slate_id).public_key().to_bytes(),
        );
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let sealed =
            sealed_payment(Network::Floonet, &issued.address, body, reply, &mut rng).unwrap();
        self.post_to_link(&issued.link, &armored(&sealed));
        sent.slate_id
    }
}

/// The amounts credited by the issuer's incoming transactions, smallest first.
fn credited(world: &World) -> Vec<u64> {
    let mut amounts: Vec<u64> = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap()
        .into_iter()
        .filter(|details| details.transaction.entry.direction == TxDirection::Incoming)
        .map(|details| details.transaction.entry.amount_credited.value())
        .collect();
    amounts.sort_unstable();
    amounts
}

/// Making a link writes nothing: a thousand links of as many amounts and messages leave the
/// settings, the watch set and the store's write count as they were.
#[test]
fn a_thousand_request_links_store_nothing() {
    let world = World::new();
    let book = world.issuer.wallet.contact_book();
    let listed = relays(&world.issuer);
    let state = || {
        let mut settings = world.issuer.read(|repos| repos.settings_with_prefix(""));
        settings.sort();
        let mut rows = world.issuer.read(|repos| repos.watch_set());
        rows.sort_by(|a, b| (&a.key_ref, &a.relay).cmp(&(&b.key_ref, &b.relay)));
        (settings, rows)
    };
    let before = state();
    let writes = world.issuer.writes();

    for i in 1..=1_000_u64 {
        book.epic1_link(
            &listed,
            Epic1LinkRequest {
                account: ACCOUNT,
                amount: Some(Amount::new(i)),
                message: Some(format!("item {i}")),
                entries: Vec::new(),
            },
        )
        .unwrap();
    }

    assert_eq!(world.issuer.writes(), writes);
    assert_eq!(state(), before);
}

/// A store a wallet of the numbered addresses left keeps its rows, unread: a payment sealed
/// to its address 3 is not read from the mailbox nor opened from a file, and a payment of any
/// amount to the address is taken. Only the address's row is watched.
#[test]
fn an_old_store_with_numbered_rows_takes_payments_at_zero_only() {
    let world = World::new();
    world.issuer.write(|repos| {
        for (key, value) in [
            ("epic1.issued.0", "3"),
            ("epic1.seen.0", "3"),
            ("epic1.last.0", "3"),
            ("epic1.open.0", "3"),
            ("epic1.link.0.3", r#"{"amount":500}"#),
            ("epic1.restored", "true"),
            ("epic1.past_gap.0", "true"),
            ("epic1.issuer", "true"),
        ] {
            repos.put_setting(key, value)?;
        }
        Ok(())
    });
    let book = world.issuer.wallet.contact_book();
    let numbered = address_any(world.issuer.seed(), Network::Floonet, ACCOUNT, 3)
        .unwrap()
        .encode();

    world.pay_link(&format!("epic:{numbered}")).unwrap();
    assert_eq!(world.taken(&world.issuer), 0);
    assert_eq!(world.relay.pending(&mailbox_of(&numbered)), 1);

    world.payer.fund(20, FUNDING);
    let text = world.s1_file(&numbered, None, 3);
    assert!(matches!(
        world.block_on(book.sealed_receive(&text, ReceiveRequest::default())),
        Err(ContactError::NotForThisInstall)
    ));

    world.payer.fund(21, FUNDING);
    world
        .pay_epic1(&format!("epic:{}", world.address()), half())
        .unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.received_index(), Some(0));
    assert_eq!(credited(&world), [AMOUNT / 2]);
    reconciled(&world, &world.issuer);
    assert_eq!(
        rows_of(&world.issuer, MailClass::Address),
        expected_address_rows(&[0])
    );
}

/// What a link asks only fills in the payer's form: a payment of another amount and message
/// than the link's is taken and finalized.
#[test]
fn a_request_link_paid_with_another_amount_and_message_is_taken() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world
        .pay_epic1(
            &issued.link,
            SendRequest {
                message: Some("tea".to_owned()),
                ..half()
            },
        )
        .unwrap();
    assert_eq!(paid.address, issued.address);

    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(credited(&world), [AMOUNT / 2]);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

/// A link is its fields: the same fields give the same text, another amount another text on
/// the same address.
#[test]
fn making_a_link_twice_gives_the_same_text() {
    let world = World::new();
    let first = world.issue_link(&world.issuer);
    let again = world.issue_link(&world.issuer);
    assert_eq!(again.link, first.link);
    assert_eq!(again.address, first.address);

    let other = world
        .issuer
        .wallet
        .contact_book()
        .epic1_link(
            &relays(&world.issuer),
            Epic1LinkRequest {
                amount: Some(Amount::new(AMOUNT / 2)),
                ..link_request(Vec::new())
            },
        )
        .unwrap();
    assert_ne!(other.link, first.link);
    assert_eq!(other.address, first.address);
}

/// A wallet restored from its phrase finds the payments waiting at the address of each
/// account in one pass, makes the links the first install makes, and takes a payment to one.
#[test]
fn a_restored_wallet_takes_a_payment_and_makes_a_link() {
    let world = World::new();
    let twin = world.issuer_twin();
    for party in [&world.issuer, &twin] {
        party.wallet.create_account("second").unwrap();
    }
    pay_address(&world, 0);
    world.payer.fund(20, FUNDING);
    pay_address(&world, 1);

    assert_eq!(
        world
            .block_on(twin.wallet.contact_book().epic1_restore(&relays(&twin)))
            .unwrap()
            .taken,
        2
    );
    let issued = world.issue_link(&twin);
    assert_eq!(issued.link, world.issue_link(&world.issuer).link);

    world.payer.fund(21, FUNDING);
    world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&twin), 1);
}
