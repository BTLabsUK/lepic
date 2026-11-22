// SPDX-License-Identifier: Apache-2.0
//! Epic1 payments in the outbox: the first post is made in the paying call and goes to every
//! relay of the list, a later post waits for a confirmed tip and never goes out at or past the
//! payment's cutoff, a post that may have arrived is posted again with the same bytes, the next
//! entry carries the same payment, and once the answer is taken the copies on the other relays
//! are cancelled. A restore reads every relay of the list.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::epic1::{collect_on, mailbox_of, received, reconciled, refusal, rows_of, send};
use crate::epicbox_world as world;
use crate::pairing_helpers::{adding, on, relays};

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::RELAY_RETENTION;
use lepic_epicbox::mock_relay::Unanswered;
use lepic_epicbox::{Connector, Domain, RelayEndpoint, RelayStream, Security};
use lepic_methods::epicbox::Epicbox;
use lepic_methods::http::{
    ClientSettings, Exposure, Host, Http, ListenLimits, ListenSettings, MAX_BODY_LEN, Receiver,
    Refusal, RpcClient, SocketRoute, listen_with, refuse, webpki_tls_config,
};
use lepic_methods::method::Method;
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::SlateId;
use lepic_store::{
    MailClass, MemoryStore, NativeOutboxEntry, OutboxState, StoreError, StoredNativeOutbox, TxId,
    TxState, WalletStore,
};
use lepic_transport::transport::BoxFuture;
use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};
use lepic_wallet::{Epic1AccountKeys, ProofKey, ReceiveRequest, Received, SharedRng, WalletPolicy};
use lepic_wallet_contacts::epic1_testing::delivery_mailbox;
use lepic_wallet_contacts::{
    CollectTrigger, ContactError, ContactRelays, DirectHandler, Epic1Keys, Epic1Paid,
    Epic1PayRequest, Epic1Refusal, InPersonDirect, InPersonInbox, InPersonInvoiceRequest,
    InPersonPostOutcome, InboxRoute, MailboxList, MethodId, NotReadReason, OUTBOX_STUCK_AFTER,
    OutboxReport, PeerDialFuture, PeerDialer, PeerStream, RelayMode, RouteEntry, WalletContacts,
};
use rand::SeedableRng;
use uuid::Uuid;
use world::{ACCOUNT, FUNDING, Party, World};

/// Longer than the back-off of a row posted once, shorter than a day.
pub(crate) const LATER: Duration = Duration::from_secs(60 * 60);

/// How long a post the relay does not answer is waited for.
const PATIENCE: Duration = Duration::from_secs(2);

/// The issuer's wallet as the host of its listener, receiving as `lepic listen` does.
struct Listening(Arc<World>);

impl Host for Listening {
    fn receive(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> BoxFuture<'_, Result<Received, Refusal>> {
        let method = Arc::clone(method);
        let wire = wire.clone();
        Box::pin(async move {
            self.0
                .issuer
                .wallet
                .receive_unsolicited(&method, &wire, request)
                .await
                .map_err(|error| refuse(&error))
        })
    }

    fn build_coinbase(
        &self,
        _request: CoinbaseRequest,
    ) -> BoxFuture<'_, Result<Coinbase, Refusal>> {
        Box::pin(async { Err(Refusal::Unavailable) })
    }

    fn received(&self, _received: &Received) {}

    fn refused(&self, _refusal: Refusal) {}
}

fn http() -> Http {
    let settings = ClientSettings {
        connect_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(30),
        max_response_bytes: MAX_BODY_LEN,
    };
    Http::new(RpcClient::new(settings, webpki_tls_config().unwrap()))
}

fn listen_limits() -> ListenLimits {
    ListenLimits {
        max_connections: 16,
        max_connections_per_address: 4,
        header_timeout: Duration::from_secs(10),
        body_timeout: Duration::from_secs(15),
        request_timeout: Duration::from_secs(60),
        answer_timeout: Duration::from_secs(10),
        requests_per_minute: 120,
        receives_per_minute: 30,
    }
}

/// `party`'s relays on a client that gives up on an unanswered post after [`PATIENCE`].
pub(crate) fn quick(world: &World, party: &Party) -> ContactRelays {
    let mut settings = world::settings();
    settings.response_timeout = PATIENCE;
    ContactRelays {
        epicbox: Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        ..relays(party)
    }
}

/// Reaches every relay but `domain`, whose connections fail before anything is written.
struct Unreachable {
    domain: &'static str,
    inner: Arc<dyn Connector>,
}

impl Connector for Unreachable {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        if endpoint.domain().as_str() == self.domain {
            Box::pin(async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) })
        } else {
            self.inner.connect(endpoint)
        }
    }
}

/// `party`'s relays on a client that cannot reach `domain`.
fn without(world: &World, party: &Party, domain: &'static str) -> ContactRelays {
    let connector = Arc::new(Unreachable {
        domain,
        inner: world.relay.connector(),
    });
    ContactRelays {
        epicbox: Epicbox::new(world::settings(), RelayNetwork::Floonet, connector),
        ..relays(party)
    }
}

fn shop() -> RelayEndpoint {
    RelayEndpoint::new(Domain::parse("shop.test").unwrap(), None, Security::Tls)
}

fn far() -> RelayEndpoint {
    RelayEndpoint::new(Domain::parse("far.test").unwrap(), None, Security::Tls)
}

/// `party`'s relays with `shop.test` in the relay list.
pub(crate) fn on_shop(party: &Party) -> ContactRelays {
    adding(relays(party), vec![shop()])
}

/// `party`'s relays with `shop.test` listed after its own relay, on a client that gives up on
/// an unanswered post after [`PATIENCE`].
pub(crate) fn quick_on_shop(world: &World, party: &Party) -> ContactRelays {
    adding(quick(world, party), vec![shop()])
}

/// `party`'s relays with `shop.test` listed, on a client that cannot reach `domain`.
fn without_on_shop(world: &World, party: &Party, domain: &'static str) -> ContactRelays {
    adding(without(world, party, domain), vec![shop()])
}

/// The payments the issuer takes reading its own relay and `shop.test`.
pub(crate) fn taken_on_shop(world: &World) -> usize {
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_collect(&on_shop(&world.issuer), CollectTrigger::Open),
        )
        .unwrap()
        .epic1
}

/// The payer pays `link` over `relays`.
pub(crate) fn pay_over(world: &World, relays: &ContactRelays, link: &str) -> Epic1Paid {
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    world
        .block_on(world.payer.wallet.contact_book().epic1_pay(
            relays,
            Epic1PayRequest {
                link: link.to_owned(),
                send: send(),
                slate_file: file,
                mailboxes: Vec::new(),
            },
        ))
        .unwrap()
}

/// The payer pays `link` over `relays` while the relay leaves every post unanswered: the post
/// may have arrived, and was not stored.
pub(crate) fn pay_unanswered(world: &World, relays: &ContactRelays, link: &str) -> Epic1Paid {
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    world.relay.set_unanswered(Unanswered::PostSlate, true);
    let paid = world.block_on(world.payer.wallet.contact_book().epic1_pay(
        relays,
        Epic1PayRequest {
            link: link.to_owned(),
            send: send(),
            slate_file: file,
            mailboxes: Vec::new(),
        },
    ));
    world.relay.set_unanswered(Unanswered::PostSlate, false);
    paid.unwrap()
}

/// The outbox rows of the payment `slate_id`, oldest first.
pub(crate) fn rows(party: &Party, slate_id: SlateId) -> Vec<StoredNativeOutbox> {
    let mut rows =
        party.read(|repos| repos.native_outbox_of(Uuid::from_bytes(*slate_id.as_bytes())));
    rows.sort_by_key(|row| row.id);
    rows
}

/// One outbox run of `party`, as the app starts it.
fn due(world: &World, party: &Party) -> OutboxReport {
    due_over(world, party, &quick(world, party))
}

/// One outbox run of `party` over `relays`.
pub(crate) fn due_over(world: &World, party: &Party, relays: &ContactRelays) -> OutboxReport {
    world
        .block_on(party.wallet.contact_book().contacts_outbox_deliver(relays))
        .unwrap()
}

/// The payer moves the payment `slate_id` to its next route, its relays being `shop.test` after
/// its own.
fn post_next(world: &World, slate_id: SlateId) -> Result<Epic1Paid, ContactError> {
    world.block_on(
        world
            .payer
            .wallet
            .contact_book()
            .epic1_post_next(&quick_on_shop(world, &world.payer), slate_id),
    )
}

/// Gives `party` a second coin, at its next key.
fn fund_again(party: &Party) {
    let next = party
        .read(|repos| repos.account(ACCOUNT))
        .unwrap()
        .next_child;
    party.fund(next, FUNDING);
}

/// Stores `height` as the tip `party` confirmed, as a refresh does.
fn set_tip(party: &Party, height: u64) {
    let seen_at = party
        .wallet
        .confirmed_tip()
        .unwrap()
        .unwrap()
        .seen_at
        .as_second();
    party.write(|repos| repos.put_setting("chain.reference", &format!("{height} {seen_at}")));
}

/// A restored wallet that never refreshed pays: the first post is made in the paying call. A
/// payment whose post may have arrived, and was lost, is not posted again until a refresh
/// confirmed a tip; then it is posted again with the same bytes and finalized once.
#[test]
fn a_wallet_without_a_tip_posts_in_the_paying_call_and_waits_for_a_tip_to_post_again() {
    let world = World::new();
    assert!(world.payer.wallet.confirmed_tip().unwrap().is_none());

    let first = world.issue_link(&world.issuer);
    let paid_first = world.pay_link(&first.link).unwrap();
    assert_eq!(paid_first.posted, Some(0));
    assert_eq!(
        rows(&world.payer, paid_first.slate_id)[0].entry.state,
        OutboxState::Posted
    );

    fund_again(&world.payer);
    let second = world.issue_link(&world.issuer);
    // Both links carry the account's one address, so its mailbox holds the first payment.
    let mailbox = mailbox_of(&second.link);
    assert_eq!(mailbox, mailbox_of(&first.link));
    let before = world.relay.pending(&mailbox);
    let posts = world.relay.received("PostSlate");
    let paid = pay_unanswered(&world, &quick(&world, &world.payer), &second.link);
    assert_eq!(paid.posted, None);
    assert_eq!(paid.uncertain, Some(0));
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
    assert_eq!(world.relay.pending(&mailbox), before);

    // Its back-off is over, but without a confirmed tip the row waits.
    world.payer.clock.advance(LATER);
    assert_eq!(due(&world, &world.payer), OutboxReport::default());
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
    let held = rows(&world.payer, paid.slate_id);
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].entry.state, OutboxState::Uncertain);
    assert_eq!(held[0].entry.attempts, 1);

    world.confirm_tips();
    let report = due(&world, &world.payer);
    assert_eq!(report.delivered, 1);
    assert_eq!(world.relay.received("PostSlate"), posts + 2);
    assert_eq!(world.relay.pending(&mailbox), before + 1);
    let again = rows(&world.payer, paid.slate_id);
    assert_eq!(again.len(), 1, "posted again on the same row");
    assert_eq!(again[0].entry.envelope, held[0].entry.envelope);
    assert_eq!(again[0].entry.attempts, 2);
    assert_eq!(again[0].entry.state, OutboxState::Posted);

    // Both payments are taken; each is finalized once.
    assert_eq!(world.taken(&world.issuer), 2);
    assert_eq!(world.answers_posted(), 2);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 2);
    assert_eq!(received(&world), 2);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
    assert_ne!(world.payer_state(paid_first.tx_id), TxState::Sent);
}

/// A payment whose post may have arrived is not posted again at its cutoff, and is not moved
/// to the next relay at or past it: nothing is sent.
#[test]
fn a_payment_at_or_past_its_cutoff_is_not_posted_again() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let shop = delivery_mailbox(&issued.link, "shop.test").unwrap();
    let paid = pay_unanswered(&world, &quick_on_shop(&world, &world.payer), &issued.link);
    assert_eq!(paid.posted, None);
    assert_eq!(paid.uncertain, Some(0));
    let posts = world.relay.received("PostSlate");
    let cutoff = rows(&world.payer, paid.slate_id)[0]
        .entry
        .cutoff_height
        .unwrap()
        .value();

    set_tip(&world.payer, cutoff);
    world.payer.clock.advance(LATER);
    let report = due(&world, &world.payer);
    assert_eq!(report.stuck, 1);
    assert_eq!(world.relay.received("PostSlate"), posts);
    let ended = rows(&world.payer, paid.slate_id);
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].entry.state, OutboxState::Failed);

    for tip in [cutoff, cutoff + 1] {
        set_tip(&world.payer, tip);
        assert_eq!(
            refusal(post_next(&world, paid.slate_id)),
            Epic1Refusal::NoMoreEntries
        );
    }
    assert_eq!(world.relay.received("PostSlate"), posts);
    assert_eq!(rows(&world.payer, paid.slate_id).len(), 1);
    assert_eq!(world.relay.pending(&shop), 0);
}

/// A payment whose post may have arrived on every relay of the list has no next route: after
/// its back-off it is posted again to each relay, with the same bytes on the same row. The
/// payee takes it once and the payer finalizes once.
#[test]
fn an_uncertain_payment_is_posted_again_to_every_relay_with_the_same_bytes() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    let paid = pay_unanswered(&world, &quick_on_shop(&world, &world.payer), &issued.link);
    assert_eq!(paid.posted, None);
    assert_eq!(paid.uncertain, Some(0));
    let first = rows(&world.payer, paid.slate_id);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].entry.state, OutboxState::Uncertain);

    // It waits on its route: a run before its back-off is over posts nothing.
    let posts = world.relay.received("PostSlate");
    let both = quick_on_shop(&world, &world.payer);
    assert_eq!(
        due_over(&world, &world.payer, &both),
        OutboxReport::default()
    );
    assert_eq!(world.relay.received("PostSlate"), posts);
    assert_eq!(
        refusal(post_next(&world, paid.slate_id)),
        Epic1Refusal::NoMoreEntries
    );

    world.payer.clock.advance(LATER);
    assert_eq!(due_over(&world, &world.payer, &both).delivered, 1);
    assert_eq!(world.relay.received("PostSlate"), posts + 2);
    let again = rows(&world.payer, paid.slate_id);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].entry.envelope, first[0].entry.envelope);
    assert_eq!(again[0].entry.route_value, first[0].entry.route_value);
    assert_eq!(again[0].entry.state, OutboxState::Posted);
    for mailbox in &mailboxes {
        assert_eq!(world.relay.pending(mailbox), 1);
    }

    assert_eq!(taken_on_shop(&world), 1);
    assert_eq!(world.answers_posted(), 1);
    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(received(&world), 1);
}

/// One payment whose envelope arrived on two relays the payee watches is taken once and
/// answered once, on every relay of the payee's list it reaches; reading the other copy later
/// posts the stored answer again to every relay, once each, and the payer finalizes once.
#[test]
fn t2_a_payment_read_on_two_relays_is_taken_and_answered_once() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    // The payment goes to the delivery mailbox on each relay of the list.
    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 2);
    for mailbox in &mailboxes {
        assert_eq!(world.relay.pending(mailbox), 1);
    }
    let replies = |world: &World| {
        ["relay.test", "shop.test"].map(|domain| {
            world
                .relay
                .pending(&world.reply_mailbox_on(paid.slate_id, domain))
        })
    };

    // The payee reads shop.test first: its own relay cannot be reached.
    let first = world
        .block_on(world.issuer.wallet.contact_book().contacts_collect(
            &without_on_shop(&world, &world.issuer, "relay.test"),
            CollectTrigger::Open,
        ))
        .unwrap();
    assert_eq!(first.epic1, 1);
    assert_eq!(world.relay.pending(&mailboxes[1]), 0);
    assert_eq!(replies(&world), [0, 1]);

    assert_eq!(taken_on_shop(&world), 0);
    assert_eq!(world.relay.pending(&mailboxes[0]), 0, "the copy is read");
    assert_eq!(
        replies(&world),
        [1, 2],
        "and the stored answer posted again on each relay, the copy owed to relay.test with it"
    );
    // The copy is answered with the stored answer's bytes, to the reply key on the list, from
    // the answer's own row made due again.
    let answer = rows(&world.issuer, paid.slate_id);
    assert_eq!(answer.len(), 1);
    assert!(
        !answer[0].entry.route_value.contains('@'),
        "{}",
        answer[0].entry.route_value
    );
    assert_eq!(world.answers_posted(), 1);

    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(received(&world), 1);
}

/// A cancelled payment is not posted again. The next collect sends its `cancelled` notice on
/// the payment's route and keeps the payment's row for it; the collect after deletes both.
#[test]
fn a_cancelled_payment_is_not_posted_again() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);
    assert_eq!(paid.posted, Some(0));
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();
    let posts = world.relay.received("PostSlate");

    assert_eq!(
        refusal(post_next(&world, paid.slate_id)),
        Epic1Refusal::NoPayment
    );
    assert_eq!(world.relay.received("PostSlate"), posts);
    let payment = rows(&world.payer, paid.slate_id);
    assert_eq!(payment.len(), 1);

    // The collect posts the notice on the wallet's one relay, and not the payment.
    world.collect(&world.payer);
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
    let kept = rows(&world.payer, paid.slate_id);
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].entry, payment[0].entry);
    assert_eq!(kept[1].entry.stage, None);

    world.collect(&world.payer);
    assert!(rows(&world.payer, paid.slate_id).is_empty());
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
}

/// A cancelled payment no relay took gets no `cancelled` notice, whether it went to a link's
/// entry or every post was refused; the collects that follow its cancel keep nothing of it.
#[test]
fn a_cancelled_payment_no_relay_took_sends_no_notice_and_is_not_kept() {
    for on_entry in [true, false] {
        let world = World::new();
        world.confirm_tips();
        let issued = world.issue_link(&world.issuer);
        let mailbox = mailbox_of(&issued.link);
        let link = if on_entry {
            on_tor(&issued.link)
        } else {
            world.relay.set_post_refused(&mailbox);
            issued.link.clone()
        };
        let paid = pay_over(&world, &relays(&world.payer), &link);
        assert_eq!(paid.posted, None);
        world
            .block_on(world.payer.wallet.cancel(paid.tx_id))
            .unwrap();
        let posts = world.relay.received("PostSlate");

        world.collect(&world.payer);
        world.collect(&world.payer);
        assert!(rows(&world.payer, paid.slate_id).is_empty(), "{on_entry}");
        assert_eq!(
            world
                .payer
                .read(|repos| repos.setting(&format!("epic1.pay.{}", paid.slate_id))),
            None
        );
        assert_eq!(world.relay.received("PostSlate"), posts);
        assert_eq!(world.relay.pending(&mailbox), 0);
    }
}

/// Posts the issuer's answer to the payment `slate_id` again, as a wallet stopped before it
/// marked the post done does: its outbox row is queued once more, and the outbox of the wallet
/// opened again posts it.
pub(crate) fn answer_again(world: &World, slate_id: SlateId) {
    let row = rows(&world.issuer, slate_id).remove(0);
    let entry = NativeOutboxEntry {
        state: OutboxState::Queued,
        attempts: 0,
        posted_at: None,
        ..row.entry
    };
    world
        .issuer
        .write(|repos| repos.update_native_outbox(row.id, &entry));
    let issuer = world
        .issuer
        .reopened(&world.node, &world.relay, &world.runtime);
    assert_eq!(due_over(world, &issuer, &relays(&issuer)).delivered, 1);
}

/// The answer offered again to a payer whose transaction is finalized, though its payment was
/// not marked finalized (stopped between the two), is not finalized again: the mark is set.
#[test]
fn an_answer_to_a_finalized_payment_not_marked_so_is_not_finalized_again() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(world.answers_posted(), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let state = world.payer_state(paid.tx_id);

    let key = format!("epic1.pay.{}", paid.slate_id);
    let finalized = |party: &Party| {
        let text = party.read(|repos| repos.setting(&key)).unwrap();
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["finalized"].clone()
    };
    assert_eq!(finalized(&world.payer), true);
    let mut record: serde_json::Value =
        serde_json::from_str(&world.payer.read(|repos| repos.setting(&key)).unwrap()).unwrap();
    record["finalized"] = false.into();
    world
        .payer
        .write(|repos| repos.put_setting(&key, &record.to_string()));

    answer_again(&world, paid.slate_id);
    let report = collect_on(&world, &world.payer, CollectTrigger::Open);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.payer_state(paid.tx_id), state);
    assert_eq!(finalized(&world.payer), true);
}

/// A payment record written by an earlier release, with the reply relay and outbox fields it
/// kept then, still reads: the payment is listed, the wallet opens, its outbox runs and its
/// answer is finalized once.
#[test]
fn a_payment_stored_with_its_reply_relay_still_reads() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    let key = format!("epic1.pay.{}", paid.slate_id);
    let mut record: serde_json::Value =
        serde_json::from_str(&world.payer.read(|repos| repos.setting(&key)).unwrap()).unwrap();
    record["reply_relay"] = "relay.test:80".into();
    record["next"] = 1.into();
    record["posted"] = 0.into();
    world
        .payer
        .write(|repos| repos.put_setting(&key, &record.to_string()));

    let payer = world
        .payer
        .reopened(&world.node, &world.relay, &world.runtime);
    let book = payer.wallet.contact_book();
    let stored = world
        .block_on(book.epic1_payment(paid.slate_id))
        .unwrap()
        .unwrap();
    assert_eq!(stored.tx_id, paid.tx_id);
    payer.clock.advance(LATER);
    due_over(&world, &payer, &relays(&payer));
    assert_eq!(world.taken(&world.issuer), 1);
    world.collect(&payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(received(&world), 1);
}

/// A relay that refuses the post leaves the payment posted on the relay that took it: one row,
/// posted, whose attempts name that relay alone. The host hears nothing: the payment went on
/// its first post.
#[test]
fn a_relay_that_refuses_leaves_the_payment_posted_on_the_relay_that_took_it() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    // Posts to the payer's own relay are refused; the payer still reads its answer there.
    world.relay.set_domain_refused("relay.test");
    let mut events = world.payer.wallet.subscribe();

    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);

    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert!(
        paid.attempts[0].host.starts_with("shop.test"),
        "{}",
        paid.attempts[0].host
    );
    let one = rows(&world.payer, paid.slate_id);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].entry.state, OutboxState::Posted);
    assert_eq!(delivery_changes(&mut events), []);
    assert_eq!(world.relay.pending(&mailboxes[0]), 0);
    assert_eq!(world.relay.pending(&mailboxes[1]), 1);
    assert_eq!(taken_on_shop(&world), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

/// A link without entries is paid through the delivery mailbox on every relay of the list, in
/// one row; with the payer's own relay out of reach, on the others. The payee, watching both,
/// takes each payment once.
#[test]
fn a_link_without_entries_is_paid_on_every_relay_of_the_list() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let first = world.issue_link(&world.issuer);
    let paid = pay_over(&world, &on_shop(&world.payer), &first.link);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 2);
    let posted = rows(&world.payer, paid.slate_id);
    assert_eq!(posted.len(), 1);
    assert!(
        !posted[0].entry.route_value.contains('@'),
        "{}",
        posted[0].entry.route_value
    );
    assert_eq!(world.relay.pending(&mailbox_of(&first.link)), 1);
    assert_eq!(
        world
            .relay
            .pending(&delivery_mailbox(&first.link, "shop.test").unwrap()),
        1
    );

    fund_again(&world.payer);
    let issued = world.issue_link(&world.issuer);
    let mailboxes = [
        mailbox_of(&issued.link),
        delivery_mailbox(&issued.link, "shop.test").unwrap(),
    ];
    let posts = world.relay.received("PostSlate");
    // Both links carry the account's one address, so its mailboxes hold the first payment.
    let before = mailboxes
        .each_ref()
        .map(|mailbox| world.relay.pending(mailbox));

    let paid = pay_over(
        &world,
        &without_on_shop(&world, &world.payer, "relay.test"),
        &issued.link,
    );

    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
    let one = rows(&world.payer, paid.slate_id);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].entry.state, OutboxState::Posted);
    assert_eq!(world.relay.pending(&mailboxes[0]), before[0]);
    assert_eq!(world.relay.pending(&mailboxes[1]), before[1] + 1);
    assert_eq!(taken_on_shop(&world), 2);
}

/// `party`'s relays with `shop.test` as its own relay and no other: a wallet that reads one
/// relay, not the payer's.
fn shop_only(world: &World, party: &Party) -> ContactRelays {
    let mut settings = world::settings();
    settings.endpoint =
        RelayEndpoint::new(Domain::parse("shop.test").unwrap(), None, Security::Tls);
    on(
        Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        relays(party),
    )
}

/// A payer whose own relay is not the payee's reaches the payee through the relay list they
/// share: the payment goes to every relay of the payer's list, the payee reading its own relay
/// takes it there and answers there, and the payer, watching for the answer on each relay it
/// posted to, finalizes once.
#[test]
fn payer_and_payee_on_different_relays_of_a_shared_list() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 2);

    let taken = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_collect(&shop_only(&world, &world.issuer), CollectTrigger::Open),
        )
        .unwrap()
        .epic1;
    assert_eq!(taken, 1);
    assert_eq!(world.answers_posted(), 1);

    // The payer watches for the answer on both relays it posted to, though it lists one.
    reconciled(&world, &world.payer);
    let watched: Vec<String> = rows_of(&world.payer, MailClass::Reply)
        .into_iter()
        .map(|row| row.relay)
        .collect();
    assert_eq!(watched, ["relay.test:80", "shop.test"]);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
}

/// The payer reads the answers of `party`'s reply mailboxes on its own relay and `shop.test`,
/// on a client that gives up on an unanswered frame after [`PATIENCE`].
fn payer_collect_on_shop(world: &World) {
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contacts_collect(&quick_on_shop(world, &world.payer), CollectTrigger::Open),
        )
        .unwrap();
}

/// The payments the issuer takes reading `shop.test` alone.
/// A payer whose list keeps no shipped mailbox is refused before anything is stored, with the
/// shipped mailboxes named; the same payment with a mailbox given posts there alone, where the
/// payee reading it takes it.
#[test]
fn a_payer_sharing_no_mailbox_is_refused_until_it_gives_one() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let own = world.payer.epicbox.settings().endpoint.clone();
    let apart = relays(&world.payer)
        .with_mailboxes(MailboxList::new(vec![own.clone()], vec![far()], vec![own]).unwrap());
    let pay = |mailboxes: Vec<RelayEndpoint>| {
        world.block_on(world.payer.wallet.contact_book().epic1_pay(
            &apart,
            Epic1PayRequest {
                link: issued.link.clone(),
                send: send(),
                slate_file: tempfile::tempdir().unwrap().keep().join("s1.tx"),
                mailboxes,
            },
        ))
    };

    let refused = pay(Vec::new());
    assert!(
        matches!(&refused, Err(ContactError::NoSharedMailbox { shipped }) if shipped == &["relay.test:80"]),
        "{refused:?}"
    );
    assert!(
        world
            .payer
            .read(|repos| repos.transactions(ACCOUNT))
            .is_empty()
    );

    let paid = pay(vec![shop()]).unwrap();
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(taken_on_shop_only(&world), 1);
}

fn taken_on_shop_only(world: &World) -> usize {
    world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .contacts_collect(&shop_only(world, &world.issuer), CollectTrigger::Open),
        )
        .unwrap()
        .epic1
}

/// A payment posted to two relays under one relay transaction id, answered on one, is
/// finalized; then its copy on the other relay is cancelled under that id. The relay the
/// answer was read on gets no cancel, and a later read sends none.
#[test]
fn the_other_copy_is_cancelled_after_the_answer() {
    let world = World::new();
    world.relay.set_version(Some("3.1.0"));
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);
    assert_eq!(paid.attempts.len(), 2);
    let txids = world.relay.posted_txids();
    assert_eq!(txids.len(), 1, "both copies go under one transaction id");
    assert_eq!(taken_on_shop_only(&world), 1);
    assert!(!world.relay.is_cancelled(&txids[0]));

    payer_collect_on_shop(&world);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
    assert!(world.relay.is_cancelled_on("relay.test", &txids[0]));
    assert!(!world.relay.is_cancelled_on("shop.test", &txids[0]));
    assert_eq!(
        world.relay.received_on("relay.test", "CancelTx"),
        1,
        "relay.test is told: it holds the copy nobody answered"
    );
    assert_eq!(
        world.relay.received_on("shop.test", "CancelTx"),
        0,
        "shop.test is not told: the answer was read there"
    );

    payer_collect_on_shop(&world);
    assert_eq!(world.relay.received("CancelTx"), 1);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

/// A relay without the cancel protocol is sent no cancel: the payment answered on the other
/// relay is finalized once, its outbox row stays posted, and a later read finalizes nothing
/// more.
#[test]
fn no_cancel_is_sent_to_a_relay_without_the_cancel_protocol() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);
    assert_eq!(taken_on_shop_only(&world), 1);

    payer_collect_on_shop(&world);
    assert_eq!(world.relay.received("CancelTx"), 0);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
    let states: Vec<OutboxState> = staged_rows(&world.payer, paid.slate_id)
        .into_iter()
        .map(|row| row.entry.state)
        .collect();
    assert_eq!(states, [OutboxState::Posted]);

    payer_collect_on_shop(&world);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

/// Sets the state of the transaction `tx_id` in `store` to `state` on each connection to a
/// relay: the answer another read stores while a post goes.
struct SettlesOnConnect {
    store: MemoryStore,
    tx_id: TxId,
    state: TxState,
    inner: Arc<dyn Connector>,
}

impl Connector for SettlesOnConnect {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        self.store
            .write(|repos| -> Result<(), StoreError> {
                let mut entry = repos.transaction(self.tx_id)?.unwrap();
                entry.state = self.state;
                repos.update_transaction(self.tx_id, &entry)
            })
            .unwrap();
        self.inner.connect(endpoint)
    }
}

/// A payment answered on one relay, its row posted again to the other, as a wallet stopped
/// before it marked the post done does, while the answer is stored: the other relay refuses the
/// copy cancelled after the answer, and the row ends posted, with no delivery news and nothing
/// stuck, the finalized transaction being the news.
#[test]
fn a_post_refused_as_cancelled_after_the_answer_ends_quietly() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_version(Some("3.1.0"));
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let paid = pay_over(&world, &on_shop(&world.payer), &issued.link);
    assert_eq!(paid.posted, Some(0));
    let txids = world.relay.posted_txids();
    assert_eq!(taken_on_shop_only(&world), 1);
    payer_collect_on_shop(&world);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert!(world.relay.is_cancelled_on("relay.test", &txids[0]));
    let answered = world.payer_state(paid.tx_id);
    assert_ne!(answered, TxState::Sent);

    // The row is queued again while the answer is not yet stored, and the answer is stored
    // while its post goes: the payer's relay refuses the copy it cancelled.
    let row = staged_rows(&world.payer, paid.slate_id).remove(0);
    let entry = NativeOutboxEntry {
        state: OutboxState::Queued,
        attempts: 0,
        posted_at: None,
        ..row.entry
    };
    world
        .payer
        .write(|repos| repos.update_native_outbox(row.id, &entry));
    world.payer.write(|repos| {
        let mut entry = repos.transaction(paid.tx_id)?.unwrap();
        entry.state = TxState::Sent;
        repos.update_transaction(paid.tx_id, &entry)
    });
    let connector = Arc::new(SettlesOnConnect {
        store: world.payer.store(),
        tx_id: paid.tx_id,
        state: answered,
        inner: world.relay.connector(),
    });
    let mut settings = world::settings();
    settings.response_timeout = PATIENCE;
    let relays = ContactRelays {
        epicbox: Epicbox::new(settings, RelayNetwork::Floonet, connector),
        ..relays(&world.payer)
    };
    let mut events = world.payer.wallet.subscribe();
    let posts = world.relay.received_on("relay.test", "PostSlate");
    world.payer.clock.advance(LATER);
    let report = due_over(&world, &world.payer, &relays);

    assert_eq!(
        world.relay.received_on("relay.test", "PostSlate"),
        posts + 1,
        "the copy is posted again"
    );
    let settled = staged_rows(&world.payer, paid.slate_id);
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].entry.state, OutboxState::Posted);
    assert_eq!(delivery_changes(&mut events), []);
    assert_eq!(report.stuck, 0);
    assert_eq!(report.failed, 0);
}

/// Two payments answered in one read owe a cancel each. A relay that takes the cancels and
/// never answers them holds the read up for one response timeout, not one per cancel, and both
/// answers are stored and acknowledged.
#[test]
fn two_answers_read_together_are_stored_though_no_cancel_is_answered() {
    let world = World::new();
    world.relay.set_version(Some("3.1.0"));
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let first = pay_over(&world, &on_shop(&world.payer), &issued.link);
    world.payer.fund(20, FUNDING);
    let second = pay_over(
        &world,
        &on_shop(&world.payer),
        &format!("epic:{}", issued.address),
    );
    assert_eq!(taken_on_shop_only(&world), 2);

    world.relay.set_unanswered(Unanswered::CancelTx, true);
    let started = Instant::now();
    payer_collect_on_shop(&world);
    let took = started.elapsed();
    assert_eq!(world.relay.received("CancelTx"), 2);
    assert!(
        took < PATIENCE * 2,
        "the cancels ran one after the other: {took:?}"
    );
    assert_eq!(world.node.pushed_transactions().len(), 2);
    for paid in [&first, &second] {
        assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
        assert_eq!(
            world
                .relay
                .pending(&world.reply_mailbox_on(paid.slate_id, "shop.test")),
            0
        );
    }
}

/// A restore reads the delivery mailboxes on every relay of the list, not only on the wallet's
/// own: a payment the payer posted only to a mailbox the payee added is found there.
#[test]
fn a_restore_finds_a_payment_posted_to_an_added_mailbox_only() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let address = world
        .issuer
        .wallet
        .contact_book()
        .epic1_address(ACCOUNT)
        .unwrap();
    let link = format!("epic:{address}");
    let paid = pay_over(&world, &shop_only(&world, &world.payer), &link);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);

    let twin = world.issuer_twin();
    let restored = world.block_on(twin.wallet.contact_book().epic1_restore(&on_shop(&twin)));
    assert_eq!(restored.unwrap().taken, 1);
}

/// A restore with one of three mailboxes down reads the other two, takes the payment waiting
/// on the wallet's own and names the one it could not read.
#[test]
fn a_restore_with_one_of_three_mailboxes_down_completes_and_names_it() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    world.pay_link(&issued.link).unwrap();
    let twin = world.issuer_twin();
    let three = adding(without(&world, &twin, "far.test"), vec![shop(), far()]);

    let restored = world
        .block_on(twin.wallet.contact_book().epic1_restore(&three))
        .unwrap();

    assert_eq!(restored.taken, 1);
    let not_read: Vec<_> = restored
        .not_read
        .iter()
        .map(|mailbox| (mailbox.host.as_str(), mailbox.reason))
        .collect();
    assert_eq!(not_read, [("far.test:443", NotReadReason::NotAnswering)]);
}

/// A payment whose only entry cannot be reached stays queued and is tried again after its
/// back-off. A day on it is marked stuck, still tried, and `epic1 post-next` may post it at
/// once; it ends at its cutoff, never sent.
#[test]
fn an_unreachable_last_entry_is_tried_past_a_day_and_ends_at_its_cutoff() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let unreachable = without(&world, &world.payer, "relay.test");
    let posts = world.relay.received("PostSlate");
    let book = world.payer.wallet.contact_book();

    let paid = pay_over(&world, &unreachable, &issued.link);

    assert_eq!(paid.posted, None);
    assert_eq!(paid.uncertain, None);
    let queued = rows(&world.payer, paid.slate_id);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].entry.state, OutboxState::Queued);
    assert_eq!(queued[0].entry.attempts, 1);
    let post = world
        .block_on(book.payment_post(paid.slate_id))
        .unwrap()
        .unwrap();
    assert!(!post.delivered && post.waiting && !post.stuck);
    assert!(post.reason.is_some());

    assert_eq!(
        due_over(&world, &world.payer, &unreachable),
        OutboxReport::default()
    );
    assert_eq!(rows(&world.payer, paid.slate_id)[0].entry.attempts, 1);
    world.payer.clock.advance(Duration::from_secs(31));
    due_over(&world, &world.payer, &unreachable);
    let again = rows(&world.payer, paid.slate_id);
    assert_eq!(again[0].entry.state, OutboxState::Queued);
    assert_eq!(again[0].entry.attempts, 2);

    world.payer.clock.advance(Duration::from_secs(25 * 60 * 60));
    let report = due_over(&world, &world.payer, &unreachable);
    assert_eq!(report.stuck, 1);
    let late = rows(&world.payer, paid.slate_id);
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].entry.state, OutboxState::Queued);
    assert_eq!(late[0].entry.attempts, 3);
    let post = world
        .block_on(book.payment_post(paid.slate_id))
        .unwrap()
        .unwrap();
    assert!(!post.delivered && post.waiting && post.stuck);
    assert_eq!(post.attempts, 3);
    assert!(post.reason.is_some());

    // The mark is raised once; post-next after it posts the waiting row at once.
    world.payer.clock.advance(Duration::from_secs(60));
    assert_eq!(due_over(&world, &world.payer, &unreachable).stuck, 0);
    let next = world.block_on(book.epic1_post_next(&unreachable, paid.slate_id));
    assert!(next.is_ok(), "{next:?}");
    let posted_again = rows(&world.payer, paid.slate_id);
    assert_eq!(posted_again.len(), 1);
    assert_eq!(posted_again[0].entry.attempts, 4);

    let cutoff = late[0].entry.cutoff_height.unwrap().value();
    set_tip(&world.payer, cutoff);
    world.payer.clock.advance(Duration::from_secs(60 * 60));
    let report = due_over(&world, &world.payer, &unreachable);
    assert_eq!(report.stuck, 1);
    let ended = rows(&world.payer, paid.slate_id);
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].entry.state, OutboxState::Failed);
    let post = world
        .block_on(book.payment_post(paid.slate_id))
        .unwrap()
        .unwrap();
    assert!(!post.delivered && !post.waiting && post.stuck);
    assert_eq!(world.relay.received("PostSlate"), posts);
}

/// The collect report lists a payment the outbox holds stuck, with its mark and reason, also
/// once it ended at its cutoff, never sent.
#[test]
fn the_collect_report_lists_a_payment_the_outbox_holds_stuck() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let unreachable = without(&world, &world.payer, "relay.test");
    let book = world.payer.wallet.contact_book();
    let collect = || {
        world
            .block_on(book.contacts_collect(&unreachable, CollectTrigger::Open))
            .unwrap()
    };

    let paid = pay_over(&world, &unreachable, &issued.link);
    let early = collect().stuck;
    assert!(early.is_empty(), "{early:?}");

    world.payer.clock.advance(Duration::from_secs(25 * 60 * 60));
    let report = collect();
    let post = world
        .block_on(book.payment_post(paid.slate_id))
        .unwrap()
        .unwrap();
    assert!(post.stuck && post.waiting);
    let [stuck] = report.stuck.as_slice() else {
        panic!("one stuck payment: {:?}", report.stuck);
    };
    assert_eq!(stuck.slate_id, paid.slate_id);
    assert_eq!(Some(stuck.since), post.stuck_at);
    assert_eq!(stuck.reason, post.reason);
    assert!(stuck.reason.is_some());

    let cutoff = rows(&world.payer, paid.slate_id)[0]
        .entry
        .cutoff_height
        .unwrap()
        .value();
    set_tip(&world.payer, cutoff);
    world.payer.clock.advance(Duration::from_secs(60 * 60));
    let ended = collect().stuck;
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0].slate_id, paid.slate_id);
    assert_eq!(ended[0].since, stuck.since);
}

/// A payment is stored before it is posted: a wallet whose post did not go, opened again, posts
/// it once, and the payment is finalized once.
#[test]
fn a_payment_stored_and_not_posted_is_posted_once_after_the_wallet_is_opened_again() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let mailbox = mailbox_of(&issued.link);
    let paid = pay_over(
        &world,
        &without(&world, &world.payer, "relay.test"),
        &issued.link,
    );
    assert_eq!(paid.posted, None);
    assert_eq!(world.relay.pending(&mailbox), 0);

    let payer = world
        .payer
        .reopened(&world.node, &world.relay, &world.runtime);
    payer.clock.advance(Duration::from_secs(31));
    let report = due_over(&world, &payer, &relays(&payer));
    assert_eq!(report.delivered, 1);
    assert_eq!(world.relay.pending(&mailbox), 1);
    let posts = world.relay.received("PostSlate");
    payer.clock.advance(LATER);
    assert_eq!(
        due_over(&world, &payer, &relays(&payer)),
        OutboxReport::default()
    );
    assert_eq!(world.relay.received("PostSlate"), posts);

    assert_eq!(world.taken(&world.issuer), 1);
    world.collect(&payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(received(&world), 1);
    assert_ne!(
        payer
            .read(|repos| repos.transaction(paid.tx_id))
            .unwrap()
            .state,
        TxState::Sent
    );
}

const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

impl InPersonInbox for Listening {
    fn take(&self, envelope: Vec<u8>) -> BoxFuture<'_, InPersonDirect> {
        Box::pin(async move {
            self.0
                .issuer
                .wallet
                .contact_book()
                .in_person_take_direct(&envelope)
                .await
        })
    }
}

impl Epic1Keys for Listening {
    fn epic1_keys(&self) -> BoxFuture<'_, Vec<Epic1AccountKeys>> {
        Box::pin(async { self.0.issuer.wallet.epic1_trial_keys_all().await.unwrap() })
    }
}

/// The issuer's inbox route on a local port, taking payments sealed to its epic1
/// addresses, as `lepic listen` serves it. Returns the port.
fn payee_endpoint(world: &Arc<World>) -> u16 {
    let method: Arc<dyn Method> = Arc::new(http());
    let host = Arc::new(Listening(Arc::clone(world)));
    let receiver = Arc::new(Receiver::new(
        Arc::clone(&host),
        Arc::clone(&method),
        ProofKey::Payments,
    ));
    let rng = SharedRng::new(rand::rngs::StdRng::seed_from_u64(9));
    let handler = DirectHandler::new(Arc::clone(&host), method, Network::Floonet, rng)
        .with_epic1(Arc::<Listening>::clone(&host))
        .with_in_person(host);
    let endpoint: Arc<dyn SocketRoute> = Arc::new(InboxRoute::new(Arc::new(handler)));
    let settings = ListenSettings::new(Exposure::LocalOnly, 0, listen_limits());
    let handle = world
        .block_on(listen_with(settings, receiver, Some(endpoint)))
        .unwrap();
    let port = handle.local_addr().port();
    // The listener stays up for the rest of the test.
    std::mem::forget(handle);
    port
}

/// A Tor dialer that takes every onion to the local port of the payee's endpoint, and counts
/// the dials.
struct ToPayee {
    port: u16,
    dials: std::sync::Mutex<usize>,
}

impl PeerDialer for ToPayee {
    fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> PeerDialFuture<'a> {
        *self.dials.lock().unwrap() += 1;
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port)).await?;
            Ok(Box::new(stream) as Box<dyn PeerStream>)
        })
    }
}

/// An in-person answer posted on the code's `tor` direct route is taken by the payee's
/// listener in the same exchange. Once one is finalized, another answer posted there is
/// refused with its reason, and the payment it carries is not cancelled.
#[test]
fn an_in_person_answer_on_a_direct_route_is_taken_and_a_late_one_refused() {
    let world = Arc::new(World::new());
    let port = payee_endpoint(&world);
    let route = RouteEntry {
        method: MethodId::Tor,
        value: ONION.to_owned(),
    };
    let offline = ContactRelays {
        mode: RelayMode::Offline,
        ..relays(&world.issuer)
    };
    let code = world
        .block_on(world.issuer.wallet.contact_book().in_person_invoice(
            &offline,
            InPersonInvoiceRequest {
                account: ACCOUNT,
                amount: lepic_primitives::amount::Amount::new(world::AMOUNT),
                message: None,
                ttl_blocks: None,
                slate_id: None,
                direct: vec![route.clone()],
                claim: None,
                shared_slot: false,
            },
        ))
        .unwrap();
    assert_eq!(code.mailbox, None);
    let dialer = Arc::new(ToPayee {
        port,
        dials: std::sync::Mutex::new(0),
    });
    let twin = world.payer_twin();
    twin.fund(0, FUNDING);
    let mut posted = Vec::new();
    for party in [&world.payer, &twin] {
        let book = party.wallet.contact_book();
        let paid = world
            .block_on(book.in_person_pay(&relays(party), &code.bytes, world::pay_request()))
            .unwrap();
        let tor = relays(party).with_tor(dialer.clone(), |_| Ok(()));
        let routes = world
            .block_on(book.in_person_post(&tor, paid.slate_id))
            .unwrap()
            .routes;
        posted.push((paid, routes));
        if posted.len() == 1 {
            world
                .block_on(world.issuer.wallet.contact_book().in_person_finalize(
                    code.slate_id,
                    1,
                    lepic_node::Propagation::Stem,
                ))
                .unwrap();
        }
    }

    assert_eq!(*dialer.dials.lock().unwrap(), 2);
    assert_eq!(posted[0].1.len(), 1);
    assert_eq!(posted[0].1[0].route, route);
    assert_eq!(posted[0].1[0].outcome, InPersonPostOutcome::Accepted);
    assert_eq!(
        posted[1].1[0].outcome,
        InPersonPostOutcome::Refused {
            reason: Some("already_finalized".to_owned())
        }
    );
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let late = &posted[1].0;
    assert_eq!(
        twin.read(|repos| repos.transaction(late.tx_id))
            .unwrap()
            .state,
        TxState::Sent
    );
}

/// `link`, which asks an amount, with a `tor` entry added; links are not signed.
fn on_tor(link: &str) -> String {
    assert!(link.contains('?'), "{link}");
    format!("{link}&tor={ONION}")
}

/// A payment posted on a `tor` entry is answered in the same exchange: the answer is taken
/// before the row says posted, the payment is finalized once, and a later run posts nothing.
#[test]
fn a_payment_answered_on_a_tor_entry_is_finalized_once_and_not_posted_again() {
    let world = Arc::new(World::new());
    let port = payee_endpoint(&world);
    let issued = world.issue_link(&world.issuer);
    let link = on_tor(&issued.link);
    assert!(
        link.contains("tor=") && !link.contains("epicbox="),
        "{link}"
    );
    let dialer = Arc::new(ToPayee {
        port,
        dials: std::sync::Mutex::new(0),
    });
    let tor = relays(&world.payer).with_tor(dialer.clone(), |_| Ok(()));
    let posts = world.relay.received("PostSlate");

    let paid = pay_over(&world, &tor, &link);

    assert_eq!(paid.posted, Some(0));
    assert_eq!(*dialer.dials.lock().unwrap(), 1);
    assert_eq!(
        world.relay.received("PostSlate"),
        posts,
        "nothing went to the relay"
    );
    let posted = rows(&world.payer, paid.slate_id);
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].entry.state, OutboxState::Posted);
    assert_eq!(posted[0].entry.attempts, 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    // The answer came in the exchange: no relay is watched for it.
    reconciled(&world, &world.payer);
    assert_eq!(rows_of(&world.payer, MailClass::Reply), []);

    world.payer.clock.advance(LATER);
    world.confirm_tips();
    assert_eq!(
        due_over(&world, &world.payer, &tor),
        OutboxReport::default()
    );
    assert_eq!(*dialer.dials.lock().unwrap(), 1);
    assert_eq!(rows(&world.payer, paid.slate_id), posted);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

/// A link with entries is paid through its entries alone: a payer without Tor has no carrier
/// for a `tor` entry, so the row ends; the payment is never posted to the payee's mailbox on a
/// relay, has no next route to move to, and no relay is watched for its answer.
#[test]
fn a_link_with_entries_never_falls_back_to_the_mailbox() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let link = on_tor(&issued.link);
    let mailbox = mailbox_of(&issued.link);
    let posts = world.relay.received("PostSlate");

    let paid = pay_over(&world, &relays(&world.payer), &link);

    assert_eq!(paid.posted, None);
    assert_eq!(world.relay.received("PostSlate"), posts);
    assert_eq!(world.relay.pending(&mailbox), 0);
    let ended = rows(&world.payer, paid.slate_id);
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].entry.route_method, "tor");
    assert_eq!(ended[0].entry.state, OutboxState::Failed);
    assert_eq!(
        refusal(post_next(&world, paid.slate_id)),
        Epic1Refusal::NoMoreEntries
    );

    world.payer.clock.advance(LATER);
    world.confirm_tips();
    due(&world, &world.payer);
    assert_eq!(world.relay.received("PostSlate"), posts);
    assert_eq!(world.relay.pending(&mailbox), 0);
    reconciled(&world, &world.payer);
    assert_eq!(rows_of(&world.payer, MailClass::Reply), []);
}

/// The second onion of a link with two `tor` entries.
const OTHER_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

/// A Tor dialer that loses every post to [`ONION`] after it was written, and takes every other
/// onion to the local port of the payee's endpoint. Counts the dials of each.
struct LosesFirst {
    port: u16,
    lost: std::sync::Mutex<usize>,
    reached: std::sync::Mutex<usize>,
}

impl PeerDialer for LosesFirst {
    fn dial<'a>(&'a self, host: &'a str, _port: u16) -> PeerDialFuture<'a> {
        Box::pin(async move {
            if host == ONION {
                *self.lost.lock().unwrap() += 1;
                // The far end goes away: the post may have arrived.
                let (ours, theirs) = tokio::io::duplex(1 << 16);
                drop(theirs);
                return Ok(Box::new(ours) as Box<dyn PeerStream>);
            }
            *self.reached.lock().unwrap() += 1;
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port)).await?;
            Ok(Box::new(stream) as Box<dyn PeerStream>)
        })
    }
}

/// A payment whose post on its first entry may have arrived, moved to the next entry and
/// taken there, ends the first entry's row: a later outbox run does not post it again.
#[test]
fn a_payment_taken_on_its_next_entry_ends_the_row_that_may_have_arrived() {
    let world = Arc::new(World::new());
    world.confirm_tips();
    let port = payee_endpoint(&world);
    let issued = world.issue_link(&world.issuer);
    let link = format!("{}&tor={OTHER_ONION}", on_tor(&issued.link));
    let dialer = Arc::new(LosesFirst {
        port,
        lost: std::sync::Mutex::new(0),
        reached: std::sync::Mutex::new(0),
    });
    let tor = relays(&world.payer).with_tor(dialer.clone(), |_| Ok(()));

    let paid = pay_over(&world, &tor, &link);
    assert_eq!(paid.posted, None);
    assert_eq!(paid.uncertain, Some(0));
    assert_eq!(*dialer.lost.lock().unwrap(), 1);

    let moved = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .epic1_post_next(&tor, paid.slate_id),
        )
        .unwrap();
    assert_eq!(moved.posted, Some(1));
    assert_eq!(*dialer.reached.lock().unwrap(), 1);
    let settled = rows(&world.payer, paid.slate_id);
    let states: Vec<OutboxState> = settled.iter().map(|row| row.entry.state).collect();
    assert_eq!(states, [OutboxState::Failed, OutboxState::Posted]);
    assert_eq!(world.node.pushed_transactions().len(), 1);

    world.payer.clock.advance(LATER);
    assert_eq!(
        due_over(&world, &world.payer, &tor),
        OutboxReport::default()
    );
    assert_eq!(*dialer.lost.lock().unwrap(), 1);
    assert_eq!(*dialer.reached.lock().unwrap(), 1);
    assert_eq!(rows(&world.payer, paid.slate_id), settled);
}

/// A payment whose post arrived and whose answer was lost is posted again on the same entry,
/// with the same bytes, once its back-off is over. The payee takes the two arrivals as one
/// payment and answers once; the payer finalizes once.
#[test]
fn a_post_that_arrived_unanswered_is_posted_again_and_taken_once() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let mailbox = mailbox_of(&issued.link);
    let posts = world.relay.received("PostSlate");
    world.relay.set_unanswered(Unanswered::PostAnswer, true);
    let paid = pay_over(&world, &quick(&world, &world.payer), &issued.link);
    world.relay.set_unanswered(Unanswered::PostAnswer, false);
    assert_eq!(paid.uncertain, Some(0));
    assert_eq!(world.relay.pending(&mailbox), 1);
    let first = rows(&world.payer, paid.slate_id);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].entry.state, OutboxState::Uncertain);

    world.payer.clock.advance(LATER);
    assert_eq!(due(&world, &world.payer).delivered, 1);
    assert_eq!(world.relay.received("PostSlate"), posts + 2);
    assert_eq!(world.relay.pending(&mailbox), 2, "two arrivals");
    let again = rows(&world.payer, paid.slate_id);
    assert_eq!(again.len(), 1, "posted again on the same row");
    assert_eq!(again[0].entry.route_value, first[0].entry.route_value);
    assert_eq!(again[0].entry.envelope, first[0].entry.envelope);
    assert_eq!(again[0].entry.attempts, 2);
    assert_eq!(again[0].entry.state, OutboxState::Posted);

    assert_eq!(world.taken(&world.issuer), 1);
    assert_eq!(received(&world), 1);
    assert_eq!(world.answers_posted(), 1);
    world.collect(&world.payer);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_ne!(world.payer_state(paid.tx_id), TxState::Sent);
}

/// A refusal the payee posted belongs to no transaction and goes once the relay would have
/// dropped it. The answer of a payment still open stays however old it is.
#[test]
fn a_posted_refusal_goes_by_age_and_an_open_payments_answer_stays() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    fund_again(&world.payer);
    let refused = world.pay_asking_for_a_proof(&issued, 9);
    assert_eq!(world.taken(&world.issuer), 0);
    for slate_id in [paid.slate_id, refused] {
        let posted = rows(&world.issuer, slate_id);
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].entry.state, OutboxState::Posted);
    }

    world.issuer.clock.advance(RELAY_RETENTION + LATER);
    world.collect(&world.issuer);

    assert!(rows(&world.issuer, refused).is_empty());
    assert_eq!(rows(&world.issuer, paid.slate_id).len(), 1);
    let receipts = world
        .block_on(world.issuer.wallet.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert!(!matches!(
        receipts[0].transaction.entry.state,
        TxState::Confirmed | TxState::Cancelled | TxState::Expired
    ));
}

/// The envelope names no relay: the payee refuses a payment read on a relay other than its
/// own and queues the notice to the reply key on its list, so it waits in the payer's reply
/// mailbox on that relay and on the payee's own.
#[test]
fn a_refusal_of_a_payment_read_on_another_relay_waits_there() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let file = tempfile::tempdir().unwrap().keep().join("s1.tx");
    let refused = world
        .block_on(world.payer.wallet.contact_book().epic1_pay(
            &without_on_shop(&world, &world.payer, "relay.test"),
            Epic1PayRequest {
                link: issued.link.clone(),
                send: send(),
                slate_file: file,
                mailboxes: Vec::new(),
            },
        ))
        .unwrap();
    assert_eq!(refused.posted, Some(0));

    assert_eq!(taken_on_shop(&world), 0);
    let posted = rows(&world.issuer, refused.slate_id);
    assert_eq!(posted.len(), 1);
    assert!(!posted[0].entry.route_value.contains('@'));
    assert_eq!(
        world
            .relay
            .pending(&world.reply_mailbox_on(refused.slate_id, "shop.test")),
        1
    );
    assert_eq!(
        world.relay.pending(&world.reply_mailbox(refused.slate_id)),
        1
    );
}

/// The delivery changes `events` holds, in order.
fn delivery_changes(
    events: &mut tokio::sync::broadcast::Receiver<lepic_wallet::Event>,
) -> Vec<OutboxState> {
    let mut states = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let lepic_wallet::Event::DeliveryChanged(news) = event {
            states.push(news.state);
        }
    }
    states
}

/// A payment whose post may have arrived, posted again on the same route and taken, tells the
/// host once that it went; a later run tells nothing.
#[test]
fn an_uncertain_payment_posted_later_is_told_once() {
    let world = World::new();
    world.confirm_tips();
    let issued = world.issue_link(&world.issuer);
    let mut events = world.payer.wallet.subscribe();
    world.relay.set_unanswered(Unanswered::PostAnswer, true);
    let paid = pay_over(&world, &quick(&world, &world.payer), &issued.link);
    world.relay.set_unanswered(Unanswered::PostAnswer, false);
    assert_eq!(paid.uncertain, Some(0));
    assert_eq!(delivery_changes(&mut events), [OutboxState::Uncertain]);

    world.payer.clock.advance(LATER);
    assert_eq!(due(&world, &world.payer).delivered, 1);
    assert_eq!(delivery_changes(&mut events), [OutboxState::Posted]);

    world.payer.clock.advance(LATER);
    due(&world, &world.payer);
    assert_eq!(delivery_changes(&mut events), []);
}

/// A payment whose post may have arrived, then answered and finalized, is not posted again:
/// the outbox ends its row as posted with no delivery news, the finalized transaction being
/// the news.
#[test]
fn an_uncertain_payment_answered_is_not_posted_again() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mut events = world.payer.wallet.subscribe();
    let both = quick_on_shop(&world, &world.payer);
    world.relay.set_unanswered(Unanswered::PostAnswer, true);
    let paid = pay_over(&world, &both, &issued.link);
    world.relay.set_unanswered(Unanswered::PostAnswer, false);
    assert_eq!(paid.uncertain, Some(0));
    assert_eq!(delivery_changes(&mut events), [OutboxState::Uncertain]);

    // The payee reads the two copies and answers once; the payer finalizes.
    assert_eq!(taken_on_shop(&world), 1);
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);

    let posts = world.relay.received("PostSlate");
    world.payer.clock.advance(LATER);
    due_over(&world, &world.payer, &both);
    assert_eq!(world.relay.received("PostSlate"), posts);
    let (settled, notices): (Vec<_>, Vec<_>) = rows(&world.payer, paid.slate_id)
        .into_iter()
        .partition(|row| row.entry.stage.is_some());
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].entry.state, OutboxState::Posted);
    assert_eq!(notices.len(), 1, "the `posted` notice");
    assert_eq!(delivery_changes(&mut events), []);
    world.payer.clock.advance(LATER);
    due_over(&world, &world.payer, &both);
    assert_eq!(world.relay.received("PostSlate"), posts);
    assert_eq!(delivery_changes(&mut events), []);
}

/// A payment whose post may have arrived, posted again and refused by one relay while the
/// other takes it, tells the host each change in order: uncertain, then posted.
#[test]
fn an_uncertain_payment_taken_by_one_relay_of_two_is_told_each_change() {
    let world = World::new();
    world.confirm_tips();
    world.relay.set_relays_apart(true);
    let issued = world.issue_link(&world.issuer);
    let mut events = world.payer.wallet.subscribe();
    let both = quick_on_shop(&world, &world.payer);
    let paid = pay_unanswered(&world, &both, &issued.link);
    assert_eq!(paid.uncertain, Some(0));

    world.relay.set_domain_refused("relay.test");
    world.payer.clock.advance(LATER);
    assert_eq!(due_over(&world, &world.payer, &both).delivered, 1);
    let posted = rows(&world.payer, paid.slate_id);
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].entry.state, OutboxState::Posted);
    assert_eq!(
        delivery_changes(&mut events),
        [OutboxState::Uncertain, OutboxState::Posted]
    );
}

/// The outbox rows of the payment `slate_id` that carry a slate, oldest first.
fn staged_rows(party: &Party, slate_id: SlateId) -> Vec<StoredNativeOutbox> {
    rows(party, slate_id)
        .into_iter()
        .filter(|row| row.entry.stage.is_some())
        .collect()
}

/// The payer's notice row of the payment `slate_id`: its one row of no stage.
fn notice_row(party: &Party, slate_id: SlateId) -> StoredNativeOutbox {
    let mut notices: Vec<_> = rows(party, slate_id)
        .into_iter()
        .filter(|row| row.entry.stage.is_none())
        .collect();
    assert_eq!(notices.len(), 1);
    notices.remove(0)
}

/// A payer's `posted` notice goes out though the payment's transaction is finalized, which
/// would end the payment's own row unposted. It goes with no relay transaction id.
#[test]
fn a_posted_notice_goes_out_though_its_payment_is_finalized() {
    let world = World::new();
    world.relay.set_version(Some("3.1.0"));
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);

    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(
        notice_row(&world.payer, paid.slate_id).entry.state,
        OutboxState::Posted
    );
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 1);
    assert_eq!(
        world.relay.posted_txids().len(),
        1,
        "the payment has an id, its notice none"
    );
}

/// A payer's `cancelled` notice goes out though the payment's transaction is cancelled, which
/// ends the payment's own row as owed to nobody.
#[test]
fn a_cancelled_notice_goes_out_though_its_payment_is_cancelled() {
    let world = World::new();
    let issued = world.issue_link(&world.issuer);
    let paid = world.pay_link(&issued.link).unwrap();
    assert_eq!(world.taken(&world.issuer), 1);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();

    world.collect(&world.payer);
    assert_eq!(
        notice_row(&world.payer, paid.slate_id).entry.state,
        OutboxState::Posted
    );
    assert_eq!(world.relay.pending(&mailbox_of(&issued.link)), 1);
}

/// A payer's notice whose post is refused, or may have arrived, leaves the payment's delivery
/// state as it was and tells the host nothing: the notice is no post of the payment.
#[test]
fn a_notice_refused_or_uncertain_leaves_the_payments_delivery_alone() {
    for refused in [true, false] {
        let world = World::new();
        world.confirm_tips();
        let issued = world.issue_link(&world.issuer);
        let mailbox = mailbox_of(&issued.link);
        let paid = world.pay_link(&issued.link).unwrap();
        assert_eq!(world.taken(&world.issuer), 1);
        let payment_id = Uuid::from_bytes(*paid.slate_id.as_bytes());
        let delivery = || world.payer.read(|repos| repos.payment_delivery(payment_id));
        let before = delivery();
        assert!(before.is_some());
        let mut events = world.payer.wallet.subscribe();

        if refused {
            world.relay.set_post_refused(&mailbox);
        } else {
            world.relay.set_unanswered(Unanswered::PostAnswer, true);
        }
        world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .contacts_collect(&quick(&world, &world.payer), CollectTrigger::Open),
            )
            .unwrap();
        world.relay.set_unanswered(Unanswered::PostAnswer, false);
        assert_eq!(world.node.pushed_transactions().len(), 1);
        let notice = notice_row(&world.payer, paid.slate_id);
        assert_eq!(
            notice.entry.state,
            if refused {
                OutboxState::Failed
            } else {
                OutboxState::Uncertain
            }
        );
        assert_eq!(delivery(), before, "{refused}");
        assert_eq!(delivery_changes(&mut events), [], "{refused}");
    }
}

/// The payee's `declined` row, of no stage and no transaction, goes as before: posted to the
/// reply mailbox the payment named, with no relay transaction id, no delivery state and no
/// delivery news.
#[test]
fn a_payees_declined_row_goes_as_before() {
    let world = World::with_issuer_policy(WalletPolicy {
        refuse_unsolicited_payments: true,
        ..WalletPolicy::default()
    });
    world.relay.set_version(Some("3.1.0"));
    let issued = world.issue_link(&world.issuer);
    let refused = world.pay_link(&issued.link).unwrap();
    let posted_ids = world.relay.posted_txids().len();
    let mut events = world.issuer.wallet.subscribe();

    assert_eq!(world.taken(&world.issuer), 0);
    let row = rows(&world.issuer, refused.slate_id).remove(0);
    assert_eq!(row.entry.stage, None);
    assert_eq!(row.entry.state, OutboxState::Posted);
    assert_eq!(
        world.relay.pending(&world.reply_mailbox(refused.slate_id)),
        1
    );
    assert_eq!(world.relay.posted_txids().len(), posted_ids);
    let payment_id = Uuid::from_bytes(*refused.slate_id.as_bytes());
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.payment_delivery(payment_id)),
        None
    );
    assert_eq!(delivery_changes(&mut events), []);
}

/// A `cancelled` notice that waits, its relay unreachable, stays through the prune while the
/// payment's row goes; once posted, or failed after a day, the prune takes it.
#[test]
fn a_waiting_cancelled_notice_survives_the_prune_until_it_ends() {
    for posted in [true, false] {
        let world = World::new();
        world.confirm_tips();
        let issued = world.issue_link(&world.issuer);
        let paid = world.pay_link(&issued.link).unwrap();
        assert_eq!(world.taken(&world.issuer), 1);
        world
            .block_on(world.payer.wallet.cancel(paid.tx_id))
            .unwrap();
        world.relay.set_refusing(true);

        world.collect(&world.payer);
        assert_eq!(
            notice_row(&world.payer, paid.slate_id).entry.state,
            OutboxState::Queued
        );
        world.collect(&world.payer);
        let waiting = rows(&world.payer, paid.slate_id);
        assert_eq!(waiting.len(), 1, "{posted}");
        assert_eq!(waiting[0].entry.stage, None);

        if posted {
            world.relay.set_refusing(false);
            world.payer.clock.advance(LATER);
        } else {
            world.payer.clock.advance(OUTBOX_STUCK_AFTER + LATER);
        }
        world.collect(&world.payer);
        let ended = notice_row(&world.payer, paid.slate_id).entry.state;
        assert_eq!(
            ended,
            if posted {
                OutboxState::Posted
            } else {
                OutboxState::Failed
            }
        );
        world.collect(&world.payer);
        assert!(rows(&world.payer, paid.slate_id).is_empty(), "{posted}");
    }
}
