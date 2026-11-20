// SPDX-License-Identifier: Apache-2.0
//! The outbox of sealed messages to contacts and pairings (RFC 0002 12.4), rows of the one
//! outbox ([`crate::delivery::outbox`]). Contact mail (payments of invoices, answers to
//! withdrawals, messages) goes from the contact's mailbox to its mailbox on its home relay.
//! Pairing mail (a reply, a confirm, the status and unpaired notices) goes to the peer's key on
//! every usable relay of the list and on the relay the mail names; when only other relays took
//! it, it is owed to the named relay alone. Rows are stored, so a killed app loses nothing, and
//! posted at once, then after 30 s, 2 min, 10 min and every 30 min, and on every collecting
//! cycle.

use std::collections::BTreeSet;
use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::armor;
use lepic_epic1::{MethodId, RouteEntry};
use lepic_epicbox::TRANSPORT_ID;
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::model::SlateId;
use lepic_store::{
    ContactId, ContactOutboxId, ContactOutboxState, NativeOutboxId, OutboxState, Repositories,
    SlateStage, StoreError, StoredNativeOutbox, TxDirection, TxState, WalletStore,
};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::relay::check_online;
use super::{ContactError, ContactRelays};
use crate::ContactBook;
use crate::delivery::outbox::{self, Owed, Sender, link_carrier};
use lepic_wallet::SlateFormat;
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// Waits before the next try, one step per failed try; the last repeats.
const RETRY: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(2 * 60),
    Duration::from_secs(10 * 60),
    Duration::from_secs(30 * 60),
];

/// An entry undelivered this long is stuck (RFC 0002 12.4).
pub const OUTBOX_STUCK_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// A delivered entry is kept this long, as long as the relay keeps its message, unless its
/// transaction ended sooner.
const DELIVERED_KEPT: Duration = lepic_epicbox::RELAY_RETENTION;

/// A payment delivered this long ago and not posted yet is shown so (RFC 0002 12.4).
pub const NOT_POSTED_AFTER: Duration = Duration::from_secs(2 * 60 * 60);

/// An outbox entry as the host shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxView {
    pub id: ContactOutboxId,
    pub contact_id: ContactId,
    pub slate_id: SlateId,
    pub stage: SlateStage,
    pub state: ContactOutboxState,
    pub attempts: u32,
    pub created_at: Timestamp,
    pub delivered_at: Option<Timestamp>,
    /// Delivered more than [`NOT_POSTED_AFTER`] ago while the payment still waits for the
    /// contact: "X has not posted yet", with "Send again".
    pub not_posted_yet: bool,
}

/// What one outbox run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboxReport {
    pub delivered: usize,
    pub failed: usize,
    /// The payments of this run that ended undelivered or were marked stuck
    /// ([`PaymentPost::stuck`]).
    pub stuck: usize,
    /// The posts of this run that a mailbox refused, one per post, in the order they went.
    pub refused: Vec<RefusedPost>,
}

/// A mailbox's refusal of a post: "mailbox X refused: <reason>, retry in N s". Its
/// [`Display`](std::fmt::Display) writes it so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRefusal {
    /// The mailbox that refused, `domain:port`; `None` for a native endpoint.
    pub mailbox: Option<String>,
    /// The mailbox's own words, at most 256 bytes; `None` when it gave none.
    pub reason: Option<String>,
    /// The wait the mailbox asked for before the next post, at most a day.
    pub retry_after: Option<Duration>,
    /// The refusal passes, for a rate limit or for want of room: the outbox posts again after
    /// `retry_after` and its own back-off, until the payment's cutoff. Any other refusal is
    /// final: the row fails and the next route, if any, goes.
    pub retryable: bool,
}

impl std::fmt::Display for MailboxRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::delivery::epicbox::refused_text(
            self.mailbox.as_deref(),
            self.reason.as_deref(),
            self.retry_after,
        ))
    }
}

/// A post of an outbox run that a mailbox refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedPost {
    /// The payment the post carried.
    pub slate_id: SlateId,
    pub refusal: MailboxRefusal,
}

/// A payment the outbox holds marked stuck: no route took it within [`OUTBOX_STUCK_AFTER`] of
/// its newest row. A mark only: the outbox tries on until the payment's cutoff, and the host may
/// offer a cancel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckPayment {
    pub slate_id: SlateId,
    /// When the payment was marked stuck.
    pub since: Timestamp,
    /// Why the last post did not go, with the mailbox, its words and its wait when one
    /// refused; `None` when no post was answered yet.
    pub reason: Option<String>,
}

/// How the posts of one payment stand, as [`ContactBook::payment_post`] reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPost {
    /// A route took the payment: a mailbox or the payee's endpoint holds it.
    pub delivered: bool,
    /// A row of the payment waits: the outbox posts it again at [`PaymentPost::next_at`].
    pub waiting: bool,
    /// No route took the payment within [`OUTBOX_STUCK_AFTER`] of its newest row. A mark
    /// only: the outbox tries on until the chain reaches the payment's cutoff, and the host
    /// may offer a cancel.
    pub stuck: bool,
    /// When the payment is, or will be, marked stuck; `None` once delivered.
    pub stuck_at: Option<Timestamp>,
    /// When the outbox posts the payment next; `None` when no row waits.
    pub next_at: Option<Timestamp>,
    /// The posts made, over every route.
    pub attempts: u32,
    /// Why the last post did not go, with the mailbox, its words and its wait when one
    /// refused; `None` once delivered.
    pub reason: Option<String>,
}

/// How the posts of a payment stand at `now`, from `rows`, its rows, and `reason`, its stored
/// reason. `None` when no row of `rows` carries the payment.
pub(crate) fn payment_post_of(
    rows: &[StoredNativeOutbox],
    reason: Option<String>,
    now: Timestamp,
) -> Option<PaymentPost> {
    let posts = || rows.iter().filter(|row| outbox::payment(&row.entry));
    posts().next()?;
    let delivered = posts().any(|row| row.entry.state == OutboxState::Posted);
    let next_at = posts()
        .filter(|row| waiting(row.entry.state))
        .map(|row| row.entry.next_at)
        .min();
    let stuck_at = outbox::stuck_mark(rows);
    Some(PaymentPost {
        delivered,
        waiting: !delivered && next_at.is_some(),
        stuck: stuck_at.is_some_and(|mark| mark <= now),
        stuck_at,
        next_at: next_at.filter(|_| !delivered),
        attempts: posts().fold(0u32, |sum, row| sum.saturating_add(row.entry.attempts)),
        reason: reason.filter(|_| !delivered),
    })
}

/// The contact's rows in the outbox, sent from its mailbox under either salt, by id.
pub(crate) fn contact_rows(
    repos: &dyn Repositories,
    contact_id: ContactId,
) -> Result<Vec<StoredNativeOutbox>, StoreError> {
    let mut rows = repos.native_outbox_from(&Sender::Contact(contact_id).from_ref())?;
    rows.extend(repos.native_outbox_from(&Sender::ContactOldSalt(contact_id).from_ref())?);
    rows.sort_by_key(|row| row.id);
    Ok(rows)
}

/// Whether a row still waits for its post.
pub(crate) fn waiting(state: OutboxState) -> bool {
    matches!(state, OutboxState::Queued | OutboxState::Uncertain)
}

/// The route value of mail to a contact whose mailbox is `peer_mailbox`, `key@host`: the key
/// alone. The carrier posts it to every mailbox of the list and to the contact's card mailbox,
/// which it reads from the record when it posts.
pub(crate) fn peer_route(peer_mailbox: &str) -> &str {
    peer_mailbox
        .split_once('@')
        .map_or(peer_mailbox, |(key, _)| key)
}

/// Points the contact's queued rows at its mailbox `new`, `key@host`: a row to the contact's
/// current key, or to a mailbox on one relay as an earlier release wrote it, then goes to the
/// key of `new` alone. Rows already posted, or posted without an answer, keep the mailbox they
/// went to, and pairing mail to another key is left as it is. Called before the record's
/// mailbox changes.
pub(crate) fn redirect_contact_rows(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    new: &str,
) -> Result<usize, StoreError> {
    let new = peer_route(new);
    let current = repos
        .contact_mailbox(contact_id)?
        .map(|mailbox| peer_route(&mailbox.peer_mailbox).to_owned());
    let old: BTreeSet<String> = contact_rows(repos, contact_id)?
        .into_iter()
        .filter(|row| {
            let value = &row.entry.route_value;
            row.entry.state == OutboxState::Queued
                && value != new
                && (value.contains('@') || current.as_ref() == Some(value))
        })
        .map(|row| row.entry.route_value)
        .collect();
    let mut moved = 0usize;
    for sender in [
        Sender::Contact(contact_id),
        Sender::ContactOldSalt(contact_id),
    ] {
        for value in &old {
            let changed = repos.redirect_native_outbox(&sender.from_ref(), value, new)?;
            moved = moved.saturating_add(changed);
        }
    }
    Ok(moved)
}

/// Deletes every row of the contact, and returns how many there were.
pub(crate) fn drop_contact_rows(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
) -> Result<usize, StoreError> {
    let mut dropped = repos.delete_native_outbox_from(&Sender::Contact(contact_id).from_ref())?;
    dropped = dropped.saturating_add(
        repos.delete_native_outbox_from(&Sender::ContactOldSalt(contact_id).from_ref())?,
    );
    Ok(dropped)
}

/// A post of `payload` to the contact's mailbox `mailbox`, `key@host`, for the slate or message
/// `id`: to its key alone ([`peer_route`]).
pub(crate) fn contact_owed(
    contact_id: ContactId,
    id: Uuid,
    stage: SlateStage,
    mailbox: &str,
    payload: String,
) -> Owed {
    Owed {
        payment_id: id,
        sender: Sender::Contact(contact_id),
        route: RouteEntry {
            method: MethodId::Epicbox,
            value: peer_route(mailbox).to_owned(),
        },
        envelope: payload,
        cutoff: None,
        stage: Some(stage),
        notice: false,
    }
}

/// Stores pairing mail from `sender`, `payload` armored, as a row `id` for the mailbox key
/// `to_key` alone: the carrier posts it to every usable relay, and the outbox back-off retries
/// it until the row is posted or a day old.
pub(crate) fn queue_mail(
    repos: &mut dyn Repositories,
    id: [u8; 16],
    sender: Sender,
    to_key: String,
    payload: String,
    now: Timestamp,
) -> Result<NativeOutboxId, StoreError> {
    let owed = Owed {
        payment_id: Uuid::from_bytes(id),
        sender,
        route: RouteEntry {
            method: MethodId::Epicbox,
            value: to_key,
        },
        envelope: payload,
        cutoff: None,
        stage: None,
        notice: false,
    };
    outbox::enqueue(repos, &owed, now)
}

/// The state an outbox entry shows as.
fn shown(state: OutboxState) -> ContactOutboxState {
    match state {
        OutboxState::Queued | OutboxState::Uncertain => ContactOutboxState::Queued,
        OutboxState::Posted => ContactOutboxState::Delivered,
        OutboxState::Failed => ContactOutboxState::Stuck,
    }
}

pub(crate) fn retry_after(attempts: u32) -> Duration {
    let step = usize::try_from(attempts.saturating_sub(1)).unwrap_or(usize::MAX);
    RETRY
        .get(step)
        .or(RETRY.last())
        .copied()
        .unwrap_or_default()
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Queues `envelope` for the contact's mailbox, due at once. A transaction whose slate goes
    /// this way is recorded as exchanged over Epicbox, as it travels there; a sealed file stays
    /// a file.
    pub(crate) async fn enqueue_for_contact(
        &self,
        contact_id: ContactId,
        slate_id: Uuid,
        stage: SlateStage,
        envelope: &[u8],
    ) -> Result<NativeOutboxId, ContactError> {
        self.enqueue_armored(contact_id, slate_id, stage, armor(envelope))
            .await
    }

    /// [`Self::enqueue_for_contact`] for an envelope already armored as `payload`.
    pub(crate) async fn enqueue_armored(
        &self,
        contact_id: ContactId,
        slate_id: Uuid,
        stage: SlateStage,
        payload: String,
    ) -> Result<NativeOutboxId, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                let mailbox = repos
                    .contact_mailbox(contact_id)?
                    .ok_or(ContactError::UnknownContact)?;
                for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                    if let Some(mut tx) = repos.transaction_by_slate(slate_id, direction)?
                        && tx.entry.transport.as_deref() != Some(TRANSPORT_ID.as_str())
                        && lepic_wallet::contact_link::tx_contact(repos, tx.id)? == Some(contact_id)
                    {
                        tx.entry.transport = Some(TRANSPORT_ID.as_str().to_owned());
                        repos.update_transaction(tx.id, &tx.entry)?;
                    }
                }
                let owed =
                    contact_owed(contact_id, slate_id, stage, &mailbox.peer_mailbox, payload);
                Ok(outbox::enqueue(repos, &owed, now)?)
            })
        })
        .await
    }

    /// The outbox's own post of the pairing mail in row `id`, for a caller that holds the
    /// contact engine's turn: the post a due run would make, at once. Returns whether a relay
    /// took it, the one the mail names or another; a row the named relay did not take stays for
    /// the back-off, and a post no relay took is logged as `what`.
    pub(crate) async fn post_mail(
        &self,
        relays: &ContactRelays,
        id: NativeOutboxId,
        what: &'static str,
    ) -> bool {
        // Boxed: the post's future is large, and every pairing step that awaits this one would
        // carry it on its own state and stack.
        let carrier = link_carrier(relays);
        let delivery = Box::pin(self.outbox_deliver(&carrier, id, true));
        match delivery.await {
            Ok((tried, failure)) => {
                let posted = tried
                    .iter()
                    .any(|post| post.state == OutboxState::Posted || !post.relays.is_empty());
                if !posted {
                    match failure {
                        Some(error) => {
                            warn!(row = %id, error = %ErrorChain(&error), "{what}");
                        }
                        None => warn!(row = %id, "{what}"),
                    }
                }
                posted
            }
            Err(error) => {
                warn!(row = %id, error = %ErrorChain(&error), "{what}");
                false
            }
        }
    }

    /// Posts every outbox row that is due: messages to contacts' mailboxes, from our mailbox
    /// key for that contact, and the posts of epic1 payments. Raises
    /// [`lepic_wallet::event::Event::OutboxDelivered`] for each message a contact's relay took.
    /// A payment no route took within [`OUTBOX_STUCK_AFTER`] is marked stuck and raises
    /// [`lepic_wallet::event::Event::OutboxStuck`] once, and is tried on until the chain
    /// reaches its cutoff, or for one with no cutoff, until a mailbox would have dropped it;
    /// see [`ContactBook::payment_post`].
    ///
    /// Fails with [`ContactError::Offline`] before connecting, and as the store does; a relay
    /// that fails is counted, not returned.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_outbox_deliver(
        &self,
        relays: &ContactRelays,
    ) -> Result<OutboxReport, ContactError> {
        check_online(relays)?;
        let _turn = self.wallet.contact_turn().await;
        self.deliver_outbox(relays, false).await
    }

    /// The outbox run of [`ContactBook::contacts_outbox_deliver`], for a caller that holds the
    /// contact engine's turn. `all` tries every waiting row at once, due or not.
    pub(crate) async fn deliver_outbox(
        &self,
        relays: &ContactRelays,
        all: bool,
    ) -> Result<OutboxReport, ContactError> {
        check_online(relays)?;
        self.outbox_fill(relays).await?;
        let tried = self.outbox_due(&link_carrier(relays), all).await?;
        let mut report = OutboxReport::default();
        for post in tried.iter().filter(|post| !post.mail) {
            if post.state == OutboxState::Posted {
                report.delivered = report.delivered.saturating_add(1);
            } else {
                report.failed = report.failed.saturating_add(1);
            }
            if post.ended || post.marked {
                report.stuck = report.stuck.saturating_add(1);
            }
            if let Some(refusal) = &post.refusal {
                report.refused.push(RefusedPost {
                    slate_id: post.slate_id,
                    refusal: refusal.clone(),
                });
            }
        }
        if report != OutboxReport::default() {
            debug!(count = report.delivered, "outbox run");
        }
        Ok(report)
    }

    /// Deletes outbox rows nothing waits for any more: posted ones older than the
    /// relay keeps messages, failed ones of no transaction as old, and any whose transaction
    /// confirmed, was cancelled or expired, except the waiting `withdrawn` of an invoice this
    /// wallet issued and cancelled, and the waiting `cancelled` of a send, a contact's or an
    /// epic1 payer's, which the payer and the receiver must still get. The posted payment of a
    /// cancelled epic1 payment also stays while the payment is kept: its route is where
    /// [`ContactBook::tend_epic1`] sends the `cancelled`, whichever of the two runs first. An
    /// epic1 row of a transaction stays until the transaction ends, so a `posted` not yet sent
    /// when its transaction confirms goes unsent: the payee sees the confirmation itself. One of
    /// no transaction, such as a refusal, goes by the same age rules.
    pub(crate) async fn prune_outbox(&self) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let pruned = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let mut pruned = 0usize;
                    let mut rows = Vec::new();
                    for record in repos.contacts()? {
                        let contact = contact_rows(repos, record.contact_id)?;
                        rows.extend(contact.into_iter().map(|row| (row, true)));
                    }
                    for account in repos.accounts()? {
                        for sender in [Sender::Payer(account.index), Sender::Payee(account.index)] {
                            let epic1 = repos.native_outbox_from(&sender.from_ref())?;
                            rows.extend(epic1.into_iter().map(|row| (row, false)));
                        }
                    }
                    for (stored, contact) in rows {
                        let entry = &stored.entry;
                        let pending = waiting(entry.state);
                        let old = entry.state == OutboxState::Posted
                            && entry
                                .posted_at
                                .and_then(|at| at.checked_add(DELIVERED_KEPT).ok())
                                .is_some_and(|end| end <= now);
                        let stale = entry.state == OutboxState::Failed
                            && entry
                                .created_at
                                .checked_add(DELIVERED_KEPT)
                                .is_ok_and(|end| end <= now);
                        let mut ended = false;
                        let mut of_transaction = false;
                        for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                            if let Some(tx) =
                                repos.transaction_by_slate(entry.payment_id, direction)?
                            {
                                of_transaction = true;
                                // A cancelled payment still has its notice to deliver, an
                                // issued invoice its `withdrawn` and a send its `cancelled`:
                                // a waiting notice stays until it goes or gets stuck, else
                                // the payer could still pay the invoice.
                                let notice_owed =
                                    entry.notice && tx.entry.state == TxState::Cancelled && pending;
                                let notice_route = direction == TxDirection::Outgoing
                                    && crate::epic1::held_for_notice(
                                        repos,
                                        (Sender::parse(&entry.from_ref), entry.stage),
                                        entry.payment_id,
                                        tx.entry.state,
                                    )?;
                                ended |= !notice_owed
                                    && !notice_route
                                    && matches!(
                                        tx.entry.state,
                                        TxState::Confirmed | TxState::Cancelled | TxState::Expired
                                    );
                            }
                        }
                        // A row of no transaction, such as a contact update or an epic1
                        // refusal, goes once the relay would have dropped it anyway.
                        if ended || (!of_transaction && (old || stale)) || (contact && old) {
                            repos.delete_native_outbox(stored.id)?;
                            pruned = pruned.saturating_add(1);
                        }
                    }
                    Ok::<_, StoreError>(pruned)
                })?)
            })
            .await?;
        if pruned > 0 {
            debug!(count = pruned, "contact outbox pruned");
        }
        Ok(())
    }

    /// Posts an outbox entry again, whatever its state: "Send again" for a payment the contact
    /// has not posted, or a stuck one. It goes to the contact's mailbox as it is now, and stays
    /// queued for the next run when the relay does not take it. The contact treats a repeated
    /// slate id as a duplicate.
    ///
    /// Fails with [`ContactError::UnknownTransaction`] for an id that is no message to a
    /// contact, or whose transaction no longer waits for the contact (finalized, posted,
    /// confirmed, cancelled or expired), with [`ContactError::Offline`], and with
    /// [`ContactError::Relay`] when the relay fails.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_outbox_resend(
        &self,
        relays: &ContactRelays,
        id: ContactOutboxId,
    ) -> Result<SlateFormat, ContactError> {
        check_online(relays)?;
        let _turn = self.wallet.contact_turn().await;
        let session = self.wallet.session()?;
        let id = NativeOutboxId(id.0);
        let payload = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let Some(mut stored) = repos.native_outbox_entry(id)? else {
                        return Ok::<_, StoreError>(None);
                    };
                    let Some(contact_id) =
                        Sender::parse(&stored.entry.from_ref).and_then(Sender::contact)
                    else {
                        return Ok(None);
                    };
                    let Some(mailbox) = repos.contact_mailbox(contact_id)? else {
                        return Ok(None);
                    };
                    // Pairing mail, to a key alone other than the contact's, is not the host's
                    // to send again: the outbox's back-off carries it to every relay. A row to a
                    // mailbox on one relay is an earlier release's mail to the contact.
                    let route = peer_route(&mailbox.peer_mailbox);
                    let value = &stored.entry.route_value;
                    if !value.contains('@') && value != route {
                        return Ok(None);
                    }
                    // A slate goes again only while its transaction still waits for the
                    // contact; messages of no transaction, such as contact updates, always may.
                    for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                        if let Some(tx) =
                            repos.transaction_by_slate(stored.entry.payment_id, direction)?
                            && !matches!(tx.entry.state, TxState::Sent | TxState::Received)
                        {
                            return Ok(None);
                        }
                    }
                    let entry = &mut stored.entry;
                    entry.route_value = route.to_owned();
                    entry.state = OutboxState::Queued;
                    entry.next_at = now;
                    // The user asked for it: the day it may take starts now.
                    entry.created_at = now;
                    entry.posted_at = None;
                    repos.update_native_outbox(id, entry)?;
                    Ok(Some(stored.entry.envelope))
                })?)
            })
            .await?
            .ok_or(ContactError::UnknownTransaction)?;
        let (tried, failure) = self
            .outbox_deliver(&link_carrier(relays), id, false)
            .await?;
        if !tried.iter().any(|post| post.state == OutboxState::Posted) {
            return Err(failure.unwrap_or(ContactError::UnknownTransaction));
        }
        info!("outbox entry sent again");
        Ok(if super::sealed::is_epictx(&payload) {
            SlateFormat::Native
        } else {
            SlateFormat::Legacy
        })
    }

    /// How the posts of the payment `slate_id` stand: an epic1 payment or its answer, or a
    /// payment to or from a contact. Whether a route took it, whether it waits and when it is
    /// posted next, the stuck mark, and why the last post did not go. `None` when the outbox
    /// holds no post of it: it never went through the outbox, or its rows were pruned.
    ///
    /// Fails as the store does.
    pub async fn payment_post(
        &self,
        slate_id: SlateId,
    ) -> Result<Option<PaymentPost>, ContactError> {
        let session = self.wallet.session()?;
        let payment_id = Uuid::from_bytes(*slate_id.as_bytes());
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let rows = repos.native_outbox_of(payment_id)?;
                let reason = repos
                    .payment_delivery(payment_id)?
                    .and_then(|delivery| delivery.state_reason);
                Ok::<_, StoreError>(payment_post_of(&rows, reason, now))
            })?)
        })
        .await
    }

    /// The payments the outbox holds marked stuck, sent to or from a contact or over epic1,
    /// by slate id. The caller holds the contact turn.
    pub(crate) async fn stuck_payments(&self) -> Result<Vec<StuckPayment>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut payments = BTreeSet::new();
                for record in repos.contacts()? {
                    let rows = contact_rows(repos, record.contact_id)?;
                    payments.extend(rows.iter().map(|row| row.entry.payment_id));
                }
                for account in repos.accounts()? {
                    for sender in [Sender::Payer(account.index), Sender::Payee(account.index)] {
                        let rows = repos.native_outbox_from(&sender.from_ref())?;
                        payments.extend(rows.iter().map(|row| row.entry.payment_id));
                    }
                }
                let mut stuck = Vec::new();
                for payment_id in payments {
                    let rows = repos.native_outbox_of(payment_id)?;
                    let reason = repos
                        .payment_delivery(payment_id)?
                        .and_then(|delivery| delivery.state_reason);
                    let Some(post) = payment_post_of(&rows, reason, now) else {
                        continue;
                    };
                    if let (true, Some(since)) = (post.stuck, post.stuck_at) {
                        stuck.push(StuckPayment {
                            slate_id: SlateId::from_bytes(payment_id.into_bytes()),
                            since,
                            reason: post.reason,
                        });
                    }
                }
                Ok::<_, StoreError>(stuck)
            })?)
        })
        .await
    }

    /// The contact's outbox entries, by id.
    pub async fn contact_outbox(
        &self,
        contact_id: ContactId,
    ) -> Result<Vec<OutboxView>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for stored in contact_rows(repos, contact_id)? {
                    let entry = &stored.entry;
                    let Some(stage) = entry.stage else {
                        continue;
                    };
                    let waiting = matches!(
                        repos.transaction_by_slate(entry.payment_id, TxDirection::Outgoing)?,
                        Some(tx) if tx.entry.state == TxState::Sent
                    );
                    let late = entry
                        .posted_at
                        .and_then(|at| at.checked_add(NOT_POSTED_AFTER).ok())
                        .is_some_and(|end| end <= now);
                    let state = shown(entry.state);
                    views.push(OutboxView {
                        id: ContactOutboxId(stored.id.0),
                        contact_id,
                        slate_id: SlateId::from_bytes(entry.payment_id.into_bytes()),
                        stage,
                        state,
                        attempts: entry.attempts,
                        created_at: entry.created_at,
                        delivered_at: entry.posted_at,
                        not_posted_yet: state == ContactOutboxState::Delivered && late && waiting,
                    });
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use lepic_store::{MemoryStore, StoreKeys};

    use super::*;

    const OLD: &str = "old@relay.test:80";
    const NEW: &str = "new@relay2.test:80";
    /// The key of [`NEW`], the route a redirected row takes.
    const NEW_KEY: &str = "new";

    fn owed(sender: Sender, payment: u8) -> Owed {
        Owed {
            payment_id: Uuid::from_bytes([payment; 16]),
            sender,
            route: RouteEntry {
                method: MethodId::Epicbox,
                value: OLD.to_owned(),
            },
            envelope: format!("envelope {payment}"),
            cutoff: None,
            stage: Some(SlateStage::Standard1),
            notice: false,
        }
    }

    fn routes(store: &MemoryStore, contact_id: ContactId) -> Vec<(OutboxState, String)> {
        store
            .read(|repos| contact_rows(repos, contact_id))
            .unwrap()
            .into_iter()
            .map(|row| (row.entry.state, row.entry.route_value))
            .collect()
    }

    /// A move points the contact's queued rows, under either salt, at its new mailbox; rows
    /// posted, or posted without an answer, and another contact's rows keep theirs. A removal
    /// drops every row of the contact and none of another's.
    #[test]
    fn a_move_redirects_the_queued_rows_and_a_removal_drops_the_contacts_rows() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let contact = ContactId([1; 16]);
        let other = ContactId([2; 16]);
        let now = Timestamp::from_second(1_800_000_000).unwrap();
        store
            .write(|repos| {
                outbox::enqueue(repos, &owed(Sender::Contact(contact), 1), now)?;
                outbox::enqueue_as(
                    repos,
                    &owed(Sender::Contact(contact), 2),
                    OutboxState::Uncertain,
                    now,
                )?;
                outbox::enqueue_as(
                    repos,
                    &owed(Sender::Contact(contact), 3),
                    OutboxState::Posted,
                    now,
                )?;
                outbox::enqueue(repos, &owed(Sender::ContactOldSalt(contact), 4), now)?;
                outbox::enqueue(repos, &owed(Sender::Contact(other), 5), now)
            })
            .unwrap();

        let moved = store
            .write(|repos| redirect_contact_rows(repos, contact, NEW))
            .unwrap();

        assert_eq!(moved, 2);
        assert_eq!(
            routes(&store, contact),
            [
                (OutboxState::Queued, NEW_KEY.to_owned()),
                (OutboxState::Uncertain, OLD.to_owned()),
                (OutboxState::Posted, OLD.to_owned()),
                (OutboxState::Queued, NEW_KEY.to_owned()),
            ]
        );
        assert_eq!(
            routes(&store, other),
            [(OutboxState::Queued, OLD.to_owned())]
        );

        let dropped = store
            .write(|repos| drop_contact_rows(repos, contact))
            .unwrap();

        assert_eq!(dropped, 4);
        assert!(routes(&store, contact).is_empty());
        assert_eq!(
            routes(&store, other),
            [(OutboxState::Queued, OLD.to_owned())]
        );
    }
}
