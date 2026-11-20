// SPDX-License-Identifier: Apache-2.0
//! One outbox for the posts a payment owes: a link payment and its answer or refusal, an
//! in-person answer, and every message to a contact's mailbox.
//!
//! A post is stored as a queued row in the write that makes it owed, and posted after that
//! write, so a crash leaves it queued. Each route a post tries has a row of its own, never
//! rewritten to another route. The outcome of a post is stored with the payment's delivery
//! state in one write:
//!
//! - taken: posted;
//! - not sent, or refused with a time to come back: failed, and the next route at once; on the
//!   last route, queued again later;
//! - refused, or an address or envelope not taken: failed, and the next route at once;
//! - sent and not answered: uncertain, and the same bytes again on the same route later.
//!
//! A payment's row ends failed once the chain reached its cutoff height; one with no cutoff
//! once it is as old as a mailbox keeps a post ([`RELAY_RETENTION`]). Any other row ends
//! failed once it is [`OUTBOX_STUCK_AFTER`] old. A payment no route took within
//! [`OUTBOX_STUCK_AFTER`] of its newest row is marked stuck ([`stuck_mark`]) and still tried.
//! Nothing moves on from an uncertain row but the host, by asking for the next route: the
//! first post may have arrived.
//!
//! The tip a row's cutoff is checked against:
//!
//! - The posts made in the call that stored the row are not held for a tip. The payment stage
//!   that built the slate has just asked the node for the tip and checked it, and the cutoff
//!   was set from that tip, so it cannot have passed within the call. A restored wallet that
//!   pays before its first refresh posts at once.
//! - Every later post (a due run, the next route, a post again) reads the wallet's confirmed
//!   tip. Nothing is posted at or past the cutoff, and a row with a cutoff stays as it is while
//!   the wallet has confirmed no tip.

use std::time::Duration;

use futures_util::future::join_all;
use hmac::{Hmac, KeyInit, Mac};
use jiff::Timestamp;
use lepic_contact::{ContactCard, Invite};
use lepic_crypto::SecretKey;
use lepic_epic1::{MethodId, RouteEntry};
use lepic_epicbox::{
    ClientError, EpicboxAddress, EpicboxTxId, Identity, MailboxError, MessageError,
    RELAY_RETENTION, RelayEndpoint, RelayErrorKind,
};
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::model::SlateId;
use lepic_store::{
    AccountIndex, ContactId, CopyState, MAX_STATE_REASON_LEN, NativeOutboxEntry, NativeOutboxId,
    OutboxCopy, OutboxState, PairingId, PairingRole, PaymentDelivery, Record, Repositories,
    SlateStage, StoreError, StoredNativeOutbox, StoredOutboxCopy, TxDirection, TxState,
    WalletStore,
};
use lepic_wallet::event::{DeliveryNews, Event, OutboxNews};
use lepic_wallet::namespace::PostRole;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::carrier::Carrier;
use super::epicbox::{
    Envelope, MailboxRelay, Missed, PostError, Posted, RefusalCode, RouteAddressError, Unanswered,
    Unsent,
};
use super::peer::link_posters;
use super::transport::Transport;
use crate::collect::{OldSalt, old_salt_key};
use crate::epic1;
use crate::in_person::{corrupt, identity};
use crate::keys::{box_identity, contact_keys, contact_network, pairing_mailbox};
use crate::outbox::MailboxRefusal;
use crate::outbox::{OUTBOX_STUCK_AFTER, retry_after, waiting};
use crate::private::{class_of, record_keys};
use crate::relay::{endpoint_for, endpoint_of_address, host_text, mailbox_host};
use crate::{ContactBook, ContactError, ContactRelays, LockedRng, hex, new_id};

const PAYER: &str = "epic1-init:";
const PAYEE: &str = "epic1-resp:";
const CONTACT: &str = "contact:";
const CONTACT_OLD_SALT: &str = "contact-old-salt:";
const PAIRING: &str = "pairing:";

/// The payer's row of each answered payment and its copies, `None` for a payment of no post to
/// the payee's key over Epicbox.
type PostedPayments = Vec<Option<(StoredNativeOutbox, Vec<OutboxCopy>)>>;

/// Who a row is sent from, as its `from_ref` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sender {
    /// The payer of an epic1 payment, from the payment's post key.
    Payer(AccountIndex),
    /// The payee of an epic1 payment, from the payment's post key.
    Payee(AccountIndex),
    /// A contact's mailbox.
    Contact(ContactId),
    /// A contact's mailbox under the salt it had before an in-person pairing moved it.
    ContactOldSalt(ContactId),
    /// A pairing in progress: an invitee's reply, an inviter's confirm.
    Pairing(PairingId),
}

impl Sender {
    #[allow(clippy::wrong_self_convention)] // named after the row's `from_ref` column
    pub(crate) fn from_ref(self) -> String {
        match self {
            Self::Payer(account) => format!("{PAYER}{}", account.0),
            Self::Payee(account) => format!("{PAYEE}{}", account.0),
            Self::Contact(id) => format!("{CONTACT}{}", hex::encode(&id.0)),
            Self::ContactOldSalt(id) => format!("{CONTACT_OLD_SALT}{}", hex::encode(&id.0)),
            Self::Pairing(id) => format!("{PAIRING}{}", hex::encode(&id.0)),
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let account = |rest: &str| rest.parse().ok().map(AccountIndex);
        let contact = |rest: &str| hex::decode_array(rest).ok().map(ContactId);
        if let Some(rest) = text.strip_prefix(PAYER) {
            account(rest).map(Self::Payer)
        } else if let Some(rest) = text.strip_prefix(PAYEE) {
            account(rest).map(Self::Payee)
        } else if let Some(rest) = text.strip_prefix(CONTACT_OLD_SALT) {
            contact(rest).map(Self::ContactOldSalt)
        } else if let Some(rest) = text.strip_prefix(CONTACT) {
            contact(rest).map(Self::Contact)
        } else if let Some(rest) = text.strip_prefix(PAIRING) {
            hex::decode_array(rest)
                .ok()
                .map(PairingId)
                .map(Self::Pairing)
        } else {
            None
        }
    }

    pub(crate) fn contact(self) -> Option<ContactId> {
        match self {
            Self::Contact(id) | Self::ContactOldSalt(id) => Some(id),
            Self::Payer(_) | Self::Payee(_) | Self::Pairing(_) => None,
        }
    }
}

/// A post to store as owed.
#[derive(Debug, Clone)]
pub(crate) struct Owed {
    pub(crate) payment_id: Uuid,
    pub(crate) sender: Sender,
    pub(crate) route: RouteEntry,
    /// The armored envelope, as an Epicbox route carries it.
    pub(crate) envelope: String,
    pub(crate) cutoff: Option<Height>,
    pub(crate) stage: Option<SlateStage>,
    /// The post carries a notice (ADR 0067), of no stage.
    pub(crate) notice: bool,
}

/// Stores `owed` as a queued row on its route, due at once, with the payment's delivery
/// state, in the caller's write. Nothing is posted.
pub(crate) fn enqueue(
    repos: &mut dyn Repositories,
    owed: &Owed,
    now: Timestamp,
) -> Result<NativeOutboxId, StoreError> {
    enqueue_as(repos, owed, OutboxState::Queued, now)
}

/// [`enqueue`] for a post that already got as far as `state`, as a store made before the
/// outbox says: one that is not queued counts as posted once.
pub(crate) fn enqueue_as(
    repos: &mut dyn Repositories,
    owed: &Owed,
    state: OutboxState,
    now: Timestamp,
) -> Result<NativeOutboxId, StoreError> {
    let tried = state != OutboxState::Queued;
    let id = repos.enqueue_native_outbox(&NativeOutboxEntry {
        payment_id: owed.payment_id,
        from_ref: owed.sender.from_ref(),
        route_method: owed.route.method.as_str().to_owned(),
        route_value: owed.route.value.clone(),
        envelope: owed.envelope.clone(),
        state,
        attempts: u32::from(tried),
        next_at: now,
        cutoff_height: owed.cutoff,
        stage: owed.stage,
        notice: owed.notice,
        created_at: now,
        posted_at: (state == OutboxState::Posted).then_some(now),
    })?;
    if !owed.notice {
        put_delivery(repos, owed.payment_id, None, now)?;
    }
    Ok(id)
}

/// Makes `stored` a queued row again, due at once, and stores the payment's delivery state, in
/// the caller's write: the same bytes once more, on the same route and in the same row, so a
/// repeat stores nothing new. The posts `stored` still owes are dropped: the row posts to every
/// mailbox again.
pub(crate) fn requeue(
    repos: &mut dyn Repositories,
    stored: &StoredNativeOutbox,
    now: Timestamp,
) -> Result<(), StoreError> {
    for copy in repos.outbox_copies(stored.id)? {
        if copy.state == CopyState::Owed {
            repos.delete_outbox_copy(stored.id, &copy.mailbox)?;
        }
    }
    let entry = NativeOutboxEntry {
        state: OutboxState::Queued,
        attempts: 0,
        next_at: now,
        created_at: now,
        posted_at: None,
        ..stored.entry.clone()
    };
    repos.update_native_outbox(stored.id, &entry)?;
    if !entry.notice {
        put_delivery(repos, entry.payment_id, None, now)?;
    }
    Ok(())
}

/// Stores the payment's delivery state from its rows as they are now; see [`put_delivery_with`].
fn put_delivery(
    repos: &mut dyn Repositories,
    payment_id: Uuid,
    reason: Option<String>,
    now: Timestamp,
) -> Result<(), StoreError> {
    let rows = repos.native_outbox_of(payment_id)?;
    put_delivery_with(repos, payment_id, &rows, reason, now)
}

/// Ends each row of `rows` other than the posted row `id` with the same sender and bytes that is
/// queued or uncertain: the payment went out on another route, so it is not posted again.
fn end_other_copies(
    repos: &mut dyn Repositories,
    rows: &mut [StoredNativeOutbox],
    (id, posted): (NativeOutboxId, &NativeOutboxEntry),
    now: Timestamp,
) -> Result<(), StoreError> {
    for row in rows.iter_mut().filter(|row| {
        row.id != id
            && row.entry.from_ref == posted.from_ref
            && row.entry.envelope == posted.envelope
            && matches!(
                row.entry.state,
                OutboxState::Queued | OutboxState::Uncertain
            )
    }) {
        row.entry.state = OutboxState::Failed;
        row.entry.next_at = now;
        repos.update_native_outbox(row.id, &row.entry)?;
        debug!(row = %row.id, "outbox row ended: the payment went out on another route");
    }
    Ok(())
}

/// Whether `entry` is mail: a notice, or a pairing's reply or confirmation. No outbox report
/// counts mail, and it has no delivery state.
fn mail(entry: &NativeOutboxEntry) -> bool {
    entry.notice
        || (entry.stage.is_none()
            && matches!(Sender::parse(&entry.from_ref), Some(Sender::Pairing(_))))
}

/// What a post of the pairing mail row `id` of `from` changes, in the caller's write: an
/// inviter's confirmation a relay `taken` (the relay it names, or another while the row is owed
/// to that one) marks the confirm sent, and a row that ended (`terminal`) after its pairing or
/// contact was removed is deleted. The confirm is marked at the first relay that took it: an
/// invitee that reads that relay too finishes, and an inviter whose confirm was never marked
/// would end the pairing as not confirmed at its deadline.
fn settle_mail(
    repos: &mut dyn Repositories,
    (id, from): (NativeOutboxId, Option<Sender>),
    taken: bool,
    terminal: bool,
) -> Result<(), StoreError> {
    let gone = match from {
        Some(Sender::Pairing(pairing_id)) => match repos.pending_pairing(pairing_id)? {
            Some(pending) => {
                if taken && pending.role == PairingRole::Inviter {
                    repos.put_setting(&crate::pairing::confirm_out_key(pairing_id), "1")?;
                }
                false
            }
            None => true,
        },
        Some(Sender::Contact(contact_id)) => repos.contact(contact_id)?.is_none(),
        _ => false,
    };
    if terminal && gone {
        repos.delete_native_outbox(id)?;
        debug!(row = %id, "outbox row of a removed pairing ended");
    }
    Ok(())
}

/// Stores the payment's delivery state from `rows`, its rows as written: posted when any row
/// is posted, as the payment's news says, else the state of its newest row; with `reason` when
/// that row is the one just written, else the reason stored before. A posted row has no
/// reason. A post of no transaction has no delivery state, and a notice counts for none.
fn put_delivery_with(
    repos: &mut dyn Repositories,
    payment_id: Uuid,
    rows: &[StoredNativeOutbox],
    reason: Option<String>,
    now: Timestamp,
) -> Result<(), StoreError> {
    let rows = || rows.iter().filter(|row| !row.entry.notice);
    let state = if rows().any(|row| row.entry.state == OutboxState::Posted) {
        Some(OutboxState::Posted)
    } else {
        rows().max_by_key(|row| row.id).map(|row| row.entry.state)
    };
    let before = repos.payment_delivery(payment_id)?;
    if before.is_none() && !has_tx(repos, payment_id)? {
        return Ok(());
    }
    let alias = before.as_ref().and_then(|delivery| delivery.alias.clone());
    repos.put_payment_delivery(&PaymentDelivery {
        payment_id,
        alias,
        state,
        state_reason: (state != Some(OutboxState::Posted))
            .then(|| reason.or_else(|| before.and_then(|delivery| delivery.state_reason)))
            .flatten(),
        updated_at: now,
    })
}

/// Whether a due row is posted now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    Post,
    /// The row has a cutoff and the wallet has confirmed no tip yet: it stays as it is.
    Wait,
    End(Ending),
}

/// Why a row ended without a post.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum Ending {
    #[error("the chain reached the payment's cutoff height")]
    Cutoff,
    /// A row of no payment.
    #[error("no route took the post within a day")]
    Stuck,
    /// A payment's row of no cutoff.
    #[error("no route took the post in the 7 days a mailbox keeps one")]
    Outlived,
}

/// Whether the row `entry` is posted now. `made_now` says the row was stored in this call, so
/// an unknown tip does not hold it (see the module notes).
pub(crate) fn gate(
    entry: &NativeOutboxEntry,
    now: Timestamp,
    tip: Option<Height>,
    made_now: bool,
) -> Gate {
    // A payment's row with a cutoff is tried until the cutoff, however long that is.
    let life = match (payment(entry), entry.cutoff_height) {
        (true, Some(_)) => None,
        (true, None) => Some((RELAY_RETENTION, Ending::Outlived)),
        (false, _) => Some((OUTBOX_STUCK_AFTER, Ending::Stuck)),
    };
    if let Some((life, ending)) = life
        && entry
            .created_at
            .checked_add(life)
            .is_ok_and(|end| end <= now)
    {
        return Gate::End(ending);
    }
    match (entry.cutoff_height, tip) {
        (None, _) => Gate::Post,
        (Some(_), None) if made_now => Gate::Post,
        (Some(_), None) => Gate::Wait,
        (Some(cutoff), Some(tip)) if tip >= cutoff => Gate::End(Ending::Cutoff),
        (Some(_), Some(_)) => Gate::Post,
    }
}

/// Whether `entry` carries a payment's slate, not a notice or other mail.
pub(crate) fn payment(entry: &NativeOutboxEntry) -> bool {
    entry.stage.is_some() && !entry.notice
}

/// When the payment of `rows`, its rows, is marked stuck: [`OUTBOX_STUCK_AFTER`] after its
/// newest payment row was stored. `None` once a route took it, and for no payment row. The
/// mark changes nothing: the outbox tries the payment until its row ends.
pub(crate) fn stuck_mark(rows: &[StoredNativeOutbox]) -> Option<Timestamp> {
    let rows = rows.iter().filter(|row| payment(&row.entry));
    if rows
        .clone()
        .any(|row| row.entry.state == OutboxState::Posted)
    {
        return None;
    }
    let newest = rows.max_by_key(|row| row.id)?;
    newest.entry.created_at.checked_add(OUTBOX_STUCK_AFTER).ok()
}

/// Whether the payment of `rows` crossed its stuck mark between `last`, when its delivery
/// state was stored before, and `now` (it is marked once per mark), and whether it had crossed
/// it by `last`.
fn crossed_mark(
    rows: &[StoredNativeOutbox],
    last: Option<Timestamp>,
    now: Timestamp,
) -> (bool, bool) {
    let (Some(mark), Some(last)) = (stuck_mark(rows), last) else {
        return (false, false);
    };
    (last < mark && mark <= now, mark <= last)
}

/// How a post went, as the outbox acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Taken,
    /// Nothing was sent, or the relay asked to come back after `wait`.
    Unsent {
        wait: Option<Duration>,
    },
    /// Refused, or the route or envelope was not taken: posting it again would not help.
    Refused,
    /// Sent and not answered: it may have arrived.
    Unanswered,
}

pub(crate) fn outcome(result: &Result<Posted, PostError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Taken,
        Err(PostError::NotSent(_)) => Outcome::Unsent { wait: None },
        // A rate limit or a want of room passes: the post goes again after the mailbox's wait.
        Err(PostError::Refused {
            retryable: true,
            retry_after,
            ..
        }) => Outcome::Unsent { wait: *retry_after },
        Err(
            PostError::Refused {
                retryable: false, ..
            }
            | PostError::Address(_)
            | PostError::NoCarrier(_)
            | PostError::Envelope(_)
            | PostError::TooLong { .. },
        ) => Outcome::Refused,
        Err(PostError::Uncertain(_)) => Outcome::Unanswered,
    }
}

/// A row after its post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settled {
    pub(crate) entry: NativeOutboxEntry,
    /// Queue and post the next route at once.
    pub(crate) move_on: bool,
}

/// The row `entry` after a post that went as `outcome`. `has_next` says a route follows.
pub(crate) fn settle(
    mut entry: NativeOutboxEntry,
    outcome: Outcome,
    has_next: bool,
    now: Timestamp,
) -> Settled {
    let was_uncertain = entry.state == OutboxState::Uncertain;
    entry.attempts = entry.attempts.saturating_add(1);
    let backoff = |attempts: u32, wait: Option<Duration>| {
        let wait = wait.map_or(retry_after(attempts), |wait| {
            wait.max(retry_after(attempts))
        });
        now.checked_add(wait).unwrap_or(now)
    };
    let mut move_on = false;
    match outcome {
        Outcome::Taken => {
            entry.state = OutboxState::Posted;
            entry.posted_at = Some(now);
            entry.next_at = now;
        }
        Outcome::Unanswered => {
            entry.state = OutboxState::Uncertain;
            entry.next_at = backoff(entry.attempts, None);
        }
        // An uncertain row stays on its route: the post before may have arrived.
        Outcome::Unsent { wait } if was_uncertain || !has_next => {
            entry.next_at = backoff(entry.attempts, wait);
        }
        Outcome::Unsent { .. } | Outcome::Refused => {
            entry.state = OutboxState::Failed;
            entry.next_at = now;
            move_on = has_next && !was_uncertain;
        }
    }
    Settled { entry, move_on }
}

/// The route mail `entry` to a pairing or a contact narrows to after a post to a key alone
/// that `took`, the relays that took it, names: the key's mailbox on `named`, the relay the
/// mail names (the invite's or the card's), when other relays took the mail and that one did
/// not. The peer is sure to read only there. None when the row is no such mail, names no
/// relay, or no relay or the named one took it.
fn narrowed_to(
    entry: &NativeOutboxEntry,
    named: Option<&RelayEndpoint>,
    took: &[String],
    relays: &ContactRelays,
) -> Option<String> {
    let named = named?;
    if !mail(entry)
        || !matches!(
            Sender::parse(&entry.from_ref),
            Some(Sender::Pairing(_) | Sender::Contact(_) | Sender::ContactOldSalt(_))
        )
        || entry.route_value.contains('@')
        || took.is_empty()
        || took.contains(&host_text(named))
    {
        return None;
    }
    let network = relays.epicbox.network();
    let key = EpicboxAddress::parse_key(&entry.route_value, network).ok()?;
    let to = EpicboxAddress::new(key, network, named.domain().clone(), Some(named.port()));
    Some(to.to_string())
}

/// `entry` after a post that relays other than the one its mail names took: owed to that relay
/// alone, on route `to`, on the back-off. The relays that took it get no second copy; the
/// row's next post settles it as any post to one relay.
fn narrow(mut entry: NativeOutboxEntry, to: String, now: Timestamp) -> Settled {
    entry.attempts = entry.attempts.saturating_add(1);
    entry.route_value = to;
    entry.state = OutboxState::Queued;
    entry.next_at = now.checked_add(retry_after(entry.attempts)).unwrap_or(now);
    Settled {
        entry,
        move_on: false,
    }
}

/// The first of `routes` that no row of `rows` with `envelope` names.
pub(crate) fn next_route<'r>(
    rows: &[StoredNativeOutbox],
    envelope: &str,
    routes: &'r [RouteEntry],
) -> Option<&'r RouteEntry> {
    routes.iter().find(|route| {
        !rows.iter().any(|row| {
            row.entry.envelope == envelope
                && row.entry.route_method == route.method.as_str()
                && row.entry.route_value == route.value
        })
    })
}

/// The row of `route` that follows `entry`.
fn follow(entry: &NativeOutboxEntry, route: &RouteEntry, now: Timestamp) -> NativeOutboxEntry {
    NativeOutboxEntry {
        route_method: route.method.as_str().to_owned(),
        route_value: route.value.clone(),
        state: OutboxState::Queued,
        attempts: 0,
        next_at: now,
        posted_at: None,
        ..entry.clone()
    }
}

/// What the host is told about a post that failed.
pub(crate) fn reason(error: &PostError) -> String {
    let text = match error {
        PostError::NoCarrier(MethodId::Tor) => "Tor is not available".to_owned(),
        PostError::NoCarrier(method) => format!("posting by {method} is not available"),
        PostError::Address(RouteAddressError::Peer(refusal)) => format!(
            "the onion address did not pass the check: {}",
            ErrorChain(refusal.as_ref())
        ),
        other => ErrorChain(other).to_string(),
    };
    clip(text)
}

/// `text` cut to the longest reason the store keeps, at a character boundary.
pub(crate) fn clip(mut text: String) -> String {
    if text.len() > MAX_STATE_REASON_LEN {
        let end = (0..=MAX_STATE_REASON_LEN)
            .rev()
            .find(|end| text.is_char_boundary(*end))
            .unwrap_or(0);
        text.truncate(end);
    }
    text
}

/// The error a post to a contact's relay gives the host that asked for it.
pub(crate) fn contact_error(error: PostError) -> ContactError {
    match error {
        PostError::NotSent(Unsent::Relay(error)) => error,
        PostError::Uncertain(Unanswered::Connection(error)) => ContactError::Relay(error),
        // A refusal that gave its words or a wait keeps them, so the host reads the wait from
        // the error, and one that names its mailbox keeps that, so the host can say which
        // refused. A wait comes from the mailbox's frame on mux/1, from its description on a
        // short connection and from the endpoint's answer on a native one.
        PostError::Refused {
            code,
            retry_after,
            reason,
            mailbox,
            ..
        } if retry_after.is_some()
            || ((reason.is_some() || mailbox.is_some())
                && matches!(code, Some(RefusalCode::Relay(_)))) =>
        {
            let kind = match code {
                Some(RefusalCode::Relay(kind)) => kind,
                _ => RelayErrorKind::InvalidRequest,
            };
            ContactError::Relay(MailboxError::Protocol(ClientError::PostRefused {
                kind,
                description: reason,
                retry_after,
                mailbox,
            }))
        }
        PostError::Refused {
            code: Some(RefusalCode::Relay(kind)),
            ..
        } => ContactError::Relay(MailboxError::Protocol(ClientError::Relay { kind })),
        PostError::Address(RouteAddressError::Mailbox(_)) => ContactError::RelayAddress,
        PostError::Address(RouteAddressError::Host(error)) => error,
        PostError::TooLong { bytes, limit } => ContactError::Relay(MailboxError::Local(
            ClientError::Message(MessageError::OverRelayLimit { bytes, limit }),
        )),
        PostError::NotSent(Unsent::Peer(_) | Unsent::NoRelay) => {
            ContactError::Relay(MailboxError::Unreachable(ClientError::Closed))
        }
        PostError::NoCarrier(_)
        | PostError::Envelope(_)
        | PostError::Address(_)
        | PostError::Uncertain(_)
        | PostError::Refused { .. } => {
            ContactError::Relay(MailboxError::Unanswered(ClientError::Closed))
        }
    }
}

/// The tag of [`post_txid`]'s MAC.
const POST_TXID_TAG: &[u8] = b"lepic/post-txid/v1";

/// The transaction id of the post of the payment `payment_id` at `stage` from the key
/// `secret`: the first 16 bytes of an HMAC-SHA256 under the key over a fixed tag, the payment
/// id and the stage, as a version 4 id. Nothing is stored: the same row posted again carries
/// the same id, and only the key's holder can make it. `None` for a row of no stage, a notice,
/// which posts with no id, and when the MAC takes no key.
pub(crate) fn post_txid(
    secret: &SecretKey,
    payment_id: Uuid,
    stage: Option<SlateStage>,
) -> Option<EpicboxTxId> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.expose_bytes()).ok()?;
    mac.update(POST_TXID_TAG);
    mac.update(payment_id.as_bytes());
    mac.update(match stage? {
        SlateStage::Standard1 => b"S1",
        SlateStage::Standard2 => b"S2",
        SlateStage::Standard3 => b"S3",
        SlateStage::Invoice1 => b"I1",
        SlateStage::Invoice2 => b"I2",
        SlateStage::Invoice3 => b"I3",
    });
    let digest = mac.finalize().into_bytes();
    let first: [u8; 16] = digest.get(..16)?.try_into().ok()?;
    let id = uuid::Builder::from_random_bytes(first).into_uuid();
    EpicboxTxId::parse(&id.simple().to_string()).ok()
}

/// One post the outbox made, or a row it ended without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tried {
    pub(crate) route: RouteEntry,
    pub(crate) state: OutboxState,
    pub(crate) reason: Option<String>,
    /// The row failed and no route follows it: the post ended undelivered.
    pub(crate) ended: bool,
    /// The post did not go and its payment crossed its stuck mark ([`stuck_mark`]) with it.
    pub(crate) marked: bool,
    /// The relays that took a post to a key's mailbox, `domain:port`; empty for any other
    /// post.
    pub(crate) relays: Vec<String>,
    /// The post was pairing mail, which no outbox report counts.
    pub(crate) mail: bool,
    /// The payment the row carries.
    pub(crate) slate_id: SlateId,
    /// The mailbox's refusal of the post, when one refused it.
    pub(crate) refusal: Option<MailboxRefusal>,
}

/// Whether row `id`, `before` and now `state`, took the payment out for the first time, and
/// not on its first post: an earlier post of it may have arrived or failed. `rows` are the
/// payment's rows.
fn posted_late(
    rows: &[StoredNativeOutbox],
    id: NativeOutboxId,
    before: OutboxState,
    state: OutboxState,
) -> bool {
    let others = || rows.iter().filter(|row| row.id != id && !row.entry.notice);
    let earlier = before == OutboxState::Uncertain
        || others().any(|row| {
            matches!(
                row.entry.state,
                OutboxState::Uncertain | OutboxState::Failed
            )
        });
    state == OutboxState::Posted
        && earlier
        && !others().any(|row| row.entry.state == OutboxState::Posted)
}

/// Whether `tip` reached the cutoff height of `entry`; never without one of them.
fn past_cutoff(entry: &NativeOutboxEntry, tip: Option<Height>) -> bool {
    matches!((entry.cutoff_height, tip), (Some(cutoff), Some(tip)) if tip >= cutoff)
}

/// Why the next route of a payment was not posted.
#[derive(Debug, Error)]
pub(crate) enum NextRouteError {
    #[error("the chain reached the payment's cutoff height")]
    PastCutoff,
    #[error("every route of the payment was tried")]
    NoMoreRoutes,
    /// The payment was answered, finalized, cancelled or expired, or there is none.
    #[error("the payment does not wait for a post")]
    NotOpen,
    #[error(transparent)]
    Contact(#[from] ContactError),
}

impl From<StoreError> for NextRouteError {
    fn from(error: StoreError) -> Self {
        Self::Contact(error.into())
    }
}

impl From<lepic_wallet::WalletError> for NextRouteError {
    fn from(error: lepic_wallet::WalletError) -> Self {
        Self::Contact(error.into())
    }
}

/// The routes a row's post may take, in order: a payment's link routes, and the row's own
/// route for any other row or a payment whose record does not read.
fn routes_of(
    repos: &dyn Repositories,
    stored: &StoredNativeOutbox,
    route: &RouteEntry,
) -> Result<Vec<RouteEntry>, StoreError> {
    let routes = match Sender::parse(&stored.entry.from_ref) {
        Some(Sender::Payer(_)) => epic1::pay_routes(repos, stored.entry.payment_id)?,
        _ => None,
    };
    Ok(routes
        .filter(|routes| routes.contains(route))
        .unwrap_or_else(|| vec![route.clone()]))
}

/// A Carrier for an epic1 link's routes: the wallet's relays, and the `https` and Tor
/// posters the relays allow.
pub(crate) fn link_carrier(relays: &ContactRelays) -> Carrier {
    let (http, tor) = link_posters(relays);
    Carrier::new(relays.clone()).with_posters(http, tor)
}

fn route_of(entry: &NativeOutboxEntry) -> Option<RouteEntry> {
    Some(RouteEntry {
        method: entry.route_method.parse().ok()?,
        value: entry.route_value.clone(),
    })
}

/// A row read for its post.
struct Due {
    stored: StoredNativeOutbox,
    sender: Option<Sender>,
    route: Option<RouteEntry>,
    rows: Vec<StoredNativeOutbox>,
    routes: Vec<RouteEntry>,
    /// What the payment's transaction makes of the row.
    by_tx: ByTx,
    now: Timestamp,
}

/// What a post of a row made: its sender and route, the relays that took it, `domain:port`,
/// and the copies it leaves per relay.
struct PostedRow {
    sender: Sender,
    route: RouteEntry,
    took: Vec<String>,
    copies: Vec<OutboxCopy>,
    /// The mailbox's refusal of the post, when one refused it.
    refusal: Option<MailboxRefusal>,
}

impl PostedRow {
    /// A row of `sender` on `route` that no relay took.
    fn none(sender: Sender, route: RouteEntry) -> Self {
        Self {
            sender,
            route,
            took: Vec::new(),
            copies: Vec::new(),
            refusal: None,
        }
    }
}

/// The copies a post to a key's mailbox on the relays of the list leaves: one taken on each
/// relay of `took`, and one owed to each of `missed`, posted there again on the back-off.
fn copies_of(took: &[String], missed: &[Missed], now: Timestamp) -> Vec<OutboxCopy> {
    let taken = took.iter().map(|mailbox| OutboxCopy {
        mailbox: mailbox.clone(),
        state: CopyState::Taken,
        attempts: 1,
        next_at: now,
    });
    let owed = missed.iter().map(|missed| OutboxCopy {
        mailbox: missed.relay.clone(),
        state: CopyState::Owed,
        attempts: 1,
        next_at: copy_due(now, 1, missed.wait),
    });
    taken.chain(owed).collect()
}

/// When a copy tried `attempts` times is tried again: after the outbox's back-off, or after
/// `wait`, the wait its relay asked for, when that is longer.
fn copy_due(now: Timestamp, attempts: u32, wait: Option<Duration>) -> Timestamp {
    let back_off = retry_after(attempts);
    let wait = wait.map_or(back_off, |wait| wait.max(back_off));
    now.checked_add(wait).unwrap_or(now)
}

/// `copy` after one more try that did not go, due again on the back-off or after `wait`.
fn retried(mut copy: OutboxCopy, wait: Option<Duration>, now: Timestamp) -> OutboxCopy {
    copy.attempts = copy.attempts.saturating_add(1);
    copy.next_at = copy_due(now, copy.attempts, wait);
    copy
}

/// A copy read for its post or cancel, with its row and what the payment's transaction makes
/// of the row.
struct DueCopy {
    copy: StoredOutboxCopy,
    stored: StoredNativeOutbox,
    by_tx: ByTx,
}

/// What a try leaves of a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyAfter {
    /// The copy stays as it was.
    Same,
    Put(OutboxCopy),
    /// Nothing more is owed on its relay.
    Delete,
}

/// Why a payment's row ended because its transaction did.
const PAYMENT_ENDED: &str = "the payment ended";

/// What a payment's transaction makes of a row of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByTx {
    /// The post is still owed.
    Owed,
    /// The row ends in this state without a post.
    Ends(OutboxState),
    /// The row is left as it is and not posted; see [`crate::epic1::held_for_notice`].
    Held,
}

/// What a payment's transaction makes of the row `entry` of `sender`. A payer's S1 is done
/// once the payment is finalized, and owed to nobody once it is cancelled or expired, but held
/// while its `cancelled` notice may be owed; a payee's answer is done once the payment
/// confirmed. A message to a contact and a notice are not judged here.
fn by_tx(
    repos: &dyn Repositories,
    sender: Option<Sender>,
    entry: &NativeOutboxEntry,
) -> Result<ByTx, StoreError> {
    if entry.notice {
        return Ok(ByTx::Owed);
    }
    let (stage, payment_id) = (entry.stage, entry.payment_id);
    let (direction, done): (_, &[TxState]) = match sender {
        Some(Sender::Payer(_)) => (
            TxDirection::Outgoing,
            &[TxState::Finalized, TxState::Posted, TxState::Confirmed],
        ),
        // An answer to an in-person invoice is the payer's: its transaction is outgoing.
        Some(Sender::Payee(_)) => (TxDirection::Incoming, &[TxState::Confirmed]),
        Some(Sender::Contact(_) | Sender::ContactOldSalt(_) | Sender::Pairing(_)) | None => {
            return Ok(ByTx::Owed);
        }
    };
    let mut state = repos
        .transaction_by_slate(payment_id, direction)?
        .map(|tx| tx.entry.state);
    if state.is_none() && matches!(sender, Some(Sender::Payee(_))) {
        state = repos
            .transaction_by_slate(payment_id, TxDirection::Outgoing)?
            .map(|tx| tx.entry.state);
    }
    if let Some(state) = state
        && crate::epic1::held_for_notice(repos, (sender, stage), payment_id, state)?
    {
        return Ok(ByTx::Held);
    }
    Ok(match state {
        Some(state) if done.contains(&state) => ByTx::Ends(OutboxState::Posted),
        Some(TxState::Cancelled | TxState::Expired) => ByTx::Ends(OutboxState::Failed),
        // A payer's row of no transaction has nothing to pay; a payee's is a refusal.
        None if matches!(sender, Some(Sender::Payer(_))) => ByTx::Ends(OutboxState::Failed),
        _ => ByTx::Owed,
    })
}

/// Whether the payment has a transaction, sent or received.
fn has_tx(repos: &dyn Repositories, payment_id: Uuid) -> Result<bool, StoreError> {
    for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
        if repos.transaction_by_slate(payment_id, direction)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Posts the row `id` when it is queued or uncertain, and the routes that follow it while
    /// a post fails where nothing reached. Returns each post made and the error of the last
    /// post when it did not go. `made_now` says the caller stored the row in this call: an
    /// unknown tip does not hold its posts (see the module notes). The caller holds the
    /// contact turn.
    pub(crate) async fn outbox_deliver(
        &self,
        carrier: &Carrier,
        id: NativeOutboxId,
        made_now: bool,
    ) -> Result<(Vec<Tried>, Option<ContactError>), ContactError> {
        let mut tried = Vec::new();
        let mut failure = None;
        let mut next = Some(id);
        while let Some(id) = next.take() {
            next = self
                .outbox_post(carrier, id, made_now, &mut tried, &mut failure)
                .await?;
        }
        Ok((tried, failure))
    }

    /// Posts every row that is due, or with `all` every queued and uncertain row, due or
    /// not, then the copies owed to relays that missed a post or owed a cancel. A row whose
    /// post fails is stored so and the run goes on. Returns each post of a row made. The
    /// caller holds the contact turn.
    pub(crate) async fn outbox_due(
        &self,
        carrier: &Carrier,
        all: bool,
    ) -> Result<Vec<Tried>, ContactError> {
        let session = self.wallet.session()?;
        let due = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                // No row waits longer than a day past now.
                let until = if all {
                    now.checked_add(OUTBOX_STUCK_AFTER).unwrap_or(now)
                } else {
                    now
                };
                Ok(session.store.read(|repos| repos.due_native_outbox(until))?)
            })
            .await?;
        let mut tried = Vec::new();
        for stored in due {
            tried.extend(self.outbox_deliver(carrier, stored.id, false).await?.0);
        }
        self.outbox_copies_due(carrier, all).await?;
        if !tried.is_empty() {
            debug!(count = tried.len(), "outbox run");
        }
        Ok(tried)
    }

    /// Queues the envelope of `payment_id`'s newest row for the route that follows the routes
    /// it tried, and posts it. Once every route was tried and the payment is past its stuck
    /// mark ([`stuck_mark`]), the newest row's route is posted again: a row still waiting
    /// there is made due now, and one that ended is queued again on it. The caller holds the
    /// contact turn.
    pub(crate) async fn outbox_next_route(
        &self,
        carrier: &Carrier,
        payment_id: Uuid,
    ) -> Result<Vec<Tried>, NextRouteError> {
        let session = self.wallet.session()?;
        let tip = self.wallet.confirmed_tip()?.map(|tip| tip.height);
        let id = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let rows = repos.native_outbox_of(payment_id)?;
                    let Some(last) = rows.iter().max_by_key(|row| row.id) else {
                        return Ok(Err(NextRouteError::NotOpen));
                    };
                    if !open(repos, payment_id)? {
                        return Ok(Err(NextRouteError::NotOpen));
                    }
                    if past_cutoff(&last.entry, tip) {
                        return Ok(Err(NextRouteError::PastCutoff));
                    }
                    let Some(route) = route_of(&last.entry) else {
                        return Ok(Err(NextRouteError::NoMoreRoutes));
                    };
                    let routes = routes_of(repos, last, &route)?;
                    let next = match next_route(&rows, &last.entry.envelope, &routes) {
                        Some(next) => next,
                        None if stuck_mark(&rows).is_some_and(|mark| mark <= now) => {
                            if waiting(last.entry.state) {
                                let mut entry = last.entry.clone();
                                entry.next_at = now;
                                repos.update_native_outbox(last.id, &entry)?;
                                return Ok(Ok(last.id));
                            }
                            &route
                        }
                        None => return Ok(Err(NextRouteError::NoMoreRoutes)),
                    };
                    let mut entry = follow(&last.entry, next, now);
                    // The host asked for it: the day it may take starts now.
                    entry.created_at = now;
                    let id = repos.enqueue_native_outbox(&entry)?;
                    put_delivery(repos, payment_id, None, now)?;
                    Ok::<_, StoreError>(Ok(id))
                })?)
            })
            .await??;
        Ok(self.outbox_deliver(carrier, id, false).await?.0)
    }

    /// Posts `owed` now, as the user asked: its newest row of the same sender and bytes when
    /// that one still waits, made due now, else a new row. The caller holds the contact turn.
    ///
    /// Fails with the error of the post when it was not taken.
    pub(crate) async fn outbox_post_now(
        &self,
        relays: &ContactRelays,
        owed: Owed,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let id = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let from_ref = owed.sender.from_ref();
                    let waiting = repos
                        .native_outbox_of(owed.payment_id)?
                        .into_iter()
                        .filter(|row| {
                            row.entry.from_ref == from_ref && row.entry.envelope == owed.envelope
                        })
                        .max_by_key(|row| row.id)
                        .filter(|row| {
                            matches!(
                                row.entry.state,
                                OutboxState::Queued | OutboxState::Uncertain
                            )
                        });
                    match waiting {
                        Some(mut row) => {
                            row.entry.next_at = now;
                            repos.update_native_outbox(row.id, &row.entry)?;
                            Ok::<_, StoreError>(row.id)
                        }
                        None => enqueue(repos, &owed, now),
                    }
                })?)
            })
            .await?;
        let (tried, failure) = self
            .outbox_deliver(&link_carrier(relays), id, false)
            .await?;
        if tried.iter().any(|tried| tried.state == OutboxState::Posted) {
            return Ok(());
        }
        Err(
            failure.unwrap_or(ContactError::Relay(MailboxError::Unanswered(
                ClientError::Closed,
            ))),
        )
    }

    /// Posts the row `id` once, stores how it went, and returns the row of the route that
    /// follows when it is to be posted at once.
    #[allow(clippy::too_many_lines)]
    async fn outbox_post(
        &self,
        carrier: &Carrier,
        id: NativeOutboxId,
        made_now: bool,
        tried: &mut Vec<Tried>,
        failure: &mut Option<ContactError>,
    ) -> Result<Option<NativeOutboxId>, ContactError> {
        let session = self.wallet.session()?;
        let tip = self.wallet.confirmed_tip()?.map(|tip| tip.height);
        let due = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.read(|repos| {
                    let Some(stored) = repos.native_outbox_entry(id)? else {
                        return Ok::<_, StoreError>(None);
                    };
                    let rows = repos.native_outbox_of(stored.entry.payment_id)?;
                    let route = route_of(&stored.entry);
                    let routes = match &route {
                        Some(route) => routes_of(repos, &stored, route)?,
                        None => Vec::new(),
                    };
                    let sender = Sender::parse(&stored.entry.from_ref);
                    Ok(Some(Due {
                        by_tx: by_tx(repos, sender, &stored.entry)?,
                        sender,
                        route,
                        stored,
                        rows,
                        routes,
                        now,
                    }))
                })?)
            })
            .await?
        };
        let Some(Due {
            stored,
            sender,
            route,
            rows,
            routes,
            by_tx,
            now,
        }) = due
        else {
            return Ok(None);
        };
        if !matches!(
            stored.entry.state,
            OutboxState::Queued | OutboxState::Uncertain
        ) {
            return Ok(None);
        }
        match by_tx {
            ByTx::Owed => {}
            ByTx::Ends(state) => {
                // The transaction settled the post: nothing is sent and nothing is raised.
                debug!(row = %id, state = ?state, "outbox row settled by its payment");
                return self.settle_by_tx(stored, state, now, tried).await;
            }
            ByTx::Held => {
                debug!(row = %id, "outbox row held for its payment's notice");
                return Ok(None);
            }
        }
        let (Some(sender), Some(route)) = (sender, route) else {
            warn!(row = %id, "outbox row names no sender or route it can post from");
            let settled = settle(stored.entry.clone(), Outcome::Refused, false, now);
            let reason = "the row names no sender or route".to_owned();
            return self
                .outbox_store(stored, None, settled, None, Some(reason), tried)
                .await;
        };
        let ending = match gate(&stored.entry, now, tip, made_now) {
            Gate::Wait => return Ok(None),
            Gate::Post => None,
            Gate::End(ending) => Some(ending),
        };
        if let Some(ending) = ending {
            let mut entry = stored.entry.clone();
            entry.state = OutboxState::Failed;
            let settled = Settled {
                entry,
                move_on: false,
            };
            return self
                .outbox_store(
                    stored,
                    Some(PostedRow::none(sender, route)),
                    settled,
                    None,
                    Some(ending.to_string()),
                    tried,
                )
                .await;
        }
        let mut named = None;
        let result = match self
            .outbox_envelope(carrier.relays(), &stored, sender, &route)
            .await
        {
            Ok(envelope) => {
                if let Envelope::Mailbox {
                    relay: Some(relay), ..
                } = &envelope
                {
                    named = Some(relay.endpoint.clone());
                }
                carrier.post(&envelope, &route, None).await
            }
            Err(error) => {
                warn!(row = %id, error = %ErrorChain(&error), "outbox envelope not built");
                let settled = settle(stored.entry.clone(), Outcome::Refused, false, now);
                let reason = clip(ErrorChain(&error).to_string());
                *failure = Some(error);
                return self
                    .outbox_store(
                        stored,
                        Some(PostedRow::none(sender, route)),
                        settled,
                        None,
                        Some(reason),
                        tried,
                    )
                    .await;
            }
        };
        if result.is_err()
            && let ByTx::Ends(state) = self.by_tx_now(sender, stored.entry.clone()).await?
        {
            // The payment was answered or ended while this post went: a relay refuses a copy
            // the payer cancelled after the answer. The row ends as the payment says, quietly.
            debug!(row = %id, state = ?state, "outbox post not taken after its payment settled");
            return self.settle_by_tx(stored, state, now, tried).await;
        }
        let (took, missed) = match &result {
            Ok(Posted::Relays { took, missed }) => (took.clone(), missed.clone()),
            _ => (Vec::new(), Vec::new()),
        };
        let (mut outcome, mut reason) = match &result {
            Ok(_) => (Outcome::Taken, None),
            Err(error) => (outcome(&result), Some(reason(error))),
        };
        let refusal = result.as_ref().err().and_then(PostError::refusal);
        *failure = None;
        match result {
            Ok(Posted::Reply(reply)) => {
                // The reply is stored before the row says posted; one not stored leaves the
                // row owed, and the endpoint answers the same post again.
                if let Err(error) = self.outbox_reply(&stored, sender, reply).await {
                    warn!(
                        row = %id, error = %ErrorChain(&error),
                        "reply to an outbox post not taken"
                    );
                    outcome = Outcome::Unanswered;
                    reason = Some(clip(ErrorChain(&error).to_string()));
                    *failure = Some(error);
                }
            }
            Ok(_) => {}
            Err(error) => *failure = Some(contact_error(error)),
        }
        if let Some(reason) = &reason {
            let attempt = stored.entry.attempts.saturating_add(1);
            warn!(
                row = %id, route = %route.method, attempt, error = %reason,
                "outbox post did not go"
            );
        }
        let next = next_route(&rows, &stored.entry.envelope, &routes).cloned();
        let settled = match narrowed_to(&stored.entry, named.as_ref(), &took, carrier.relays()) {
            Some(to) => {
                debug!(row = %id, relays = ?took, "pairing mail owed to the relay it names");
                narrow(stored.entry.clone(), to, now)
            }
            None => settle(stored.entry.clone(), outcome, next.is_some(), now),
        };
        let copies = if settled.entry.state == OutboxState::Posted {
            copies_of(&took, &missed, now)
        } else {
            Vec::new()
        };
        let next = next.filter(|_| settled.move_on);
        self.outbox_store(
            stored,
            Some(PostedRow {
                sender,
                route,
                took,
                copies,
                refusal,
            }),
            settled,
            next,
            reason,
            tried,
        )
        .await
    }

    /// The payer's row of each of `keys`, a payment posted to the payee's key over Epicbox,
    /// with its copies, or `None` for a payment of no such post; and the time it was read.
    async fn posted_payments(
        &self,
        keys: Vec<(Uuid, AccountIndex)>,
    ) -> Result<(PostedPayments, Timestamp), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut found = Vec::with_capacity(keys.len());
                for (payment_id, account) in keys {
                    let row = repos.native_outbox_of(payment_id)?.into_iter().find(|row| {
                        row.entry.route_method == MethodId::Epicbox.as_str()
                            && !row.entry.route_value.contains('@')
                            && Sender::parse(&row.entry.from_ref) == Some(Sender::Payer(account))
                            && row.entry.stage.is_some()
                    });
                    found.push(match row {
                        Some(row) => {
                            let copies = repos.outbox_copies(row.id)?;
                            Some((row, copies))
                        }
                        None => None,
                    });
                }
                Ok::<_, StoreError>((found, now))
            })?)
        })
        .await
    }

    /// Cancels the copies left of payments whose answer or refusal was taken. Each of `owed` is
    /// a payment's slate id, account and the relay, as the watch rows name it, the answer was
    /// read on. A payment posted to the payee's key alone went to each relay of the list with
    /// one transaction id ([`post_txid`]); the payee answers one copy, and a cancel goes, all
    /// at once, to each other relay that took a copy. A copy still owed to a relay is not
    /// posted there. A cancel that fails is stored and tried again on the outbox's back-off
    /// (see [`ContactBook::outbox_due`]). A payment of no such post has none to cancel.
    pub(crate) async fn cancel_copies(
        &self,
        carrier: &Carrier,
        owed: Vec<(SlateId, AccountIndex, String)>,
    ) {
        if owed.is_empty() {
            return;
        }
        let keys: Vec<(Uuid, AccountIndex)> = owed
            .iter()
            .map(|(slate_id, account, _)| (Uuid::from_bytes(*slate_id.as_bytes()), *account))
            .collect();
        let (found, now) = match self.posted_payments(keys).await {
            Ok(read) => read,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "copies of answered payments not cancelled");
                return;
            }
        };
        let relays = carrier.relays();
        let mut changes: Vec<(NativeOutboxId, String, CopyAfter)> = Vec::new();
        let mut cancels = Vec::new();
        for ((slate_id, _, read_on), found) in owed.into_iter().zip(found) {
            let Some((row, copies)) = found else {
                continue;
            };
            let mut taken = Vec::new();
            for copy in copies {
                let endpoint = match copy.state {
                    CopyState::Owed => None,
                    CopyState::Cancel => continue,
                    CopyState::Taken => endpoint_for(&copy.mailbox, relays)
                        .ok()
                        .filter(|endpoint| mailbox_host(endpoint) != read_on),
                };
                match endpoint {
                    Some(endpoint) => taken.push((copy, endpoint)),
                    None => changes.push((row.id, copy.mailbox, CopyAfter::Delete)),
                }
            }
            if taken.is_empty() {
                continue;
            }
            match self.payer_post(relays, &row.entry) {
                Ok(Some((from, txid))) => cancels.push((row.id, slate_id, from, txid, taken)),
                Ok(None) => {}
                Err(error) => {
                    warn!(payment = %slate_id, error = %ErrorChain(&error), "copies of an answered payment not cancelled");
                }
            }
        }
        let done = join_all(cancels.into_iter().map(
            |(id, slate_id, from, txid, taken)| async move {
                let (copies, endpoints): (Vec<_>, Vec<_>) = taken.into_iter().unzip();
                let cancelled = carrier.cancel(&slate_id, &from, &txid, endpoints).await;
                copies
                    .into_iter()
                    .zip(cancelled)
                    .map(|(copy, cancelled)| {
                        let after = if cancelled {
                            CopyAfter::Delete
                        } else {
                            CopyAfter::Put(OutboxCopy {
                                state: CopyState::Cancel,
                                attempts: 1,
                                next_at: copy_due(now, 1, None),
                                ..copy.clone()
                            })
                        };
                        (id, copy.mailbox, after)
                    })
                    .collect::<Vec<_>>()
            },
        ))
        .await;
        changes.extend(done.into_iter().flatten());
        if let Err(error) = self.store_copies(changes).await {
            warn!(error = %ErrorChain(&error), "cancels of answered payments' copies not stored");
        }
    }

    /// Posts each copy owed to a relay that missed its post, that is due or with `all` every
    /// one, and cancels each copy owed a cancel that is due, and stores how each went. A copy whose
    /// post or payment ended is deleted, as is a cancel once its relay would have dropped the
    /// copy. The caller holds the contact turn.
    async fn outbox_copies_due(&self, carrier: &Carrier, all: bool) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let tip = self.wallet.confirmed_tip()?.map(|tip| tip.height);
        let (due, now) = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                let until = if all {
                    now.checked_add(OUTBOX_STUCK_AFTER).unwrap_or(now)
                } else {
                    now
                };
                Ok(session.store.read(|repos| {
                    let mut due = Vec::new();
                    for copy in repos.due_outbox_copies(until)? {
                        let Some(stored) = repos.native_outbox_entry(copy.id)? else {
                            continue;
                        };
                        let sender = Sender::parse(&stored.entry.from_ref);
                        let by_tx = by_tx(repos, sender, &stored.entry)?;
                        due.push(DueCopy {
                            copy,
                            stored,
                            by_tx,
                        });
                    }
                    Ok::<_, StoreError>((due, now))
                })?)
            })
            .await?;
        let mut changes = Vec::with_capacity(due.len());
        for due in &due {
            let after = match due.copy.copy.state {
                CopyState::Owed => self.post_owed_copy(carrier, due, now, tip).await,
                // `all` hurries posts only: a cancel stored by this pass's read would go again.
                CopyState::Cancel if due.copy.copy.next_at > now => continue,
                CopyState::Cancel => self.cancel_owed_copy(carrier, due, now).await,
                CopyState::Taken => CopyAfter::Same,
            };
            changes.push((due.copy.id, due.copy.copy.mailbox.clone(), after));
        }
        self.store_copies(changes).await
    }

    /// Posts the owed copy `due` to its relay, and returns what that leaves of it. A copy of a
    /// row no longer posted, or of a payment that no longer owes the post, is deleted.
    async fn post_owed_copy(
        &self,
        carrier: &Carrier,
        due: &DueCopy,
        now: Timestamp,
        tip: Option<Height>,
    ) -> CopyAfter {
        let id = due.copy.id;
        let copy = &due.copy.copy;
        let entry = &due.stored.entry;
        if entry.state != OutboxState::Posted || due.by_tx != ByTx::Owed {
            return CopyAfter::Delete;
        }
        let (Some(sender), Some(route)) = (Sender::parse(&entry.from_ref), route_of(entry)) else {
            return CopyAfter::Delete;
        };
        match gate(entry, now, tip, false) {
            Gate::Post => {}
            Gate::Wait => return CopyAfter::Same,
            Gate::End(_) => return CopyAfter::Delete,
        }
        let envelope = match self
            .outbox_envelope(carrier.relays(), &due.stored, sender, &route)
            .await
        {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!(row = %id, peer_relay = %copy.mailbox, error = %ErrorChain(&error), "owed copy not built");
                return CopyAfter::Delete;
            }
        };
        let result = carrier.post(&envelope, &route, Some(&copy.mailbox)).await;
        if matches!(result, Err(PostError::NotSent(Unsent::NoRelay))) {
            debug!(row = %id, peer_relay = %copy.mailbox, "owed copy's relay no longer listed");
            return CopyAfter::Delete;
        }
        // A mailbox that refuses is asked again until the payment ends (ADR 0065 §3), unless it
        // cancelled the transaction or the post itself cannot be made.
        match &result {
            Err(PostError::Refused {
                code: Some(RefusalCode::Cancelled),
                ..
            }) => return CopyAfter::Delete,
            Err(PostError::Refused {
                retry_after: None, ..
            }) => return CopyAfter::Put(retried(copy.clone(), None, now)),
            _ => {}
        }
        match outcome(&result) {
            Outcome::Taken => {
                debug!(row = %id, peer_relay = %copy.mailbox, "owed copy taken");
                CopyAfter::Put(OutboxCopy {
                    state: CopyState::Taken,
                    attempts: 1,
                    next_at: now,
                    ..copy.clone()
                })
            }
            Outcome::Refused => CopyAfter::Delete,
            Outcome::Unsent { wait } => CopyAfter::Put(retried(copy.clone(), wait, now)),
            Outcome::Unanswered => CopyAfter::Put(retried(copy.clone(), None, now)),
        }
    }

    /// Cancels the copy `due` on its relay, and returns what that leaves of it. A copy its relay
    /// would have dropped by now is deleted.
    async fn cancel_owed_copy(
        &self,
        carrier: &Carrier,
        due: &DueCopy,
        now: Timestamp,
    ) -> CopyAfter {
        let copy = &due.copy.copy;
        let entry = &due.stored.entry;
        if entry
            .created_at
            .checked_add(RELAY_RETENTION)
            .is_ok_and(|end| end <= now)
        {
            return CopyAfter::Delete;
        }
        let relays = carrier.relays();
        let Ok(endpoint) = endpoint_for(&copy.mailbox, relays) else {
            return CopyAfter::Delete;
        };
        let (from, txid) = match self.payer_post(relays, entry) {
            Ok(Some(post)) => post,
            Ok(None) => return CopyAfter::Delete,
            Err(error) => {
                warn!(row = %due.copy.id, error = %ErrorChain(&error), "copy of an answered payment not cancelled");
                return CopyAfter::Delete;
            }
        };
        let slate_id = SlateId::from_bytes(entry.payment_id.into_bytes());
        let cancelled = carrier
            .cancel(&slate_id, &from, &txid, vec![endpoint])
            .await;
        if cancelled.first() == Some(&true) {
            CopyAfter::Delete
        } else {
            CopyAfter::Put(retried(copy.clone(), None, now))
        }
    }

    /// The identity the payer's row `entry` posted from and the transaction id it posted with,
    /// which a cancel of its copies names. None for a row of no payer's slate.
    fn payer_post(
        &self,
        relays: &ContactRelays,
        entry: &NativeOutboxEntry,
    ) -> Result<Option<(Identity, EpicboxTxId)>, ContactError> {
        let Some(Sender::Payer(account)) = Sender::parse(&entry.from_ref) else {
            return Ok(None);
        };
        let network = self.wallet.config().network;
        let secret = self.wallet.post_key(
            account,
            contact_network(network),
            entry.payment_id.as_bytes(),
            PostRole::Initiator,
        )?;
        let Some(txid) = post_txid(&secret, entry.payment_id, entry.stage) else {
            return Ok(None);
        };
        let from = identity(secret, network, &relays.epicbox.settings().endpoint)?;
        Ok(Some((from, txid)))
    }

    /// Stores what tries left of copies, each of a row's copy on a relay, in one write. A row
    /// gone meanwhile took its copies with it.
    async fn store_copies(
        &self,
        changes: Vec<(NativeOutboxId, String, CopyAfter)>,
    ) -> Result<(), ContactError> {
        if changes
            .iter()
            .all(|(_, _, after)| *after == CopyAfter::Same)
        {
            return Ok(());
        }
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                for (id, mailbox, after) in &changes {
                    match after {
                        CopyAfter::Same => {}
                        CopyAfter::Put(copy) => match repos.put_outbox_copy(*id, copy) {
                            Ok(())
                            | Err(StoreError::NotFound {
                                record: Record::NativeOutbox,
                            }) => {}
                            Err(error) => return Err(error),
                        },
                        CopyAfter::Delete => {
                            repos.delete_outbox_copy(*id, mailbox)?;
                        }
                    }
                }
                Ok::<_, StoreError>(())
            })?)
        })
        .await
    }

    /// Ends `stored` in `state`, the one its payment's transaction gives it, without a post and
    /// without news.
    async fn settle_by_tx(
        &self,
        stored: StoredNativeOutbox,
        state: OutboxState,
        now: Timestamp,
        tried: &mut Vec<Tried>,
    ) -> Result<Option<NativeOutboxId>, ContactError> {
        let mut entry = stored.entry.clone();
        entry.state = state;
        entry.next_at = now;
        let reason = (state == OutboxState::Failed).then(|| PAYMENT_ENDED.to_owned());
        let settled = Settled {
            entry,
            move_on: false,
        };
        self.outbox_store(stored, None, settled, None, reason, tried)
            .await
    }

    /// What the payment's transaction makes of the row `entry` of `sender` now; see [`by_tx`].
    async fn by_tx_now(
        &self,
        sender: Sender,
        entry: NativeOutboxEntry,
    ) -> Result<ByTx, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .read(|repos| by_tx(repos, Some(sender), &entry))?)
        })
        .await
    }

    /// Stores `settled` over `stored`, the copies its post left, and the row of `next`, with
    /// the payment's delivery state, in one write, then raises what changed. A post that went
    /// out ends the payment's other rows of the same sender and bytes that still wait: the
    /// payment is out, on this route, and they are not posted again.
    ///
    /// Mail raises nothing: the pairing's own events say what happened, and a notice is not
    /// reported. An inviter's confirmation that went out marks the confirm sent. A row of mail
    /// that ended after its pairing or contact was removed is deleted, as nothing else would.
    #[allow(clippy::too_many_lines)]
    async fn outbox_store(
        &self,
        stored: StoredNativeOutbox,
        posted: Option<PostedRow>,
        settled: Settled,
        next: Option<RouteEntry>,
        reason: Option<String>,
        tried: &mut Vec<Tried>,
    ) -> Result<Option<NativeOutboxId>, ContactError> {
        let session = self.wallet.session()?;
        let id = stored.id;
        let before = stored.entry.state;
        let payment_id = stored.entry.payment_id;
        let entry = settled.entry.clone();
        let next_entry = next
            .as_ref()
            .map(|route| follow(&settled.entry, route, settled.entry.next_at));
        let stored_reason = reason.clone();
        let notice = stored.entry.notice;
        let mail = mail(&stored.entry);
        let from = Sender::parse(&stored.entry.from_ref);
        let terminal = settled.entry.state == OutboxState::Posted
            || (settled.entry.state == OutboxState::Failed && next.is_none());
        let taken = settled.entry.state == OutboxState::Posted
            || posted
                .as_ref()
                .is_some_and(|posted| !posted.took.is_empty());
        let copies = posted
            .as_ref()
            .map(|posted| posted.copies.clone())
            .unwrap_or_default();
        let written = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    match repos.update_native_outbox(id, &entry) {
                        Ok(()) => {}
                        // The contact was removed during the post, its rows with it.
                        Err(StoreError::NotFound {
                            record: Record::NativeOutbox,
                        }) => return Ok(None),
                        Err(error) => return Err(error),
                    }
                    for copy in &copies {
                        repos.put_outbox_copy(id, copy)?;
                    }
                    let next = next_entry
                        .as_ref()
                        .map(|entry| repos.enqueue_native_outbox(entry))
                        .transpose()?;
                    let mut rows = repos.native_outbox_of(payment_id)?;
                    let late = posted_late(&rows, id, before, entry.state);
                    if entry.state == OutboxState::Posted {
                        end_other_copies(repos, &mut rows, (id, &entry), now)?;
                    }
                    let (mut marked, mut was_marked) = (false, false);
                    if !notice {
                        let last = repos
                            .payment_delivery(payment_id)?
                            .map(|delivery| delivery.updated_at);
                        (marked, was_marked) = crossed_mark(&rows, last, now);
                        put_delivery_with(repos, payment_id, &rows, stored_reason, now)?;
                    }
                    if mail {
                        settle_mail(repos, (id, from), taken, terminal)?;
                    }
                    Ok::<_, StoreError>(Some((next, late, marked && !mail, was_marked)))
                })?)
            })
            .await?;
        let Some((next_id, late, marked, was_marked)) = written else {
            debug!(row = %id, "outbox row of a removed contact dropped");
            return Ok(None);
        };
        let state = settled.entry.state;
        let Some(PostedRow {
            sender,
            route,
            took: relays,
            refusal,
            ..
        }) = posted
        else {
            return Ok(next_id);
        };
        let ended = state == OutboxState::Failed && next_id.is_none();
        tried.push(Tried {
            route: route.clone(),
            state,
            reason,
            ended,
            marked,
            relays,
            mail,
            slate_id: SlateId::from_bytes(payment_id.into_bytes()),
            refusal,
        });
        let slate_id = SlateId::from_bytes(payment_id.into_bytes());
        let news = !notice
            && !mail
            && match state {
                OutboxState::Uncertain if before != OutboxState::Uncertain => true,
                // The payment went out after a post that may have arrived or failed, once.
                OutboxState::Posted => late,
                OutboxState::Failed => ended,
                _ => false,
            };
        if news {
            self.wallet.emit(Event::DeliveryChanged(DeliveryNews {
                slate_id,
                state,
                route: route.value.clone(),
            }));
        }
        if let Some(contact_id) = sender.contact().filter(|_| !mail) {
            if state == OutboxState::Posted {
                self.wallet.emit(Event::OutboxDelivered(OutboxNews {
                    contact_id,
                    slate_id,
                }));
            } else if marked || (ended && !was_marked) {
                // Raised once a payment is stuck: at its mark, or when it ends before.
                self.wallet.emit(Event::OutboxStuck(OutboxNews {
                    contact_id,
                    slate_id,
                }));
            }
        }
        if state == OutboxState::Posted {
            info!(row = %id, route = %route.method, "outbox post taken");
        }
        Ok(next_id)
    }

    /// The envelope of `stored` as `route`'s carrier takes it, from `sender`.
    async fn outbox_envelope(
        &self,
        relays: &ContactRelays,
        stored: &StoredNativeOutbox,
        sender: Sender,
        route: &RouteEntry,
    ) -> Result<Envelope, ContactError> {
        let payload = stored.entry.envelope.clone();
        if route.method != MethodId::Epicbox {
            let sealed = lepic_seal::dearmor(&payload).map_err(|_| corrupt("outbox envelope"))?;
            return Ok(Envelope::Sealed(sealed));
        }
        let network = self.wallet.config().network;
        let (role, account) = match sender {
            Sender::Payer(account) => (PostRole::Initiator, account),
            Sender::Payee(account) => (PostRole::Responder, account),
            Sender::Contact(contact_id) | Sender::ContactOldSalt(contact_id) => {
                let old = matches!(sender, Sender::ContactOldSalt(_));
                let mail = mail(&stored.entry);
                return self
                    .contact_envelope(relays, (contact_id, old, mail), route, payload)
                    .await;
            }
            Sender::Pairing(pairing_id) => {
                return self.pairing_envelope(relays, pairing_id, payload).await;
            }
        };
        let secret = self.wallet.post_key(
            account,
            contact_network(network),
            stored.entry.payment_id.as_bytes(),
            role,
        )?;
        // A payment to a key alone goes to every relay of the list: each copy carries one id,
        // so that the copies left once the answer is taken can be cancelled.
        let txid = (role == PostRole::Initiator && !route.value.contains('@'))
            .then(|| post_txid(&secret, stored.entry.payment_id, stored.entry.stage))
            .flatten();
        // The relays check no sender's relay: the key is what counts.
        let from = identity(secret, network, &relays.epicbox.settings().endpoint)?;
        let keyed = !route.value.contains('@');
        let relay = if role == PostRole::Responder && keyed {
            self.read_on(relays, stored.entry.payment_id).await?
        } else {
            None
        };
        let list = if role == PostRole::Initiator && keyed {
            self.given_mailboxes(relays, stored.entry.payment_id)
                .await?
        } else {
            None
        };
        Ok(Envelope::Mailbox {
            from,
            payload,
            relay,
            txid,
            list,
        })
    }

    /// The mailboxes the payment `payment_id` was given for itself, when it was.
    async fn given_mailboxes(
        &self,
        relays: &ContactRelays,
        payment_id: Uuid,
    ) -> Result<Option<Vec<RelayEndpoint>>, ContactError> {
        let session = self.wallet.session()?;
        let slate_id = SlateId::from_bytes(*payment_id.as_bytes());
        let hosts = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| crate::epic1::given_hosts(repos, slate_id))?)
            })
            .await?;
        hosts
            .map(|hosts| {
                hosts
                    .iter()
                    .map(|host| endpoint_for(host, relays))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
    }

    /// The mailbox the payment `payment_id` was read on, as the hint of its answer or refusal:
    /// the answer also goes there when the list no longer holds it.
    async fn read_on(
        &self,
        relays: &ContactRelays,
        payment_id: Uuid,
    ) -> Result<Option<MailboxRelay>, ContactError> {
        let session = self.wallet.session()?;
        let slate_id = SlateId::from_bytes(*payment_id.as_bytes());
        let host = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| crate::epic1::read_on_host(repos, slate_id))?)
            })
            .await?;
        let Some(host) = host else {
            return Ok(None);
        };
        Ok(Some(MailboxRelay {
            endpoint: endpoint_for(&host, relays)?,
            onion: None,
        }))
    }

    /// The envelope of a post to a contact's mailbox, from our mailbox for the contact (`old`:
    /// under its old salt). A route of a key alone takes the contact's relay as its hint. Once
    /// the record is removed, pairing mail (`mail`) goes from a mailbox of no pairing: the
    /// envelope is signed and the contact checks that, not the relay's sender. To a key alone it
    /// then has no hint; on a route narrowed to the relay the contact named, it goes there, with
    /// no onion, as the card is gone.
    async fn contact_envelope(
        &self,
        relays: &ContactRelays,
        (contact_id, old, mail): (ContactId, bool, bool),
        route: &RouteEntry,
        payload: String,
    ) -> Result<Envelope, ContactError> {
        let network = self.wallet.config().network;
        let keyed = !route.value.contains('@');
        let session = self.wallet.session()?;
        let found = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                session.store.read(|repos| {
                    let Some(record) = repos.contact(contact_id)? else {
                        return Ok::<_, ContactError>(None);
                    };
                    let Some(mailbox) = repos.contact_mailbox(contact_id)? else {
                        return Ok(None);
                    };
                    let keys = if old {
                        let text = repos
                            .setting(&old_salt_key(contact_id))?
                            .ok_or(ContactError::UnknownContact)?;
                        let old: OldSalt =
                            serde_json::from_str(&text).map_err(|_| corrupt("old salt"))?;
                        let salt = hex::decode_array(&old.salt).map_err(|_| corrupt("old salt"))?;
                        contact_keys(
                            &session.keychain,
                            network,
                            record.account,
                            record.slot,
                            salt,
                        )?
                    } else {
                        let class = class_of(repos, &record)?;
                        record_keys(&session.keychain, network, &record, &class)?
                    };
                    Ok(Some((record, mailbox, keys)))
                })
            })
            .await?
        };
        let Some((record, mailbox, keys)) = found else {
            if !keyed && !mail {
                return Err(ContactError::UnknownContact);
            }
            let relay = if keyed {
                None
            } else {
                let to = EpicboxAddress::parse(&route.value, relays.epicbox.network())
                    .map_err(|_| ContactError::RelayAddress)?;
                Some(MailboxRelay {
                    endpoint: endpoint_of_address(&to, relays)?,
                    onion: None,
                })
            };
            let seed = new_id(&mut LockedRng(&mut **self.wallet.ports().rng.lock()));
            let (_, from) = pairing_mailbox(&seed, network, &relays.epicbox.settings().endpoint)?;
            return Ok(Envelope::Mailbox {
                from,
                payload,
                relay,
                txid: None,
                list: None,
            });
        };
        let home = endpoint_for(&mailbox.home_relay, relays)?;
        let from = box_identity(&keys, network, &home)?;
        let to = if keyed {
            mailbox.peer_mailbox.as_str()
        } else {
            route.value.as_str()
        };
        let to = EpicboxAddress::parse(to, relays.epicbox.network())
            .map_err(|_| ContactError::RelayAddress)?;
        let onion = record
            .peer
            .as_ref()
            .and_then(|peer| ContactCard::decode(&peer.bytes, contact_network(network)).ok())
            .and_then(|card| {
                card.fields()
                    .home_onion
                    .as_ref()
                    .map(|onion| onion.as_str().to_owned())
            });
        Ok(Envelope::Mailbox {
            from,
            payload,
            relay: Some(MailboxRelay {
                endpoint: endpoint_of_address(&to, relays)?,
                onion,
            }),
            txid: None,
            list: None,
        })
    }

    /// The envelope of a pairing's reply or confirmation, from the pairing's own mailbox on the
    /// invite's relay: the invitee's reply to the inviter's pairing mailbox, the inviter's
    /// confirmation to the invitee's. The relay the peer reads on is the hint, with the invite's
    /// onion when that relay is the invite's.
    async fn pairing_envelope(
        &self,
        relays: &ContactRelays,
        pairing_id: PairingId,
        payload: String,
    ) -> Result<Envelope, ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let pending = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.pending_pairing(pairing_id))?)
            })
            .await?
            .ok_or(ContactError::UnknownContact)?;
        let invite = Invite::decode(&pending.invite, contact_network(network))
            .map_err(ContactError::StoredData)?;
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let (seed, target) = match pending.role {
            PairingRole::Invitee => {
                let to = pending
                    .peer_mailbox
                    .as_deref()
                    .ok_or_else(|| corrupt("pairing mailbox"))?;
                let to = EpicboxAddress::parse(to, relays.epicbox.network())
                    .map_err(|_| ContactError::RelayAddress)?;
                (pending.secrets.code, endpoint_of_address(&to, relays)?)
            }
            PairingRole::Inviter => (pending.secrets.rc, home.clone()),
        };
        let seed = seed.ok_or_else(|| corrupt("pairing secrets"))?;
        let (_, from) = pairing_mailbox(&seed, network, &home)?;
        let onion = (host_text(&target) == host_text(&home))
            .then(|| {
                invite
                    .fields()
                    .onion
                    .as_ref()
                    .map(|onion| onion.as_str().to_owned())
            })
            .flatten();
        Ok(Envelope::Mailbox {
            from,
            payload,
            relay: Some(MailboxRelay {
                endpoint: target,
                onion,
            }),
            txid: None,
            list: None,
        })
    }

    /// Takes the reply envelope an endpoint answered `stored`'s post with.
    async fn outbox_reply(
        &self,
        stored: &StoredNativeOutbox,
        sender: Sender,
        reply: Vec<u8>,
    ) -> Result<(), ContactError> {
        let Sender::Payer(account) = sender else {
            // Only a payment's S1 is posted where an endpoint answers it.
            debug!(row = %stored.id, "reply to an outbox post that asks none dropped");
            return Ok(());
        };
        let slate_id = SlateId::from_bytes(*stored.entry.payment_id.as_bytes());
        match self.take_epic1_answer(slate_id, account, &reply).await {
            Err(ContactError::CannotOpen) => {
                self.take_epic1_refusal(slate_id, account, &reply).await?;
            }
            taken => {
                taken?;
            }
        }
        Ok(())
    }
}

/// Whether the payment still waits for a post: its transaction, when it has one, is sent or
/// received.
fn open(repos: &dyn Repositories, payment_id: Uuid) -> Result<bool, StoreError> {
    let mut any = false;
    for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
        if let Some(tx) = repos.transaction_by_slate(payment_id, direction)? {
            any = true;
            if !matches!(tx.entry.state, TxState::Sent | TxState::Received) {
                return Ok(false);
            }
        }
    }
    Ok(any)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use std::time::Duration;

    use jiff::Timestamp;
    use lepic_epic1::{MethodId, RouteEntry};
    use lepic_primitives::amount::Height;
    use lepic_store::{
        AccountIndex, ContactId, MemoryStore, NativeOutboxEntry, NativeOutboxId, OutboxState,
        PaymentDelivery, StoreKeys, StoredNativeOutbox, WalletStore,
    };
    use uuid::Uuid;

    use lepic_crypto::SecretKey;
    use lepic_store::SlateStage;

    use lepic_epicbox::{MuxCode, RelayErrorKind};
    use lepic_store::{CopyState, OutboxCopy};

    use super::{
        Ending, Gate, Missed, Outcome, RELAY_RETENTION, Sender, clip, contact_error, copies_of,
        crossed_mark, gate, next_route, outcome, post_txid, put_delivery, reason, retried, settle,
        stuck_mark,
    };
    use crate::ContactError;
    use crate::delivery::epicbox::{
        PostError, Posted, RefusalCode, RouteAddressError, Unanswered, Unsent,
    };
    use crate::outbox::MailboxRefusal;
    use crate::outbox::{OUTBOX_STUCK_AFTER, payment_post_of};

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + second).unwrap()
    }

    fn route(method: MethodId, value: &str) -> RouteEntry {
        RouteEntry {
            method,
            value: value.to_owned(),
        }
    }

    fn entry(route: &RouteEntry) -> NativeOutboxEntry {
        NativeOutboxEntry {
            payment_id: Uuid::from_u128(7),
            from_ref: Sender::Payer(AccountIndex(0)).from_ref(),
            route_method: route.method.as_str().to_owned(),
            route_value: route.value.clone(),
            envelope: "ENVELOPE".to_owned(),
            state: OutboxState::Queued,
            attempts: 0,
            next_at: at(0),
            cutoff_height: None,
            stage: None,
            notice: false,
            created_at: at(0),
            posted_at: None,
        }
    }

    /// A failed row keeps the stored reason; a posted row after it clears the reason.
    #[test]
    fn a_posted_row_clears_the_payments_reason() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let row = NativeOutboxEntry {
            stage: Some(SlateStage::Standard1),
            ..entry(&route(MethodId::Epicbox, "key@relay.test"))
        };
        let reason_after = |state| {
            store
                .write(|repos| {
                    repos.enqueue_native_outbox(&NativeOutboxEntry {
                        state,
                        ..row.clone()
                    })?;
                    put_delivery(repos, row.payment_id, None, at(1))?;
                    repos.payment_delivery(row.payment_id)
                })
                .unwrap()
                .and_then(|delivery| delivery.state_reason)
        };
        store
            .write(|repos| {
                repos.put_payment_delivery(&PaymentDelivery {
                    payment_id: row.payment_id,
                    alias: None,
                    state: Some(OutboxState::Failed),
                    state_reason: Some("refused".to_owned()),
                    updated_at: at(0),
                })
            })
            .unwrap();
        assert_eq!(
            reason_after(OutboxState::Failed).as_deref(),
            Some("refused")
        );
        assert_eq!(reason_after(OutboxState::Posted), None);
    }

    #[test]
    fn senders_read_back_from_their_reference() {
        for sender in [
            Sender::Payer(AccountIndex(3)),
            Sender::Payee(AccountIndex(0)),
            Sender::Contact(ContactId([0xab; lepic_store::CONTACT_ID_LEN])),
            Sender::ContactOldSalt(ContactId([0x01; lepic_store::CONTACT_ID_LEN])),
            Sender::Pairing(lepic_store::PairingId([0x22; 16])),
        ] {
            assert_eq!(Sender::parse(&sender.from_ref()), Some(sender));
        }
        assert_eq!(Sender::parse("epic1-init:x"), None);
        assert_eq!(Sender::parse("contact:00"), None);
        assert_eq!(Sender::parse("link:0.screen.1"), None);
    }

    #[test]
    fn a_row_with_a_cutoff_waits_for_a_tip_and_ends_at_the_cutoff() {
        let mut row = entry(&route(MethodId::Epicbox, "a"));
        assert_eq!(gate(&row, at(1), None, false), Gate::Post);
        row.cutoff_height = Some(Height::new(100));
        assert_eq!(gate(&row, at(1), None, false), Gate::Wait);
        assert_eq!(gate(&row, at(1), Some(Height::new(99)), false), Gate::Post);
        assert_eq!(
            gate(&row, at(1), Some(Height::new(100)), false),
            Gate::End(Ending::Cutoff)
        );
        assert_eq!(
            gate(&row, at(1), Some(Height::new(101)), false),
            Gate::End(Ending::Cutoff)
        );
    }

    #[test]
    fn a_row_stored_in_the_call_is_posted_without_a_tip_and_never_past_its_cutoff() {
        let mut row = entry(&route(MethodId::Epicbox, "a"));
        row.cutoff_height = Some(Height::new(100));
        assert_eq!(gate(&row, at(1), None, true), Gate::Post);
        assert_eq!(gate(&row, at(1), Some(Height::new(99)), true), Gate::Post);
        assert_eq!(
            gate(&row, at(1), Some(Height::new(100)), true),
            Gate::End(Ending::Cutoff)
        );
    }

    #[test]
    fn a_row_of_no_payment_ends_a_day_after_it_was_stored() {
        let row = entry(&route(MethodId::Epicbox, "a"));
        let day = i64::try_from(OUTBOX_STUCK_AFTER.as_secs()).unwrap();
        assert_eq!(gate(&row, at(day - 1), None, false), Gate::Post);
        assert_eq!(gate(&row, at(day), None, false), Gate::End(Ending::Stuck));
        let notice = NativeOutboxEntry {
            stage: Some(SlateStage::Standard1),
            notice: true,
            ..row
        };
        assert_eq!(
            gate(&notice, at(day), None, false),
            Gate::End(Ending::Stuck)
        );
    }

    /// A payment's row is posted past the day, up to its cutoff; one with no cutoff up to the
    /// time a mailbox keeps a post.
    #[test]
    fn a_payment_row_runs_past_the_day() {
        let day = i64::try_from(OUTBOX_STUCK_AFTER.as_secs()).unwrap();
        let kept = i64::try_from(RELAY_RETENTION.as_secs()).unwrap();
        let row = NativeOutboxEntry {
            stage: Some(SlateStage::Standard1),
            cutoff_height: Some(Height::new(100)),
            ..entry(&route(MethodId::Epicbox, "a"))
        };
        assert_eq!(
            gate(&row, at(day + 3600), Some(Height::new(99)), false),
            Gate::Post
        );
        assert_eq!(
            gate(&row, at(kept * 2), Some(Height::new(99)), false),
            Gate::Post
        );
        assert_eq!(
            gate(&row, at(day + 3600), Some(Height::new(100)), false),
            Gate::End(Ending::Cutoff)
        );
        let open = NativeOutboxEntry {
            cutoff_height: None,
            ..row
        };
        assert_eq!(gate(&open, at(day + 3600), None, false), Gate::Post);
        assert_eq!(gate(&open, at(kept - 1), None, false), Gate::Post);
        assert_eq!(
            gate(&open, at(kept), None, false),
            Gate::End(Ending::Outlived)
        );
    }

    fn stored(id: u64, entry: NativeOutboxEntry) -> StoredNativeOutbox {
        StoredNativeOutbox {
            id: NativeOutboxId(id),
            entry,
        }
    }

    fn paid(state: OutboxState, created: i64) -> NativeOutboxEntry {
        NativeOutboxEntry {
            stage: Some(SlateStage::Standard1),
            cutoff_height: Some(Height::new(100)),
            state,
            created_at: at(created),
            next_at: at(created),
            attempts: 2,
            ..entry(&route(MethodId::Epicbox, "a"))
        }
    }

    /// The mark falls a day after the newest row of the payment; a posted row clears it, and
    /// a notice neither sets nor clears it.
    #[test]
    fn the_stuck_mark_follows_the_newest_payment_row() {
        let day = i64::try_from(OUTBOX_STUCK_AFTER.as_secs()).unwrap();
        let rows = [
            stored(1, paid(OutboxState::Failed, 0)),
            stored(2, paid(OutboxState::Queued, 600)),
        ];
        assert_eq!(stuck_mark(&rows), Some(at(600 + day)));
        let notice = NativeOutboxEntry {
            notice: true,
            ..paid(OutboxState::Posted, 900)
        };
        let with_notice = [rows[0].clone(), rows[1].clone(), stored(3, notice)];
        assert_eq!(stuck_mark(&with_notice), Some(at(600 + day)));
        let posted = [rows[0].clone(), stored(2, paid(OutboxState::Posted, 600))];
        assert_eq!(stuck_mark(&posted), None);
        assert_eq!(stuck_mark(&[]), None);
    }

    /// The mark is raised once: on the store that crosses it, not on a later one.
    #[test]
    fn the_stuck_mark_is_crossed_once() {
        let day = i64::try_from(OUTBOX_STUCK_AFTER.as_secs()).unwrap();
        let rows = [stored(1, paid(OutboxState::Queued, 0))];
        assert_eq!(
            crossed_mark(&rows, Some(at(day - 60)), at(day - 1)),
            (false, false)
        );
        assert_eq!(
            crossed_mark(&rows, Some(at(day - 60)), at(day + 60)),
            (true, false)
        );
        assert_eq!(
            crossed_mark(&rows, Some(at(day + 60)), at(day + 600)),
            (false, true)
        );
        assert_eq!(crossed_mark(&rows, None, at(day + 60)), (false, false));
    }

    /// An undelivered payment reads its reason, its next post and its mark; a delivered one
    /// reads none of them.
    #[test]
    fn a_payment_post_reads_not_delivered_with_the_reason() {
        let day = i64::try_from(OUTBOX_STUCK_AFTER.as_secs()).unwrap();
        let rows = [
            stored(1, paid(OutboxState::Failed, 0)),
            stored(
                2,
                NativeOutboxEntry {
                    next_at: at(day + 1800),
                    ..paid(OutboxState::Queued, 60)
                },
            ),
        ];
        let reason = Some("no mailbox took the post".to_owned());
        let post = payment_post_of(&rows, reason.clone(), at(day + 120)).unwrap();
        assert!(!post.delivered);
        assert!(post.waiting);
        assert!(post.stuck);
        assert_eq!(post.stuck_at, Some(at(60 + day)));
        assert_eq!(post.next_at, Some(at(day + 1800)));
        assert_eq!(post.attempts, 4);
        assert_eq!(post.reason, reason);
        let early = payment_post_of(&rows, None, at(day)).unwrap();
        assert!(!early.stuck);
        let ended = [stored(1, paid(OutboxState::Failed, 0))];
        let ended = payment_post_of(&ended, reason.clone(), at(day + 120)).unwrap();
        assert!(!ended.waiting && !ended.delivered && ended.stuck);
        assert_eq!(ended.next_at, None);
        let delivered = [rows[0].clone(), stored(2, paid(OutboxState::Posted, 60))];
        let delivered = payment_post_of(&delivered, reason, at(day + 120)).unwrap();
        assert!(delivered.delivered && !delivered.waiting && !delivered.stuck);
        assert_eq!((delivered.next_at, delivered.reason), (None, None));
        let notice = NativeOutboxEntry {
            notice: true,
            ..paid(OutboxState::Queued, 0)
        };
        assert_eq!(payment_post_of(&[stored(1, notice)], None, at(0)), None);
    }

    #[test]
    fn outcomes_follow_the_post_errors() {
        let refused = |retry_after| PostError::refused(None, retry_after, None);
        assert_eq!(outcome(&Ok(Posted::Connection)), Outcome::Taken);
        assert_eq!(outcome(&Ok(Posted::Reply(vec![1]))), Outcome::Taken);
        assert_eq!(
            outcome(&Err(PostError::NotSent(Unsent::Relay(
                ContactError::Offline
            )))),
            Outcome::Unsent { wait: None }
        );
        let wait = Duration::from_secs(90);
        assert_eq!(
            outcome(&Err(refused(Some(wait)))),
            Outcome::Unsent { wait: Some(wait) }
        );
        assert_eq!(outcome(&Err(refused(None))), Outcome::Refused);
        assert_eq!(
            outcome(&Err(PostError::Address(RouteAddressError::HostPort))),
            Outcome::Refused
        );
        assert_eq!(
            outcome(&Err(PostError::NoCarrier(MethodId::Tor))),
            Outcome::Refused
        );
        assert_eq!(
            outcome(&Err(PostError::Envelope(MethodId::Http))),
            Outcome::Refused
        );
        assert_eq!(
            outcome(&Err(PostError::TooLong {
                bytes: 131_072,
                limit: 131_071
            })),
            Outcome::Refused
        );
        assert_eq!(
            outcome(&Err(PostError::Uncertain(Unanswered::Session))),
            Outcome::Unanswered
        );
    }

    #[test]
    fn a_taken_post_is_posted() {
        let settled = settle(
            entry(&route(MethodId::Epicbox, "a")),
            Outcome::Taken,
            true,
            at(5),
        );
        assert_eq!(settled.entry.state, OutboxState::Posted);
        assert_eq!(settled.entry.posted_at, Some(at(5)));
        assert_eq!(settled.entry.attempts, 1);
        assert!(!settled.move_on);
    }

    #[test]
    fn an_unsent_post_moves_on_and_stays_queued_on_the_last_route() {
        let row = entry(&route(MethodId::Epicbox, "a"));
        let unsent = Outcome::Unsent { wait: None };
        let moved = settle(row.clone(), unsent, true, at(5));
        assert_eq!(moved.entry.state, OutboxState::Failed);
        assert!(moved.move_on);

        let last = settle(row.clone(), unsent, false, at(5));
        assert_eq!(last.entry.state, OutboxState::Queued);
        assert!(!last.move_on);
        assert_eq!(last.entry.next_at, at(5 + 30));

        // A relay's time to come back counts when it is longer than the back-off.
        let later = settle(
            row,
            Outcome::Unsent {
                wait: Some(Duration::from_secs(600)),
            },
            false,
            at(5),
        );
        assert_eq!(later.entry.next_at, at(5 + 600));
    }

    #[test]
    fn a_refused_post_moves_on_or_fails() {
        let row = entry(&route(MethodId::Epicbox, "a"));
        let moved = settle(row.clone(), Outcome::Refused, true, at(5));
        assert_eq!(moved.entry.state, OutboxState::Failed);
        assert!(moved.move_on);
        let last = settle(row, Outcome::Refused, false, at(5));
        assert_eq!(last.entry.state, OutboxState::Failed);
        assert!(!last.move_on);
    }

    /// `row`, on its last route, after a refusal of `code` with the mailbox's `words` and
    /// `wait`.
    fn refused_by(
        code: RefusalCode,
        words: &str,
        wait: Option<Duration>,
        row: NativeOutboxEntry,
        now: Timestamp,
    ) -> NativeOutboxEntry {
        let error = PostError::refused(Some(code), wait, Some(words.to_owned()));
        settle(row, outcome(&Err(error)), false, now).entry
    }

    #[test]
    fn a_rate_limited_post_waits_for_the_mailbox_then_the_back_off() {
        let wait = Some(Duration::from_secs(90));
        let row = entry(&route(MethodId::Epicbox, "a"));
        let code = || RefusalCode::Mux(MuxCode::RateLimited);
        let first = refused_by(code(), "Rate limit exceeded.", wait, row, at(5));
        assert_eq!(first.state, OutboxState::Queued);
        assert_eq!(first.next_at, at(5 + 90));
        // The back-off's next step, 2 min, is longer than the mailbox's wait.
        let second = refused_by(code(), "Rate limit exceeded.", wait, first, at(100));
        assert_eq!(second.state, OutboxState::Queued);
        assert_eq!(second.next_at, at(100 + 120));

        // A short connection names its wait in its words alone.
        let row = entry(&route(MethodId::Epicbox, "a"));
        let classic = refused_by(
            RefusalCode::Relay(RelayErrorKind::InvalidRequest),
            "Rate limit exceeded; retry in 300 s.",
            None,
            row,
            at(5),
        );
        assert_eq!(classic.state, OutboxState::Queued);
        assert_eq!(classic.next_at, at(5 + 300));
    }

    #[test]
    fn a_full_mailbox_is_posted_again_on_the_back_off() {
        let cases = [
            (
                RefusalCode::Mux(MuxCode::PostRefused),
                "Recipient mailbox is full; try again later.",
            ),
            (
                RefusalCode::Mux(MuxCode::PostRefused),
                "Too many messages from this sender are waiting for the recipient.",
            ),
            (
                RefusalCode::Relay(RelayErrorKind::InvalidRequest),
                "Relay storage is full; try again later.",
            ),
        ];
        for (code, words) in cases {
            let row = entry(&route(MethodId::Epicbox, "a"));
            let after = refused_by(code, words, None, row, at(5));
            assert_eq!(after.state, OutboxState::Queued, "{words}");
            assert_eq!(after.next_at, at(5 + 30), "{words}");
            assert_eq!(after.attempts, 1);
        }
    }

    #[test]
    fn a_final_refusal_fails_the_row() {
        let cases = [
            (
                RefusalCode::Mux(MuxCode::PostRefused),
                "Address host is not allowed.",
            ),
            (
                RefusalCode::Relay(RelayErrorKind::InvalidRequest),
                "Invalid request.",
            ),
            (
                RefusalCode::Mux(MuxCode::BadSignature),
                "Rate limit exceeded.",
            ),
        ];
        for (code, words) in cases {
            let row = entry(&route(MethodId::Epicbox, "a"));
            let after = refused_by(code, words, None, row, at(5));
            assert_eq!(after.state, OutboxState::Failed, "{words}");
        }
    }

    #[test]
    fn a_refusal_tells_its_mailbox_words_and_wait() {
        let error = PostError::refused(
            Some(RefusalCode::Relay(RelayErrorKind::InvalidRequest)),
            None,
            Some("Rate limit exceeded; retry in 20 s.".to_owned()),
        );
        let mut refusal = error.refusal().unwrap();
        assert_eq!(
            refusal,
            MailboxRefusal {
                mailbox: None,
                reason: Some("Rate limit exceeded; retry in 20 s.".to_owned()),
                retry_after: Some(Duration::from_secs(20)),
                retryable: true,
            }
        );
        refusal.mailbox = Some("relay.test:80".to_owned());
        assert_eq!(
            refusal.to_string(),
            "mailbox relay.test:80 refused the post: Rate limit exceeded; retry in 20 s"
        );
        let full = MailboxRefusal {
            mailbox: Some("relay.test:80".to_owned()),
            reason: Some("Recipient mailbox is full.".to_owned()),
            retry_after: Some(Duration::from_secs(45)),
            retryable: true,
        };
        assert_eq!(
            full.to_string(),
            "mailbox relay.test:80 refused the post: Recipient mailbox is full; retry in 45 s"
        );
        assert_eq!(
            PostError::NotSent(Unsent::Relay(ContactError::Offline)).refusal(),
            None
        );
    }

    /// A copy owed to a relay after the first post goes again on the back-off, or after the
    /// relay's wait when that is longer.
    #[test]
    fn an_owed_copy_is_due_on_the_back_off_or_the_longer_wait_of_its_mailbox() {
        let missed = [
            Missed {
                relay: "a.test:80".to_owned(),
                wait: None,
            },
            Missed {
                relay: "b.test:80".to_owned(),
                wait: Some(Duration::from_secs(10)),
            },
            Missed {
                relay: "c.test:80".to_owned(),
                wait: Some(Duration::from_secs(600)),
            },
        ];
        let copies = copies_of(&["took.test:80".to_owned()], &missed, at(5));
        let due: Vec<_> = copies
            .iter()
            .map(|copy| (copy.mailbox.as_str(), copy.state, copy.next_at))
            .collect();
        assert_eq!(
            due,
            [
                ("took.test:80", CopyState::Taken, at(5)),
                ("a.test:80", CopyState::Owed, at(5 + 30)),
                ("b.test:80", CopyState::Owed, at(5 + 30)),
                ("c.test:80", CopyState::Owed, at(5 + 600)),
            ]
        );
    }

    /// An owed copy its mailbox refuses again waits the longer of the wait it names and the
    /// back-off.
    #[test]
    fn an_owed_copy_refused_again_honours_a_longer_wait() {
        let copy = OutboxCopy {
            mailbox: "a.test:80".to_owned(),
            state: CopyState::Owed,
            attempts: 1,
            next_at: at(0),
        };
        let longer = retried(copy.clone(), Some(Duration::from_secs(3600)), at(40));
        assert_eq!(longer.attempts, 2);
        assert_eq!(longer.next_at, at(40 + 3600));
        let shorter = retried(copy, Some(Duration::from_secs(10)), at(40));
        assert_eq!(shorter.next_at, at(40 + 120));
    }

    #[test]
    fn an_unanswered_post_stays_on_its_route() {
        let row = entry(&route(MethodId::Epicbox, "a"));
        let first = settle(row, Outcome::Unanswered, true, at(5));
        assert_eq!(first.entry.state, OutboxState::Uncertain);
        assert!(!first.move_on);
        assert_eq!(first.entry.next_at, at(5 + 30));

        let again = settle(first.entry, Outcome::Unanswered, true, at(40));
        assert_eq!(again.entry.state, OutboxState::Uncertain);
        assert_eq!(again.entry.next_at, at(40 + 120));

        // Nothing reaching the route now does not make the post before arrive elsewhere.
        let unsent = settle(
            again.entry.clone(),
            Outcome::Unsent { wait: None },
            true,
            at(200),
        );
        assert_eq!(unsent.entry.state, OutboxState::Uncertain);
        assert!(!unsent.move_on);

        let refused = settle(again.entry, Outcome::Refused, true, at(200));
        assert_eq!(refused.entry.state, OutboxState::Failed);
        assert!(!refused.move_on);

        let taken = settle(unsent.entry, Outcome::Taken, true, at(900));
        assert_eq!(taken.entry.state, OutboxState::Posted);
    }

    #[test]
    fn the_next_route_is_the_first_no_row_of_the_envelope_names() {
        let a = route(MethodId::Epicbox, "a");
        let b = route(MethodId::Http, "b");
        let c = route(MethodId::Tor, "c");
        let routes = [a.clone(), b.clone(), c.clone()];
        let row = |id, route: &RouteEntry, envelope: &str| StoredNativeOutbox {
            id: NativeOutboxId(id),
            entry: NativeOutboxEntry {
                envelope: envelope.to_owned(),
                ..entry(route)
            },
        };
        assert_eq!(next_route(&[], "ENVELOPE", &routes), Some(&a));
        let rows = [row(1, &a, "ENVELOPE")];
        assert_eq!(next_route(&rows, "ENVELOPE", &routes), Some(&b));
        // Rows of another envelope of the payment do not count.
        assert_eq!(next_route(&rows, "OTHER", &routes), Some(&a));
        // The same value under another method is another route.
        let rows = [
            row(1, &a, "ENVELOPE"),
            row(2, &route(MethodId::Epicbox, "b"), "ENVELOPE"),
        ];
        assert_eq!(next_route(&rows, "ENVELOPE", &routes), Some(&b));
        let rows = [
            row(1, &a, "ENVELOPE"),
            row(2, &b, "ENVELOPE"),
            row(3, &c, "ENVELOPE"),
        ];
        assert_eq!(next_route(&rows, "ENVELOPE", &routes), None);
    }

    #[test]
    fn reasons_name_tor_and_a_refused_onion() {
        assert_eq!(
            reason(&PostError::NoCarrier(MethodId::Tor)),
            "Tor is not available"
        );
        let refused = PostError::Address(RouteAddressError::Peer("bad checksum".into()));
        assert!(
            reason(&refused).starts_with("the onion address did not pass the check"),
            "{}",
            reason(&refused)
        );
    }

    #[test]
    fn a_long_reason_is_cut_at_a_character() {
        let text = "é".repeat(400);
        let cut = clip(text);
        assert!(cut.len() <= lepic_store::MAX_STATE_REASON_LEN);
        assert_eq!(cut.len(), 512);
        assert_eq!(clip("short".to_owned()), "short");
    }

    #[test]
    fn a_post_txid_is_a_version_4_id_the_same_row_gets_again() {
        let secret = SecretKey::from_array([7; 32]).unwrap();
        let payment = Uuid::from_u128(1);
        let txid = post_txid(&secret, payment, Some(SlateStage::Standard1)).unwrap();

        let id = Uuid::parse_str(txid.as_str()).unwrap();
        assert_eq!(id.get_version_num(), 4);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        assert_eq!(
            post_txid(&secret, payment, Some(SlateStage::Standard1)),
            Some(txid)
        );
    }

    #[test]
    fn a_post_txid_differs_between_payments_stages_and_keys() {
        let secret = SecretKey::from_array([7; 32]).unwrap();
        let other = SecretKey::from_array([8; 32]).unwrap();
        let payment = Uuid::from_u128(1);
        let ids = [
            post_txid(&secret, payment, Some(SlateStage::Standard1)),
            post_txid(&secret, Uuid::from_u128(2), Some(SlateStage::Standard1)),
            post_txid(&secret, payment, Some(SlateStage::Standard2)),
            post_txid(&other, payment, Some(SlateStage::Standard1)),
        ];

        let distinct: std::collections::HashSet<_> = ids.iter().flatten().collect();
        assert_eq!(distinct.len(), ids.len());
        assert_eq!(post_txid(&secret, payment, None), None);
    }

    /// `testdata/vectors/keys/post_txids.json`, written by the conformance generator with
    /// `ring`'s HMAC: the id of each key, payment and stage.
    #[test]
    fn post_txids_match_the_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../testdata/vectors/keys/post_txids.json"
        ))
        .unwrap();
        let text = |value: &serde_json::Value| value.as_str().unwrap().to_owned();
        let cases = vector["expected"]["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 24);
        for case in cases {
            let key: [u8; 32] = crate::hex::decode_array(&text(&case["post_key"])).unwrap();
            let payment: [u8; 16] = crate::hex::decode_array(&text(&case["payment_id"])).unwrap();
            let stage = match text(&case["stage"]).as_str() {
                "S1" => SlateStage::Standard1,
                "S2" => SlateStage::Standard2,
                "S3" => SlateStage::Standard3,
                "I1" => SlateStage::Invoice1,
                "I2" => SlateStage::Invoice2,
                "I3" => SlateStage::Invoice3,
                other => panic!("stage {other}"),
            };
            let secret = SecretKey::from_array(key).unwrap();
            let txid = post_txid(&secret, Uuid::from_bytes(payment), Some(stage)).unwrap();
            assert_eq!(txid.as_str(), text(&case["txid"]));
        }
    }

    #[test]
    fn a_refusal_that_names_a_wait_reaches_the_host_with_it() {
        use lepic_epicbox::{ClientError, MailboxError};

        let wait = Some(Duration::from_secs(12));
        // On mux/1 the frame names the wait; on a short connection the description does, and
        // `refused` reads it out; either way the error carries it as data.
        for error in [
            PostError::refused(
                Some(RefusalCode::Mux(MuxCode::RateLimited)),
                wait,
                Some("Rate limit exceeded.".to_owned()),
            ),
            PostError::refused(
                Some(RefusalCode::Relay(RelayErrorKind::InvalidRequest)),
                None,
                Some("Rate limit exceeded; retry in 12 s.".to_owned()),
            ),
        ] {
            let error = contact_error(error);
            assert!(
                matches!(
                    &error,
                    ContactError::Relay(MailboxError::Protocol(ClientError::PostRefused {
                        retry_after,
                        ..
                    })) if *retry_after == wait
                ),
                "{error:?}"
            );
            assert_eq!(crate::retry_after_of(&error), wait);
        }
        // A final refusal without a wait names none.
        let error = contact_error(PostError::refused(
            Some(RefusalCode::Relay(RelayErrorKind::InvalidRequest)),
            None,
            Some("Invalid request.".to_owned()),
        ));
        assert_eq!(crate::retry_after_of(&error), None);
    }
}
