// SPDX-License-Identifier: Apache-2.0
//! Notices in the engine (ADR 0016, ADR 0067): one intake for every notice, and who sends which.
//!
//! [`Wallet::take_notice`] takes every notice, whoever sent it. [`accepts`] is the table of ADR
//! 0067: which kind is taken from which source. A notice never changes a transaction's state,
//! moves coins or changes a balance, with two exceptions. A `withdrawn` deletes the parked
//! invoice it names while it is unpaid, so it is never paid. A `declined` from the receiver of
//! a send that waits unanswered erases the send, below. Otherwise the core stores a mark or
//! hands the body to the host, and raises an event; the host decides what to do.
//!
//! `declined` goes from the payer of an invoice to its issuer, and from a receiver set to refuse
//! payments nobody asked for to the sender of such an S1 (ADR 0045). The issuer of an invoice
//! records when and raises [`Event::InvoiceDeclined`]. A send declined before it was answered
//! never happened: the sender erases it and unlocks its inputs, keeps only when it was
//! declined, raises [`Event::PaymentDeclined`] and tells no one.
//!
//! `posted` goes from the issuer of a paid invoice to its payer, and from the sender of an
//! ordinary payment to its receiver, once, when the wallet first posts the transaction. The
//! receiver keeps the time of the first report it
//! accepted, which the host shows for [`POSTED_REPORT_WINDOW`] while the payment waits.
//!
//! `cancelled` goes from the sender of an ordinary payment to its receiver once the sender
//! cancelled or released the send after finalizing the receiver's answer. The receiver keeps
//! the time of the first report it accepted while the payment waited, and leaves the payment as
//! it is.

use lepic_node::NodeApi;
use lepic_slate::model::SlateId;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    ContactId, PendingInvoiceStatus, Repositories, SlateStage, StoreError, TxDirection, TxId,
    TxState, WalletStore,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::cancel::erase_declined_send;
use crate::details::POSTED_REPORT_WINDOW;
use crate::early_notice::{self, EarlyLimits};
use crate::epicbox_invoice::stored_codecs;
use crate::event::{
    CancelledPayment, DeclinedInvoice, DeclinedPayment, Event, PostedInvoice, PostedPayment,
    WithdrawnInvoice,
};
use crate::finalize::answered_excess;
use crate::inbox::Hold;
use crate::notice::Notice;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{final_kernel, stored_slate};
use crate::wallet::Wallet;
use lepic_primitives::error_chain::ErrorChain;

/// What a taken notice changed, for the event it raises.
#[derive(Clone, Copy)]
enum Effect {
    Posted {
        tx_id: TxId,
        excess: lepic_crypto::Commitment,
    },
    PaymentPosted {
        tx_id: TxId,
        excess: lepic_crypto::Commitment,
    },
    PaymentCancelled {
        tx_id: TxId,
    },
    Declined {
        tx_id: TxId,
    },
    /// The receiver of the send `tx_id` refused it unanswered. Only the first such notice
    /// raises an event.
    SendDeclined {
        tx_id: TxId,
    },
    /// The issuer withdrew an invoice: a parked one, now deleted, or the paid one `tx_id`.
    Withdrawn {
        tx_id: Option<TxId>,
    },
    /// Accepted, with nothing left to tell the host.
    Noted,
    /// Not from the counterparty of the slate, or with another excess than its payment implies.
    Dropped,
    /// About a slate of which this wallet holds no transaction and no invoice: another install
    /// on the same recovery phrase may hold it.
    Unheld,
    /// A kind its source may not send, by [`accepts`].
    Refused,
    /// A pairing status kind, for the contacts layer.
    Contact,
}

/// What [`Wallet::take_notice`] did with a notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    /// A kind its source may not send ([`accepts`]); nothing changed.
    Refused,
    /// It matched nothing it may change; nothing changed.
    Dropped,
    /// About a slate this wallet does not hold yet; kept in the buffer for it (ADR 0049).
    Buffered,
    /// Taken; it was a repeat or came too late, so no event was raised.
    Noted,
    /// Taken; a mark was stored and its event raised.
    Raised,
    /// A pairing status kind (`pair-*`, `unpaired`) or the host's `app` from a source that may
    /// send it, for the contacts layer: it applies the first to the pairing and keeps the
    /// other for the host.
    Contact,
}

/// Who a notice is from: the envelope it came in and the key that opened it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeFrom {
    /// Anonymous, sealed to the epic1 address key that took the received payment.
    AddressKey(TxId),
    /// Anonymous, sealed to the reply key the send of this slate named.
    ReplyKey(SlateId),
    /// Sealed and signed by a paired contact. Only the contact the slate was exchanged with
    /// counts; its mailbox, which it chooses itself, never decides (RFC 0002 3.4).
    Pairing(ContactId),
    /// Sealed and signed by a private pairing: two wallets of one owner.
    PrivatePairing(ContactId),
}

/// The table of ADR 0067: whether a notice of `notice`'s kind is taken from `from`.
///
/// | Kind | Anonymous | Pairing | Private pairing |
/// |---|---|---|---|
/// | posted, cancelled | address key | yes | no |
/// | declined | reply key | yes | no |
/// | withdrawn | no | yes | no |
/// | pair-*, unpaired | no | yes | unpaired only |
/// | app | no | yes | yes |
#[must_use]
pub fn accepts(notice: &Notice, from: &NoticeFrom) -> bool {
    use NoticeFrom::{AddressKey, Pairing, PrivatePairing, ReplyKey};
    match notice {
        Notice::Posted { .. } | Notice::Cancelled { .. } => {
            matches!(from, AddressKey(_) | Pairing(_))
        }
        Notice::Declined { .. } => matches!(from, ReplyKey(_) | Pairing(_)),
        Notice::Withdrawn { .. }
        | Notice::PairFinished
        | Notice::PairMatch { .. }
        | Notice::PairMismatch { .. } => matches!(from, Pairing(_)),
        Notice::Unpaired | Notice::App { .. } => matches!(from, Pairing(_) | PrivatePairing(_)),
    }
}

/// Prefix of the settings that record a taken decline, one per invoice, keyed by its
/// hyphenated slate id.
pub(crate) const DECLINED_PREFIX: &str = "notice.declined.";

/// Prefix of the settings that record when the receiver of a send declined it unanswered, one
/// per send, keyed by its hyphenated slate id, valued with the time in RFC 3339.
pub(crate) const SEND_DECLINED_PREFIX: &str = "notice.send_declined.";

/// Prefix of the settings that record when the issuer of an invoice this wallet paid withdrew
/// it, one per invoice, keyed by its hyphenated slate id, valued with the time in RFC 3339.
const WITHDRAWN_PREFIX: &str = "notice.withdrawn.";

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

/// The transaction for `slate_id` in `direction` that stored `stage`, when it was exchanged
/// with the paired contact `contact`.
fn transaction_with(
    repos: &dyn Repositories,
    slate_id: Uuid,
    direction: TxDirection,
    stage: SlateStage,
    contact: ContactId,
) -> Result<Option<(TxId, TxState)>, StoreError> {
    let Some(stored) = repos.transaction_by_slate(slate_id, direction)? else {
        return Ok(None);
    };
    // Matched by the transaction the exchange with the contact made, never by a slate id a
    // contact could have claimed.
    let exchanged = crate::contact_link::slate_contact(repos, slate_id)? == Some(contact)
        && crate::contact_link::tx_contact(repos, stored.id)? == Some(contact);
    if !exchanged || repos.slate(slate_id, stage)?.is_none() {
        return Ok(None);
    }
    Ok(Some((stored.id, stored.entry.state)))
}

/// Applies `notice` from `from` by the table of [`accepts`]. Stores marks only.
fn apply_notice(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    notice: &Notice,
    from: NoticeFrom,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    if !accepts(notice, &from) {
        return Ok(Effect::Refused);
    }
    let Some(slate_id) = notice.slate_id() else {
        return Ok(Effect::Contact);
    };
    let id = uuid(slate_id);
    let effect = match (notice.clone(), from) {
        (Notice::Posted { excess, .. }, NoticeFrom::AddressKey(tx_id)) => {
            match answered_here(repos, tx_id, id)? {
                Some(payment) => mark_posted(repos, codecs, payment, id, excess, now)?,
                None => Effect::Dropped,
            }
        }
        (Notice::Cancelled { .. }, NoticeFrom::AddressKey(tx_id)) => {
            match answered_here(repos, tx_id, id)? {
                Some(payment) => mark_cancelled(repos, payment, now)?,
                None => Effect::Dropped,
            }
        }
        (Notice::Declined { .. }, NoticeFrom::ReplyKey(send)) if send == slate_id => {
            take_send_decline(repos, id, None, now)?
        }
        (Notice::Posted { excess, .. }, NoticeFrom::Pairing(contact)) => {
            let payment = transaction_with(
                repos,
                id,
                TxDirection::Outgoing,
                SlateStage::Invoice2,
                contact,
            )?;
            match payment {
                Some((tx_id, _))
                    if final_kernel(repos, codecs, tx_id, id)?
                        .is_some_and(|(expected, _)| expected == excess) =>
                {
                    Effect::Posted { tx_id, excess }
                }
                Some(_) => Effect::Dropped,
                None => report_posted(repos, codecs, id, excess, contact, now)?,
            }
        }
        (Notice::Declined { .. }, NoticeFrom::Pairing(contact)) => match transaction_with(
            repos,
            id,
            TxDirection::Incoming,
            SlateStage::Invoice1,
            contact,
        )? {
            Some((tx_id, TxState::Received)) => take_decline(repos, tx_id, id, now)?,
            // The invoice was paid and finalized, or ended otherwise, before the decline came.
            Some(_) => Effect::Noted,
            None => take_send_decline(repos, id, Some(contact), now)?,
        },
        (Notice::Withdrawn { .. }, NoticeFrom::Pairing(contact)) => {
            withdraw(repos, id, contact, now)?
        }
        (Notice::Cancelled { .. }, NoticeFrom::Pairing(contact)) => {
            report_cancelled(repos, id, contact, now)?
        }
        _ => Effect::Dropped,
    };
    // Only a pairing's notice may come before its slate: an anonymous one is about a payment
    // its key took or named, which this wallet holds.
    if matches!(effect, Effect::Dropped)
        && matches!(from, NoticeFrom::Pairing(_))
        && !holds_slate(repos, id)?
    {
        return Ok(Effect::Unheld);
    }
    Ok(effect)
}

/// [`apply_notice`], then keeps a pairing's notice for a slate this wallet does not hold while
/// the host has the buffer on (ADR 0049). Returns what it changed and whether it was kept.
fn apply_or_keep(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    notice: &Notice,
    from: NoticeFrom,
    limits: Option<EarlyLimits>,
    now: jiff::Timestamp,
) -> Result<(Effect, bool), StoreError> {
    let effect = apply_notice(repos, codecs, notice, from, now)?;
    let kept = match (limits, from) {
        (Some(limits), NoticeFrom::Pairing(contact)) if matches!(effect, Effect::Unheld) => {
            early_notice::keep(repos, limits, notice, contact, now)?
        }
        _ => false,
    };
    Ok((effect, kept))
}

/// The event `effect` raises for the notice about `slate_id`. The one mapping from what a
/// notice changed to what the host is told.
fn event_of(slate_id: SlateId, effect: Effect) -> Option<Event> {
    match effect {
        Effect::Posted { tx_id, excess } => Some(Event::InvoicePosted(PostedInvoice {
            tx_id,
            slate_id,
            excess,
        })),
        Effect::PaymentPosted { tx_id, excess } => Some(Event::PaymentPosted(PostedPayment {
            tx_id,
            slate_id,
            excess,
        })),
        Effect::PaymentCancelled { tx_id } => Some(Event::PaymentCancelled(CancelledPayment {
            tx_id,
            slate_id,
        })),
        Effect::Declined { tx_id } => {
            Some(Event::InvoiceDeclined(DeclinedInvoice { tx_id, slate_id }))
        }
        Effect::SendDeclined { tx_id } => {
            Some(Event::PaymentDeclined(DeclinedPayment { tx_id, slate_id }))
        }
        Effect::Withdrawn { tx_id } => Some(Event::InvoiceWithdrawn(WithdrawnInvoice {
            slate_id,
            tx_id,
        })),
        Effect::Noted | Effect::Dropped | Effect::Unheld | Effect::Refused | Effect::Contact => {
            None
        }
    }
}

/// The settings key recording that the decline of the invoice `slate_id` was taken.
pub(crate) fn declined_setting(slate_id: Uuid) -> String {
    format!("{DECLINED_PREFIX}{slate_id}")
}

/// A `declined` for the invoice `tx_id`, which still waits for payment. Only the first one
/// raises an event; it is recorded with its time, so a repeat, as when the method delivers it
/// again, is noted.
fn take_decline(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    slate_id: Uuid,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let key = declined_setting(slate_id);
    if repos.setting(&key)?.is_some() {
        return Ok(Effect::Noted);
    }
    repos.put_setting(&key, &now.to_string())?;
    Ok(Effect::Declined { tx_id })
}

/// The settings key recording when the receiver of the send `slate_id` declined it.
fn send_declined_setting(slate_id: Uuid) -> String {
    format!("{SEND_DECLINED_PREFIX}{slate_id}")
}

/// A `declined` for a send this wallet made, from its receiver (ADR 0045): the paired
/// `contact` it went through, or, with `None`, whoever holds the reply key the send named.
/// Taken only while the send waits unanswered: `sent`, with its S1 stored and no S2, so the
/// receiver never signed. Such a send never happened: it is erased with its change, context,
/// pending posts and watch, and its inputs unlocked ([`erase_declined_send`]). The time is
/// kept as the only trace, and the first decline raises the event. A send to the wallet itself
/// or one an open recovery holds is not erased and nothing is recorded or raised for it. A
/// repeat, one for a send that was answered, finalized or ended, or one for a send already
/// erased, is noted.
fn take_send_decline(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    contact: Option<ContactId>,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let key = send_declined_setting(slate_id);
    let send = match contact {
        Some(contact) => transaction_with(
            repos,
            slate_id,
            TxDirection::Outgoing,
            SlateStage::Standard1,
            contact,
        )?,
        None => match repos.transaction_by_slate(slate_id, TxDirection::Outgoing)? {
            Some(stored) if repos.slate(slate_id, SlateStage::Standard1)?.is_some() => {
                Some((stored.id, stored.entry.state))
            }
            _ => None,
        },
    };
    let declined = repos.setting(&key)?.is_some();
    let Some((tx_id, state)) = send else {
        // The decline erased the send; a repeat finds only its trace.
        return Ok(if declined {
            Effect::Noted
        } else {
            Effect::Dropped
        });
    };
    if state != TxState::Sent || repos.slate(slate_id, SlateStage::Standard2)?.is_some() {
        return Ok(Effect::Noted);
    }
    if let Some(entry) = repos.transaction(tx_id)?
        && !erase_declined_send(repos, tx_id, &entry)?
    {
        // A self-send or one an open recovery holds stays: it was not declined away.
        return Ok(Effect::Noted);
    }
    if declined {
        return Ok(Effect::Noted);
    }
    repos.put_setting(&key, &now.to_string())?;
    Ok(Effect::SendDeclined { tx_id })
}

/// When the payer of the invoice `slate_id` declined it. A decline recorded without a time, as
/// older versions stored it (`1`), still counts as declined for the notice but has none to give.
pub(crate) fn payer_declined_report(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    Ok(repos
        .setting(&declined_setting(slate_id))?
        .and_then(|at| at.parse().ok()))
}

/// When the receiver of the send `slate_id` declined it unanswered (ADR 0045).
pub(crate) fn receiver_declined_report(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    Ok(repos
        .setting(&send_declined_setting(slate_id))?
        .and_then(|at| at.parse().ok()))
}

/// Whether this wallet holds a transaction or a parked invoice of `slate_id`.
fn holds_slate(repos: &dyn Repositories, slate_id: Uuid) -> Result<bool, StoreError> {
    for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
        if repos.transaction_by_slate(slate_id, direction)?.is_some() {
            return Ok(true);
        }
    }
    Ok(repos.pending_invoice(slate_id)?.is_some())
}

/// When the sender of the received payment `tx_id` reported that it posted it, while that
/// report is younger than [`POSTED_REPORT_WINDOW`] at `now`. The caller checks that the payment
/// still waits for its sender.
pub(crate) fn posted_report(
    repos: &dyn Repositories,
    tx_id: TxId,
    now: jiff::Timestamp,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    let Some(reported) = repos.tx_marks(tx_id)?.sender_posted_at else {
        return Ok(None);
    };
    // A report dated after `now`, as after the clock was set back, is not shown: it would
    // otherwise outlast the window.
    let age = now.duration_since(reported);
    Ok((!age.is_negative() && age < POSTED_REPORT_WINDOW).then_some(reported))
}

/// A `posted` from the paired contact that sent a payment. Accepted only from the payment's
/// counterparty, for a payment whose S2 is stored, with the kernel excess
/// that S2 implies. Only the first report for a payment that still waits for its sender is kept
/// and raises an event; a repeat, or a report for a payment that confirmed or ended, is noted.
fn report_posted(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    slate_id: Uuid,
    excess: lepic_crypto::Commitment,
    contact: ContactId,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let Some((tx_id, state)) = transaction_with(
        repos,
        slate_id,
        TxDirection::Incoming,
        SlateStage::Standard2,
        contact,
    )?
    else {
        return Ok(Effect::Dropped);
    };
    mark_posted(repos, codecs, (tx_id, state), slate_id, excess, now)
}

/// Keeps the first `posted` for the received payment `tx_id` in `state`, when `excess` is the
/// kernel excess its stored S2 implies, while the payment waits for its sender; see
/// [`report_posted`].
fn mark_posted(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    (tx_id, state): (TxId, TxState),
    slate_id: Uuid,
    excess: lepic_crypto::Commitment,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let expected = stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Standard2)?
        .and_then(|reply| answered_excess(&reply).ok());
    if expected != Some(excess) {
        return Ok(Effect::Dropped);
    }
    let mut marks = repos.tx_marks(tx_id)?;
    if state != TxState::Received || marks.sender_posted_at.is_some() {
        return Ok(Effect::Noted);
    }
    marks.sender_posted_at = Some(now);
    repos.put_tx_marks(tx_id, &marks)?;
    Ok(Effect::PaymentPosted { tx_id, excess })
}

/// A `cancelled` from the paired contact that sent a payment. Accepted only from the payment's
/// counterparty, for a payment whose S2 is stored, so
/// one this wallet answered. Only the first report for a payment that still waits for its sender
/// is kept and raises an event; a repeat, or a report for a payment that confirmed or ended here,
/// is noted. Nothing else changes: the host decides whether to cancel the payment.
fn report_cancelled(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    contact: ContactId,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let Some((tx_id, state)) = transaction_with(
        repos,
        slate_id,
        TxDirection::Incoming,
        SlateStage::Standard2,
        contact,
    )?
    else {
        return Ok(Effect::Dropped);
    };
    mark_cancelled(repos, (tx_id, state), now)
}

/// Keeps the first `cancelled` for the received payment `tx_id` in `state` while the payment
/// waits for its sender; see [`report_cancelled`].
fn mark_cancelled(
    repos: &mut dyn Repositories,
    (tx_id, state): (TxId, TxState),
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let mut marks = repos.tx_marks(tx_id)?;
    if state != TxState::Received || marks.sender_cancelled_at.is_some() {
        return Ok(Effect::Noted);
    }
    marks.sender_cancelled_at = Some(now);
    repos.put_tx_marks(tx_id, &marks)?;
    Ok(Effect::PaymentCancelled { tx_id })
}

/// The received payment `tx_id` of `slate_id` with its state, when this wallet answered it:
/// its S2 is stored.
fn answered_here(
    repos: &dyn Repositories,
    tx_id: TxId,
    slate_id: Uuid,
) -> Result<Option<(TxId, TxState)>, StoreError> {
    let Some(stored) = repos.transaction_by_slate(slate_id, TxDirection::Incoming)? else {
        return Ok(None);
    };
    if stored.id != tx_id || repos.slate(slate_id, SlateStage::Standard2)?.is_none() {
        return Ok(None);
    }
    Ok(Some((stored.id, stored.entry.state)))
}

/// The `cancelled` an epic1 payer sends for the payment `slate_id` it cancelled (RFC 0003 5.9).
/// `None` when its payee declined it: that payee did not take it.
///
/// Fails as the store does.
pub fn epic1_cancelled_notice(
    repos: &dyn Repositories,
    slate_id: SlateId,
) -> Result<Option<Notice>, StoreError> {
    if repos
        .setting(&format!("{SEND_DECLINED_PREFIX}{}", uuid(slate_id)))?
        .is_some()
    {
        return Ok(None);
    }
    Ok(Some(Notice::Cancelled { slate_id }))
}

/// When the sender of the received payment `tx_id` reported that it cancelled it. The caller
/// checks the payment's state.
pub(crate) fn cancelled_report(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    Ok(repos.tx_marks(tx_id)?.sender_cancelled_at)
}

/// A `withdrawn` from the paired `contact` that issued the invoice `slate_id`. A parked
/// invoice that is not paid is deleted, so it is never paid. For the invoice this wallet paid,
/// while its payment waits for the issuer, the first one is recorded with its time and raises
/// the event; the payment stays as it is, and its host decides whether to cancel it. A repeat,
/// or one for a payment that confirmed or ended, is noted.
fn withdraw(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    contact: ContactId,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    if let Some(parked) = repos.pending_invoice(slate_id)?
        && crate::contact_link::slate_contact(repos, slate_id)? == Some(contact)
        && parked.status != PendingInvoiceStatus::Paid
    {
        repos.delete_pending_invoice(slate_id)?;
        return Ok(Effect::Withdrawn { tx_id: None });
    }
    let Some((tx_id, state)) = transaction_with(
        repos,
        slate_id,
        TxDirection::Outgoing,
        SlateStage::Invoice2,
        contact,
    )?
    else {
        return Ok(Effect::Dropped);
    };
    let key = format!("{WITHDRAWN_PREFIX}{slate_id}");
    if state != TxState::Sent || repos.setting(&key)?.is_some() {
        return Ok(Effect::Noted);
    }
    repos.put_setting(&key, &now.to_string())?;
    Ok(Effect::Withdrawn { tx_id: Some(tx_id) })
}

/// The invoice whose `withdrawn` goes to its paired contact for the cancelled transaction
/// `tx_id`: one this wallet issued to the contact, while no payment of it was finalized.
fn withdrawal_target(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<SlateId>, StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    let Some(slate_id) = entry.slate_id else {
        return Ok(None);
    };
    if entry.direction != TxDirection::Incoming
        || crate::contact_link::slate_contact(repos, slate_id)?.is_none()
        || repos.slate(slate_id, SlateStage::Invoice1)?.is_none()
        || repos.slate(slate_id, SlateStage::Invoice3)?.is_some()
    {
        return Ok(None);
    }
    Ok(Some(SlateId::from_bytes(slate_id.into_bytes())))
}

/// The send whose `cancelled` goes to its paired contact for the cancelled send `tx_id`: an
/// ordinary payment through the contact, whose receiver was not told before. With `answered`,
/// only when this wallet finalized the receiver's answer, so the receiver holds an S2 and waits
/// for this wallet to post it.
fn cancellation_target(
    repos: &dyn Repositories,
    tx_id: TxId,
    answered: bool,
) -> Result<Option<SlateId>, StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    let Some(slate_id) = entry.slate_id else {
        return Ok(None);
    };
    if entry.direction != TxDirection::Outgoing
        || entry.state != TxState::Cancelled
        || crate::contact_link::slate_contact(repos, slate_id)?.is_none()
        || repos.slate(slate_id, SlateStage::Standard1)?.is_none()
        || (answered && repos.slate(slate_id, SlateStage::Standard3)?.is_none())
        || repos.tx_marks(tx_id)?.cancelled_answered
    {
        return Ok(None);
    }
    Ok(Some(SlateId::from_bytes(slate_id.into_bytes())))
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes `notice` from `from`: the one intake for every notice (ADR 0067). [`accepts`] says
    /// which kind is taken from which source; a kind its source may not send changes nothing.
    /// A notice about a slate is taken only from the slate's counterparty: the paired contact
    /// it was exchanged with, or the key its payment used. Taking one stores a mark at most and
    /// raises the event for it; the first of each kind for a payment raises it, a repeat is
    /// noted. No notice changes a transaction's state, moves coins or changes a balance. A
    /// pairing's notice about a slate this wallet does not hold stays in the buffer while the
    /// host has it on (ADR 0049). A pairing status kind is left to the contacts layer.
    ///
    /// Fails with [`crate::WalletError::Locked`] and as the store does; the caller keeps the
    /// message and takes it again.
    pub async fn take_notice(
        &self,
        notice: Notice,
        from: NoticeFrom,
    ) -> Result<Taken, crate::WalletError> {
        let codecs = stored_codecs(self.config().network);
        let limits = EarlyLimits::of(&self.config().policy);
        let taken = notice.clone();
        let (effect, buffered) = self
            .inbox_write(move |repos, now| apply_or_keep(repos, &codecs, &taken, from, limits, now))
            .await?;
        Ok(self.report_notice(&notice, effect, buffered))
    }

    /// Applies the notices kept for `slate_id`, now that the slate is here, and raises their
    /// events. An entry that matches nothing goes. The entries leave the buffer in the store
    /// transaction that applies them; the caller runs this after storing the slate and before
    /// acknowledging it, so a delivery that repeats finds them there or their effect stored.
    pub async fn apply_early_notices(&self, slate_id: SlateId) -> Result<(), Hold> {
        let Some(limits) = EarlyLimits::of(&self.config().policy) else {
            return Ok(());
        };
        let codecs = stored_codecs(self.config().network);
        let effects = self
            .inbox_write(move |repos, now| {
                let mut effects = Vec::new();
                for (notice, contact) in early_notice::take(repos, limits, slate_id, now)? {
                    let from = NoticeFrom::Pairing(contact);
                    let effect = apply_notice(repos, &codecs, &notice, from, now)?;
                    effects.push((notice, effect));
                }
                Ok(effects)
            })
            .await?;
        for (notice, effect) in effects {
            self.report_notice(&notice, effect, false);
        }
        Ok(())
    }

    /// Raises the event a taken notice calls for, and says what became of it.
    fn report_notice(&self, notice: &Notice, effect: Effect, buffered: bool) -> Taken {
        let kind = notice.kind();
        let taken = match effect {
            Effect::Refused => {
                debug!(kind, "notice of a kind its source may not send dropped");
                return Taken::Refused;
            }
            Effect::Contact => return Taken::Contact,
            Effect::Unheld if buffered => Taken::Buffered,
            Effect::Dropped | Effect::Unheld => Taken::Dropped,
            Effect::Noted => Taken::Noted,
            _ => Taken::Raised,
        };
        let Some(slate_id) = notice.slate_id() else {
            return taken;
        };
        match taken {
            Taken::Dropped => debug!(slate_id = %slate_id, kind, "notice dropped"),
            Taken::Buffered => debug!(slate_id = %slate_id, kind, "notice kept for its slate"),
            _ => info!(slate_id = %slate_id, kind, "notice received"),
        }
        if let Some(event) = event_of(slate_id, effect) {
            self.emit(event);
        }
        taken
    }

    /// The paired contact the slate was exchanged with, if any.
    async fn contact_of_slate(&self, slate_id: SlateId) -> Option<lepic_store::ContactId> {
        let session = self.session().ok()?;
        self.blocking(move |_, _| {
            Ok(session
                .store
                .read(|repos| crate::contact_link::slate_contact(repos, uuid(slate_id)))?)
        })
        .await
        .ok()
        .flatten()
    }

    /// Whether `slate_id` is a payment this wallet received at a listing. Anything unreadable
    /// counts as one, so a notice is withheld rather than sent from the payments address.
    async fn received_at_listing(&self, slate_id: SlateId) -> bool {
        let Ok(session) = self.session() else {
            return true;
        };
        self.blocking(move |_, _| {
            Ok(session.store.read(|repos| {
                match repos.transaction_by_slate(uuid(slate_id), TxDirection::Incoming)? {
                    Some(stored) => Ok::<_, lepic_store::StoreError>(
                        repos.receive_listing(stored.id)?.is_some(),
                    ),
                    None => Ok(false),
                }
            })?)
        })
        .await
        .unwrap_or(true)
    }

    /// Tells the counterparty of the transaction `tx_id`, which this wallet just posted for the
    /// first time as `finalized`, that it was posted: the paired contact the slate was exchanged
    /// with, through its mailbox, or else the address an epic1 payment paid. Nothing for any
    /// other slate.
    pub(crate) async fn notify_posted(
        &self,
        tx_id: TxId,
        finalized: &crate::finalize::FinalizedSlate,
    ) {
        let Some(kernel) = finalized.transaction.kernels().first() else {
            return;
        };
        let notice = Notice::Posted {
            slate_id: finalized.slate.id(),
            excess: kernel.excess,
        };
        if self.send_notice(notice.clone()).await.is_ok() {
            return;
        }
        let Some(notices) = self.contact_notices() else {
            return;
        };
        if let Err(error) = notices.queue_to_address(self, notice).await {
            warn!(tx_id = %tx_id, error = %ErrorChain(&*error), "posted notice not queued");
        }
    }

    /// Tells the paired contact the cancelled invoice `tx_id` was issued to that it is
    /// withdrawn, and records that it was told. Fails with why such a notice was not queued.
    pub(crate) async fn notify_withdrawn(&self, tx_id: TxId) -> Result<(), Hold> {
        let target = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| withdrawal_target(repos, tx_id))?)
            })
            .await
        };
        let slate_id = match target.await {
            Ok(Some(slate_id)) => slate_id,
            Ok(None) => return Ok(()),
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return Err(error.into());
            }
        };
        let notice = Notice::Withdrawn { slate_id };
        self.send_notice(notice).await?;
        let recorded = self
            .inbox_write(move |repos, _| {
                let mut marks = repos.tx_marks(tx_id)?;
                marks.withdrawn_answered = true;
                repos.put_tx_marks(tx_id, &marks)
            })
            .await;
        if let Err(error) = recorded {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "withdrawn notice not recorded");
        }
        Ok(())
    }

    /// Tells the receiver of the cancelled send `tx_id` that it is cancelled, when it is an
    /// ordinary payment through a paired contact whose receiver was not told before, and
    /// records that it was told. With `answered`, only when this wallet finalized the
    /// receiver's answer: the cancel of a send calls it so, and a late answer to a cancelled
    /// send without. Fails with why such a notice was not queued; a cancel never fails on it.
    pub async fn notify_cancelled(&self, tx_id: TxId, answered: bool) -> Result<(), Hold> {
        let target = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| cancellation_target(repos, tx_id, answered))?)
            })
            .await
        };
        let slate_id = match target.await {
            Ok(Some(slate_id)) => slate_id,
            Ok(None) => return Ok(()),
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return Err(error.into());
            }
        };
        let notice = Notice::Cancelled { slate_id };
        self.send_notice(notice).await?;
        let recorded = self
            .inbox_write(move |repos, _| {
                let mut marks = repos.tx_marks(tx_id)?;
                marks.cancelled_answered = true;
                repos.put_tx_marks(tx_id, &marks)
            })
            .await;
        if let Err(error) = recorded {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "cancelled notice not recorded");
        }
        Ok(())
    }

    /// Queues `notice` in the mailbox of the paired contact its slate was exchanged with, which
    /// only LEPIC reads. A notice that was not queued is logged here, and the reason is
    /// returned for the callers that hold a message on it: [`Hold::Withheld`] for a payment to
    /// a listing, whose messages go from the listing or not at all, and for a slate exchanged
    /// with no paired contact, whose classic address gets no notice (ADR 0062).
    async fn send_notice(&self, notice: Notice) -> Result<(), Hold> {
        let Some(slate_id) = notice.slate_id() else {
            return Err(Hold::Withheld);
        };
        if self.received_at_listing(slate_id).await {
            debug!(slate_id = %slate_id, "notice withheld for a payment to a listing");
            return Err(Hold::Withheld);
        }
        let Some(contact_id) = self.contact_of_slate(slate_id).await else {
            debug!(slate_id = %slate_id, reason = "no paired contact", "notice withheld");
            return Err(Hold::Withheld);
        };
        let Some(notices) = self.contact_notices() else {
            warn!(slate_id = %slate_id, "notice for a contact not queued, contacts are off");
            return Err(Hold::Withheld);
        };
        notices
            .queue(self, contact_id, notice)
            .await
            .map_err(|error| {
                warn!(slate_id = %slate_id, error = %ErrorChain(&*error), "notice not queued");
                Hold::Withheld
            })
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use lepic_crypto::Commitment;
    use lepic_store::VERDICT_LEN;

    use super::*;

    fn slate_id() -> SlateId {
        SlateId::parse("0436430c-2b02-624c-2032-570501212b00").unwrap()
    }

    fn every_kind() -> Vec<(&'static str, Notice)> {
        let slate_id = slate_id();
        vec![
            (
                "posted",
                Notice::Posted {
                    slate_id,
                    excess: Commitment::commit_value(1).unwrap(),
                },
            ),
            ("cancelled", Notice::Cancelled { slate_id }),
            (
                "declined",
                Notice::Declined {
                    slate_id,
                    reason: None,
                },
            ),
            ("withdrawn", Notice::Withdrawn { slate_id }),
            ("pair-finished", Notice::PairFinished),
            (
                "pair-match",
                Notice::PairMatch {
                    sas: [1; VERDICT_LEN],
                },
            ),
            (
                "pair-mismatch",
                Notice::PairMismatch {
                    sas: [2; VERDICT_LEN],
                },
            ),
            ("unpaired", Notice::Unpaired),
        ]
    }

    fn every_source() -> [(&'static str, NoticeFrom); 4] {
        let contact = ContactId([7; lepic_store::CONTACT_ID_LEN]);
        [
            ("address key", NoticeFrom::AddressKey(TxId(1))),
            ("reply key", NoticeFrom::ReplyKey(slate_id())),
            ("pairing", NoticeFrom::Pairing(contact)),
            ("private pairing", NoticeFrom::PrivatePairing(contact)),
        ]
    }

    /// The table of ADR 0067, one row per kind, one column per source in the order of
    /// [`every_source`].
    fn table(kind: &str) -> [bool; 4] {
        match kind {
            "posted" | "cancelled" => [true, false, true, false],
            "declined" => [false, true, true, false],
            "withdrawn" | "pair-finished" | "pair-match" | "pair-mismatch" => {
                [false, false, true, false]
            }
            "unpaired" => [false, false, true, true],
            other => panic!("no row for {other}"),
        }
    }

    #[test]
    fn every_kind_is_taken_from_the_sources_of_its_row_and_refused_from_the_rest() {
        for (kind, notice) in every_kind() {
            let row = table(kind);
            for ((source, from), expected) in every_source().iter().zip(row) {
                assert_eq!(accepts(&notice, from), expected, "{kind} from the {source}");
            }
        }
    }
}
