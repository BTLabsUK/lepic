// SPDX-License-Identifier: Apache-2.0
//! Notices in the engine (ADR 0016): which peers may be sent one over the method, what a
//! received one does, and who sends which.
//!
//! A plain notice goes to a payments address only when the exchange it is about came marked
//! from that key and the key is LEPIC lately ([`crate::peer_compat`]), because any other
//! listener processes only V2 and V3 slates and never acknowledges a notice. A notice is
//! accepted only from the recorded counterparty of its slate. It never moves funds, and it
//! unlocks something in one case only: a `declined` for a send this wallet made and its
//! receiver never answered cancels that send (ADR 0045), which only frees this wallet's own
//! inputs, since a receiver that never signed cannot complete the payment. Otherwise it deletes
//! a parked invoice at most, and only tells the host.
//!
//! `declined` goes from the payer of an invoice to its issuer, and from a receiver set to refuse
//! payments nobody asked for to the sender of such an S1 (ADR 0045). A wallet before ADR 0045
//! holds no invoice of the S1's slate id, and drops the second kind.
//!
//! `posted` goes from the issuer of a paid invoice to its payer, and from the sender of an
//! ordinary payment to its receiver. The receiver keeps the time of the first report it
//! accepted, which the host shows for [`POSTED_REPORT_WINDOW`] while the payment waits.
//!
//! `cancelled` goes from the sender of an ordinary payment to its receiver once the sender
//! cancelled or released the send after finalizing the receiver's answer, and in answer to a
//! late S2 of a send already cancelled. The receiver keeps the time of the first report it
//! accepted while the payment waited, and leaves the payment as it is.

use std::sync::Arc;

use lepic_node::NodeApi;
use lepic_primitives::params::Network;
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    ContactId, PendingInvoiceStatus, Repositories, SlateStage, StoreError, TxDirection, TxId,
    TxState, WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::method::{Method, MethodLookup};
use lepic_transport::transport::Destination;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::details::POSTED_REPORT_WINDOW;
use crate::early_notice::{self, EarlyLimits};
use crate::epicbox_invoice::stored_codecs;
use crate::event::{
    CancelledPayment, DeclinedInvoice, DeclinedPayment, Event, PostedInvoice, PostedPayment,
    UnmatchedNotice, WithdrawnInvoice,
};
use crate::finalize::kernel_excess;
use crate::inbox::{Handled, Hold};
use crate::invoice::check_signed_payment;
use crate::notice::{Notice, NoticeKind};
use crate::peer_compat::{facts, record_marked, record_slate};
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{final_kernel, stored_slate};
use crate::wallet::Wallet;
use lepic_primitives::error_chain::ErrorChain;

/// What an accepted notice changed, for the event it raises.
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
    /// The receiver of the send `tx_id` refused it unanswered: the send is to be cancelled.
    /// `first` for the first such notice, which raises the event.
    SendDeclined {
        tx_id: TxId,
        first: bool,
    },
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
}

/// Prefix of the settings that record a taken decline, one per invoice, keyed by its
/// hyphenated slate id.
const DECLINED_PREFIX: &str = "notice.declined.";

/// Prefix of the settings that record when the receiver of a send declined it unanswered, one
/// per send, keyed by its hyphenated slate id, valued with the time in RFC 3339.
const SEND_DECLINED_PREFIX: &str = "notice.send_declined.";

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

/// The methods notices are matched against and sent over. A notice that arrived over a method
/// is matched only against payments made over that method; one replayed from the buffer, or
/// sent when the engine changes state on its own, finds the method of the payment it is about
/// by the name the payment stored.
#[derive(Clone)]
pub(crate) struct NoticeMethods {
    via: Option<Arc<dyn Method>>,
    lookup: Option<Arc<dyn MethodLookup>>,
    network: Network,
}

impl NoticeMethods {
    /// The method a payment that stored `transport` went over, as notices about it see it.
    fn method_of(&self, transport: Option<&str>) -> Option<Arc<dyn Method>> {
        let name = transport?;
        match &self.via {
            Some(via) => (via.id().as_str() == name).then(|| Arc::clone(via)),
            None => self.lookup.as_ref()?.method_named(name),
        }
    }

    /// The method a payment that stored `transport` went over, when it sends notices.
    fn notices_over(&self, transport: Option<&str>) -> Option<Arc<dyn Method>> {
        self.method_of(transport)
            .filter(|method| !method.notice_lengths().is_empty())
    }

    /// The key `address` names under `method`, as the store keys peers.
    fn key_of(&self, method: &dyn Method, address: &str) -> Option<String> {
        method.peer_key(self.network, address).ok()
    }

    /// The key of the recorded counterparty of `tx_id`, under `method`.
    fn counterparty_key(
        &self,
        repos: &dyn Repositories,
        method: &dyn Method,
        tx_id: TxId,
    ) -> Result<Option<String>, StoreError> {
        Ok(repos
            .counterparty(tx_id)?
            .and_then(|address| self.key_of(method, &address)))
    }
}

/// What became of a contact's notice, from [`Wallet::apply_contact_notice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactNotice {
    /// The transaction the notice ends, for the caller to cancel.
    pub cancel: Option<TxId>,
    /// It is about a slate this wallet does not hold yet, and stayed in the buffer.
    pub buffered: bool,
}

/// Who a notice is from.
#[derive(Debug, Clone)]
pub(crate) enum NoticeFrom {
    /// The peer key, under the method that carried it, a plain notice came from.
    Peer(String),
    /// The paired contact whose signed envelope carried it. Only the contact the slate was
    /// exchanged with counts; its mailbox, which it chooses itself, never decides (RFC 0002 3.4).
    Contact(ContactId),
}

/// The transaction for `slate_id` in `direction` that stored `stage`, when it was exchanged
/// with `from`: over one of `methods` with that counterparty key, or with that paired contact.
fn transaction_with(
    repos: &dyn Repositories,
    slate_id: Uuid,
    direction: TxDirection,
    stage: SlateStage,
    from: &NoticeFrom,
    methods: &NoticeMethods,
) -> Result<Option<(TxId, TxState)>, StoreError> {
    let Some(stored) = repos.transaction_by_slate(slate_id, direction)? else {
        return Ok(None);
    };
    let contact = crate::contact_link::slate_contact(repos, slate_id)?;
    let exchanged = match from {
        NoticeFrom::Peer(key) => match methods.method_of(stored.entry.transport.as_deref()) {
            Some(method) if contact.is_none() => {
                methods
                    .counterparty_key(repos, &*method, stored.id)?
                    .as_deref()
                    == Some(key.as_str())
            }
            _ => false,
        },
        // Matched by the transaction the exchange with the contact made, never by a slate id
        // a contact could have claimed.
        NoticeFrom::Contact(id) => {
            contact == Some(*id) && crate::contact_link::tx_contact(repos, stored.id)? == Some(*id)
        }
    };
    if !exchanged || repos.slate(slate_id, stage)?.is_none() {
        return Ok(None);
    }
    Ok(Some((stored.id, stored.entry.state)))
}

fn apply_notice(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    methods: &NoticeMethods,
    notice: Notice,
    from: NoticeFrom,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let slate_id = uuid(notice.slate_id);
    let effect = match notice.kind {
        NoticeKind::Posted { excess } => {
            let payment = transaction_with(
                repos,
                slate_id,
                TxDirection::Outgoing,
                SlateStage::Invoice2,
                &from,
                methods,
            )?;
            match payment {
                Some((tx_id, _))
                    if final_kernel(repos, codecs, tx_id, slate_id)?
                        .is_some_and(|(expected, _)| expected == excess) =>
                {
                    Effect::Posted { tx_id, excess }
                }
                Some(_) => Effect::Dropped,
                None => report_posted(repos, codecs, methods, slate_id, excess, &from, now)?,
            }
        }
        NoticeKind::Declined => match transaction_with(
            repos,
            slate_id,
            TxDirection::Incoming,
            SlateStage::Invoice1,
            &from,
            methods,
        )? {
            Some((tx_id, TxState::Received)) => take_decline(repos, tx_id, slate_id)?,
            // The invoice was paid and finalized, or ended otherwise, before the decline came.
            Some(_) => Effect::Noted,
            None => take_send_decline(repos, slate_id, &from, methods, now)?,
        },
        NoticeKind::Withdrawn => withdraw(repos, slate_id, &from, methods)?,
        NoticeKind::Cancelled => report_cancelled(repos, slate_id, &from, methods, now)?,
    };
    if matches!(effect, Effect::Dropped) && !holds_slate(repos, slate_id)? {
        return Ok(Effect::Unheld);
    }
    if let NoticeFrom::Peer(key) = from
        && !matches!(effect, Effect::Dropped)
    {
        record_marked(repos, &key, now, None)?;
    }
    Ok(effect)
}

/// [`apply_notice`], then keeps a notice for a slate this wallet does not hold while the host
/// has the buffer on (ADR 0049). Returns what it changed and whether it was kept.
fn apply_or_keep(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    methods: &NoticeMethods,
    notice: Notice,
    from: &NoticeFrom,
    limits: Option<EarlyLimits>,
    now: jiff::Timestamp,
) -> Result<(Effect, bool), StoreError> {
    let effect = apply_notice(repos, codecs, methods, notice, from.clone(), now)?;
    let kept = match limits {
        Some(limits) if matches!(effect, Effect::Unheld) => {
            early_notice::keep(repos, limits, notice, from, now)?
        }
        _ => false,
    };
    Ok((effect, kept))
}

/// The settings key recording that the decline of the invoice `slate_id` was taken.
fn declined_setting(slate_id: Uuid) -> String {
    format!("{DECLINED_PREFIX}{slate_id}")
}

/// A `declined` for the invoice `tx_id`, which still waits for payment. Only the first one
/// raises an event; it is recorded, so a repeat, as when the method delivers it again, is noted.
fn take_decline(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    slate_id: Uuid,
) -> Result<Effect, StoreError> {
    let key = declined_setting(slate_id);
    if repos.setting(&key)?.is_some() {
        return Ok(Effect::Noted);
    }
    repos.put_setting(&key, "1")?;
    Ok(Effect::Declined { tx_id })
}

/// A `declined` for a send this wallet made, from its receiver (ADR 0045). Taken only while the
/// send waits unanswered: `sent`, with no S2 stored, so the receiver never signed and cannot
/// complete it. The first one is recorded with its time; a repeat, as when the method delivers
/// it again or a cancel before failed for a reason that passes, cancels again without an
/// event. One for a send that was answered, finalized or ended is noted.
fn take_send_decline(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    from: &NoticeFrom,
    methods: &NoticeMethods,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let Some((tx_id, state)) = transaction_with(
        repos,
        slate_id,
        TxDirection::Outgoing,
        SlateStage::Standard1,
        from,
        methods,
    )?
    else {
        return Ok(Effect::Dropped);
    };
    if state != TxState::Sent || repos.slate(slate_id, SlateStage::Standard2)?.is_some() {
        return Ok(Effect::Noted);
    }
    let key = format!("{SEND_DECLINED_PREFIX}{slate_id}");
    let first = repos.setting(&key)?.is_none();
    if first {
        repos.put_setting(&key, &now.to_string())?;
    }
    Ok(Effect::SendDeclined { tx_id, first })
}

/// When the receiver of the send `slate_id` declined it unanswered (ADR 0045).
pub(crate) fn receiver_declined_report(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    Ok(repos
        .setting(&format!("{SEND_DECLINED_PREFIX}{slate_id}"))?
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

/// A `posted` from the sender of a payment received over a method. Accepted only from the
/// payment's recorded counterparty, for a payment whose S2 is stored, with the kernel excess
/// that S2 implies. Only the first report for a payment that still waits for its sender is kept
/// and raises an event; a repeat, or a report for a payment that confirmed or ended, is noted.
fn report_posted(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    methods: &NoticeMethods,
    slate_id: Uuid,
    excess: lepic_crypto::Commitment,
    from: &NoticeFrom,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let Some((tx_id, state)) = transaction_with(
        repos,
        slate_id,
        TxDirection::Incoming,
        SlateStage::Standard2,
        from,
        methods,
    )?
    else {
        return Ok(Effect::Dropped);
    };
    let expected = stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Standard2)?
        .and_then(|reply| kernel_excess(&reply).ok());
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

/// A `cancelled` from the sender of a payment received over a method or from a paired contact.
/// Accepted only from the payment's recorded counterparty, for a payment whose S2 is stored, so
/// one this wallet answered. Only the first report for a payment that still waits for its sender
/// is kept and raises an event; a repeat, or a report for a payment that confirmed or ended here,
/// is noted. Nothing else changes: the host decides whether to cancel the payment.
fn report_cancelled(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    from: &NoticeFrom,
    methods: &NoticeMethods,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let Some((tx_id, state)) = transaction_with(
        repos,
        slate_id,
        TxDirection::Incoming,
        SlateStage::Standard2,
        from,
        methods,
    )?
    else {
        return Ok(Effect::Dropped);
    };
    let mut marks = repos.tx_marks(tx_id)?;
    if state != TxState::Received || marks.sender_cancelled_at.is_some() {
        return Ok(Effect::Noted);
    }
    marks.sender_cancelled_at = Some(now);
    repos.put_tx_marks(tx_id, &marks)?;
    Ok(Effect::PaymentCancelled { tx_id })
}

/// When the sender of the received payment `tx_id` reported that it cancelled it. The caller
/// checks the payment's state.
pub(crate) fn cancelled_report(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    Ok(repos.tx_marks(tx_id)?.sender_cancelled_at)
}

/// A parked invoice that is not paid is deleted; a paid one is only reported while its payment
/// waits for the issuer.
fn withdraw(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    from: &NoticeFrom,
    methods: &NoticeMethods,
) -> Result<Effect, StoreError> {
    let parked_by_sender = match (repos.pending_invoice(slate_id)?, from) {
        (Some(parked), NoticeFrom::Peer(key)) => {
            parked.sender_key == *key && parked.status != PendingInvoiceStatus::Paid
        }
        (Some(parked), NoticeFrom::Contact(id)) => {
            crate::contact_link::slate_contact(repos, slate_id)? == Some(*id)
                && parked.status != PendingInvoiceStatus::Paid
        }
        (None, _) => false,
    };
    if parked_by_sender {
        repos.delete_pending_invoice(slate_id)?;
        return Ok(Effect::Withdrawn { tx_id: None });
    }
    Ok(
        match transaction_with(
            repos,
            slate_id,
            TxDirection::Outgoing,
            SlateStage::Invoice2,
            from,
            methods,
        )? {
            Some((tx_id, TxState::Sent)) => Effect::Withdrawn { tx_id: Some(tx_id) },
            Some(_) => Effect::Noted,
            None => Effect::Dropped,
        },
    )
}

/// Where a notice about a stored transaction goes: the slate it is about, the counterparty, the
/// method that carries it unless a paired contact's mailbox does, and one flag of the caller's.
type NoticeTarget = (SlateId, Destination, Option<Arc<dyn Method>>, bool);

/// Where a `withdrawn` for the cancelled transaction `tx_id` goes: the address an invoice over
/// a method that sends notices was issued to, while no payment of it was finalized. With
/// whether its payer declined it, which only LEPIC does.
fn withdrawal_target(
    repos: &dyn Repositories,
    methods: &NoticeMethods,
    tx_id: TxId,
) -> Result<Option<NoticeTarget>, StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    let Some(slate_id) = entry.slate_id else {
        return Ok(None);
    };
    let method = methods.notices_over(entry.transport.as_deref());
    let contact = crate::contact_link::slate_contact(repos, slate_id)?;
    if entry.direction != TxDirection::Incoming
        || (method.is_none() && contact.is_none())
        || repos.slate(slate_id, SlateStage::Invoice1)?.is_none()
        || repos.slate(slate_id, SlateStage::Invoice3)?.is_some()
    {
        return Ok(None);
    }
    let declined = repos.setting(&declined_setting(slate_id))?.is_some();
    Ok(repos.counterparty(tx_id)?.map(|to| {
        (
            SlateId::from_bytes(slate_id.into_bytes()),
            Destination::new(to),
            method,
            declined,
        )
    }))
}

/// Where a `cancelled` for the cancelled send `tx_id` goes: the receiver of an ordinary payment
/// sent over a method that sends notices or through a paired contact, while it was not told before. With
/// `answered`, only when this wallet finalized the receiver's answer, so the receiver holds an
/// S2 and waits for this wallet to post it; a send cancelled before any answer came is told
/// when its late answer arrives. A contact's notice goes to its mailbox, which
/// [`Wallet::send_notice`] finds by the slate, so its destination is not used.
fn cancellation_target(
    repos: &dyn Repositories,
    methods: &NoticeMethods,
    tx_id: TxId,
    answered: bool,
) -> Result<Option<NoticeTarget>, StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    let Some(slate_id) = entry.slate_id else {
        return Ok(None);
    };
    let contact = crate::contact_link::slate_contact(repos, slate_id)?;
    let method = methods.notices_over(entry.transport.as_deref());
    let marks = repos.tx_marks(tx_id)?;
    if entry.direction != TxDirection::Outgoing
        || entry.state != TxState::Cancelled
        || (method.is_none() && contact.is_none())
        || repos.slate(slate_id, SlateStage::Standard1)?.is_none()
        || (answered && repos.slate(slate_id, SlateStage::Standard3)?.is_none())
        || marks.cancelled_answered
    {
        return Ok(None);
    }
    let to = match (repos.counterparty(tx_id)?, contact) {
        (Some(to), _) => to,
        (None, Some(_)) => String::new(),
        (None, None) => return Ok(None),
    };
    Ok(Some((
        SlateId::from_bytes(slate_id.into_bytes()),
        Destination::new(to),
        method,
        marks.answer_marked,
    )))
}

/// Whether `payment` of the cancelled invoice `tx_id` is to be answered with a `withdrawn`: it
/// pays the I1 this wallet issued under its slate id with a payer signature that verifies, and
/// the payer of that slate was not told before. Once per slate, so repeating a payment sends
/// nothing more. The sender key is not compared: a payer pays from its payments address, which
/// need not be the address the invoice went to.
fn withdrawn_answer_due(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    payment: &Slate,
) -> Result<bool, StoreError> {
    let slate_id = uuid(payment.id());
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(false);
    };
    if entry.state != TxState::Cancelled
        || entry.slate_id != Some(slate_id)
        || repos.tx_marks(tx_id)?.withdrawn_answered
    {
        return Ok(false);
    }
    Ok(
        stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Invoice1)?
            .is_some_and(|issued| check_signed_payment(&issued, payment).is_ok()),
    )
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The methods notices are matched against and sent over: only `via` when a notice arrived
    /// over it, otherwise those of [`crate::ports::Ports::methods`].
    fn notice_methods(&self, via: Option<&Arc<dyn Method>>) -> NoticeMethods {
        NoticeMethods {
            via: via.cloned(),
            lookup: self.ports().methods.clone(),
            network: self.config().network,
        }
    }

    /// Takes a notice that arrived over `method` from `from`, and raises the event it calls
    /// for. It is matched only against payments made over `method`, and dropped when `from`
    /// names no peer key of the method. One about a slate this wallet does not hold raises
    /// [`Event::NoticeUnmatched`], for the host to forward to its other installs, and stays in
    /// the buffer while the host keeps one.
    ///
    /// Fails with the [`Hold`] the message is kept for: the wallet locked or the store not
    /// answering.
    pub async fn notice_arrived(
        &self,
        method: &Arc<dyn Method>,
        from: &Destination,
        notice: Notice,
    ) -> Result<Handled, Hold> {
        let Ok(key) = method.peer_key(self.config().network, from.as_str()) else {
            return Ok(Handled::Dropped);
        };
        let (effect, kept) = self.apply_peer_notice(method, notice, key).await?;
        let slate_id = notice.slate_id;
        if matches!(effect, Effect::Unheld) {
            debug!(slate_id = %slate_id, "notice for a slate held elsewhere passed on");
            self.emit(Event::NoticeUnmatched(UnmatchedNotice {
                notice,
                sender: from.as_str().to_owned(),
            }));
            return Ok(if kept {
                Handled::Buffered
            } else {
                Handled::Dropped
            });
        }
        let handled = self.report_notice(slate_id, effect);
        if let Effect::SendDeclined { tx_id, .. } = effect {
            self.cancel_declined(tx_id).await?;
        }
        Ok(handled)
    }

    /// Applies a notice another install of this wallet received over `method` from `sender`,
    /// the address the method reported, and passed on from its [`Event::NoticeUnmatched`]. It
    /// is taken under exactly the rules of one received here: only from the recorded
    /// counterparty of its slate, `posted` only with the kernel excess the payment implies, and
    /// once. Returns whether it was accepted; one this wallet does not hold either, or from a
    /// `sender` that names no peer key of the method on the wallet's network, is not accepted
    /// and never passed on again. The former stays in the buffer while the host keeps one.
    ///
    /// Fails with [`crate::WalletError::Locked`] and as the store does.
    pub async fn notice_apply_forwarded(
        &self,
        method: &Arc<dyn Method>,
        sender: &str,
        notice: Notice,
    ) -> Result<bool, crate::WalletError> {
        let Ok(key) = method.peer_key(self.config().network, sender) else {
            return Ok(false);
        };
        let (effect, _) = self.apply_peer_notice(method, notice, key).await?;
        if matches!(effect, Effect::Unheld) {
            debug!(slate_id = %notice.slate_id, "passed-on notice for a slate not held dropped");
            return Ok(false);
        }
        let handled = self.report_notice(notice.slate_id, effect);
        if let Effect::SendDeclined { tx_id, .. } = effect {
            self.cancel_declined(tx_id).await?;
        }
        Ok(handled == Handled::Notice)
    }

    /// Cancels the send `tx_id` its receiver declined unanswered, as [`Wallet::cancel`] does,
    /// so its inputs are free again. A failure that passes, the wallet locked or the store not
    /// answering, is returned, so the notice is taken again. Any other means the send moved on
    /// meanwhile and is only logged.
    async fn cancel_declined(&self, tx_id: TxId) -> Result<(), crate::WalletError> {
        match self.cancel(tx_id).await {
            Ok(()) => {
                info!(tx_id = %tx_id, "send declined by its receiver cancelled");
                Ok(())
            }
            Err(error @ (crate::WalletError::Locked | crate::WalletError::Store(_))) => Err(error),
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "declined send not cancelled");
                Ok(())
            }
        }
    }

    async fn apply_peer_notice(
        &self,
        method: &Arc<dyn Method>,
        notice: Notice,
        key: String,
    ) -> Result<(Effect, bool), crate::WalletError> {
        let methods = self.notice_methods(Some(method));
        let from = NoticeFrom::Peer(key);
        let codecs = stored_codecs(self.config().network);
        let limits = EarlyLimits::of(&self.config().policy);
        self.inbox_write(move |repos, now| {
            apply_or_keep(repos, &codecs, &methods, notice, &from, limits, now)
        })
        .await
    }

    /// Applies the notices kept for `slate_id`, now that the slate is here, and raises their
    /// events. An entry that matches nothing goes. The entries leave the buffer in the store
    /// transaction that applies them; the caller runs this after storing the slate and before
    /// acknowledging it, so a delivery that repeats finds them there or their effect stored.
    /// Returns what a contact's notice asks to cancel, for
    /// [`apply_contact_notice`](Self::apply_contact_notice)'s caller to end the same way. A
    /// peer's notice is matched against the payment of the method its stored name finds in
    /// [`crate::ports::Ports::methods`].
    pub async fn apply_early_notices(&self, slate_id: SlateId) -> Result<Vec<TxId>, Hold> {
        self.early_notices(None, slate_id).await
    }

    /// [`Self::apply_early_notices`] for a slate that arrived over `method`, whose peers'
    /// notices are matched only against payments made over it.
    pub(crate) async fn apply_early_notices_over(
        &self,
        method: &Arc<dyn Method>,
        slate_id: SlateId,
    ) -> Result<Vec<TxId>, Hold> {
        self.early_notices(Some(method), slate_id).await
    }

    async fn early_notices(
        &self,
        via: Option<&Arc<dyn Method>>,
        slate_id: SlateId,
    ) -> Result<Vec<TxId>, Hold> {
        let Some(limits) = EarlyLimits::of(&self.config().policy) else {
            return Ok(Vec::new());
        };
        let methods = self.notice_methods(via);
        let codecs = stored_codecs(self.config().network);
        let effects = self
            .inbox_write(move |repos, now| {
                let mut effects = Vec::new();
                for (notice, from) in early_notice::take(repos, limits, slate_id, now)? {
                    let contact = matches!(from, NoticeFrom::Contact(_));
                    let effect = apply_notice(repos, &codecs, &methods, notice, from, now)?;
                    effects.push((effect, contact));
                }
                Ok(effects)
            })
            .await?;
        let mut cancels = Vec::new();
        for (effect, contact) in effects {
            self.report_notice(slate_id, effect);
            match effect {
                Effect::SendDeclined { tx_id, .. } if !contact => {
                    self.cancel_declined(tx_id).await?;
                }
                Effect::SendDeclined { tx_id, .. } => cancels.push(tx_id),
                Effect::Withdrawn { tx_id: Some(tx_id) } if contact => cancels.push(tx_id),
                _ => {}
            }
        }
        Ok(cancels)
    }

    /// Whether the payment `tx_id` just received is not to be answered: its sender reported that
    /// it cancelled it, in a notice that came first. Always `false` while the host keeps no
    /// buffer, so a repeat of an answered payment is answered as before.
    pub async fn answer_withheld(&self, tx_id: TxId) -> Result<bool, Hold> {
        if EarlyLimits::of(&self.config().policy).is_none() {
            return Ok(false);
        }
        let session = self.session()?;
        let reported = self
            .blocking(move |_, _| Ok(session.store.read(|repos| cancelled_report(repos, tx_id))?))
            .await?;
        Ok(reported.is_some())
    }

    /// Raises the event an applied notice calls for, and says how its message is settled.
    fn report_notice(&self, slate_id: SlateId, effect: Effect) -> Handled {
        let event = match effect {
            Effect::Dropped | Effect::Unheld => {
                debug!(slate_id = %slate_id, "notice dropped");
                return Handled::Dropped;
            }
            Effect::Noted => None,
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
            Effect::SendDeclined { tx_id, first } => {
                first.then_some(Event::PaymentDeclined(DeclinedPayment { tx_id, slate_id }))
            }
            Effect::Withdrawn { tx_id } => Some(Event::InvoiceWithdrawn(WithdrawnInvoice {
                slate_id,
                tx_id,
            })),
        };
        info!(slate_id = %slate_id, "notice received");
        if let Some(event) = event {
            self.emit(event);
        }
        Handled::Notice
    }

    /// Records what a payment of an invoice this wallet issued showed about its senders. A
    /// marked one shows that the key it came from runs LEPIC, and so does the key the invoice
    /// went to, whose holder is the only one that could answer it; an unmarked one shows only
    /// that the key it came from does not, for now.
    pub(crate) async fn record_paying_peer(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
        reply_to: &Destination,
        marked: bool,
        features: Option<u32>,
    ) {
        let methods = self.notice_methods(Some(method));
        let from = methods.key_of(&**method, reply_to.as_str());
        let method = Arc::clone(method);
        let recorded = self
            .inbox_write(move |repos, now| {
                let invoiced = if marked {
                    methods.counterparty_key(repos, &*method, tx_id)?
                } else {
                    None
                };
                // The claim is the payer's: the key the invoice went to is only shown LEPIC.
                if let Some(key) = &from {
                    record_slate(repos, key, now, marked, features)?;
                }
                if let Some(key) = &invoiced
                    && Some(key) != from.as_ref()
                {
                    record_slate(repos, key, now, marked, None)?;
                }
                Ok(())
            })
            .await;
        if let Err(error) = recorded {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "peer capability not recorded");
        }
    }

    /// Records what an S1 showed about its sender: only a LEPIC wallet writes the marker, and
    /// the method binds the S1 to the key it came from.
    pub(crate) async fn record_sending_peer(
        &self,
        method: &dyn Method,
        reply_to: &Destination,
        marked: bool,
        features: Option<u32>,
    ) {
        let Ok(from) = method.peer_key(self.config().network, reply_to.as_str()) else {
            return;
        };
        let recorded = self
            .inbox_write(move |repos, now| record_slate(repos, &from, now, marked, features))
            .await;
        if let Err(error) = recorded {
            warn!(error = %ErrorChain(&error), "peer capability not recorded");
        }
    }

    /// Records what an S2 for the send `tx_id` showed about its receiver, when it came from the
    /// key the send went to, and whether this answer was marked, which a later `cancelled`
    /// needs. An S2 from any other key shows nothing about that receiver. Runs before any notice
    /// about the send is decided.
    pub(crate) async fn record_receiving_peer(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
        reply_to: &Destination,
        marked: bool,
        features: Option<u32>,
    ) {
        let methods = self.notice_methods(Some(method));
        let Some(from) = methods.key_of(&**method, reply_to.as_str()) else {
            return;
        };
        let method = Arc::clone(method);
        let recorded = self
            .inbox_write(move |repos, now| {
                if methods.counterparty_key(repos, &*method, tx_id)?.as_deref()
                    == Some(from.as_str())
                {
                    record_slate(repos, &from, now, marked, features)?;
                    let mut marks = repos.tx_marks(tx_id)?;
                    if marks.answer_marked != marked {
                        marks.answer_marked = marked;
                        repos.put_tx_marks(tx_id, &marks)?;
                    }
                }
                Ok(())
            })
            .await;
        if let Err(error) = recorded {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "peer capability not recorded");
        }
    }

    /// Tells the receiver of `tx_id`, a send whose S2 this wallet just finalized and pushed in
    /// a listen or drain, that it was posted with the kernel of `finalized`, when that S2 came
    /// `marked`. Nothing for a send whose stored method [`crate::ports::Ports::methods`] does
    /// not know, or a slate without a kernel. Only the inbox calls it, so nothing goes out
    /// outside a listen or drain the host started.
    pub(crate) async fn notify_pushed(&self, tx_id: TxId, finalized: &Slate, marked: bool) {
        let Some(kernel) = finalized.kernel() else {
            return;
        };
        let Some(lookup) = self.ports().methods.clone() else {
            return;
        };
        let transport = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.transaction(tx_id))?
                    .and_then(|entry| entry.transport))
            })
            .await
        };
        match transport.await {
            Ok(Some(name)) if lookup.method_named(&name).is_some() => {
                self.posted_notice(None, tx_id, finalized.id(), kernel.excess, marked)
                    .await;
            }
            Ok(_) => {}
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
            }
        }
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

    /// Applies a notice the paired contact `contact_id` sent sealed and signed, for a slate
    /// exchanged with that contact only, and raises its event. Returns the payment to cancel
    /// for a `withdrawn` of an invoice this wallet paid, and the send to cancel for a
    /// `declined` of a send the contact refused unanswered (ADR 0045), and whether a notice for
    /// a slate this wallet does not hold stayed in the buffer.
    pub async fn apply_contact_notice(
        &self,
        notice: Notice,
        contact_id: ContactId,
    ) -> Result<ContactNotice, Hold> {
        let from = NoticeFrom::Contact(contact_id);
        let methods = self.notice_methods(None);
        let codecs = stored_codecs(self.config().network);
        let limits = EarlyLimits::of(&self.config().policy);
        let (effect, buffered) = self
            .inbox_write(move |repos, now| {
                apply_or_keep(repos, &codecs, &methods, notice, &from, limits, now)
            })
            .await?;
        let slate_id = notice.slate_id;
        let (event, cancel) = match effect {
            Effect::Dropped | Effect::Unheld | Effect::Noted => (None, None),
            Effect::Posted { tx_id, excess } => (
                Some(Event::InvoicePosted(PostedInvoice {
                    tx_id,
                    slate_id,
                    excess,
                })),
                None,
            ),
            Effect::PaymentPosted { tx_id, excess } => (
                Some(Event::PaymentPosted(PostedPayment {
                    tx_id,
                    slate_id,
                    excess,
                })),
                None,
            ),
            Effect::PaymentCancelled { tx_id } => (
                Some(Event::PaymentCancelled(CancelledPayment {
                    tx_id,
                    slate_id,
                })),
                None,
            ),
            Effect::Declined { tx_id } => (
                Some(Event::InvoiceDeclined(DeclinedInvoice { tx_id, slate_id })),
                None,
            ),
            Effect::SendDeclined { tx_id, first } => (
                first.then_some(Event::PaymentDeclined(DeclinedPayment { tx_id, slate_id })),
                Some(tx_id),
            ),
            Effect::Withdrawn { tx_id } => (
                Some(Event::InvoiceWithdrawn(WithdrawnInvoice {
                    slate_id,
                    tx_id,
                })),
                tx_id,
            ),
        };
        if let Some(event) = event {
            info!(slate_id = %slate_id, "notice received");
            self.emit(event);
        }
        Ok(ContactNotice { cancel, buffered })
    }

    /// Tells the payer that the paid invoice `tx_id` was pushed with `excess`. Over the method
    /// the invoice stored, found in [`crate::ports::Ports::methods`], only when the payment came
    /// `answer_marked`; a paired contact is told in its mailbox either way.
    pub async fn notify_posted(
        &self,
        tx_id: TxId,
        slate_id: SlateId,
        excess: lepic_crypto::Commitment,
        answer_marked: bool,
    ) {
        self.posted_notice(None, tx_id, slate_id, excess, answer_marked)
            .await;
    }

    /// [`Self::notify_posted`] for an invoice whose payment arrived over `method`.
    pub(crate) async fn notify_posted_over(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
        slate_id: SlateId,
        excess: lepic_crypto::Commitment,
        answer_marked: bool,
    ) {
        self.posted_notice(Some(method), tx_id, slate_id, excess, answer_marked)
            .await;
    }

    async fn posted_notice(
        &self,
        via: Option<&Arc<dyn Method>>,
        tx_id: TxId,
        slate_id: SlateId,
        excess: lepic_crypto::Commitment,
        answer_marked: bool,
    ) {
        let (to, method) = match self.counterparty_of(tx_id).await {
            Ok(Some((to, transport))) => {
                (to, self.notice_methods(via).method_of(transport.as_deref()))
            }
            Ok(None) => return,
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return;
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Posted { excess },
        };
        let _ = self.send_notice(method, &to, notice, answer_marked).await;
    }

    /// Tells the payer that the cancelled invoice `tx_id` is withdrawn, when it was one issued
    /// over a method that sends notices, `via` or else one of [`crate::ports::Ports::methods`],
    /// and records that it was told. Over the method only when its payer answered with LEPIC's
    /// marker: a payment that came `payment_marked`, or a `declined` this wallet took. The
    /// invoice itself is this wallet's own slate and shows nothing about the payer. Fails with
    /// why such a notice was not delivered.
    pub(crate) async fn notify_withdrawn(
        &self,
        via: Option<&Arc<dyn Method>>,
        tx_id: TxId,
        payment_marked: bool,
    ) -> Result<(), Hold> {
        let methods = self.notice_methods(via);
        let target = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| withdrawal_target(repos, &methods, tx_id))?)
            })
            .await
        };
        let (slate_id, to, method, declined) = match target.await {
            Ok(Some(target)) => target,
            Ok(None) => return Ok(()),
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return Err(error.into());
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Withdrawn,
        };
        self.send_notice(method, &to, notice, payment_marked || declined)
            .await?;
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

    /// Answers a marked `payment` of the cancelled invoice `tx_id`, which arrived over `method`,
    /// with a `withdrawn` to the address the invoice was issued to, when the payer was never
    /// told: the cancel tells a payer over a method nothing until it answered with the marker,
    /// and the notice it sends fails while this wallet is offline. A due answer records the key the invoice went
    /// to as running LEPIC, and not the sender's, which a verified payment does not prove.
    /// Fails with why that answer was due and not delivered.
    pub(crate) async fn answer_withdrawn_payment(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
        payment: &Slate,
    ) -> Result<(), Hold> {
        let methods = self.notice_methods(Some(method));
        let codecs = stored_codecs(self.config().network);
        let payment = payment.clone();
        let over = Arc::clone(method);
        let due = self.inbox_write(move |repos, now| {
            let due = withdrawn_answer_due(repos, &codecs, tx_id, &payment)?;
            if due && let Some(invoiced) = methods.counterparty_key(repos, &*over, tx_id)? {
                record_marked(repos, &invoiced, now, None)?;
            }
            Ok(due)
        });
        match due.await {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return Err(error.into());
            }
        }
        self.notify_withdrawn(Some(method), tx_id, true).await
    }

    /// Tells the receiver of the cancelled send `tx_id` that it is cancelled, when it is an
    /// ordinary payment sent over a method of [`crate::ports::Ports::methods`] that sends
    /// notices or through a paired contact, whose receiver was not told before, and records
    /// that it was told. With `answered`, only when this wallet finalized the receiver's
    /// answer: the cancel and release of a send call it so, and a late answer to a cancelled
    /// send without. Over a method only a receiver whose latest answer came marked, and that
    /// is LEPIC lately, is told. Fails with why such a notice was not delivered; a cancel
    /// never fails on it.
    pub async fn notify_cancelled(&self, tx_id: TxId, answered: bool) -> Result<(), Hold> {
        self.cancelled_notice(None, tx_id, answered).await
    }

    async fn cancelled_notice(
        &self,
        via: Option<&Arc<dyn Method>>,
        tx_id: TxId,
        answered: bool,
    ) -> Result<(), Hold> {
        let methods = self.notice_methods(via);
        let target = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| cancellation_target(repos, &methods, tx_id, answered))?)
            })
            .await
        };
        let (slate_id, to, method, answer_marked) = match target.await {
            Ok(Some(target)) => target,
            Ok(None) => return Ok(()),
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return Err(error.into());
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Cancelled,
        };
        self.send_notice(method, &to, notice, answer_marked).await?;
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

    /// Answers a marked late S2 of the cancelled send `tx_id`, which arrived over `method` from
    /// the key the send went to, with a `cancelled`: the receiver answered after the cancel, or
    /// its answer reached this wallet only after it. The caller recorded the answer first. Once
    /// per send. Fails with why that answer was due and not delivered.
    pub(crate) async fn answer_cancelled_send(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
    ) -> Result<(), Hold> {
        self.cancelled_notice(Some(method), tx_id, false).await
    }

    /// Tells the issuer of the parked invoice `slate_id` that it was declined, over `method`
    /// from the payments address. Only when the parked I1, kept as it arrived, carried the
    /// marker as `method` reads it.
    pub(crate) async fn notify_declined(&self, method: &Arc<dyn Method>, slate_id: SlateId) {
        let to = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.pending_invoice(uuid(slate_id)))?)
            })
            .await
        };
        let (to, marked) = match to.await {
            Ok(Some(parked)) => {
                let marked = method
                    .sender_facts(&lepic_slate::codec::WireSlate::binary(
                        lepic_slate::codec::MediaType::JSON,
                        parked.bytes,
                    ))
                    .marked;
                (Destination::new(parked.sender_address), marked)
            }
            Ok(None) => return,
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                return;
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Declined,
        };
        let _ = self
            .send_notice(Some(Arc::clone(method)), &to, notice, marked)
            .await;
    }

    /// The recorded counterparty of `tx_id`, with the method name the transaction stored.
    async fn counterparty_of(
        &self,
        tx_id: TxId,
    ) -> Result<Option<(Destination, Option<String>)>, crate::error::WalletError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            Ok(session.store.read(|repos| {
                let Some(to) = repos.counterparty(tx_id)? else {
                    return Ok::<_, StoreError>(None);
                };
                let transport = repos.transaction(tx_id)?.and_then(|entry| entry.transport);
                Ok(Some((Destination::new(to), transport)))
            })?)
        })
        .await
    }

    /// Tells `to`, the sender of the S1 `slate_id` this wallet refused as nobody asked for it
    /// (ADR 0045), over `method`, the one it came over, that it was declined, when the S1 came
    /// `marked` from a key lately shown to run LEPIC. Nothing goes for a slate id this wallet
    /// holds anything of, which the S1's sender could have chosen to reach someone else.
    pub(crate) async fn decline_unsolicited(
        &self,
        method: &Arc<dyn Method>,
        to: &Destination,
        slate_id: SlateId,
        marked: bool,
    ) -> Result<(), Hold> {
        let session = self.session()?;
        let held = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| holds_slate(repos, uuid(slate_id)))?)
            })
            .await?;
        if held {
            debug!(slate_id = %slate_id, "declined notice withheld for a slate held here");
            return Err(Hold::Withheld);
        }
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Declined,
        };
        self.send_notice(Some(Arc::clone(method)), to, notice, marked)
            .await
    }

    /// Sends `notice` to `to` over the method of [`crate::ports::Ports::methods`] named as
    /// `method`, the method of the exchange, when the exchange's own incoming slate came
    /// `exchange_marked` and the key is LEPIC lately. A paired contact's notice goes to its
    /// mailbox instead, which only LEPIC reads. A notice that was not sent is logged here, and
    /// the reason is returned for the callers that hold a message on it: [`Hold::Withheld`]
    /// without such a method or over one that sends no notices.
    async fn send_notice(
        &self,
        method: Option<Arc<dyn Method>>,
        to: &Destination,
        notice: Notice,
        exchange_marked: bool,
    ) -> Result<(), Hold> {
        let slate_id = notice.slate_id;
        // Every message about a payment to a listing goes from the listing or not at all; the
        // payments address never speaks for it.
        if self.received_at_listing(slate_id).await {
            debug!(slate_id = %slate_id, "notice withheld for a payment to a listing");
            return Err(Hold::Withheld);
        }
        if let Some(contact_id) = self.contact_of_slate(slate_id).await {
            // Exchanges with a paired contact keep their notices in its mailbox, sealed.
            let Some(notices) = self.contact_notices() else {
                warn!(slate_id = %slate_id, "notice for a contact not queued, contacts are off");
                return Err(Hold::Withheld);
            };
            return notices
                .queue(self, contact_id, notice)
                .await
                .map_err(|error| {
                    warn!(slate_id = %slate_id, error = %ErrorChain(&*error), "notice not queued");
                    Hold::Withheld
                });
        }
        // The method of the exchange names the method; the one of the wallet's ports by that
        // name sends, as the host set it up.
        let Some(method) = method.and_then(|method| {
            self.ports()
                .methods
                .as_ref()?
                .method_named(method.id().as_str())
        }) else {
            warn!(slate_id = %slate_id, "notice not sent");
            return Err(Hold::Withheld);
        };
        let lengths = method.notice_lengths();
        if lengths.is_empty() {
            debug!(slate_id = %slate_id, transport = %method.id(), "notice withheld, the method sends none");
            return Err(Hold::Withheld);
        }
        let Ok(key) = method.peer_key(self.config().network, to.as_str()) else {
            debug!(slate_id = %slate_id, "notice not sent to a destination that is no address");
            return Err(Hold::Reply(TransportError::UnknownDestination {
                transport: method.id(),
            }));
        };
        if !exchange_marked {
            debug!(slate_id = %slate_id, "notice withheld, the exchange came unmarked");
            return Err(Hold::Withheld);
        }
        let allowed = async {
            let session = self.session()?;
            self.blocking(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.read(|repos| facts(repos, &key, now))?.notices)
            })
            .await
        };
        match allowed.await {
            Ok(true) => {}
            Ok(false) => {
                debug!(slate_id = %slate_id, "notice withheld from a peer not lately shown to run lepic");
                return Err(Hold::Withheld);
            }
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                return Err(error.into());
            }
        }
        let Some(outbound) = method.outbound() else {
            warn!(slate_id = %slate_id, "notice not sent");
            return Err(Hold::NoOutbound {
                transport: method.id(),
            });
        };
        let length = crate::notice::notice_length(lengths, &mut **self.ports().rng.lock());
        match outbound
            .deliver(to, &notice.encode_to(lengths, length))
            .await
        {
            Ok(()) => {
                info!(slate_id = %slate_id, "notice sent");
                Ok(())
            }
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                Err(Hold::Reply(error))
            }
        }
    }
}
