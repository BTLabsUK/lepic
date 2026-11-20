// SPDX-License-Identifier: Apache-2.0
//! Invoices over a method, the payer's side and the housekeeping of both sides.
//!
//! A parked invoice is one an older wallet stored from an Epicbox sender. Nothing pays or
//! declines it: it is listed until [`crate::Wallet::sweep_invoices`] deletes it at its expiry.
//! [`crate::Wallet::sweep_invoices`] also expires what was left unpaid on the issuer side.

use std::time::Duration;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::{MAX_MESSAGE_LEN, Slate, SlateId};
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    PendingInvoiceStatus, Repositories, SlateStage, StoreError, TxDirection, TxId, TxState,
    WalletStore,
};
use lepic_transport::file::FILE;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::cancel::pool_holds;
use crate::codecs;
use crate::error::WalletError;
use crate::event::{Event, ExpiredInvoice};
use crate::in_person_keys::IN_PERSON_REPLY_PREFIX;
use crate::inbox::InboxError;
use crate::invoice::payer_release_height;
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::verify_message;
use crate::refresh::{final_kernel, last_confirmed, ttl_cutoff};
use crate::wallet::Wallet;

/// How long an unpaid invoice is kept by default, on either side.
pub const DEFAULT_INVOICE_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

/// How long an unpaid invoice is kept: a payer deletes a parked one, an issuer cancels its own,
/// once this much time passed since it was received or issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvoiceExpiry(Duration);

impl InvoiceExpiry {
    /// Fails with [`InboxError::InvoiceExpiry`] for zero. The longest a host lets an invoice be
    /// kept is its own to check.
    pub fn new(window: Duration) -> Result<Self, InboxError> {
        if window.is_zero() {
            return Err(InboxError::InvoiceExpiry);
        }
        Ok(Self(window))
    }

    pub const fn window(self) -> Duration {
        self.0
    }

    /// The moment before which something received or issued has expired at `now`.
    fn cutoff(self, now: Timestamp) -> Option<Timestamp> {
        now.checked_sub(self.0).ok()
    }
}

impl Default for InvoiceExpiry {
    fn default() -> Self {
        Self(DEFAULT_INVOICE_EXPIRY)
    }
}

/// A parked invoice, as the host shows it to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingInvoice {
    pub slate_id: SlateId,
    /// The address of the sender, as stored, where the payment goes.
    pub sender: String,
    pub amount: Amount,
    /// The issuer's message, when its signature verifies, made safe to display by
    /// [`display_message`].
    pub message: Option<String>,
    pub received_at: Timestamp,
    /// When [`Wallet::sweep_invoices`] deletes it unpaid.
    pub expires_at: Timestamp,
}

/// What one [`Wallet::sweep_invoices`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InvoiceSweep {
    /// Parked invoices deleted unpaid.
    pub deleted: Vec<SlateId>,
    /// Invoices this wallet issued that were cancelled unpaid.
    pub cancelled: Vec<TxId>,
    /// Payments of invoices whose TTL passed with the kernel neither on chain nor in the
    /// node's pool. Nothing was changed: the host offers the user a cancel.
    pub cancellable: Vec<TxId>,
}

/// Characters that make displayed text read differently from what was signed: bidirectional
/// formatting, line and paragraph separators, and zero-width characters.
pub(crate) const HIDDEN_FORMATTING: [char; 19] = [
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}', '\u{200B}', '\u{200C}',
    '\u{200D}', '\u{2060}', '\u{FEFF}',
];

/// `text` as a host may display it: control characters, bidirectional formatting, line and
/// paragraph separators and zero-width characters removed, then cut to [`MAX_MESSAGE_LEN`]
/// bytes on a character boundary.
pub fn display_message(text: &str) -> String {
    let mut shown = String::with_capacity(text.len().min(MAX_MESSAGE_LEN));
    for c in text
        .chars()
        .filter(|c| !c.is_control() && !HIDDEN_FORMATTING.contains(c))
    {
        if shown.len().saturating_add(c.len_utf8()) > MAX_MESSAGE_LEN {
            break;
        }
        shown.push(c);
    }
    shown
}

fn slate_id(uuid: Uuid) -> SlateId {
    SlateId::from_bytes(uuid.into_bytes())
}

/// The name an Epicbox payment stores as its transport: the id of the Epicbox method.
const EPICBOX: &str = "epicbox";

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The invoices parked on the payments address, oldest first, with when `expiry` deletes
    /// them; invoices from paired contacts are listed by `contact_invoices` only. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn pending_invoices(
        &self,
        expiry: InvoiceExpiry,
    ) -> Result<Vec<IncomingInvoice>, WalletError> {
        let network = self.config().network;
        let codecs = stored_codecs(network);
        let session = self.session()?;
        // Invoices from paired contacts are listed by `contact_invoices` only.
        let parked = session.store.read(|repos| {
            let mut parked = Vec::new();
            for invoice in repos.pending_invoices()? {
                if crate::contact_link::slate_contact(repos, invoice.slate_id)?.is_none() {
                    parked.push(invoice);
                }
            }
            Ok::<_, WalletError>(parked)
        })?;
        Ok(parked
            .into_iter()
            .filter(|invoice| invoice.status == PendingInvoiceStatus::Parked)
            .filter_map(|invoice| {
                let sender = invoice.sender_address;
                let wire = WireSlate::binary(MediaType::JSON, invoice.bytes);
                let Ok(slate) = codecs.decode(&wire) else {
                    warn!(slate_id = %invoice.slate_id, "parked invoice unreadable");
                    return None;
                };
                Some(IncomingInvoice {
                    slate_id: slate.id(),
                    sender,
                    amount: slate.amount(),
                    message: issuer_message(&slate),
                    received_at: invoice.received_at,
                    expires_at: invoice
                        .received_at
                        .checked_add(expiry.window())
                        .unwrap_or(invoice.received_at),
                })
            })
            .collect())
    }

    /// Expires what invoices left unpaid, as a host or a listener runs it from time to time:
    ///
    /// - a parked or declined invoice received more than `expiry` ago is deleted;
    /// - an invoice this wallet issued over Epicbox, by file or to a contact more than `expiry`
    ///   ago and not paid is cancelled, which frees its output and private context, so a late
    ///   payment is refused;
    /// - a payment of an invoice over Epicbox whose TTL a confirmed height has passed, with its
    ///   kernel neither in the node's pool nor on its chain, is listed as cancellable. It is
    ///   never cancelled here: the user decides.
    ///
    /// Emits [`Event::InvoiceExpired`] for each deletion and cancel. Asks the node only when a
    /// payment is past its TTL. Fails with [`WalletError::Locked`], [`WalletError::Node`]
    /// when a lookup fails, and as [`Wallet::cancel`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn sweep_invoices(&self, expiry: InvoiceExpiry) -> Result<InvoiceSweep, WalletError> {
        let session = self.session()?;
        let network = self.config().network;
        let (deleted, due, overdue) = self
            .blocking(move |ports, _| {
                let Some(cutoff) = expiry.cutoff(ports.clock.now()) else {
                    return Ok((Vec::new(), Vec::new(), Vec::new()));
                };
                session.store.write(|repos| {
                    let codecs = stored_codecs(network);
                    let deleted = delete_expired_parked(repos, cutoff)?;
                    let due = issued_unpaid_before(repos, cutoff)?;
                    let overdue = payments_past_ttl(repos, &codecs)?;
                    Ok::<_, WalletError>((deleted, due, overdue))
                })
            })
            .await?;
        let mut sweep = InvoiceSweep::default();
        for slate_uuid in deleted {
            let slate_id = slate_id(slate_uuid);
            debug!(slate_id = %slate_id, "parked invoice expired");
            self.emit(Event::InvoiceExpired(ExpiredInvoice {
                slate_id,
                tx_id: None,
            }));
            sweep.deleted.push(slate_id);
        }
        for (tx_id, slate_uuid) in due {
            match self.cancel(tx_id).await {
                Ok(()) => {}
                // Paid and finalized meanwhile: no longer unpaid.
                Err(WalletError::ChangedDuringCancel(_) | WalletError::Transition(_)) => continue,
                Err(error) => return Err(error),
            }
            info!(tx_id = %tx_id, "issued invoice expired");
            self.emit(Event::InvoiceExpired(ExpiredInvoice {
                slate_id: slate_id(slate_uuid),
                tx_id: Some(tx_id),
            }));
            sweep.cancelled.push(tx_id);
        }
        for (tx_id, excess, min_height) in overdue {
            let node = &self.ports().node;
            if pool_holds(node, &excess).await.map_err(WalletError::Node)? {
                continue;
            }
            let on_chain = node
                .get_kernel(&excess, Some(min_height), None)
                .await
                .map_err(WalletError::Node)?;
            if on_chain.is_none() {
                debug!(tx_id = %tx_id, "invoice payment cancellable");
                sweep.cancellable.push(tx_id);
            }
        }
        Ok(sweep)
    }
}

/// The legacy codecs at the network's base fee, which read every slate this wallet stores. They
/// detect the V3 shape before the V2 shape, as the Epicbox policy does.
pub(crate) fn stored_codecs(network: Network) -> CodecRegistry {
    codecs::legacy(network.params().default_base_fee())
}

/// The issuer's message of an I1, when its signature verifies, for display.
pub fn issuer_message(slate: &Slate) -> Option<String> {
    slate.participants().find_map(|(_, participant)| {
        let message = participant.message.as_ref()?;
        verify_message(message, &participant.public_blind_excess)
            .ok()
            .map(|()| display_message(message.text()))
    })
}

/// Deletes parked and declined invoices received before `cutoff`, and returns their ids.
fn delete_expired_parked(
    repos: &mut dyn Repositories,
    cutoff: Timestamp,
) -> Result<Vec<Uuid>, StoreError> {
    let mut deleted = Vec::new();
    for invoice in repos.pending_invoices()? {
        if invoice.status != PendingInvoiceStatus::Paid && invoice.received_at <= cutoff {
            repos.delete_pending_invoice(invoice.slate_id)?;
            deleted.push(invoice.slate_id);
        }
    }
    Ok(deleted)
}

/// Invoices issued over Epicbox before `cutoff` that nobody paid yet.
fn issued_unpaid_before(
    repos: &dyn Repositories,
    cutoff: Timestamp,
) -> Result<Vec<(TxId, Uuid)>, StoreError> {
    let mut due = Vec::new();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            let entry = &stored.entry;
            let (TxDirection::Incoming, TxState::Received, Some(slate_uuid)) =
                (entry.direction, entry.state, entry.slate_id)
            else {
                continue;
            };
            let issued_here = matches!(entry.transport.as_deref(), Some(transport)
                if transport == EPICBOX || transport == FILE.as_str());
            if (!issued_here && crate::contact_link::slate_contact(repos, slate_uuid)?.is_none())
                || entry.created_at > cutoff
                || repos.slate(slate_uuid, SlateStage::Invoice1)?.is_none()
            {
                continue;
            }
            due.push((stored.id, slate_uuid));
        }
    }
    Ok(due)
}

/// Payments of invoices over Epicbox, still waiting for the issuer, whose TTL a confirmed
/// height has passed by [`crate::invoice::INVOICE_TTL_MARGIN_BLOCKS`], with the kernel to look
/// up.
fn payments_past_ttl(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<Vec<(TxId, Commitment, Height)>, StoreError> {
    let Some(confirmed) = last_confirmed(repos)? else {
        return Ok(Vec::new());
    };
    let mut overdue = Vec::new();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            let Some(slate_uuid) = epicbox_invoice_payment(repos, &stored)? else {
                continue;
            };
            let past = ttl_cutoff(repos, codecs, stored.id, slate_uuid)?
                .is_some_and(|cutoff| confirmed >= payer_release_height(cutoff));
            if !past {
                continue;
            }
            if let Some((excess, min_height)) = final_kernel(repos, codecs, stored.id, slate_uuid)?
            {
                overdue.push((stored.id, excess, min_height));
            }
        }
    }
    Ok(overdue)
}

/// The slate id of a payment of an invoice over Epicbox that waits for the issuer to post it.
pub(crate) fn epicbox_invoice_payment(
    repos: &dyn Repositories,
    stored: &lepic_store::StoredTransaction,
) -> Result<Option<Uuid>, StoreError> {
    let entry = &stored.entry;
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_uuid)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Ok(None);
    };
    if (entry.transport.as_deref() != Some(EPICBOX)
        && crate::contact_link::slate_contact(repos, slate_uuid)?.is_none()
        && repos
            .setting(&format!("{IN_PERSON_REPLY_PREFIX}{slate_uuid}"))?
            .is_none())
        || repos.slate(slate_uuid, SlateStage::Invoice2)?.is_none()
    {
        return Ok(None);
    }
    Ok(Some(slate_uuid))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_stored_epicbox_name_is_the_id_of_the_epicbox_method() {
        assert_eq!(EPICBOX, lepic_methods::epicbox::TRANSPORT_ID.as_str());
    }

    #[test]
    fn display_removes_control_and_bidirectional_characters() {
        assert_eq!(
            display_message("pay\u{202E}evil\u{2066} me\n\tnow\u{0007}"),
            "payevil menow"
        );
        assert_eq!(
            display_message("a\u{2028}b\u{2029}c\u{200B}d\u{200C}e\u{200D}f\u{FEFF}g"),
            "abcdefg"
        );
    }

    #[test]
    fn display_cuts_on_a_character_boundary() {
        let long = "é".repeat(MAX_MESSAGE_LEN);
        let shown = display_message(&long);
        assert_eq!(shown.len(), MAX_MESSAGE_LEN);
        assert!(shown.chars().all(|c| c == 'é'));
        let odd = format!("a{long}");
        assert_eq!(display_message(&odd).len(), MAX_MESSAGE_LEN - 1);
    }

    #[test]
    fn expiry_is_positive() {
        assert!(InvoiceExpiry::new(Duration::ZERO).is_err());
        assert!(InvoiceExpiry::new(Duration::from_secs(48 * 60 * 60 + 1)).is_ok());
        assert_eq!(InvoiceExpiry::default().window(), DEFAULT_INVOICE_EXPIRY);
    }
}
