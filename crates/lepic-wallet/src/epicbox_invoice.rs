//! Invoices over Epicbox, the payer's side and the housekeeping of both sides.
//!
//! A parked invoice waits in the store for the user to pay or decline it; nothing in the inbox
//! ever pays. Paying a parked invoice is a host call, which delivers the I2 to the address the
//! invoice names as its sender.
//!
//! The issuer side lives in the payments inbox ([`crate::inbox`]): an I2 that answers an
//! invoice this wallet issued is finalized and posted, and an I1 the payer sent back unchanged
//! records that the payer does not pay invoices. [`crate::Wallet::sweep_invoices`] expires
//! what was left unpaid on either side.

use std::time::Duration;

use jiff::Timestamp;
use lepic_crypto::{Commitment, PublicKey};
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork, TRANSPORT_ID};
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::{MAX_MESSAGE_LEN, Slate, SlateId};
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::Stage;
use lepic_store::{
    PeerCapability, PeerSupport, PendingInvoiceStatus, Repositories, SlateStage, StoreError,
    TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::{Destination, Transport};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::cancel::pool_holds;
use crate::error::WalletError;
use crate::event::{BouncedInvoice, Event, ExpiredInvoice};
use crate::inbox::{Hold, InboxError, relay_network};
use crate::invoice::{InvoiceError, PaidInvoice, PayRequest};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::verify_message;
use crate::refresh::{final_kernel, last_confirmed, legacy_codecs, ttl_cutoff};
use crate::wallet::Wallet;

/// What a peer's own messages showed about invoices, from [`Wallet::peer_capability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerInvoiceSupport {
    /// Nothing yet: no marked slate or notice from it, and no invoice sent back.
    Unknown,
    /// A slate or notice from it carried the LEPIC marker, so it pays invoices and reads
    /// notices.
    Lepic,
    /// It sent an invoice back unpaid, so it neither pays invoices nor reads notices.
    NoInvoices,
}

/// How long an unpaid invoice is kept by default, on either side.
pub const DEFAULT_INVOICE_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest an unpaid invoice may be kept.
pub const MAX_INVOICE_EXPIRY: Duration = Duration::from_secs(48 * 60 * 60);

/// The TTL a payment of a parked invoice carries when the payer sets none: about a day of
/// blocks, the default expiry window.
pub const DEFAULT_PAYMENT_TTL_BLOCKS: u64 = 1440;

/// How long an unpaid invoice is kept: a payer deletes a parked one, an issuer cancels its own,
/// once this much time passed since it was received or issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvoiceExpiry(Duration);

impl InvoiceExpiry {
    /// Fails with [`InboxError::InvoiceExpiry`] for zero or anything over
    /// [`MAX_INVOICE_EXPIRY`].
    pub fn new(window: Duration) -> Result<Self, InboxError> {
        if window.is_zero() || window > MAX_INVOICE_EXPIRY {
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
    /// The address of the sender, where the payment goes.
    pub sender: EpicboxAddress,
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

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn slate_id(uuid: Uuid) -> SlateId {
    SlateId::from_bytes(uuid.into_bytes())
}

/// The key of `address`, as the store keys peers.
fn peer_key(address: &EpicboxAddress) -> String {
    address.key_text()
}

/// Prefix of the setting that keeps, per parked invoice, the address its I1 came from when
/// that names the sender's key under another relay than its stored address does.
const ORIGIN_PREFIX: &str = "invoice.origin.";

fn origin_key(slate_id: Uuid) -> String {
    format!("{ORIGIN_PREFIX}{slate_id}")
}

/// The address the I1 of parked invoice `slate_id` came from, when it differs from the stored
/// address its payment goes to. Same key, another relay: the issuer listens where it sent the
/// invoice from, which the stored address may no longer name.
pub(crate) fn invoice_origin(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<String>, StoreError> {
    repos.setting(&origin_key(slate_id))
}

/// The issued invoice and the address it went to, when `slate` is an I1 this wallet issued and
/// still holds, sent back unchanged from that address.
fn returned_invoice(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    slate: &Slate,
    from: &PublicKey,
    network: RelayNetwork,
) -> Result<Option<BouncedInvoice>, StoreError> {
    let slate_uuid = uuid(slate.id());
    let Some(issued) = repos.transaction_by_slate(slate_uuid, TxDirection::Incoming)? else {
        return Ok(None);
    };
    let Some(went_to) = repos
        .counterparty(issued.id)?
        .and_then(|address| EpicboxAddress::parse(&address, network).ok())
        .filter(|address| address.public_key() == from)
    else {
        return Ok(None);
    };
    let Some(stored) = repos.slate(slate_uuid, SlateStage::Invoice1)? else {
        return Ok(None);
    };
    let unchanged = codecs
        .decode(&WireSlate::binary(MediaType::JSON, stored.bytes))
        .is_ok_and(|issued| issued.with_origin(None) == slate.clone().with_origin(None));
    Ok(unchanged.then(|| BouncedInvoice {
        tx_id: issued.id,
        slate_id: slate.id(),
        peer: went_to,
    }))
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// What this wallet learned about the peer at `address` from its own messages: whether it
    /// proved it runs LEPIC, or sent an invoice back unpaid. Matched on the key only. Reads only
    /// the store.
    ///
    /// Fails with [`InboxError::Address`] for an address that does not parse or is on the other
    /// network, and with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn peer_capability(&self, address: &str) -> Result<PeerInvoiceSupport, InboxError> {
        let key = peer_key(&self.parse_address(address)?);
        let session = self.session()?;
        let learned = session
            .store
            .read(|repos| Ok::<_, WalletError>(repos.peer_capability(&key)?))?;
        Ok(match learned.map(|capability| capability.support) {
            None => PeerInvoiceSupport::Unknown,
            Some(PeerSupport::Lepic) => PeerInvoiceSupport::Lepic,
            Some(PeerSupport::NoInvoices) => PeerInvoiceSupport::NoInvoices,
        })
    }

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
                if crate::contact::slate_contact(repos, invoice.slate_id)?.is_none() {
                    parked.push(invoice);
                }
            }
            Ok::<_, WalletError>(parked)
        })?;
        Ok(parked
            .into_iter()
            .filter(|invoice| invoice.status == PendingInvoiceStatus::Parked)
            .filter_map(|invoice| {
                let sender =
                    EpicboxAddress::parse(&invoice.sender_address, relay_network(network)).ok()?;
                let wire = WireSlate::binary(MediaType::JSON, invoice.bytes);
                let Ok(slate) = epicbox_decode(&codecs, &wire) else {
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

    /// Pays the parked invoice `slate_id`, as [`Wallet::pay_invoice`] pays an I1, and delivers
    /// the I2 over Epicbox to the sender's stored address, and to the address the invoice came
    /// from when it names that key under another relay; either delivery is enough. The payment
    /// carries [`DEFAULT_PAYMENT_TTL_BLOCKS`] when `request.ttl_blocks` is `None`. The invoice
    /// is marked paid in the same store transaction that stores the payment.
    ///
    /// Fails with [`InvoiceError::NotParked`] when no invoice with the slate id waits to be
    /// paid, as [`Wallet::pay_invoice`] does, and with [`InvoiceError::PaymentUndelivered`]
    /// when the payment was stored but the relay failed; [`Wallet::resend`] tries again.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = TRANSPORT_ID.as_str(),
        slate_id = %slate_id,
        stage = %Stage::I2,
    ))]
    pub async fn pay_parked_invoice(
        &self,
        slate_id: SlateId,
        mut request: PayRequest,
    ) -> Result<PaidInvoice, InvoiceError> {
        let network = self.config().network;
        let session = self.session()?;
        let slate_uuid = uuid(slate_id);
        let parked = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.pending_invoice(slate_uuid))?)
            })
            .await?
            .filter(|invoice| invoice.status == PendingInvoiceStatus::Parked)
            .ok_or(InvoiceError::NotParked { slate_id })?;
        let session = self.session()?;
        let from_contact = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| crate::contact::slate_contact(repos, slate_uuid))?)
            })
            .await?;
        if from_contact.is_some() {
            // A contact's invoice is paid sealed, through Wallet::contact_pay_invoice.
            return Err(InvoiceError::NotParked { slate_id });
        }
        let codecs = stored_codecs(network);
        let i1 = epicbox_decode(&codecs, &WireSlate::binary(MediaType::JSON, parked.bytes))
            .map_err(InvoiceError::Decode)?;
        let to = Destination::new(parked.sender_address);
        let session = self.session()?;
        let origin = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| invoice_origin(repos, slate_uuid))?)
            })
            .await?
            .map(Destination::new);
        request.ttl_blocks = request.ttl_blocks.or(Some(DEFAULT_PAYMENT_TTL_BLOCKS));
        let paid = self
            .pay_decoded(TRANSPORT_ID, i1, request, Some(to.clone()))
            .await?;
        info!(tx_id = paid.tx_id.0, "invoice paid");
        let outbound = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .and_then(Transport::outbound)
            .ok_or(InvoiceError::CannotDeliver {
                transport: TRANSPORT_ID,
            })?;
        let delivered = outbound.deliver(&to, &paid.reply).await;
        // The issuer listens where it sent the invoice from; the stored address may name the
        // same key under a relay it left. Either delivery is enough.
        let delivered = match origin {
            Some(origin) => {
                let also = outbound.deliver(&origin, &paid.reply).await;
                if let Err(error) = &also {
                    debug!(error = %error, "payment not delivered to the invoice's relay");
                }
                delivered.or(also)
            }
            None => delivered,
        };
        delivered.map_err(|source| InvoiceError::PaymentUndelivered {
            tx_id: paid.tx_id,
            slate_id,
            source,
        })?;
        info!("slate sent");
        Ok(paid)
    }

    /// Declines the parked invoice `slate_id`: it is kept as declined and never paid. When its
    /// sender proved that it runs LEPIC, it is sent a `declined` notice from the payments
    /// address; the notice is advisory, so a failure to send it is logged and not returned.
    /// Fails with [`InvoiceError::NotParked`] when no invoice with the slate id waits to be
    /// paid, or when it came from a paired contact: decline those with
    /// `contact_decline_invoice`.
    #[instrument(skip_all, fields(wallet = %self.config().name, slate_id = %slate_id))]
    pub async fn decline_invoice(&self, slate_id: SlateId) -> Result<(), InvoiceError> {
        self.decline_parked(slate_id)?;
        info!("invoice declined");
        self.notify_declined(slate_id).await;
        Ok(())
    }

    fn decline_parked(&self, slate_id: SlateId) -> Result<(), InvoiceError> {
        let session = self.session()?;
        session.store.write(|repos| {
            // A contact's invoice is declined with `contact_decline_invoice` only.
            if crate::contact::slate_contact(repos, uuid(slate_id))?.is_some() {
                return Err(InvoiceError::NotParked { slate_id });
            }
            match repos.set_pending_invoice_status(uuid(slate_id), PendingInvoiceStatus::Declined) {
                Ok(()) => Ok(()),
                Err(StoreError::NotFound { .. } | StoreError::InvalidStatus { .. }) => {
                    Err(InvoiceError::NotParked { slate_id })
                }
                Err(error) => Err(error.into()),
            }
        })
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

    fn parse_address(&self, address: &str) -> Result<EpicboxAddress, InboxError> {
        EpicboxAddress::parse(address, relay_network(self.config().network))
            .map_err(InboxError::Address)
    }

    /// The issued invoice, when an I1 that arrived from `reply_to` is one this wallet issued to
    /// that address, sent back unchanged: what a stock `epic-wallet` listener does with an
    /// invoice.
    pub(crate) async fn bounced_invoice(
        &self,
        slate: &Slate,
        reply_to: &Destination,
    ) -> Result<Option<BouncedInvoice>, Hold> {
        let network = relay_network(self.config().network);
        let Ok(from) = EpicboxAddress::parse(reply_to.as_str(), network) else {
            return Ok(None);
        };
        let codecs = stored_codecs(self.config().network);
        let session = self.session()?;
        let slate = slate.clone();
        Ok(self
            .blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    returned_invoice(repos, &codecs, &slate, from.public_key(), network)
                })?)
            })
            .await?)
    }

    /// Records that the peer of a bounced invoice does not pay invoices, so nothing but slates
    /// is ever sent to it, and tells the host which invoice came back.
    pub(crate) async fn record_bounce(&self, bounced: BouncedInvoice) -> Result<(), Hold> {
        let key = peer_key(&bounced.peer);
        self.inbox_write(move |repos, now| {
            repos.put_peer_capability(&PeerCapability {
                key,
                support: PeerSupport::NoInvoices,
                learned_at: now,
            })
        })
        .await?;
        info!(tx_id = %bounced.tx_id, slate_id = %bounced.slate_id, "invoice returned unpaid");
        self.emit(Event::InvoiceBounced(bounced));
        Ok(())
    }
}

/// The legacy codecs at the network's base fee, which read every slate this wallet stores.
pub(crate) fn stored_codecs(network: Network) -> CodecRegistry {
    legacy_codecs(network.params().default_base_fee())
}

fn epicbox_decode(
    codecs: &CodecRegistry,
    wire: &WireSlate,
) -> Result<Slate, lepic_slate::error::DecodeError> {
    use lepic_transport::policy::FormatPolicy;
    lepic_epicbox::transport::EpicboxPolicy.decode(codecs, wire)
}

/// The issuer's message of an I1, when its signature verifies, for display.
pub(crate) fn issuer_message(slate: &Slate) -> Option<String> {
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
            repos.delete_setting(&origin_key(invoice.slate_id))?;
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
                if transport == TRANSPORT_ID.as_str() || transport == FILE.as_str());
            if (!issued_here && crate::contact::slate_contact(repos, slate_uuid)?.is_none())
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
/// height has reached, with the kernel to look up.
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
                .is_some_and(|cutoff| confirmed >= cutoff);
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
    if (entry.transport.as_deref() != Some(TRANSPORT_ID.as_str())
        && crate::contact::slate_contact(repos, slate_uuid)?.is_none())
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
    fn expiry_is_positive_and_at_most_two_days() {
        assert!(InvoiceExpiry::new(Duration::ZERO).is_err());
        assert!(InvoiceExpiry::new(MAX_INVOICE_EXPIRY).is_ok());
        assert!(InvoiceExpiry::new(MAX_INVOICE_EXPIRY + Duration::from_secs(1)).is_err());
        assert_eq!(InvoiceExpiry::default().window(), DEFAULT_INVOICE_EXPIRY);
    }
}
