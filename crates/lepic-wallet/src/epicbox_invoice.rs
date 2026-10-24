//! Invoices over Epicbox, the payer's side and the housekeeping of both sides.
//!
//! Invoices arrive on a separate invoice address, the wallet's Epicbox identity at address index
//! 1 or higher, which hears only from senders the user allowed. Its subscription drops every
//! message from another key before the signature check, key agreement or decryption, and
//! without touching the store. An allowed sender's I1 is parked in the store before the relay
//! is told it was received; nothing in the inbox ever pays. Paying a parked invoice is a host
//! call, which delivers the I2 to the address the user allowed.
//!
//! The issuer side lives in the payments inbox ([`crate::inbox`]): an I2 that answers an
//! invoice this wallet issued is finalized and posted, and an I1 the payer sent back unchanged
//! records that the payer does not pay invoices. [`crate::Wallet::sweep_invoices`] expires
//! what was left unpaid on either side.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use lepic_crypto::{Commitment, PublicKey};
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{
    Admission, EpicboxAddress, EpicboxClient, Network as RelayNetwork, Prefilter, TRANSPORT_ID,
};
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::codec::marked_v3::carries_lepic_marker;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::{MAX_MESSAGE_LEN, Slate, SlateId};
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::Stage;
use lepic_store::{
    AllowedPeer, InvoiceAddressIndex, PeerCapability, PeerSupport, PendingInvoice,
    PendingInvoiceStatus, Repositories, SlateStage, StoreError, TxDirection, TxId, TxState,
    WalletStore,
};
use lepic_transport::transport::{Destination, Envelope, Transport};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::account::is_hidden;
use crate::cancel::pool_holds;
use crate::epicbox_notice::record_lepic;
use crate::error::WalletError;
use crate::event::{BouncedInvoice, Event, ExpiredInvoice, ParkedInvoice};
use crate::inbox::{
    Handled, Hold, InboxError, InboxSummary, Mailbox, Refusal, Settlement, relay_network,
};
use crate::invoice::{InvoiceError, PaidInvoice, PayRequest, check_messages};
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

/// The longest a user-chosen sender label may be, in bytes.
pub const MAX_SENDER_LABEL_LEN: usize = 64;

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

/// A sender whose invoices the invoice address accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSender {
    /// The full address the user added. Payments and replies go here, whatever domain a
    /// message from the same key names.
    pub address: EpicboxAddress,
    pub label: String,
    pub added_at: Timestamp,
}

/// An invoice parked on the invoice address, as the host shows it to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingInvoice {
    pub slate_id: SlateId,
    /// The allowed address of the sender, where the payment goes.
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

/// The sender keys the invoice address accepts, read once when a drain starts.
struct Allowlist(HashSet<PublicKey>);

impl Prefilter for Allowlist {
    fn admit(&self, sender: &PublicKey) -> Admission {
        if self.0.contains(sender) {
            Admission::Accept
        } else {
            Admission::Drop
        }
    }
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

/// How parking an I1 ended in the store.
enum Parking {
    Parked,
    /// The same invoice was parked before.
    Again,
    /// Another slate is stored under the slate id.
    Conflict,
    /// A cap on parked invoices is reached; the invoice is dropped.
    Full,
    /// The sender was removed from the allowlist since the drain started.
    NotAllowed,
}

/// A received I1 to park, before the store says where its sender is allowed.
struct Arrival {
    slate_id: Uuid,
    sender_key: String,
    codec: String,
    bytes: Vec<u8>,
    /// The I1 carried the LEPIC marker, so its sender runs LEPIC.
    marked: bool,
    /// The address the I1 came from: the sender's key under the relay it sent from.
    origin: EpicboxAddress,
}

/// Prefix of the setting that keeps, per parked invoice, the address its I1 came from when
/// that names the allowed key under another relay than the allowed address does.
const ORIGIN_PREFIX: &str = "invoice.origin.";

fn origin_key(slate_id: Uuid) -> String {
    format!("{ORIGIN_PREFIX}{slate_id}")
}

/// The address the I1 of parked invoice `slate_id` came from, when it differs from the
/// allowed address its payment goes to. Same key, another relay: the issuer listens where it
/// sent the invoice from, which the allowed entry may no longer name.
pub(crate) fn invoice_origin(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<String>, StoreError> {
    repos.setting(&origin_key(slate_id))
}

fn park_stored(
    repos: &mut dyn Repositories,
    arrival: Arrival,
    now: Timestamp,
) -> Result<Parking, StoreError> {
    let Some(allowed) = repos.allowed_peer(&arrival.sender_key)? else {
        return Ok(Parking::NotAllowed);
    };
    if arrival.marked {
        record_lepic(repos, arrival.sender_key.clone(), now)?;
    }
    let allowed_at = EpicboxAddress::parse(&allowed.address, arrival.origin.network()).ok();
    let origin = (allowed_at.as_ref() != Some(&arrival.origin)).then(|| arrival.origin.to_string());
    let invoice = PendingInvoice {
        slate_id: arrival.slate_id,
        sender_key: arrival.sender_key,
        sender_address: allowed.address,
        received_at: now,
        status: PendingInvoiceStatus::Parked,
        codec: arrival.codec,
        bytes: arrival.bytes,
    };
    if let Some(stored) = repos.pending_invoice(invoice.slate_id)? {
        return Ok(if stored.bytes == invoice.bytes {
            Parking::Again
        } else {
            Parking::Conflict
        });
    }
    match repos.park_invoice(&invoice) {
        Ok(()) => {
            if let Some(origin) = origin {
                repos.put_setting(&origin_key(invoice.slate_id), &origin)?;
            }
            Ok(Parking::Parked)
        }
        Err(StoreError::InvoiceCapReached { .. }) => Ok(Parking::Full),
        Err(error) => Err(error),
    }
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
    /// The current invoice address index: the one stored, or 1 before any was, as after a
    /// restore. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn invoice_address_index(&self) -> Result<u32, WalletError> {
        let session = self.session()?;
        let index = session.store.read(|repos| current_index(repos))?;
        Ok(index.get())
    }

    /// Sets the invoice address index, for example to the one the host kept before a restore.
    /// Messages for the previous invoice address are no longer read.
    ///
    /// Fails with [`InboxError::PaymentsAddressIndex`] for index 0, and with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn set_invoice_address_index(&self, index: u32) -> Result<(), InboxError> {
        let index = InvoiceAddressIndex::new(index).ok_or(InboxError::PaymentsAddressIndex)?;
        let session = self.session()?;
        session
            .store
            .write(|repos| Ok::<_, WalletError>(repos.set_invoice_address_index(index)?))?;
        info!("invoice address set");
        Ok(())
    }

    /// The wallet's invoice address at the relay of `epicbox`: the address key at the current
    /// invoice address index, derived as `epic-wallet` derives index 0, so the seed restores
    /// it. It is not attached; [`Wallet::epicbox_drain_invoices`] reads it on a connection of
    /// its own.
    ///
    /// Fails with [`InboxError::NetworkMismatch`] and as [`Wallet::invoice_address_index`]
    /// does.
    pub fn invoice_address(
        &self,
        epicbox: &EpicboxTransport,
    ) -> Result<EpicboxAddress, InboxError> {
        let index = self.invoice_address_index()?;
        Ok(self.identity_at(epicbox, index)?.address().clone())
    }

    /// Moves the invoice address to the next index and returns the new address. The old one is
    /// abandoned: its messages are no longer read.
    ///
    /// Fails with [`InboxError::InvoiceIndexExhausted`] past the last index, and as
    /// [`Wallet::invoice_address`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn rotate_invoice_address(
        &self,
        epicbox: &EpicboxTransport,
    ) -> Result<EpicboxAddress, InboxError> {
        let next = {
            let session = self.session()?;
            session.store.write(|repos| {
                let next = current_index(repos)?
                    .next()
                    .ok_or(InboxError::InvoiceIndexExhausted)?;
                repos
                    .set_invoice_address_index(next)
                    .map_err(WalletError::Store)?;
                Ok::<_, InboxError>(next)
            })?
        };
        let address = self.identity_at(epicbox, next.get())?.address().clone();
        info!("invoice address rotated");
        Ok(address)
    }

    /// What this wallet learned about the peer at `address` from its own messages: whether it
    /// proved it runs LEPIC, or sent an invoice back unpaid. Matched on the key only, as the
    /// allowlist is. Reads only the store.
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

    /// Allows invoices from the key of `address`, a full Epicbox address on the wallet's
    /// network. Payments of its invoices go to `address`, whatever domain its messages name,
    /// because the relay authenticates the key of a message and never its domain. Adding the
    /// key again replaces its address and label.
    ///
    /// Fails with [`InboxError::Address`] for an address that does not parse or is on the other
    /// network, with [`InboxError::SenderLabel`] for a label longer than
    /// [`MAX_SENDER_LABEL_LEN`] bytes or with control or hidden formatting characters, and with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn allow_invoice_sender(
        &self,
        address: &str,
        label: &str,
    ) -> Result<AllowedSender, InboxError> {
        let address = self.parse_address(address)?;
        if label.len() > MAX_SENDER_LABEL_LEN || label.chars().any(is_hidden) {
            return Err(InboxError::SenderLabel);
        }
        let session = self.session()?;
        let added_at = self.ports().clock.now();
        let peer = AllowedPeer {
            key: peer_key(&address),
            address: address.to_string(),
            label: label.to_owned(),
            added_at,
        };
        session
            .store
            .write(|repos| Ok::<_, WalletError>(repos.put_allowed_peer(&peer)?))?;
        info!("invoice sender allowed");
        Ok(AllowedSender {
            address,
            label: peer.label,
            added_at,
        })
    }

    /// Stops allowing invoices from the key of `address`, and returns whether it was allowed.
    /// Invoices already parked from it stay. Fails as [`Wallet::allow_invoice_sender`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn remove_invoice_sender(&self, address: &str) -> Result<bool, InboxError> {
        let key = peer_key(&self.parse_address(address)?);
        let session = self.session()?;
        let removed = session
            .store
            .write(|repos| Ok::<_, WalletError>(repos.remove_allowed_peer(&key)?))?;
        if removed {
            info!("invoice sender removed");
        }
        Ok(removed)
    }

    /// The allowed senders, in the order they were added. An entry whose stored address no
    /// longer parses is left out. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn invoice_senders(&self) -> Result<Vec<AllowedSender>, WalletError> {
        let network = relay_network(self.config().network);
        let session = self.session()?;
        let peers = session
            .store
            .read(|repos| Ok::<_, WalletError>(repos.allowed_peers()?))?;
        Ok(peers
            .into_iter()
            .filter_map(|peer| {
                let address = EpicboxAddress::parse(&peer.address, network).ok()?;
                Some(AllowedSender {
                    address,
                    label: peer.label,
                    added_at: peer.added_at,
                })
            })
            .collect())
    }

    /// Connects to the relay as the invoice address once, handles every pending message and
    /// disconnects. A message from a key that is not allowed is acknowledged and dropped
    /// unopened, with no store write. An allowed sender's I1 is parked, within the store's
    /// caps, before it is acknowledged, and announced as [`Event::InvoiceParked`]; one over
    /// a cap is dropped. An I2 is finalized as in [`Wallet::epicbox_drain`]. Anything else is
    /// rejected and acknowledged.
    ///
    /// The drain reads the allowlist when it starts. Fails as [`Wallet::epicbox_drain`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn epicbox_drain_invoices(
        &self,
        epicbox: &EpicboxTransport,
    ) -> Result<InboxSummary, InboxError> {
        self.check_epicbox_registered()?;
        let client = self.invoice_client(epicbox).await?;
        self.prune_relay_inbox().await;
        let subscription = client.drain().map_err(InboxError::Subscription)?;
        let mut summary = self
            .run_inbox(
                &subscription,
                None,
                epicbox.settings().backoff,
                Mailbox::Invoices,
            )
            .await?;
        let dropped = u32::try_from(subscription.counters().dropped).unwrap_or(u32::MAX);
        summary.dropped = summary.dropped.saturating_add(dropped);
        Ok(summary)
    }

    /// The client of the invoice address, which admits the allowlist as it is stored now and
    /// the senders of the invoices this wallet holds, whose notices about them arrive here
    /// even after a sender was removed from the allowlist.
    async fn invoice_client(
        &self,
        epicbox: &EpicboxTransport,
    ) -> Result<EpicboxClient, InboxError> {
        let identity = self.identity_at(epicbox, self.invoice_address_index()?)?;
        let network = relay_network(self.config().network);
        let session = self.session()?;
        let addresses = self
            .blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    let mut addresses: Vec<String> = repos
                        .allowed_peers()?
                        .into_iter()
                        .map(|peer| peer.address)
                        .collect();
                    addresses.extend(
                        repos
                            .pending_invoices()?
                            .into_iter()
                            .map(|invoice| invoice.sender_address),
                    );
                    Ok::<_, StoreError>(addresses)
                })?)
            })
            .await?;
        let keys = addresses
            .iter()
            .filter_map(|address| EpicboxAddress::parse(address, network).ok())
            .map(|address| *address.public_key())
            .collect();
        Ok(epicbox
            .client_for(identity)
            .with_prefilter(Arc::new(Allowlist(keys))))
    }

    /// The invoices parked on the invoice address, oldest first, with when `expiry` deletes
    /// them. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn pending_invoices(
        &self,
        expiry: InvoiceExpiry,
    ) -> Result<Vec<IncomingInvoice>, WalletError> {
        let network = self.config().network;
        let codecs = stored_codecs(network);
        let session = self.session()?;
        let parked = session
            .store
            .read(|repos| Ok::<_, WalletError>(repos.pending_invoices()?))?;
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
    /// the I2 over Epicbox to the sender's allowed address, and to the address the invoice came
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
        // The issuer listens where it sent the invoice from; the allowed entry may name the
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
    /// sender proved that it runs LEPIC, it is sent a `declined` notice from the current
    /// invoice address of `epicbox`; the notice is advisory, so a failure to send it is logged
    /// and not returned. Fails with [`InvoiceError::NotParked`] when no invoice with the slate
    /// id waits to be paid.
    #[instrument(skip_all, fields(wallet = %self.config().name, slate_id = %slate_id))]
    pub async fn decline_invoice(
        &self,
        epicbox: &EpicboxTransport,
        slate_id: SlateId,
    ) -> Result<(), InvoiceError> {
        self.decline_parked(slate_id)?;
        info!("invoice declined");
        self.notify_declined(epicbox, slate_id).await;
        Ok(())
    }

    fn decline_parked(&self, slate_id: SlateId) -> Result<(), InvoiceError> {
        let session = self.session()?;
        session.store.write(|repos| {
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
    /// - an invoice this wallet issued over Epicbox more than `expiry` ago and not paid is
    ///   cancelled, which frees its output and private context, so a late payment is refused;
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

    /// Parks an I1 from an allowed sender before the message is acknowledged.
    pub(crate) async fn park(
        &self,
        envelope: &Envelope,
        slate: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        let network = relay_network(self.config().network);
        let from = EpicboxAddress::parse(reply_to.as_str(), network)
            .map_err(|_| Refusal::SenderNotAllowed)?;
        check_messages(slate).map_err(Refusal::InvoiceMessage)?;
        let arrival = Arrival {
            slate_id: uuid(slate.id()),
            sender_key: peer_key(&from),
            codec: slate
                .origin()
                .map(|origin| origin.codec().as_str().to_owned())
                .unwrap_or_default(),
            bytes: envelope.wire().as_bytes().to_vec(),
            marked: carries_lepic_marker(envelope.wire()),
            origin: from.clone(),
        };
        let parking = self
            .inbox_write(move |repos, now| park_stored(repos, arrival, now))
            .await
            .map_err(Hold::from)?;
        match parking {
            Parking::Parked => {
                info!(slate_id = %slate.id(), "invoice parked");
                self.emit(Event::InvoiceParked(ParkedInvoice {
                    slate_id: slate.id(),
                    amount: slate.amount(),
                }));
                Ok(Handled::Parked)
            }
            Parking::Again => Ok(Handled::Repeated),
            Parking::Conflict => Err(Refusal::SlateIdReused.into()),
            Parking::Full => {
                warn!(slate_id = %slate.id(), "invoice dropped over the parking cap");
                Ok(Handled::Dropped)
            }
            Parking::NotAllowed => Err(Refusal::SenderNotAllowed.into()),
        }
    }
}

/// The stored index, or the first one before any was stored.
fn current_index(repos: &dyn Repositories) -> Result<InvoiceAddressIndex, WalletError> {
    Ok(repos
        .invoice_address_index()?
        .unwrap_or(InvoiceAddressIndex::FIRST))
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
fn issuer_message(slate: &Slate) -> Option<String> {
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
            if entry.transport.as_deref() != Some(TRANSPORT_ID.as_str())
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
    if entry.transport.as_deref() != Some(TRANSPORT_ID.as_str())
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
