//! The Epicbox inbox: what the engine does with each message the relay hands out (ADR 0004).
//!
//! A message is decoded with the Epicbox policy and routed by stage: an S1 is received and
//! answered with S2 through the same transport, an S2 is finalized and posted. A slate the
//! node's tip says has expired is held, not rejected, until a refresh confirms a height at or
//! past its cutoff. Its relay message
//! id is tracked in the store's relay inbox. A message is acknowledged once its effect is stored,
//! or once it was rejected for good and the rejection is recorded, under its relay message id
//! when the relay gave it one; a transient failure leaves it
//! unacknowledged, so the relay delivers it again.
//!
//! A held message holds back everything behind it, because the relay delivers one message at a
//! time, and the relay discards everything queued for the address when one message stays
//! unacknowledged for long. So holds are bounded by [`MAX_HOLD_ATTEMPTS`] and [`HOLD_PATIENCE`]:
//! a reply the relay refuses, or one still undelivered at the bound, leaves the payment received
//! and settles the message with [`Event::ReplyUndelivered`]; a slate still expired by the tip
//! alone after one refresh and at the bound is refused.
//!
//! An S2 or I2 for a slate this store does not know may belong to another install on the same
//! recovery phrase, which shares the payments address. It is held for [`TWIN_HOLD`] and then
//! requeued for that install, posted back to the address as its sender signed it, rather than
//! refused at once; at most [`MAX_TWIN_ANSWERS`] at a time, for [`TWIN_REQUEUE_WINDOW`], and
//! only while the inputs it spends are unspent.
//!
//! Payments nobody asked for are bounded too: at most [`MAX_OPEN_RECEIPTS_PER_SENDER`] open
//! receipts per sender key and [`MAX_OPEN_RECEIPTS`] in all (see their docs).
//!
//! Every message is idempotent on its relay id and on `(slate_id, stage)`: a redelivered S1 is
//! answered with the S2 stored the first time, never a new one, and announced as
//! [`Event::AnsweredAgain`]; finalizing an S2 again changes nothing that is stored. A message
//! whose relay id settled before is acknowledged without an answer or an event.

use std::error::Error as StdError;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{
    AddressError, Backoff, ClientError, ConnectionState, EpicboxAddress, EpicboxClient, Identity,
    Network as RelayNetwork, RELAY_RETENTION, Rejection, RelayErrorKind, RelayMessageId,
    Subscription, TRANSPORT_ID,
};
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_slate::codec::marked_v3::carries_lepic_marker;
use lepic_slate::model::Slate;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, InboxEntry, InboxStatus, Repositories, SlateStage, StoreError, TxId, TxState,
    WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{Destination, Envelope, Inbound, TransportId};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::account;
use crate::error::WalletError;
use crate::event::{
    Connection, Event, FinalizedInvoice, SlateId, TransportDisconnect, TransportState,
    TransportStatus, UndeliveredReply, UnknownSlate,
};
use crate::finalize::FinalizeError;
use crate::invoice::InvoiceError;
use crate::notice::{self, Payload};
use crate::ports::{SecretVault, StoreOpener};
use crate::receipt_cap::{NoRoom, Sender};
use crate::receive::{ReceiveError, ReceiveRequest, legacy_codecs};
use crate::refresh::last_confirmed;
use crate::twin_answer::{self, Refused, Step};
use crate::wallet::Wallet;

pub use crate::twin_answer::{MAX_TWIN_ANSWERS, TWIN_HOLD, TWIN_REQUEUE_WINDOW};

/// `epic-wallet` always uses the address key at index 0 of the account.
const ADDRESS_INDEX: u32 = 0;

/// The account whose address key is the wallet's Epicbox identity.
const ADDRESS_ACCOUNT: AccountIndex = AccountIndex(0);

/// `epic-wallet`'s Epicbox listener posts finalized transactions without fluff.
const POST_PROPAGATION: Propagation = Propagation::Stem;

const MAX_ERROR_SOURCES: usize = 8;

/// Settling messages prunes the relay inbox at most this often, on the wallet clock.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Tries of a message in one listen before a reply that keeps failing, or a slate that only the
/// node's tip says has expired, is settled anyway. The relay discards every message queued for
/// an address when one stays unacknowledged across several of its challenge rounds, which come
/// about a minute apart, and every message behind a held one waits meanwhile; so a held message
/// is settled well before that, while its payment can still be stored.
const MAX_HOLD_ATTEMPTS: u32 = 3;

/// How long after its message first arrived such a message is still held, for drains, which
/// try each message once: well under the relay's challenge rounds that end in the queue being
/// discarded, as for [`MAX_HOLD_ATTEMPTS`].
const HOLD_PATIENCE: Duration = Duration::from_secs(3 * 60);

/// How far the wallet clock may step back, as time synchronisation steps it, before a message
/// that seems to have arrived in the future counts as held for [`HOLD_PATIENCE`].
const CLOCK_STEP_TOLERANCE: Duration = Duration::from_secs(60);

/// An expired slate makes the inbox refresh the tip at most this often, on the wallet clock, so
/// a stream of expired slates costs bounded node work.
const TIP_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

const TIP_REFRESHED_SETTING: &str = "inbox.tip_refreshed_at";

/// Open receipts, payments received over Epicbox and answered with S2 that the sender has not
/// finalized, kept from one sender key. A paying wallet finalizes as soon as the S2 arrives, so
/// a sender with this many open is not finalizing; a further S1 from its key is refused and
/// acknowledged without being signed or stored, unless a refresh, made first at most once a
/// minute, confirms some of them. The same cap applies to parked invoices.
pub const MAX_OPEN_RECEIPTS_PER_SENDER: usize = 10;

/// Open receipts kept over every sender. Each holds an unconfirmed output, a transaction and its
/// slates, so this bounds what unsolicited payments can store. At the cap the inbox first
/// refreshes, at most once a minute, so receipts already mined are confirmed and leave the open
/// set. Then one open receipt is cancelled to make room, as [`Wallet::cancel`] does, so a
/// payment completed later is still restored: the sender key with the most open receipts gives
/// one up first, oldest first, and a receipt the node's pool or chain holds is kept. When none
/// can be cancelled, the new S1 is refused without being signed or stored; the sender can send
/// it again. A node that cannot be asked holds the S1 only to the hold bound before it is
/// refused the same way.
pub const MAX_OPEN_RECEIPTS: usize = 100;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InboxError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("epicbox transport serves another network than the wallet")]
    NetworkMismatch,
    #[error("epicbox identity rejected")]
    Identity(#[source] ClientError),
    /// The relay connection failed. Unacknowledged messages stay on the relay; try again later.
    #[error("epicbox subscription failed")]
    Subscription(#[source] ClientError),
    #[error("epicbox subscription failed")]
    Transport(#[source] TransportError),
    #[error("epicbox address rejected")]
    Address(#[source] AddressError),
    #[error("invoice expiry must be positive and at most two days")]
    InvoiceExpiry,
}

impl From<StoreError> for InboxError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// What one listen or drain did with the messages it was handed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboxSummary {
    /// S1 slates received and answered with S2.
    pub received: u32,
    /// S2 and I2 slates finalized for the first time; posting may still be pending.
    pub finalized: u32,
    /// Messages handled before and acknowledged again: an S1 answered again with its stored S2,
    /// or an S2 that was already finalized.
    pub repeated: u32,
    /// Messages rejected for good, recorded and acknowledged.
    pub rejected: u32,
    /// Messages left unacknowledged after a transient failure; the relay delivers them again.
    pub held: u32,
    /// Invoices stored for the user to pay or decline.
    pub parked: u32,
    /// Invoices this wallet issued that the payer sent back unchanged, so it does not pay
    /// invoices.
    pub bounced: u32,
    /// Messages acknowledged and forgotten: invoices over the parking caps, and notices not
    /// from the counterparty of their slate, of an unknown version or type, oversize or
    /// malformed.
    pub dropped: u32,
    /// Notices accepted from the counterparty of their slate (ADR 0016).
    pub notices: u32,
    /// Answers for a slate this store does not know, posted back to the address for another
    /// install of the wallet and acknowledged.
    pub requeued: u32,
}

impl InboxSummary {
    fn count(&mut self, handled: Handled) {
        let counter = match handled {
            Handled::Received => &mut self.received,
            Handled::Finalized => &mut self.finalized,
            Handled::Repeated => &mut self.repeated,
            Handled::Rejected => &mut self.rejected,
            Handled::Bounced => &mut self.bounced,
            Handled::Dropped => &mut self.dropped,
            Handled::Notice => &mut self.notices,
            Handled::Requeued => &mut self.requeued,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Ends an [`Wallet::epicbox_listen`]. Clones stop the same listen.
#[derive(Debug, Clone)]
pub struct ListenHandle(Arc<watch::Sender<Ending>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Running,
    /// Ends once no message is in hand.
    Finish,
    /// Ends at once, abandoning the message in hand.
    Stop,
}

impl ListenHandle {
    pub fn new() -> Self {
        Self(Arc::new(watch::Sender::new(Ending::Running)))
    }

    /// Asks the listen to end. It finishes or abandons the message in hand, unsubscribes and
    /// returns.
    pub fn stop(&self) {
        self.0.send_replace(Ending::Stop);
    }

    /// Asks the listen to end once no message is in hand: one being handled is settled and
    /// acknowledged first, one waiting for a retry stays on the relay. Then it unsubscribes
    /// and returns. A later [`ListenHandle::stop`] ends it at once.
    pub fn finish(&self) {
        self.0.send_if_modified(|ending| {
            let running = *ending == Ending::Running;
            if running {
                *ending = Ending::Finish;
            }
            running
        });
    }

    /// True once [`ListenHandle::stop`] or [`ListenHandle::finish`] was called.
    pub fn is_stopped(&self) -> bool {
        *self.0.borrow() != Ending::Running
    }

    /// Resolves once the listen should end between messages.
    async fn stopped(&self) {
        self.wait_for(|ending| ending != Ending::Running).await;
    }

    /// Resolves once the listen should end even with a message in hand.
    async fn abandoned(&self) {
        self.wait_for(|ending| ending == Ending::Stop).await;
    }

    async fn wait_for(&self, ends: impl Fn(Ending) -> bool) {
        let mut receiver = self.0.subscribe();
        // The sender lives in `self`, so waiting cannot fail.
        let _ = receiver.wait_for(|ending| ends(*ending)).await;
    }
}

impl Default for ListenHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// What became of one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handled {
    Received,
    Finalized,
    Repeated,
    Rejected,
    Bounced,
    Dropped,
    Notice,
    Requeued,
}

impl Handled {
    fn inbox_status(self) -> InboxStatus {
        match self {
            Self::Rejected | Self::Dropped => InboxStatus::Rejected,
            Self::Received
            | Self::Finalized
            | Self::Repeated
            | Self::Bounced
            | Self::Notice
            | Self::Requeued => InboxStatus::Processed,
        }
    }
}

/// Settled messages are acknowledged; a held one is left for the relay to deliver again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Settled(Handled),
    Held,
}

enum Item {
    /// An envelope with the relay message id the subscription handed it out under, if any.
    Envelope(Envelope, Option<RelayMessageId>),
    Rejection(Rejection),
}

impl Item {
    fn envelope(subscription: &Subscription, envelope: Envelope) -> Self {
        let msg_id = subscription.relay_message_id(envelope.ack_token());
        Self::Envelope(envelope, msg_id)
    }

    fn ack_token(&self) -> &lepic_transport::transport::AckToken {
        match self {
            Self::Envelope(envelope, _) => envelope.ack_token(),
            Self::Rejection(rejection) => rejection.ack_token(),
        }
    }

    fn msg_id(&self) -> Option<&str> {
        match self {
            Self::Envelope(_, msg_id) => msg_id.as_ref(),
            Self::Rejection(rejection) => rejection.msg_id(),
        }
        .map(RelayMessageId::as_str)
    }
}

/// Why a message is rejected for good, for the log.
#[derive(Debug, Error)]
pub(crate) enum Refusal {
    #[error("message carries no reply address")]
    NoReplyAddress,
    #[error("slate could not be decoded")]
    Decode(#[source] lepic_slate::error::DecodeError),
    #[error("slate at stage {stage} is not handled over epicbox")]
    UnsupportedStage { stage: Stage },
    #[error("slate id was received before with another slate")]
    SlateIdReused,
    #[error("slate was not received")]
    Receive(#[source] ReceiveError),
    #[error("slate was not finalized")]
    Finalize(#[source] FinalizeError),
    #[error("invoice was not finalized")]
    Invoice(#[source] InvoiceError),
    #[error("sender already has the most open receipts allowed")]
    OpenReceiptsFromSender,
    #[error("open receipts are at the cap and none could be cancelled")]
    OpenReceipts,
    #[error("open receipts are at the cap and the node could not be asked to cancel one")]
    OpenReceiptsUnchecked(#[source] WalletError),
}

/// A failure that leaves the message for the relay to deliver again.
#[derive(Debug, Error)]
pub(crate) enum Hold {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} cannot deliver the reply")]
    NoOutbound { transport: TransportId },
    #[error("notice withheld from a peer not proven to run lepic")]
    Withheld,
    #[error("reply was not delivered")]
    Reply(#[source] TransportError),
    #[error("slate was not received")]
    Receive(#[source] ReceiveError),
    #[error("slate was not finalized")]
    Finalize(#[source] FinalizeError),
    #[error("invoice was not finalized")]
    Invoice(#[source] InvoiceError),
    #[error("answer for an unknown slate held for another install")]
    UnknownSlate,
    #[error("answer for an unknown slate not requeued")]
    Requeue(#[source] ClientError),
}

impl From<StoreError> for Hold {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// Displays an error with its source chain, for the `error` log field.
pub(crate) struct ErrorChain<'a>(pub(crate) &'a (dyn StdError + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let sources = std::iter::successors(self.0.source(), |&error| error.source());
        for source in sources.take(MAX_ERROR_SOURCES) {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

/// Failures of receiving an S1 that the same message would meet again: the slate itself is
/// wrong. Local and node failures pass.
fn receive_is_permanent(error: &ReceiveError) -> bool {
    match error {
        ReceiveError::Wallet(_)
        | ReceiveError::UnknownTransport { .. }
        | ReceiveError::Node(_)
        | ReceiveError::Codecs(_)
        | ReceiveError::OpenReceipts(_) => false,
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::ZeroAmount
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::Expired { .. }
        | ReceiveError::AheadOfTip { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::FeeOverflow
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ForeignProofAddress
        | ReceiveError::Output(_)
        | ReceiveError::Signing(_)
        | ReceiveError::Excess(_)
        | ReceiveError::Slate(_)
        | ReceiveError::Encode(_) => true,
    }
}

/// Failures of finalizing an S2 that the same message would meet again. A slate that was
/// finalized and stored but not posted is not a failure of the message; the caller handles it.
fn finalize_is_permanent(error: &FinalizeError) -> bool {
    match error {
        FinalizeError::Wallet(_)
        | FinalizeError::UnknownTransport { .. }
        | FinalizeError::Node(_)
        | FinalizeError::Codecs(_)
        | FinalizeError::NotPosted { .. } => false,
        FinalizeError::Decode(_)
        | FinalizeError::WrongStage { .. }
        | FinalizeError::UnknownSlate { .. }
        | FinalizeError::AlreadyFinalized { .. }
        | FinalizeError::NotFinalizable { .. }
        | FinalizeError::Expired { .. }
        | FinalizeError::Mismatch { .. }
        | FinalizeError::MissingPaymentProof
        | FinalizeError::ForeignSenderAddress
        | FinalizeError::PaymentProofSignature
        | FinalizeError::MessageSignature(_)
        | FinalizeError::ReceiverSignature(_)
        | FinalizeError::FeeBelowMinimum { .. }
        | FinalizeError::FeeOverflow
        | FinalizeError::Signing(_)
        | FinalizeError::Excess(_)
        | FinalizeError::InvalidTransaction(_)
        | FinalizeError::Slate(_)
        | FinalizeError::Encode(_)
        | FinalizeError::StoredSlate(_)
        | FinalizeError::MissingContext { .. }
        | FinalizeError::MalformedContext
        | FinalizeError::NotPostable { .. } => true,
    }
}

/// Failures of finalizing an I2 that the same message would meet again, as for an S2. A late
/// I2 for an invoice cancelled or expired here is refused this way.
fn invoice_finalize_is_permanent(error: &InvoiceError) -> bool {
    match error {
        InvoiceError::Wallet(_)
        | InvoiceError::Node(_)
        | InvoiceError::UnknownTransport { .. }
        | InvoiceError::CannotDeliver { .. }
        | InvoiceError::CannotExport { .. }
        | InvoiceError::Codecs(_)
        | InvoiceError::Selection(_)
        | InvoiceError::NotPosted { .. }
        | InvoiceError::Undelivered { .. }
        | InvoiceError::PaymentUndelivered { .. } => false,
        InvoiceError::Decode(_)
        | InvoiceError::WrongStage { .. }
        | InvoiceError::AmountMismatch { .. }
        | InvoiceError::AlreadyPaid { .. }
        | InvoiceError::Expired { .. }
        | InvoiceError::LockedUntil { .. }
        | InvoiceError::AheadOfTip { .. }
        | InvoiceError::MessageSignature { .. }
        | InvoiceError::Mismatch { .. }
        | InvoiceError::InputKeyMismatch
        | InvoiceError::KeyIdentifier(_)
        | InvoiceError::Output(_)
        | InvoiceError::Signing(_)
        | InvoiceError::PayerSignature(_)
        | InvoiceError::FeeBelowMinimum { .. }
        | InvoiceError::FeeOverflow
        | InvoiceError::Excess(_)
        | InvoiceError::InvalidTransaction(_)
        | InvoiceError::Slate(_)
        | InvoiceError::Arithmetic(_)
        | InvoiceError::Encode(_)
        | InvoiceError::Unrepresentable(_)
        | InvoiceError::StoredSlate(_)
        | InvoiceError::UnknownSlate { .. }
        | InvoiceError::AlreadyFinalized { .. }
        | InvoiceError::NotFinalizable { .. }
        | InvoiceError::MissingContext { .. }
        | InvoiceError::MalformedContext
        | InvoiceError::NotParked { .. } => true,
    }
}

/// Reply failures that delivering the same reply again would meet: the relay refused the post,
/// or the reply cannot be sealed for or sent to the address.
fn reply_is_permanent(hold: &Hold) -> bool {
    let Hold::Reply(error) = hold else {
        return false;
    };
    match error {
        TransportError::UnsupportedLocation { .. } | TransportError::UnknownDestination { .. } => {
            true
        }
        TransportError::Backend { source, .. } => {
            source
                .downcast_ref::<ClientError>()
                .is_some_and(|error| match error {
                    ClientError::Relay { kind } => *kind == RelayErrorKind::InvalidRequest,
                    ClientError::Destination(_)
                    | ClientError::Message(_)
                    | ClientError::Frame(_)
                    | ClientError::BinarySlate => true,
                    _ => false,
                })
        }
        _ => false,
    }
}

/// The key part of an Epicbox address text, which alone identifies a sender: the domain is not
/// signed. Text that is not an address is compared whole.
fn sender_key(address: &str, network: RelayNetwork) -> String {
    EpicboxAddress::parse(address, network)
        .map_or_else(|_| address.to_owned(), |address| address.key_text())
}

/// The relay client's reconnect backoff also paces the retries of a held message.
fn backoff(epicbox: &EpicboxTransport) -> Backoff {
    epicbox.settings().backoff
}

pub(crate) fn relay_network(network: Network) -> RelayNetwork {
    match network {
        Network::Mainnet => RelayNetwork::Mainnet,
        Network::Floonet => RelayNetwork::Floonet,
    }
}

fn transport_state(state: ConnectionState) -> TransportState {
    match state {
        ConnectionState::Connecting { .. } => TransportState::Connecting,
        ConnectionState::Subscribed => TransportState::Connected,
        ConnectionState::Stopped | ConnectionState::Drained => TransportState::Stopped,
        _ => TransportState::Disconnected,
    }
}

/// Inserts or updates the inbox entry of `msg_id`, keeping when it was first received.
fn put_inbox(
    repos: &mut dyn Repositories,
    msg_id: &str,
    status: InboxStatus,
    now: jiff::Timestamp,
) -> Result<(), StoreError> {
    let received_at = repos.inbox(msg_id)?.map_or(now, |entry| entry.received_at);
    repos.put_inbox(&InboxEntry {
        msg_id: msg_id.to_owned(),
        status,
        received_at,
        updated_at: now,
    })
}

/// Forgets relay message ids received longer ago than the relay keeps messages, since the relay
/// can no longer deliver them; `(slate_id, stage)` still makes a late copy harmless.
pub(crate) fn prune_inbox(
    repos: &mut dyn Repositories,
    now: jiff::Timestamp,
) -> Result<usize, StoreError> {
    match now.checked_sub(RELAY_RETENTION) {
        Ok(cutoff) => repos.prune_inbox(cutoff),
        Err(_) => Ok(0),
    }
}

/// When one drain or listen last pruned the relay inbox as a message settled.
#[derive(Default)]
struct PruneSchedule(Mutex<Option<jiff::Timestamp>>);

impl PruneSchedule {
    fn last(&self) -> Option<jiff::Timestamp> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, at: jiff::Timestamp) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(at);
    }
}

fn prune_due(last: Option<jiff::Timestamp>, now: jiff::Timestamp) -> bool {
    last.is_none_or(|last| {
        now.checked_sub(PRUNE_INTERVAL)
            .is_ok_and(|due_from| last <= due_from)
    })
}

/// Records how a message settled. When a prune is due after `last_pruned`, it runs in the same
/// write, so a listen held open for longer than the relay retention keeps the inbox bounded
/// too; returns when it ran.
fn record_settled(
    repos: &mut dyn Repositories,
    msg_id: &str,
    status: InboxStatus,
    now: jiff::Timestamp,
    last_pruned: Option<jiff::Timestamp>,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    let pruned = if prune_due(last_pruned, now) {
        prune_inbox(repos, now)?;
        Some(now)
    } else {
        None
    };
    put_inbox(repos, msg_id, status, now)?;
    Ok(pruned)
}

/// The status a message had before this delivery, recording it as received when it is new.
fn begin_inbox(
    repos: &mut dyn Repositories,
    msg_id: &str,
    now: jiff::Timestamp,
) -> Result<Option<InboxStatus>, StoreError> {
    let previous = repos.inbox(msg_id)?.map(|entry| entry.status);
    if previous.is_none() {
        put_inbox(repos, msg_id, InboxStatus::Received, now)?;
    }
    Ok(previous)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Attaches this wallet's Epicbox identity, the address key of the default account at index
    /// 0 as `epic-wallet` derives it, to `epicbox`, so that it can send and receive, and returns
    /// the wallet's address at the transport's relay. Attaching again replaces the identity.
    /// The key stays attached until [`EpicboxTransport::detach`]; hosts detach when they lock.
    ///
    /// Fails with [`InboxError::Wallet`] carrying [`WalletError::Locked`], and with
    /// [`InboxError::NetworkMismatch`] when the transport serves the other network.
    pub fn epicbox_attach(&self, epicbox: &EpicboxTransport) -> Result<EpicboxAddress, InboxError> {
        Ok(self.attached_client(epicbox)?.address().clone())
    }

    /// The payments address of `epicbox` and the signature of the push registration `request`
    /// made with its key. Fails as [`Wallet::epicbox_attach`] does.
    pub fn epicbox_push_signature(
        &self,
        epicbox: &EpicboxTransport,
        request: &lepic_epicbox::PushRequest,
    ) -> Result<(EpicboxAddress, lepic_crypto::EcdsaSignature), InboxError> {
        let identity = self.identity_at(epicbox, ADDRESS_INDEX)?;
        let signature = identity
            .sign_push(request)
            .map_err(|_| InboxError::Identity(ClientError::IdentityMismatch))?;
        Ok((identity.address().clone(), signature))
    }

    fn attached_client(&self, epicbox: &EpicboxTransport) -> Result<EpicboxClient, InboxError> {
        Ok(epicbox.attach(self.identity_at(epicbox, ADDRESS_INDEX)?))
    }

    /// The wallet's Epicbox identity at address index `index` of the default account, at the
    /// relay of `epicbox`.
    pub(crate) fn identity_at(
        &self,
        epicbox: &EpicboxTransport,
        index: u32,
    ) -> Result<Identity, InboxError> {
        let network = relay_network(self.config().network);
        if epicbox.network() != network {
            return Err(InboxError::NetworkMismatch);
        }
        let session = self.session()?;
        let parent = account::parent_key_id(ADDRESS_ACCOUNT)?;
        let secret = session
            .keychain
            .address_key(&parent, index)
            .map_err(WalletError::Keychain)?;
        let public = lepic_crypto::PublicKey::from_secret_key(&secret)
            .map_err(|_| InboxError::Identity(ClientError::IdentityMismatch))?;
        let endpoint = &epicbox.settings().endpoint;
        let address = EpicboxAddress::new(
            public,
            network,
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        Identity::new(secret, address).map_err(InboxError::Identity)
    }

    /// Connects to the relay once, handles every pending message and disconnects: the mode for
    /// background work on mobile. Attaches the wallet's identity first, as
    /// [`Wallet::epicbox_attach`] does. `epicbox` must be the transport registered in the
    /// wallet's registry, or a clone of it.
    ///
    /// Stops at the first message that fails for a transient reason, such as the node being
    /// unreachable, and leaves it and everything behind it on the relay for the next drain.
    /// A slate the node's tip says has expired is such a message until a refresh stores a
    /// confirmed height at or past its cutoff; the drain makes one refresh itself before it
    /// holds one. A reply or an expired slate is not held past the bound the module docs give.
    /// Fails with [`InboxError::Subscription`] when the relay connection fails; whatever was
    /// handled until then stays handled. Fails as [`Wallet::epicbox_attach`] does, and with
    /// [`InboxError::UnknownTransport`] when Epicbox is not registered.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn epicbox_drain(
        &self,
        epicbox: &EpicboxTransport,
    ) -> Result<InboxSummary, InboxError> {
        let client = self.inbox_client(epicbox).await?;
        let subscription = client.drain().map_err(InboxError::Subscription)?;
        self.run_inbox(&subscription, None, backoff(epicbox)).await
    }

    /// Holds a relay connection and handles messages as they arrive, until `handle` is stopped:
    /// the mode while the app is in the foreground. Reconnects on its own after the relay
    /// drops. Emits [`Event::Transport`] as the connection changes, and attaches the wallet's
    /// identity first, as [`Wallet::epicbox_attach`] does.
    ///
    /// A message that fails for a transient reason is tried again with backoff, and nothing
    /// behind it is delivered until it settles. A slate the node's tip says has expired settles
    /// once a refresh stores a confirmed height at or past its cutoff; the listen refreshes the
    /// tip itself before it holds one, at most once a minute. A reply or an expired slate is not
    /// held past the bound the module docs give. Fails as [`Wallet::epicbox_drain`] does
    /// before it connects.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn epicbox_listen(
        &self,
        epicbox: &EpicboxTransport,
        handle: &ListenHandle,
    ) -> Result<InboxSummary, InboxError> {
        let client = self.inbox_client(epicbox).await?;
        let subscription = client.listen().map_err(InboxError::Subscription)?;
        self.run_inbox(&subscription, Some(handle), backoff(epicbox))
            .await
    }

    /// The attached client for a drain or a listen, after pruning the relay inbox. Pruning runs
    /// before the subscription starts, so the host sees every connection state.
    async fn inbox_client(&self, epicbox: &EpicboxTransport) -> Result<EpicboxClient, InboxError> {
        self.check_epicbox_registered()?;
        let client = self.attached_client(epicbox)?;
        self.prune_relay_inbox().await;
        Ok(client)
    }

    pub(crate) fn check_epicbox_registered(&self) -> Result<(), InboxError> {
        if self.ports().transports.get(TRANSPORT_ID).is_none() {
            return Err(InboxError::UnknownTransport {
                transport: TRANSPORT_ID,
            });
        }
        Ok(())
    }

    pub(crate) async fn prune_relay_inbox(&self) {
        if let Err(error) = self.inbox_write(prune_inbox).await {
            warn!(error = %ErrorChain(&error), "epicbox inbox not pruned");
        }
    }

    /// Consumes the subscription and stops it, while its connection state goes out as events.
    pub(crate) async fn run_inbox(
        &self,
        subscription: &Subscription,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
    ) -> Result<InboxSummary, InboxError> {
        let consume = async {
            let consumed = self
                .consume(subscription, listen, backoff, &PruneSchedule::default())
                .await;
            // A failed connection explains a failed consume better than the consume does.
            subscription
                .stop()
                .await
                .map_err(InboxError::Subscription)?;
            consumed
        };
        let connection = match listen {
            Some(_) => Connection::Listener,
            None => Connection::PaymentsDrain,
        };
        let (result, ()) = tokio::join!(consume, self.forward_states(subscription, connection));
        result
    }

    async fn forward_states(&self, subscription: &Subscription, connection: Connection) {
        let mut states = subscription.state();
        let mut last = None;
        loop {
            let state = *states.borrow_and_update();
            let mapped = transport_state(state);
            if last != Some(mapped) {
                last = Some(mapped);
                self.emit(Event::Transport(TransportStatus {
                    transport: TRANSPORT_ID,
                    connection,
                    state: mapped,
                }));
                if mapped == TransportState::Disconnected {
                    let disconnect = subscription.last_disconnect();
                    self.emit(Event::TransportDisconnected(TransportDisconnect {
                        transport: TRANSPORT_ID,
                        connection,
                        reason: disconnect.as_ref().map_or_else(
                            || "connection ended".to_owned(),
                            |disconnect| disconnect.reason.clone(),
                        ),
                        retry_in: disconnect.map(|disconnect| disconnect.retry_in),
                    }));
                }
            }
            if state.has_ended() || states.changed().await.is_err() {
                return;
            }
        }
    }

    async fn consume(
        &self,
        subscription: &Subscription,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
        pruning: &PruneSchedule,
    ) -> Result<InboxSummary, InboxError> {
        let mut summary = InboxSummary::default();
        loop {
            let item = match subscription.next_rejection() {
                Some(rejection) => Item::Rejection(rejection),
                None => {
                    let next = match listen {
                        None => subscription.next_envelope().await,
                        Some(handle) => tokio::select! {
                            biased;
                            () = handle.stopped() => return Ok(summary),
                            next = subscription.next_envelope() => next,
                        },
                    };
                    match next.map_err(InboxError::Transport)? {
                        Some(envelope) => Item::envelope(subscription, envelope),
                        // A rejection may have arrived while no envelope did.
                        None if listen.is_none() => match subscription.next_rejection() {
                            Some(rejection) => Item::Rejection(rejection),
                            None => return Ok(summary),
                        },
                        None => {
                            let Some(handle) = listen else {
                                return Ok(summary);
                            };
                            tokio::select! {
                                biased;
                                () = handle.stopped() => return Ok(summary),
                                () = subscription.delivery_available() => {}
                            }
                            if subscription.state().borrow().has_ended() {
                                return Ok(summary);
                            }
                            continue;
                        }
                    }
                }
            };
            match self
                .settle(subscription, &item, listen, backoff, pruning)
                .await
            {
                Some(handled) => summary.count(handled),
                None => {
                    summary.held = summary.held.saturating_add(1);
                    return Ok(summary);
                }
            }
        }
    }

    /// Handles `item` until it settles, then acknowledges it. Returns `None` when it is held:
    /// at once in a drain, and in a listen once the listen is stopped while retrying.
    async fn settle(
        &self,
        subscription: &Subscription,
        item: &Item,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
        pruning: &PruneSchedule,
    ) -> Option<Handled> {
        let mut attempt: u32 = 0;
        let handled = loop {
            let try_number = attempt.saturating_add(1);
            let disposition = match listen {
                None => self.handle(subscription, item, pruning, try_number).await,
                Some(handle) => tokio::select! {
                    biased;
                    () = handle.abandoned() => return None,
                    disposition = self.handle(subscription, item, pruning, try_number) => disposition,
                },
            };
            match (disposition, listen) {
                (Disposition::Settled(handled), _) => break handled,
                (Disposition::Held, None) => return None,
                (Disposition::Held, Some(handle)) => {
                    attempt = attempt.saturating_add(1);
                    let delay = backoff.ceiling(attempt);
                    debug!(
                        attempt,
                        msg_id = item.msg_id().unwrap_or(""),
                        "epicbox message retry scheduled"
                    );
                    tokio::select! {
                        biased;
                        () = handle.stopped() => return None,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            }
        };
        self.acknowledge(subscription, item, handled, listen, backoff)
            .await;
        Some(handled)
    }

    /// Sends `Made` for a settled item. A listen tries again until the relay accepts it,
    /// because the relay delivers nothing else to the address while a message is
    /// unacknowledged. A drain whose acknowledgement fails has lost its connection; the relay
    /// delivers the message again later and its inbox entry settles it at once.
    async fn acknowledge(
        &self,
        subscription: &Subscription,
        item: &Item,
        handled: Handled,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
    ) {
        let msg_id = item.msg_id().unwrap_or("");
        let mut attempt: u32 = 0;
        while let Err(error) = subscription.acknowledge(item.ack_token()).await {
            warn!(msg_id, error = %ErrorChain(&error), "epicbox acknowledgement failed");
            let Some(handle) = listen else {
                return;
            };
            attempt = attempt.saturating_add(1);
            tokio::select! {
                biased;
                () = handle.abandoned() => return,
                () = tokio::time::sleep(backoff.ceiling(attempt)) => {}
            }
        }
        debug!(msg_id, "epicbox message settled");
        if handled.inbox_status() == InboxStatus::Rejected {
            return;
        }
        let Some(msg_id) = item.msg_id().map(str::to_owned) else {
            return;
        };
        let recorded = self
            .inbox_write(move |repos, now| {
                put_inbox(repos, &msg_id, InboxStatus::Acknowledged, now)
            })
            .await;
        if let Err(error) = recorded {
            warn!(error = %ErrorChain(&error), "epicbox acknowledgement not recorded");
        }
    }

    /// Handles `item` on its try number `attempt`, counted from 1.
    async fn handle(
        &self,
        subscription: &Subscription,
        item: &Item,
        pruning: &PruneSchedule,
        attempt: u32,
    ) -> Disposition {
        let msg_id = item.msg_id().map(str::to_owned);
        let outcome = match item {
            Item::Rejection(rejection) => {
                debug!(
                    msg_id = msg_id.as_deref().unwrap_or(""),
                    error = ?rejection.reason(),
                    "epicbox rejection recorded"
                );
                Ok(Handled::Rejected)
            }
            Item::Envelope(envelope, _) => {
                self.handle_envelope(subscription, msg_id.as_deref(), envelope, attempt)
                    .await
            }
        };
        let handled = match outcome {
            Ok(handled) => handled,
            Err(Hold::UnknownSlate) => {
                debug!(
                    msg_id = msg_id.as_deref().unwrap_or(""),
                    "epicbox message held for another install"
                );
                return Disposition::Held;
            }
            Err(hold) => {
                warn!(
                    msg_id = msg_id.as_deref().unwrap_or(""),
                    error = %ErrorChain(&hold),
                    "epicbox message held"
                );
                return Disposition::Held;
            }
        };
        if let Some(msg_id) = msg_id {
            let status = handled.inbox_status();
            let last_pruned = pruning.last();
            let recorded = self
                .inbox_write(move |repos, now| {
                    record_settled(repos, &msg_id, status, now, last_pruned)
                })
                .await;
            match recorded {
                Ok(Some(pruned_at)) => pruning.record(pruned_at),
                Ok(None) => {}
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "epicbox message held");
                    return Disposition::Held;
                }
            }
        }
        Disposition::Settled(handled)
    }

    async fn handle_envelope(
        &self,
        subscription: &Subscription,
        msg_id: Option<&str>,
        envelope: &Envelope,
        attempt: u32,
    ) -> Result<Handled, Hold> {
        if let Some(msg_id) = msg_id.map(str::to_owned) {
            let previous = self
                .inbox_write(move |repos, now| begin_inbox(repos, &msg_id, now))
                .await?;
            if matches!(
                previous,
                Some(InboxStatus::Processed | InboxStatus::Acknowledged | InboxStatus::Rejected)
            ) {
                debug!("epicbox message already settled");
                return Ok(Handled::Repeated);
            }
        }
        match self.apply(msg_id, envelope, attempt).await {
            Ok(handled) => Ok(handled),
            Err(Settlement::Hold(hold)) => Err(hold),
            Err(Settlement::Requeue(answer)) => {
                self.requeue(subscription, msg_id, envelope, answer).await
            }
            Err(Settlement::Refuse(refusal)) => {
                warn!(
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(&refusal),
                    "epicbox message rejected"
                );
                Ok(Handled::Rejected)
            }
        }
    }

    async fn apply(
        &self,
        msg_id: Option<&str>,
        envelope: &Envelope,
        attempt: u32,
    ) -> Result<Handled, Settlement> {
        let reply_to = envelope.reply_to().ok_or(Refusal::NoReplyAddress)?;
        let network = self.config().network;
        let transport = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .ok_or(WalletError::Config(
                crate::config::ConfigError::UnknownTransport {
                    transport: TRANSPORT_ID,
                },
            ))
            .map_err(Hold::from)?;
        match notice::classify(envelope.wire()) {
            Payload::Slate => {}
            Payload::Notice(notice) => return Ok(self.take_notice(notice, reply_to).await?),
            Payload::Unknown => {
                debug!("notice of an unknown version or type ignored");
                return Ok(Handled::Dropped);
            }
            Payload::Oversize | Payload::Malformed => {
                debug!("notice dropped as oversize or malformed");
                return Ok(Handled::Dropped);
            }
        }
        let codecs = legacy_codecs(network).map_err(Hold::Receive)?;
        let slate = transport
            .policy()
            .decode(&codecs, envelope.wire())
            .map_err(Refusal::Decode)?;
        match slate.stage() {
            Stage::S1 => {
                self.answer(msg_id, attempt, envelope, &slate, reply_to)
                    .await
            }
            Stage::S2 => self.complete(msg_id, envelope, &slate, reply_to).await,
            Stage::I1 => match self.bounced_invoice(&slate, reply_to).await? {
                Some(bounced) => {
                    self.record_bounce(bounced).await?;
                    Ok(Handled::Bounced)
                }
                None => Err(Refusal::UnsupportedStage { stage: Stage::I1 }.into()),
            },
            Stage::I2 => {
                self.complete_invoice(msg_id, attempt, envelope, &slate, reply_to)
                    .await
            }
            stage => Err(Refusal::UnsupportedStage { stage }.into()),
        }
    }

    /// Finalizes an I2 and posts it, as [`Self::complete`] does for an S2. Only an I2 that
    /// answers an invoice this wallet issued and still waits for payment is finalized.
    ///
    /// A payment that carries the LEPIC marker proves that its payer runs LEPIC. Once it is
    /// pushed, that payer is sent a `posted` notice.
    async fn complete_invoice(
        &self,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        payment: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        let marked = carries_lepic_marker(envelope.wire());
        let session = self.session().map_err(Hold::from)?;
        let slate_id = Uuid::from_bytes(*payment.id().as_bytes());
        let finalized_before = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.slate(slate_id, SlateStage::Invoice3))?
                    .is_some())
            })
            .await
            .map_err(Hold::from)?;
        match self
            .finalize_invoice(TRANSPORT_ID, envelope.wire(), POST_PROPAGATION)
            .await
        {
            Ok(finalized) => {
                if marked {
                    self.record_paying_peer(finalized.tx_id, reply_to).await;
                }
                if let Some(kernel) = finalized.slate.kernel() {
                    self.notify_posted(finalized.tx_id, payment.id(), kernel.excess)
                        .await;
                }
                Ok(self.invoice_finalized(finalized.tx_id, payment, finalized_before))
            }
            Err(InvoiceError::NotPosted { tx_id, source }) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&source), "finalized transaction not posted");
                if marked {
                    self.record_paying_peer(tx_id, reply_to).await;
                }
                Ok(self.invoice_finalized(tx_id, payment, finalized_before))
            }
            Err(error @ InvoiceError::Expired { cutoff, .. }) => {
                if self.confirmed_at(cutoff).await? {
                    Err(Refusal::Invoice(error).into())
                } else {
                    Err(Hold::Invoice(error).into())
                }
            }
            Err(error @ InvoiceError::UnknownSlate { .. }) => {
                self.unknown_answer(
                    msg_id,
                    payment,
                    Stage::I2,
                    reply_to,
                    Refusal::Invoice(error),
                )
                .await
            }
            // The payer may not have heard the withdrawal: the notice sent at the cancel fails
            // while this wallet is offline. The payment is kept for another try while the
            // answer cannot be delivered, up to the hold bound; after that the payer's next
            // try of the same payment brings the answer again.
            Err(
                error @ InvoiceError::NotFinalizable {
                    tx_id,
                    state: TxState::Cancelled,
                },
            ) if marked => match self.answer_withdrawn_payment(tx_id, payment).await {
                Ok(()) => Err(Refusal::Invoice(error).into()),
                Err(hold)
                    if reply_is_permanent(&hold)
                        || self.hold_exhausted(msg_id, attempt).await? =>
                {
                    warn!(tx_id = %tx_id, error = %ErrorChain(&hold), "withdrawn notice undelivered");
                    Err(Refusal::Invoice(error).into())
                }
                Err(_) => Err(Hold::Invoice(error).into()),
            },
            Err(error) if invoice_finalize_is_permanent(&error) => {
                Err(Refusal::Invoice(error).into())
            }
            Err(error) => Err(Hold::Invoice(error).into()),
        }
    }

    /// Tells the host that an answer arrived for a slate this store does not know: it may
    /// belong to another install of the same wallet (ADR 0016).
    fn unknown_slate(&self, slate_id: SlateId, stage: Stage, sender: &Destination) {
        self.emit(Event::UnknownSlate(UnknownSlate {
            slate_id,
            stage,
            sender: sender.as_str().to_owned(),
        }));
    }

    /// Settles the message `msg_id` of `answer`, an S2 or I2 for a slate this store does not
    /// know, as `twin_answer` decides: held, requeued for another install, or refused
    /// with `refusal`. [`Event::UnknownSlate`] is raised the first time the answer is seen,
    /// and when it is refused without being held. An answer is requeued only while every input
    /// it spends is still unspent on chain: once one is spent, the sender's transaction was
    /// completed elsewhere, or never can be, and the answer is refused. A node that cannot be
    /// asked does not stop the requeue.
    async fn unknown_answer(
        &self,
        msg_id: Option<&str>,
        answer: &Slate,
        stage: Stage,
        sender: &Destination,
        refusal: Refusal,
    ) -> Result<Handled, Settlement> {
        let slate_id = answer.id();
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        let arrived = self.first_arrival(msg_id).await?;
        let step = self
            .inbox_write(move |repos, now| twin_answer::step(repos, uuid, stage, arrived, now))
            .await
            .map_err(Hold::from)?;
        let first = match step {
            Step::Hold { first } | Step::Requeue { first } => first,
            Step::Refuse(_) => false,
        };
        if first {
            info!(
                slate_id = %slate_id,
                stage = stage.as_str(),
                msg_id = msg_id.unwrap_or(""),
                "answer for an unknown slate held for another install"
            );
            self.unknown_slate(slate_id, stage, sender);
        }
        match step {
            Step::Hold { .. } => Err(Hold::UnknownSlate.into()),
            Step::Requeue { .. } => {
                if self.inputs_spent(answer).await {
                    info!(
                        slate_id = %slate_id,
                        stage = stage.as_str(),
                        msg_id = msg_id.unwrap_or(""),
                        "answer for an unknown slate refused as settled elsewhere"
                    );
                    self.inbox_write(move |repos, _| twin_answer::forget(repos, uuid, stage))
                        .await
                        .map_err(Hold::from)?;
                    return Err(refusal.into());
                }
                Err(Settlement::Requeue(Requeue {
                    slate_id,
                    stage,
                    refusal,
                }))
            }
            Step::Refuse(Refused::Crowded) => {
                info!(
                    slate_id = %slate_id,
                    stage = stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    "answer for an unknown slate refused"
                );
                self.unknown_slate(slate_id, stage, sender);
                Err(refusal.into())
            }
            Step::Refuse(Refused::WindowPassed) => {
                info!(
                    slate_id = %slate_id,
                    stage = stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    "answer for an unknown slate refused after its requeue window"
                );
                Err(refusal.into())
            }
        }
    }

    /// Whether an input `answer` spends is not unspent on chain, as two answers of the node
    /// agree. `false` when the node cannot be asked.
    async fn inputs_spent(&self, answer: &Slate) -> bool {
        let inputs: Vec<_> = answer
            .inputs()
            .iter()
            .map(|input| input.commitment)
            .collect();
        if inputs.is_empty() {
            return false;
        }
        let node = &self.ports().node;
        let mut missing = inputs;
        for _ in 0..2 {
            match node.get_outputs(&missing).await {
                Ok(found) => {
                    missing.retain(|commitment| {
                        !found
                            .iter()
                            .any(|location| location.commitment == *commitment)
                    });
                }
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "inputs of an unknown slate not checked");
                    return false;
                }
            }
            if missing.is_empty() {
                return false;
            }
        }
        true
    }

    /// Posts the message of `answer` back to the subscription's address for another install,
    /// then lets it be acknowledged. A post that fails holds the message, until it first
    /// arrived [`HOLD_PATIENCE`] ago: then it is refused for good, as before this rule.
    async fn requeue(
        &self,
        subscription: &Subscription,
        msg_id: Option<&str>,
        envelope: &Envelope,
        answer: Requeue,
    ) -> Result<Handled, Hold> {
        let Requeue {
            slate_id,
            stage,
            refusal,
        } = answer;
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        match subscription.requeue(envelope.ack_token()).await {
            Ok(()) => {
                let count = self
                    .inbox_write(move |repos, _| twin_answer::record_requeued(repos, uuid, stage))
                    .await;
                let count = match count {
                    Ok(count) => count,
                    Err(error) => {
                        warn!(error = %ErrorChain(&error), "requeue not recorded");
                        0
                    }
                };
                info!(
                    slate_id = %slate_id,
                    stage = stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    count,
                    "answer for an unknown slate requeued for another install"
                );
                Ok(Handled::Requeued)
            }
            Err(error) => {
                let arrived = self.first_arrival(msg_id).await?;
                let now = self.ports().clock.now();
                if !twin_answer::waited(arrived, now, HOLD_PATIENCE) {
                    return Err(Hold::Requeue(error));
                }
                warn!(
                    slate_id = %slate_id,
                    stage = stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(&error),
                    "answer for an unknown slate not requeued"
                );
                warn!(
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(&refusal),
                    "epicbox message rejected"
                );
                Ok(Handled::Rejected)
            }
        }
    }

    /// When the message `msg_id` first arrived, from its relay inbox entry. `None` for a
    /// message without a relay id.
    async fn first_arrival(&self, msg_id: Option<&str>) -> Result<Option<jiff::Timestamp>, Hold> {
        let Some(msg_id) = msg_id.map(str::to_owned) else {
            return Ok(None);
        };
        let session = self.session()?;
        Ok(self
            .blocking(move |_, _| Ok(session.store.read(|repos| repos.inbox(&msg_id))?))
            .await?
            .map(|entry| entry.received_at))
    }

    fn invoice_finalized(&self, tx_id: TxId, payment: &Slate, finalized_before: bool) -> Handled {
        if finalized_before {
            return Handled::Repeated;
        }
        self.emit(Event::InvoiceFinalized(FinalizedInvoice {
            tx_id,
            slate_id: payment.id(),
        }));
        Handled::Finalized
    }

    /// Receives an S1 and replies with S2, or replies again with the S2 stored for it. A
    /// different S1 under a slate id received before is refused, and so is a new one over the
    /// open receipt caps. A reply that cannot be delivered is given up at the hold bound.
    async fn answer(
        &self,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        proposal: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        self.make_room_for(msg_id, attempt, proposal, reply_to)
            .await?;
        let marked = carries_lepic_marker(envelope.wire());
        match self
            .receive_from(
                TRANSPORT_ID,
                envelope.wire(),
                ReceiveRequest::default(),
                Some(reply_to.clone()),
            )
            .await
        {
            Ok(received) => {
                if marked {
                    self.record_sending_peer(reply_to).await;
                }
                match self.reply(reply_to, &received.reply).await {
                    Ok(()) => {}
                    Err(hold)
                        if reply_is_permanent(&hold)
                            || self.hold_exhausted(msg_id, attempt).await? =>
                    {
                        warn!(tx_id = %received.tx_id, error = %ErrorChain(&hold), "slate reply undelivered");
                        self.emit(Event::ReplyUndelivered(UndeliveredReply {
                            tx_id: received.tx_id,
                            slate_id: received.slate.id(),
                        }));
                    }
                    Err(hold) => return Err(hold.into()),
                }
                Ok(if received.repeated {
                    Handled::Repeated
                } else {
                    Handled::Received
                })
            }
            Err(ReceiveError::AlreadyReceived { .. }) => Err(Refusal::SlateIdReused.into()),
            Err(error @ ReceiveError::Expired { cutoff, .. }) => {
                if self.expired_for_good(msg_id, attempt, cutoff).await? {
                    Err(Refusal::Receive(error).into())
                } else {
                    Err(Hold::Receive(error).into())
                }
            }
            Err(error) if receive_is_permanent(&error) => Err(Refusal::Receive(error).into()),
            Err(error) => Err(Hold::Receive(error).into()),
        }
    }

    async fn reply(&self, to: &Destination, wire: &WireSlate) -> Result<(), Hold> {
        let outbound = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .and_then(|transport| transport.outbound())
            .ok_or(Hold::NoOutbound {
                transport: TRANSPORT_ID,
            })?;
        outbound.deliver(to, wire).await.map_err(Hold::Reply)?;
        info!(stage = Stage::S2.as_str(), "slate sent");
        Ok(())
    }

    /// Finalizes an S2 and posts it. A transaction that was finalized but not posted is
    /// settled: it waits in state `finalized` for [`Wallet::post`].
    /// An S2 finalized before, which arrives again when the receiver resent it, counts as
    /// repeated; finalizing it again posts only if the first post did not succeed.
    async fn complete(
        &self,
        msg_id: Option<&str>,
        envelope: &Envelope,
        reply: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        let marked = carries_lepic_marker(envelope.wire());
        let session = self.session().map_err(Hold::from)?;
        let slate_id = Uuid::from_bytes(*reply.id().as_bytes());
        let finalized_before = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.slate(slate_id, SlateStage::Standard3))?
                    .is_some())
            })
            .await
            .map_err(Hold::from)?;
        let handled = if finalized_before {
            Handled::Repeated
        } else {
            Handled::Finalized
        };
        match self
            .finalize(TRANSPORT_ID, envelope.wire(), POST_PROPAGATION)
            .await
        {
            Ok(finalized) => {
                if marked {
                    self.record_receiving_peer(finalized.tx_id, reply_to).await;
                }
                // Only the call that pushed the transaction tells the receiver; an S2 that
                // arrives again for a posted transaction pushes nothing.
                if finalized.pushed {
                    self.notify_pushed(finalized.tx_id, &finalized.slate).await;
                }
                Ok(handled)
            }
            Err(FinalizeError::NotPosted { tx_id, source }) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&source), "finalized transaction not posted");
                if marked {
                    self.record_receiving_peer(tx_id, reply_to).await;
                }
                Ok(handled)
            }
            // Not reachable over Epicbox today: new Epicbox slates go out in the V2 shape,
            // which carries no TTL, so no S2 with a cutoff comes back. It becomes reachable
            // once an Epicbox codec that carries the TTL is used for new slates.
            Err(error @ FinalizeError::Expired { cutoff, .. }) => {
                if self.confirmed_at(cutoff).await? {
                    Err(Refusal::Finalize(error).into())
                } else {
                    Err(Hold::Finalize(error).into())
                }
            }
            Err(error @ FinalizeError::UnknownSlate { .. }) => {
                self.unknown_answer(msg_id, reply, Stage::S2, reply_to, Refusal::Finalize(error))
                    .await
            }
            Err(error) if finalize_is_permanent(&error) => Err(Refusal::Finalize(error).into()),
            Err(error) => Err(Hold::Finalize(error).into()),
        }
    }

    /// Whether a slate the node's tip says expired at `cutoff` is refused for good: a refresh
    /// stored a confirmed height at or past it, before or in one refresh made now, or the
    /// message reached the hold bound. A failed refresh leaves it held.
    async fn expired_for_good(
        &self,
        msg_id: Option<&str>,
        attempt: u32,
        cutoff: lepic_primitives::amount::Height,
    ) -> Result<bool, Hold> {
        if self.confirmed_at(cutoff).await? {
            return Ok(true);
        }
        if self.tip_refresh_due().await? {
            match self.refresh().await {
                Ok(_) => {
                    if self.confirmed_at(cutoff).await? {
                        return Ok(true);
                    }
                }
                Err(error) => warn!(error = %ErrorChain(&error), "tip not refreshed"),
            }
        }
        self.hold_exhausted(msg_id, attempt).await
    }

    /// Records a tip refresh for the inbox now when none was made in the last
    /// [`TIP_REFRESH_INTERVAL`], and says whether it is due.
    pub(crate) async fn tip_refresh_due(&self) -> Result<bool, WalletError> {
        self.inbox_write(|repos, now| {
            let last = repos
                .setting(TIP_REFRESHED_SETTING)?
                .and_then(|text| text.parse::<jiff::Timestamp>().ok());
            let due = last.is_none_or(|last| {
                now.checked_sub(TIP_REFRESH_INTERVAL)
                    .is_ok_and(|due_from| last <= due_from || last > now)
            });
            if due {
                repos.put_setting(TIP_REFRESHED_SETTING, &now.to_string())?;
            }
            Ok(due)
        })
        .await
    }

    /// Whether the message `msg_id`, on its try `attempt`, reached the hold bound: this is try
    /// [`MAX_HOLD_ATTEMPTS`], or it first arrived [`HOLD_PATIENCE`] or longer ago, or more than
    /// [`CLOCK_STEP_TOLERANCE`] after the wallet clock's now, which only a clock set back
    /// explains.
    async fn hold_exhausted(&self, msg_id: Option<&str>, attempt: u32) -> Result<bool, Hold> {
        if attempt >= MAX_HOLD_ATTEMPTS {
            return Ok(true);
        }
        // A relay gives every message a relay id on a subscription of protocol version 2.0.0 or
        // later, and marks one it sends without an id as handled as it sends it: that one is
        // never delivered again, so holding it gains nothing.
        let Some(msg_id) = msg_id.map(str::to_owned) else {
            return Ok(true);
        };
        let session = self.session()?;
        let now = self.ports().clock.now();
        let first_seen = self
            .blocking(move |_, _| Ok(session.store.read(|repos| repos.inbox(&msg_id))?))
            .await?
            .map(|entry| entry.received_at);
        let stepped_back_from = now.checked_add(CLOCK_STEP_TOLERANCE).ok();
        Ok(match (first_seen, now.checked_sub(HOLD_PATIENCE)) {
            (Some(first_seen), _) if stepped_back_from.is_some_and(|late| first_seen > late) => {
                true
            }
            (Some(first_seen), Ok(held_from)) => first_seen <= held_from,
            _ => false,
        })
    }

    /// Checks the open receipt caps before a new S1 from `reply_to`, the message `msg_id` on its
    /// try `attempt`, is received. A slate id received before passes, so its stored S2 is sent
    /// again. Over the sender's cap the S1 is refused; at the total cap room is made as
    /// [`MAX_OPEN_RECEIPTS`] says.
    async fn make_room_for(
        &self,
        msg_id: Option<&str>,
        attempt: u32,
        proposal: &Slate,
        reply_to: &Destination,
    ) -> Result<(), Settlement> {
        let slate_id = Uuid::from_bytes(*proposal.id().as_bytes());
        let network = relay_network(self.config().network);
        let key = sender_key(reply_to.as_str(), network);
        let key_of = |address: &str| sender_key(address, network);
        let sender = Sender {
            key: &key,
            key_of: &key_of,
        };
        match self.make_room(TRANSPORT_ID, slate_id, Some(sender)).await {
            Ok(()) => Ok(()),
            Err(NoRoom::FromSender) => Err(Refusal::OpenReceiptsFromSender.into()),
            Err(NoRoom::Full) => Err(Refusal::OpenReceipts.into()),
            Err(NoRoom::Unchecked(error)) => {
                if self.hold_exhausted(msg_id, attempt).await? {
                    Err(Refusal::OpenReceiptsUnchecked(error).into())
                } else {
                    Err(Hold::Wallet(error).into())
                }
            }
            Err(NoRoom::Wallet(error)) => Err(Hold::Wallet(error).into()),
        }
    }

    /// Whether a refresh stored a confirmed height at or past `cutoff`. Only then is a slate
    /// that expired by the node's tip refused for good; until then the tip alone may be wrong,
    /// so the message stays on the relay.
    pub(crate) async fn confirmed_at(
        &self,
        cutoff: lepic_primitives::amount::Height,
    ) -> Result<bool, Hold> {
        let session = self.session()?;
        let confirmed = self
            .blocking(move |_, _| Ok(session.store.read(|repos| last_confirmed(repos))?))
            .await?;
        Ok(confirmed.is_some_and(|height| height >= cutoff))
    }

    pub(crate) async fn inbox_write<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut dyn Repositories, jiff::Timestamp) -> Result<T, StoreError>
        + Send
        + 'static,
    ) -> Result<T, WalletError> {
        let session = self.session()?;
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| Ok(work(repos, now)?))
        })
        .await
    }
}

/// How a message that was not handled ends: refused for good, held for redelivery, or
/// posted back to the address for another install before it is acknowledged.
pub(crate) enum Settlement {
    Refuse(Refusal),
    Hold(Hold),
    Requeue(Requeue),
}

/// An answer for a slate this store does not know, to requeue.
pub(crate) struct Requeue {
    slate_id: SlateId,
    stage: Stage,
    /// Why it is refused should the requeue fail for good.
    refusal: Refusal,
}

impl From<Refusal> for Settlement {
    fn from(refusal: Refusal) -> Self {
        Self::Refuse(refusal)
    }
}

impl From<Hold> for Settlement {
    fn from(hold: Hold) -> Self {
        Self::Hold(hold)
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn at(second: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(second).unwrap()
    }

    #[test]
    fn settling_prunes_at_most_once_per_interval() {
        let interval = i64::try_from(PRUNE_INTERVAL.as_secs()).unwrap();
        let last = at(1_000_000);
        assert!(prune_due(None, last));
        assert!(!prune_due(Some(last), last));
        assert!(!prune_due(Some(last), at(1_000_000 + interval - 1)));
        assert!(prune_due(Some(last), at(1_000_000 + interval)));
    }
}
