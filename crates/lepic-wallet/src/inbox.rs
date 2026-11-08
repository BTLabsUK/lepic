// SPDX-License-Identifier: Apache-2.0
//! The inbox: what the engine does with each message a method's relay or mailbox hands out
//! (ADR 0004). The method's loop receives the messages, acknowledges them and keeps the
//! connection; the engine decides what each one does through the entries here.
//!
//! A message is decoded with the method's policy and routed by stage: an S1 is received and
//! answered with S2 through the same method, an S2 is finalized and posted. A slate the
//! node's tip says has expired is held, not rejected, until a refresh confirms a height at or
//! past its cutoff. Its message id, when the method gives one, is tracked in the store's relay
//! inbox. A message is acknowledged once its effect is stored, or once it was rejected for good
//! and the rejection is recorded, under its message id when it has one; a transient failure
//! leaves it unacknowledged, so the method delivers it again.
//!
//! A held message holds back everything behind it, because a relay delivers one message at a
//! time, and the relay discards everything queued for the address when one message stays
//! unacknowledged for long. So holds are bounded by [`MAX_HOLD_ATTEMPTS`] and [`HOLD_PATIENCE`]:
//! a reply the method refuses, or one still undelivered at the bound, leaves the payment
//! received and settles the message with [`Event::ReplyUndelivered`]; a slate still expired by
//! the tip alone after one refresh and at the bound is refused.
//!
//! An S2 or I2 for a slate this store does not know may belong to another install on the same
//! recovery phrase, which shares the payments address. It is held for [`TWIN_HOLD`] and then
//! requeued for that install, posted back to the address as its sender signed it, rather than
//! refused at once; at most [`MAX_TWIN_ANSWERS`] at a time, for [`TWIN_REQUEUE_WINDOW`], and
//! only while the inputs it spends are unspent.
//!
//! Payments nobody asked for are bounded too: at most
//! [`crate::config::WalletPolicy::max_open_receipts_per_sender`] open receipts per sender key and
//! [`crate::config::WalletPolicy::max_open_receipts`] in all (see their docs).
//!
//! Every message is idempotent on its message id and on `(slate_id, stage)`: a redelivered S1
//! is answered with the S2 stored the first time, never a new one, and announced as
//! [`Event::AnsweredAgain`]; finalizing an S2 again changes nothing that is stored. A message
//! whose id settled before is acknowledged without an answer or an event.

mod listing;

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use lepic_crypto::SecretKey;
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::Slate;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, InboxEntry, InboxStatus, Repositories, SlateStage, StoreError, TxId, TxState,
    WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::method::Method;
use lepic_transport::transport::{Destination, Envelope, TransportId};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::account;
use crate::error::WalletError;
use crate::event::{Event, FinalizedInvoice, SlateId, UndeliveredReply, UnknownSlate};
use crate::finalize::{Answerer, FinalizeError};
use crate::invoice::InvoiceError;
use crate::namespace::{self, Listing};
use crate::notice::{self, Payload};
use crate::ports::{SecretVault, StoreOpener};
use crate::receipt_cap::{NoRoom, Sender};
use crate::receive::{ReceiveError, ReceiveRequest};
use crate::refresh::last_confirmed;
use crate::twin_answer::{self, Refused, Step};
use crate::wallet::Wallet;

pub use crate::twin_answer::{MAX_TWIN_ANSWERS, TWIN_HOLD, TWIN_REQUEUE_WINDOW};

/// A failure a method builds for [`InboxError`] and [`Hold`] from its own error type.
pub type MethodFailure = Box<dyn StdError + Send + Sync + 'static>;

/// `epic-wallet` always uses the address key at index 0 of the account.
const ADDRESS_INDEX: u32 = 0;

/// The account whose address key is the wallet's address identity.
const ADDRESS_ACCOUNT: AccountIndex = AccountIndex(0);

/// `epic-wallet`'s Epicbox listener posts finalized transactions without fluff.
const POST_PROPAGATION: Propagation = Propagation::Stem;

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

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InboxError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("epicbox transport serves another network than the wallet")]
    NetworkMismatch,
    /// The method refused the wallet's identity.
    #[error("epicbox identity rejected")]
    Identity(#[source] MethodFailure),
    /// The relay connection failed. Unacknowledged messages stay on the relay; try again later.
    #[error("epicbox subscription failed")]
    Subscription(#[source] MethodFailure),
    #[error("epicbox subscription failed")]
    Transport(#[source] TransportError),
    /// The method could not read an address.
    #[error("epicbox address rejected")]
    Address(#[source] MethodFailure),
    #[error("invoice expiry must be positive and at most two days")]
    InvoiceExpiry,
    /// Only one of the host app's own feature bits can be reported.
    #[error("not a host feature bit")]
    NotHostFeature,
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
    /// Notices for a slate this wallet does not hold yet, kept to apply when it arrives
    /// (ADR 0049).
    pub buffered: u32,
    /// Answers for a slate this store does not know, posted back to the address for another
    /// install of the wallet and acknowledged.
    pub requeued: u32,
}

impl InboxSummary {
    /// Counts one message that settled as `handled`.
    pub fn count(&mut self, handled: Handled) {
        let counter = match handled {
            Handled::Received => &mut self.received,
            Handled::Finalized => &mut self.finalized,
            Handled::Repeated => &mut self.repeated,
            Handled::Rejected => &mut self.rejected,
            Handled::Bounced => &mut self.bounced,
            Handled::Dropped => &mut self.dropped,
            Handled::Notice => &mut self.notices,
            Handled::Buffered => &mut self.buffered,
            Handled::Requeued => &mut self.requeued,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Ends a method's listen. Clones stop the same listen.
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
    pub async fn stopped(&self) {
        self.wait_for(|ending| ending != Ending::Running).await;
    }

    /// Resolves once the listen should end even with a message in hand.
    pub async fn abandoned(&self) {
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

/// What became of one message: the result of [`Wallet::arrived`] that a method's loop counts
/// in its [`InboxSummary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    /// An S1 received and answered with S2.
    Received,
    /// An S2 or I2 finalized for the first time.
    Finalized,
    /// A message handled before, settled again.
    Repeated,
    /// A message rejected for good.
    Rejected,
    /// An invoice this wallet issued, sent back unchanged.
    Bounced,
    /// A message acknowledged and forgotten.
    Dropped,
    /// A notice or pairing request taken.
    Notice,
    /// A notice kept for a slate this wallet does not hold yet.
    Buffered,
    /// An answer for an unknown slate posted back for another install.
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
            | Self::Buffered
            | Self::Requeued => InboxStatus::Processed,
        }
    }
}

/// Why a message is rejected for good, for the log.
#[derive(Debug, Error)]
pub(crate) enum Refusal {
    #[error("message carries no reply address")]
    NoReplyAddress,
    #[error("slate could not be decoded")]
    Decode(#[source] lepic_slate::error::DecodeError),
    #[error("slate at stage {stage} is not handled over the method")]
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
    #[error("this wallet refuses payments nobody asked for")]
    Unsolicited,
}

/// A failure that leaves the message for the relay to deliver again.
#[derive(Debug, Error)]
pub enum Hold {
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
    /// The method could not post an answer back for another install.
    #[error("answer for an unknown slate not requeued")]
    Requeue(#[source] MethodFailure),
    #[error("pairing request not stored")]
    PairRequest,
}

impl From<StoreError> for Hold {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
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
        | ReceiveError::Encode(_)
        | ReceiveError::Refused => true,
    }
}

/// Failures of finalizing an S2 that the same message would meet again. A slate that was
/// finalized and stored but not posted is not a failure of the message; the caller handles it.
pub fn finalize_is_permanent(error: &FinalizeError) -> bool {
    match error {
        FinalizeError::Wallet(_)
        | FinalizeError::UnknownTransport { .. }
        | FinalizeError::Node(_)
        | FinalizeError::Codecs(_)
        | FinalizeError::NotPosted { .. } => false,
        // The send was cancelled: the same answer finds nothing to finalize.
        FinalizeError::InputsSpentElsewhere { .. }
        | FinalizeError::InputsSpentByOwnTransaction { .. }
        | FinalizeError::PeerInputsSpent { .. }
        | FinalizeError::Decode(_)
        | FinalizeError::WrongStage { .. }
        | FinalizeError::UnknownSlate { .. }
        | FinalizeError::AlreadyFinalized { .. }
        | FinalizeError::NotFinalizable { .. }
        | FinalizeError::Expired { .. }
        | FinalizeError::Mismatch { .. }
        | FinalizeError::MissingPaymentProof
        | FinalizeError::ForeignSenderAddress
        | FinalizeError::UnexpectedAnswerer { .. }
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
pub fn invoice_finalize_is_permanent(error: &InvoiceError) -> bool {
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
        InvoiceError::InputsSpentElsewhere { .. }
        | InvoiceError::InputsSpentByOwnTransaction { .. }
        | InvoiceError::PeerInputsSpent { .. }
        | InvoiceError::Decode(_)
        | InvoiceError::WrongStage { .. }
        | InvoiceError::AmountMismatch { .. }
        | InvoiceError::AlreadyPaid { .. }
        | InvoiceError::Expired { .. }
        | InvoiceError::LockedUntil { .. }
        | InvoiceError::AheadOfTip { .. }
        | InvoiceError::TtlTooFarAhead { .. }
        | InvoiceError::TtlTooFarBehind { .. }
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

/// Reply failures that delivering the same reply again would meet: the method refused the
/// post, or the reply cannot be sealed for or sent to the address. A [`TransportError::Backend`]
/// failure is the method's to judge.
fn reply_is_permanent(method: &dyn Method, hold: &Hold) -> bool {
    let Hold::Reply(error) = hold else {
        return false;
    };
    match error {
        TransportError::UnsupportedLocation { .. }
        | TransportError::UnknownDestination { .. }
        | TransportError::InvalidDestination { .. } => true,
        TransportError::Backend { .. } => method.delivery_is_permanent(error),
        _ => false,
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

/// Forgets message ids received longer ago than `retention`, how long the method's relay keeps
/// messages, since the relay can no longer deliver them; `(slate_id, stage)` still makes a late
/// copy harmless.
pub(crate) fn prune_inbox(
    repos: &mut dyn Repositories,
    now: jiff::Timestamp,
    retention: Duration,
) -> Result<usize, StoreError> {
    match now.checked_sub(retention) {
        Ok(cutoff) => repos.prune_inbox(cutoff),
        Err(_) => Ok(0),
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
    retention: Duration,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    let pruned = if prune_due(last_pruned, now) {
        prune_inbox(repos, now, retention)?;
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
    /// The address key of the default account at index 0, as `epic-wallet` derives it: the
    /// secret of the wallet's payments address. Its one caller is the Epicbox method in
    /// `lepic-methods`, which connects to the relay as that address; no other caller should
    /// read it.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn address_secret(&self) -> Result<SecretKey, WalletError> {
        let session = self.session()?;
        let parent = account::parent_key_id(ADDRESS_ACCOUNT)?;
        Ok(session.keychain.address_key(&parent, ADDRESS_INDEX)?)
    }

    /// The secret key of `listing`'s address. Its callers are the Epicbox method in
    /// `lepic-methods`: it connects to the relay as the listing's address, and it signs a
    /// service listing with it; no other caller should read it.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn listing_secret(&self, listing: &Listing) -> Result<SecretKey, WalletError> {
        namespace::listing_key(&self.session()?.seed, listing)
    }

    /// Forgets the ids of messages received longer ago than `retention`, how long the method's
    /// relay keeps messages. A method's loop calls it before its subscription starts; a failure
    /// is logged and changes nothing else.
    pub async fn prune_arrivals(&self, retention: Duration) {
        if let Err(error) = self
            .inbox_write(move |repos, now| prune_inbox(repos, now, retention))
            .await
        {
            warn!(error = %ErrorChain(&error), "epicbox inbox not pruned");
        }
    }

    /// Takes one message a method received, on its try `arrival.attempt`, counted from 1: the
    /// message id is recorded before the slate is applied, and a message whose id settled
    /// before is [`Handled::Repeated`] at once. A message refused for good is logged and
    /// [`Handled::Rejected`]. An answer goes back through `method`'s outbound.
    ///
    /// Fails with [`Outcome::Hold`] when the message is to stay for the method to deliver
    /// again, and with [`Outcome::Requeue`] when it is to go back to the address for another
    /// install; the loop then calls [`Wallet::requeued`] or [`Wallet::requeue_failed`].
    pub async fn arrived(
        &self,
        method: &Arc<dyn Method>,
        arrival: Arrival<'_>,
    ) -> Result<Handled, Outcome> {
        let Arrival {
            msg_id,
            envelope,
            attempt,
            listing,
        } = arrival;
        if let Some(msg_id) = msg_id.map(str::to_owned) {
            let previous = self
                .inbox_write(move |repos, now| begin_inbox(repos, &msg_id, now))
                .await
                .map_err(|error| Outcome::Hold(error.into()))?;
            if matches!(
                previous,
                Some(InboxStatus::Processed | InboxStatus::Acknowledged | InboxStatus::Rejected)
            ) {
                debug!("epicbox message already settled");
                return Ok(Handled::Repeated);
            }
        }
        let applied = match listing {
            None => self.apply(method, msg_id, envelope, attempt).await,
            Some(listing) => {
                self.apply_at_listing(method, msg_id, envelope, attempt, listing)
                    .await
            }
        };
        match applied {
            Ok(handled) => Ok(handled),
            Err(Settlement::Hold(hold)) => Err(Outcome::Hold(hold)),
            Err(Settlement::Requeue(answer)) => Err(Outcome::Requeue(answer)),
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

    /// Records that `requeue` was posted back to the address for another install, and returns
    /// how often its answer was. A failed write is logged and counts 0.
    pub async fn requeued(&self, requeue: &Requeue) -> u32 {
        let uuid = Uuid::from_bytes(*requeue.slate_id.as_bytes());
        let stage = requeue.stage;
        let count = self
            .inbox_write(move |repos, _| twin_answer::record_requeued(repos, uuid, stage))
            .await;
        match count {
            Ok(count) => count,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "requeue not recorded");
                0
            }
        }
    }

    /// Whether the message `msg_id`, whose requeue the method failed to post, first arrived
    /// [`HOLD_PATIENCE`] ago or longer: then it is refused for good, as before requeues were
    /// made; until then it is held.
    pub async fn requeue_failed(&self, msg_id: Option<&str>) -> Result<bool, Hold> {
        let arrived = self.first_arrival(msg_id).await?;
        let now = self.ports().clock.now();
        Ok(twin_answer::waited(arrived, now, HOLD_PATIENCE))
    }

    /// Records how the message `msg_id` settled. When a prune is due after `last_pruned`, it
    /// forgets ids older than `retention` in the same write and returns when it ran, for the
    /// loop to pass as the next `last_pruned`. A failed write holds the message.
    pub async fn arrival_settled(
        &self,
        msg_id: &str,
        handled: Handled,
        last_pruned: Option<jiff::Timestamp>,
        retention: Duration,
    ) -> Result<Option<jiff::Timestamp>, Hold> {
        let msg_id = msg_id.to_owned();
        let status = handled.inbox_status();
        Ok(self
            .inbox_write(move |repos, now| {
                record_settled(repos, &msg_id, status, now, last_pruned, retention)
            })
            .await?)
    }

    /// Records that the method acknowledged the message `msg_id`, which settled as `handled`.
    /// A method's loop calls it after the acknowledgement; a message refused or dropped keeps
    /// the row [`Wallet::arrival_settled`] wrote. A failed write is logged.
    pub async fn arrival_acknowledged(&self, msg_id: &str, handled: Handled) {
        if handled.inbox_status() == InboxStatus::Rejected {
            return;
        }
        let msg_id = msg_id.to_owned();
        let recorded = self
            .inbox_write(move |repos, now| {
                put_inbox(repos, &msg_id, InboxStatus::Acknowledged, now)
            })
            .await;
        if let Err(error) = recorded {
            warn!(error = %ErrorChain(&error), "epicbox acknowledgement not recorded");
        }
    }

    async fn apply(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        envelope: &Envelope,
        attempt: u32,
    ) -> Result<Handled, Settlement> {
        let reply_to = envelope.reply_to().ok_or(Refusal::NoReplyAddress)?;
        let network = self.config().network;
        match notice::classify(envelope.wire()) {
            Payload::Slate => {}
            Payload::Notice(notice) => {
                return Ok(self.notice_arrived(method, reply_to, notice).await?);
            }
            Payload::Unknown => {
                let invite = envelope
                    .wire()
                    .as_text()
                    .and_then(notice::pair_request_invite);
                if let (Some(invite), Some(hook)) = (invite, self.pair_requests()) {
                    // Stored or dropped before the message is acknowledged.
                    // A store that keeps failing leaves the request on the relay only up to the
                    // hold bound; then it is acknowledged and the sender may send it again.
                    return match hook.take(self, reply_to.as_str(), invite).await {
                        Ok(()) => Ok(Handled::Notice),
                        Err(error) if self.hold_exhausted(msg_id, attempt).await? => {
                            warn!(error = %error, "pairing request not stored, dropped");
                            Ok(Handled::Dropped)
                        }
                        Err(error) => {
                            warn!(error = %error, "pairing request kept for later");
                            Err(Hold::PairRequest.into())
                        }
                    };
                }
                debug!("notice of an unknown version or type ignored");
                return Ok(Handled::Dropped);
            }
            Payload::Oversize | Payload::Malformed => {
                debug!("notice dropped as oversize or malformed");
                return Ok(Handled::Dropped);
            }
        }
        let slate = method
            .decode(network, envelope.wire())
            .map_err(Refusal::Decode)?;
        match slate.stage() {
            Stage::S1 => {
                self.answer(method, msg_id, attempt, envelope, &slate, reply_to, None)
                    .await
            }
            Stage::S2 => {
                self.complete(method, msg_id, attempt, envelope, &slate, reply_to)
                    .await
            }
            Stage::I1 => match self.bounced_invoice(method, &slate, reply_to).await? {
                Some(bounced) => {
                    self.record_bounce(method, bounced).await?;
                    Ok(Handled::Bounced)
                }
                None => Err(Refusal::UnsupportedStage { stage: Stage::I1 }.into()),
            },
            Stage::I2 => {
                self.complete_invoice(method, msg_id, attempt, envelope, &slate, reply_to)
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
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        payment: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        let facts = method.sender_facts(envelope.wire());
        let (marked, features) = (facts.marked, facts.features);
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
            .finalize_invoice(method, envelope.wire(), POST_PROPAGATION)
            .await
        {
            Ok(finalized) => {
                // Recorded before the notice is decided, so an unmarked payment holds it back.
                self.record_paying_peer(method, finalized.tx_id, reply_to, marked, features)
                    .await;
                if let Some(kernel) = finalized.slate.kernel() {
                    self.notify_posted_over(
                        method,
                        finalized.tx_id,
                        payment.id(),
                        kernel.excess,
                        marked,
                    )
                    .await;
                }
                Ok(self.invoice_finalized(finalized.tx_id, payment, finalized_before))
            }
            Err(InvoiceError::NotPosted { tx_id, source }) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&source), "finalized transaction not posted");
                self.record_paying_peer(method, tx_id, reply_to, marked, features)
                    .await;
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
            // The payer may not have heard the withdrawal: the cancel tells a payer over
            // Epicbox nothing before it answered with the marker, and its notice fails while
            // this wallet is offline. The payment is kept for another try while the
            // answer cannot be delivered, up to the hold bound; after that the payer's next
            // try of the same payment brings the answer again.
            Err(
                error @ InvoiceError::NotFinalizable {
                    tx_id,
                    state: TxState::Cancelled,
                },
            ) if marked => match self.answer_withdrawn_payment(method, tx_id, payment).await {
                Ok(()) => Err(Refusal::Invoice(error).into()),
                Err(hold)
                    if reply_is_permanent(&**method, &hold)
                        || self.hold_exhausted(msg_id, attempt).await? =>
                {
                    warn!(tx_id = %tx_id, error = %ErrorChain(&hold), "withdrawn notice undelivered");
                    Err(Refusal::Invoice(error).into())
                }
                Err(_) => Err(Hold::Invoice(error).into()),
            },
            Err(
                error @ InvoiceError::NotFinalizable {
                    tx_id,
                    state: TxState::Cancelled,
                },
            ) => {
                self.record_paying_peer(method, tx_id, reply_to, false, None)
                    .await;
                Err(Refusal::Invoice(error).into())
            }
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
    /// open receipt caps, or at the payments address of a wallet that refuses payments nobody
    /// asked for. A reply that cannot be delivered is given up at the hold bound.
    #[allow(clippy::too_many_arguments)]
    async fn answer(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        proposal: &Slate,
        reply_to: &Destination,
        listing: Option<Listing>,
    ) -> Result<Handled, Settlement> {
        self.make_room_for(
            method, msg_id, attempt, envelope, proposal, reply_to, listing,
        )
        .await?;
        let facts = method.sender_facts(envelope.wire());
        let (marked, features) = (facts.marked, facts.features);
        match self
            .receive_from(
                method,
                envelope.wire(),
                ReceiveRequest::default(),
                Some(reply_to.clone()),
                listing,
            )
            .await
        {
            Ok(received) => {
                self.record_sending_peer(&**method, reply_to, marked, features)
                    .await;
                // A notice that came before this S1 applies now, so a payment its sender
                // cancelled is not answered.
                self.apply_early_notices_over(method, received.slate.id())
                    .await?;
                if self.answer_withheld(received.tx_id).await? {
                    debug!(tx_id = %received.tx_id, "answer withheld for a cancelled payment");
                    return Ok(if received.repeated {
                        Handled::Repeated
                    } else {
                        Handled::Received
                    });
                }
                // A payment answers only from the address it came in on: the S1 of a listing
                // payment that arrives again at the payments address, or the other way round,
                // gets no answer from there.
                let stored = self.receive_listing_of(received.tx_id).await?;
                if stored != listing {
                    debug!(tx_id = %received.tx_id, "answer withheld at another address");
                    return Ok(Handled::Repeated);
                }
                match self
                    .reply(&**method, reply_to, &received.reply, listing.is_some())
                    .await
                {
                    Ok(()) => {}
                    Err(hold)
                        if reply_is_permanent(&**method, &hold)
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

    /// Delivers the answer `wire` to `to` through `method`'s outbound, which sends from a
    /// listing's address when the message came in `at_listing`.
    async fn reply(
        &self,
        method: &dyn Method,
        to: &Destination,
        wire: &WireSlate,
        at_listing: bool,
    ) -> Result<(), Hold> {
        let outbound = method.outbound().ok_or(Hold::NoOutbound {
            transport: method.id(),
        })?;
        outbound.deliver(to, wire).await.map_err(Hold::Reply)?;
        if at_listing {
            info!(stage = Stage::S2.as_str(), "slate sent from a listing");
        } else {
            info!(stage = Stage::S2.as_str(), "slate sent");
        }
        Ok(())
    }

    /// Finalizes an S2 and posts it. A transaction that was finalized but not posted is
    /// settled: it waits in state `finalized` for [`Wallet::post`].
    /// An S2 finalized before, which arrives again when the receiver resent it, counts as
    /// repeated; finalizing it again posts only if the first post did not succeed. A marked S2
    /// of a send cancelled here is answered with a `cancelled` notice and refused.
    async fn complete(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        reply: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        let facts = method.sender_facts(envelope.wire());
        let (marked, features) = (facts.marked, facts.features);
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
        let finalized = self
            .finalize_from(
                method,
                envelope.wire(),
                POST_PROPAGATION,
                Answerer::From(reply_to.clone()),
            )
            .await;
        // What the answer showed is recorded before any notice about the send is decided, so
        // an unmarked answer holds every notice back.
        let answered = match &finalized {
            Ok(finalized) => Some(finalized.tx_id),
            Err(
                FinalizeError::NotPosted { tx_id, .. }
                | FinalizeError::NotFinalizable {
                    tx_id,
                    state: TxState::Cancelled,
                },
            ) => Some(*tx_id),
            Err(_) => None,
        };
        if let Some(tx_id) = answered {
            self.record_receiving_peer(method, tx_id, reply_to, marked, features)
                .await;
        }
        match finalized {
            Ok(finalized) => {
                // Only the call that pushed the transaction tells the receiver; an S2 that
                // arrives again for a posted transaction pushes nothing.
                if finalized.pushed {
                    self.notify_pushed(finalized.tx_id, &finalized.slate, marked)
                        .await;
                }
                Ok(handled)
            }
            Err(FinalizeError::NotPosted { tx_id, source }) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&source), "finalized transaction not posted");
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
            // The receiver answered a send cancelled here and waits for it to be posted: it
            // hears of the cancel, as a `withdrawn` answers a late payment of an invoice. The
            // answer came from the key the send went to, which finalizing checked first. The
            // answer is kept for another try while the notice cannot be delivered, up to the
            // hold bound.
            Err(
                error @ FinalizeError::NotFinalizable {
                    tx_id,
                    state: TxState::Cancelled,
                },
            ) if marked => match self.answer_cancelled_send(method, tx_id).await {
                Ok(()) => Err(Refusal::Finalize(error).into()),
                Err(hold)
                    if matches!(hold, Hold::Withheld)
                        || reply_is_permanent(&**method, &hold)
                        || self.hold_exhausted(msg_id, attempt).await? =>
                {
                    warn!(tx_id = %tx_id, error = %ErrorChain(&hold), "cancelled notice undelivered");
                    Err(Refusal::Finalize(error).into())
                }
                Err(_) => Err(Hold::Finalize(error).into()),
            },
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
    /// [`crate::config::WalletPolicy::max_open_receipts`] says. At the payments address, not a
    /// listing, a wallet that refuses payments nobody asked for refuses every new S1 and
    /// answers it with a `declined` notice (ADR 0045).
    #[allow(clippy::too_many_arguments)]
    async fn make_room_for(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        proposal: &Slate,
        reply_to: &Destination,
        listing: Option<Listing>,
    ) -> Result<(), Settlement> {
        let slate_id = Uuid::from_bytes(*proposal.id().as_bytes());
        let network = self.config().network;
        // The key part of an address alone identifies a sender; text that is no address of
        // the method is compared whole.
        let key_of = |address: &str| {
            method
                .peer_key(network, address)
                .unwrap_or_else(|_| address.to_owned())
        };
        let key = key_of(reply_to.as_str());
        let sender = Sender {
            key: &key,
            key_of: &key_of,
        };
        let refuse = listing.is_none() && self.config().policy.refuse_unsolicited_payments;
        match self
            .make_room(method.id(), slate_id, Some(sender), refuse)
            .await
        {
            Ok(()) => Ok(()),
            Err(NoRoom::Refused) => {
                self.decline_payment(method, msg_id, attempt, envelope, proposal, reply_to)
                    .await
            }
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

    /// Refuses the new S1 `proposal` of a wallet that refuses payments nobody asked for, and
    /// first tells its sender with a `declined` notice, which goes only to a marked sender
    /// lately shown to run LEPIC. A notice that cannot be delivered for a reason that passes
    /// holds the message up to the hold bound.
    async fn decline_payment(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        proposal: &Slate,
        reply_to: &Destination,
    ) -> Result<(), Settlement> {
        let facts = method.sender_facts(envelope.wire());
        let (marked, features) = (facts.marked, facts.features);
        self.record_sending_peer(&**method, reply_to, marked, features)
            .await;
        match self
            .decline_unsolicited(method, reply_to, proposal.id(), marked)
            .await
        {
            Ok(()) => {}
            Err(hold)
                if matches!(hold, Hold::Withheld)
                    || reply_is_permanent(&**method, &hold)
                    || self.hold_exhausted(msg_id, attempt).await? =>
            {
                debug!(slate_id = %proposal.id(), error = %ErrorChain(&hold), "declined notice not sent");
            }
            Err(hold) => return Err(hold.into()),
        }
        info!(slate_id = %proposal.id(), "payment nobody asked for refused");
        Err(Refusal::Unsolicited.into())
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

/// One message a method received, as [`Wallet::arrived`] takes it.
#[derive(Debug, Clone, Copy)]
pub struct Arrival<'a> {
    /// The id the method's relay gave the message, when it gave one.
    pub msg_id: Option<&'a str>,
    /// The message.
    pub envelope: &'a Envelope,
    /// The try of the message in this drain or listen, counted from 1.
    pub attempt: u32,
    /// The listing whose address received it; `None` at the payments address.
    pub listing: Option<Listing>,
}

/// How a message [`Wallet::arrived`] did not settle ends.
#[derive(Debug)]
pub enum Outcome {
    /// Left for the method to deliver again.
    Hold(Hold),
    /// To be posted back to the address for another install of the wallet.
    Requeue(Requeue),
}

/// How a message that was not handled ends: refused for good, held for redelivery, or
/// posted back to the address for another install before it is acknowledged.
pub(crate) enum Settlement {
    Refuse(Refusal),
    Hold(Hold),
    Requeue(Requeue),
}

/// An answer for a slate this store does not know, to requeue.
#[derive(Debug)]
pub struct Requeue {
    /// The slate it answers.
    pub slate_id: SlateId,
    /// Its stage: S2 or I2.
    pub stage: Stage,
    /// Why it is refused should the requeue fail for good.
    refusal: Refusal,
}

impl Requeue {
    /// Why the answer is refused should the requeue fail for good, for the log.
    pub fn refusal(&self) -> &(dyn StdError + Send + Sync + 'static) {
        &self.refusal
    }
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
