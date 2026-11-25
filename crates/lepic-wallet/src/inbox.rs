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
//!
//! [`MAX_HOLD_ATTEMPTS`]: ledger::MAX_HOLD_ATTEMPTS
//! [`HOLD_PATIENCE`]: ledger::HOLD_PATIENCE
//! [`Event::ReplyUndelivered`]: crate::Event::ReplyUndelivered
//! [`Event::AnsweredAgain`]: crate::Event::AnsweredAgain

mod ledger;
mod legacy;
mod listing;

use std::error::Error as StdError;
use std::sync::Arc;

use lepic_slate::stage::Stage;
use lepic_store::{InboxStatus, StoreError};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{Envelope, TransportId};
use thiserror::Error;
use tokio::sync::watch;

use crate::error::WalletError;
use crate::event::SlateId;
use crate::finalize::FinalizeError;
use crate::invoice::InvoiceError;
use crate::namespace::Listing;
use crate::receive::ReceiveError;

pub use crate::twin_answer::{MAX_TWIN_ANSWERS, TWIN_HOLD, TWIN_REQUEUE_WINDOW};

/// A failure a method builds for [`InboxError`] and [`Hold`] from its own error type.
pub type MethodFailure = Box<dyn StdError + Send + Sync + 'static>;

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
    /// Messages acknowledged and forgotten: anything over Epicbox that is not a stock slate,
    /// and notices not from the counterparty of their slate, of an unknown version or type,
    /// oversize or malformed.
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
///
/// [`Wallet::arrived`]: crate::Wallet::arrived
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
    #[error("slate id was received before with another slate")]
    SlateIdReused,
    #[error("slate was not received")]
    Receive(#[source] ReceiveError),
    #[error("slate was not finalized")]
    Finalize(#[source] FinalizeError),
    #[error("sender already has the most open receipts allowed")]
    OpenReceiptsFromSender,
    #[error("open receipts are at the cap")]
    OpenReceipts,
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
    #[error("answer for an unknown slate held for another install")]
    UnknownSlate,
    /// The method could not post an answer back for another install.
    #[error("answer for an unknown slate not requeued")]
    Requeue(#[source] MethodFailure),
}

impl From<StoreError> for Hold {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
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
        | FinalizeError::NotPosted { .. }
        | FinalizeError::InputsReorged { .. } => false,
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
        | InvoiceError::CannotExport { .. }
        | InvoiceError::Codecs(_)
        | InvoiceError::Selection(_)
        | InvoiceError::NotPosted { .. }
        | InvoiceError::InputsReorged { .. }
        | InvoiceError::Undelivered { .. }
        | InvoiceError::PaymentUndelivered { .. } => false,
        InvoiceError::ToAddress
        | InvoiceError::InputsSpentElsewhere { .. }
        | InvoiceError::InputsSpentByOwnTransaction { .. }
        | InvoiceError::PeerInputsSpent { .. }
        | InvoiceError::AnswerInputsSpent { .. }
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
        | InvoiceError::SlateIdTaken { .. }
        | InvoiceError::AlreadyFinalized { .. }
        | InvoiceError::NotFinalizable { .. }
        | InvoiceError::MissingContext { .. }
        | InvoiceError::MalformedContext
        | InvoiceError::NotParked { .. } => true,
    }
}

/// One message a method received, as [`Wallet::arrived`] takes it.
///
/// [`Wallet::arrived`]: crate::Wallet::arrived
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
///
/// [`Wallet::arrived`]: crate::Wallet::arrived
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
    /// The slate it answers. For a native answer to a send this wallet does not hold, which
    /// it cannot open, a key taken from its envelope instead.
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
