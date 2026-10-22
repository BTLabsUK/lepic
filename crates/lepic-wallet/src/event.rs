//! What the engine tells the host while it runs. Events go to every subscriber of
//! [`crate::Wallet::subscribe`]; a subscriber that falls more than [`EVENT_CAPACITY`] events
//! behind misses the oldest ones and is told how many it missed.

use lepic_crypto::Commitment;
use lepic_epicbox::EpicboxAddress;
use lepic_primitives::amount::{Amount, Height};
pub use lepic_slate::model::SlateId;
use lepic_store::{AccountIndex, TxId, TxState};
use lepic_transport::transport::TransportId;

use crate::state::StateChange;

pub const EVENT_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    Session(SessionState),
    Balance(Balance),
    Transaction(TransactionState),
    /// A received slate created a transaction. Its later state changes arrive as
    /// [`Event::Transaction`]. A send to the wallet itself raises [`Event::SelfSent`]
    /// instead: nothing was received from anyone.
    Received(ReceivedTransaction),
    /// A send to the wallet itself was stored and finalized: two entries over transport
    /// `self`, the outgoing one `finalized` and the incoming one `received`. Its posting and
    /// confirmation arrive as [`Event::Transaction`] for each entry.
    SelfSent(SelfSentTransaction),
    /// A slate received before arrived again and was answered with the reply stored the first
    /// time. Nothing changed; no [`Event::Received`] follows for it.
    AnsweredAgain(AnsweredSlate),
    /// A payment received over Epicbox was stored, but its S2 reply could not be delivered: the
    /// relay refused it, or delivering it kept failing. The transaction stays received and its
    /// message is settled; a sender that sends the same S1 again is answered with the stored S2.
    ReplyUndelivered(UndeliveredReply),
    Sync(SyncProgress),
    Transport(TransportStatus),
    /// An invoice from an allowed sender was stored on the invoice address, waiting for the
    /// user to pay or decline it. Nothing was paid.
    InvoiceParked(ParkedInvoice),
    /// An invoice this wallet issued was paid and finalized. Its posting shows as
    /// [`Event::Transaction`].
    InvoiceFinalized(FinalizedInvoice),
    /// An invoice expired unpaid: a parked one was deleted, or one this wallet issued was
    /// cancelled.
    InvoiceExpired(ExpiredInvoice),
    /// The issuer of an invoice this wallet paid reports that it pushed the transaction, with
    /// the kernel excess the payment expects. Advisory: the transaction's state changes only
    /// when a refresh finds the kernel.
    InvoicePosted(PostedInvoice),
    /// The payer declined an invoice this wallet issued. Nothing changed; the host may cancel
    /// the invoice.
    InvoiceDeclined(DeclinedInvoice),
    /// The issuer withdrew an invoice. A parked one was deleted. For one this wallet already
    /// paid, `tx_id` names the payment, which the host may offer the user to cancel; nothing
    /// was cancelled.
    InvoiceWithdrawn(WithdrawnInvoice),
    /// A payer sent an invoice this wallet issued back unchanged, as a wallet that does not
    /// pay invoices does. The peer is recorded as not paying invoices; the invoice stays
    /// issued until the host cancels it or it expires. A bounce redelivered before its relay
    /// message was settled raises this again for the same `tx_id`; treat it as the same bounce.
    InvoiceBounced(BouncedInvoice),
}

/// Whether the root key is in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Unlocked,
    Locked,
    /// The wallet handle was closed; no further events follow.
    Closed,
}

/// The balance of one account, in the categories `epic-wallet info` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    pub account: AccountIndex,
    /// The tip height the balance was computed at.
    pub height: Height,
    pub total: Amount,
    pub spendable: Amount,
    pub awaiting_confirmation: Amount,
    pub awaiting_finalization: Amount,
    pub immature: Amount,
    pub locked: Amount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionState {
    pub tx_id: TxId,
    pub from: TxState,
    pub to: TxState,
}

/// The transaction a received slate created, stored in state `received`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedTransaction {
    pub tx_id: TxId,
    pub account: AccountIndex,
    pub amount: Amount,
    pub transport: TransportId,
}

/// The two entries a send to the wallet itself stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfSentTransaction {
    /// The outgoing entry: it spent the inputs and holds the change.
    pub tx_id: TxId,
    /// The incoming entry: it holds the output of `amount`.
    pub received_tx_id: TxId,
    pub account: AccountIndex,
    pub amount: Amount,
}

/// A received transaction whose S2 reply was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndeliveredReply {
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

/// The transaction a repeated slate was received as before, and the transport it came over
/// this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnsweredSlate {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub transport: TransportId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParkedInvoice {
    pub slate_id: SlateId,
    pub amount: Amount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedInvoice {
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredInvoice {
    pub slate_id: SlateId,
    /// The issuer's cancelled transaction; `None` for a parked invoice, which has none.
    pub tx_id: Option<TxId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostedInvoice {
    /// The payment of the invoice.
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub excess: Commitment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclinedInvoice {
    /// The issued invoice.
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawnInvoice {
    pub slate_id: SlateId,
    /// The payment still waiting for the issuer; `None` when the invoice was not paid.
    pub tx_id: Option<TxId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BouncedInvoice {
    /// The issued invoice.
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The address the invoice was issued to.
    pub peer: EpicboxAddress,
}

impl From<StateChange> for Event {
    fn from(change: StateChange) -> Self {
        Self::Transaction(TransactionState {
            tx_id: change.tx_id,
            from: change.from,
            to: change.to,
        })
    }
}

/// Progress of a scan or refresh over a height range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncProgress {
    pub height: Height,
    pub target: Height,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportStatus {
    pub transport: TransportId,
    pub state: TransportState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportState {
    Connecting,
    Connected,
    /// Disconnected; the transport retries on its own unless it was stopped.
    Disconnected,
    Stopped,
}
