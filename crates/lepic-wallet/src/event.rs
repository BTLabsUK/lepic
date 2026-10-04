//! What the engine tells the host while it runs. Events go to every subscriber of
//! [`crate::Wallet::subscribe`]; a subscriber that falls more than [`EVENT_CAPACITY`] events
//! behind misses the oldest ones and is told how many it missed.

use lepic_primitives::amount::{Amount, Height};
use lepic_slate::model::SlateId;
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
    /// [`Event::Transaction`].
    Received(ReceivedTransaction),
    /// A slate received before arrived again and was answered with the reply stored the first
    /// time. Nothing changed; no [`Event::Received`] follows for it.
    AnsweredAgain(AnsweredSlate),
    Sync(SyncProgress),
    Transport(TransportStatus),
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

/// The transaction a repeated slate was received as before, and the transport it came over
/// this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnsweredSlate {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub transport: TransportId,
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
