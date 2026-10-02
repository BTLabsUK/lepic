//! What the engine tells the host while it runs. Events go to every subscriber of
//! [`crate::Wallet::subscribe`]; a subscriber that falls more than [`EVENT_CAPACITY`] events
//! behind misses the oldest ones and is told how many it missed.

use lepic_primitives::amount::{Amount, Height};
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
