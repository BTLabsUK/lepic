use std::fmt;

use jiff::Timestamp;
use uuid::Uuid;

use crate::encoding::stored_enum;
use crate::error::StoreError;
use crate::slate::SlateStage;

stored_enum! {
    pub enum InboxStatus {
        /// Received from the relay; its effect is not stored yet.
        Received => "received",
        /// Its effect is stored.
        Processed => "processed",
        /// Rejected for good.
        Rejected => "rejected",
        /// Acknowledged to the relay after it was processed or rejected.
        Acknowledged => "acknowledged",
    }
}

/// A relay message seen by the wallet, tracked by the id the relay gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEntry {
    pub msg_id: String,
    pub status: InboxStatus,
    pub received_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Local outbox message id, assigned by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutboxId(pub u64);

impl fmt::Display for OutboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

stored_enum! {
    pub enum OutboxStatus {
        Pending => "pending",
        Delivered => "delivered",
    }
}

/// A stored slate waiting to be delivered, or delivered, through a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    pub transport: String,
    pub destination: String,
    pub slate_id: Uuid,
    pub stage: SlateStage,
    pub status: OutboxStatus,
    pub attempts: u32,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOutbox {
    pub id: OutboxId,
    pub entry: OutboxEntry,
}

pub trait RelayRepository {
    /// Inserts or replaces the inbox entry with the same message id.
    fn put_inbox(&mut self, entry: &InboxEntry) -> Result<(), StoreError>;

    fn inbox(&self, msg_id: &str) -> Result<Option<InboxEntry>, StoreError>;

    /// Stores a new outbox entry under the next free id.
    fn enqueue_outbox(&mut self, entry: &OutboxEntry) -> Result<OutboxId, StoreError>;

    fn update_outbox(&mut self, id: OutboxId, entry: &OutboxEntry) -> Result<(), StoreError>;

    /// Outbox entries with `status`, ordered by id.
    fn outbox(&self, status: OutboxStatus) -> Result<Vec<StoredOutbox>, StoreError>;

    /// Removes the outbox entry if it is stored.
    fn delete_outbox(&mut self, id: OutboxId) -> Result<(), StoreError>;
}
