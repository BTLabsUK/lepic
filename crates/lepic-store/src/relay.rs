// SPDX-License-Identifier: Apache-2.0
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

    /// Removes every inbox entry first received before `received_before`, and returns how many
    /// were removed.
    fn prune_inbox(&mut self, received_before: Timestamp) -> Result<usize, StoreError>;

    /// Stores a new outbox entry under the next free id.
    fn enqueue_outbox(&mut self, entry: &OutboxEntry) -> Result<OutboxId, StoreError>;

    fn update_outbox(&mut self, id: OutboxId, entry: &OutboxEntry) -> Result<(), StoreError>;

    /// Outbox entries with `status`, ordered by id.
    fn outbox(&self, status: OutboxStatus) -> Result<Vec<StoredOutbox>, StoreError>;

    /// Removes the outbox entry if it is stored.
    fn delete_outbox(&mut self, id: OutboxId) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::context::StoreKeys;
    use crate::memory::MemoryStore;
    use crate::store::WalletStore;

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(second).unwrap()
    }

    fn entry(msg_id: &str, received_at: Timestamp) -> InboxEntry {
        InboxEntry {
            msg_id: msg_id.to_owned(),
            status: InboxStatus::Acknowledged,
            received_at,
            updated_at: at(1_000),
        }
    }

    /// Entries received before the cutoff go, the one received at it and later ones stay.
    fn prunes_inbox_entries_received_before_the_cutoff(store: &impl WalletStore) {
        let pruned = store
            .write(|repos| {
                for (id, second) in [("old1", 10), ("old2", 99), ("edge", 100), ("new", 500)] {
                    repos.put_inbox(&entry(id, at(second)))?;
                }
                repos.prune_inbox(at(100))
            })
            .unwrap();
        assert_eq!(pruned, 2);
        let kept = store
            .read(|repos| {
                ["old1", "old2", "edge", "new"]
                    .map(|id| repos.inbox(id).map(|found| found.is_some()))
                    .into_iter()
                    .collect::<Result<Vec<_>, StoreError>>()
            })
            .unwrap();
        assert_eq!(kept, [false, false, true, true]);
    }

    #[test]
    fn memory_store_prunes_inbox_entries_received_before_the_cutoff() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        prunes_inbox_entries_received_before_the_cutoff(&store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_store_prunes_inbox_entries_received_before_the_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::SqliteStore::open(
            &dir.path().join("wallet.sqlite"),
            StoreKeys::from_bytes([1; 32], [1; 32]),
        )
        .unwrap();
        prunes_inbox_entries_received_before_the_cutoff(&store);
    }
}
