use std::fmt;

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use uuid::Uuid;

use crate::account::AccountIndex;
use crate::encoding::stored_enum;
use crate::error::StoreError;

/// Local transaction log id, assigned by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId(pub u32);

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

stored_enum! {
    pub enum TxDirection {
        Outgoing => "outgoing",
        Incoming => "incoming",
    }
}

stored_enum! {
    pub enum TxState {
        Sent => "sent",
        Received => "received",
        Finalized => "finalized",
        Posted => "posted",
        Confirmed => "confirmed",
        Cancelled => "cancelled",
        Expired => "expired",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEntry {
    pub account: AccountIndex,
    pub direction: TxDirection,
    pub state: TxState,
    /// Unique per direction, so a payment to self keeps one entry on each side.
    pub slate_id: Option<Uuid>,
    pub transport: Option<String>,
    pub amount_credited: Amount,
    pub amount_debited: Amount,
    pub fee: Option<Fee>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTransaction {
    pub id: TxId,
    pub entry: TransactionEntry,
}

pub trait TransactionRepository {
    /// Stores a new entry under the next free id. The account must exist, and no entry with the
    /// same slate id and direction may be stored.
    fn insert_transaction(&mut self, entry: &TransactionEntry) -> Result<TxId, StoreError>;

    /// Replaces a stored entry, under the same rules as insertion.
    fn update_transaction(&mut self, id: TxId, entry: &TransactionEntry) -> Result<(), StoreError>;

    fn transaction(&self, id: TxId) -> Result<Option<TransactionEntry>, StoreError>;

    fn transaction_by_slate(
        &self,
        slate_id: Uuid,
        direction: TxDirection,
    ) -> Result<Option<StoredTransaction>, StoreError>;

    /// Entries of an account, ordered by id.
    fn transactions(&self, account: AccountIndex) -> Result<Vec<StoredTransaction>, StoreError>;

    /// Records the block height at which the chain confirmed an entry, replacing any height
    /// recorded before. Updating the entry keeps it. Fails with
    /// [`StoreError::UnknownTransaction`] when no entry has the id.
    fn set_confirmed_height(&mut self, id: TxId, height: Height) -> Result<(), StoreError>;

    /// `None` when no height was recorded, as for an entry confirmed before heights were stored.
    fn confirmed_height(&self, id: TxId) -> Result<Option<Height>, StoreError>;

    /// Records the address of the other party, replacing any recorded before. Updating the
    /// entry keeps it. Fails with [`StoreError::UnknownTransaction`] when no entry has the id.
    fn set_counterparty(&mut self, id: TxId, address: &str) -> Result<(), StoreError>;

    /// `None` when no address was recorded, as for a file exchange or an entry stored before
    /// addresses were.
    fn counterparty(&self, id: TxId) -> Result<Option<String>, StoreError>;
}
