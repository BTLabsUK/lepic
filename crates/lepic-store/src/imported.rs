//! What the wallet keeps of transactions imported from another wallet's history, beyond the
//! log entry each one is stored as.
//!
//! An imported transaction is an ordinary log entry plus a record here. The record keeps what
//! only the old wallet knew (its log id, its kind, the kernel, the messages) and how the chain
//! scan judged it. Balances never read these records: they come from the outputs alone.

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Height};
use uuid::Uuid;

use crate::encoding::stored_enum;
use crate::error::StoreError;
use crate::output::CommitmentBytes;
use crate::transaction::TxId;

/// The longest message text kept, in bytes.
pub const MAX_IMPORTED_MESSAGE_BYTES: usize = 1024;

/// The most messages kept per transaction: one for each party of a two-party transaction.
pub const MAX_IMPORTED_MESSAGES: usize = 2;

stored_enum! {
    /// The kind the old wallet's log gave the transaction.
    pub enum ImportedKind {
        Coinbase => "coinbase",
        Received => "received",
        Sent => "sent",
        ReceivedCancelled => "received-cancelled",
        SentCancelled => "sent-cancelled",
        SentMempool => "sent-mempool",
        ReceivedMempool => "received-mempool",
        SentCreated => "sent-created",
    }
}

stored_enum! {
    /// How the chain scan judged an imported transaction.
    pub enum ChainCheck {
        /// Nothing on chain confirmed or contradicted it yet.
        Unchecked => "unchecked",
        /// A scan found an output it created, or the node holds its kernel.
        OnChain => "on-chain",
        /// The old wallet had cancelled it, but a scan found an output it created.
        CancelledButOnChain => "cancelled-but-on-chain",
        /// The old wallet held an output of it as unspent, and a full scan did not find it.
        UnspentNotOnChain => "unspent-not-on-chain",
    }
}

stored_enum! {
    /// The status the old wallet gave an output.
    pub enum ImportedOutputStatus {
        Unconfirmed => "unconfirmed",
        Unspent => "unspent",
        Locked => "locked",
        Spent => "spent",
        Deleted => "deleted",
    }
}

/// A participant's message, as the old wallet stored it and the importer verified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedMessage {
    /// The participant id in the slate: 0 for the sender of the money, 1 for its receiver.
    pub participant: u8,
    /// At most [`MAX_IMPORTED_MESSAGE_BYTES`].
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedTransaction {
    /// The old wallet's local log id.
    pub source_id: u32,
    pub kind: ImportedKind,
    /// The old wallet's slate id. Kept here also when the log entry cannot carry it, because
    /// another entry of the same direction already has it.
    pub slate_id: Option<Uuid>,
    /// When the old wallet saw it confirmed.
    pub confirmed_at: Option<Timestamp>,
    pub input_count: u32,
    pub output_count: u32,
    pub kernel_excess: Option<CommitmentBytes>,
    pub ttl_cutoff_height: Option<Height>,
    /// At most [`MAX_IMPORTED_MESSAGES`], in participant order.
    pub messages: Vec<ImportedMessage>,
    pub check: ChainCheck,
}

/// An output the old wallet recorded, and the imported transaction that created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedOutput {
    pub commitment: CommitmentBytes,
    pub tx: TxId,
    pub status: ImportedOutputStatus,
    pub height: Height,
    pub amount: Amount,
}

pub trait ImportedRepository {
    /// Inserts or replaces the record of transaction `tx`, which must exist. Fails with
    /// [`StoreError::OutOfRange`] for a message over the bounds above.
    fn put_imported_transaction(
        &mut self,
        tx: TxId,
        imported: &ImportedTransaction,
    ) -> Result<(), StoreError>;

    fn imported_transaction(&self, tx: TxId) -> Result<Option<ImportedTransaction>, StoreError>;

    /// Replaces the chain check of a stored record. Fails with [`StoreError::NotFound`] when
    /// `tx` has none.
    fn set_chain_check(&mut self, tx: TxId, check: ChainCheck) -> Result<(), StoreError>;

    /// Inserts or replaces the imported output with the same commitment. Its transaction must
    /// exist.
    fn put_imported_output(&mut self, output: &ImportedOutput) -> Result<(), StoreError>;

    fn imported_output(
        &self,
        commitment: &CommitmentBytes,
    ) -> Result<Option<ImportedOutput>, StoreError>;

    /// The imported outputs the old wallet gave `status`, ordered by commitment.
    fn imported_outputs(
        &self,
        status: ImportedOutputStatus,
    ) -> Result<Vec<ImportedOutput>, StoreError>;
}

pub(crate) fn check_messages(messages: &[ImportedMessage]) -> Result<(), StoreError> {
    if messages.len() > MAX_IMPORTED_MESSAGES
        || messages
            .iter()
            .any(|message| message.text.len() > MAX_IMPORTED_MESSAGE_BYTES)
    {
        return Err(StoreError::OutOfRange {
            field: "imported message",
        });
    }
    Ok(())
}
