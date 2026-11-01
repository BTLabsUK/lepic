// SPDX-License-Identifier: Apache-2.0
//! What the wallet keeps about a transaction besides its log entry: heights and flags of its
//! limits, the watch on a transaction that ended unconfirmed, the spend another wallet on the
//! same recovery phrase made, and how a scan found it. Every record belongs to one entry and is
//! deleted with it.

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Height};

use crate::encoding::stored_enum;
use crate::error::StoreError;
use crate::output::{CommitmentBytes, KeyId};
use crate::transaction::TxId;

/// Heights and flags recorded for one transaction. `None` and `false` mean not recorded, so
/// [`TxMarks::default`] is the value of an entry with no marks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxMarks {
    /// A send's wallet-local limit, past which the wallet neither finalizes nor posts it.
    pub local_cutoff: Option<Height>,
    /// The tip a send was finalized at.
    pub finalized_at: Option<Height>,
    /// The height up to which a lookup of a send's kernel did not find it.
    pub kernel_absent_at: Option<Height>,
    /// The tip a refresh first saw a received payment without a TTL waiting for its sender.
    pub receive_seen_at: Option<Height>,
    /// A refresh found every input of a received payment's slate unspent.
    pub receive_inputs_unspent: bool,
    /// The node refused a send because another wallet spent its inputs.
    pub inputs_spent_elsewhere: bool,
    /// When the sender of a received payment first reported that it posted it.
    pub sender_posted_at: Option<Timestamp>,
    /// The payer of a cancelled invoice was told it is withdrawn.
    pub withdrawn_answered: bool,
    /// When the sender of a received payment first reported that it cancelled it.
    pub sender_cancelled_at: Option<Timestamp>,
    /// The receiver of a cancelled send was told it is cancelled.
    pub cancelled_answered: bool,
    /// The latest answer to a send over Epicbox carried the LEPIC marker, so its receiver may
    /// be told of the send's end.
    pub answer_marked: bool,
}

stored_enum! {
    /// How a refresh looks for a watched transaction.
    pub enum WatchPhase {
        /// By its kernel, for a window of blocks after it ended.
        Kernel => "kernel",
        /// By its outputs, with no end.
        Outputs => "outputs",
    }
}

/// An unconfirmed output a watched transaction would have created, deleted when it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedOutput {
    pub commitment: CommitmentBytes,
    pub key_id: KeyId,
    pub amount: Amount,
}

/// What recognises a transaction that ended unconfirmed (released, cancelled, expired or
/// superseded) if the chain mines it after all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxWatch {
    pub phase: WatchPhase,
    /// The kernel excess.
    pub excess: CommitmentBytes,
    /// The height the slate was created at, below which the kernel cannot be.
    pub min_height: Height,
    /// The tip the transaction ended at.
    pub ended_at: Height,
    /// In the order the transaction listed them.
    pub outputs: Vec<WatchedOutput>,
}

/// The spend another wallet on the recovery phrase made, recorded with the outgoing entry that
/// stands for it, or the receive it made, recorded with the incoming entry a scan stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtherWalletSpend {
    /// The spend lies above this height and at or below `to`.
    pub after: Height,
    pub to: Height,
    /// A scan may still credit change to it.
    pub open: bool,
    /// The outputs of this wallet it spent.
    pub spent: Vec<CommitmentBytes>,
    /// The outputs a scan took for its change.
    pub change: Vec<CommitmentBytes>,
}

stored_enum! {
    /// Which scan stored an entry for an output it found with no record.
    pub enum FoundDuring {
        /// The scan from genesis a wallet rebuilt from its seed needs before it hands out keys.
        Restore => "restore",
        /// Any other scan, including the first one of a wallet made with a new seed.
        Rescan => "rescan",
    }
}

/// What a scan recorded about an entry it stored for an output it found with no record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanFoundRecord {
    /// The output the entry was stored for. The output's own link moves to the transaction that
    /// spends it; this one stays.
    pub output: Option<CommitmentBytes>,
    /// `None` for an entry of another wallet's receive.
    pub during: Option<FoundDuring>,
    /// The entry is dated by the output's block, not by the time of the scan.
    pub dated_by_block: bool,
}

/// The records of a transaction. Writing a record for an id with no entry fails with
/// [`StoreError::UnknownTransaction`]; deleting the entry deletes its records.
pub trait TxRecordRepository {
    /// [`TxMarks::default`] when none are recorded.
    fn tx_marks(&self, id: TxId) -> Result<TxMarks, StoreError>;

    /// Replaces the marks; the default value removes them.
    fn put_tx_marks(&mut self, id: TxId, marks: &TxMarks) -> Result<(), StoreError>;

    fn tx_watch(&self, id: TxId) -> Result<Option<TxWatch>, StoreError>;

    /// Every watch, ordered by transaction id.
    fn tx_watches(&self) -> Result<Vec<(TxId, TxWatch)>, StoreError>;

    /// Inserts or replaces the watch.
    fn put_tx_watch(&mut self, id: TxId, watch: &TxWatch) -> Result<(), StoreError>;

    /// Removes the watch if one is stored.
    fn delete_tx_watch(&mut self, id: TxId) -> Result<(), StoreError>;

    fn other_wallet_spend(&self, id: TxId) -> Result<Option<OtherWalletSpend>, StoreError>;

    /// Every record of another wallet's spend or receive, ordered by transaction id.
    fn other_wallet_spends(&self) -> Result<Vec<(TxId, OtherWalletSpend)>, StoreError>;

    /// Inserts or replaces the record.
    fn put_other_wallet_spend(
        &mut self,
        id: TxId,
        spend: &OtherWalletSpend,
    ) -> Result<(), StoreError>;

    fn scan_found(&self, id: TxId) -> Result<Option<ScanFoundRecord>, StoreError>;

    /// Inserts or replaces the record.
    fn put_scan_found(&mut self, id: TxId, found: &ScanFoundRecord) -> Result<(), StoreError>;
}
