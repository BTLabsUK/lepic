// SPDX-License-Identifier: Apache-2.0
//! The recovery of a payment: a self-send pair that spends the payment's inputs back to the
//! wallet. The record belongs to the payment's transaction and is deleted with it, or with
//! either transaction of the pair.

use jiff::Timestamp;
use lepic_primitives::amount::Height;

use crate::encoding::{stored_enum, timestamp_to_column};
use crate::error::StoreError;
use crate::transaction::TxId;

/// The longest error text kept of a recovery, in bytes.
pub const MAX_RECOVERY_ERROR_LEN: usize = 1024;

stored_enum! {
    /// Where a recovery stands.
    pub enum RecoveryState {
        /// Stored, and no post has reached the node yet.
        Uncertain => "uncertain",
        /// The node accepted it; its kernel is not on chain.
        Posted => "posted",
        /// Its kernel is on chain, with fewer confirmations than the count.
        Confirming => "confirming",
        /// Its kernel has the count of confirmations; the payment's coins are back.
        Done => "done",
        /// It ended without being mined.
        Failed => "failed",
    }
}

impl RecoveryState {
    /// Whether the recovery can still be mined or reach the count.
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Uncertain | Self::Posted | Self::Confirming)
    }
}

/// The recovery of one payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// The payment recovered.
    pub tx_id: TxId,
    /// The outgoing entry of the recovery's self-send pair.
    pub sent_tx: TxId,
    /// The incoming entry of the recovery's self-send pair.
    pub received_tx: TxId,
    pub state: RecoveryState,
    /// The height of the block holding the recovery's kernel, once the chain has it.
    pub kernel_height: Option<Height>,
    pub last_error: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub trait RecoveryRepository {
    /// Stores `recovery`, replacing the one of the same payment. Fails with
    /// [`StoreError::UnknownTransaction`] when one of its three transactions does not exist, and
    /// with [`StoreError::OutOfRange`] for an error text longer than [`MAX_RECOVERY_ERROR_LEN`].
    fn put_recovery(&mut self, recovery: &Recovery) -> Result<(), StoreError>;

    /// The recovery of the payment `tx_id`.
    fn recovery(&self, tx_id: TxId) -> Result<Option<Recovery>, StoreError>;

    /// Every stored recovery, ordered by the payment's id.
    fn recoveries(&self) -> Result<Vec<Recovery>, StoreError>;
}

pub(crate) fn check_recovery(recovery: &Recovery) -> Result<(), StoreError> {
    if recovery
        .last_error
        .as_ref()
        .is_some_and(|error| error.len() > MAX_RECOVERY_ERROR_LEN)
    {
        return Err(StoreError::OutOfRange {
            field: "recovery error",
        });
    }
    timestamp_to_column(recovery.created_at)?;
    timestamp_to_column(recovery.updated_at)?;
    Ok(())
}
