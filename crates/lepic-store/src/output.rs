// SPDX-License-Identifier: Apache-2.0
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputIdentifier;

use crate::account::AccountIndex;
use crate::encoding::stored_enum;
use crate::error::StoreError;
use crate::transaction::TxId;

/// Length of a Pedersen commitment, the key outputs are stored under.
pub const COMMITMENT_LEN: usize = 33;

/// The bytes of a commitment, as `Commitment::as_bytes` returns them.
pub type CommitmentBytes = [u8; COMMITMENT_LEN];

/// Length of a key identifier: depth, then four big-endian path components.
pub const KEY_ID_LEN: usize = 17;

/// The keychain identifier of the key that blinds an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; KEY_ID_LEN]);

stored_enum! {
    pub enum OutputStatus {
        Unconfirmed => "unconfirmed",
        Unspent => "unspent",
        Locked => "locked",
        Spent => "spent",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRecord {
    pub id: OutputIdentifier,
    pub key_id: KeyId,
    pub account: AccountIndex,
    pub amount: Amount,
    pub status: OutputStatus,
    /// Height the output was created or confirmed at.
    pub height: Height,
    /// First height at which the output may be spent.
    pub lock_height: Height,
    pub mmr_index: Option<u64>,
    /// The transaction that created or is spending the output.
    pub tx: Option<TxId>,
}

impl OutputRecord {
    pub fn commitment(&self) -> &CommitmentBytes {
        self.id.commitment.as_bytes()
    }
}

pub trait OutputRepository {
    /// Inserts or replaces the output with the same commitment. The account, and the
    /// transaction when set, must exist.
    fn put_output(&mut self, output: &OutputRecord) -> Result<(), StoreError>;

    /// Inserts an output the wallet has just derived. Fails with [`StoreError::Duplicate`] when
    /// an output with the same commitment is stored, which is left unchanged. The account, and
    /// the transaction when set, must exist.
    fn insert_output(&mut self, output: &OutputRecord) -> Result<(), StoreError>;

    fn output(&self, commitment: &CommitmentBytes) -> Result<Option<OutputRecord>, StoreError>;

    /// Outputs of an account, optionally only those with `status`, ordered by commitment.
    fn outputs(
        &self,
        account: AccountIndex,
        status: Option<OutputStatus>,
    ) -> Result<Vec<OutputRecord>, StoreError>;

    /// Outputs linked to a transaction, ordered by commitment.
    fn outputs_of_transaction(&self, tx: TxId) -> Result<Vec<OutputRecord>, StoreError>;

    /// Removes the output if it is stored.
    fn delete_output(&mut self, commitment: &CommitmentBytes) -> Result<(), StoreError>;
}
