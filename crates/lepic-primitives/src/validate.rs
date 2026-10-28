// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2019 The Grin Developers
// Ported from EpicCash/epic core/src/core/transaction.rs, core/src/core/committed.rs (Apache-2.0);
// see NOTICE and upstream.toml.

//! Full transaction validation, as the node's `Transaction::validate(Weighting::AsTransaction)`
//! runs it and `epic-wallet` calls it when finalizing a slate.

use lepic_crypto::{CommittedProof, CryptoError, RangeProof, aggsig};
use thiserror::Error;

use crate::committed::{self, KernelSumError};
use crate::kernel::TxKernel;
use crate::tx::{Transaction, TransactionBody, TxError};

/// The rule a transaction breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error(transparent)]
    Structure(#[from] TxError),
    #[error("an output range proof does not verify")]
    RangeProof(#[source] CryptoError),
    #[error("signature of kernel {index} does not verify")]
    KernelSignature {
        index: usize,
        #[source]
        source: CryptoError,
    },
    #[error("kernel sums do not balance")]
    KernelSum(#[from] KernelSumError),
}

impl Transaction {
    /// Runs the node's `Transaction::validate(Weighting::AsTransaction)` checks, in its order:
    /// weight, sorting and duplicates, cut-through, range proofs, kernel signatures, features,
    /// kernel sums. Passing does not mean the pool accepts the transaction: lock heights,
    /// coinbase maturity and fee rules are not checked.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let body = self.body();
        body.verify_tx_weight()?;
        body.verify_sorted()?;
        body.verify_cut_through()?;
        verify_range_proofs(body)?;
        verify_kernel_signatures(body.kernels())?;
        body.verify_features()?;
        committed::verify_kernel_sums(body, committed::overage(body), self.offset())?;
        Ok(())
    }
}

fn verify_range_proofs(body: &TransactionBody) -> Result<(), ValidationError> {
    if body.outputs().is_empty() {
        return Ok(());
    }
    let items: Vec<CommittedProof<'_>> = body
        .outputs()
        .iter()
        .map(|output| CommittedProof {
            commitment: &output.commitment,
            proof: &output.proof,
        })
        .collect();
    RangeProof::verify_batch(&items).map_err(ValidationError::RangeProof)
}

// Upstream verifies kernels as one batch. Each kernel is checked on its own here with the same
// equation, which accepts exactly the signatures the batch accepts and names the failing kernel.
fn verify_kernel_signatures(kernels: &[TxKernel]) -> Result<(), ValidationError> {
    for (index, kernel) in kernels.iter().enumerate() {
        aggsig::verify_single_from_commit(
            &kernel.excess_sig,
            &kernel.signature_message(),
            &kernel.excess,
        )
        .map_err(|source| ValidationError::KernelSignature { index, source })?;
    }
    Ok(())
}
