// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2018 The Grin Developers
// Ported from EpicCash/epic core/src/core/committed.rs (Apache-2.0); see NOTICE and upstream.toml.

//! Kernel sums, as the node's `core::committed` computes them for a transaction: the outputs
//! plus the fee, less the inputs, must equal the kernel excesses plus `commit(0, offset)`.

use lepic_crypto::{Commitment, CryptoError};
use thiserror::Error;

use crate::crypto_ser::BlindingFactor;
use crate::tx::TransactionBody;

/// The sum check of a transaction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KernelSumError {
    #[error("input, output and fee commitments could not be summed")]
    Commitments(#[source] CryptoError),
    #[error("kernel excesses and offset could not be summed")]
    Excesses(#[source] CryptoError),
    #[error("kernel offset is not a valid scalar")]
    InvalidOffset(#[source] CryptoError),
    #[error("kernel excesses and offset do not equal the outputs, fee and inputs")]
    Mismatch,
}

// Upstream sums fees with saturation and clamps the overage to `i64`, so any total above
// `i64::MAX` is committed as `i64::MAX`.
const MAX_OVERAGE: u64 = i64::MAX.unsigned_abs();

/// The value a transaction body commits to beyond its outputs: its fee, as upstream computes it.
pub fn overage(body: &TransactionBody) -> u64 {
    body.kernels()
        .iter()
        .map(|kernel| kernel.features.fee().value())
        .fold(0, u64::saturating_add)
        .min(MAX_OVERAGE)
}

/// `sum(outputs) + commit_value(overage) - sum(inputs)`.
pub fn sum_commitments(body: &TransactionBody, overage: u64) -> Result<Commitment, KernelSumError> {
    let mut positive: Vec<Commitment> = body
        .outputs()
        .iter()
        .map(|output| output.commitment)
        .collect();
    if overage != 0 {
        positive.push(Commitment::commit_value(overage).map_err(KernelSumError::Commitments)?);
    }
    let negative: Vec<Commitment> = body.inputs().iter().map(|input| input.commitment).collect();
    Commitment::sum(&positive, &negative).map_err(KernelSumError::Commitments)
}

/// `sum(kernel excesses) + commit(0, offset)`. A zero offset adds nothing.
pub fn sum_kernel_excesses(
    body: &TransactionBody,
    offset: &BlindingFactor,
) -> Result<Commitment, KernelSumError> {
    let excesses: Vec<Commitment> = body.kernels().iter().map(|kernel| kernel.excess).collect();
    // Upstream sums the excesses on their own first, which fails when they cancel out even if
    // the offset would make the total non-zero.
    let kernel_sum = Commitment::sum(&excesses, &[]).map_err(KernelSumError::Excesses)?;
    if offset.is_zero() {
        return Ok(kernel_sum);
    }
    let key = offset
        .to_secret_key()
        .map_err(KernelSumError::InvalidOffset)?;
    let offset_commit = Commitment::commit(0, &key).map_err(KernelSumError::Excesses)?;
    Commitment::sum(&[kernel_sum, offset_commit], &[]).map_err(KernelSumError::Excesses)
}

/// Checks that the body balances against its kernels, given its overage and offset.
pub fn verify_kernel_sums(
    body: &TransactionBody,
    overage: u64,
    offset: &BlindingFactor,
) -> Result<(), KernelSumError> {
    let utxo_sum = sum_commitments(body, overage)?;
    let kernel_sum = sum_kernel_excesses(body, offset)?;
    if utxo_sum == kernel_sum {
        Ok(())
    } else {
        Err(KernelSumError::Mismatch)
    }
}
