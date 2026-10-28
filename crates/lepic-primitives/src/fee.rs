// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic core/src/libtx/mod.rs, core/src/consensus.rs (Apache-2.0); see NOTICE
// and upstream.toml.

//! Transaction weights and the fee rule, equal to the node's `TransactionBody::weight`,
//! `weight_as_block` and `libtx::tx_fee`.

use crate::amount::{ArithmeticError, Fee};
use crate::params::{BLOCK_INPUT_WEIGHT, BLOCK_KERNEL_WEIGHT, BLOCK_OUTPUT_WEIGHT};

/// Item counts of a transaction or block body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BodyCounts {
    pub inputs: u64,
    pub outputs: u64,
    pub kernels: u64,
}

impl BodyCounts {
    pub const fn new(inputs: u64, outputs: u64, kernels: u64) -> Self {
        Self {
            inputs,
            outputs,
            kernels,
        }
    }

    /// Fee weight: `max(4 * outputs + kernels - inputs, 1)`, each step saturating. It rewards
    /// spending many inputs and is not a consensus value.
    pub fn tx_weight(self) -> u64 {
        self.outputs
            .saturating_mul(4)
            .saturating_add(self.kernels)
            .saturating_sub(self.inputs)
            .max(1)
    }

    /// Consensus weight, compared with the block and transaction weight limits. Saturates.
    pub fn weight_as_block(self) -> u64 {
        self.inputs
            .saturating_mul(BLOCK_INPUT_WEIGHT)
            .saturating_add(self.outputs.saturating_mul(BLOCK_OUTPUT_WEIGHT))
            .saturating_add(self.kernels.saturating_mul(BLOCK_KERNEL_WEIGHT))
    }

    /// The fee `epic-wallet` charges and expects: fee weight times `base_fee`.
    pub fn tx_fee(self, base_fee: Fee) -> Result<Fee, ArithmeticError> {
        self.tx_weight()
            .checked_mul(base_fee.value())
            .map(Fee::new)
            .ok_or(ArithmeticError::Overflow)
    }
}
