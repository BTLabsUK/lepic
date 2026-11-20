// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic core/src/consensus.rs (Apache-2.0); see NOTICE and upstream.toml.

use crate::error::{CryptoError, Item};

// The limits follow from Epic's consensus block weight, so every consensus-valid transaction fits
// while untrusted input cannot request unbounded work.
const MAX_BLOCK_WEIGHT: usize = 40_000;
const INPUT_WEIGHT: usize = 1;
const OUTPUT_WEIGHT: usize = 21;

/// Most terms, positive and negative together, in one commitment or blinding-factor sum.
pub const MAX_SUM_TERMS: usize = MAX_BLOCK_WEIGHT / INPUT_WEIGHT;

/// Most range proofs in one batch verification.
pub const MAX_PROOF_BATCH: usize = MAX_BLOCK_WEIGHT / OUTPUT_WEIGHT;

pub(crate) fn check_batch_len(len: usize, max: usize, item: Item) -> Result<(), CryptoError> {
    if len == 0 {
        Err(CryptoError::EmptyBatch { item })
    } else if len > max {
        Err(CryptoError::BatchTooLarge {
            item,
            max,
            actual: len,
        })
    } else {
        Ok(())
    }
}
