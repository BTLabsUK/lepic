// SPDX-License-Identifier: Apache-2.0
// Each test binary uses a different part of these helpers, and helpers outside `#[test]`
// functions are test code too.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};

/// Plays `script` first, then a SHA-256 counter stream from `seed`, so a test fixes exactly the
/// bytes HPKE draws (the ephemeral key's ikm) and stays reproducible after them.
pub struct ScriptedRng {
    script: Vec<u8>,
    seed: u8,
    counter: u64,
    pending: Vec<u8>,
}

impl ScriptedRng {
    pub fn new(script: &[u8]) -> Self {
        Self {
            script: script.iter().rev().copied().collect(),
            seed: 0,
            counter: 0,
            pending: Vec::new(),
        }
    }

    pub fn seeded(seed: u8) -> Self {
        Self {
            script: Vec::new(),
            seed,
            counter: 0,
            pending: Vec::new(),
        }
    }

    fn next_byte(&mut self) -> u8 {
        if let Some(byte) = self.script.pop() {
            return byte;
        }
        if self.pending.is_empty() {
            let block = Sha256::new()
                .chain_update([self.seed])
                .chain_update(self.counter.to_be_bytes())
                .finalize();
            self.counter += 1;
            self.pending = block.iter().rev().copied().collect();
        }
        self.pending.pop().unwrap()
    }
}

impl TryRng for ScriptedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst {
            *byte = self.next_byte();
        }
        Ok(())
    }
}

impl TryCryptoRng for ScriptedRng {}

pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
