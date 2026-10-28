// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/lifecycle/seed.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Argon2id parameters and the vault key they derive from a password.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use thiserror::Error;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Upper bounds on parameters read from a vault file or sealed text, so a crafted header cannot
/// demand more memory or time than LEPIC itself spends. They are the largest settings LEPIC
/// writes: [`KdfParams::DEFAULT`] and the candidates its Argon2 benchmark measures. The Argon2
/// implementation runs lanes one after another, so the lane count adds no memory or time.
pub const MAX_MEMORY_KIB: u32 = 128 * 1024;
pub const MAX_ITERATIONS: u32 = 4;
pub const MAX_PARALLELISM: u32 = 8;

/// The least memory a new vault's key derivation may use: 19 MiB, the smallest setting OWASP
/// recommends for Argon2id. Files with weaker parameters still open; LEPIC only refuses to write
/// them.
pub const MIN_WRITE_MEMORY_KIB: u32 = 19 * 1024;
/// The least memory times passes a new vault's key derivation may use: 19 MiB with two passes,
/// so one pass needs at least 38 MiB. OWASP's 46 MiB with one pass and 19 MiB with two passes
/// both meet it.
pub const MIN_WRITE_COST_KIB: u32 = MIN_WRITE_MEMORY_KIB * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "argon2id parameters m={memory_kib} KiB t={iterations} p={parallelism} are outside the \
     supported range"
)]
pub struct KdfParamsError {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Argon2id version 0x13 cost parameters.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    /// Set only by [`KdfParams::for_tests`]: the vault may write these below the floor.
    below_floor_allowed: bool,
}

/// Equal when the cost parameters are; whether they came from [`KdfParams::for_tests`] does
/// not matter, so a vault reopened from its file reports the parameters it was created with.
impl PartialEq for KdfParams {
    fn eq(&self, other: &Self) -> bool {
        (self.memory_kib, self.iterations, self.parallelism)
            == (other.memory_kib, other.iterations, other.parallelism)
    }
}

impl Eq for KdfParams {}

impl KdfParams {
    /// The parameters new vaults use. `docs/spikes/k-03-argon2.md` records how they were chosen.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
        below_floor_allowed: false,
    };

    /// Accepts any setting Argon2 allows (at least 8 KiB per lane, one pass, one lane) up to the
    /// `MAX_*` bounds, so every vault LEPIC can read opens. A new vault or a rekey takes only
    /// parameters that also meet the write floor ([`KdfParams::meets_write_floor`]).
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, KdfParamsError> {
        let error = KdfParamsError {
            memory_kib,
            iterations,
            parallelism,
        };
        let lanes_fit = parallelism
            .checked_mul(8)
            .is_some_and(|minimum| memory_kib >= minimum);
        if !(1..=MAX_PARALLELISM).contains(&parallelism)
            || !(1..=MAX_ITERATIONS).contains(&iterations)
            || memory_kib > MAX_MEMORY_KIB
            || !lanes_fit
        {
            return Err(error);
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
            below_floor_allowed: false,
        })
    }

    /// Parameters a vault may write even below the floor, so tests of the layers above stay
    /// fast. Only with the `test-kdf` feature, which app builds never enable.
    #[cfg(any(test, feature = "test-kdf"))]
    pub fn for_tests(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, KdfParamsError> {
        Ok(Self {
            below_floor_allowed: true,
            ..Self::new(memory_kib, iterations, parallelism)?
        })
    }

    /// Whether a new vault may use these parameters: at least [`MIN_WRITE_MEMORY_KIB`] of
    /// memory and [`MIN_WRITE_COST_KIB`] of memory times passes.
    pub fn meets_write_floor(&self) -> bool {
        self.memory_kib >= MIN_WRITE_MEMORY_KIB
            && self
                .memory_kib
                .checked_mul(self.iterations)
                .is_none_or(|cost| cost >= MIN_WRITE_COST_KIB)
    }

    /// Whether [`crate::Vault::create`] and [`crate::Vault::rekey`] may write these parameters.
    pub(crate) fn writable(&self) -> bool {
        self.below_floor_allowed || self.meets_write_floor()
    }

    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    pub(crate) fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> Result<VaultKey, argon2::Error> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
            password,
            salt,
            key.as_mut_slice(),
        )?;
        Ok(VaultKey(key))
    }
}

/// The XChaCha20-Poly1305 key of one vault. Wiped on drop and never printed.
pub(crate) struct VaultKey(Zeroizing<[u8; KEY_LEN]>);

impl VaultKey {
    /// Builds the cipher from the key in place; the cipher wipes its copy on drop.
    pub(crate) fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.0).into())
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_argon2_minimum_and_the_bounds() {
        for (m, t, p) in [
            (8, 1, 1),
            (64, 1, 8),
            (MAX_MEMORY_KIB, MAX_ITERATIONS, MAX_PARALLELISM),
        ] {
            let params = KdfParams::new(m, t, p).unwrap();
            assert_eq!(
                (
                    params.memory_kib(),
                    params.iterations(),
                    params.parallelism()
                ),
                (m, t, p)
            );
        }
    }

    #[test]
    fn rejects_parameters_outside_the_range() {
        for (m, t, p) in [
            (7, 1, 1),
            (63, 1, 8),
            (MAX_MEMORY_KIB + 1, 1, 1),
            (8, 0, 1),
            (8, MAX_ITERATIONS + 1, 1),
            (8, 1, 0),
            (u32::MAX, 1, MAX_PARALLELISM + 1),
        ] {
            assert_eq!(
                KdfParams::new(m, t, p),
                Err(KdfParamsError {
                    memory_kib: m,
                    iterations: t,
                    parallelism: p
                })
            );
        }
    }

    #[test]
    fn default_is_in_range() {
        let default = KdfParams::DEFAULT;
        assert_eq!(
            KdfParams::new(
                default.memory_kib(),
                default.iterations(),
                default.parallelism()
            ),
            Ok(default)
        );
    }

    #[test]
    fn derives_the_same_key_only_from_the_same_inputs() {
        let params = KdfParams::new(32, 3, 4).unwrap();
        let a = params.derive_key(b"password", &[1; SALT_LEN]).unwrap();
        let b = params.derive_key(b"password", &[1; SALT_LEN]).unwrap();
        let c = params.derive_key(b"password", &[2; SALT_LEN]).unwrap();
        assert_eq!(*a.0, *b.0);
        assert_ne!(*a.0, *c.0);
        assert_eq!(format!("{a:?}"), "VaultKey([redacted])");
    }
}
