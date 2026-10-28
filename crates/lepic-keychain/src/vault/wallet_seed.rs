// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/lifecycle/seed.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Read-only import of the `wallet.seed` file `epic-wallet` writes. LEPIC never writes this
//! format (ADR 0005).
//!
//! Pretty-printed JSON `{ "encrypted_seed", "salt", "nonce" }`, each hex. The key is
//! PBKDF2-HMAC-SHA512 over the password with the 8-byte salt and 100 rounds; the seed is sealed
//! with ChaCha20-Poly1305 under the 12-byte nonce and empty associated data, tag appended.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag};
use lepic_crypto::hex;
use serde::Deserialize;
use sha2::Sha512;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::mnemonic::{MnemonicError, Seed};

pub const WALLET_SEED_SALT_LEN: usize = 8;
pub const WALLET_SEED_NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PBKDF2_ROUNDS: u32 = 100;
const MAX_SEED_LEN: usize = 32;

/// Far above the largest file `epic-wallet` writes (a 32-byte seed is under 200 bytes of JSON),
/// so a wrong file is rejected before it is parsed.
pub const MAX_WALLET_SEED_FILE_LEN: usize = 4096;

/// A field of the `wallet.seed` JSON that a [`WalletSeedError`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletSeedField {
    EncryptedSeed,
    Salt,
    Nonce,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletSeedError {
    #[error("wallet.seed has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("wallet.seed is not the expected json")]
    Json(#[source] serde_json::Error),
    #[error("wallet.seed field {field:?} is not hex")]
    InvalidHex { field: WalletSeedField },
    #[error("wallet.seed field {field:?} has {actual} bytes, expected {expected}")]
    WrongLength {
        field: WalletSeedField,
        expected: usize,
        actual: usize,
    },
    #[error("wallet.seed did not decrypt with this password")]
    Decryption,
    #[error("wallet.seed holds a seed lepic cannot use")]
    Seed(#[source] MnemonicError),
}

#[derive(Deserialize)]
struct WalletSeedJson {
    encrypted_seed: String,
    salt: String,
    nonce: String,
}

/// A parsed `wallet.seed`, still encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSeedFile {
    sealed: Vec<u8>,
    salt: [u8; WALLET_SEED_SALT_LEN],
    nonce: [u8; WALLET_SEED_NONCE_LEN],
}

impl WalletSeedFile {
    /// Parses the file text. Unknown keys are ignored, as `epic-wallet` ignores them.
    pub fn parse(text: &str) -> Result<Self, WalletSeedError> {
        if text.len() > MAX_WALLET_SEED_FILE_LEN {
            return Err(WalletSeedError::TooLong {
                actual: text.len(),
                max: MAX_WALLET_SEED_FILE_LEN,
            });
        }
        let json: WalletSeedJson = serde_json::from_str(text).map_err(WalletSeedError::Json)?;
        let sealed = hex_decode(&json.encrypted_seed, WalletSeedField::EncryptedSeed)?;
        let max_sealed = MAX_SEED_LEN.saturating_add(TAG_LEN);
        if sealed.len() <= TAG_LEN || sealed.len() > max_sealed {
            return Err(WalletSeedError::WrongLength {
                field: WalletSeedField::EncryptedSeed,
                expected: max_sealed,
                actual: sealed.len(),
            });
        }
        Ok(Self {
            sealed,
            salt: hex_decode_array(&json.salt, WalletSeedField::Salt)?,
            nonce: hex_decode_array(&json.nonce, WalletSeedField::Nonce)?,
        })
    }

    /// Decrypts the seed. A wrong password and a tampered file both fail with
    /// [`WalletSeedError::Decryption`]; the cipher cannot tell them apart.
    pub fn decrypt(&self, password: &[u8]) -> Result<Seed, WalletSeedError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha512>(password, &self.salt, PBKDF2_ROUNDS, key.as_mut_slice());
        let cipher = ChaCha20Poly1305::new((&*key).into());

        let body_len = self
            .sealed
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(WalletSeedError::Decryption)?;
        let (body, tag) = self.sealed.split_at(body_len);
        let tag = Tag::try_from(tag).map_err(|_| WalletSeedError::Decryption)?;
        let mut entropy = Zeroizing::new(body.to_vec());
        cipher
            .decrypt_inout_detached(&self.nonce.into(), &[], entropy.as_mut_slice().into(), &tag)
            .map_err(|_| WalletSeedError::Decryption)?;
        Seed::from_entropy(&entropy).map_err(WalletSeedError::Seed)
    }
}

/// Upper or lower case, no prefix, as `epic-wallet` writes.
fn hex_decode(text: &str, field: WalletSeedField) -> Result<Vec<u8>, WalletSeedError> {
    hex::decode_bounded(text, 0, usize::MAX).map_err(|_| WalletSeedError::InvalidHex { field })
}

fn hex_decode_array<const N: usize>(
    text: &str,
    field: WalletSeedField,
) -> Result<[u8; N], WalletSeedError> {
    let bytes = hex_decode(text, field)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| WalletSeedError::WrongLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(encrypted_seed: &str, salt: &str, nonce: &str) -> String {
        format!(r#"{{"encrypted_seed": "{encrypted_seed}", "salt": "{salt}", "nonce": "{nonce}"}}"#)
    }

    const SEALED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const SALT: &str = "0011223344556677";
    const NONCE: &str = "00112233445566778899aabb";

    #[test]
    fn rejects_files_over_the_limit_before_parsing() {
        let text = " ".repeat(MAX_WALLET_SEED_FILE_LEN + 1);
        assert!(matches!(
            WalletSeedFile::parse(&text),
            Err(WalletSeedError::TooLong { actual, .. }) if actual == MAX_WALLET_SEED_FILE_LEN + 1
        ));
    }

    #[test]
    fn rejects_truncated_or_incomplete_json() {
        let full = file(SEALED, SALT, NONCE);
        for len in [0, 1, full.len() / 2, full.len() - 1] {
            assert!(
                matches!(
                    WalletSeedFile::parse(&full[..len]),
                    Err(WalletSeedError::Json(_))
                ),
                "{len}"
            );
        }
        let missing_nonce = format!(r#"{{"encrypted_seed": "{SEALED}", "salt": "{SALT}"}}"#);
        assert!(matches!(
            WalletSeedFile::parse(&missing_nonce),
            Err(WalletSeedError::Json(_))
        ));
    }

    #[test]
    fn rejects_fields_that_are_not_hex() {
        for (text, field) in [
            (file("zz", SALT, NONCE), WalletSeedField::EncryptedSeed),
            (
                file(SEALED, "0x11223344556677", NONCE),
                WalletSeedField::Salt,
            ),
            (
                file(SEALED, SALT, "00112233445566778899aab"),
                WalletSeedField::Nonce,
            ),
        ] {
            assert!(matches!(
                WalletSeedFile::parse(&text),
                Err(WalletSeedError::InvalidHex { field: actual }) if actual == field
            ));
        }
    }

    #[test]
    fn rejects_fields_of_the_wrong_length() {
        let short_tag = &SEALED[..32];
        let long_seed = "00".repeat(MAX_SEED_LEN + TAG_LEN + 1);
        for (text, field) in [
            (file(short_tag, SALT, NONCE), WalletSeedField::EncryptedSeed),
            (
                file(&long_seed, SALT, NONCE),
                WalletSeedField::EncryptedSeed,
            ),
            (file(SEALED, "00112233445566", NONCE), WalletSeedField::Salt),
            (
                file(SEALED, SALT, "00112233445566778899aabbcc"),
                WalletSeedField::Nonce,
            ),
        ] {
            assert!(matches!(
                WalletSeedFile::parse(&text),
                Err(WalletSeedError::WrongLength { field: actual, .. }) if actual == field
            ));
        }
    }

    #[test]
    fn accepts_upper_case_hex() {
        let upper = file(
            &SEALED.to_uppercase(),
            &SALT.to_uppercase(),
            &NONCE.to_uppercase(),
        );
        assert_eq!(
            WalletSeedFile::parse(&upper).unwrap(),
            WalletSeedFile::parse(&file(SEALED, SALT, NONCE)).unwrap()
        );
    }
}
