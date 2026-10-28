// Portions Copyright 2019 The Grin Developers
// Ported from EpicCash/epic keychain/src/mnemonic.rs (Apache-2.0); see NOTICE and upstream.toml.

//! BIP39 English mnemonics and the wallet seed they encode.
//!
//! The wallet seed is the BIP39 entropy itself, not the PBKDF2 seed BIP39 defines, because that is
//! what `epic-wallet` feeds to the keychain.

use std::fmt;

use bip39::{Language, Mnemonic};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Entropy lengths in bytes that map to 12, 15, 18, 21 and 24 words.
const ENTROPY_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];

const MAX_ENTROPY_LEN: usize = 32;

/// Long enough for 24 words of the longest English word (8 letters) and their separators, so the
/// phrase buffer is never reallocated and no unwiped copy is left behind.
const MAX_PHRASE_LEN: usize = 24 * 9;

/// Why a mnemonic or entropy was rejected. Variants never carry the words themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MnemonicError {
    #[error("mnemonic has {actual} words, expected 12, 15, 18, 21 or 24")]
    WordCount { actual: usize },
    #[error("mnemonic word {position} is not in the english word list")]
    UnknownWord { position: usize },
    #[error("mnemonic checksum does not match")]
    Checksum,
    #[error("entropy has {actual} bytes, expected 16, 20, 24, 28 or 32")]
    EntropyLength { actual: usize },
}

impl From<bip39::Error> for MnemonicError {
    fn from(error: bip39::Error) -> Self {
        match error {
            bip39::Error::BadWordCount(actual) => Self::WordCount { actual },
            bip39::Error::UnknownWord(position) => Self::UnknownWord { position },
            bip39::Error::BadEntropyBitCount(bits) => Self::EntropyLength { actual: bits / 8 },
            // Only English is enabled, so a phrase cannot match several languages; a checksum
            // failure is the remaining case.
            bip39::Error::InvalidChecksum | bip39::Error::AmbiguousLanguages(_) => Self::Checksum,
        }
    }
}

/// The wallet seed: 16 to 32 bytes of BIP39 entropy. Wiped on drop and never printed.
#[derive(Clone)]
pub struct Seed {
    bytes: Zeroizing<[u8; MAX_ENTROPY_LEN]>,
    len: usize,
}

impl Seed {
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, MnemonicError> {
        if !ENTROPY_LENGTHS.contains(&entropy.len()) {
            return Err(MnemonicError::EntropyLength {
                actual: entropy.len(),
            });
        }
        let mut bytes = Zeroizing::new([0u8; MAX_ENTROPY_LEN]);
        let target = bytes
            .get_mut(..entropy.len())
            .ok_or(MnemonicError::EntropyLength {
                actual: entropy.len(),
            })?;
        target.copy_from_slice(entropy);
        Ok(Self {
            bytes,
            len: entropy.len(),
        })
    }

    /// Parses an English phrase. Words are separated by any run of whitespace and must be
    /// lowercase, as upstream requires.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, MnemonicError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)?;
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let seed = entropy
            .get(..len)
            .ok_or(MnemonicError::EntropyLength { actual: len })
            .and_then(Self::from_entropy);
        entropy.zeroize();
        seed
    }

    /// The phrase, words separated by single spaces.
    pub fn to_mnemonic(&self) -> Result<Zeroizing<String>, MnemonicError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, self.expose_bytes())?;
        let mut phrase = Zeroizing::new(String::with_capacity(MAX_PHRASE_LEN));
        for (position, word) in mnemonic.words().enumerate() {
            if position > 0 {
                phrase.push(' ');
            }
            phrase.push_str(word);
        }
        Ok(phrase)
    }

    pub fn word_count(&self) -> usize {
        self.len.saturating_mul(3) / 4
    }

    /// The entropy bytes. Callers must not log them or copy them into memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_entropy_of_unsupported_length() {
        for len in [0, 15, 17, 33] {
            assert_eq!(
                Seed::from_entropy(&vec![0u8; len]).err(),
                Some(MnemonicError::EntropyLength { actual: len })
            );
        }
    }

    #[test]
    fn redacts_seed_in_debug() {
        let seed = Seed::from_entropy(&[0x5a; 16]).unwrap();
        assert_eq!(format!("{seed:?}"), "Seed([redacted])");
    }

    #[test]
    fn counts_words_from_entropy_length() {
        for (len, words) in [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)] {
            assert_eq!(
                Seed::from_entropy(&vec![1u8; len]).unwrap().word_count(),
                words
            );
        }
    }
}
