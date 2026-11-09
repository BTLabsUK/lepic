// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

pub use lepic_seal::{DecodeError, EncodeError, KeyError, Malformed, TextError};

/// Why the SAS table could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SasTableError {
    #[error("sas table has no line {index}")]
    MissingLine { index: u8 },
    #[error("sas table line {index} is not emoji, tab, name")]
    BadLine { index: u8 },
    #[error("the symbol is not an entry of the sas table")]
    UnknownSymbol,
}

/// Why pairing words could not be read or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WordsError {
    #[error("the words are not five entries of the table")]
    Unknown,
    #[error("no invite opens with these words")]
    CannotOpen,
    #[error("stretching the words failed")]
    Derivation,
    #[error("sealing the invite failed")]
    Encryption,
}
