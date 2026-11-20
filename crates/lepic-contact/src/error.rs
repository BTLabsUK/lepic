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
