// SPDX-License-Identifier: Apache-2.0
use crate::error::{DecodeError, Malformed};

/// The chain a format belongs to; its byte keeps mainnet and floonet data apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    pub fn byte(self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Floonet => 0x01,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Mainnet),
            0x01 => Some(Self::Floonet),
            _ => None,
        }
    }

    /// Checks a network byte read from input against the network the reader expects.
    pub fn expect_byte(self, byte: u8) -> Result<(), DecodeError> {
        match Self::from_byte(byte) {
            Some(found) if found == self => Ok(()),
            Some(_) => Err(DecodeError::WrongNetwork),
            None => Err(Malformed::Network { byte }.into()),
        }
    }
}
