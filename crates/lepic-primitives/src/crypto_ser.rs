//! Binary encodings of the crypto types, as the node's `core::ser` writes them, and the
//! [`BlindingFactor`] that transactions carry as their offset.
//!
//! Decoding is stricter than upstream where upstream would accept bytes that can never verify:
//! commitments and public keys must be curve points, and a range proof must have between one and
//! [`RangeProof::MAX_LEN`] bytes.

use std::fmt;

use lepic_crypto::hex::{self, HexError};
use lepic_crypto::{Commitment, CryptoError, PublicKey, RangeProof, SecretKey, Signature};
use zeroize::Zeroizing;

use crate::ser::{Readable, Reader, SerError, Writeable, Writer};

impl Writeable for Commitment {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_fixed_bytes(self.as_bytes());
    }
}

impl Readable for Commitment {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        let bytes = reader.read_array::<{ Commitment::LEN }>()?;
        Commitment::from_bytes(&bytes).map_err(|_| SerError::Invalid {
            type_name: "commitment",
        })
    }
}

impl Writeable for PublicKey {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_fixed_bytes(&self.to_bytes());
    }
}

impl Readable for PublicKey {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        let bytes = reader.read_array::<{ PublicKey::LEN }>()?;
        PublicKey::from_bytes(&bytes).map_err(|_| SerError::Invalid {
            type_name: "public key",
        })
    }
}

// The binary format carries the wrapper's raw signature bytes, not the compact form JSON uses.
impl Writeable for Signature {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_fixed_bytes(&self.to_raw());
    }
}

impl Readable for Signature {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        let bytes = reader.read_array::<{ Signature::LEN }>()?;
        Signature::from_raw(&bytes).map_err(|_| SerError::Invalid {
            type_name: "signature",
        })
    }
}

impl Writeable for RangeProof {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_bytes(self.as_bytes());
    }
}

impl Readable for RangeProof {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        let bytes = reader.read_bytes_len_prefix(RangeProof::MAX_LEN)?;
        RangeProof::from_bytes(bytes).map_err(|_| SerError::Invalid {
            type_name: "range proof",
        })
    }
}

/// A 32-byte blinding factor such as a transaction offset.
///
/// Unlike [`SecretKey`] it may be zero or not below the curve order, because upstream encodes and
/// sums such values; [`BlindingFactor::to_secret_key`] checks before any curve operation. The
/// bytes are wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindingFactor(Zeroizing<[u8; BlindingFactor::LEN]>);

impl BlindingFactor {
    pub const LEN: usize = 32;

    pub fn zero() -> Self {
        Self::from_array([0; Self::LEN])
    }

    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlindingFactorError> {
        <[u8; Self::LEN]>::try_from(bytes)
            .map(Self::from_array)
            .map_err(|_| BlindingFactorError::WrongLength {
                actual: bytes.len(),
            })
    }

    /// Parses exactly 64 hex digits in either case.
    pub fn from_hex(text: &str) -> Result<Self, BlindingFactorError> {
        let mut bytes = Zeroizing::new([0u8; Self::LEN]);
        hex::decode_into(text, bytes.as_mut_slice()).map_err(|error| match error {
            HexError::InvalidDigit { .. } => BlindingFactorError::InvalidHex,
            _ => BlindingFactorError::WrongHexLength { actual: text.len() },
        })?;
        Ok(Self(bytes))
    }

    /// Lowercase hex, as upstream JSON writes it.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_slice())
    }

    pub fn from_secret_key(key: &SecretKey) -> Self {
        Self::from_array(*key.expose_bytes())
    }

    /// The raw bytes. Callers must not log them or copy them into memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// The factor as a scalar. Fails for zero and for values not below the curve order.
    pub fn to_secret_key(&self) -> Result<SecretKey, CryptoError> {
        SecretKey::from_bytes(self.0.as_slice())
    }
}

impl Default for BlindingFactor {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlindingFactor([redacted])")
    }
}

impl Writeable for BlindingFactor {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_fixed_bytes(self.0.as_slice());
    }
}

impl Readable for BlindingFactor {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        reader.read_array().map(Self::from_array)
    }
}

/// Failure to build a [`BlindingFactor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlindingFactorError {
    #[error("blinding factor has {actual} bytes, expected 32")]
    WrongLength { actual: usize },
    #[error("blinding factor hex has {actual} digits, expected 64")]
    WrongHexLength { actual: usize },
    #[error("blinding factor is not valid hex")]
    InvalidHex,
}
