//! BLAKE2b-256 hashing of serialized values, compatible with the Epic node's `core::hash`.

use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::{Blake2b256, Blake2bMac};
use lepic_crypto::hex::{self, HexError};
use thiserror::Error;

use crate::ser::{
    ProtocolVersion, Readable, Reader, SerError, SerializationMode, Writeable, Writer,
};

/// Longest key BLAKE2b accepts.
pub const MAX_KEY_LEN: usize = 64;

/// The all-zero hash, used as a sentinel. It has no known preimage.
pub const ZERO_HASH: Hash = Hash([0; Hash::LEN]);

/// Failure to build a [`Hash`] or to start a keyed hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HashError {
    #[error("hash must be 32 bytes, got {len}")]
    InvalidLength { len: usize },
    #[error("hash hex must be 64 characters, got {len}")]
    InvalidHexLength { len: usize },
    #[error("invalid hex digit in byte {byte}")]
    InvalidHexDigit { byte: usize },
    #[error("blake2b key of {len} bytes exceeds 64")]
    KeyTooLong { len: usize },
}

/// A 32-byte BLAKE2b digest. Ordering is lexicographic over the bytes, as upstream sorts by it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash([u8; Hash::LEN]);

impl Hash {
    pub const LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashError> {
        <[u8; Self::LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| HashError::InvalidLength { len: bytes.len() })
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Lowercase hex, as the node prints hashes.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parses exactly 64 hex characters in either case.
    pub fn from_hex(text: &str) -> Result<Self, HashError> {
        hex::decode_array::<{ Self::LEN }>(text)
            .map(Self)
            .map_err(|error| match error {
                HexError::InvalidDigit { byte } => HashError::InvalidHexDigit { byte },
                _ => HashError::InvalidHexLength { len: text.len() },
            })
    }

    /// The most significant 64 bits, read big-endian.
    pub fn to_u64(&self) -> u64 {
        let [a, b, c, d, e, f, g, h, ..] = self.0;
        u64::from_be_bytes([a, b, c, d, e, f, g, h])
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.to_hex();
        f.write_str(hex.get(..12).unwrap_or(&hex))
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Writeable for Hash {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_fixed_bytes(&self.0);
    }
}

impl Readable for Hash {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        reader.read_array().map(Self)
    }
}

/// Writer that hashes what is written instead of storing it.
#[derive(Debug, Clone, Default)]
pub struct HashWriter {
    state: Blake2b256,
}

impl HashWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_hash(self) -> Hash {
        Hash(self.state.finalize_fixed().into())
    }
}

impl Writer for HashWriter {
    fn serialization_mode(&self) -> SerializationMode {
        SerializationMode::Hash
    }

    // Writers see version 2 here, the node's local version. A type whose hash encoding differs
    // from its version 2 encoding, such as kernel features, checks `serialization_mode()`.
    fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::V2
    }

    fn write_fixed_bytes(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
    }
}

/// A value with a canonical hash.
pub trait Hashed {
    fn hash(&self) -> Hash;
}

/// Marker for types whose hash is BLAKE2b-256 of their [`SerializationMode::Hash`] encoding.
pub trait DefaultHashable: Writeable {}

impl<T: DefaultHashable + ?Sized> Hashed for T {
    fn hash(&self) -> Hash {
        let mut writer = HashWriter::new();
        self.write(&mut writer);
        writer.into_hash()
    }
}

impl DefaultHashable for Hash {}
impl DefaultHashable for u8 {}
impl DefaultHashable for u64 {}
impl DefaultHashable for Vec<u8> {}
impl<T: DefaultHashable + ?Sized> DefaultHashable for &T {}
impl<A: DefaultHashable, B: DefaultHashable> DefaultHashable for (A, B) {}
impl<A: DefaultHashable, B: DefaultHashable, C: DefaultHashable> DefaultHashable for (A, B, C) {}

/// Unkeyed BLAKE2b with a 32-byte output, equal to `blake2_rfc::blake2b::blake2b(32, &[], data)`.
pub fn blake2b_256(data: &[u8]) -> Hash {
    let mut state = Blake2b256::default();
    state.update(data);
    Hash(state.finalize_fixed().into())
}

/// Keyed BLAKE2b with a 32-byte output, equal to `blake2_rfc::blake2b::blake2b(32, key, data)`.
/// An empty key gives the unkeyed hash, as in `blake2-rfc`.
pub fn blake2b_256_keyed(key: &[u8], data: &[u8]) -> Result<Hash, HashError> {
    if key.is_empty() {
        return Ok(blake2b_256(data));
    }
    // `KeyInit` would treat an empty key as a block of zeros, which `blake2-rfc` does not; the
    // empty case is handled above.
    let mut state = <Blake2bMac<blake2::digest::consts::U32> as KeyInit>::new_from_slice(key)
        .map_err(|_| HashError::KeyTooLong { len: key.len() })?;
    state.update(data);
    Ok(Hash(state.finalize_fixed().into()))
}

/// Checks that `items` are in strictly increasing hash order, as the node requires of inputs,
/// outputs and kernels.
pub fn verify_sorted_and_unique<T: Hashed>(items: &[T]) -> Result<(), SerError> {
    let hashes: Vec<Hash> = items.iter().map(Hashed::hash).collect();
    for pair in hashes.windows(2) {
        if let [previous, next] = pair {
            match previous.cmp(next) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(SerError::Duplicate),
                std::cmp::Ordering::Greater => return Err(SerError::NotSorted),
            }
        }
    }
    Ok(())
}
