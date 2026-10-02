//! Key identifiers: a derivation depth and up to four BIP32 path components in 17 bytes.

use std::fmt;

use lepic_primitives::ser::{Readable, Reader, SerError, Writeable, Writer};
use thiserror::Error;

use crate::bip32::ChildNumber;

/// Deepest path an identifier can hold.
pub const MAX_DEPTH: u8 = 4;

const COMPONENTS: usize = MAX_DEPTH as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IdentifierError {
    #[error("identifier has {actual} bytes, expected 17")]
    WrongLength { actual: usize },
    #[error("identifier is not valid hex")]
    InvalidHex,
    #[error("identifier depth {depth} exceeds the maximum of 4")]
    DepthTooLarge { depth: u8 },
}

/// A derivation path, serialized as the depth (u8) followed by four big-endian `u32` components.
///
/// Components past the depth are carried as they are, because upstream keeps them in the bytes it
/// stores and hashes. Only the first `depth` components take part in derivation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier([u8; Identifier::LEN]);

impl Identifier {
    pub const LEN: usize = 17;

    /// The master key, `m`.
    pub const ROOT: Self = Self([0; Self::LEN]);

    pub fn new(depth: u8, components: [u32; COMPONENTS]) -> Result<Self, IdentifierError> {
        if depth > MAX_DEPTH {
            return Err(IdentifierError::DepthTooLarge { depth });
        }
        Ok(Self::encode(depth, components))
    }

    fn encode(depth: u8, components: [u32; COMPONENTS]) -> Self {
        let mut bytes = [0u8; Self::LEN];
        bytes[0] = depth;
        for (chunk, component) in bytes[1..].as_chunks_mut::<4>().0.iter_mut().zip(components) {
            *chunk = component.to_be_bytes();
        }
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentifierError> {
        let array =
            <[u8; Self::LEN]>::try_from(bytes).map_err(|_| IdentifierError::WrongLength {
                actual: bytes.len(),
            })?;
        let [depth, ..] = array;
        if depth > MAX_DEPTH {
            return Err(IdentifierError::DepthTooLarge { depth });
        }
        Ok(Self(array))
    }

    pub fn from_hex(hex: &str) -> Result<Self, IdentifierError> {
        let digits = hex.as_bytes();
        if digits.len() != Self::LEN * 2 {
            return Err(IdentifierError::WrongLength {
                actual: digits.len() / 2,
            });
        }
        let mut bytes = [0u8; Self::LEN];
        let (pairs, _) = digits.as_chunks::<2>();
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = nibble(*high)?.wrapping_shl(4) | nibble(*low)?;
        }
        Self::from_bytes(&bytes)
    }

    /// Restores an identifier from a depth and the 16 path bytes that follow it, as proof
    /// messages carry them.
    pub fn from_serialized_path(depth: u8, path: [u8; 16]) -> Result<Self, IdentifierError> {
        let mut bytes = [0u8; Self::LEN];
        bytes[0] = depth;
        bytes[1..].copy_from_slice(&path);
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut hex = String::with_capacity(Self::LEN * 2);
        for byte in self.0 {
            for value in [byte >> 4, byte & 0x0f] {
                if let Some(digit) = DIGITS.get(usize::from(value)) {
                    hex.push(char::from(*digit));
                }
            }
        }
        hex
    }

    /// The 16 path bytes without the depth.
    pub fn serialize_path(&self) -> [u8; 16] {
        let mut path = [0u8; 16];
        path.copy_from_slice(&self.0[1..]);
        path
    }

    pub fn depth(&self) -> u8 {
        self.0[0]
    }

    /// All four components, including those past the depth.
    pub fn components(&self) -> [u32; COMPONENTS] {
        let mut components = [0u32; COMPONENTS];
        for (component, chunk) in components.iter_mut().zip(self.0[1..].as_chunks::<4>().0) {
            *component = u32::from_be_bytes(*chunk);
        }
        components
    }

    /// The components that take part in derivation, from the master key down.
    pub fn path(&self) -> impl Iterator<Item = ChildNumber> {
        self.components()
            .into_iter()
            .take(usize::from(self.depth()))
            .map(ChildNumber::from)
    }

    /// The identifier one level up, with the dropped component zeroed. The root is its own parent.
    pub fn parent(&self) -> Self {
        let Some(parent_depth) = self.depth().checked_sub(1) else {
            return *self;
        };
        let mut components = self.components();
        if let Some(dropped) = components.get_mut(usize::from(parent_depth)) {
            *dropped = 0;
        }
        Self::encode(parent_depth, components)
    }

    /// The last component that takes part in derivation, or 0 for the root.
    pub fn last_path_index(&self) -> u32 {
        self.path().last().map_or(0, u32::from)
    }

    /// Upstream's `to_bip_32_string`, which prints hardened components as their raw `u32`.
    pub fn to_bip32_path(&self) -> String {
        let mut path = String::from("m");
        for child in self.path() {
            path.push('/');
            path.push_str(&u32::from(child).to_string());
        }
        path
    }
}

fn nibble(digit: u8) -> Result<u8, IdentifierError> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(IdentifierError::InvalidHex)
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identifier({})", self.to_hex())
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Writeable for Identifier {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_fixed_bytes(&self.0);
    }
}

impl Readable for Identifier {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        let bytes = reader.read_array::<{ Self::LEN }>()?;
        Self::from_bytes(&bytes).map_err(|_| SerError::Invalid {
            type_name: "identifier",
        })
    }
}
