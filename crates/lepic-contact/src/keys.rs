use std::fmt;

use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::KeyError;

/// Any clamped scalar sends exactly the small-order points to the all-zero output.
const SMALL_ORDER_PROBE: [u8; 32] = [0x01; 32];

/// An X25519 public key that envelopes may be sealed to: never of small order, so the HPKE
/// Diffie-Hellman output cannot be all zeros.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncPublicKey([u8; 32]);

impl EncPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        if x25519(SMALL_ORDER_PROBE, bytes) == [0; 32] {
            return Err(KeyError::SmallOrder);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EncPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncPublicKey(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// An X25519 private key that opens envelopes. The bytes are used as given; X25519 clamps them.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncSecretKey([u8; 32]);

impl EncSecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn public_key(&self) -> EncPublicKey {
        // A clamped non-zero scalar times the base point has the large prime order.
        EncPublicKey(x25519(self.0, X25519_BASEPOINT_BYTES))
    }
}

impl fmt::Debug for EncSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncSecretKey(<redacted>)")
    }
}

/// The key a contact uses to tag envelopes for us so we find the opening key fast (RFC 0002 3.2).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HintKey([u8; 32]);

impl HintKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HintKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical encodings of the points of order 1, 2, 4 and 8 (RFC 7748 errata, libsodium
    /// blocklist), plus the non-canonical ones that reduce to them.
    pub(crate) const SMALL_ORDER_POINTS: [[u8; 32]; 7] = [
        [0; 32],
        {
            let mut one = [0; 32];
            one[0] = 1;
            one
        },
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    #[test]
    fn rejects_small_order_public_keys() {
        for point in SMALL_ORDER_POINTS {
            assert_eq!(
                EncPublicKey::from_bytes(point),
                Err(KeyError::SmallOrder),
                "{point:02x?}"
            );
        }
    }

    #[test]
    fn accepts_a_derived_public_key() {
        let public = EncSecretKey::from_bytes([7; 32]).public_key();
        assert_eq!(EncPublicKey::from_bytes(*public.as_bytes()), Ok(public));
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", EncSecretKey::from_bytes([7; 32])),
            "EncSecretKey(<redacted>)"
        );
    }
}
