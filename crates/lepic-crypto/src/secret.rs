use std::fmt;

use secp256k1zkp::constants::SECRET_KEY_SIZE;
use secp256k1zkp::key::SecretKey as BackendSecretKey;
use zeroize::Zeroizing;

use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::item_hex;

/// A non-zero scalar below the secp256k1 curve order: a private key, blinding factor or nonce.
///
/// The bytes are wiped on drop and never printed.
#[derive(Clone)]
pub struct SecretKey(BackendSecretKey);

impl SecretKey {
    pub const LEN: usize = SECRET_KEY_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LEN {
            return Err(CryptoError::WrongLength {
                item: Item::SecretKey,
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        BackendSecretKey::from_slice(secp(), bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    pub fn from_array(bytes: [u8; SECRET_KEY_SIZE]) -> Result<Self, CryptoError> {
        let bytes = Zeroizing::new(bytes);
        Self::from_bytes(bytes.as_slice())
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        item_hex::decode_into(hex, bytes.as_mut_slice(), Item::SecretKey)?;
        Self::from_bytes(bytes.as_slice())
    }

    /// The raw scalar, for hashing and serialization. Callers must not log or copy it into
    /// memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.0.0
    }

    pub(crate) fn from_backend(key: &BackendSecretKey) -> Result<Self, CryptoError> {
        Self::from_bytes(&key.0)
    }

    pub(crate) fn as_backend(&self) -> &BackendSecretKey {
        &self.0
    }

    pub(crate) fn to_backend(&self) -> BackendSecretKey {
        self.0.clone()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

/// The 32-byte X coordinate of an ECDH shared point. Wiped on drop and never printed.
pub struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    pub const LEN: usize = 32;

    /// All zero, to be filled in place so the secret is never held in an unwiped temporary.
    pub(crate) fn zeroed() -> Self {
        Self(Zeroizing::new([0u8; Self::LEN]))
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; Self::LEN] {
        &mut self.0
    }

    pub fn expose_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDER: [u8; 32] = secp256k1zkp::constants::CURVE_ORDER;

    #[test]
    fn accepts_one() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        assert!(SecretKey::from_array(bytes).is_ok());
    }

    #[test]
    fn rejects_secret_key_of_the_wrong_length() {
        assert_eq!(
            SecretKey::from_bytes(&[1u8; 31]).err(),
            Some(CryptoError::WrongLength {
                item: Item::SecretKey,
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            SecretKey::from_bytes(&[1u8; 33]).err(),
            Some(CryptoError::WrongLength {
                item: Item::SecretKey,
                expected: 32,
                actual: 33
            })
        );
    }

    #[test]
    fn rejects_zero_secret_key() {
        assert_eq!(
            SecretKey::from_array([0u8; 32]).err(),
            Some(CryptoError::InvalidSecretKey)
        );
    }

    #[test]
    fn rejects_secret_key_at_or_above_the_curve_order() {
        assert_eq!(
            SecretKey::from_array(ORDER).err(),
            Some(CryptoError::InvalidSecretKey)
        );
        assert_eq!(
            SecretKey::from_array([0xff; 32]).err(),
            Some(CryptoError::InvalidSecretKey)
        );
    }

    #[test]
    fn accepts_largest_secret_key_below_the_curve_order() {
        let mut bytes = ORDER;
        bytes[31] -= 1;
        assert!(SecretKey::from_array(bytes).is_ok());
    }

    #[test]
    fn parses_secret_key_hex_in_either_case() {
        let hex = format!("{}0A", "00".repeat(31));
        let key = SecretKey::from_hex(&hex).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 10;
        assert_eq!(key.expose_bytes(), &expected);
        assert_eq!(
            SecretKey::from_hex(&hex.to_lowercase())
                .unwrap()
                .expose_bytes(),
            &expected
        );
    }

    #[test]
    fn rejects_secret_key_hex_with_bad_digits_or_a_zero_scalar() {
        assert_eq!(
            SecretKey::from_hex(&format!("{}zz", "00".repeat(31))).err(),
            Some(CryptoError::InvalidHex {
                item: Item::SecretKey
            })
        );
        assert_eq!(
            SecretKey::from_hex(&"00".repeat(32)).err(),
            Some(CryptoError::InvalidSecretKey)
        );
    }

    #[test]
    fn rejects_secret_key_hex_of_the_wrong_length() {
        assert_eq!(
            SecretKey::from_hex("01").err(),
            Some(CryptoError::WrongLength {
                item: Item::SecretKey,
                expected: 32,
                actual: 1
            })
        );
    }

    #[test]
    fn redacts_secret_key_in_debug() {
        let key = SecretKey::from_array([7u8; 32]).unwrap();
        let printed = format!("{key:?}");
        assert_eq!(printed, "SecretKey([redacted])");
        assert!(!printed.contains("0707"));
    }

    #[test]
    fn redacts_shared_secret_in_debug() {
        let mut secret = SharedSecret::zeroed();
        secret.as_mut_bytes().fill(7);
        assert_eq!(format!("{secret:?}"), "SharedSecret([redacted])");
    }
}
