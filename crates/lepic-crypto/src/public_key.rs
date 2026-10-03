use std::fmt;

use secp256k1zkp::constants::COMPRESSED_PUBLIC_KEY_SIZE;
use secp256k1zkp::key::PublicKey as BackendPublicKey;
use zeroize::Zeroize;

use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::hex;
use crate::limits::{MAX_SUM_TERMS, check_batch_len};
use crate::secret::{SecretKey, SharedSecret};

/// A secp256k1 point, encoded as 33 compressed bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey {
    point: BackendPublicKey,
    compressed: [u8; COMPRESSED_PUBLIC_KEY_SIZE],
}

impl PublicKey {
    pub const LEN: usize = COMPRESSED_PUBLIC_KEY_SIZE;

    /// Parses the 33-byte compressed encoding. Uncompressed keys are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LEN {
            return Err(CryptoError::WrongLength {
                item: Item::PublicKey,
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        let point = BackendPublicKey::from_slice(secp(), bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_backend(point)
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        Self::from_bytes(&hex::decode_array::<COMPRESSED_PUBLIC_KEY_SIZE>(
            hex,
            Item::PublicKey,
        )?)
    }

    pub fn from_secret_key(secret: &SecretKey) -> Result<Self, CryptoError> {
        Self::from_backend(BackendPublicKey::from_secret_key(
            secp(),
            secret.as_backend(),
        )?)
    }

    pub fn to_bytes(&self) -> [u8; COMPRESSED_PUBLIC_KEY_SIZE] {
        self.compressed
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.compressed)
    }

    /// ECDH as `epic-wallet` computes it for Epicbox: the X coordinate of `self * secret`, not the
    /// hashed output of libsecp256k1's own ECDH function.
    pub fn shared_secret(&self, secret: &SecretKey) -> Result<SharedSecret, CryptoError> {
        let mut point = self.point;
        let serialized = point
            .mul_assign(secp(), secret.as_backend())
            .map(|()| point.serialize_vec(secp(), true));
        // The product point is the shared secret in another encoding.
        point.0.0.zeroize();
        let mut serialized = serialized?;
        let mut shared = SharedSecret::zeroed();
        let copied = serialized
            .get(1..COMPRESSED_PUBLIC_KEY_SIZE)
            .filter(|x| x.len() == SharedSecret::LEN)
            .map(|x| shared.as_mut_bytes().copy_from_slice(x));
        serialized.as_mut_slice().zeroize();
        copied.map(|()| shared).ok_or(CryptoError::Backend)
    }

    /// The point sum of `keys`, as slates sum the parties' public nonces and blind excesses.
    /// Fails with [`CryptoError::InvalidPublicKey`] when the keys cancel out.
    pub fn sum(keys: &[Self]) -> Result<Self, CryptoError> {
        check_batch_len(keys.len(), MAX_SUM_TERMS, Item::PublicKey)?;
        let points = keys.iter().map(Self::as_backend).collect();
        let sum = BackendPublicKey::from_combination(secp(), points)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_backend(sum)
    }

    pub(crate) fn from_backend(point: BackendPublicKey) -> Result<Self, CryptoError> {
        let serialized = point.serialize_vec(secp(), true);
        let compressed = <[u8; COMPRESSED_PUBLIC_KEY_SIZE]>::try_from(serialized.as_slice())
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self { point, compressed })
    }

    pub(crate) fn as_backend(&self) -> &BackendPublicKey {
        &self.point
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATOR_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn secret(byte: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        SecretKey::from_array(bytes).unwrap()
    }

    #[test]
    fn public_key_of_one_is_the_generator() {
        let key = PublicKey::from_secret_key(&secret(1)).unwrap();
        assert_eq!(key.to_hex(), GENERATOR_HEX);
    }

    #[test]
    fn round_trips_compressed_encoding() {
        let key = PublicKey::from_hex(GENERATOR_HEX).unwrap();
        assert_eq!(PublicKey::from_bytes(&key.to_bytes()), Ok(key));
    }

    #[test]
    fn rejects_public_key_of_the_wrong_length() {
        assert_eq!(
            PublicKey::from_bytes(&[2u8; 32]),
            Err(CryptoError::WrongLength {
                item: Item::PublicKey,
                expected: 33,
                actual: 32
            })
        );
    }

    #[test]
    fn rejects_uncompressed_public_key() {
        let mut bytes = [0u8; 65];
        bytes[0] = 4;
        assert_eq!(
            PublicKey::from_bytes(&bytes),
            Err(CryptoError::WrongLength {
                item: Item::PublicKey,
                expected: 33,
                actual: 65
            })
        );
    }

    #[test]
    fn rejects_public_key_not_on_the_curve() {
        let mut bytes = [0u8; 33];
        bytes[0] = 2;
        bytes[32] = 5;
        assert_eq!(
            PublicKey::from_bytes(&bytes),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn rejects_public_key_with_a_bad_prefix() {
        let mut bytes = PublicKey::from_hex(GENERATOR_HEX).unwrap().to_bytes();
        bytes[0] = 0x08;
        assert_eq!(
            PublicKey::from_bytes(&bytes),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn sum_of_public_keys_is_the_public_key_of_the_secret_sum() {
        let (a, b) = (secret(3), secret(5));
        let sum = PublicKey::sum(&[
            PublicKey::from_secret_key(&a).unwrap(),
            PublicKey::from_secret_key(&b).unwrap(),
        ])
        .unwrap();
        assert_eq!(sum, PublicKey::from_secret_key(&secret(8)).unwrap());
        let single = PublicKey::from_secret_key(&a).unwrap();
        assert_eq!(PublicKey::sum(&[single]), Ok(single));
    }

    #[test]
    fn rejects_an_empty_public_key_sum() {
        assert_eq!(
            PublicKey::sum(&[]),
            Err(CryptoError::EmptyBatch {
                item: Item::PublicKey
            })
        );
    }

    #[test]
    fn rejects_public_keys_that_cancel_out() {
        let key = PublicKey::from_secret_key(&secret(1)).unwrap();
        let mut negated = key.to_bytes();
        negated[0] ^= 1;
        let negated = PublicKey::from_bytes(&negated).unwrap();
        assert_eq!(
            PublicKey::sum(&[key, negated]),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn shared_secret_agrees_on_both_sides() {
        let (a, b) = (secret(3), secret(5));
        let a_pub = PublicKey::from_secret_key(&a).unwrap();
        let b_pub = PublicKey::from_secret_key(&b).unwrap();
        let ab = b_pub.shared_secret(&a).unwrap();
        let ba = a_pub.shared_secret(&b).unwrap();
        assert_eq!(ab.expose_bytes(), ba.expose_bytes());
    }

    #[test]
    fn shared_secret_is_the_x_coordinate_of_the_product() {
        let product = PublicKey::from_secret_key(&secret(15)).unwrap();
        let shared = PublicKey::from_secret_key(&secret(3))
            .unwrap()
            .shared_secret(&secret(5))
            .unwrap();
        assert_eq!(shared.expose_bytes().as_slice(), &product.to_bytes()[1..]);
    }
}
