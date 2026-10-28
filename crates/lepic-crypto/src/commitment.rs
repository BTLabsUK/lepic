// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2020 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic core/src/ser.rs, core/src/libtx/secp_ser.rs (Apache-2.0); see NOTICE
// and upstream.toml.

use std::fmt;

use secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE;
use secp256k1zkp::pedersen::Commitment as BackendCommitment;

use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::hex;
use crate::item_hex;
use crate::limits::{MAX_SUM_TERMS, check_batch_len};
use crate::secret::SecretKey;

/// A Pedersen commitment `blinding*G + value*H`, 33 bytes, always a valid curve point.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Commitment([u8; PEDERSEN_COMMITMENT_SIZE]);

impl Commitment {
    pub const LEN: usize = PEDERSEN_COMMITMENT_SIZE;

    /// Parses a commitment, rejecting a wrong prefix byte or an X coordinate off the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array = <[u8; PEDERSEN_COMMITMENT_SIZE]>::try_from(bytes).map_err(|_| {
            CryptoError::WrongLength {
                item: Item::Commitment,
                expected: Self::LEN,
                actual: bytes.len(),
            }
        })?;
        Self::from_backend(BackendCommitment(array))
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        Self::from_bytes(&item_hex::decode_array::<PEDERSEN_COMMITMENT_SIZE>(
            hex,
            Item::Commitment,
        )?)
    }

    pub fn as_bytes(&self) -> &[u8; PEDERSEN_COMMITMENT_SIZE] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Commits to `value` with `blinding`.
    pub fn commit(value: u64, blinding: &SecretKey) -> Result<Self, CryptoError> {
        Self::from_backend(secp().commit(value, blinding.to_backend())?)
    }

    /// Commits to `value` with a zero blinding factor, as upstream does for fees and overage.
    /// Zero has no such commitment and is rejected.
    pub fn commit_value(value: u64) -> Result<Self, CryptoError> {
        Self::from_backend(secp().commit_value(value)?)
    }

    /// `sum(positive) - sum(negative)`. Fails with [`CryptoError::SumIsZero`] when the terms
    /// cancel out, because the point at infinity has no commitment encoding.
    pub fn sum(positive: &[Self], negative: &[Self]) -> Result<Self, CryptoError> {
        check_batch_len(
            positive.len().saturating_add(negative.len()),
            MAX_SUM_TERMS,
            Item::Commitment,
        )?;
        let positive = positive.iter().copied().map(Self::to_backend).collect();
        let negative = negative.iter().copied().map(Self::to_backend).collect();
        Self::from_backend(secp().commit_sum(positive, negative)?)
    }

    // Every commitment the wrapper returns is re-parsed, because its commit functions ignore the
    // library's status code and would hand back the bytes of an invalid point unchecked.
    pub(crate) fn from_backend(commitment: BackendCommitment) -> Result<Self, CryptoError> {
        commitment
            .to_pubkey(secp())
            .map_err(|_| CryptoError::InvalidCommitment)?;
        Ok(Self(commitment.0))
    }

    pub(crate) fn to_backend(self) -> BackendCommitment {
        BackendCommitment(self.0)
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Commitment({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        SecretKey::from_array(bytes).unwrap()
    }

    #[test]
    fn round_trips_bytes_and_hex() {
        let commitment = Commitment::commit(5, &secret(7)).unwrap();
        assert_eq!(
            Commitment::from_bytes(commitment.as_bytes()),
            Ok(commitment)
        );
        assert_eq!(Commitment::from_hex(&commitment.to_hex()), Ok(commitment));
    }

    #[test]
    fn commitment_is_additively_homomorphic() {
        let a = Commitment::commit(3, &secret(2)).unwrap();
        let b = Commitment::commit(4, &secret(5)).unwrap();
        let c = Commitment::commit(7, &secret(7)).unwrap();
        assert_eq!(Commitment::sum(&[a, b], &[]), Ok(c));
        assert_eq!(Commitment::sum(&[c], &[b]), Ok(a));
    }

    #[test]
    fn commit_value_is_the_value_part_of_a_commitment() {
        let blinded = Commitment::commit(9, &secret(3)).unwrap();
        let value_only = Commitment::commit_value(9).unwrap();
        assert_eq!(
            Commitment::sum(&[blinded], &[value_only]),
            Commitment::commit(0, &secret(3))
        );
    }

    #[test]
    fn rejects_commitment_of_the_wrong_length() {
        assert_eq!(
            Commitment::from_bytes(&[8u8; 32]),
            Err(CryptoError::WrongLength {
                item: Item::Commitment,
                expected: 33,
                actual: 32
            })
        );
        assert_eq!(
            Commitment::from_hex(&"08".repeat(34)),
            Err(CryptoError::WrongLength {
                item: Item::Commitment,
                expected: 33,
                actual: 34
            })
        );
    }

    #[test]
    fn rejects_commitment_with_a_bad_prefix() {
        let mut bytes = *Commitment::commit(5, &secret(7)).unwrap().as_bytes();
        bytes[0] = 0x02;
        assert_eq!(
            Commitment::from_bytes(&bytes),
            Err(CryptoError::InvalidCommitment)
        );
    }

    #[test]
    fn rejects_all_zero_commitment() {
        assert_eq!(
            Commitment::from_bytes(&[0u8; 33]),
            Err(CryptoError::InvalidCommitment)
        );
    }

    #[test]
    fn rejects_commitment_off_the_curve() {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x08;
        bytes[32] = 5;
        assert_eq!(
            Commitment::from_bytes(&bytes),
            Err(CryptoError::InvalidCommitment)
        );
    }

    #[test]
    fn rejects_commitment_to_zero_value_without_blinding() {
        assert_eq!(
            Commitment::commit_value(0),
            Err(CryptoError::InvalidCommitment)
        );
    }

    #[test]
    fn rejects_sum_that_cancels_out() {
        let a = Commitment::commit(3, &secret(2)).unwrap();
        assert_eq!(Commitment::sum(&[a], &[a]), Err(CryptoError::SumIsZero));
    }

    #[test]
    fn rejects_empty_commitment_sum() {
        assert_eq!(
            Commitment::sum(&[], &[]),
            Err(CryptoError::EmptyBatch {
                item: Item::Commitment
            })
        );
    }

    #[test]
    fn rejects_oversized_commitment_sum() {
        let a = Commitment::commit(1, &secret(1)).unwrap();
        let positive = vec![a; MAX_SUM_TERMS];
        assert_eq!(
            Commitment::sum(&positive, &[a]),
            Err(CryptoError::BatchTooLarge {
                item: Item::Commitment,
                max: MAX_SUM_TERMS,
                actual: MAX_SUM_TERMS + 1
            })
        );
    }
}
