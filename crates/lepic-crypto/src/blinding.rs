// SPDX-License-Identifier: Apache-2.0
use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::limits::{MAX_SUM_TERMS, check_batch_len};
use crate::secret::SecretKey;

impl SecretKey {
    /// `sum(positive) - sum(negative)` modulo the curve order. Fails with
    /// [`CryptoError::SumIsZero`] when the terms cancel out.
    pub fn sum(positive: &[Self], negative: &[Self]) -> Result<Self, CryptoError> {
        check_batch_len(
            positive.len().saturating_add(negative.len()),
            MAX_SUM_TERMS,
            Item::SecretKey,
        )?;
        let positive = positive.iter().map(Self::to_backend).collect();
        let negative = negative.iter().map(Self::to_backend).collect();
        match secp().blind_sum(positive, negative) {
            Ok(sum) => Self::from_backend(&sum),
            Err(_) => Err(CryptoError::SumIsZero),
        }
    }

    /// The "regular" switch-commitment blinding factor for `value`, as output keys use.
    pub fn blind_switch(&self, value: u64) -> Result<Self, CryptoError> {
        Self::from_backend(&secp().blind_switch(value, self.to_backend())?)
    }
}

#[cfg(test)]
mod tests {
    use crate::Commitment;

    use super::*;

    fn secret(byte: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        SecretKey::from_array(bytes).unwrap()
    }

    #[test]
    fn sums_and_subtracts_scalars() {
        let sum = SecretKey::sum(&[secret(2), secret(5)], &[secret(3)]).unwrap();
        assert_eq!(sum.expose_bytes(), secret(4).expose_bytes());
    }

    #[test]
    fn negative_only_sum_is_the_negation() {
        let negated = SecretKey::sum(&[], &[secret(1)]).unwrap();
        let mut expected = secp256k1zkp::constants::CURVE_ORDER;
        expected[31] -= 1;
        assert_eq!(negated.expose_bytes(), &expected);
    }

    #[test]
    fn blinding_sum_matches_commitment_sum() {
        let (a, b) = (secret(9), secret(4));
        let difference =
            SecretKey::sum(std::slice::from_ref(&a), std::slice::from_ref(&b)).unwrap();
        let commitments = Commitment::sum(
            &[Commitment::commit(10, &a).unwrap()],
            &[Commitment::commit(10, &b).unwrap()],
        );
        assert_eq!(commitments, Commitment::commit(0, &difference));
    }

    #[test]
    fn rejects_blinding_sum_that_cancels_out() {
        assert_eq!(
            SecretKey::sum(&[secret(3)], &[secret(3)]).err(),
            Some(CryptoError::SumIsZero)
        );
    }

    #[test]
    fn rejects_empty_blinding_sum() {
        assert_eq!(
            SecretKey::sum(&[], &[]).err(),
            Some(CryptoError::EmptyBatch {
                item: Item::SecretKey
            })
        );
    }

    #[test]
    fn rejects_oversized_blinding_sum() {
        let positive = vec![secret(1); MAX_SUM_TERMS + 1];
        assert_eq!(
            SecretKey::sum(&positive, &[]).err(),
            Some(CryptoError::BatchTooLarge {
                item: Item::SecretKey,
                max: MAX_SUM_TERMS,
                actual: MAX_SUM_TERMS + 1
            })
        );
    }

    #[test]
    fn blind_switch_is_deterministic_and_depends_on_value() {
        let key = secret(7);
        let once = key.blind_switch(100).unwrap();
        let twice = key.blind_switch(100).unwrap();
        let other = key.blind_switch(101).unwrap();
        assert_eq!(once.expose_bytes(), twice.expose_bytes());
        assert_ne!(once.expose_bytes(), other.expose_bytes());
        assert_ne!(once.expose_bytes(), key.expose_bytes());
    }
}
