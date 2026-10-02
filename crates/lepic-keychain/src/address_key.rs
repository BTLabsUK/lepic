//! The Epicbox address key, derived as `epic-wallet`'s `address_from_derivation_path` does, and
//! the payment-proof key built on it.

use std::fmt;

use blake2::Blake2b256;
use blake2::digest::{FixedOutput, Update};
use ed25519_dalek::SigningKey;
use lepic_crypto::SecretKey;
use zeroize::Zeroize;

use crate::identifier::{Identifier, MAX_DEPTH};
use crate::keychain::{Keychain, KeychainError, SwitchCommitment};

/// The path of the address key for `index` under an account: the account path with its second
/// component set to 1 and `index` appended, so account `m/0/0` gives `m/0/1/<index>`.
pub fn address_key_id(parent: &Identifier, index: u32) -> Result<Identifier, KeychainError> {
    let depth = parent.depth();
    if depth >= MAX_DEPTH {
        return Err(KeychainError::AddressParentTooDeep { depth });
    }
    let mut components = parent.components();
    // Upstream sets the second component before appending, whatever the parent depth, so a
    // depth-0 parent ends up with it in the bytes past the derivation depth.
    if let Some(branch) = components.get_mut(1) {
        *branch = 1;
    }
    if let Some(slot) = components.get_mut(usize::from(depth)) {
        *slot = index;
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(KeychainError::AddressParentTooDeep { depth })?;
    Identifier::new(child_depth, components)
        .map_err(|_| KeychainError::AddressParentTooDeep { depth })
}

impl Keychain {
    /// The Epicbox address secret key: unkeyed BLAKE2b-256 of the plain key at
    /// [`address_key_id`]. `epic-wallet` always uses index 0.
    pub fn address_key(&self, parent: &Identifier, index: u32) -> Result<SecretKey, KeychainError> {
        let id = address_key_id(parent, index)?;
        let raw = self.derive_key(0, &id, SwitchCommitment::None)?;
        let mut state = Blake2b256::default();
        state.update(raw.expose_bytes());
        let mut hashed = state.finalize_fixed();
        let key = SecretKey::from_bytes(&hashed);
        hashed.as_mut_slice().zeroize();
        Ok(key?)
    }

    /// The ed25519 key `epic-wallet` signs payment proofs with: its seed is the
    /// [`Keychain::address_key`] for the same account and index.
    pub fn payment_proof_key(
        &self,
        parent: &Identifier,
        index: u32,
    ) -> Result<PaymentProofKey, KeychainError> {
        let address_key = self.address_key(parent, index)?;
        Ok(PaymentProofKey(SigningKey::from_bytes(
            address_key.expose_bytes(),
        )))
    }
}

/// An ed25519 payment-proof key. Wiped on drop and never printed.
pub struct PaymentProofKey(SigningKey);

impl PaymentProofKey {
    /// The 32-byte public key, which is the wallet's payment-proof address.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// The signing key. Callers must not log it or copy its bytes into memory that is not wiped.
    pub fn expose_signing_key(&self) -> &SigningKey {
        &self.0
    }
}

impl fmt::Debug for PaymentProofKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaymentProofKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_path_of_default_account() {
        let parent = Identifier::new(2, [0, 0, 0, 0]).unwrap();
        let id = address_key_id(&parent, 7).unwrap();
        assert_eq!(id, Identifier::new(3, [0, 1, 7, 0]).unwrap());
        assert_eq!(id.to_bip32_path(), "m/0/1/7");
    }

    #[test]
    fn address_path_of_root_keeps_upstream_branch_bytes() {
        let id = address_key_id(&Identifier::ROOT, 5).unwrap();
        assert_eq!(id, Identifier::new(1, [5, 1, 0, 0]).unwrap());
    }

    #[test]
    fn rejects_address_parent_at_maximum_depth() {
        let parent = Identifier::new(4, [0, 0, 0, 0]).unwrap();
        assert_eq!(
            address_key_id(&parent, 0),
            Err(KeychainError::AddressParentTooDeep { depth: 4 })
        );
    }
}
