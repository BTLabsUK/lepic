//! The contact-identity key of RFC 0002 section 2.1: the plain BIP32 key at `m/<a>/2/0` under an
//! account. The contact key schedule built on it is a feature of `lepic-wallet-contacts`, not part
//! of Epic compatibility, and lives there.

use lepic_crypto::SecretKey;

use crate::identifier::Identifier;
use crate::keychain::{Keychain, KeychainError, SwitchCommitment};

/// The depth of an account's own path `m/<a>/0`.
const ACCOUNT_DEPTH: u8 = 2;

/// The second path component of the contact-identity branch.
const CONTACT_BRANCH: u32 = 2;

/// The path `m/<a>/2/0` of the contact-identity root key under the account at `parent`, which
/// must be the account's own path `m/<a>/0`.
pub fn contact_identity_key_id(parent: &Identifier) -> Result<Identifier, KeychainError> {
    let depth = parent.depth();
    let mut components = parent.components();
    if depth != ACCOUNT_DEPTH || components.get(1) != Some(&0) {
        return Err(KeychainError::NotAnAccountPath { depth });
    }
    if let Some(branch) = components.get_mut(1) {
        *branch = CONTACT_BRANCH;
    }
    if let Some(slot) = components.get_mut(usize::from(depth)) {
        *slot = 0;
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(KeychainError::NotAnAccountPath { depth })?;
    Identifier::new(child_depth, components).map_err(|_| KeychainError::NotAnAccountPath { depth })
}

impl Keychain {
    /// The contact-identity key of the account at `parent`: the plain BIP32 output at
    /// `m/<a>/2/0`, with no switch commitment. Callers must not log it.
    pub fn contact_identity_secret(&self, parent: &Identifier) -> Result<SecretKey, KeychainError> {
        self.derive_key(0, &contact_identity_key_id(parent)?, SwitchCommitment::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_path_of_default_account() {
        let parent = Identifier::new(2, [0, 0, 0, 0]).unwrap();
        let id = contact_identity_key_id(&parent).unwrap();
        assert_eq!(id, Identifier::new(3, [0, 2, 0, 0]).unwrap());
        assert_eq!(id.to_bip32_path(), "m/0/2/0");
    }

    #[test]
    fn refuses_a_parent_that_is_not_an_account_path() {
        for (depth, components) in [
            (0, [0, 0, 0, 0]),
            (1, [0, 0, 0, 0]),
            (2, [0, 1, 0, 0]),
            (2, [0, 2, 0, 0]),
            (3, [0, 0, 0, 0]),
            (4, [0, 0, 0, 0]),
        ] {
            let parent = Identifier::new(depth, components).unwrap();
            assert_eq!(
                contact_identity_key_id(&parent),
                Err(KeychainError::NotAnAccountPath { depth }),
                "{components:?} at depth {depth}"
            );
        }
    }

    #[test]
    fn contact_path_of_another_account() {
        let parent = Identifier::new(2, [7, 0, 0, 0]).unwrap();
        assert_eq!(
            contact_identity_key_id(&parent).unwrap().to_bip32_path(),
            "m/7/2/0"
        );
    }
}
