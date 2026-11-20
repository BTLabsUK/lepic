// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Grin Developers
// Ported from EpicCash/epic keychain/src/keychain.rs, keychain/src/types.rs (Apache-2.0); see
// NOTICE and upstream.toml.

//! The keychain: a master key and the output keys and commitments derived from it.

use std::fmt;

use lepic_crypto::{Commitment, CryptoError, PublicKey, SecretKey};
use lepic_primitives::params::Network;
use thiserror::Error;

use crate::bip32::{Bip32Error, ExtendedPrivKey};
use crate::identifier::Identifier;
use crate::mnemonic::{MnemonicError, Seed};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KeychainError {
    #[error("mnemonic rejected")]
    Mnemonic(#[from] MnemonicError),
    #[error("key derivation failed")]
    Derivation(#[from] Bip32Error),
    #[error("key operation failed")]
    Crypto(#[from] CryptoError),
    #[error("address key path cannot extend a parent of depth {depth}")]
    AddressParentTooDeep { depth: u8 },
    #[error("contact key path needs an account path m/<a>/0, not a path of depth {depth}")]
    NotAnAccountPath { depth: u8 },
    #[error("unknown switch commitment type {code}")]
    UnknownSwitchType { code: u8 },
}

/// How an output's blinding factor is derived from its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwitchCommitment {
    /// The plain BIP32 key.
    None,
    /// `blind_switch(amount, key)`, which every output `epic-wallet` creates uses.
    Regular,
}

impl SwitchCommitment {
    /// The type code stored in range proof messages.
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Regular => 1,
        }
    }
}

impl TryFrom<u8> for SwitchCommitment {
    type Error = KeychainError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::Regular),
            code => Err(KeychainError::UnknownSwitchType { code }),
        }
    }
}

/// A wallet's master key. Wiped on drop and never printed.
#[derive(Clone)]
pub struct Keychain {
    master: ExtendedPrivKey,
    network: Network,
}

impl Keychain {
    pub fn from_seed(seed: &Seed, network: Network) -> Result<Self, KeychainError> {
        Ok(Self {
            master: ExtendedPrivKey::new_master(seed.expose_bytes())?,
            network,
        })
    }

    pub fn from_mnemonic(phrase: &str, network: Network) -> Result<Self, KeychainError> {
        Self::from_seed(&Seed::from_mnemonic(phrase)?, network)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn master(&self) -> &ExtendedPrivKey {
        &self.master
    }

    pub fn master_public_key(&self) -> Result<PublicKey, KeychainError> {
        Ok(self.master.public_key()?)
    }

    /// The extended key at `id`, without a switch commitment.
    pub fn derive_ext_key(&self, id: &Identifier) -> Result<ExtendedPrivKey, KeychainError> {
        Ok(self.master.derive_priv(id.path())?)
    }

    /// The key at `id`, switched for `amount` when `switch` is regular.
    pub fn derive_key(
        &self,
        amount: u64,
        id: &Identifier,
        switch: SwitchCommitment,
    ) -> Result<SecretKey, KeychainError> {
        let key = self.derive_ext_key(id)?;
        match switch {
            SwitchCommitment::None => Ok(key.secret_key().clone()),
            SwitchCommitment::Regular => Ok(key.secret_key().blind_switch(amount)?),
        }
    }

    /// The commitment to `amount` under the key `derive_key` returns.
    pub fn commit(
        &self,
        amount: u64,
        id: &Identifier,
        switch: SwitchCommitment,
    ) -> Result<Commitment, KeychainError> {
        let key = self.derive_key(amount, id, switch)?;
        Ok(Commitment::commit(amount, &key)?)
    }
}

impl fmt::Debug for Keychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keychain([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::bip32::ExtKeyVersion;

    #[test]
    fn extended_key_versions_match_the_derivation_vectors() {
        const VECTORS: [(Network, &str); 4] = [
            (
                Network::Mainnet,
                include_str!("../../../testdata/vectors/keys/derivation_seed16_mainnet.json"),
            ),
            (
                Network::Floonet,
                include_str!("../../../testdata/vectors/keys/derivation_seed16_floonet.json"),
            ),
            (
                Network::Mainnet,
                include_str!("../../../testdata/vectors/keys/derivation_seed32_mainnet.json"),
            ),
            (
                Network::Floonet,
                include_str!("../../../testdata/vectors/keys/derivation_seed32_floonet.json"),
            ),
        ];
        for (network, text) in VECTORS {
            let vector: Value = serde_json::from_str(text).unwrap();
            let master = &vector["expected"]["master"];
            let version = ExtKeyVersion::of(network);
            let hex = |bytes: [u8; 4]| lepic_crypto::hex::encode(&bytes);
            assert_eq!(master["ext_priv_version"], hex(version.private));
            assert_eq!(master["ext_pub_version"], hex(version.public));
        }
    }

    #[test]
    fn mainnet_and_floonet_use_different_versions() {
        assert_ne!(ExtKeyVersion::MAINNET, ExtKeyVersion::FLOONET);
    }

    #[test]
    fn switch_type_codes_round_trip() {
        for switch in [SwitchCommitment::None, SwitchCommitment::Regular] {
            assert_eq!(SwitchCommitment::try_from(switch.code()), Ok(switch));
        }
        assert_eq!(
            SwitchCommitment::try_from(2),
            Err(KeychainError::UnknownSwitchType { code: 2 })
        );
    }
}
