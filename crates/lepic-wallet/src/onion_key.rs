// SPDX-License-Identifier: Apache-2.0
//! The keys of the wallet's onion service (ADR 0044). The onion's own key is a key of the LEPIC
//! namespace, so the Epicbox and payment-proof addresses do not give the onion; a restore from
//! the phrase gives it back. The previous onion is the payment-proof key of the default account,
//! what `epic-wallet address` prints (ADR 0018); a host keeps it reachable for senders that saved
//! it.

use std::fmt;

use ed25519_dalek::SigningKey;

use lepic_node::NodeApi;
use lepic_store::AccountIndex;
use zeroize::Zeroizing;

use crate::account;
use crate::error::WalletError;
use crate::namespace;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

const ONION_ACCOUNT: AccountIndex = AccountIndex(0);
const ONION_KEY_INDEX: u32 = 0;

/// The 32-byte ed25519 seed tor publishes an onion of the wallet with, and its public key. The
/// seed is wiped on drop and never printed. A payment proof asked for the public key over Tor
/// is signed with this key.
pub struct OnionKey {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl OnionKey {
    /// The seed. Callers must not log it or copy it into memory that is not wiped.
    pub fn expose_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The ed25519 public key: the onion in bytes, and the receiver address of a payment proof
    /// asked for over it.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OnionKey([redacted])")
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The key of the wallet's onion service: the namespace key labelled
    /// [`namespace::ONION_KEY_LABEL`], on no BIP32 path.
    ///
    /// Fails with [`WalletError::Locked`] while the wallet is locked.
    pub fn onion_key(&self) -> Result<OnionKey, WalletError> {
        let session = self.session()?;
        let seed = namespace::onion_seed(&session.seed)?;
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Ok(OnionKey { seed, public_key })
    }

    /// The key of the onion the wallet published before ADR 0044: the address secret key of
    /// account `m/0/0`, index 0, which seeds the payment-proof key, so its public key is the
    /// payment-proof address. A host that keeps the previous onion reachable publishes it with
    /// this key.
    ///
    /// Fails with [`WalletError::Locked`] while the wallet is locked.
    pub fn previous_onion_key(&self) -> Result<OnionKey, WalletError> {
        let session = self.session()?;
        let parent = account::parent_key_id(ONION_ACCOUNT)?;
        let secret = session
            .keychain
            .address_key(&parent, ONION_KEY_INDEX)
            .map_err(WalletError::Keychain)?;
        let public_key = session
            .keychain
            .payment_proof_key(&parent, ONION_KEY_INDEX)
            .map_err(WalletError::Keychain)?
            .public_key();
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(secret.expose_bytes());
        Ok(OnionKey { seed, public_key })
    }
}
