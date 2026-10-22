//! The key of the wallet's onion service (ADR 0018): the payment-proof key of the default
//! account, so the onion equals what `epic-wallet address` prints and survives a restore.

use std::fmt;

use lepic_node::NodeApi;
use lepic_store::AccountIndex;
use zeroize::Zeroizing;

use crate::account;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

const ONION_ACCOUNT: AccountIndex = AccountIndex(0);
const ONION_KEY_INDEX: u32 = 0;

/// The 32-byte ed25519 seed tor publishes the wallet's onion with, and its public key. The
/// seed is wiped on drop and never printed.
pub struct OnionKey {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl OnionKey {
    /// The seed. Callers must not log it or copy it into memory that is not wiped.
    pub fn expose_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The ed25519 public key, which is also the wallet's payment-proof address.
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
    /// The key of the wallet's onion service: the address secret key of account `m/0/0`,
    /// index 0, which seeds the payment-proof key.
    ///
    /// Fails with [`WalletError::Locked`] while the wallet is locked.
    pub fn onion_key(&self) -> Result<OnionKey, WalletError> {
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
