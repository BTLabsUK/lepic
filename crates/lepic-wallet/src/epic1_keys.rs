// SPDX-License-Identifier: Apache-2.0
//! The seal keys of the epic1 addresses the wallet derived while it is unlocked. A zero-hint
//! envelope is tried with the key of every account, so each request would otherwise derive
//! them all again. The keys go with the session: locking or closing the wallet drops them, and
//! each is zeroized when dropped.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use lepic_contact::{EncSecretKey, Network};
use lepic_keychain::Seed;

use crate::error::WalletError;
use crate::namespace;

/// `(account, network byte)`.
type KeyId = (u32, u8);

/// Each key sits in its own allocation, so growing the map moves pointers, not key bytes.
#[derive(Default)]
pub(crate) struct Epic1KeyCache {
    keys: Mutex<HashMap<KeyId, Box<EncSecretKey>>>,
}

impl Epic1KeyCache {
    /// The seal key of the epic1 address of `account` on `network`, index 0, derived once per
    /// session.
    pub(crate) fn key(
        &self,
        seed: &Seed,
        account: u32,
        network: Network,
    ) -> Result<EncSecretKey, WalletError> {
        get_or_derive(&mut self.lock(), seed, account, network)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<KeyId, Box<EncSecretKey>>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn get_or_derive(
    cached: &mut HashMap<KeyId, Box<EncSecretKey>>,
    seed: &Seed,
    account: u32,
    network: Network,
) -> Result<EncSecretKey, WalletError> {
    let id = (account, network.byte());
    if let Some(key) = cached.get(&id) {
        return Ok(EncSecretKey::clone(key));
    }
    let key = namespace::epic1_seal_key(seed, account, network, 0)?;
    cached.insert(id, Box::new(key.clone()));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Seed {
        Seed::from_entropy(&[7; 32]).unwrap()
    }

    fn public(key: &EncSecretKey) -> [u8; 32] {
        *key.public_key().as_bytes()
    }

    #[test]
    fn keeps_each_derived_key_and_gives_the_namespace_key() {
        let seed = seed();
        let cache = Epic1KeyCache::default();
        let first = cache.key(&seed, 2, Network::Floonet).unwrap();
        assert_eq!(cache.lock().len(), 1);
        let again = cache.key(&seed, 2, Network::Floonet).unwrap();
        assert_eq!(cache.lock().len(), 1);
        let derived = namespace::epic1_seal_key(&seed, 2, Network::Floonet, 0).unwrap();
        assert_eq!(public(&first), public(&again));
        assert_eq!(public(&first), public(&derived));
    }

    #[test]
    fn keeps_accounts_and_networks_apart() {
        let seed = seed();
        let cache = Epic1KeyCache::default();
        let a = cache.key(&seed, 0, Network::Floonet).unwrap();
        let b = cache.key(&seed, 1, Network::Floonet).unwrap();
        let c = cache.key(&seed, 0, Network::Mainnet).unwrap();
        assert_eq!(cache.lock().len(), 3);
        assert_ne!(public(&a), public(&b));
        assert_ne!(public(&a), public(&c));
    }
}
