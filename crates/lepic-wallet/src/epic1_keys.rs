// SPDX-License-Identifier: Apache-2.0
//! The seal keys of the epic1 addresses the wallet derived while it is unlocked. A zero-hint
//! envelope is tried with the key of every address an account issued, so each request would
//! otherwise derive them all again. The keys go with the session: locking or closing the
//! wallet drops them, and each is zeroized when dropped.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use lepic_contact::{EncSecretKey, Network};
use lepic_keychain::Seed;

use crate::error::WalletError;
use crate::namespace;

/// `(account, network byte, address index)`.
type KeyId = (u32, u8, u32);

/// Each key sits in its own allocation, so growing the map moves pointers, not key bytes.
#[derive(Default)]
pub(crate) struct Epic1KeyCache {
    keys: Mutex<HashMap<KeyId, Box<EncSecretKey>>>,
}

impl Epic1KeyCache {
    /// The seal key of the epic1 address `index` of `account` on `network`, derived once per
    /// session.
    pub(crate) fn key(
        &self,
        seed: &Seed,
        account: u32,
        network: Network,
        index: u32,
    ) -> Result<EncSecretKey, WalletError> {
        get_or_derive(&mut self.lock(), seed, account, network, index)
    }

    /// The seal keys of the epic1 addresses `indexes` of `account` on `network`, each with its
    /// index, in the order given. Derives only the ones not derived before in this session.
    pub(crate) fn keys(
        &self,
        seed: &Seed,
        account: u32,
        network: Network,
        indexes: &[u32],
    ) -> Result<Vec<(u32, EncSecretKey)>, WalletError> {
        let mut cached = self.lock();
        indexes
            .iter()
            .map(|&index| {
                Ok((
                    index,
                    get_or_derive(&mut cached, seed, account, network, index)?,
                ))
            })
            .collect()
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
    index: u32,
) -> Result<EncSecretKey, WalletError> {
    let id = (account, network.byte(), index);
    if let Some(key) = cached.get(&id) {
        return Ok(EncSecretKey::clone(key));
    }
    let key = namespace::epic1_seal_key(seed, account, network, index)?;
    cached.insert(id, Box::new(key.clone()));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Seed {
        Seed::from_entropy(&[7; 32]).unwrap()
    }

    fn public(keys: &[(u32, EncSecretKey)]) -> Vec<(u32, [u8; 32])> {
        keys.iter()
            .map(|(index, key)| (*index, *key.public_key().as_bytes()))
            .collect()
    }

    #[test]
    fn keeps_each_derived_key_and_gives_the_namespace_key() {
        let seed = seed();
        let cache = Epic1KeyCache::default();
        let first = cache.keys(&seed, 2, Network::Floonet, &[3, 0, 1]).unwrap();
        assert_eq!(cache.lock().len(), 3);
        let again = cache
            .keys(&seed, 2, Network::Floonet, &[0, 3, 1, 4])
            .unwrap();
        assert_eq!(cache.lock().len(), 4);
        assert_eq!(public(&first)[0], public(&again)[1]);
        let single = cache.key(&seed, 2, Network::Floonet, 4).unwrap();
        assert_eq!(cache.lock().len(), 4);
        assert_eq!(*single.public_key().as_bytes(), public(&again)[3].1);
        for (index, key) in &again {
            let derived = namespace::epic1_seal_key(&seed, 2, Network::Floonet, *index).unwrap();
            assert_eq!(
                *key.public_key().as_bytes(),
                *derived.public_key().as_bytes()
            );
        }
    }

    #[test]
    fn keeps_accounts_and_networks_apart() {
        let seed = seed();
        let cache = Epic1KeyCache::default();
        let a = cache.keys(&seed, 0, Network::Floonet, &[1]).unwrap();
        let b = cache.keys(&seed, 1, Network::Floonet, &[1]).unwrap();
        let c = cache.keys(&seed, 0, Network::Mainnet, &[1]).unwrap();
        assert_eq!(cache.lock().len(), 3);
        assert_ne!(public(&a), public(&b));
        assert_ne!(public(&a), public(&c));
    }
}
