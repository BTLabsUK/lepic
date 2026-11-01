// SPDX-License-Identifier: Apache-2.0
//! The product SQLite store, with a handle the CLI keeps to read history that the engine has no
//! query for yet.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use lepic_store::{
    AtRestReport, Repositories, SqliteStore, StoreError, StoreKey, StoreKeys, WalletStore,
};
use lepic_wallet::{EncryptingSqliteStores, StoreOpener};

/// A [`SqliteStore`] shared between the engine and the CLI.
#[derive(Debug, Clone)]
pub struct SharedStore(Arc<SqliteStore>);

impl WalletStore for SharedStore {
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        self.0.read(operation)
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        self.0.write(operation)
    }
}

/// The product store, encrypted at rest ([`EncryptingSqliteStores`]): it moves a plain
/// database of an earlier build into an encrypted one at its first open, as the app does, and
/// remembers the last store it opened.
#[derive(Debug, Default)]
pub struct CliStores {
    stores: EncryptingSqliteStores,
    opened: Mutex<Option<SharedStore>>,
}

impl CliStores {
    /// The store the wallet opened when it was unlocked.
    pub fn opened(&self) -> Option<SharedStore> {
        self.opened
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl StoreOpener for CliStores {
    type Store = SharedStore;

    fn open(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<SharedStore, StoreError> {
        self.open_reporting(data_dir, keys, store_key)
            .map(|(store, _)| store)
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Option<SharedStore>, StoreError> {
        // A check of a phrase, not an unlock: not recorded as the opened store.
        Ok(self
            .stores
            .open_existing(data_dir, keys, store_key)?
            .map(|store| SharedStore(Arc::new(store))))
    }

    fn open_reporting(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<(SharedStore, Option<AtRestReport>), StoreError> {
        let (store, report) = self.stores.open_reporting(data_dir, keys, store_key)?;
        let store = SharedStore(Arc::new(store));
        *self.opened.lock().unwrap_or_else(PoisonError::into_inner) = Some(store.clone());
        Ok((store, report))
    }
}
