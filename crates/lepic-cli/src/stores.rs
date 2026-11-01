// SPDX-License-Identifier: Apache-2.0
//! The product SQLite store, with a handle the CLI keeps to read history that the engine has no
//! query for yet.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use lepic_store::{Repositories, SqliteStore, StoreError, StoreKey, StoreKeys, WalletStore};
use lepic_wallet::{ENCRYPTED_DATABASE_FILE, EncryptedSqliteStores, SqliteStores, StoreOpener};

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

/// Opens the database as [`EncryptedSqliteStores`] does when the data directory holds an
/// encrypted one, [`ENCRYPTED_DATABASE_FILE`], and as [`SqliteStores`] does otherwise, and
/// remembers the last store it opened.
#[derive(Debug, Default)]
pub struct CliStores {
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
        let store = if is_encrypted(data_dir)? {
            EncryptedSqliteStores.open(data_dir, keys, store_key)?
        } else {
            SqliteStores.open(data_dir, keys, store_key)?
        };
        let store = SharedStore(Arc::new(store));
        *self.opened.lock().unwrap_or_else(PoisonError::into_inner) = Some(store.clone());
        Ok(store)
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Option<SharedStore>, StoreError> {
        // A check of a phrase, not an unlock: not recorded as the opened store.
        let store = if is_encrypted(data_dir)? {
            EncryptedSqliteStores.open_existing(data_dir, keys, store_key)?
        } else {
            SqliteStores.open_existing(data_dir, keys, store_key)?
        };
        Ok(store.map(|store| SharedStore(Arc::new(store))))
    }
}

/// Whether `data_dir` holds an encrypted database. The encrypted one wins when the plain one is
/// there too, as it does for a data directory a wallet made before the encrypted database was
/// copied in.
fn is_encrypted(data_dir: &Path) -> Result<bool, StoreError> {
    data_dir
        .join(ENCRYPTED_DATABASE_FILE)
        .try_exists()
        .map_err(|source| StoreError::Io {
            operation: "look for the encrypted database",
            source,
        })
}
