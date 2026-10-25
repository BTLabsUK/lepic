//! The product SQLite store, with a handle the CLI keeps to read history that the engine has no
//! query for yet.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use lepic_store::{ContextKey, Repositories, SqliteStore, StoreError, WalletStore};
use lepic_wallet::{SqliteStores, StoreOpener};

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

/// Opens the database as [`SqliteStores`] does and remembers the last store it opened.
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

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<SharedStore, StoreError> {
        let store = SharedStore(Arc::new(SqliteStores.open(data_dir, key)?));
        *self.opened.lock().unwrap_or_else(PoisonError::into_inner) = Some(store.clone());
        Ok(store)
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        key: ContextKey,
    ) -> Result<Option<SharedStore>, StoreError> {
        // A check of a phrase, not an unlock: not recorded as the opened store.
        Ok(SqliteStores
            .open_existing(data_dir, key)?
            .map(|store| SharedStore(Arc::new(store))))
    }
}
