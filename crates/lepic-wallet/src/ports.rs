// SPDX-License-Identifier: Apache-2.0
//! The ports the engine runs on. The host supplies every one of them; the engine owns no
//! runtime, clock, randomness or storage of its own (ADR 0011).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jiff::Timestamp;
use lepic_keychain::SecretStore;
use lepic_keychain::vault::BackendError;
#[cfg(feature = "sqlite")]
use lepic_store::{AtRest, MigrationObserver, SqliteStore};
use lepic_store::{AtRestReport, StoreError, StoreKey, StoreKeys, WalletStore};
use lepic_transport::method::MethodLookup;
use rand_core::CryptoRng;
use thiserror::Error;
use tokio::runtime::Handle;

use crate::lifecycle::Password;

/// Wall-clock time, for transaction timestamps.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

/// The cryptographic random number generator every key, nonce and offset is drawn from.
pub struct SharedRng(Mutex<Box<dyn CryptoRng + Send>>);

impl SharedRng {
    pub fn new(rng: impl CryptoRng + Send + 'static) -> Self {
        Self(Mutex::new(Box::new(rng)))
    }

    /// Exclusive use of the generator until the guard is dropped. The guard is itself a
    /// [`CryptoRng`].
    ///
    /// Never call the store while holding it: take the store first and the generator inside
    /// its transaction, or drop the guard before opening one. The reverse order deadlocks.
    pub fn lock(&self) -> MutexGuard<'_, Box<dyn CryptoRng + Send>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for SharedRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedRng")
    }
}

/// Opens the wallet database. It can only be opened once the seed is known, because private
/// transaction contexts are sealed under a key derived from it, and the whole file under
/// another.
pub trait StoreOpener: Send + Sync {
    type Store: WalletStore + 'static;

    /// Opens or creates the database. `store_key` encrypts the file for openers that keep it
    /// encrypted at rest; the others ignore it.
    fn open(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Self::Store, StoreError>;

    /// Opens the database only when one exists, and changes nothing when it is damaged:
    /// `None` when there is none, [`StoreError::Damaged`] for a damaged one, left where it
    /// is. The default opens with [`StoreOpener::open`], for stores that cannot be damaged.
    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Option<Self::Store>, StoreError> {
        self.open(data_dir, keys, store_key).map(Some)
    }

    /// [`StoreOpener::open`], and what the open found on disk, for openers that keep the
    /// database encrypted at rest; the default reports nothing.
    fn open_reporting(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<(Self::Store, Option<AtRestReport>), StoreError> {
        self.open(data_dir, keys, store_key)
            .map(|store| (store, None))
    }
}

#[cfg(feature = "sqlite")]
pub use lepic_store::{DATABASE_FILE, ENCRYPTED_DATABASE_FILE};

#[cfg(feature = "sqlite")]
/// The product store: SQLite encrypted at rest under the store key in the configured data
/// directory, which must exist, as [`lepic_store::open_wallet_dir`] opens it. A plain
/// [`DATABASE_FILE`] of an earlier build is copied into [`ENCRYPTED_DATABASE_FILE`] at its
/// first open and set aside; a copy that fails runs the session on the plain file and is tried
/// again at the next open. A check of a phrase ([`StoreOpener::open_existing`]) creates and
/// moves nothing. The observer, when given, hears the progress of a copy.
#[derive(Clone, Default)]
pub struct EncryptingSqliteStores {
    observer: Option<Arc<MigrationObserver>>,
}

#[cfg(feature = "sqlite")]
impl EncryptingSqliteStores {
    /// The store, reporting the progress of a copy to `observer`.
    pub fn with_observer(observer: Arc<MigrationObserver>) -> Self {
        Self {
            observer: Some(observer),
        }
    }
}

#[cfg(feature = "sqlite")]
impl std::fmt::Debug for EncryptingSqliteStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingSqliteStores")
            .field("observer", &self.observer.is_some())
            .finish()
    }
}

#[cfg(feature = "sqlite")]
impl StoreOpener for EncryptingSqliteStores {
    type Store = SqliteStore;

    fn open(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<SqliteStore, StoreError> {
        self.open_reporting(data_dir, keys, store_key)
            .map(|(store, _)| store)
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Option<SqliteStore>, StoreError> {
        lepic_store::open_existing_wallet_dir(data_dir, keys, store_key)
    }

    fn open_reporting(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<(SqliteStore, Option<AtRestReport>), StoreError> {
        let (store, report) =
            lepic_store::open_wallet_dir(data_dir, keys, store_key, self.observer.as_deref())?;
        Ok((store, Some(report)))
    }
}

#[cfg(feature = "sqlite")]
/// Plain SQLite in [`DATABASE_FILE`] inside the configured data directory, which must exist.
/// It ignores the store key. For tests and tools that read the plain database of an earlier
/// build; the product opens [`EncryptingSqliteStores`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteStores;

#[cfg(feature = "sqlite")]
impl StoreOpener for SqliteStores {
    type Store = SqliteStore;

    fn open(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        _: &StoreKey,
    ) -> Result<SqliteStore, StoreError> {
        SqliteStore::open(&data_dir.join(DATABASE_FILE), keys, AtRest::Plain)
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        _: &StoreKey,
    ) -> Result<Option<SqliteStore>, StoreError> {
        SqliteStore::open_existing(&data_dir.join(DATABASE_FILE), keys, AtRest::Plain)
    }
}

#[cfg(feature = "sqlite")]
/// SQLite in [`ENCRYPTED_DATABASE_FILE`] inside the configured data directory, which must
/// exist, encrypted at rest under the store key ([`SqliteStore::open`] with
/// [`AtRest::Encrypted`]). A key the file's check refuses fails with
/// [`StoreError::WrongKey`] and changes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncryptedSqliteStores;

#[cfg(feature = "sqlite")]
impl StoreOpener for EncryptedSqliteStores {
    type Store = SqliteStore;

    fn open(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<SqliteStore, StoreError> {
        SqliteStore::open(
            &data_dir.join(ENCRYPTED_DATABASE_FILE),
            keys,
            AtRest::Encrypted(store_key),
        )
    }

    fn open_existing(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &StoreKey,
    ) -> Result<Option<SqliteStore>, StoreError> {
        SqliteStore::open_existing(
            &data_dir.join(ENCRYPTED_DATABASE_FILE),
            keys,
            AtRest::Encrypted(store_key),
        )
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretVaultError {
    #[error("no secret storage exists for this wallet")]
    NotFound,
    #[error("secret storage already exists for this wallet")]
    AlreadyExists,
    /// The password is wrong or the stored secrets were altered.
    #[error("secret storage did not unlock with this password")]
    WrongPassword,
    #[error("secret storage backend failed")]
    Backend(#[source] BackendError),
}

/// Where the seed is kept: the `lepic-keychain` vault on desktop, the platform keystore through
/// the host app on mobile. One vault holds the secrets of one wallet. A keystore that gates
/// access by biometrics or device lock may ignore the password.
pub trait SecretVault: Send + Sync {
    type Secrets: SecretStore + Send;

    /// Whether secret storage for this wallet exists, locked or not.
    fn exists(&self) -> Result<bool, SecretVaultError>;

    /// Creates empty secret storage protected by `password`. Fails with
    /// [`SecretVaultError::AlreadyExists`] rather than replace storage that exists.
    fn create(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError>;

    fn unlock(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError>;
}

/// Everything a [`crate::Wallet`] runs on.
pub struct Ports<N, S, V> {
    pub node: N,
    pub stores: S,
    pub secrets: V,
    pub clock: Arc<dyn Clock>,
    pub rng: SharedRng,
    /// Blocking work (key derivation, database access) runs on this runtime's blocking pool.
    pub runtime: Handle,
    /// The methods a stored payment may have gone over, as the engine finds the one that
    /// carries a LEPIC notice to its counterparty when it changes state on its own (cancel,
    /// release, decline) and matches notices replayed from the buffer; `None` sends none.
    pub methods: Option<Arc<dyn MethodLookup>>,
}

impl<N, S, V> std::fmt::Debug for Ports<N, S, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}
