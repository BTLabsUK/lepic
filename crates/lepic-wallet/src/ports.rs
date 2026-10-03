//! The ports the engine runs on. The host supplies every one of them; the engine owns no
//! runtime, clock, randomness or storage of its own (ADR 0011).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jiff::Timestamp;
use lepic_keychain::SecretStore;
use lepic_keychain::vault::BackendError;
#[cfg(feature = "sqlite")]
use lepic_store::SqliteStore;
use lepic_store::{ContextKey, StoreError, WalletStore};
use lepic_transport::registry::TransportRegistry;
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
/// transaction contexts are sealed under a key derived from it.
pub trait StoreOpener: Send + Sync {
    type Store: WalletStore + 'static;

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<Self::Store, StoreError>;
}

#[cfg(feature = "sqlite")]
/// File name of the wallet database inside the data directory.
pub const DATABASE_FILE: &str = "wallet.sqlite3";

#[cfg(feature = "sqlite")]
/// The product store: SQLite in [`DATABASE_FILE`] inside the configured data directory, which
/// must exist.
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteStores;

#[cfg(feature = "sqlite")]
impl StoreOpener for SqliteStores {
    type Store = SqliteStore;

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<SqliteStore, StoreError> {
        SqliteStore::open(&data_dir.join(DATABASE_FILE), key)
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
    pub transports: TransportRegistry,
    pub clock: Arc<dyn Clock>,
    pub rng: SharedRng,
    /// Blocking work (key derivation, database access) runs on this runtime's blocking pool.
    pub runtime: Handle,
}

impl<N, S, V> std::fmt::Debug for Ports<N, S, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports")
            .field("transports", &self.transports)
            .finish_non_exhaustive()
    }
}
