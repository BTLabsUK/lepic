//! The engine's `SecretVault` port over the app's store. The engine reads and writes the vault
//! synchronously, while the app's store answers asynchronously from Dart, so the vault bytes are
//! loaded before an engine call and written back after it.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_keychain::vault::BackendError;
use lepic_keychain::vault::MAX_VAULT_LEN;
use lepic_keychain::{KdfParams, Vault, VaultError, VaultStorage};
use lepic_wallet::{Password, SecretVault, SecretVaultError};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::secret_store::AppSecretStore;

/// The key of the vault in the app's store.
pub(crate) const VAULT_KEY: &str = "lepic.vault";

#[derive(Default)]
struct Bytes {
    stored: Option<Vec<u8>>,
    dirty: bool,
}

/// The vault bytes of one wallet, shared between the engine and the code that syncs them with
/// the app's store.
#[derive(Clone, Default)]
pub(crate) struct VaultBytes(Arc<Mutex<Bytes>>);

impl VaultBytes {
    fn lock(&self) -> MutexGuard<'_, Bytes> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the bytes with what the app's store holds now.
    pub(crate) async fn load(&self, store: &AppSecretStore) -> Result<(), WalletError> {
        let stored = store
            .read(VAULT_KEY)
            .await?
            .map(|text| decode(&text))
            .transpose()?;
        *self.lock() = Bytes {
            stored,
            dirty: false,
        };
        Ok(())
    }

    /// Writes the bytes to the app's store if the engine changed them.
    pub(crate) async fn flush(&self, store: &AppSecretStore) -> Result<(), WalletError> {
        let pending = {
            let bytes = self.lock();
            match (&bytes.stored, bytes.dirty) {
                (Some(stored), true) => Some(STANDARD.encode(stored)),
                _ => None,
            }
        };
        if let Some(text) = pending {
            store.write(VAULT_KEY, text).await?;
            self.lock().dirty = false;
        }
        Ok(())
    }
}

fn decode(text: &str) -> Result<Vec<u8>, WalletError> {
    let damaged = || WalletError::new(WalletErrorKind::SecretStore, "stored vault is damaged");
    // Base64 of the largest vault, rounded up, bounds the work before decoding.
    let max_text = MAX_VAULT_LEN.div_ceil(3).saturating_mul(4);
    if text.len() > max_text {
        return Err(damaged());
    }
    STANDARD.decode(text.as_bytes()).map_err(|_| damaged())
}

/// What the engine's vault writes into.
#[derive(Clone)]
pub(crate) struct SharedStorage(VaultBytes);

impl SharedStorage {
    pub(crate) fn new(bytes: VaultBytes) -> Self {
        Self(bytes)
    }
}

impl VaultStorage for SharedStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.0.lock().stored.clone())
    }

    fn replace(&mut self, contents: &[u8]) -> Result<(), BackendError> {
        let mut bytes = self.0.lock();
        bytes.stored = Some(contents.to_vec());
        bytes.dirty = true;
        Ok(())
    }
}

/// The wallet's secret storage: a `lepic-keychain` vault whose bytes live in the app's store.
pub(crate) struct AppVault {
    bytes: VaultBytes,
    kdf: KdfParams,
}

impl AppVault {
    pub(crate) fn new(bytes: VaultBytes, kdf: KdfParams) -> Self {
        Self { bytes, kdf }
    }
}

fn os_rng() -> Result<StdRng, SecretVaultError> {
    StdRng::try_from_rng(&mut getrandom::SysRng)
        .map_err(|error| SecretVaultError::Backend(Box::new(error)))
}

pub(crate) fn vault_error(error: VaultError) -> SecretVaultError {
    match error {
        VaultError::NotFound => SecretVaultError::NotFound,
        VaultError::AlreadyExists => SecretVaultError::AlreadyExists,
        VaultError::Decryption => SecretVaultError::WrongPassword,
        other => SecretVaultError::Backend(Box::new(other)),
    }
}

impl SecretVault for AppVault {
    type Secrets = Vault<SharedStorage, StdRng>;

    fn exists(&self) -> Result<bool, SecretVaultError> {
        Ok(self.bytes.lock().stored.is_some())
    }

    fn create(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError> {
        Vault::create(
            SharedStorage(self.bytes.clone()),
            os_rng()?,
            password.expose_bytes(),
            self.kdf,
        )
        .map_err(vault_error)
    }

    fn unlock(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError> {
        Vault::open(
            SharedStorage(self.bytes.clone()),
            os_rng()?,
            password.expose_bytes(),
        )
        .map_err(vault_error)
    }
}
