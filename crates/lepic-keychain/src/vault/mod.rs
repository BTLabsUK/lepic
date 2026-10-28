// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/lifecycle/seed.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Seed storage: the [`SecretStore`] port, the desktop vault that implements it, and the
//! read-only import of `epic-wallet`'s `wallet.seed`.
//!
//! The vault keeps named secrets in one file, sealed with XChaCha20-Poly1305 under an Argon2id
//! key (ADR 0005). This crate does no I/O: a [`VaultStorage`] supplied by the caller reads and
//! replaces the file, and the caller supplies the randomness.

mod format;
mod kdf;
mod store;
mod wallet_seed;

use std::collections::BTreeMap;
use std::fmt;

use rand_core::CryptoRng;
use thiserror::Error;

pub use format::{
    FORMAT_VERSION, HEADER_LEN, MAGIC, MAX_SECRET_LEN, MAX_SECRETS, MAX_VAULT_LEN, MIN_VAULT_LEN,
    NONCE_LEN, TAG_LEN, VaultFile, VaultHeader,
};
pub use kdf::{
    KEY_LEN, KdfParams, KdfParamsError, MAX_ITERATIONS, MAX_MEMORY_KIB, MAX_PARALLELISM,
    MIN_WRITE_COST_KIB, MIN_WRITE_MEMORY_KIB, SALT_LEN,
};
pub use store::{
    BackendError, MAX_SECRET_NAME_LEN, SecretBytes, SecretName, SecretNameError, SecretStore,
    SecretStoreError,
};
pub use wallet_seed::{
    MAX_WALLET_SEED_FILE_LEN, WALLET_SEED_NONCE_LEN, WALLET_SEED_SALT_LEN, WalletSeedError,
    WalletSeedField, WalletSeedFile,
};

use format::Secrets;
use kdf::VaultKey;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultError {
    #[error("no vault is stored")]
    NotFound,
    #[error("a vault is already stored")]
    AlreadyExists,
    #[error("vault file has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("vault file is truncated, {actual} bytes where at least {min} are needed")]
    Truncated { actual: usize, min: usize },
    #[error("file is not a lepic vault")]
    NotAVault,
    #[error("vault format version {version} is not supported")]
    UnsupportedVersion { version: u8 },
    #[error("vault key derivation {kdf} is not supported")]
    UnsupportedKdf { kdf: u8 },
    #[error("vault key derivation parameters are invalid")]
    KdfParams(#[from] KdfParamsError),
    /// A new vault or a rekey asked for parameters below the write floor.
    #[error("argon2id parameters m={memory_kib} KiB t={iterations} are too weak for a new vault")]
    WeakKdf { memory_kib: u32, iterations: u32 },
    #[error("vault key could not be derived")]
    Kdf(#[source] argon2::Error),
    #[error("vault could not be encrypted")]
    Encryption,
    /// The password is wrong or the file was changed. The cipher cannot tell these apart.
    #[error("vault did not decrypt with this password")]
    Decryption,
    #[error("vault decrypted but its contents are malformed")]
    CorruptPayload,
    #[error("vault holds {max} secrets, the most it can")]
    TooManySecrets { max: usize },
    #[error("secret has {actual} bytes, the vault accepts at most {max}")]
    SecretTooLarge { actual: usize, max: usize },
    #[error("vault storage failed")]
    Storage(#[source] BackendError),
}

fn check_writable(params: KdfParams) -> Result<(), VaultError> {
    if params.writable() {
        Ok(())
    } else {
        Err(VaultError::WeakKdf {
            memory_kib: params.memory_kib(),
            iterations: params.iterations(),
        })
    }
}

/// Where the vault file lives. The desktop implementation is a file next to the wallet database.
pub trait VaultStorage {
    /// The stored bytes, or `None` when no vault has been stored yet.
    fn load(&self) -> Result<Option<Vec<u8>>, BackendError>;

    /// Replaces the stored bytes with `contents` atomically: after a crash or power loss, reading
    /// returns either the previous contents or `contents`, never a mix. On a filesystem, write a
    /// temporary file in the same directory, sync it, rename it over the vault and sync the
    /// directory.
    fn replace(&mut self, contents: &[u8]) -> Result<(), BackendError>;
}

/// Keeps the vault bytes in memory. For tests and for hosts that persist the bytes themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryVaultStorage {
    contents: Option<Vec<u8>>,
}

impl MemoryVaultStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_contents(contents: Vec<u8>) -> Self {
        Self {
            contents: Some(contents),
        }
    }

    pub fn contents(&self) -> Option<&[u8]> {
        self.contents.as_deref()
    }
}

impl VaultStorage for MemoryVaultStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.contents.clone())
    }

    fn replace(&mut self, contents: &[u8]) -> Result<(), BackendError> {
        self.contents = Some(contents.to_vec());
        Ok(())
    }
}

/// An unlocked vault. Holds the derived key, so changes are written without running the KDF
/// again, and every change is written to storage before the method returns.
pub struct Vault<S, R> {
    storage: S,
    rng: R,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    key: VaultKey,
    secrets: Secrets,
}

impl<S: VaultStorage, R: CryptoRng> Vault<S, R> {
    /// Creates an empty vault and writes it. Fails with [`VaultError::AlreadyExists`] rather
    /// than overwrite a stored vault, and with [`VaultError::WeakKdf`] for parameters below the
    /// write floor.
    pub fn create(
        storage: S,
        mut rng: R,
        password: &[u8],
        params: KdfParams,
    ) -> Result<Self, VaultError> {
        check_writable(params)?;
        if storage.load().map_err(VaultError::Storage)?.is_some() {
            return Err(VaultError::AlreadyExists);
        }
        let salt = random_array(&mut rng);
        let key = params
            .derive_key(password, &salt)
            .map_err(VaultError::Kdf)?;
        let mut vault = Self {
            storage,
            rng,
            params,
            salt,
            key,
            secrets: BTreeMap::new(),
        };
        vault.write()?;
        Ok(vault)
    }

    /// Reads and decrypts the stored vault.
    pub fn open(storage: S, rng: R, password: &[u8]) -> Result<Self, VaultError> {
        let bytes = storage
            .load()
            .map_err(VaultError::Storage)?
            .ok_or(VaultError::NotFound)?;
        let file = VaultFile::decode(&bytes)?;
        let header = file.header();
        let key = header
            .params
            .derive_key(password, &header.salt)
            .map_err(VaultError::Kdf)?;
        let secrets = file.open(&key)?;
        Ok(Self {
            params: header.params,
            salt: header.salt,
            storage,
            rng,
            key,
            secrets,
        })
    }

    /// Re-encrypts every secret under `password` with `params` and a fresh salt. The vault keeps
    /// its previous password and parameters if the write fails. Fails with
    /// [`VaultError::WeakKdf`] for parameters below the write floor.
    pub fn rekey(&mut self, password: &[u8], params: KdfParams) -> Result<(), VaultError> {
        check_writable(params)?;
        let salt = random_array(&mut self.rng);
        let key = params
            .derive_key(password, &salt)
            .map_err(VaultError::Kdf)?;
        let header = self.next_header(params, salt);
        store_sealed(&mut self.storage, header, &key, &self.secrets)?;
        self.params = params;
        self.salt = salt;
        self.key = key;
        Ok(())
    }

    pub fn params(&self) -> KdfParams {
        self.params
    }

    pub fn names(&self) -> impl Iterator<Item = &SecretName> {
        self.secrets.keys()
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn into_storage(self) -> S {
        self.storage
    }

    fn write(&mut self) -> Result<(), VaultError> {
        let header = self.next_header(self.params, self.salt);
        store_sealed(&mut self.storage, header, &self.key, &self.secrets)
    }

    fn next_header(&mut self, params: KdfParams, salt: [u8; SALT_LEN]) -> VaultHeader {
        VaultHeader {
            params,
            salt,
            nonce: random_array(&mut self.rng),
        }
    }

    fn check_capacity(&self, name: &SecretName, secret: &SecretBytes) -> Result<(), VaultError> {
        if secret.len() > MAX_SECRET_LEN {
            return Err(VaultError::SecretTooLarge {
                actual: secret.len(),
                max: MAX_SECRET_LEN,
            });
        }
        if !self.secrets.contains_key(name) && self.secrets.len() >= MAX_SECRETS {
            return Err(VaultError::TooManySecrets { max: MAX_SECRETS });
        }
        Ok(())
    }
}

impl<S: VaultStorage, R: CryptoRng> SecretStore for Vault<S, R> {
    fn put(&mut self, name: &SecretName, secret: &SecretBytes) -> Result<(), SecretStoreError> {
        self.check_capacity(name, secret)?;
        let previous = self.secrets.insert(name.clone(), secret.clone());
        if let Err(error) = self.write() {
            match previous {
                Some(previous) => self.secrets.insert(name.clone(), previous),
                None => self.secrets.remove(name),
            };
            return Err(error.into());
        }
        Ok(())
    }

    fn get(&self, name: &SecretName) -> Result<Option<SecretBytes>, SecretStoreError> {
        Ok(self.secrets.get(name).cloned())
    }

    fn delete(&mut self, name: &SecretName) -> Result<bool, SecretStoreError> {
        let Some(previous) = self.secrets.remove(name) else {
            return Ok(false);
        };
        if let Err(error) = self.write() {
            self.secrets.insert(name.clone(), previous);
            return Err(error.into());
        }
        Ok(true)
    }
}

impl From<VaultError> for SecretStoreError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::SecretTooLarge { actual, max } => Self::SecretTooLarge { actual, max },
            VaultError::TooManySecrets { max } => Self::Full { max },
            VaultError::Storage(source) => Self::Backend(source),
            other => Self::Backend(Box::new(other)),
        }
    }
}

impl<S, R> fmt::Debug for Vault<S, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("params", &self.params)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

fn store_sealed(
    storage: &mut impl VaultStorage,
    header: VaultHeader,
    key: &VaultKey,
    secrets: &Secrets,
) -> Result<(), VaultError> {
    let file = VaultFile::seal(header, key, secrets)?;
    storage.replace(&file.encode()).map_err(VaultError::Storage)
}

fn random_array<const N: usize>(rng: &mut impl CryptoRng) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}
