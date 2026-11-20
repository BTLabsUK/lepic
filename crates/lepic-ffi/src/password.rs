// SPDX-License-Identifier: Apache-2.0
//! Changing the password of a password wallet: the vault in the app's store is re-encrypted
//! under the new password without ever leaving the store without a vault that opens. A reset
//! after a forgotten password installs a new vault holding the seed the same way.
//!
//! The new vault is written to `lepic.vault-next` first and read back, then written over
//! `lepic.vault`, and only then is `lepic.vault-next` deleted. Whatever step a stop interrupts,
//! `lepic.vault` opens with the old or the new password, or `lepic.vault-next` opens with the
//! new one, and the next open settles it (see `Session::open`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_keychain::{KdfParams, MemoryVaultStorage, SecretStore as _, Seed, Vault};
use rand::rngs::StdRng;
use tracing::warn;
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::secret_store::AppSecretStore;
use crate::vault_port::{VAULT_KEY, VAULT_NEXT_KEY, blocking, decode, rng, vault_error};

/// A vault opened in memory, apart from the app's store.
pub(crate) type MemoryVault = Vault<MemoryVaultStorage, StdRng>;

fn store_failed(message: &str) -> WalletError {
    WalletError::new(WalletErrorKind::SecretStore, message)
}

/// Opens vault `text` with `password` on the blocking pool, where Argon2 does not stall the
/// runtime: `WrongPassword` when it does not open, `SecretStore` when the text is damaged.
pub(crate) async fn open_text(
    text: &str,
    password: Zeroizing<String>,
) -> Result<MemoryVault, WalletError> {
    let bytes = decode(text)?;
    blocking(move || {
        Vault::open(
            MemoryVaultStorage::with_contents(bytes),
            rng()?,
            password.as_bytes(),
        )
        .map_err(|error| WalletError::from(lepic_wallet::WalletError::from(vault_error(error))))
    })
    .await
}

/// The stored vault, opened with `password`.
pub(crate) async fn open_stored(
    store: &AppSecretStore,
    password: Zeroizing<String>,
) -> Result<MemoryVault, WalletError> {
    let text = store.read(VAULT_KEY).await?.ok_or_else(|| {
        WalletError::new(
            WalletErrorKind::WalletNotFound,
            "the app's store holds no vault",
        )
    })?;
    open_text(&text, password).await
}

/// Re-encrypts `vault`, the stored vault opened with the current password, under `new` with
/// `kdf` and a fresh salt, and makes it the stored vault.
///
/// Fails with `SecretStore` when the store fails or does not give back what was written. The
/// stored vault then still opens with the current password, unless the store failed while
/// reporting the write of `lepic.vault` itself; `lepic.vault-next` is then kept, so the next
/// open finishes the change with the new password or drops it with the current one.
pub(crate) async fn replace(
    store: &AppSecretStore,
    vault: MemoryVault,
    new: Zeroizing<String>,
    kdf: KdfParams,
) -> Result<(), WalletError> {
    let rekey_password = new.clone();
    let vault = blocking(move || {
        let mut vault = vault;
        vault
            .rekey(rekey_password.as_bytes(), kdf)
            .map_err(|error| {
                WalletError::from(lepic_wallet::WalletError::from(vault_error(error)))
            })?;
        Ok(vault)
    })
    .await?;
    install(store, vault, new).await
}

/// A new vault holding only `seed`, as a new wallet's does, sealed under `password` with `kdf`.
pub(crate) async fn seal_seed(
    seed: Seed,
    password: Zeroizing<String>,
    kdf: KdfParams,
) -> Result<MemoryVault, WalletError> {
    blocking(move || {
        let mut vault = Vault::create(MemoryVaultStorage::new(), rng()?, password.as_bytes(), kdf)
            .map_err(|error| {
                WalletError::from(lepic_wallet::WalletError::from(vault_error(error)))
            })?;
        lepic_wallet::lifecycle::put_seed(&mut vault, &seed)?;
        Ok(vault)
    })
    .await
}

/// Makes `vault`, sealed under `new`, the stored vault in place of whatever is stored, in the
/// steps the module describes. Fails as [`replace`] does.
pub(crate) async fn install(
    store: &AppSecretStore,
    vault: MemoryVault,
    new: Zeroizing<String>,
) -> Result<(), WalletError> {
    let text = vault
        .storage()
        .contents()
        .map(|bytes| STANDARD.encode(bytes))
        .ok_or_else(|| store_failed("the new vault was not sealed"))?;

    let written = match store.write(VAULT_NEXT_KEY, text.clone()).await {
        Ok(()) => read_back(store, &text, new, vault).await,
        Err(error) => Err(error),
    };
    if let Err(error) = written {
        discard_next(store).await;
        return Err(error);
    }
    if let Err(error) = store.write(VAULT_KEY, text.clone()).await {
        // A store may fail after it wrote; what it holds now decides.
        match store.read(VAULT_KEY).await {
            Ok(Some(stored)) if stored == text => {}
            Ok(Some(_)) => {
                discard_next(store).await;
                return Err(error);
            }
            // Without a vault to fall back on, `lepic.vault-next` is the wallet.
            Ok(None) | Err(_) => return Err(error),
        }
    }
    discard_next(store).await;
    Ok(())
}

/// Checks that `lepic.vault-next` holds `text` and opens with the new password to the secrets
/// of `vault`.
async fn read_back(
    store: &AppSecretStore,
    text: &str,
    password: Zeroizing<String>,
    vault: MemoryVault,
) -> Result<(), WalletError> {
    let stored = store.read(VAULT_NEXT_KEY).await?;
    if stored.as_deref() != Some(text) {
        return Err(store_failed("the app's store did not keep the new vault"));
    }
    let reopened = open_text(text, password).await?;
    if same_secrets(&vault, &reopened)? {
        Ok(())
    } else {
        Err(store_failed(
            "the new vault does not hold the wallet's secrets",
        ))
    }
}

fn same_secrets(left: &MemoryVault, right: &MemoryVault) -> Result<bool, WalletError> {
    if left.names().count() != right.names().count() {
        return Ok(false);
    }
    for name in left.names() {
        let (Ok(Some(a)), Ok(Some(b))) = (left.get(name), right.get(name)) else {
            return Ok(false);
        };
        if a.expose_bytes() != b.expose_bytes() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Deletes `lepic.vault-next`. A failure only delays it to the next open, which deletes or
/// applies it.
pub(crate) async fn discard_next(store: &AppSecretStore) {
    if let Err(error) = store.delete(VAULT_NEXT_KEY).await {
        warn!(error = %error, "pending vault not deleted");
    }
}
