//! Wallet passwords the user never sees, sealed under a PIN. The app keeps the sealed text in
//! its secure storage and opens it with the PIN to unlock the wallet.
//!
//! Sealed text is a `lepic-keychain` vault (Argon2id, XChaCha20-Poly1305) in base64. Text sealed
//! by the earlier binding cannot be opened here; seal the password again after the switch.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flutter_rust_bridge::frb;
use lepic_keychain::vault::{MAX_VAULT_LEN, SecretName};
use lepic_keychain::{
    KdfParams, MemoryVaultStorage, SecretBytes, SecretStore as _, Vault, VaultError,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::boundary::guard;

const PASSWORD_SECRET: &str = "app/wallet-password";

fn rng() -> Result<StdRng, WalletError> {
    StdRng::try_from_rng(&mut getrandom::SysRng)
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))
}

fn damaged() -> WalletError {
    WalletError::new(WalletErrorKind::InvalidArgument, "sealed text is damaged")
}

fn sealing_error(error: &VaultError) -> WalletError {
    match error {
        VaultError::Decryption => WalletError::new(
            WalletErrorKind::WrongPassword,
            "pin did not open the sealed text",
        ),
        VaultError::NotFound
        | VaultError::TooLong { .. }
        | VaultError::Truncated { .. }
        | VaultError::NotAVault
        | VaultError::UnsupportedVersion { .. }
        | VaultError::UnsupportedKdf { .. }
        | VaultError::CorruptPayload => damaged(),
        other => WalletError::new(WalletErrorKind::Other, other.to_string()),
    }
}

/// A new random wallet password: 256 bits, hex encoded.
#[frb(sync)]
pub fn generate_wallet_password() -> Result<String, WalletError> {
    guard("generate_wallet_password", || {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *bytes)
            .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    })
}

/// Seals `password` under `pin`. Slow on purpose, so it runs on the runtime. The result is text
/// safe to store.
pub async fn seal_password(
    runtime: &LepicRuntime,
    pin: String,
    password: String,
) -> Result<String, WalletError> {
    let kdf = runtime.inner.kdf;
    runtime
        .inner
        .boundary
        .run("seal_password", async move {
            blocking(move || seal(&Zeroizing::new(pin), &Zeroizing::new(password), kdf)).await
        })
        .await
}

/// Opens text from [`seal_password`]. A wrong PIN gives `WrongPassword`, damaged text
/// `InvalidArgument`.
pub async fn open_password(
    runtime: &LepicRuntime,
    pin: String,
    sealed: String,
) -> Result<String, WalletError> {
    runtime
        .inner
        .boundary
        .run("open_password", async move {
            blocking(move || open(&Zeroizing::new(pin), &sealed)).await
        })
        .await
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, WalletError> + Send + 'static,
) -> Result<T, WalletError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| WalletError::new(WalletErrorKind::Panic, "sealing failed inside lepic"))?
}

fn secret_name() -> Result<SecretName, WalletError> {
    SecretName::new(PASSWORD_SECRET)
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))
}

fn seal(pin: &str, password: &str, kdf: KdfParams) -> Result<String, WalletError> {
    let mut vault = Vault::create(MemoryVaultStorage::new(), rng()?, pin.as_bytes(), kdf)
        .map_err(|error| sealing_error(&error))?;
    vault
        .put(
            &secret_name()?,
            &SecretBytes::from_slice(password.as_bytes()),
        )
        .map_err(|error| WalletError::new(WalletErrorKind::InvalidArgument, error.to_string()))?;
    let bytes = vault
        .into_storage()
        .contents()
        .map(<[u8]>::to_vec)
        .ok_or_else(damaged)?;
    Ok(STANDARD.encode(bytes))
}

fn open(pin: &str, sealed: &str) -> Result<String, WalletError> {
    if sealed.len() > MAX_VAULT_LEN.div_ceil(3).saturating_mul(4) {
        return Err(damaged());
    }
    let bytes = STANDARD.decode(sealed.trim()).map_err(|_| damaged())?;
    let vault = Vault::open(
        MemoryVaultStorage::with_contents(bytes),
        rng()?,
        pin.as_bytes(),
    )
    .map_err(|error| sealing_error(&error))?;
    let secret = vault
        .get(&secret_name()?)
        .map_err(|_| damaged())?
        .ok_or_else(damaged)?;
    String::from_utf8(secret.expose_bytes().to_vec()).map_err(|_| damaged())
}
