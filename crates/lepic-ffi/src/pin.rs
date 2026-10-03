//! The wallet password of PIN unlock: generated, sealed under the PIN and opened again inside
//! Rust, so Dart holds only the sealed text (ADR 0014).
//!
//! Sealed text is a `lepic-keychain` vault (Argon2id, XChaCha20-Poly1305) in base64.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_keychain::vault::{MAX_VAULT_LEN, SecretName};
use lepic_keychain::{
    KdfParams, MemoryVaultStorage, SecretBytes, SecretStore as _, Vault, VaultError,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};

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

fn secret_name() -> Result<SecretName, WalletError> {
    SecretName::new(PASSWORD_SECRET)
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))
}

/// A new random wallet password: 256 bits, hex encoded.
pub(crate) fn generate_password() -> Result<Zeroizing<String>, WalletError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
    let mut text = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        text.push_str(&format!("{byte:02x}"));
    }
    Ok(text)
}

/// `password` sealed under `pin`, as text safe to store. Slow on purpose; run it off the
/// runtime's worker threads.
pub(crate) fn seal(pin: &str, password: &str, kdf: KdfParams) -> Result<String, WalletError> {
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

/// The password sealed in `sealed`. A wrong PIN gives `WrongPassword`, damaged text
/// `InvalidArgument`.
pub(crate) fn open(pin: &str, sealed: &str) -> Result<Zeroizing<String>, WalletError> {
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
    let text = std::str::from_utf8(secret.expose_bytes()).map_err(|_| damaged())?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Runs sealing work on the blocking pool, where Argon2 does not stall the runtime.
pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, WalletError> + Send + 'static,
) -> Result<T, WalletError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| WalletError::new(WalletErrorKind::Panic, "sealing failed inside lepic"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    #[test]
    fn sealed_password_opens_only_with_its_pin() {
        let password = generate_password().unwrap();
        assert_eq!(password.len(), 64);
        let sealed = seal("1234", &password, cheap()).unwrap();
        assert!(!sealed.contains(password.as_str()));
        assert_eq!(*open("1234", &sealed).unwrap(), *password);
        assert_eq!(
            open("0000", &sealed).unwrap_err().kind,
            WalletErrorKind::WrongPassword
        );
        assert_eq!(
            open("1234", "damaged").unwrap_err().kind,
            WalletErrorKind::InvalidArgument
        );
    }
}
