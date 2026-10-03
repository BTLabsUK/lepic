//! The wallet password of PIN unlock: generated, sealed and opened again inside Rust, so Dart
//! holds only the sealed text (ADR 0014).
//!
//! Sealed text is a `lepic-keychain` vault (Argon2id, XChaCha20-Poly1305) in base64. Its
//! passphrase is the PIN together with a random key LEPIC keeps in the app's store, so the
//! sealed text cannot be searched for the PIN without that store. Every PIN attempt is counted
//! in the store, and attempts after a few failures wait longer each time.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_keychain::vault::{MAX_VAULT_LEN, SecretName};
use lepic_keychain::{
    KdfParams, MemoryVaultStorage, SecretBytes, SecretStore as _, Vault, VaultError,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::secret_store::AppSecretStore;

const PASSWORD_SECRET: &str = "app/wallet-password";

/// The key of the PIN key in the app's store, next to the vault.
pub(crate) const KEY_KEY: &str = "lepic.pin-key";

/// The key of the count of PIN failures since the last right PIN, in decimal.
pub(crate) const FAILURES_KEY: &str = "lepic.pin-failures";

/// The shortest PIN `create_with_pin` accepts, in characters.
pub(crate) const MIN_PIN_LEN: usize = 4;

const KEY_LEN: usize = 32;

/// How long PIN attempts wait after failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinPolicy {
    /// Failures before attempts start to wait, for typing mistakes.
    pub(crate) free_failures: u32,
    /// The wait once `free_failures` failures are counted; it doubles with each further one.
    pub(crate) first_delay: Duration,
    pub(crate) max_delay: Duration,
}

impl PinPolicy {
    pub(crate) const DEFAULT: Self = Self {
        free_failures: 3,
        first_delay: Duration::from_secs(30),
        max_delay: Duration::from_secs(60 * 60),
    };

    /// The wait before an attempt that follows `failures` failures.
    pub(crate) fn delay(&self, failures: u32) -> Duration {
        let Some(past_free) = failures.checked_sub(self.free_failures) else {
            return Duration::ZERO;
        };
        1u32.checked_shl(past_free)
            .and_then(|factor| self.first_delay.checked_mul(factor))
            .map_or(self.max_delay, |delay| delay.min(self.max_delay))
    }
}

/// PIN attempts of one runtime. They run one at a time, so concurrent calls cannot share one
/// wait or one failure count.
pub(crate) struct PinGuard {
    policy: PinPolicy,
    attempts: Mutex<()>,
}

impl PinGuard {
    pub(crate) fn new(policy: PinPolicy) -> Self {
        Self {
            policy,
            attempts: Mutex::new(()),
        }
    }
}

/// A PIN the user typed, long enough to seal under.
pub(crate) struct NewPin(Zeroizing<String>);

impl NewPin {
    pub(crate) fn new(pin: Zeroizing<String>) -> Result<Self, WalletError> {
        if pin.chars().count() < MIN_PIN_LEN {
            return Err(WalletError::new(
                WalletErrorKind::InvalidArgument,
                format!("pin has fewer than {MIN_PIN_LEN} characters"),
            ));
        }
        Ok(Self(pin))
    }
}

/// The random key the sealed text is bound to.
struct PinKey(Zeroizing<[u8; KEY_LEN]>);

impl PinKey {
    fn generate() -> Result<Self, WalletError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(&mut *key).map_err(|error| other(&error))?;
        Ok(Self(key))
    }

    async fn store(&self, store: &AppSecretStore) -> Result<(), WalletError> {
        store.write(KEY_KEY, STANDARD.encode(*self.0)).await
    }

    async fn load(store: &AppSecretStore) -> Result<Self, WalletError> {
        let text = Zeroizing::new(store.read(KEY_KEY).await?.ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::SecretStore,
                "the app's store holds no pin key",
            )
        })?);
        let bytes = Zeroizing::new(STANDARD.decode(text.as_bytes()).map_err(|_| bad_key())?);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        if bytes.len() != KEY_LEN {
            return Err(bad_key());
        }
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    /// The vault passphrase: this key, then the PIN.
    fn passphrase(&self, pin: &str) -> Zeroizing<Vec<u8>> {
        let mut passphrase = Zeroizing::new(Vec::with_capacity(KEY_LEN.saturating_add(pin.len())));
        passphrase.extend_from_slice(&*self.0);
        passphrase.extend_from_slice(pin.as_bytes());
        passphrase
    }
}

fn other(error: &dyn std::fmt::Display) -> WalletError {
    WalletError::new(WalletErrorKind::Other, error.to_string())
}

fn bad_key() -> WalletError {
    WalletError::new(
        WalletErrorKind::SecretStore,
        "the pin key in the app's store is damaged",
    )
}

fn rng() -> Result<StdRng, WalletError> {
    StdRng::try_from_rng(&mut getrandom::SysRng).map_err(|error| other(&error))
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
    SecretName::new(PASSWORD_SECRET).map_err(|error| other(&error))
}

/// A new random wallet password: 256 bits, hex encoded.
pub(crate) fn generate_password() -> Result<Zeroizing<String>, WalletError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|error| other(&error))?;
    let mut text = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        for nibble in [byte >> 4, byte & 0x0f] {
            text.push(char::from(
                HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    Ok(text)
}

/// Seals `password` under `pin` and a new PIN key, which goes into `store` first; the failure
/// count starts again at zero. Returns the sealed text.
pub(crate) async fn seal_new(
    store: &AppSecretStore,
    pin: NewPin,
    password: Zeroizing<String>,
    kdf: KdfParams,
) -> Result<String, WalletError> {
    let key = PinKey::generate()?;
    key.store(store).await?;
    store.delete(FAILURES_KEY).await?;
    blocking(move || seal(&key, &pin.0, &password, kdf)).await
}

fn seal(key: &PinKey, pin: &str, password: &str, kdf: KdfParams) -> Result<String, WalletError> {
    let mut vault = Vault::create(MemoryVaultStorage::new(), rng()?, &key.passphrase(pin), kdf)
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

fn open(key: &PinKey, pin: &str, sealed: &str) -> Result<Zeroizing<String>, WalletError> {
    if sealed.len() > MAX_VAULT_LEN.div_ceil(3).saturating_mul(4) {
        return Err(damaged());
    }
    let bytes = STANDARD.decode(sealed.trim()).map_err(|_| damaged())?;
    let vault = Vault::open(
        MemoryVaultStorage::with_contents(bytes),
        rng()?,
        &key.passphrase(pin),
    )
    .map_err(|error| sealing_error(&error))?;
    let secret = vault
        .get(&secret_name()?)
        .map_err(|_| damaged())?
        .ok_or_else(damaged)?;
    let text = std::str::from_utf8(secret.expose_bytes()).map_err(|_| damaged())?;
    Ok(Zeroizing::new(text.to_owned()))
}

async fn read_failures(store: &AppSecretStore) -> Result<u32, WalletError> {
    // A count that does not parse costs the longest wait rather than none.
    Ok(store
        .read(FAILURES_KEY)
        .await?
        .map_or(0, |text| text.trim().parse().unwrap_or(u32::MAX)))
}

async fn write_failures(store: &AppSecretStore, failures: u32) -> Result<(), WalletError> {
    if failures == 0 {
        store.delete(FAILURES_KEY).await
    } else {
        store.write(FAILURES_KEY, failures.to_string()).await
    }
}

/// The password sealed in `sealed`, opened with `pin` and the PIN key in `store`. Waits as
/// `guard`'s policy says for the failures counted in `store`. The attempt is counted as a
/// failure before the PIN is tried, so stopping the app mid-attempt does not undo it; a right
/// PIN clears the count and damaged text restores it.
///
/// A wrong PIN gives `WrongPassword`, damaged text `InvalidArgument`, a missing or damaged PIN
/// key `SecretStore`.
pub(crate) async fn unlock(
    guard: &PinGuard,
    store: &AppSecretStore,
    pin: Zeroizing<String>,
    sealed: String,
) -> Result<Zeroizing<String>, WalletError> {
    let _attempt = guard.attempts.lock().await;
    let failures = read_failures(store).await?;
    write_failures(store, failures.saturating_add(1)).await?;
    tokio::time::sleep(guard.policy.delay(failures)).await;
    let key = PinKey::load(store).await?;
    let opened = blocking(move || open(&key, &pin, &sealed)).await;
    match &opened {
        Err(error) if error.kind == WalletErrorKind::WrongPassword => {}
        Ok(_) => write_failures(store, 0).await?,
        Err(_) => write_failures(store, failures).await?,
    }
    opened
}

/// Removes the PIN key and the failure count from `store`.
pub(crate) async fn forget(store: &AppSecretStore) -> Result<(), WalletError> {
    store.delete(KEY_KEY).await?;
    store.delete(FAILURES_KEY).await
}

/// Runs sealing work on the blocking pool, where Argon2 does not stall the runtime.
async fn blocking<T: Send + 'static>(
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

    fn pin(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    #[test]
    fn sealed_password_opens_only_with_its_pin_and_key() {
        let password = generate_password().unwrap();
        assert_eq!(password.len(), 64);
        assert!(password.bytes().all(|b| b.is_ascii_hexdigit()));
        let key = PinKey::generate().unwrap();
        let sealed = seal(&key, "1234", &password, cheap()).unwrap();
        assert!(!sealed.contains(password.as_str()));
        assert_eq!(*open(&key, "1234", &sealed).unwrap(), *password);
        assert_eq!(
            open(&key, "0000", &sealed).unwrap_err().kind,
            WalletErrorKind::WrongPassword
        );
        let other_key = PinKey::generate().unwrap();
        assert_eq!(
            open(&other_key, "1234", &sealed).unwrap_err().kind,
            WalletErrorKind::WrongPassword
        );
        assert_eq!(
            open(&key, "1234", "damaged").unwrap_err().kind,
            WalletErrorKind::InvalidArgument
        );
    }

    #[test]
    fn new_pin_needs_four_characters() {
        assert!(NewPin::new(pin("")).is_err());
        assert!(NewPin::new(pin("123")).is_err());
        assert!(NewPin::new(pin("1234")).is_ok());
        // Characters, not bytes: three two-byte characters are still too short.
        assert!(NewPin::new(pin("äöü")).is_err());
    }

    #[test]
    fn waits_start_after_the_free_failures_and_double_up_to_the_cap() {
        let policy = PinPolicy::DEFAULT;
        let secs = |failures| policy.delay(failures).as_secs();
        assert_eq!([secs(0), secs(1), secs(2)], [0, 0, 0]);
        assert_eq!([secs(3), secs(4), secs(5)], [30, 60, 120]);
        assert_eq!(secs(10), 3600);
        assert_eq!(secs(40), 3600);
        assert_eq!(secs(u32::MAX), 3600);
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_after_the_free_failures_wait() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let password = generate_password().unwrap();
        let sealed = seal_new(
            &store,
            NewPin::new(pin("1234")).unwrap(),
            password.clone(),
            cheap(),
        )
        .await
        .unwrap();
        for _ in 0..3 {
            let started = tokio::time::Instant::now();
            assert!(
                unlock(&guard, &store, pin("0000"), sealed.clone())
                    .await
                    .is_err()
            );
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
        let started = tokio::time::Instant::now();
        assert!(
            unlock(&guard, &store, pin("0000"), sealed.clone())
                .await
                .is_err()
        );
        assert_eq!(started.elapsed(), Duration::from_secs(30));

        let started = tokio::time::Instant::now();
        let opened = unlock(&guard, &store, pin("1234"), sealed.clone())
            .await
            .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        assert_eq!(*opened, *password);

        let started = tokio::time::Instant::now();
        assert!(unlock(&guard, &store, pin("1234"), sealed).await.is_ok());
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// Concurrent attempts queue: each counts on top of the last and waits its own delay.
    #[tokio::test(start_paused = true)]
    async fn concurrent_attempts_run_one_at_a_time() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let password = generate_password().unwrap();
        let sealed = seal_new(&store, NewPin::new(pin("1234")).unwrap(), password, cheap())
            .await
            .unwrap();
        store.write(FAILURES_KEY, "3".to_owned()).await.unwrap();

        let started = tokio::time::Instant::now();
        let attempt = || unlock(&guard, &store, pin("0000"), sealed.clone());
        let (first, second, third) = tokio::join!(attempt(), attempt(), attempt());
        for result in [first, second, third] {
            assert_eq!(result.unwrap_err().kind, WalletErrorKind::WrongPassword);
        }
        assert_eq!(started.elapsed(), Duration::from_secs(30 + 60 + 120));
        assert_eq!(read_failures(&store).await.unwrap(), 6);
    }

    #[tokio::test]
    async fn a_count_that_does_not_parse_costs_the_longest_wait() {
        let store = AppSecretStore::in_memory();
        store.write(FAILURES_KEY, "x".to_owned()).await.unwrap();
        assert_eq!(read_failures(&store).await.unwrap(), u32::MAX);
    }
}
