//! The wallet password of PIN unlock: generated, sealed and opened again inside Rust, so Dart
//! holds only the sealed text (ADR 0014).
//!
//! Sealed text is a `lepic-keychain` vault (Argon2id, XChaCha20-Poly1305) in base64. Its
//! passphrase is the PIN together with a random key LEPIC keeps in the app's store, so the
//! sealed text cannot be searched for the PIN without that store. Every PIN attempt is counted
//! in the store, and attempts after a few failures wait longer each time. Wallet passwords the
//! user types are counted and delayed the same way.
//!
//! A PIN change is two-phase. It writes a pending key beside the current one, so the old and
//! the new sealed text both open until the app confirms it stored the new text; confirming
//! makes the pending key current.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_keychain::vault::{MAX_VAULT_LEN, SecretName};
use lepic_keychain::{
    KdfParams, MemoryVaultStorage, SecretBytes, SecretStore as _, Vault, VaultError,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::secret_store::AppSecretStore;

const PASSWORD_SECRET: &str = "app/wallet-password";

/// The key of the PIN key in the app's store, next to the vault.
pub(crate) const KEY_KEY: &str = "lepic.pin-key";

/// The key of the PIN key of a PIN change not confirmed yet, next to the current one.
pub(crate) const PENDING_KEY_KEY: &str = "lepic.pin-key-pending";

/// The key of the count of PIN or password failures since the last right one, in decimal.
pub(crate) const FAILURES_KEY: &str = "lepic.pin-failures";

/// The shortest PIN `create_with_pin` and `change_pin` accept, in characters. Unlocking does
/// not check it, so text sealed under a shorter PIN of an earlier version keeps opening.
pub(crate) const MIN_PIN_LEN: usize = 6;

const KEY_LEN: usize = 32;

/// The length of the PIN key in padded base64.
const KEY_TEXT_LEN: usize = 44;

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

    async fn store(&self, store: &AppSecretStore, slot: &str) -> Result<(), WalletError> {
        store.write(slot, self.to_text()?).await
    }

    /// Encodes straight from the key's buffer into another wiped buffer: no copy of the array,
    /// and no encoder scratch space, holds the key. Only the text for the store is left.
    fn to_text(&self) -> Result<String, WalletError> {
        let mut text = Zeroizing::new([0u8; KEY_TEXT_LEN]);
        let written = STANDARD
            .encode_slice(self.0.as_slice(), text.as_mut_slice())
            .map_err(|error| other(&error))?;
        let text = text
            .get(..written)
            .and_then(|text| std::str::from_utf8(text).ok())
            .ok_or_else(bad_key)?;
        Ok(text.to_owned())
    }

    async fn load(store: &AppSecretStore) -> Result<Self, WalletError> {
        let text = Zeroizing::new(store.read(KEY_KEY).await?.ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::SecretStore,
                "the app's store holds no pin key",
            )
        })?);
        Self::from_text(&text)
    }

    /// Decodes into the key's own wiped buffer, without an intermediate vector.
    fn from_text(text: &str) -> Result<Self, WalletError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        match STANDARD.decode_slice(text.as_bytes(), key.as_mut_slice()) {
            Ok(KEY_LEN) => Ok(Self(key)),
            _ => Err(bad_key()),
        }
    }

    /// The vault passphrase: this key, then the PIN.
    fn passphrase(&self, pin: &str) -> Zeroizing<Vec<u8>> {
        let mut passphrase = Zeroizing::new(Vec::with_capacity(KEY_LEN.saturating_add(pin.len())));
        passphrase.extend_from_slice(&*self.0);
        passphrase.extend_from_slice(pin.as_bytes());
        passphrase
    }
}

/// The key of an unconfirmed PIN change and a digest of the sealed text that change returned,
/// so a confirmation can check that the app holds that text without needing the PIN. Stored
/// as `<key>.<digest>`, both in padded base64.
struct PendingKey {
    key: PinKey,
    sealed_digest: [u8; DIGEST_LEN],
}

const DIGEST_LEN: usize = 32;

impl PendingKey {
    fn new(key: PinKey, sealed: &str) -> Self {
        Self {
            key,
            sealed_digest: sealed_digest(sealed),
        }
    }

    async fn store(&self, store: &AppSecretStore) -> Result<(), WalletError> {
        let key = Zeroizing::new(self.key.to_text()?);
        let digest = STANDARD.encode(self.sealed_digest);
        let mut text = Zeroizing::new(String::with_capacity(
            key.len().saturating_add(1).saturating_add(digest.len()),
        ));
        text.push_str(&key);
        text.push('.');
        text.push_str(&digest);
        store.write(PENDING_KEY_KEY, text.as_str().to_owned()).await
    }

    async fn load(store: &AppSecretStore) -> Result<Option<Self>, WalletError> {
        let Some(text) = store.read(PENDING_KEY_KEY).await? else {
            return Ok(None);
        };
        let text = Zeroizing::new(text);
        let (key, digest) = text.split_once('.').ok_or_else(bad_key)?;
        let mut sealed_digest = [0u8; DIGEST_LEN];
        match STANDARD.decode_slice(digest.as_bytes(), &mut sealed_digest) {
            Ok(DIGEST_LEN) => Ok(Some(Self {
                key: PinKey::from_text(key)?,
                sealed_digest,
            })),
            _ => Err(bad_key()),
        }
    }

    fn was_returned_as(&self, sealed: &str) -> bool {
        self.sealed_digest == sealed_digest(sealed)
    }
}

/// Trimmed as [`open`] trims, so text the app stored with a line break still matches.
fn sealed_digest(sealed: &str) -> [u8; DIGEST_LEN] {
    Sha256::digest(sealed.trim().as_bytes()).into()
}

/// Which stored key opened sealed text.
enum OpenedBy {
    Current,
    Pending(PendingKey),
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

/// Seals `password` under `pin` and a new PIN key, then starts the failure count again at zero
/// and puts that key into `store` as its only PIN key. Returns the sealed text.
///
/// The store is touched only once sealing succeeded, and the key is written last, so a call
/// that fails leaves the PIN key, and with it the sealed text the app holds, working.
pub(crate) async fn seal_new(
    store: &AppSecretStore,
    pin: NewPin,
    password: Zeroizing<String>,
    kdf: KdfParams,
) -> Result<String, WalletError> {
    let (key, sealed) = seal_with_new_key(pin, password, kdf).await?;
    store.delete(FAILURES_KEY).await?;
    store.delete(PENDING_KEY_KEY).await?;
    key.store(store, KEY_KEY).await?;
    Ok(sealed)
}

async fn seal_with_new_key(
    pin: NewPin,
    password: Zeroizing<String>,
    kdf: KdfParams,
) -> Result<(PinKey, String), WalletError> {
    blocking(move || {
        let key = PinKey::generate()?;
        let sealed = seal(&key, &pin.0, &password, kdf)?;
        Ok((key, sealed))
    })
    .await
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

/// The password sealed in `sealed`, opened with `pin` and the PIN key in `store`, or the pending
/// key of an unconfirmed PIN change. Waits as `guard`'s policy says for the failures counted in
/// `store`. The attempt is counted once, whichever key opens it, and before the PIN is tried, so
/// stopping the app mid-attempt does not undo it; a right PIN clears the count and damaged text
/// restores it.
///
/// A wrong PIN gives `WrongPassword`, damaged text `InvalidArgument`, a missing or damaged PIN
/// key `SecretStore`. That last case keeps the attempt counted, since a store that lost its key
/// is no reason to allow free attempts.
pub(crate) async fn unlock(
    guard: &PinGuard,
    store: &AppSecretStore,
    pin: Zeroizing<String>,
    sealed: String,
) -> Result<Zeroizing<String>, WalletError> {
    let _attempt = guard.attempts.lock().await;
    attempt(guard.policy, store, pin, sealed)
        .await
        .map(|(password, _)| password)
}

/// Changes the PIN: `old_pin` must open `sealed` as in [`unlock`], `check` must accept the
/// password it opens, and the password is then sealed under `new_pin` and a new key that
/// becomes the pending key. Returns the new sealed text.
///
/// The key that opened `sealed` keeps opening it until [`confirm_change`], since that is the
/// text the app holds. When the current key opened it, a pending key of an earlier change is
/// replaced and its text stops opening. When the pending key opened it, the app already
/// stored that change's text in place of the old one, so the pending key first becomes the
/// current key and the old text stops opening.
pub(crate) async fn change<F, Fut>(
    guard: &PinGuard,
    store: &AppSecretStore,
    old_pin: Zeroizing<String>,
    sealed: String,
    new_pin: NewPin,
    kdf: KdfParams,
    check: F,
) -> Result<String, WalletError>
where
    F: FnOnce(Zeroizing<String>) -> Fut,
    Fut: Future<Output = Result<(), WalletError>>,
{
    // Held to the end, so an attempt or a confirmation never sees half a change.
    let _attempt = guard.attempts.lock().await;
    let (password, opened_by) = attempt(guard.policy, store, old_pin, sealed).await?;
    check(password.clone()).await?;
    let (key, sealed) = seal_with_new_key(new_pin, password, kdf).await?;
    // Promoted before the new pending key is written: stopping in between leaves the held
    // text opening by the current key, and the pending slot still holding that same key.
    if let OpenedBy::Pending(held) = opened_by {
        held.key.store(store, KEY_KEY).await?;
    }
    PendingKey::new(key, &sealed).store(store).await?;
    Ok(sealed)
}

/// Makes the pending key of a PIN change the current one, so only the new sealed text opens.
/// `sealed` must be the text that change returned, which the app now holds; other text gives
/// `InvalidArgument` and changes nothing. Does nothing when no change is pending. A damaged
/// pending key gives `SecretStore` and leaves both keys as they were.
pub(crate) async fn confirm_change(
    guard: &PinGuard,
    store: &AppSecretStore,
    sealed: &str,
) -> Result<(), WalletError> {
    let _attempt = guard.attempts.lock().await;
    let Some(pending) = PendingKey::load(store).await? else {
        return Ok(());
    };
    if !pending.was_returned_as(sealed) {
        return Err(WalletError::new(
            WalletErrorKind::InvalidArgument,
            "sealed text is not the text of the pending pin change",
        ));
    }
    // The current key is overwritten before the pending one is deleted: stopping in between
    // leaves the new key in both, which opens the new text and confirms again harmlessly.
    pending.key.store(store, KEY_KEY).await?;
    store.delete(PENDING_KEY_KEY).await
}

/// Tries a wallet password the user typed with `check`, counted and delayed as a PIN attempt
/// of [`unlock`] is, in the same failure count: a wallet is unlocked either by PIN or by
/// password, never both. `WrongPassword` and `SecretStore` keep the attempt counted, success
/// clears the count, and any other failure restores it.
pub(crate) async fn password_attempt<T, Fut>(
    guard: &PinGuard,
    store: &AppSecretStore,
    check: impl FnOnce() -> Fut,
) -> Result<T, WalletError>
where
    Fut: Future<Output = Result<T, WalletError>>,
{
    let _attempt = guard.attempts.lock().await;
    counted(guard.policy, store, check).await
}

async fn attempt(
    policy: PinPolicy,
    store: &AppSecretStore,
    pin: Zeroizing<String>,
    sealed: String,
) -> Result<(Zeroizing<String>, OpenedBy), WalletError> {
    counted(policy, store, || async move {
        let key = PinKey::load(store).await?;
        // Read now but reported only when the current key does not open the text, so a damaged
        // pending key never stops the current text from opening.
        let pending = PendingKey::load(store).await;
        blocking(move || match open(&key, &pin, &sealed) {
            Ok(password) => Ok((password, OpenedBy::Current)),
            Err(error) if error.kind == WalletErrorKind::WrongPassword => match pending? {
                Some(pending) => open(&pending.key, &pin, &sealed)
                    .map(|password| (password, OpenedBy::Pending(pending))),
                None => Err(error),
            },
            Err(error) => Err(error),
        })
        .await
    })
    .await
}

/// Runs `try_secret` as one attempt: counted before it runs, so stopping the app mid-attempt
/// does not undo it, and after the wait the failures counted so far call for.
async fn counted<T, Fut>(
    policy: PinPolicy,
    store: &AppSecretStore,
    try_secret: impl FnOnce() -> Fut,
) -> Result<T, WalletError>
where
    Fut: Future<Output = Result<T, WalletError>>,
{
    let failures = read_failures(store).await?;
    write_failures(store, failures.saturating_add(1)).await?;
    tokio::time::sleep(policy.delay(failures)).await;
    let result = try_secret().await;
    match &result {
        Err(error)
            if matches!(
                error.kind,
                WalletErrorKind::WrongPassword | WalletErrorKind::SecretStore
            ) => {}
        Ok(_) => write_failures(store, 0).await?,
        Err(_) => write_failures(store, failures).await?,
    }
    result
}

/// Removes the PIN keys and the failure count from `store`.
pub(crate) async fn forget(store: &AppSecretStore) -> Result<(), WalletError> {
    store.delete(KEY_KEY).await?;
    store.delete(PENDING_KEY_KEY).await?;
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
        let sealed = seal(&key, "123456", &password, cheap()).unwrap();
        assert!(!sealed.contains(password.as_str()));
        assert_eq!(*open(&key, "123456", &sealed).unwrap(), *password);
        assert_eq!(
            open(&key, "000000", &sealed).unwrap_err().kind,
            WalletErrorKind::WrongPassword
        );
        let other_key = PinKey::generate().unwrap();
        assert_eq!(
            open(&other_key, "123456", &sealed).unwrap_err().kind,
            WalletErrorKind::WrongPassword
        );
        assert_eq!(
            open(&key, "123456", "damaged").unwrap_err().kind,
            WalletErrorKind::InvalidArgument
        );
    }

    #[test]
    fn new_pin_needs_six_characters() {
        assert!(NewPin::new(pin("")).is_err());
        assert!(NewPin::new(pin("1234")).is_err());
        assert!(NewPin::new(pin("12345")).is_err());
        assert!(NewPin::new(pin("123456")).is_ok());
        // Characters, not bytes: five two-byte characters are still too short.
        assert!(NewPin::new(pin("äöüäö")).is_err());
    }

    /// Text sealed under a PIN shorter than today's floor, as an earlier version allowed, keeps
    /// opening with that PIN.
    #[tokio::test]
    async fn a_pin_below_the_floor_still_unlocks_text_sealed_under_it() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let password = generate_password().unwrap();
        let key = PinKey::generate().unwrap();
        let sealed = seal(&key, "1234", &password, cheap()).unwrap();
        key.store(&store, KEY_KEY).await.unwrap();
        let opened = unlock(&guard, &store, pin("1234"), sealed).await.unwrap();
        assert_eq!(*opened, *password);
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
            NewPin::new(pin("123456")).unwrap(),
            password.clone(),
            cheap(),
        )
        .await
        .unwrap();
        for _ in 0..3 {
            let started = tokio::time::Instant::now();
            assert!(
                unlock(&guard, &store, pin("000000"), sealed.clone())
                    .await
                    .is_err()
            );
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
        let started = tokio::time::Instant::now();
        assert!(
            unlock(&guard, &store, pin("000000"), sealed.clone())
                .await
                .is_err()
        );
        assert_eq!(started.elapsed(), Duration::from_secs(30));

        let started = tokio::time::Instant::now();
        let opened = unlock(&guard, &store, pin("123456"), sealed.clone())
            .await
            .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        assert_eq!(*opened, *password);

        let started = tokio::time::Instant::now();
        assert!(unlock(&guard, &store, pin("123456"), sealed).await.is_ok());
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// Concurrent attempts queue: each counts on top of the last and waits its own delay.
    #[tokio::test(start_paused = true)]
    async fn concurrent_attempts_run_one_at_a_time() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let password = generate_password().unwrap();
        let sealed = seal_new(
            &store,
            NewPin::new(pin("123456")).unwrap(),
            password,
            cheap(),
        )
        .await
        .unwrap();
        store.write(FAILURES_KEY, "3".to_owned()).await.unwrap();

        let started = tokio::time::Instant::now();
        let attempt = || unlock(&guard, &store, pin("000000"), sealed.clone());
        let (first, second, third) = tokio::join!(attempt(), attempt(), attempt());
        for result in [first, second, third] {
            assert_eq!(result.unwrap_err().kind, WalletErrorKind::WrongPassword);
        }
        assert_eq!(started.elapsed(), Duration::from_secs(30 + 60 + 120));
        assert_eq!(read_failures(&store).await.unwrap(), 6);
    }

    #[test]
    fn pin_key_text_round_trips_and_refuses_other_lengths() {
        let key = PinKey::generate().unwrap();
        let text = key.to_text().unwrap();
        assert_eq!(text.len(), KEY_TEXT_LEN);
        assert_eq!(*PinKey::from_text(&text).unwrap().0, *key.0);
        let short = STANDARD.encode([7u8; KEY_LEN - 1]);
        let long = STANDARD.encode([7u8; KEY_LEN + 1]);
        for text in [short.as_str(), long.as_str(), "", "not base64!"] {
            assert_eq!(
                PinKey::from_text(text).err().map(|error| error.kind),
                Some(WalletErrorKind::SecretStore),
                "{text:?}"
            );
        }
    }

    /// A store that lost its PIN key is no reason for a free attempt.
    #[tokio::test]
    async fn an_attempt_without_the_pin_key_is_counted() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let sealed = seal_new(
            &store,
            NewPin::new(pin("123456")).unwrap(),
            generate_password().unwrap(),
            cheap(),
        )
        .await
        .unwrap();
        store.delete(KEY_KEY).await.unwrap();
        let opened = unlock(&guard, &store, pin("123456"), sealed).await;
        assert_eq!(opened.unwrap_err().kind, WalletErrorKind::SecretStore);
        assert_eq!(read_failures(&store).await.unwrap(), 1);
    }

    /// Stopping the app during the wait must not undo the attempt.
    #[tokio::test(start_paused = true)]
    async fn the_attempt_is_counted_before_the_wait() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let sealed = seal_new(
            &store,
            NewPin::new(pin("123456")).unwrap(),
            generate_password().unwrap(),
            cheap(),
        )
        .await
        .unwrap();
        store.write(FAILURES_KEY, "3".to_owned()).await.unwrap();
        let during_wait = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            read_failures(&store).await.unwrap()
        };
        let (opened, counted) =
            tokio::join!(unlock(&guard, &store, pin("000000"), sealed), during_wait);
        assert_eq!(counted, 4);
        assert_eq!(opened.unwrap_err().kind, WalletErrorKind::WrongPassword);
        assert_eq!(read_failures(&store).await.unwrap(), 4);
    }

    /// A PIN change whose seal fails must not lock the wallet: the old key, the old sealed text
    /// and the failure count stay as they were.
    #[tokio::test]
    async fn a_failed_seal_leaves_the_old_sealed_text_working() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let password = generate_password().unwrap();
        let sealed = seal_new(
            &store,
            NewPin::new(pin("123456")).unwrap(),
            password.clone(),
            cheap(),
        )
        .await
        .unwrap();
        store.write(FAILURES_KEY, "2".to_owned()).await.unwrap();
        let old_key = store.read(KEY_KEY).await.unwrap();

        // A secret longer than a vault holds cannot be sealed.
        let unsealable = Zeroizing::new("x".repeat(lepic_keychain::vault::MAX_SECRET_LEN + 1));
        let failed = seal_new(
            &store,
            NewPin::new(pin("987654")).unwrap(),
            unsealable,
            cheap(),
        )
        .await;
        assert!(failed.is_err());
        assert_eq!(store.read(KEY_KEY).await.unwrap(), old_key);
        assert_eq!(read_failures(&store).await.unwrap(), 2);

        let opened = unlock(&guard, &store, pin("123456"), sealed).await.unwrap();
        assert_eq!(*opened, *password);
    }

    /// A change opened by the pending key starts from text the app already stored in place of
    /// the old one, so that text must keep opening while the new change is pending.
    #[tokio::test]
    async fn a_change_from_the_pending_pair_keeps_that_pair_opening() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (_, first) = new_wallet(&store, "111111").await;
        let second = change_pin(&guard, &store, "111111", &first, "222222")
            .await
            .unwrap();
        // The app stored `second` and dropped `first`, then changed again and stopped before
        // it stored the third text.
        change_pin(&guard, &store, "222222", &second, "333333")
            .await
            .unwrap();
        assert!(opens(&guard, &store, "222222", &second).await);
    }

    /// An app that stopped before it stored the new text still holds the old one; confirming
    /// then must not stop that text from opening.
    #[tokio::test]
    async fn a_confirmation_for_text_the_app_never_stored_keeps_the_old_text_opening() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (_, old) = new_wallet(&store, "111111").await;
        let new = change_pin(&guard, &store, "111111", &old, "222222")
            .await
            .unwrap();
        let confirmed = confirm_change(&guard, &store, &old).await;
        assert_eq!(
            confirmed.unwrap_err().kind,
            WalletErrorKind::InvalidArgument
        );
        assert!(opens(&guard, &store, "111111", &old).await);
        assert!(opens(&guard, &store, "222222", &new).await);
        // Text the app stored with a line break is the same text.
        confirm_change(&guard, &store, &format!("{new}\n"))
            .await
            .unwrap();
        assert!(!opens(&guard, &store, "111111", &old).await);
        assert!(opens(&guard, &store, "222222", &new).await);
        // Nothing is pending any more.
        confirm_change(&guard, &store, &old).await.unwrap();
        assert!(opens(&guard, &store, "222222", &new).await);
    }

    #[tokio::test]
    async fn a_count_that_does_not_parse_costs_the_longest_wait() {
        let store = AppSecretStore::in_memory();
        store.write(FAILURES_KEY, "x".to_owned()).await.unwrap();
        assert_eq!(read_failures(&store).await.unwrap(), u32::MAX);
    }

    async fn new_wallet(store: &AppSecretStore, old: &str) -> (Zeroizing<String>, String) {
        let password = generate_password().unwrap();
        let sealed = seal_new(
            store,
            NewPin::new(pin(old)).unwrap(),
            password.clone(),
            cheap(),
        )
        .await
        .unwrap();
        (password, sealed)
    }

    async fn change_pin(
        guard: &PinGuard,
        store: &AppSecretStore,
        old: &str,
        sealed: &str,
        new: &str,
    ) -> Result<String, WalletError> {
        let new = NewPin::new(pin(new)).unwrap();
        let accept = |_| async { Ok(()) };
        change(
            guard,
            store,
            pin(old),
            sealed.to_owned(),
            new,
            cheap(),
            accept,
        )
        .await
    }

    async fn opens(guard: &PinGuard, store: &AppSecretStore, pin_text: &str, sealed: &str) -> bool {
        unlock(guard, store, pin(pin_text), sealed.to_owned())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn a_change_from_the_old_pair_replaces_the_pending_key() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (_, first) = new_wallet(&store, "111111").await;
        let second = change_pin(&guard, &store, "111111", &first, "222222")
            .await
            .unwrap();
        // The app never stored `second` and changes again from the pair it holds.
        let third = change_pin(&guard, &store, "111111", &first, "333333")
            .await
            .unwrap();
        assert!(opens(&guard, &store, "111111", &first).await);
        assert!(!opens(&guard, &store, "222222", &second).await);
        assert!(opens(&guard, &store, "333333", &third).await);

        confirm_change(&guard, &store, &third).await.unwrap();
        assert!(!opens(&guard, &store, "111111", &first).await);
        assert!(opens(&guard, &store, "333333", &third).await);
    }

    #[tokio::test]
    async fn a_change_from_the_pending_pair_promotes_it_before_replacing_it() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (_, first) = new_wallet(&store, "111111").await;
        let second = change_pin(&guard, &store, "111111", &first, "222222")
            .await
            .unwrap();
        // The app stored `second` in place of `first`, so `first` is gone.
        let third = change_pin(&guard, &store, "222222", &second, "333333")
            .await
            .unwrap();
        assert!(!opens(&guard, &store, "111111", &first).await);
        assert!(opens(&guard, &store, "222222", &second).await);
        assert!(opens(&guard, &store, "333333", &third).await);

        confirm_change(&guard, &store, &third).await.unwrap();
        assert!(!opens(&guard, &store, "222222", &second).await);
        assert!(opens(&guard, &store, "333333", &third).await);
    }

    /// A change the vault check refuses stores no pending key.
    #[tokio::test]
    async fn a_refused_change_leaves_nothing_pending() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (_, sealed) = new_wallet(&store, "111111").await;
        let refuse = |_| async { Err(WalletError::new(WalletErrorKind::WrongPassword, "refused")) };
        let new = NewPin::new(pin("222222")).unwrap();
        let changed = change(&guard, &store, pin("111111"), sealed, new, cheap(), refuse).await;
        assert_eq!(changed.unwrap_err().kind, WalletErrorKind::WrongPassword);
        assert_eq!(store.read(PENDING_KEY_KEY).await.unwrap(), None);
    }

    /// A damaged pending key costs only the new text, and its attempts stay counted.
    #[tokio::test]
    async fn a_damaged_pending_key_leaves_the_current_text_working() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (password, old) = new_wallet(&store, "111111").await;
        let new = change_pin(&guard, &store, "111111", &old, "222222")
            .await
            .unwrap();
        store
            .write(PENDING_KEY_KEY, "damaged".to_owned())
            .await
            .unwrap();
        let key = store.read(KEY_KEY).await.unwrap();

        let opened = unlock(&guard, &store, pin("222222"), new.clone()).await;
        assert_eq!(opened.unwrap_err().kind, WalletErrorKind::SecretStore);
        assert_eq!(read_failures(&store).await.unwrap(), 1);
        let opened = unlock(&guard, &store, pin("111111"), old).await.unwrap();
        assert_eq!(*opened, *password);

        let confirmed = confirm_change(&guard, &store, &new).await;
        assert_eq!(confirmed.unwrap_err().kind, WalletErrorKind::SecretStore);
        assert_eq!(store.read(KEY_KEY).await.unwrap(), key);
    }

    /// A stale pending key, from a wallet deleted while a change was pending, never opens the
    /// next wallet's text.
    #[tokio::test]
    async fn a_new_wallet_drops_a_pending_key() {
        let store = AppSecretStore::in_memory();
        store
            .write(
                PENDING_KEY_KEY,
                PinKey::generate().unwrap().to_text().unwrap(),
            )
            .await
            .unwrap();
        new_wallet(&store, "111111").await;
        assert_eq!(store.read(PENDING_KEY_KEY).await.unwrap(), None);
    }

    #[tokio::test]
    async fn forget_removes_a_pending_key() {
        let store = AppSecretStore::in_memory();
        let guard = PinGuard::new(PinPolicy::DEFAULT);
        let (_, sealed) = new_wallet(&store, "111111").await;
        change_pin(&guard, &store, "111111", &sealed, "222222")
            .await
            .unwrap();
        forget(&store).await.unwrap();
        for slot in [KEY_KEY, PENDING_KEY_KEY, FAILURES_KEY] {
            assert_eq!(store.read(slot).await.unwrap(), None, "{slot}");
        }
    }
}
