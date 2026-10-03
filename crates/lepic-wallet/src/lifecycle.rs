//! Wallet creation, restore, import and unlock: how a seed becomes a keychain and an open
//! database, and what is checked on the way.

use std::fmt;
use std::path::Path;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::vault::SecretName;
use lepic_keychain::{ExtKeyVersion, Keychain, SecretBytes, SecretStore, Seed};
use lepic_primitives::params::Network;
use lepic_store::{CONTEXT_KEY_LEN, ContextKey, Repositories, StoreError, WalletStore};
use rand_core::CryptoRng;
use tracing::debug;
use zeroize::Zeroizing;

use crate::account::ensure_default_account;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};

/// The secret name the seed is stored under in the wallet's secret storage.
const SEED_SECRET: &str = "wallet/seed";

const NETWORK_SETTING: &str = "wallet.network";
const FINGERPRINT_SETTING: &str = "wallet.fingerprint";

/// Present while a database rebuilt from a seed has not been scanned from genesis.
const RESTORE_SCAN_SETTING: &str = "wallet.restore_scan_required";

/// Domain separator of the key private transaction contexts are sealed under.
const CONTEXT_KEY_DOMAIN: &[u8] = b"lepic-wallet private context key v1";

/// The password protecting the wallet's secret storage. Wiped on drop and never printed.
pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(password: String) -> Self {
        Self(Zeroizing::new(password))
    }

    /// The password. Callers must not log it or copy it into memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password([redacted])")
    }
}

/// The recovery phrase of a new wallet, for the user to write down. Wiped on drop and never
/// printed.
pub struct RecoveryPhrase(Zeroizing<String>);

impl RecoveryPhrase {
    /// The words separated by single spaces. Callers must not log the phrase.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase([redacted])")
    }
}

/// Length of a new wallet's recovery phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WordCount {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    /// What `epic-wallet` creates.
    #[default]
    TwentyFour,
}

impl WordCount {
    const fn entropy_len(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::Fifteen => 20,
            Self::Eighteen => 24,
            Self::TwentyOne => 28,
            Self::TwentyFour => 32,
        }
    }
}

/// How the seed of a new wallet was obtained. Only a fresh seed proves the database cannot
/// already belong to this wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedSource {
    Generated,
    Recovered,
}

/// The unlocked state of a wallet: the root key and the database it opened.
pub(crate) struct Session<D> {
    pub(crate) keychain: Keychain,
    pub(crate) store: D,
}

/// Where a wallet lives and what it must match, for work on the blocking pool.
pub(crate) struct Target<'a> {
    pub(crate) data_dir: &'a Path,
    pub(crate) network: Network,
}

pub(crate) fn generate_seed(
    rng: &mut (impl CryptoRng + ?Sized),
    words: WordCount,
) -> Result<Seed, WalletError> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    let used = entropy
        .get_mut(..words.entropy_len())
        .ok_or(WalletError::Mnemonic(
            lepic_keychain::MnemonicError::EntropyLength {
                actual: words.entropy_len(),
            },
        ))?;
    rng.fill_bytes(used);
    Seed::from_entropy(used).map_err(WalletError::Mnemonic)
}

pub(crate) fn recovery_phrase(seed: &Seed) -> Result<RecoveryPhrase, WalletError> {
    Ok(RecoveryPhrase(
        seed.to_mnemonic().map_err(WalletError::Mnemonic)?,
    ))
}

/// Stores `seed` as a new wallet. Secret storage and database are checked before either is
/// written, so a refused wallet leaves nothing behind.
pub(crate) fn create<S: StoreOpener, V: SecretVault>(
    stores: &S,
    secrets: &V,
    target: &Target<'_>,
    password: &Password,
    seed: &Seed,
    source: SeedSource,
) -> Result<Session<S::Store>, WalletError> {
    if secrets.exists()? {
        return Err(WalletError::WalletExists);
    }
    let keychain = Keychain::from_seed(seed, ext_key_version(target.network))?;
    let fingerprint = fingerprint(&keychain)?;
    let store = stores.open(target.data_dir, context_key(seed)?)?;
    let identity = store.read(|repos| stored_identity(repos, target.network, &fingerprint))?;
    if identity == StoredIdentity::Matches && source == SeedSource::Generated {
        return Err(WalletError::ForeignDatabase);
    }
    let mut vault = secrets.create(password)?;
    vault.put(&seed_name()?, &SecretBytes::from_slice(seed.expose_bytes()))?;
    debug!("secret storage created");
    let rebuilt = identity == StoredIdentity::Empty && source == SeedSource::Recovered;
    store.write(|repos| {
        initialise(repos, target.network, &fingerprint)?;
        if rebuilt {
            require_restore_scan(repos)?;
        }
        Ok::<_, WalletError>(())
    })?;
    debug!("wallet database prepared");
    Ok(Session { keychain, store })
}

/// Unlocks the secret storage, reads the seed and opens the database it belongs to.
pub(crate) fn open<S: StoreOpener, V: SecretVault>(
    stores: &S,
    secrets: &V,
    target: &Target<'_>,
    password: &Password,
) -> Result<Session<S::Store>, WalletError> {
    let vault = secrets.unlock(password)?;
    debug!("secret storage unlocked");
    let stored = vault.get(&seed_name()?)?.ok_or(WalletError::NoWallet)?;
    let seed = Seed::from_entropy(stored.expose_bytes()).map_err(WalletError::StoredSeed)?;
    let keychain = Keychain::from_seed(&seed, ext_key_version(target.network))?;
    let fingerprint = fingerprint(&keychain)?;
    let store = stores.open(target.data_dir, context_key(&seed)?)?;
    // A missing database is rebuilt empty: everything in it but history is recovered by a scan,
    // which must run before new outputs are created.
    store.write(|repos| {
        let identity = stored_identity(repos, target.network, &fingerprint)?;
        initialise(repos, target.network, &fingerprint)?;
        if identity == StoredIdentity::Empty {
            require_restore_scan(repos)?;
        }
        Ok::<_, WalletError>(())
    })?;
    debug!("wallet database prepared");
    Ok(Session { keychain, store })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredIdentity {
    Empty,
    Matches,
}

/// Whether the database is unused or already belongs to this seed on this network.
fn stored_identity(
    repos: &dyn Repositories,
    network: Network,
    fingerprint: &str,
) -> Result<StoredIdentity, WalletError> {
    let stored_network = repos.setting(NETWORK_SETTING)?;
    let stored_fingerprint = repos.setting(FINGERPRINT_SETTING)?;
    if let Some(stored) = stored_network
        && stored != network.as_str()
    {
        return Err(WalletError::NetworkMismatch {
            stored,
            configured: network,
        });
    }
    match stored_fingerprint {
        None if repos.accounts()?.is_empty() => Ok(StoredIdentity::Empty),
        Some(stored) if stored == fingerprint => Ok(StoredIdentity::Matches),
        _ => Err(WalletError::ForeignDatabase),
    }
}

fn initialise(
    repos: &mut dyn Repositories,
    network: Network,
    fingerprint: &str,
) -> Result<(), WalletError> {
    repos.put_setting(NETWORK_SETTING, network.as_str())?;
    repos.put_setting(FINGERPRINT_SETTING, fingerprint)?;
    ensure_default_account(repos)
}

fn require_restore_scan(repos: &mut dyn Repositories) -> Result<(), WalletError> {
    repos.put_setting(RESTORE_SCAN_SETTING, "true")?;
    debug!("restore scan required");
    Ok(())
}

/// Refuses to hand out output keys on a rebuilt database before a scan from genesis found the
/// keys already in use on chain.
pub(crate) fn ensure_restore_scanned(repos: &dyn Repositories) -> Result<(), WalletError> {
    if restore_scan_pending(repos)? {
        return Err(WalletError::RestoreScanRequired);
    }
    Ok(())
}

pub(crate) fn restore_scan_pending(repos: &dyn Repositories) -> Result<bool, StoreError> {
    Ok(repos.setting(RESTORE_SCAN_SETTING)?.is_some())
}

pub(crate) fn restore_scan_completed(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    repos.delete_setting(RESTORE_SCAN_SETTING)
}

fn seed_name() -> Result<SecretName, WalletError> {
    Ok(SecretName::new(SEED_SECRET)?)
}

/// `epic-wallet` uses the mainnet version bytes on mainnet and the floonet ones elsewhere.
pub(crate) const fn ext_key_version(network: Network) -> ExtKeyVersion {
    match network {
        Network::Mainnet => ExtKeyVersion::MAINNET,
        Network::Floonet => ExtKeyVersion::FLOONET,
    }
}

/// The BIP32 fingerprint of the master key, which tells databases of different seeds apart
/// without revealing anything that derives keys.
fn fingerprint(keychain: &Keychain) -> Result<String, WalletError> {
    let lepic_keychain::Fingerprint(bytes) = keychain
        .master()
        .fingerprint()
        .map_err(lepic_keychain::KeychainError::from)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Keyed BLAKE2b of a domain string under the seed: the same seed always opens its database,
/// and the key reveals nothing about the seed.
fn context_key(seed: &Seed) -> Result<ContextKey, WalletError> {
    let bytes = context_key_bytes(seed)?;
    Ok(ContextKey::from_bytes(*bytes))
}

fn context_key_bytes(seed: &Seed) -> Result<Zeroizing<[u8; CONTEXT_KEY_LEN]>, WalletError> {
    let mut mac =
        <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).map_err(|_| {
            WalletError::StoredSeed(lepic_keychain::MnemonicError::EntropyLength {
                actual: seed.expose_bytes().len(),
            })
        })?;
    mac.update(CONTEXT_KEY_DOMAIN);
    let mut key = Zeroizing::new([0u8; CONTEXT_KEY_LEN]);
    mac.finalize_into((&mut *key).into());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn generated_seeds_have_the_requested_word_count() {
        let mut rng = StdRng::seed_from_u64(7);
        for (words, count) in [
            (WordCount::Twelve, 12),
            (WordCount::Fifteen, 15),
            (WordCount::Eighteen, 18),
            (WordCount::TwentyOne, 21),
            (WordCount::TwentyFour, 24),
        ] {
            let seed = generate_seed(&mut rng, words).unwrap();
            let phrase = recovery_phrase(&seed).unwrap();
            assert_eq!(phrase.expose().split(' ').count(), count);
        }
    }

    #[test]
    fn secret_wrappers_redact_debug_output() {
        assert_eq!(
            format!("{:?}", Password::new("hunter2".to_owned())),
            "Password([redacted])"
        );
        let seed = Seed::from_entropy(&[0; 16]).unwrap();
        assert_eq!(
            format!("{:?}", recovery_phrase(&seed).unwrap()),
            "RecoveryPhrase([redacted])"
        );
    }

    #[test]
    fn fingerprint_differs_between_seeds_and_matches_bip32() {
        let first = Keychain::from_seed(
            &Seed::from_entropy(&[1; 16]).unwrap(),
            ExtKeyVersion::MAINNET,
        )
        .unwrap();
        let second = Keychain::from_seed(
            &Seed::from_entropy(&[2; 16]).unwrap(),
            ExtKeyVersion::MAINNET,
        )
        .unwrap();
        let expected: String = first
            .master()
            .fingerprint()
            .unwrap()
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(fingerprint(&first).unwrap(), expected);
        assert_ne!(fingerprint(&first).unwrap(), fingerprint(&second).unwrap());
    }

    /// `tests/lifecycle_logs.rs` recomputes the context key from this formula to check that it
    /// is never logged; this test keeps the two in step.
    #[test]
    fn context_key_is_keyed_blake2b_of_the_domain_under_the_seed() {
        let seed = Seed::from_entropy(&[5; 32]).unwrap();
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[5; 32]).unwrap();
        mac.update(b"lepic-wallet private context key v1");
        let expected: [u8; 32] = mac.finalize_fixed().into();
        assert_eq!(*context_key_bytes(&seed).unwrap(), expected);
    }
}
