// SPDX-License-Identifier: Apache-2.0
//! Wallet creation, restore, import and unlock: how a seed becomes a keychain and an open
//! database, and what is checked on the way.

use std::fmt;
use std::path::Path;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::vault::SecretName;
use lepic_keychain::{Identifier, Keychain, SecretBytes, SecretStore, Seed, SwitchCommitment};
use lepic_primitives::params::Network;
use lepic_store::{
    AtRestReport, AtRestState, CONTEXT_KEY_LEN, ContextKey, PEER_TAG_KEY_LEN, PeerTagKey,
    ROLLBACK_SCAN_SETTING, Repositories, STORE_KEY_LEN, StoreError, StoreKey, StoreKeys,
    WalletStore,
};
use rand_core::CryptoRng;
use tracing::debug;
use zeroize::Zeroizing;

use crate::account::{ensure_default_account, place_key_counters};
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::slate_cache::SlateCache;

/// The secret name the seed is stored under in the wallet's secret storage.
const SEED_SECRET: &str = "wallet/seed";

const NETWORK_SETTING: &str = "wallet.network";
const FINGERPRINT_SETTING: &str = "wallet.fingerprint";

/// Present while a database rebuilt from a seed has not been scanned from genesis.
const RESTORE_SCAN_SETTING: &str = "wallet.restore_scan_required";

/// The seed check, as lowercase hex: written by every create and open, so a recovery phrase can
/// be proven the database's without its vault.
const SEED_CHECK_SETTING: &str = "wallet.seed_check";

/// Domain separator of the key private transaction contexts are sealed under.
const CONTEXT_KEY_DOMAIN: &[u8] = b"lepic-wallet private context key v1";
/// Domain of the key the whole wallet database is encrypted under (ADR 0032).
const STORE_KEY_DOMAIN: &[u8] = b"lepic-wallet store key v1";

/// Domain separator of the key the store finds what it knows of each peer by: a keyed hash under
/// it, so the store names no peer.
const PEER_TAG_KEY_DOMAIN: &[u8] = b"lepic-wallet peer tag v1";

/// Domain separator of the seed check: keyed BLAKE2b of it under the seed, which proves a seed
/// with 256 bits where the fingerprint has 32, and reveals nothing that derives keys.
const SEED_CHECK_DOMAIN: &[u8] = b"lepic-wallet seed check v1";

/// The password protecting the wallet's secret storage. Wiped on drop and never printed.
pub struct Password(Zeroizing<String>);

impl Password {
    /// The fewest characters a password set on a new wallet should have. Hosts check it where a
    /// password is chosen; opening never does, so a wallet with a shorter password keeps opening.
    pub const MIN_NEW_LEN: usize = 8;

    pub fn new(password: String) -> Self {
        Self(Zeroizing::new(password))
    }

    /// Whether the password has at least [`Password::MIN_NEW_LEN`] characters.
    pub fn is_long_enough_to_set(text: &str) -> bool {
        text.chars().count() >= Self::MIN_NEW_LEN
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
pub struct Session<D> {
    pub keychain: Keychain,
    /// The seed, for the keys of the LEPIC namespace ([`crate::namespace`]).
    pub(crate) seed: Seed,
    pub store: D,
    /// The stored slates the history read decoded, kept while the wallet is open.
    pub(crate) slates: SlateCache,
    /// How the database was found on disk, for an opener that keeps it encrypted at rest.
    pub(crate) at_rest: Option<AtRestReport>,
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
    key_start: u32,
) -> Result<Session<S::Store>, WalletError> {
    if secrets.exists()? {
        return Err(WalletError::WalletExists);
    }
    let keychain = Keychain::from_seed(seed, target.network)?;
    let ours = SeedIdentity::of(seed, &keychain)?;
    // The database is proven this seed's before the open below can move it: an open copies a
    // plain database into one encrypted under this seed's key and sets the plain one aside,
    // which for another seed's database would lock its own phrase out. The probe moves
    // nothing. A damaged database is set aside by the open, as before.
    match stores.open_existing(target.data_dir, store_keys(seed)?, &store_key(seed)?) {
        Ok(Some(probe)) => {
            let identity = probe.read(|repos| stored_identity(repos, target.network, &ours))?;
            admit(&probe, identity, source, &keychain)?;
        }
        Ok(None) | Err(StoreError::Damaged) => {}
        Err(StoreError::WrongKey) => return Err(WalletError::ForeignDatabase),
        Err(error) => return Err(error.into()),
    }
    let (store, at_rest) =
        stores.open_reporting(target.data_dir, store_keys(seed)?, &store_key(seed)?)?;
    let identity = store.read(|repos| stored_identity(repos, target.network, &ours))?;
    admit(&store, identity, source, &keychain)?;
    let mut vault = secrets.create(password)?;
    put_seed(&mut vault, seed)?;
    debug!("secret storage created");
    let rebuilt = identity == StoredIdentity::Empty && source == SeedSource::Recovered;
    let at_rest = store.write(|repos| {
        initialise(repos, target.network, &ours, key_start)?;
        let at_rest = after_rollback(repos, at_rest)?;
        if rebuilt || rolled_back(at_rest.as_ref()) {
            require_restore_scan(repos)?;
        }
        Ok::<_, WalletError>(at_rest)
    })?;
    debug!("wallet database prepared");
    Ok(Session {
        keychain,
        seed: seed.clone(),
        store,
        slates: SlateCache::default(),
        at_rest,
    })
}

/// Whether a new wallet of a seed from `source` may take a database whose identity is
/// `identity`: an unused one, or for a recovered seed one the seed is proven by.
fn admit(
    store: &impl WalletStore,
    identity: StoredIdentity,
    source: SeedSource,
    keychain: &Keychain,
) -> Result<(), WalletError> {
    match (identity, source) {
        (StoredIdentity::Empty, _) | (StoredIdentity::Proven, SeedSource::Recovered) => Ok(()),
        (_, SeedSource::Generated) => Err(WalletError::ForeignDatabase),
        // The fingerprint alone proves nothing, and the seed check a create writes would stamp
        // the database with this seed: an output of another seed refuses it. A database without
        // outputs holds nothing a seed could be proven by, nor anything to lose.
        (StoredIdentity::FingerprintOnly, SeedSource::Recovered) => {
            if store.read(|repos| outputs_prove(repos, keychain))? == Some(false) {
                return Err(WalletError::ForeignDatabase);
            }
            Ok(())
        }
    }
}

/// Unlocks the secret storage, reads the seed and opens the database it belongs to.
pub(crate) fn open<S: StoreOpener, V: SecretVault>(
    stores: &S,
    secrets: &V,
    target: &Target<'_>,
    password: &Password,
    key_start: u32,
) -> Result<Session<S::Store>, WalletError> {
    let vault = secrets.unlock(password)?;
    debug!("secret storage unlocked");
    let stored = vault.get(&seed_name()?)?.ok_or(WalletError::NoWallet)?;
    let seed = Seed::from_entropy(stored.expose_bytes()).map_err(WalletError::StoredSeed)?;
    let keychain = Keychain::from_seed(&seed, target.network)?;
    let ours = SeedIdentity::of(&seed, &keychain)?;
    let (store, at_rest) =
        stores.open_reporting(target.data_dir, store_keys(&seed)?, &store_key(&seed)?)?;
    // A missing database is rebuilt empty: everything in it but history is recovered by a scan,
    // which must run before new outputs are created. So does one beside which an older build
    // made outputs after a rollback.
    let at_rest = store.write(|repos| {
        let identity = stored_identity(repos, target.network, &ours)?;
        initialise(repos, target.network, &ours, key_start)?;
        let at_rest = after_rollback(repos, at_rest)?;
        if identity == StoredIdentity::Empty || rolled_back(at_rest.as_ref()) {
            require_restore_scan(repos)?;
        }
        Ok::<_, WalletError>(at_rest)
    })?;
    debug!("wallet database prepared");
    Ok(Session {
        keychain,
        seed: seed.clone(),
        store,
        slates: SlateCache::default(),
        at_rest,
    })
}

/// What [`check_phrase`] found the database to be.
#[derive(Debug)]
pub enum PhraseCheck {
    /// The database is the seed's: its seed check, or for a database without one, one of its
    /// outputs, proves it. Holds the seed.
    Matches(Seed),
    /// There is no database, or no wallet has used it, so there is nothing to compare with.
    Unused,
    /// The fingerprint matches, but nothing in the database proves the seed: it has no seed
    /// check, as a database no open of this version has seen, and no output. The fingerprint
    /// alone does not prove a phrase.
    Unproven,
}

/// Checks that `phrase` is the recovery phrase of the database in `data_dir` on `network`,
/// without its vault, on the calling thread. The fingerprint only tells databases apart: the
/// phrase is proven by the seed check every open stores, or, in a database no open of this
/// version has seen, by an output whose commitment the seed derives from its key and amount,
/// after which the seed check is stored. Nothing else is changed, also when the check fails,
/// but the database is migrated to the current schema as an open migrates it.
///
/// Fails with [`WalletError::Mnemonic`] for a phrase that is not valid BIP39 English,
/// [`WalletError::ForeignDatabase`] when the database belongs to another seed,
/// [`WalletError::NetworkMismatch`] when to another network, and with
/// [`lepic_store::StoreError::Damaged`] when the database is damaged, which is left where it
/// is.
pub fn check_phrase<S: StoreOpener>(
    stores: &S,
    data_dir: &Path,
    network: Network,
    phrase: &str,
) -> Result<PhraseCheck, WalletError> {
    let seed = Seed::from_mnemonic(phrase).map_err(WalletError::Mnemonic)?;
    check_seed(stores, &Target { data_dir, network }, seed)
}

/// [`check_phrase`] of a seed.
pub(crate) fn check_seed<S: StoreOpener>(
    stores: &S,
    target: &Target<'_>,
    seed: Seed,
) -> Result<PhraseCheck, WalletError> {
    let keychain = Keychain::from_seed(&seed, target.network)?;
    let ours = SeedIdentity::of(&seed, &keychain)?;
    // An encrypted database that refuses the phrase's key is not the phrase's.
    let opened = match stores.open_existing(target.data_dir, store_keys(&seed)?, &store_key(&seed)?)
    {
        Err(StoreError::WrongKey) => return Err(WalletError::ForeignDatabase),
        opened => opened?,
    };
    let Some(store) = opened else {
        return Ok(PhraseCheck::Unused);
    };
    match store.read(|repos| stored_identity(repos, target.network, &ours))? {
        StoredIdentity::Empty => Ok(PhraseCheck::Unused),
        StoredIdentity::Proven => Ok(PhraseCheck::Matches(seed)),
        StoredIdentity::FingerprintOnly => {
            match store.read(|repos| outputs_prove(repos, &keychain))? {
                Some(true) => {
                    store
                        .write(|repos| repos.put_setting(SEED_CHECK_SETTING, &ours.check_text()))?;
                    debug!("an output proved the phrase; seed check stored");
                    Ok(PhraseCheck::Matches(seed))
                }
                Some(false) => Err(WalletError::ForeignDatabase),
                None => Ok(PhraseCheck::Unproven),
            }
        }
    }
}

/// Whether the outputs stored for every account were made by `keychain`'s seed: `Some(true)`
/// when one's commitment is the one its key and amount derive, `Some(false)` when there are
/// outputs and none is, `None` when there are none.
fn outputs_prove(
    repos: &dyn Repositories,
    keychain: &Keychain,
) -> Result<Option<bool>, WalletError> {
    let mut seen = false;
    for account in repos.accounts()? {
        for output in repos.outputs(account.index, None)? {
            seen = true;
            let Ok(key_id) = Identifier::from_bytes(&output.key_id.0) else {
                continue;
            };
            // A restore keeps every output whose proof rewinds, whatever its switch commitment.
            for switch in [SwitchCommitment::Regular, SwitchCommitment::None] {
                if keychain
                    .commit(output.amount.value(), &key_id, switch)
                    .is_ok_and(|derived| derived == output.id.commitment)
                {
                    return Ok(Some(true));
                }
            }
        }
    }
    Ok(seen.then_some(false))
}

/// What a database stores to tell its seed: the fingerprint, which identifies it, and the seed
/// check, which proves it.
struct SeedIdentity {
    fingerprint: String,
    /// Keyed by the seed, with the domain already added: finalising it gives the seed check.
    check: Blake2bMac<U32>,
}

impl SeedIdentity {
    fn of(seed: &Seed, keychain: &Keychain) -> Result<Self, WalletError> {
        let mut check = seed_mac(seed)?;
        check.update(SEED_CHECK_DOMAIN);
        Ok(Self {
            fingerprint: fingerprint(keychain)?,
            check,
        })
    }

    fn check_text(&self) -> String {
        let bytes: [u8; 32] = self.check.clone().finalize_fixed().into();
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Whether the stored hex `text` is the seed check, compared in constant time. Malformed
    /// text matches nothing.
    fn check_matches(&self, text: &str) -> bool {
        unhex(text).is_some_and(|stored| {
            blake2::digest::Mac::verify_slice(self.check.clone(), &stored).is_ok()
        })
    }
}

/// The bytes of hex `text`, or `None` when it is not hex.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredIdentity {
    Empty,
    /// The fingerprint matches and the seed check proves the seed.
    Proven,
    /// The fingerprint matches; the database holds no seed check yet.
    FingerprintOnly,
}

/// Whether the database is unused or already belongs to this seed on this network. A stored
/// seed check is compared in constant time.
fn stored_identity(
    repos: &dyn Repositories,
    network: Network,
    ours: &SeedIdentity,
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
        Some(stored) if stored == ours.fingerprint => match repos.setting(SEED_CHECK_SETTING)? {
            None => Ok(StoredIdentity::FingerprintOnly),
            Some(check) if ours.check_matches(&check) => Ok(StoredIdentity::Proven),
            Some(_) => Err(WalletError::ForeignDatabase),
        },
        _ => Err(WalletError::ForeignDatabase),
    }
}

/// Stamps the database with its network and seed, gives it `key_start` unless it has a key
/// start already, and adds the default account.
fn initialise(
    repos: &mut dyn Repositories,
    network: Network,
    ours: &SeedIdentity,
    key_start: u32,
) -> Result<(), WalletError> {
    repos.put_setting(NETWORK_SETTING, network.as_str())?;
    repos.put_setting(FINGERPRINT_SETTING, &ours.fingerprint)?;
    repos.put_setting(SEED_CHECK_SETTING, &ours.check_text())?;
    place_key_counters(repos, key_start)?;
    ensure_default_account(repos)
}

/// Takes the store's mark of a plain database set aside after a rollback into `report`, and
/// clears it: the restore scan it asks for is required in the same transaction.
fn after_rollback(
    repos: &mut dyn Repositories,
    report: Option<AtRestReport>,
) -> Result<Option<AtRestReport>, WalletError> {
    if repos.setting(ROLLBACK_SCAN_SETTING)?.is_none() {
        return Ok(report);
    }
    repos.delete_setting(ROLLBACK_SCAN_SETTING)?;
    Ok(Some(match report {
        Some(report) => AtRestReport {
            rollback_set_aside: true,
            ..report
        },
        None => AtRestReport {
            state: AtRestState::Encrypted,
            rollback_set_aside: true,
        },
    }))
}

fn rolled_back(report: Option<&AtRestReport>) -> bool {
    report.is_some_and(|report| report.rollback_set_aside)
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

/// Puts `seed` into new secret storage under the name an open reads it from, as
/// [`crate::Wallet::create`] and [`crate::Wallet::restore`] do. For a host that seals a
/// wallet's seed under a new password without a wallet handle, after
/// [`crate::Wallet::check_phrase`] found it the database's.
pub fn put_seed(secrets: &mut impl SecretStore, seed: &Seed) -> Result<(), WalletError> {
    secrets.put(&seed_name()?, &SecretBytes::from_slice(seed.expose_bytes()))?;
    Ok(())
}

fn seed_name() -> Result<SecretName, WalletError> {
    Ok(SecretName::new(SEED_SECRET)?)
}

/// The fingerprint a wallet of `seed` on `network` stores in its database, as lowercase hex:
/// what [`crate::Wallet::fingerprint`] returns once the wallet is open. It is no secret, but
/// it identifies the wallet. It does not depend on `network`: a phrase has the same
/// fingerprint on every chain, so a host telling wallets apart compares the chain and the
/// fingerprint. It identifies, never authenticates: at 32 bits, a phrase of another seed with
/// the same fingerprint can be found, so only [`check_phrase`] proves a phrase a database's.
pub fn seed_fingerprint(seed: &Seed, network: Network) -> Result<String, WalletError> {
    fingerprint(&Keychain::from_seed(seed, network)?)
}

/// The BIP32 fingerprint of the master key, which tells databases of different seeds apart
/// without revealing anything that derives keys. Being 32 bits, it does not prove a seed; the
/// seed check does.
pub(crate) fn fingerprint(keychain: &Keychain) -> Result<String, WalletError> {
    let lepic_keychain::Fingerprint(bytes) = keychain
        .master()
        .fingerprint()
        .map_err(lepic_keychain::KeychainError::from)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Keyed BLAKE2b of a domain string under the seed: the same seed always opens its database,
/// and the key reveals nothing about the seed.
/// The keys a wallet's database is opened with, derived from `seed`: the key its sealed records
/// are sealed under and the key its peer rows are found by. The one place both are derived, so
/// tests open a wallet's database with what the engine uses. Fails with
/// [`WalletError::StoredSeed`] for a seed the hash refuses as a key.
pub fn store_keys(seed: &Seed) -> Result<StoreKeys, WalletError> {
    Ok(StoreKeys::new(
        ContextKey::filled_by(|key| fill_context_key(seed, key))?,
        PeerTagKey::filled_by(|key| fill_peer_tag_key(seed, key))?,
    ))
}

fn fill_context_key(seed: &Seed, key: &mut [u8; CONTEXT_KEY_LEN]) -> Result<(), WalletError> {
    let mut mac = seed_mac(seed)?;
    mac.update(CONTEXT_KEY_DOMAIN);
    mac.finalize_into(key.into());
    Ok(())
}

fn fill_peer_tag_key(seed: &Seed, key: &mut [u8; PEER_TAG_KEY_LEN]) -> Result<(), WalletError> {
    let mut mac = seed_mac(seed)?;
    mac.update(PEER_TAG_KEY_DOMAIN);
    mac.finalize_into(key.into());
    Ok(())
}

/// The key the wallet database file is encrypted under: keyed BLAKE2b of its own domain under
/// the seed, so any install of the seed opens it, after a forgotten password too.
pub fn store_key(seed: &Seed) -> Result<StoreKey, WalletError> {
    StoreKey::filled_by(|key| fill_store_key(seed, key))
}

fn fill_store_key(seed: &Seed, key: &mut [u8; STORE_KEY_LEN]) -> Result<(), WalletError> {
    let mut mac = seed_mac(seed)?;
    mac.update(STORE_KEY_DOMAIN);
    mac.finalize_into(key.into());
    Ok(())
}

/// BLAKE2b-256 keyed by the seed, for a domain string to be added.
fn seed_mac(seed: &Seed) -> Result<Blake2bMac<U32>, WalletError> {
    <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).map_err(|_| {
        WalletError::StoredSeed(lepic_keychain::MnemonicError::EntropyLength {
            actual: seed.expose_bytes().len(),
        })
    })
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
        let first =
            Keychain::from_seed(&Seed::from_entropy(&[1; 16]).unwrap(), Network::Mainnet).unwrap();
        let second =
            Keychain::from_seed(&Seed::from_entropy(&[2; 16]).unwrap(), Network::Mainnet).unwrap();
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
        let mut key = [0; CONTEXT_KEY_LEN];
        fill_context_key(&seed, &mut key).unwrap();
        assert_eq!(key, expected);
    }

    /// The store vectors record both subkeys of their seeds, as an independent implementation
    /// derived them.
    #[test]
    fn store_keys_match_the_store_vectors() {
        for name in ["peer_compat", "peer_compat_migrated"] {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/vectors/store")
                .join(format!("{name}.json"));
            let vector: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let field = |group: &str, key: &str| vector[group][key].as_str().unwrap().to_owned();
            let hex = |bytes: &[u8]| -> String {
                bytes.iter().map(|byte| format!("{byte:02x}")).collect()
            };
            let entropy_hex = field("inputs", "entropy");
            let entropy: Vec<u8> = (0..entropy_hex.len() / 2)
                .map(|at| u8::from_str_radix(&entropy_hex[2 * at..2 * at + 2], 16).unwrap())
                .collect();
            let seed = Seed::from_entropy(&entropy).unwrap();
            let mut context = [0; CONTEXT_KEY_LEN];
            fill_context_key(&seed, &mut context).unwrap();
            let mut tag = [0; PEER_TAG_KEY_LEN];
            fill_peer_tag_key(&seed, &mut tag).unwrap();
            assert_eq!(hex(&context), field("expected", "context_key"), "{name}");
            assert_eq!(hex(&tag), field("expected", "peer_tag_key"), "{name}");
        }
    }

    #[test]
    fn peer_tag_key_is_its_own_subkey_of_the_seed() {
        let seed = Seed::from_entropy(&[5; 32]).unwrap();
        let mut key = [0; PEER_TAG_KEY_LEN];
        fill_peer_tag_key(&seed, &mut key).unwrap();
        let mut context = [0; CONTEXT_KEY_LEN];
        fill_context_key(&seed, &mut context).unwrap();
        assert_ne!(key, context);
    }

    #[test]
    fn store_key_is_keyed_blake2b_of_the_domain_under_the_seed() {
        let seed = Seed::from_entropy(&[5; 32]).unwrap();
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[5; 32]).unwrap();
        mac.update(b"lepic-wallet store key v1");
        let expected: [u8; 32] = mac.finalize_fixed().into();
        let mut key = [0; STORE_KEY_LEN];
        fill_store_key(&seed, &mut key).unwrap();
        assert_eq!(key, expected);
        let mut context = [0; CONTEXT_KEY_LEN];
        fill_context_key(&seed, &mut context).unwrap();
        assert_ne!(key, context);
    }
}
