// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use std::path::PathBuf;

use lepic_keychain::{Identifier, Keychain, SecretName, SecretStore, Seed, SwitchCommitment};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, ContextKey, KeyId, MemoryStore, OutputRecord, OutputStatus, WalletStore,
};
use lepic_transport::transport::TransportId;
use lepic_wallet::lifecycle::PhraseCheck;
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanStart};
use lepic_wallet::{
    AccountError, ConfigError, DEFAULT_ACCOUNT_LABEL, Event, SecretVault, SessionState,
    SqliteStores, StoreOpener, Wallet, WalletError, WordCount, lifecycle,
};
use support::{Harness, TestVault, WALLET_SEED_VECTOR, password, vector_text};
use tokio::sync::broadcast::Receiver;

const PASSWORD: &str = "correct horse battery staple";
const WRONG_PASSWORD: &str = "incorrect horse";

fn seed_vector() -> serde_json::Value {
    serde_json::from_str(WALLET_SEED_VECTOR).unwrap()
}

fn vector_phrase() -> String {
    vector_text(&seed_vector(), "/inputs/mnemonic")
}

fn drain(events: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| events.try_recv().ok()).collect()
}

#[test]
fn create_returns_the_phrase_and_unlocks_with_the_default_account() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    let mut events = wallet.subscribe();
    assert!(!wallet.is_unlocked());

    let phrase = harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();

    assert_eq!(phrase.expose().split(' ').count(), 24);
    assert!(Seed::from_mnemonic(phrase.expose()).is_ok());
    assert!(wallet.is_unlocked());
    let accounts = wallet.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].label, DEFAULT_ACCOUNT_LABEL);
    assert_eq!(
        accounts[0].parent_key_id().unwrap().to_bip32_path(),
        "m/0/0"
    );
    assert_eq!(drain(&mut events), [Event::Session(SessionState::Unlocked)]);
}

#[test]
fn create_draws_entropy_from_the_injected_rng() {
    let first = Harness::new();
    let second = Harness::new();
    let phrases: Vec<String> = [&first, &second]
        .into_iter()
        .map(|harness| {
            let wallet = harness.wallet();
            harness
                .block_on(wallet.create(password(PASSWORD), WordCount::Twelve))
                .unwrap()
                .expose()
                .to_owned()
        })
        .collect();
    assert_eq!(phrases[0], phrases[1]);
    assert_eq!(phrases[0].split(' ').count(), 12);
}

#[test]
fn create_is_refused_when_the_secret_storage_holds_a_wallet() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .create(password(PASSWORD), WordCount::default()),
        )
        .unwrap();

    let again = harness.wallet();
    let result = harness.block_on(again.create(password(PASSWORD), WordCount::default()));

    assert!(matches!(result, Err(WalletError::WalletExists)));
    assert!(!again.is_unlocked());
}

#[test]
fn create_is_refused_over_another_wallets_database_without_creating_secrets() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .create(password(PASSWORD), WordCount::default()),
        )
        .unwrap();

    let fresh_vault = TestVault::default();
    let other = harness.wallet_with(harness.config(Network::Mainnet), fresh_vault.clone());
    let result = harness.block_on(other.create(password(PASSWORD), WordCount::default()));

    assert!(matches!(result, Err(WalletError::ForeignDatabase)));
    assert!(!fresh_vault.is_created());
}

#[test]
fn open_after_restart_unlocks_with_the_password_and_keeps_accounts() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    wallet.create_account("savings").unwrap();
    wallet.close();

    let reopened = harness.wallet();
    let mut events = reopened.subscribe();
    harness.block_on(reopened.open(password(PASSWORD))).unwrap();

    assert!(reopened.is_unlocked());
    let labels: Vec<String> = reopened
        .accounts()
        .unwrap()
        .into_iter()
        .map(|account| account.label)
        .collect();
    assert_eq!(labels, [DEFAULT_ACCOUNT_LABEL, "savings"]);
    assert_eq!(reopened.account("savings").unwrap().index, AccountIndex(1));
    assert_eq!(drain(&mut events), [Event::Session(SessionState::Unlocked)]);
}

#[test]
fn open_with_a_wrong_password_is_refused_and_stays_locked() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .create(password(PASSWORD), WordCount::default()),
        )
        .unwrap();

    let wallet = harness.wallet();
    let mut events = wallet.subscribe();
    let result = harness.block_on(wallet.open(password(WRONG_PASSWORD)));

    assert!(matches!(result, Err(WalletError::WrongPassword)));
    assert!(!wallet.is_unlocked());
    assert!(matches!(wallet.accounts(), Err(WalletError::Locked)));
    assert!(drain(&mut events).is_empty());
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();
}

#[test]
fn open_without_a_wallet_is_refused() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    let result = harness.block_on(wallet.open(password(PASSWORD)));
    assert!(matches!(result, Err(WalletError::NoWallet)));
}

#[test]
fn open_while_unlocked_is_refused() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();

    let result = harness.block_on(wallet.open(password(PASSWORD)));
    assert!(matches!(result, Err(WalletError::AlreadyOpen)));
    let result = harness.block_on(wallet.restore(password(PASSWORD), &vector_phrase()));
    assert!(matches!(result, Err(WalletError::AlreadyOpen)));
    assert!(wallet.is_unlocked());
}

#[test]
fn open_on_another_network_is_refused() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .create(password(PASSWORD), WordCount::default()),
        )
        .unwrap();

    let floonet = harness.wallet_with(harness.config(Network::Floonet), harness.vault.clone());
    let result = harness.block_on(floonet.open(password(PASSWORD)));

    assert!(matches!(
        result,
        Err(WalletError::NetworkMismatch {
            configured: Network::Floonet,
            ..
        })
    ));
    assert!(!floonet.is_unlocked());
}

#[test]
fn open_rebuilds_a_missing_database() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .create(password(PASSWORD), WordCount::default()),
        )
        .unwrap();

    let mut config = harness.config(Network::Mainnet);
    config.data_dir = PathBuf::from("/moved-wallet-data");
    let wallet = harness.wallet_with(config, harness.vault.clone());
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();

    assert_eq!(wallet.accounts().unwrap().len(), 1);
    assert!(wallet.restore_scan_required().unwrap());
}

#[test]
fn only_a_database_rebuilt_from_a_seed_needs_a_restore_scan() {
    let harness = Harness::new();
    let created = harness.wallet();
    harness
        .block_on(created.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    assert!(!created.restore_scan_required().unwrap());

    let other = Harness::new();
    let restored = other.wallet();
    other
        .block_on(restored.restore(password(PASSWORD), &vector_phrase()))
        .unwrap();
    assert!(restored.restore_scan_required().unwrap());
    // A scan that does not start at genesis does not cover every key in use.
    other
        .block_on(restored.scan(
            ScanOptions {
                start: ScanStart::Height(Height::new(5)),
                ..ScanOptions::restore(Network::Mainnet)
            },
            &ScanCancel::new(),
        ))
        .unwrap();
    assert!(restored.restore_scan_required().unwrap());
    other
        .block_on(restored.scan(ScanOptions::restore(Network::Mainnet), &ScanCancel::new()))
        .unwrap();
    assert!(!restored.restore_scan_required().unwrap());
}

#[test]
fn restore_from_a_phrase_reaches_the_same_wallet() {
    let harness = Harness::new();
    let created = harness.wallet();
    harness
        .block_on(created.restore(password(PASSWORD), &vector_phrase()))
        .unwrap();
    assert!(created.is_unlocked());
    created.create_account("savings").unwrap();
    created.close();

    // A new device: fresh secret storage, the same database.
    let restored = harness.wallet_with(harness.config(Network::Mainnet), TestVault::default());
    harness
        .block_on(restored.restore(password("another password"), &vector_phrase()))
        .unwrap();

    assert_eq!(restored.accounts().unwrap().len(), 2);
}

#[test]
fn restore_of_another_phrase_over_a_database_is_refused() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .create(password(PASSWORD), WordCount::default()),
        )
        .unwrap();

    let fresh_vault = TestVault::default();
    let other = harness.wallet_with(harness.config(Network::Mainnet), fresh_vault.clone());
    let result = harness.block_on(other.restore(password(PASSWORD), &vector_phrase()));

    assert!(matches!(result, Err(WalletError::ForeignDatabase)));
    assert!(!fresh_vault.is_created());
}

#[test]
fn the_fingerprint_of_an_open_wallet_is_its_phrases_and_differs_by_seed() {
    let harness = Harness::new();
    let created = harness.wallet();
    let phrase = harness
        .block_on(created.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    let seed = Seed::from_mnemonic(phrase.expose()).unwrap();
    let fingerprint = created.fingerprint().unwrap();
    assert_eq!(
        fingerprint,
        lifecycle::seed_fingerprint(&seed, Network::Mainnet).unwrap()
    );
    assert_eq!(fingerprint.len(), 8);

    let other = Harness::new();
    let restored = other.wallet();
    other
        .block_on(restored.restore(password(PASSWORD), &vector_phrase()))
        .unwrap();
    let vector_seed = Seed::from_mnemonic(&vector_phrase()).unwrap();
    assert_eq!(
        restored.fingerprint().unwrap(),
        lifecycle::seed_fingerprint(&vector_seed, Network::Mainnet).unwrap()
    );
    assert_ne!(restored.fingerprint().unwrap(), fingerprint);
    restored.lock();
    assert!(matches!(restored.fingerprint(), Err(WalletError::Locked)));
}

#[test]
fn check_phrase_tells_the_wallets_phrase_from_another_and_changes_nothing() {
    let harness = Harness::new();
    let created = harness.wallet();
    let phrase = harness
        .block_on(created.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    created.create_account("savings").unwrap();
    assert!(matches!(
        harness.block_on(created.check_phrase(phrase.expose())),
        Err(WalletError::AlreadyOpen)
    ));
    created.close();

    let wallet = harness.wallet();
    let PhraseCheck::Matches(seed) = harness
        .block_on(wallet.check_phrase(phrase.expose()))
        .unwrap()
    else {
        panic!("the wallet's phrase did not match");
    };
    assert_eq!(
        seed.expose_bytes(),
        Seed::from_mnemonic(phrase.expose()).unwrap().expose_bytes()
    );
    assert!(matches!(
        harness.block_on(wallet.check_phrase(&vector_phrase())),
        Err(WalletError::ForeignDatabase)
    ));
    assert!(matches!(
        harness.block_on(wallet.check_phrase("abandon abandon")),
        Err(WalletError::Mnemonic(_))
    ));
    assert!(!wallet.is_unlocked());
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();
    assert_eq!(wallet.accounts().unwrap().len(), 2);
    assert!(!wallet.restore_scan_required().unwrap());
}

#[test]
fn check_phrase_on_an_unused_database_finds_nothing_to_compare() {
    let harness = Harness::new();
    let wallet = harness.wallet();

    assert!(matches!(
        harness.block_on(wallet.check_phrase(&vector_phrase())),
        Ok(PhraseCheck::Unused)
    ));
}

const SEED_CHECK: &str = "wallet.seed_check";
const FINGERPRINT: &str = "wallet.fingerprint";

/// The harness's mainnet database, as another program with the data folder would open it.
fn database(harness: &Harness) -> MemoryStore {
    harness
        .stores
        .open(&harness.data_dir, ContextKey::from_bytes([0; 32]))
        .unwrap()
}

fn setting(harness: &Harness, key: &str) -> Option<String> {
    database(harness).read(|repos| repos.setting(key)).unwrap()
}

fn put_setting(harness: &Harness, key: &str, value: &str) {
    database(harness)
        .write(|repos| repos.put_setting(key, value))
        .unwrap();
}

/// A database as a version before the seed check left it.
fn drop_seed_check(harness: &Harness) {
    database(harness)
        .write(|repos| repos.delete_setting(SEED_CHECK))
        .unwrap();
}

/// Stores an unspent output of 5 nanoepic that the wallet of `phrase` made.
fn plant_output_of(harness: &Harness, phrase: &str) {
    let keychain =
        Keychain::from_seed(&Seed::from_mnemonic(phrase).unwrap(), Network::Mainnet).unwrap();
    let key_id = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let commitment = keychain
        .commit(
            5,
            &Identifier::from_bytes(&key_id).unwrap(),
            SwitchCommitment::Regular,
        )
        .unwrap();
    database(harness)
        .write(|repos| {
            repos.put_output(&OutputRecord {
                id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
                key_id: KeyId(key_id),
                account: AccountIndex(0),
                amount: Amount::new(5),
                status: OutputStatus::Unspent,
                height: Height::new(10),
                lock_height: Height::new(10),
                mmr_index: Some(1),
                tx: None,
            })
        })
        .unwrap();
}

/// A closed wallet made by `create`, with its phrase.
fn closed_wallet(harness: &Harness) -> String {
    let wallet = harness.wallet();
    let phrase = harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    wallet.close();
    phrase.expose().to_owned()
}

/// The fingerprint has 32 bits, so a phrase of another seed with the same one can be found by
/// grinding. Planting the other seed's fingerprint stands in for such a phrase: the seed check
/// refuses it.
#[test]
fn check_phrase_refuses_a_phrase_whose_fingerprint_matches_but_whose_seed_differs() {
    let harness = Harness::new();
    closed_wallet(&harness);
    let colliding = vector_phrase();
    let fingerprint =
        lifecycle::seed_fingerprint(&Seed::from_mnemonic(&colliding).unwrap(), Network::Mainnet)
            .unwrap();
    put_setting(&harness, FINGERPRINT, &fingerprint);
    let check = setting(&harness, SEED_CHECK).unwrap();

    let result = harness.block_on(harness.wallet().check_phrase(&colliding));

    assert!(
        matches!(result, Err(WalletError::ForeignDatabase)),
        "{result:?}"
    );
    assert_eq!(setting(&harness, SEED_CHECK).unwrap(), check);
}

#[test]
fn every_open_stores_the_seed_check_that_proves_the_phrase() {
    let harness = Harness::new();
    let phrase = closed_wallet(&harness);
    let check = setting(&harness, SEED_CHECK).unwrap();
    assert_eq!(check.len(), 64);
    drop_seed_check(&harness);

    let wallet = harness.wallet();
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();
    wallet.close();

    assert_eq!(setting(&harness, SEED_CHECK).unwrap(), check);
    assert!(matches!(
        harness.block_on(harness.wallet().check_phrase(&phrase)),
        Ok(PhraseCheck::Matches(_))
    ));
}

/// A database no open of this version has seen has no seed check: one of its outputs proves
/// the phrase, and the seed check is stored then.
#[test]
fn check_phrase_on_a_database_without_a_seed_check_is_proven_by_an_output() {
    let harness = Harness::new();
    let phrase = closed_wallet(&harness);
    let check = setting(&harness, SEED_CHECK).unwrap();
    drop_seed_check(&harness);
    plant_output_of(&harness, &phrase);

    let result = harness.block_on(harness.wallet().check_phrase(&phrase));

    assert!(matches!(result, Ok(PhraseCheck::Matches(_))), "{result:?}");
    assert_eq!(setting(&harness, SEED_CHECK).unwrap(), check);
}

#[test]
fn an_output_of_another_seed_refuses_a_phrase_with_a_matching_fingerprint() {
    let harness = Harness::new();
    let phrase = closed_wallet(&harness);
    drop_seed_check(&harness);
    plant_output_of(&harness, &phrase);
    let colliding = vector_phrase();
    let fingerprint =
        lifecycle::seed_fingerprint(&Seed::from_mnemonic(&colliding).unwrap(), Network::Mainnet)
            .unwrap();
    put_setting(&harness, FINGERPRINT, &fingerprint);

    let result = harness.block_on(harness.wallet().check_phrase(&colliding));

    assert!(
        matches!(result, Err(WalletError::ForeignDatabase)),
        "{result:?}"
    );
    assert_eq!(setting(&harness, SEED_CHECK), None);
}

/// Without a seed check or an output nothing proves the phrase, so a matching fingerprint is
/// not taken for proof.
#[test]
fn check_phrase_on_a_database_with_nothing_to_prove_the_phrase_is_unproven() {
    let harness = Harness::new();
    let phrase = closed_wallet(&harness);
    drop_seed_check(&harness);

    let result = harness.block_on(harness.wallet().check_phrase(&phrase));

    assert!(matches!(result, Ok(PhraseCheck::Unproven)), "{result:?}");
    assert_eq!(setting(&harness, SEED_CHECK), None);
}

/// A restore stores the seed check of the phrase it was given, so over a database without
/// one the fingerprint is not taken for proof: an output of another seed refuses the phrase.
#[test]
fn restore_of_a_colliding_phrase_over_a_database_without_a_seed_check_is_refused_by_an_output() {
    let harness = Harness::new();
    let phrase = closed_wallet(&harness);
    drop_seed_check(&harness);
    plant_output_of(&harness, &phrase);
    let colliding = vector_phrase();
    let fingerprint =
        lifecycle::seed_fingerprint(&Seed::from_mnemonic(&colliding).unwrap(), Network::Mainnet)
            .unwrap();
    put_setting(&harness, FINGERPRINT, &fingerprint);

    let fresh_vault = TestVault::default();
    let other = harness.wallet_with(harness.config(Network::Mainnet), fresh_vault.clone());
    let result = harness.block_on(other.restore(password(PASSWORD), &colliding));

    assert!(
        matches!(result, Err(WalletError::ForeignDatabase)),
        "{result:?}"
    );
    assert!(!fresh_vault.is_created());
    assert_eq!(setting(&harness, SEED_CHECK), None);
}

#[test]
fn restore_over_a_database_without_a_seed_check_or_outputs_is_accepted() {
    let harness = Harness::new();
    closed_wallet(&harness);
    drop_seed_check(&harness);
    let restored_phrase = vector_phrase();
    let fingerprint = lifecycle::seed_fingerprint(
        &Seed::from_mnemonic(&restored_phrase).unwrap(),
        Network::Mainnet,
    )
    .unwrap();
    put_setting(&harness, FINGERPRINT, &fingerprint);

    let restored = harness.wallet_with(harness.config(Network::Mainnet), TestVault::default());
    harness
        .block_on(restored.restore(password(PASSWORD), &restored_phrase))
        .unwrap();
    restored.close();

    assert!(setting(&harness, SEED_CHECK).is_some());
    assert!(matches!(
        harness.block_on(harness.wallet().check_phrase(&restored_phrase)),
        Ok(PhraseCheck::Matches(_))
    ));
}

#[test]
fn restore_over_a_database_without_a_seed_check_is_proven_by_its_own_output() {
    let harness = Harness::new();
    let phrase = closed_wallet(&harness);
    let check = setting(&harness, SEED_CHECK).unwrap();
    drop_seed_check(&harness);
    plant_output_of(&harness, &phrase);

    let restored = harness.wallet_with(harness.config(Network::Mainnet), TestVault::default());
    harness
        .block_on(restored.restore(password(PASSWORD), &phrase))
        .unwrap();

    assert!(restored.is_unlocked());
    assert_eq!(setting(&harness, SEED_CHECK).unwrap(), check);
}

/// The check of a phrase leaves a damaged database where it is, so it is still there to retry
/// or to set aside by an open.
#[test]
fn check_phrase_leaves_a_damaged_database_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join(lepic_wallet::DATABASE_FILE);
    std::fs::write(&database, [0x5a; 8192]).unwrap();

    for _ in 0..2 {
        let result = lifecycle::check_phrase(
            &SqliteStores,
            dir.path(),
            Network::Floonet,
            &vector_phrase(),
        );
        assert!(
            matches!(
                result,
                Err(WalletError::Store(lepic_store::StoreError::Damaged))
            ),
            "{result:?}"
        );
    }
    assert_eq!(std::fs::read(&database).unwrap(), [0x5a; 8192]);
    assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .to_string_lossy()
            .contains(".damaged-")
    }));
}

#[test]
fn check_phrase_refuses_a_database_of_another_network() {
    let harness = Harness::new();
    harness
        .block_on(
            harness
                .wallet()
                .restore(password(PASSWORD), &vector_phrase()),
        )
        .unwrap();

    let floonet = harness.wallet_with(harness.config(Network::Floonet), TestVault::default());
    let result = harness.block_on(floonet.check_phrase(&vector_phrase()));

    assert!(matches!(result, Err(WalletError::NetworkMismatch { .. })));
}

#[test]
fn restore_rejects_an_invalid_phrase() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    let mut words: Vec<String> = vector_phrase().split(' ').map(str::to_owned).collect();
    words.swap(0, 1);

    for phrase in [words.join(" "), "abandon abandon".to_owned(), String::new()] {
        let result = harness.block_on(wallet.restore(password(PASSWORD), &phrase));
        assert!(matches!(result, Err(WalletError::Mnemonic(_))));
    }
    assert!(!harness.vault.is_created());
}

#[test]
fn import_of_an_upstream_wallet_seed_reaches_the_wallet_of_its_phrase() {
    let vector = seed_vector();
    let harness = Harness::new();
    let imported = harness.wallet();
    harness
        .block_on(imported.import_wallet_seed(
            password(PASSWORD),
            &vector_text(&vector, "/expected/file"),
            password(&vector_text(&vector, "/inputs/password")),
        ))
        .unwrap();
    assert!(imported.is_unlocked());
    imported.close();

    let vault = harness.vault.unlock(&password(PASSWORD)).unwrap();
    let stored_seed = vault
        .get(&SecretName::new("wallet/seed").unwrap())
        .unwrap()
        .unwrap();
    let expected = Seed::from_mnemonic(&vector_phrase()).unwrap();
    assert_eq!(stored_seed.expose_bytes(), expected.expose_bytes());

    // The database the import prepared belongs to the phrase's wallet.
    let restored = harness.wallet_with(harness.config(Network::Mainnet), TestVault::default());
    harness
        .block_on(restored.restore(password(PASSWORD), &vector_phrase()))
        .unwrap();
}

#[test]
fn import_with_a_wrong_file_password_is_refused() {
    let vector = seed_vector();
    let harness = Harness::new();
    let wallet = harness.wallet();
    let result = harness.block_on(wallet.import_wallet_seed(
        password(PASSWORD),
        &vector_text(&vector, "/expected/file"),
        password(&vector_text(&vector, "/inputs/wrong_password")),
    ));

    assert!(matches!(result, Err(WalletError::WrongPassword)));
    assert!(!harness.vault.is_created());
    assert!(!wallet.is_unlocked());
}

#[test]
fn import_of_a_malformed_file_is_refused() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    for file in [
        "",
        "{}",
        "{\"encrypted_seed\": \"zz\", \"salt\": \"00\", \"nonce\": \"00\"}",
    ] {
        let result =
            harness.block_on(wallet.import_wallet_seed(password(PASSWORD), file, password("x")));
        assert!(
            matches!(result, Err(WalletError::WalletSeedFile(_))),
            "{file}"
        );
    }
}

#[test]
fn lock_drops_the_session_once_and_open_unlocks_again() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    let mut events = wallet.subscribe();

    wallet.lock();
    wallet.lock();

    assert!(!wallet.is_unlocked());
    assert!(matches!(wallet.accounts(), Err(WalletError::Locked)));
    assert!(matches!(
        wallet.create_account("savings"),
        Err(WalletError::Locked)
    ));
    harness.block_on(wallet.open(password(PASSWORD))).unwrap();
    assert_eq!(
        drain(&mut events),
        [
            Event::Session(SessionState::Locked),
            Event::Session(SessionState::Unlocked)
        ]
    );
}

#[test]
fn close_locks_and_ends_the_event_stream() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    let mut events = wallet.subscribe();

    wallet.close();

    assert_eq!(
        drain(&mut events),
        [
            Event::Session(SessionState::Locked),
            Event::Session(SessionState::Closed)
        ]
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Closed)
    ));
}

#[test]
fn account_labels_are_validated_and_unique() {
    let harness = Harness::new();
    let wallet = harness.wallet();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();

    assert!(matches!(
        wallet.create_account(DEFAULT_ACCOUNT_LABEL),
        Err(WalletError::Account(AccountError::LabelTaken))
    ));
    assert!(matches!(
        wallet.create_account(""),
        Err(WalletError::Account(AccountError::LabelLength {
            actual: 0
        }))
    ));
    assert!(matches!(
        wallet.account("missing"),
        Err(WalletError::Account(AccountError::UnknownLabel))
    ));
    let account = wallet.create_account("savings").unwrap();
    assert_eq!(account.parent_key_id().unwrap().to_bip32_path(), "m/1/0");
}

#[test]
fn configuration_naming_an_unregistered_transport_is_refused() {
    let harness = Harness::new();
    let mut config = harness.config(Network::Mainnet);
    config.transports.push(TransportId::new("epicbox"));

    let result = Wallet::new(config, harness.ports(TestVault::default()));

    assert!(matches!(
        result,
        Err(WalletError::Config(ConfigError::UnknownTransport { transport }))
            if transport == TransportId::new("epicbox")
    ));
}

#[test]
fn sqlite_wallet_survives_a_restart() {
    let harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let mut config = harness.config(Network::Floonet);
    config.data_dir = dir.path().to_owned();
    let ports = |vault: TestVault| {
        let memory = harness.ports(vault);
        lepic_wallet::Ports {
            node: memory.node,
            stores: SqliteStores,
            secrets: memory.secrets,
            transports: memory.transports,
            clock: memory.clock,
            rng: memory.rng,
            runtime: memory.runtime,
        }
    };

    let wallet = Wallet::new(config.clone(), ports(harness.vault.clone())).unwrap();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    wallet.create_account("savings").unwrap();
    wallet.close();
    assert!(dir.path().join(lepic_wallet::DATABASE_FILE).is_file());

    let reopened = Wallet::new(config.clone(), ports(harness.vault.clone())).unwrap();
    let result = harness.block_on(reopened.open(password(WRONG_PASSWORD)));
    assert!(matches!(result, Err(WalletError::WrongPassword)));
    harness.block_on(reopened.open(password(PASSWORD))).unwrap();
    assert_eq!(reopened.accounts().unwrap().len(), 2);
    reopened.close();

    let mut mainnet = config;
    mainnet.network = Network::Mainnet;
    let other_network = Wallet::new(mainnet, ports(harness.vault.clone())).unwrap();
    let result = harness.block_on(other_network.open(password(PASSWORD)));
    assert!(matches!(result, Err(WalletError::NetworkMismatch { .. })));
}

#[test]
fn lifecycle_futures_can_move_between_threads() {
    fn assert_send<T: Send>(_: &T) {}
    let harness = Harness::new();
    let wallet = harness.wallet();
    assert_send(&wallet.create(password(PASSWORD), WordCount::default()));
    assert_send(&wallet.restore(password(PASSWORD), ""));
    assert_send(&wallet.import_wallet_seed(password(PASSWORD), "", password("")));
    assert_send(&wallet.open(password(PASSWORD)));
}

/// A damaged database is reported once and kept beside the wallet; the next open rebuilds it as
/// if it were missing, so a scan from genesis must run before new outputs are made.
#[test]
fn a_damaged_database_is_set_aside_and_the_next_open_rebuilds_it() {
    let harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let mut config = harness.config(Network::Floonet);
    config.data_dir = dir.path().to_owned();
    let ports = |vault: TestVault| {
        let memory = harness.ports(vault);
        lepic_wallet::Ports {
            node: memory.node,
            stores: SqliteStores,
            secrets: memory.secrets,
            transports: memory.transports,
            clock: memory.clock,
            rng: memory.rng,
            runtime: memory.runtime,
        }
    };
    let wallet = Wallet::new(config.clone(), ports(harness.vault.clone())).unwrap();
    harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    wallet.close();
    let database = dir.path().join(lepic_wallet::DATABASE_FILE);
    std::fs::write(&database, [0x5a; 8192]).unwrap();

    let reopened = Wallet::new(config.clone(), ports(harness.vault.clone())).unwrap();
    let result = harness.block_on(reopened.open(password(PASSWORD)));
    assert!(
        matches!(
            result,
            Err(WalletError::Store(lepic_store::StoreError::DamagedSetAside))
        ),
        "{result:?}"
    );
    assert!(!reopened.is_unlocked());
    let kept: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.to_string_lossy().contains(".damaged-"))
        .collect();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(std::fs::read(&kept[0]).unwrap(), [0x5a; 8192]);

    harness.block_on(reopened.open(password(PASSWORD))).unwrap();
    assert_eq!(reopened.accounts().unwrap().len(), 1);
    assert!(reopened.restore_scan_required().unwrap());
}
