// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use std::path::PathBuf;

use lepic_keychain::{SecretName, SecretStore, Seed};
use lepic_primitives::params::Network;
use lepic_store::AccountIndex;
use lepic_transport::transport::TransportId;
use lepic_wallet::{
    AccountError, ConfigError, DEFAULT_ACCOUNT_LABEL, Event, SecretVault, SessionState,
    SqliteStores, Wallet, WalletError, WordCount,
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
