// SPDX-License-Identifier: Apache-2.0
//! Changing a wallet's password, and resetting a forgotten one from the recovery phrase, also
//! when the app stops or its store fails part way.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use lepic_store::WalletStore as _;

use super::http::EPIC;
use super::{FAILURES_KEY, Fixture, PENDING_KEY, PIN, PIN_KEY, kind};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::secret_store::{AppSecretStore, SecretReply};
use crate::api::types::Chain;
use crate::api::wallet::{EpicWallet, delete_wallet, reset_password, wallet_fingerprint};
use crate::vault_port::{VAULT_KEY, VAULT_NEXT_KEY};

const OLD: &str = "old password";
const NEW: &str = "new password";

/// An app store whose writes and deletes can stop taking effect, as after a power cut, or
/// fail for one key, as on a full disk.
#[derive(Clone, Default)]
struct FaultyStore {
    values: Arc<Mutex<BTreeMap<String, String>>>,
    /// Writes and deletes that still take effect; `None` for no limit.
    mutations_left: Arc<Mutex<Option<usize>>>,
    full_for: Arc<Mutex<Vec<&'static str>>>,
}

impl FaultyStore {
    fn app_store(&self) -> AppSecretStore {
        let (read, write, delete) = (self.clone(), self.clone(), self.clone());
        AppSecretStore::new(
            move |key| {
                let value = read.get(&key);
                Box::pin(async move { SecretReply { ok: true, value } })
            },
            move |key, value| {
                let ok = !write.full_for.lock().unwrap().contains(&key.as_str()) && write.mutate();
                if ok {
                    write.values.lock().unwrap().insert(key, value);
                }
                Box::pin(async move { SecretReply { ok, value: None } })
            },
            move |key| {
                let ok = delete.mutate();
                if ok {
                    delete.values.lock().unwrap().remove(&key);
                }
                Box::pin(async move { SecretReply { ok, value: None } })
            },
        )
        .unwrap()
    }

    fn mutate(&self) -> bool {
        let mut left = self.mutations_left.lock().unwrap();
        match *left {
            None => true,
            Some(0) => false,
            Some(n) => {
                *left = Some(n.saturating_sub(1));
                true
            }
        }
    }

    /// Lets `mutations` more writes and deletes take effect, and no later one.
    fn cut_after(&self, mutations: usize) {
        *self.mutations_left.lock().unwrap() = Some(mutations);
    }

    fn fill_for(&self, key: &'static str) {
        self.full_for.lock().unwrap().push(key);
    }

    fn get(&self, key: &str) -> Option<String> {
        self.values.lock().unwrap().get(key).cloned()
    }

    /// What a restarted app finds: the values, with no faults.
    fn after_restart(&self) -> Self {
        Self {
            values: Arc::new(Mutex::new(self.values.lock().unwrap().clone())),
            ..Self::default()
        }
    }
}

async fn create(fixture: &Fixture, store: &AppSecretStore) -> EpicWallet {
    EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        store,
        None,
        None,
        OLD.to_owned(),
    )
    .await
    .unwrap()
}

/// Whether `password` opens the wallet in `store`; the wallet is closed again.
async fn opens(fixture: &Fixture, store: &FaultyStore, password: &str) -> bool {
    let opened = EpicWallet::open(
        &fixture.runtime,
        fixture.config(),
        &store.app_store(),
        password.to_owned(),
    )
    .await;
    match opened {
        Ok(_) => true,
        Err(error) => {
            assert_eq!(error.kind, WalletErrorKind::WrongPassword, "{error}");
            false
        }
    }
}

/// Which of the old and the new password open the wallet after a restart into `store`, each
/// tried on its own copy. A password that opens settles the change: it opens again, the
/// other does not, and no pending vault is left.
async fn passwords_after_restart(fixture: &Fixture, store: &FaultyStore) -> (bool, bool) {
    let mut result = [false; 2];
    for (index, (password, other)) in [(OLD, NEW), (NEW, OLD)].into_iter().enumerate() {
        let copy = store.after_restart();
        if opens(fixture, &copy, password).await {
            result[index] = true;
            assert_eq!(copy.get(VAULT_NEXT_KEY), None, "{password}");
            assert!(opens(fixture, &copy, password).await, "{password}");
            assert!(!opens(fixture, &copy, other).await, "{password}");
        }
    }
    (result[0], result[1])
}

#[tokio::test]
async fn after_a_change_only_the_new_password_opens_the_wallet() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();

    wallet
        .change_password(OLD.to_owned(), NEW.to_owned())
        .await
        .unwrap();

    assert_eq!(
        kind(wallet.mnemonic(OLD.to_owned()).await),
        WalletErrorKind::WrongPassword
    );
    assert_eq!(wallet.mnemonic(NEW.to_owned()).await.unwrap(), phrase);
    drop(wallet);
    assert_eq!(store.get(VAULT_NEXT_KEY), None);
    assert_eq!(store.get(FAILURES_KEY), None);
    assert!(!opens(&fixture, &store, OLD).await);
    assert!(opens(&fixture, &store, NEW).await);
}

#[tokio::test]
async fn a_wrong_current_password_is_counted_and_changes_nothing() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    let vault = store.get(VAULT_KEY);

    let changed = wallet
        .change_password("wrong password".to_owned(), NEW.to_owned())
        .await;

    assert_eq!(kind(changed), WalletErrorKind::WrongPassword);
    assert_eq!(store.get(FAILURES_KEY), Some("1".to_owned()));
    assert_eq!(store.get(VAULT_KEY), vault);
    assert_eq!(store.get(VAULT_NEXT_KEY), None);
    drop(wallet);
    assert!(opens(&fixture, &store, OLD).await);
}

#[tokio::test]
async fn a_wrong_current_password_waits_as_a_wrong_unlock_does() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    store
        .app_store()
        .write(FAILURES_KEY, "3".to_owned())
        .await
        .unwrap();

    let waited = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        wallet.change_password("wrong password".to_owned(), NEW.to_owned()),
    )
    .await;

    assert!(waited.is_err(), "the attempt did not wait");
}

#[tokio::test]
async fn a_pin_wallet_refuses_a_password_change_and_keeps_its_pin() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let created = fixture.create_with_pin(&store.app_store(), PIN).await;
    let vault = store.get(VAULT_KEY);

    let changed = created
        .wallet
        .change_password(OLD.to_owned(), NEW.to_owned())
        .await;

    assert_eq!(kind(changed), WalletErrorKind::Unsupported);
    assert_eq!(store.get(FAILURES_KEY), None);
    assert_eq!(store.get(VAULT_KEY), vault);
    let sealed = created
        .wallet
        .change_pin(
            created.sealed_password.clone(),
            PIN.to_owned(),
            "246802".to_owned(),
        )
        .await
        .unwrap();
    created
        .wallet
        .confirm_pin_change(sealed.clone())
        .await
        .unwrap();
    drop(created);
    let store = store.app_store();
    assert!(
        fixture
            .open_with_pin(&store, "246802", &sealed)
            .await
            .is_ok()
    );
}

/// A stop after the new vault was written, before it replaced the old one: both passwords open,
/// and the first open settles which one stays.
#[tokio::test]
async fn a_stop_between_writing_and_replacing_the_vault_keeps_both_passwords_until_open() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    // The failure count counted and cleared, then the new vault.
    store.cut_after(3);

    let changed = wallet.change_password(OLD.to_owned(), NEW.to_owned()).await;
    drop(wallet);

    assert_eq!(kind(changed), WalletErrorKind::SecretStore);
    assert!(store.get(VAULT_NEXT_KEY).is_some());
    assert_eq!(
        passwords_after_restart(&fixture, &store).await,
        (true, true)
    );
}

/// A stop after the new vault replaced the old one, before the pending copy was deleted.
#[tokio::test]
async fn a_stop_between_replacing_the_vault_and_cleaning_up_keeps_the_new_password() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    store.cut_after(4);

    // The change is in place; only the cleanup did not happen.
    wallet
        .change_password(OLD.to_owned(), NEW.to_owned())
        .await
        .unwrap();
    drop(wallet);

    assert_eq!(store.get(VAULT_NEXT_KEY), store.get(VAULT_KEY));
    assert_eq!(
        passwords_after_restart(&fixture, &store).await,
        (false, true)
    );
}

/// Every point a stop can fall on leaves a wallet that opens, with the new password once the
/// change returned success.
#[tokio::test]
async fn a_stop_at_any_step_leaves_a_wallet_that_opens() {
    for mutations in 0..=6 {
        let fixture = Fixture::new();
        let store = FaultyStore::default();
        let wallet = create(&fixture, &store.app_store()).await;
        store.cut_after(mutations);

        let changed = wallet.change_password(OLD.to_owned(), NEW.to_owned()).await;
        drop(wallet);

        let (old, new) = passwords_after_restart(&fixture, &store).await;
        assert!(
            old || new,
            "after {mutations} writes neither password opens"
        );
        if changed.is_ok() {
            assert!(new && !old, "after {mutations} writes");
        }
    }
}

#[tokio::test]
async fn a_full_store_keeps_the_old_password() {
    for full in [VAULT_NEXT_KEY, VAULT_KEY] {
        let fixture = Fixture::new();
        let store = FaultyStore::default();
        let wallet = create(&fixture, &store.app_store()).await;
        let vault = store.get(VAULT_KEY);
        store.fill_for(full);

        let changed = wallet.change_password(OLD.to_owned(), NEW.to_owned()).await;

        assert_eq!(kind(changed), WalletErrorKind::SecretStore, "{full}");
        assert!(wallet.mnemonic(OLD.to_owned()).await.is_ok(), "{full}");
        drop(wallet);
        assert_eq!(store.get(VAULT_KEY), vault, "{full}");
        assert_eq!(store.get(VAULT_NEXT_KEY), None, "{full}");
        assert_eq!(
            passwords_after_restart(&fixture, &store).await,
            (true, false),
            "{full}"
        );
    }
}

/// A store that loses a write and returns an older value must not have its vault replaced.
#[tokio::test]
async fn a_store_that_does_not_keep_the_new_vault_keeps_the_old_password() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let app_store = {
        let inner = store.clone();
        let read = store.clone();
        AppSecretStore::new(
            move |key| {
                // Reads the pending vault back as the stored one.
                let key = if key == VAULT_NEXT_KEY {
                    VAULT_KEY.to_owned()
                } else {
                    key
                };
                let value = read.get(&key);
                Box::pin(async move { SecretReply { ok: true, value } })
            },
            {
                let inner = inner.clone();
                move |key, value| {
                    inner.values.lock().unwrap().insert(key, value);
                    Box::pin(async {
                        SecretReply {
                            ok: true,
                            value: None,
                        }
                    })
                }
            },
            move |key| {
                inner.values.lock().unwrap().remove(&key);
                Box::pin(async {
                    SecretReply {
                        ok: true,
                        value: None,
                    }
                })
            },
        )
        .unwrap()
    };
    let wallet = create(&fixture, &app_store).await;
    let vault = store.get(VAULT_KEY);

    let changed = wallet.change_password(OLD.to_owned(), NEW.to_owned()).await;

    assert_eq!(kind(changed), WalletErrorKind::SecretStore);
    assert_eq!(store.get(VAULT_KEY), vault);
    assert_eq!(store.get(VAULT_NEXT_KEY), None);
}

#[tokio::test]
async fn delete_wallet_removes_an_unfinished_password_change() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    store.cut_after(3);
    let changed = wallet.change_password(OLD.to_owned(), NEW.to_owned()).await;
    assert!(changed.is_err());
    drop(wallet);
    let store = store.after_restart();
    assert!(store.get(VAULT_NEXT_KEY).is_some());

    delete_wallet(&fixture.runtime, fixture.config(), &store.app_store())
        .await
        .unwrap();

    assert_eq!(store.get(VAULT_KEY), None);
    assert_eq!(store.get(VAULT_NEXT_KEY), None);
}

/// A valid phrase of no wallet in these tests.
const OTHER_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";

async fn reset(fixture: &Fixture, store: &FaultyStore, phrase: &str) -> Result<(), WalletError> {
    reset_password(
        &fixture.runtime,
        fixture.config(),
        &store.app_store(),
        phrase.to_owned(),
        NEW.to_owned(),
    )
    .await
}

/// A wallet created with `OLD` whose 10 EPIC a scan found, closed again; with its phrase.
async fn funded(fixture: &Fixture, store: &FaultyStore) -> String {
    let wallet = create(fixture, &store.app_store()).await;
    let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();
    fixture
        .chain
        .fund(phrase.clone(), Chain::Floonet, 10 * EPIC, 0)
        .unwrap();
    fixture.chain.set_height(20);
    wallet.session().scan_to_tip().await;
    assert_eq!(wallet.transactions().await.unwrap().len(), 1);
    phrase
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_with_the_phrase_opens_with_the_new_password_and_keeps_the_history() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let phrase = funded(&fixture, &store).await;
    store
        .app_store()
        .write(FAILURES_KEY, "5".to_owned())
        .await
        .unwrap();

    // Typed as a user may type it.
    reset(&fixture, &store, &format!("  {}\n", phrase.to_uppercase()))
        .await
        .unwrap();

    assert_eq!(store.get(VAULT_NEXT_KEY), None);
    assert_eq!(store.get(FAILURES_KEY), None);
    assert!(!opens(&fixture, &store, OLD).await);
    let wallet = EpicWallet::open(
        &fixture.runtime,
        fixture.config(),
        &store.app_store(),
        NEW.to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(wallet.mnemonic(NEW.to_owned()).await.unwrap(), phrase);
    assert_eq!(wallet.transactions().await.unwrap().len(), 1);
    let outputs = wallet.outputs().await.unwrap();
    assert_eq!(
        outputs
            .iter()
            .map(|output| output.value)
            .collect::<Vec<_>>(),
        [10 * EPIC]
    );
    assert!(!wallet.restore_scan_required().await.unwrap());
}

#[tokio::test]
async fn a_reset_with_another_or_an_invalid_phrase_changes_nothing() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    drop(create(&fixture, &store.app_store()).await);
    let vault = store.get(VAULT_KEY);

    assert_eq!(
        kind(reset(&fixture, &store, OTHER_PHRASE).await),
        WalletErrorKind::PhraseMismatch
    );
    assert_eq!(
        kind(reset(&fixture, &store, "abandon abandon").await),
        WalletErrorKind::InvalidMnemonic
    );

    assert_eq!(store.get(VAULT_KEY), vault);
    assert_eq!(store.get(VAULT_NEXT_KEY), None);
    assert!(opens(&fixture, &store, OLD).await);
}

#[tokio::test]
async fn a_reset_is_refused_while_the_wallet_is_open() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();
    let vault = store.get(VAULT_KEY);

    let busy = reset(&fixture, &store, &phrase).await;

    assert_eq!(kind(busy), WalletErrorKind::WalletBusy);
    assert_eq!(store.get(VAULT_KEY), vault);
    drop(wallet);
    assert!(opens(&fixture, &store, OLD).await);
}

#[tokio::test]
async fn a_reset_without_a_wallet_database_is_refused_and_writes_nothing() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();

    let refused = reset(&fixture, &store, OTHER_PHRASE).await;

    assert_eq!(kind(refused), WalletErrorKind::WalletNotFound);
    assert_eq!(store.get(VAULT_KEY), None);
    assert!(
        !fixture
            .dir
            .path()
            .join(lepic_wallet::ENCRYPTED_DATABASE_FILE)
            .exists()
    );
}

#[tokio::test]
async fn a_reset_turns_a_pin_wallet_into_one_opened_by_the_new_password() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let created = fixture.create_with_pin(&store.app_store(), PIN).await;
    let phrase = created
        .wallet
        .mnemonic_with_pin(PIN.to_owned(), created.sealed_password.clone())
        .await
        .unwrap();
    let sealed = created.sealed_password.clone();
    drop(created);

    reset(&fixture, &store, &phrase).await.unwrap();

    for key in [PIN_KEY, PENDING_KEY, FAILURES_KEY] {
        assert_eq!(store.get(key), None, "{key}");
    }
    assert!(opens(&fixture, &store, NEW).await);
    let by_pin = fixture
        .open_with_pin(&store.app_store(), PIN, &sealed)
        .await;
    assert_eq!(kind(by_pin), WalletErrorKind::SecretStore);
}

/// Every point a stop can fall on leaves a wallet that opens, with the new password once the
/// reset returned success, and a second reset finishes one that stopped.
#[tokio::test]
async fn a_stop_at_any_step_of_a_reset_leaves_a_wallet_that_opens() {
    for mutations in 0..=6 {
        let fixture = Fixture::new();
        let store = FaultyStore::default();
        let wallet = create(&fixture, &store.app_store()).await;
        let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();
        drop(wallet);
        store.cut_after(mutations);

        let reset_result = reset(&fixture, &store, &phrase).await;

        let (old, new) = passwords_after_restart(&fixture, &store).await;
        assert!(
            old || new,
            "after {mutations} writes neither password opens"
        );
        if reset_result.is_ok() {
            assert!(new && !old, "after {mutations} writes");
        }
        let again = store.after_restart();
        reset(&fixture, &again, &phrase).await.unwrap();
        assert!(
            opens(&fixture, &again, NEW).await,
            "after {mutations} writes"
        );
        assert!(
            !opens(&fixture, &again, OLD).await,
            "after {mutations} writes"
        );
    }
}

/// The wallet database of `fixture`, opened as another program with the data folder and the
/// recovery phrase would.
fn database(fixture: &Fixture, phrase: &str) -> lepic_store::SqliteStore {
    let seed = lepic_keychain::Seed::from_mnemonic(phrase).unwrap();
    lepic_store::SqliteStore::open(
        &fixture
            .dir
            .path()
            .join(lepic_wallet::ENCRYPTED_DATABASE_FILE),
        lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
        lepic_store::AtRest::Encrypted(&lepic_wallet::store_key(&seed).unwrap()),
    )
    .unwrap()
}

const SEED_CHECK: &str = "wallet.seed_check";

fn seed_check(fixture: &Fixture, phrase: &str) -> Option<String> {
    database(fixture, phrase)
        .read(|repos| repos.setting(SEED_CHECK))
        .unwrap()
}

/// The database as a version before the seed check left it.
fn drop_seed_check(fixture: &Fixture, phrase: &str) {
    database(fixture, phrase)
        .write(|repos| repos.delete_setting(SEED_CHECK))
        .unwrap();
}

/// A phrase of another seed with the wallet's 32-bit fingerprint can be found by grinding;
/// planting the other phrase's fingerprint stands in for one. The seed check refuses it.
#[tokio::test]
async fn a_reset_with_a_phrase_whose_fingerprint_collides_is_refused() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();
    drop(wallet);
    let vault = store.get(VAULT_KEY);
    let colliding = wallet_fingerprint(OTHER_PHRASE.to_owned(), Chain::Floonet).unwrap();
    database(&fixture, &phrase)
        .write(|repos| repos.put_setting("wallet.fingerprint", &colliding))
        .unwrap();

    let refused = reset(&fixture, &store, OTHER_PHRASE).await;

    assert_eq!(kind(refused), WalletErrorKind::PhraseMismatch);
    assert_eq!(store.get(VAULT_KEY), vault);
}

/// A database no open of this version has seen holds no seed check: one of its outputs proves
/// the phrase, the seed check is stored, and the reset needs no node settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_of_a_database_without_a_seed_check_is_proven_by_an_output() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let phrase = funded(&fixture, &store).await;
    let check = seed_check(&fixture, &phrase).unwrap();
    drop_seed_check(&fixture, &phrase);
    let mut config = fixture.config();
    config.node_url = "not a node url".to_owned();

    reset_password(
        &fixture.runtime,
        config,
        &store.app_store(),
        phrase.clone(),
        NEW.to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(seed_check(&fixture, &phrase), Some(check));
    assert!(opens(&fixture, &store, NEW).await);
}

#[tokio::test]
async fn a_reset_of_a_database_with_nothing_to_prove_the_phrase_is_refused() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();
    drop(wallet);
    drop_seed_check(&fixture, &phrase);
    let vault = store.get(VAULT_KEY);

    let refused = reset(&fixture, &store, &phrase).await;

    assert_eq!(kind(refused), WalletErrorKind::WalletNotFound);
    assert_eq!(store.get(VAULT_KEY), vault);
    assert_eq!(seed_check(&fixture, &phrase), None);
}

/// Unlike an open, the reset leaves a damaged database where it is, so a retry reports the
/// same.
#[tokio::test]
async fn a_reset_of_a_damaged_database_leaves_it_in_place() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;
    let phrase = wallet.mnemonic(OLD.to_owned()).await.unwrap();
    drop(wallet);
    let path = fixture
        .dir
        .path()
        .join(lepic_wallet::ENCRYPTED_DATABASE_FILE);
    std::fs::write(&path, [0x5a; 8192]).unwrap();
    let vault = store.get(VAULT_KEY);

    for _ in 0..2 {
        let damaged = reset(&fixture, &store, &phrase).await;
        assert_eq!(kind(damaged), WalletErrorKind::DamagedDatabase);
    }

    assert_eq!(std::fs::read(&path).unwrap(), [0x5a; 8192]);
    assert_eq!(store.get(VAULT_KEY), vault);
}
