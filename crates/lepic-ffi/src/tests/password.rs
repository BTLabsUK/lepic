//! Changing a wallet's password, also when the app stops or its store fails part way.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::{FAILURES_KEY, Fixture, PIN, kind};
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::{AppSecretStore, SecretReply};
use crate::api::wallet::{EpicWallet, delete_wallet};
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
async fn a_short_new_password_is_refused_before_the_attempt_is_counted() {
    let fixture = Fixture::new();
    let store = FaultyStore::default();
    let wallet = create(&fixture, &store.app_store()).await;

    let changed = wallet
        .change_password(OLD.to_owned(), "short".to_owned())
        .await;

    assert_eq!(kind(changed), WalletErrorKind::InvalidArgument);
    assert_eq!(store.get(FAILURES_KEY), None);
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
