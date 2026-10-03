//! Binding behaviour that needs a runtime, a wallet directory and the app's store, driven
//! through the API the app calls.

use crate::api::diagnostics::LogLevel;
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, WalletConfig};
use crate::api::wallet::{EpicWallet, PinWallet, delete_wallet};
use crate::vault_port::VAULT_KEY;

const PIN: &str = "4711";

/// Store keys next to `lepic.vault`; apps may see them in their store.
const PIN_KEY: &str = "lepic.pin-key";
const FAILURES_KEY: &str = "lepic.pin-failures";

struct Fixture {
    runtime: LepicRuntime,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let runtime = chain.runtime(LogLevel::Warn).unwrap();
        Self {
            runtime,
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn config(&self) -> WalletConfig {
        WalletConfig {
            data_dir: self.dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: String::new(),
            epicbox_port: 443,
        }
    }

    async fn create_with_pin(&self, store: &AppSecretStore, pin: &str) -> PinWallet {
        EpicWallet::create_with_pin(&self.runtime, self.config(), store, None, pin.to_owned())
            .await
            .unwrap()
    }

    async fn open_with_pin(
        &self,
        store: &AppSecretStore,
        pin: &str,
        sealed: &str,
    ) -> Result<EpicWallet, WalletError> {
        EpicWallet::open_with_pin(
            &self.runtime,
            self.config(),
            store,
            pin.to_owned(),
            sealed.to_owned(),
        )
        .await
    }
}

fn kind<T>(result: Result<T, WalletError>) -> WalletErrorKind {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error.kind,
    }
}

#[tokio::test]
async fn create_with_pin_rejects_a_short_pin() {
    let fixture = Fixture::new();
    for pin in ["", "1", "123"] {
        let store = AppSecretStore::in_memory();
        let created = EpicWallet::create_with_pin(
            &fixture.runtime,
            fixture.config(),
            &store,
            None,
            pin.to_owned(),
        )
        .await;
        assert_eq!(kind(created), WalletErrorKind::InvalidArgument, "{pin:?}");
        assert_eq!(store.read(VAULT_KEY).await.unwrap(), None, "{pin:?}");
    }
}

/// The sealed text and the vault together, as in a copied backup, do not open the wallet
/// without the key LEPIC keeps in the app's store.
#[tokio::test]
async fn pin_unlock_needs_the_key_in_the_app_store() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    drop(created);

    let copy = AppSecretStore::in_memory();
    let vault = store.read(VAULT_KEY).await.unwrap().unwrap();
    copy.write(VAULT_KEY, vault).await.unwrap();
    assert!(fixture.open_with_pin(&copy, PIN, &sealed).await.is_err());

    assert!(fixture.open_with_pin(&store, PIN, &sealed).await.is_ok());
}

#[tokio::test]
async fn wrong_pins_are_counted_in_the_app_store_until_one_is_right() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let wrong = created
        .wallet
        .mnemonic_with_pin("0000".to_owned(), sealed.clone())
        .await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    drop(created);
    let wrong = fixture.open_with_pin(&store, "0000", &sealed).await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("2")
    );

    // Damaged text tests no PIN, so it does not count.
    let damaged = fixture.open_with_pin(&store, PIN, "damaged").await;
    assert_eq!(kind(damaged), WalletErrorKind::InvalidArgument);
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("2")
    );

    assert!(fixture.open_with_pin(&store, PIN, &sealed).await.is_ok());
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);
}

#[tokio::test]
async fn delete_wallet_removes_the_pin_entries() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    drop(created);
    let wrong = fixture.open_with_pin(&store, "0000", &sealed).await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);

    delete_wallet(&fixture.runtime, fixture.config(), &store)
        .await
        .unwrap();
    for key in [VAULT_KEY, PIN_KEY, FAILURES_KEY] {
        assert_eq!(store.read(key).await.unwrap(), None, "{key}");
    }
}
