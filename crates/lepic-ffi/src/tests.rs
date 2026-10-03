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
    chain: MockChain,
    runtime: LepicRuntime,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let runtime = chain.runtime(LogLevel::Warn).unwrap();
        Self {
            chain,
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

#[tokio::test]
async fn a_locked_wallet_refuses_every_call_until_it_is_opened_again() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let wallet = created.wallet;
    assert!(wallet.summary(true).await.is_ok());

    wallet.lock();
    wallet.lock();
    assert_eq!(kind(wallet.summary(false).await), WalletErrorKind::Locked);
    assert_eq!(kind(wallet.summary(true).await), WalletErrorKind::Locked);
    assert_eq!(
        kind(wallet.create_send_slate(1, 1).await),
        WalletErrorKind::Locked
    );
    let phrase = wallet.mnemonic_with_pin(PIN.to_owned(), sealed.clone());
    assert_eq!(kind(phrase.await), WalletErrorKind::Locked);
    // Refused before the PIN was tried, so it costs no attempt.
    let phrase = wallet.mnemonic_with_pin("0000".to_owned(), sealed.clone());
    assert_eq!(kind(phrase.await), WalletErrorKind::Locked);
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);

    drop(wallet);
    let reopened = fixture.open_with_pin(&store, PIN, &sealed).await.unwrap();
    assert!(reopened.summary(true).await.is_ok());
}

#[tokio::test]
async fn slate_text_above_the_wire_limit_is_refused_before_it_is_written() {
    let fixture = Fixture::new();
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &AppSecretStore::in_memory(),
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let text = " ".repeat(8 * 1024 * 1024 + 1);
    assert_eq!(
        kind(wallet.receive_slate(text.clone()).await),
        WalletErrorKind::InvalidSlate
    );
    assert_eq!(
        kind(wallet.finalize_and_post(text).await),
        WalletErrorKind::InvalidSlate
    );
}

#[tokio::test]
async fn create_with_pin_keeps_the_key_of_a_wallet_in_the_store() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    drop(created);
    let key = store.read(PIN_KEY).await.unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let config = WalletConfig {
        data_dir: other_dir.path().to_string_lossy().into_owned(),
        ..fixture.config()
    };
    let again =
        EpicWallet::create_with_pin(&fixture.runtime, config, &store, None, "9876".to_owned());
    assert_eq!(kind(again.await), WalletErrorKind::WalletAlreadyExists);
    assert_eq!(store.read(PIN_KEY).await.unwrap(), key);
    assert!(fixture.open_with_pin(&store, PIN, &sealed).await.is_ok());
}

/// A second runtime in the same process stands in for a second process.
#[tokio::test]
async fn a_second_runtime_cannot_open_a_directory_in_use() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;

    let other = fixture.chain.runtime(LogLevel::Warn).unwrap();
    let opened = EpicWallet::open_with_pin(
        &other,
        fixture.config(),
        &store,
        PIN.to_owned(),
        created.sealed_password.clone(),
    )
    .await;
    assert_eq!(kind(opened), WalletErrorKind::WalletBusy);
    // A busy directory is refused before the PIN is tried, so it costs no attempt.
    let opened = EpicWallet::open_with_pin(
        &other,
        fixture.config(),
        &store,
        "0000".to_owned(),
        created.sealed_password.clone(),
    )
    .await;
    assert_eq!(kind(opened), WalletErrorKind::WalletBusy);
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);

    let sealed = created.sealed_password.clone();
    drop(created);
    let opened =
        EpicWallet::open_with_pin(&other, fixture.config(), &store, PIN.to_owned(), sealed);
    assert!(opened.await.is_ok());
}

#[test]
fn normalized_phrase_is_built_in_one_buffer() {
    let typed = "  Abandon\tABANDON\n  art ";
    let normalized = crate::session::normalize_phrase(typed);
    assert_eq!(normalized.as_str(), "abandon abandon art");
    // The buffer was never reallocated, which would leave an unwiped copy behind.
    assert_eq!(normalized.capacity(), typed.len() * 2);
}

#[test]
fn the_node_api_secret_is_taken_out_of_the_config_before_the_client_is_built() {
    let fixture = Fixture::new();
    let mut config = WalletConfig {
        node_api_secret: Some("node-secret".to_owned()),
        ..fixture.config()
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    assert_eq!(config.node_api_secret, None);
    crate::node::NodeFactory::Http
        .client(&config, &secret)
        .unwrap();
}

/// flutter_rust_bridge hands the payload of a panic in a synchronous function to Dart, so each
/// one runs its body through `boundary::guard` or `boundary::guard_or`.
#[test]
fn every_synchronous_api_function_runs_under_the_panic_guard() {
    let sources = [
        ("diagnostics.rs", include_str!("api/diagnostics.rs")),
        ("error.rs", include_str!("api/error.rs")),
        ("runtime.rs", include_str!("api/runtime.rs")),
        ("secret_store.rs", include_str!("api/secret_store.rs")),
        ("testing.rs", include_str!("api/testing.rs")),
        ("types.rs", include_str!("api/types.rs")),
        ("wallet.rs", include_str!("api/wallet.rs")),
    ];
    let mut unguarded = Vec::new();
    for (file, source) in sources {
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let signature = line.trim_start();
            // `pub async fn` runs through `Boundary::run`; `pub const fn` cannot unwind.
            if !signature.starts_with("pub fn ")
                || index > 0 && lines[index - 1].contains("#[frb(ignore)]")
            {
                continue;
            }
            let close = format!("{}}}", &line[..line.len() - signature.len()]);
            let guarded = lines[index..]
                .iter()
                .take_while(|line| **line != close)
                .any(|line| line.contains("guard"));
            if !guarded {
                unguarded.push(format!("{file}: {signature}"));
            }
        }
    }
    assert!(unguarded.is_empty(), "{unguarded:#?}");
}

#[test]
fn a_panic_in_a_call_without_an_error_gives_its_fallback() {
    #[allow(clippy::panic)]
    let answered = crate::boundary::guard_or("test", false, || panic!("inside lepic"));
    assert!(!answered);
}

struct CapturedLogs(std::sync::Mutex<Vec<lepic_telemetry::LogRecord>>);

impl lepic_telemetry::LogSink for CapturedLogs {
    fn record(&self, record: lepic_telemetry::LogRecord) {
        self.0.lock().unwrap().push(record);
    }
}

#[test]
fn app_log_messages_reach_the_stream_cut_to_1024_bytes() {
    let mut runtime = Fixture::new().runtime;
    let logs = std::sync::Arc::new(CapturedLogs(std::sync::Mutex::default()));
    let filter = lepic_telemetry::LogFilter::parse("trace").unwrap();
    std::sync::Arc::get_mut(&mut runtime.inner)
        .unwrap()
        .boundary
        .dispatch = lepic_telemetry::host_dispatch(logs.clone(), filter);

    runtime.log_message(LogLevel::Info, "app".to_owned(), "x".repeat(4096));
    let records = logs.0.lock().unwrap();
    let record = records
        .iter()
        .find(|record| record.target == "dart")
        .unwrap();
    assert_eq!(record.message.len(), 1024);
}
