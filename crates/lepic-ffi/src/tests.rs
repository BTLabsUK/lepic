// SPDX-License-Identifier: Apache-2.0
//! Binding behaviour that needs a runtime, a wallet directory and the app's store, driven
//! through the API the app calls.

use crate::api::at_rest::StoreAtRestState;
use crate::api::diagnostics::LogLevel;
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, WalletConfig};
use crate::api::wallet::{EpicWallet, PinWallet, delete_wallet, wallet_fingerprint};
use crate::session::SeedOrigin;
use crate::vault_port::VAULT_KEY;

mod address_signature;
mod contact;
mod http;
mod invoice;
mod listener;
mod live_restore;
#[cfg(feature = "tor")]
mod live_send_http_tor;
mod node;
mod offline;
mod outputs;
mod password;
mod resend;
mod scan;
mod selection;
mod self_send;
mod servers;
#[cfg(target_os = "linux")]
mod soak;
#[cfg(unix)]
#[cfg(feature = "tor")]
mod tor;

const PIN: &str = "471100";

/// Store keys next to `lepic.vault`; apps may see them in their store.
const PIN_KEY: &str = "lepic.pin-key";
const PENDING_KEY: &str = "lepic.pin-key-pending";
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
            onion_routes: Vec::new(),
            tuning: crate::tuning::shipped(),
            offline: false,
            tor_wanted: false,
            host_features: 0,
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
    for pin in ["", "1", "123", "12345"] {
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
        .mnemonic_with_pin("000000".to_owned(), sealed.clone())
        .await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    drop(created);
    let wrong = fixture.open_with_pin(&store, "000000", &sealed).await;
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

/// A PIN asked again before an action is counted like any other attempt and changes neither
/// the sealed text nor the PIN key.
#[tokio::test]
async fn check_pin_counts_attempts_and_keeps_the_key() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let wallet = created.wallet;
    let key = store.read(PIN_KEY).await.unwrap();

    let wrong = wallet.check_pin("000000".to_owned(), sealed.clone()).await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("1")
    );

    wallet
        .check_pin(PIN.to_owned(), sealed.clone())
        .await
        .unwrap();
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);
    assert_eq!(store.read(PIN_KEY).await.unwrap(), key);
    assert_eq!(store.read(PENDING_KEY).await.unwrap(), None);

    drop(wallet);
    assert!(fixture.open_with_pin(&store, PIN, &sealed).await.is_ok());
}

#[tokio::test]
async fn delete_wallet_removes_the_pin_entries() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let pending = created
        .wallet
        .change_pin(sealed.clone(), PIN.to_owned(), "246802".to_owned())
        .await;
    assert!(pending.is_ok());
    drop(created);
    let wrong = fixture.open_with_pin(&store, "000000", &sealed).await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);

    delete_wallet(&fixture.runtime, fixture.config(), &store)
        .await
        .unwrap();
    for key in [VAULT_KEY, PIN_KEY, PENDING_KEY, FAILURES_KEY] {
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
        kind(wallet.create_send_slate(1, 1, None, None).await),
        WalletErrorKind::Locked
    );
    let phrase = wallet.mnemonic_with_pin(PIN.to_owned(), sealed.clone());
    assert_eq!(kind(phrase.await), WalletErrorKind::Locked);
    // Refused before the PIN was tried, so it costs no attempt.
    let phrase = wallet.mnemonic_with_pin("000000".to_owned(), sealed.clone());
    assert_eq!(kind(phrase.await), WalletErrorKind::Locked);
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);
    assert_eq!(
        kind(wallet.confirm_pin_change(sealed.clone()).await),
        WalletErrorKind::Locked
    );

    drop(wallet);
    let reopened = fixture.open_with_pin(&store, PIN, &sealed).await.unwrap();
    assert!(reopened.summary(true).await.is_ok());
}

/// The app locks on going to the background and opens anew on coming back, with a sync that
/// may still be waiting on a node that does not answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_then_open_at_once_never_gets_wallet_busy() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let wallet = created.wallet;
    fixture.chain.set_node_stalled(true);
    let syncing = tokio::spawn({
        let handle = EpicWallet::of_session(std::sync::Arc::clone(wallet.session()));
        async move { handle.summary(true).await }
    });
    assert!(eventually(|| fixture.chain.stalled_node_calls() >= 1).await);
    assert_eq!(wallet.session().in_flight.len(), 1);

    wallet.lock();
    drop(wallet);
    let reopened = fixture.open_with_pin(&store, PIN, &sealed).await;

    assert!(reopened.is_ok(), "{:?}", reopened.err());
    let synced = tokio::time::timeout(std::time::Duration::from_secs(5), syncing)
        .await
        .expect("the stalled sync ended at the lock")
        .unwrap();
    assert_eq!(kind(synced), WalletErrorKind::Cancelled);
    fixture.chain.set_node_stalled(false);
}

/// A lock releases the directory without a dispose of the handle first; the handle itself
/// keeps refusing every call with `Locked`.
#[tokio::test]
async fn a_locked_handle_no_longer_holds_its_directory() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let wallet = created.wallet;
    assert!(wallet.session().holds_directory());

    wallet.lock();

    assert!(!wallet.session().holds_directory());
    let reopened = fixture
        .open_with_pin(&store, PIN, &created.sealed_password)
        .await
        .unwrap();
    assert!(reopened.summary(false).await.is_ok());
    assert_eq!(kind(wallet.summary(false).await), WalletErrorKind::Locked);
    assert_eq!(wallet.session().in_flight.len(), 0);
}

/// Without the stored reference the client would take any first tip of the session as its
/// reference.
#[tokio::test]
async fn an_opened_wallet_bounds_the_first_node_tip_by_the_tip_it_confirmed() {
    use lepic_node::{NodeApi as _, NodeError};

    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let password = || zeroize::Zeroizing::new("password".to_owned());
    let secret = || {
        let mut config = fixture.config();
        crate::node::NodeSecret::take(&mut config)
    };
    fixture.chain.set_height(20);
    {
        let session = crate::session::Session::new(
            &fixture.runtime.inner,
            &fixture.config(),
            &secret(),
            store.clone(),
        )
        .await
        .unwrap();
        session
            .create(SeedOrigin::Generate, password())
            .await
            .unwrap();
        // The first tip is confirmed by a second agreeing refresh.
        session.refresh().await.unwrap();
        session.refresh().await.unwrap();
    }

    let session =
        crate::session::Session::new(&fixture.runtime.inner, &fixture.config(), &secret(), store)
            .await
            .unwrap();
    session.open(password()).await.unwrap();
    fixture.chain.set_height(20 + 100_000);
    assert!(matches!(
        session.node().get_tip().await,
        Err(NodeError::ImplausibleTip { .. })
    ));
}

#[test]
fn an_implausible_node_answer_reaches_the_app_as_a_node_error() {
    let error = lepic_wallet::WalletError::Implausible(
        lepic_wallet::chain::ImplausibleNodeData::TipChanged {
            first: lepic_primitives::amount::Height::new(1),
            second: lepic_primitives::amount::Height::new(9),
        },
    );
    assert_eq!(
        WalletError::from(error).kind,
        WalletErrorKind::NodeUnreachable
    );
}

/// Polls `done` every 10 ms for up to five seconds.
async fn eventually(done: impl Fn() -> bool) -> bool {
    for _ in 0..500 {
        if done() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    done()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_stops_the_listener_and_closes_its_relay_connection() {
    let relay = lepic_epicbox::mock_relay::MockRelay::new(lepic_epicbox::Network::Floonet);
    let mut fixture = Fixture::new();
    std::sync::Arc::get_mut(&mut fixture.runtime.inner)
        .unwrap()
        .relay = Some(relay.connector());
    let mut config = WalletConfig {
        epicbox_domain: "epicbox.example".to_owned(),
        ..fixture.config()
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    let session = std::sync::Arc::new(
        crate::session::Session::new(
            &fixture.runtime.inner,
            &config,
            &secret,
            AppSecretStore::in_memory(),
        )
        .await
        .unwrap(),
    );
    session
        .create(
            SeedOrigin::Generate,
            zeroize::Zeroizing::new("password".to_owned()),
        )
        .await
        .unwrap();

    let handle = session.claim_listener().unwrap().unwrap();
    let listening = tokio::spawn({
        let session = std::sync::Arc::clone(&session);
        async move { session.listen(&handle, |_| {}).await }
    });
    assert!(eventually(|| relay.connections() == 1).await);
    assert!(session.listener_running());

    session.lock();
    assert!(!session.listener_running());
    assert!(eventually(|| relay.connections() == 0).await);
    tokio::time::timeout(std::time::Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
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
        EpicWallet::create_with_pin(&fixture.runtime, config, &store, None, "987654".to_owned());
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
        "000000".to_owned(),
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

/// The vault and the database answer it; the node is never asked.
#[tokio::test]
async fn summary_without_refresh_needs_no_node() {
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
    fixture.chain.set_node_unreachable(true);
    let summary = wallet.summary(false).await.unwrap();
    assert_eq!(summary.total, 0);
    assert!(!summary.validated_with_node);
    assert_eq!(
        kind(wallet.summary(true).await),
        WalletErrorKind::NodeUnreachable
    );
    assert_eq!(
        kind(wallet.estimate_fee(1, 1, None).await),
        WalletErrorKind::NodeUnreachable
    );
    assert!(wallet.transactions().await.unwrap().is_empty());
    assert_eq!(
        kind(wallet.transaction(1).await),
        WalletErrorKind::InvalidArgument
    );
}

/// As `validate_epicbox_address` refuses it: without `@<relay>` the engine would pick a relay
/// the user never named.
#[tokio::test]
async fn send_epicbox_refuses_an_address_without_its_relay() {
    let relay = lepic_epicbox::mock_relay::MockRelay::new(lepic_epicbox::Network::Floonet);
    let mut fixture = Fixture::new();
    std::sync::Arc::get_mut(&mut fixture.runtime.inner)
        .unwrap()
        .relay = Some(relay.connector());
    let config = WalletConfig {
        epicbox_domain: "epicbox.example".to_owned(),
        ..fixture.config()
    };
    let wallet = EpicWallet::create(
        &fixture.runtime,
        config,
        &AppSecretStore::in_memory(),
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let address = wallet.epicbox_address().await.unwrap();
    let key = address.split('@').next().unwrap().to_owned();
    for bare in [key.clone(), format!("epicbox://{key}")] {
        assert_eq!(
            kind(wallet.send_epicbox(1, 1, bare.clone(), None, None).await),
            WalletErrorKind::InvalidArgument,
            "{bare}"
        );
    }
    assert!(wallet.transactions().await.unwrap().is_empty());
    assert_eq!(relay.connections(), 0);
}

/// The options are checked before the address and before tor is asked, as every other send
/// checks them first.
#[cfg(feature = "tor")]
#[tokio::test]
async fn send_tor_takes_the_send_options_of_the_other_sends() {
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
    let too_many = crate::api::types::SendOptions {
        strategy: crate::api::types::SelectionStrategy::All,
        change_outputs: 11,
        exclude_outputs: Vec::new(),
    };

    let sent = wallet
        .send_tor(1, 1, "wallet.example.org".to_owned(), None, Some(too_many))
        .await;

    assert_eq!(kind(sent), WalletErrorKind::InvalidArgument);
    assert_eq!(
        kind(
            wallet
                .send_tor(1, 1, "wallet.example.org".to_owned(), None, None)
                .await
        ),
        WalletErrorKind::OnionAddressInvalid
    );
    assert!(wallet.transactions().await.unwrap().is_empty());
}

/// A build without Tor (ADR 0026) keeps every Tor call: those that need tor fail with
/// `Unsupported`, Tor reads as off and nothing goes over Tor.
#[cfg(not(feature = "tor"))]
#[tokio::test]
async fn a_build_without_tor_answers_every_tor_call_without_tor() {
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
    let onion = format!("{}.onion", "a".repeat(56));

    assert!(!crate::api::tor::validate_onion_address(onion.clone()));
    assert_eq!(
        kind(wallet.onion_address().await),
        WalletErrorKind::Unsupported
    );
    assert_eq!(
        kind(wallet.send_tor(1, 1, onion.clone(), None, None).await),
        WalletErrorKind::Unsupported
    );
    assert_eq!(
        kind(wallet.resend_tor(1, onion.clone()).await),
        WalletErrorKind::Unsupported
    );
    assert_eq!(
        kind(wallet.refresh_tor(true).await),
        WalletErrorKind::Unsupported
    );
    wallet.tor_network_lost().await.unwrap();
    wallet.expect_tor().unwrap();
    wallet.stop_tor();
    assert_eq!(
        wallet.tor_status().kind,
        crate::api::tor::TorStatusKind::Off
    );
    wallet.set_epicbox_over_tor(true);
    wallet.set_node_over_tor(true);
    assert!(!wallet.epicbox_over_tor());
    assert!(!wallet.node_over_tor());
    wallet.set_onion_routes(Vec::new()).unwrap();
    assert!(wallet.transactions().await.unwrap().is_empty());
}

#[test]
fn inspect_slate_refuses_text_that_is_no_slate() {
    use crate::api::wallet::inspect_slate;
    for text in ["", "not a slate", "{}", r#"{"version_info":{"version":4}}"#] {
        assert_eq!(
            kind(inspect_slate(text.to_owned(), Chain::Floonet)),
            WalletErrorKind::InvalidSlate,
            "{text}"
        );
    }
}

/// The slate JSON of a slate vector.
fn vector_slate(vector: &str) -> String {
    let vector: serde_json::Value = serde_json::from_str(vector).unwrap();
    vector["expected"]["json"].as_str().unwrap().to_owned()
}

#[test]
fn a_slate_read_from_its_qr_codes_inspects_as_the_text() {
    use crate::api::types::SlateStage;
    use crate::api::wallet::{decode_ur_slate, encode_ur_slate, inspect_slate};
    let json = vector_slate(include_str!(
        "../../../testdata/vectors/slates/send_file_plain_s1_file.json"
    ));
    let parts = encode_ur_slate(json.clone(), 200).unwrap();
    let partial = decode_ur_slate(parts[..3].to_vec()).unwrap();
    assert!(!partial.complete);
    assert_eq!((partial.received_fragments, partial.fragment_count), (3, 7));
    let progress = decode_ur_slate(parts).unwrap();
    assert!(progress.complete);
    assert_eq!(progress.received_fragments, 7);
    let decoded = progress.json.unwrap();
    assert_eq!(decoded, json);
    assert_eq!(
        inspect_slate(decoded, Chain::Floonet).unwrap().stage,
        SlateStage::S1
    );
}

#[test]
fn qr_code_refusals_have_their_own_kinds() {
    use crate::api::wallet::{decode_ur_slate, encode_ur_slate};
    let s1 = encode_ur_slate(r#"{"a":"1"}"#.to_owned(), 200).unwrap();
    let long = encode_ur_slate(format!("\"{}\"", "ab".repeat(300)), 16).unwrap();
    let cases = [
        (
            vec!["https://example.org".to_owned()],
            WalletErrorKind::NotUrCode,
        ),
        (
            vec!["UR:BYTES/AEAEAEAE".to_owned()],
            WalletErrorKind::ForeignUrCode,
        ),
        (
            vec![s1[0].clone(), long[0].clone()],
            WalletErrorKind::MixedUrCodes,
        ),
        (
            vec!["UR:EPIC-SLATE/AEAE".to_owned()],
            WalletErrorKind::InvalidUrCode,
        ),
        (vec![s1[0].clone(); 1025], WalletErrorKind::UrCodeTooLarge),
    ];
    for (parts, expected) in cases {
        assert_eq!(kind(decode_ur_slate(parts)), expected);
    }
    assert_eq!(
        kind(encode_ur_slate("slate".to_owned(), 200)),
        WalletErrorKind::InvalidSlate
    );
    assert_eq!(
        kind(encode_ur_slate("{}".to_owned(), 8)),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(encode_ur_slate(format!("\"{}\"", "a".repeat(70_000)), 200)),
        WalletErrorKind::UrCodeTooLarge
    );
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
        .client(
            (
                &config,
                &crate::tuning::Tuning::check(&config.tuning).unwrap(),
            ),
            &secret,
            &std::sync::Arc::new(crate::node::RelayTor::direct(
                true,
                std::time::Duration::from_secs(75),
            )),
            &std::sync::Arc::new(lepic_epicbox::tunnel::OnionRoutes::default()),
        )
        .unwrap();
}

/// flutter_rust_bridge hands the payload of a panic in a synchronous function to Dart, so each
/// one runs its body through `boundary::guard` or `boundary::guard_or`.
#[test]
fn every_synchronous_api_function_runs_under_the_panic_guard() {
    let sources = [
        ("diagnostics.rs", include_str!("api/diagnostics.rs")),
        ("error.rs", include_str!("api/error.rs")),
        ("http.rs", include_str!("api/http.rs")),
        ("runtime.rs", include_str!("api/runtime.rs")),
        ("secret_store.rs", include_str!("api/secret_store.rs")),
        ("testing.rs", include_str!("api/testing.rs")),
        ("tor.rs", include_str!("api/tor.rs")),
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
    let answered = crate::boundary::guard_or("test", false, || panic!("inside lepic"));
    assert!(!answered);
}

/// The crate docs and ADR 0014 tell app developers what LEPIC keeps in their store.
#[test]
fn the_docs_name_every_key_lepic_writes_to_the_app_store() {
    let readme = include_str!("lib.rs");
    let adr = include_str!("../../../docs/adr/0014-secrets-at-the-flutter-boundary.md");
    for key in [
        VAULT_KEY,
        crate::vault_port::VAULT_NEXT_KEY,
        crate::pin::KEY_KEY,
        crate::pin::PENDING_KEY_KEY,
        crate::pin::FAILURES_KEY,
    ] {
        assert!(readme.contains(&format!("`{key}`")), "{key}");
    }
    assert!(adr.contains(&format!("`{}`", crate::pin::KEY_KEY)));
    assert!(adr.contains("node API secret"));
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

/// Golden vector `keys/wallet_seed_seed32`: a `wallet.seed` written by `epic-wallet`.
const WALLET_SEED_VECTOR: &str =
    include_str!("../../../testdata/vectors/keys/wallet_seed_seed32.json");

fn wallet_seed_vector() -> (String, String, String, String) {
    let vector: serde_json::Value = serde_json::from_str(WALLET_SEED_VECTOR).unwrap();
    let text = |pointer: &str| {
        vector
            .pointer(pointer)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    };
    (
        text("/expected/file"),
        text("/inputs/password"),
        text("/inputs/wrong_password"),
        text("/inputs/mnemonic"),
    )
}

#[tokio::test]
async fn an_imported_wallet_seed_gives_the_wallet_of_its_phrase() {
    let fixture = Fixture::new();
    let (file, file_password, wrong_password, phrase) = wallet_seed_vector();
    let store = AppSecretStore::in_memory();
    let wrong = EpicWallet::import_wallet_seed(
        &fixture.runtime,
        fixture.config(),
        &store,
        file.clone(),
        wrong_password,
        "password".to_owned(),
    )
    .await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    assert_eq!(store.read(VAULT_KEY).await.unwrap(), None);

    let wallet = EpicWallet::import_wallet_seed(
        &fixture.runtime,
        fixture.config(),
        &store,
        file,
        file_password,
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(
        wallet.mnemonic("password".to_owned()).await.unwrap(),
        phrase
    );
}

/// One fingerprint for "the same wallet": what an open wallet's database stores equals what
/// the phrase alone gives, for a created, a restored and an imported wallet.
#[tokio::test]
async fn the_fingerprint_of_a_phrase_is_the_one_its_wallet_stores() {
    let created = Fixture::new();
    let store = AppSecretStore::in_memory();
    let wallet = EpicWallet::create(
        &created.runtime,
        created.config(),
        &store,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let phrase = wallet.mnemonic("password".to_owned()).await.unwrap();
    let fingerprint = wallet.fingerprint().await.unwrap();
    assert_eq!(
        wallet_fingerprint(format!(" {} ", phrase.to_uppercase()), Chain::Floonet).unwrap(),
        fingerprint
    );

    let restored = Fixture::new();
    let wallet = EpicWallet::create(
        &restored.runtime,
        restored.config(),
        &AppSecretStore::in_memory(),
        Some(phrase),
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(wallet.fingerprint().await.unwrap(), fingerprint);

    let imported = Fixture::new();
    let (file, file_password, _, vector_phrase) = wallet_seed_vector();
    let wallet = EpicWallet::import_wallet_seed(
        &imported.runtime,
        imported.config(),
        &AppSecretStore::in_memory(),
        file,
        file_password,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let vector_fingerprint = wallet.fingerprint().await.unwrap();
    assert_eq!(
        wallet_fingerprint(vector_phrase, Chain::Floonet).unwrap(),
        vector_fingerprint
    );
    assert_ne!(vector_fingerprint, fingerprint);
    assert_eq!(
        kind(wallet_fingerprint(
            "abandon abandon".to_owned(),
            Chain::Floonet
        )),
        WalletErrorKind::InvalidMnemonic
    );
}

#[tokio::test]
async fn import_of_text_that_is_no_wallet_seed_is_an_invalid_argument() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    for text in ["{}".to_owned(), " ".repeat(4097)] {
        let imported = EpicWallet::import_wallet_seed_with_pin(
            &fixture.runtime,
            fixture.config(),
            &store,
            text,
            "x".to_owned(),
            PIN.to_owned(),
        )
        .await;
        assert_eq!(kind(imported), WalletErrorKind::InvalidArgument);
    }
}

#[tokio::test]
async fn a_pin_change_opens_both_pairs_until_it_is_confirmed() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let old_sealed = created.sealed_password.clone();
    let wallet = created.wallet;

    let short = wallet
        .change_pin(old_sealed.clone(), PIN.to_owned(), "123".to_owned())
        .await;
    assert_eq!(kind(short), WalletErrorKind::InvalidArgument);
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);
    let wrong = wallet
        .change_pin(old_sealed.clone(), "000000".to_owned(), "246802".to_owned())
        .await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("1")
    );

    let new_sealed = wallet
        .change_pin(old_sealed.clone(), PIN.to_owned(), "246802".to_owned())
        .await
        .unwrap();
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);
    let phrase = wallet
        .mnemonic_with_pin("246802".to_owned(), new_sealed.clone())
        .await
        .unwrap();
    assert_eq!(
        wallet
            .mnemonic_with_pin(PIN.to_owned(), old_sealed.clone())
            .await
            .unwrap(),
        phrase
    );
    let held_old = wallet.confirm_pin_change(old_sealed.clone()).await;
    assert_eq!(kind(held_old), WalletErrorKind::InvalidArgument);
    assert!(store.read(PENDING_KEY).await.unwrap().is_some());
    wallet.confirm_pin_change(new_sealed.clone()).await.unwrap();
    assert_eq!(store.read(PENDING_KEY).await.unwrap(), None);
    // Nothing is pending any more, so a second confirmation changes nothing.
    let key = store.read(PIN_KEY).await.unwrap();
    wallet.confirm_pin_change(old_sealed.clone()).await.unwrap();
    assert_eq!(store.read(PIN_KEY).await.unwrap(), key);
    drop(wallet);

    for (pin, sealed) in [
        (PIN, &old_sealed),
        (PIN, &new_sealed),
        ("246802", &old_sealed),
    ] {
        let opened = fixture.open_with_pin(&store, pin, sealed).await;
        assert_eq!(kind(opened), WalletErrorKind::WrongPassword, "{pin}");
    }
    let opened = fixture
        .open_with_pin(&store, "246802", &new_sealed)
        .await
        .unwrap();
    assert_eq!(
        opened
            .mnemonic_with_pin("246802".to_owned(), new_sealed)
            .await
            .unwrap(),
        phrase
    );
}

#[test]
fn a_log_ring_that_cannot_open_keeps_its_path_out_of_the_error() {
    let fixture = Fixture::new();
    let file = fixture.dir.path().join("taken");
    std::fs::write(&file, "not a directory").unwrap();
    let dir_text = file.join("logs").to_string_lossy().into_owned();

    let error = fixture
        .runtime
        .open_log_ring(dir_text, 64 * 1024)
        .unwrap_err();

    assert_eq!(error.kind, WalletErrorKind::Io);
    let home = fixture.dir.path().to_string_lossy().into_owned();
    assert!(!error.message.contains(&home), "{}", error.message);
    assert!(
        error
            .message
            .starts_with("log ring directory could not be prepared")
    );
}

#[test]
fn the_log_ring_keeps_redacted_records_in_its_files() {
    let fixture = Fixture::new();
    let runtime = &fixture.runtime;
    let dir = fixture.dir.path().join("logs");
    let dir_text = dir.to_string_lossy().into_owned();
    for max_bytes in [4 * 1024 - 1, 16 * 1024 * 1024 + 1] {
        assert_eq!(
            kind(runtime.open_log_ring(dir_text.clone(), max_bytes)),
            WalletErrorKind::InvalidArgument
        );
    }
    runtime.open_log_ring(dir_text, 64 * 1024).unwrap();
    runtime.log_message(LogLevel::Warn, "app".to_owned(), "screen opened".to_owned());
    tracing::dispatcher::with_default(&runtime.inner.boundary.dispatch, || {
        tracing::warn!(amount = 123_456_789_u64, tx_id = 7, "slate sent");
    });

    // The segments, oldest (highest index) first.
    let text: String = (0..4)
        .rev()
        .filter_map(|index| std::fs::read_to_string(dir.join(format!("lepic.{index}.log"))).ok())
        .collect();
    assert!(text.contains(": screen opened tag=app\n"), "{text}");
    assert!(
        text.contains(": slate sent amount=[redacted] tx_id=7\n"),
        "{text}"
    );
    assert!(!text.contains("123456789"));
}

/// A new PIN that is too short is refused before the old PIN is tried, so it costs no attempt
/// and no wait, even after enough failures that the next attempt would wait.
#[tokio::test]
async fn a_short_new_pin_is_refused_before_the_old_pin_is_counted() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    store.write(FAILURES_KEY, "3".to_owned()).await.unwrap();

    let started = std::time::Instant::now();
    let changed = created
        .wallet
        .change_pin(
            created.sealed_password,
            "000000".to_owned(),
            "123".to_owned(),
        )
        .await;
    assert_eq!(kind(changed), WalletErrorKind::InvalidArgument);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("3")
    );
}

/// A password set on a new wallet needs eight characters; nothing is written before the check.
#[tokio::test]
async fn a_new_wallet_refuses_a_password_shorter_than_eight_characters() {
    let fixture = Fixture::new();
    let (file, file_password, _, _) = wallet_seed_vector();
    for password in ["", "pw", "1234567"] {
        let store = AppSecretStore::in_memory();
        let created = EpicWallet::create(
            &fixture.runtime,
            fixture.config(),
            &store,
            None,
            password.to_owned(),
        )
        .await;
        assert_eq!(
            kind(created),
            WalletErrorKind::InvalidArgument,
            "{password:?}"
        );
        let imported = EpicWallet::import_wallet_seed(
            &fixture.runtime,
            fixture.config(),
            &store,
            file.clone(),
            file_password.clone(),
            password.to_owned(),
        )
        .await;
        assert_eq!(
            kind(imported),
            WalletErrorKind::InvalidArgument,
            "{password:?}"
        );
        assert_eq!(store.read(VAULT_KEY).await.unwrap(), None, "{password:?}");
    }
    assert!(
        !fixture
            .dir
            .path()
            .join(lepic_wallet::ENCRYPTED_DATABASE_FILE)
            .exists()
    );
}

/// A wallet whose password predates the minimum keeps opening and showing its phrase.
#[tokio::test]
async fn a_wallet_with_a_password_below_the_minimum_still_opens() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    {
        let mut config = fixture.config();
        let secret = crate::node::NodeSecret::take(&mut config);
        let session =
            crate::session::Session::new(&fixture.runtime.inner, &config, &secret, store.clone())
                .await
                .unwrap();
        session
            .create(
                SeedOrigin::Generate,
                zeroize::Zeroizing::new("pw".to_owned()),
            )
            .await
            .unwrap();
    }
    let wallet = EpicWallet::open(&fixture.runtime, fixture.config(), &store, "pw".to_owned())
        .await
        .unwrap();
    assert!(wallet.mnemonic("pw".to_owned()).await.is_ok());
}

/// Wrong wallet passwords are counted in the app's store and delayed as wrong PINs are.
#[tokio::test]
async fn wrong_passwords_are_counted_and_delayed_until_one_is_right() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let password = "correct horse";
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &store,
        None,
        password.to_owned(),
    )
    .await
    .unwrap();
    let wrong = wallet.mnemonic("wrong password".to_owned()).await;
    assert_eq!(kind(wrong), WalletErrorKind::WrongPassword);
    drop(wallet);
    let open = |password: &str| {
        EpicWallet::open(
            &fixture.runtime,
            fixture.config(),
            &store,
            password.to_owned(),
        )
    };
    assert_eq!(
        kind(open("wrong password").await),
        WalletErrorKind::WrongPassword
    );
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("2")
    );

    let wallet = open(password).await.unwrap();
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);
    drop(wallet);

    // After the free failures the next attempt waits before the password is tried.
    store.write(FAILURES_KEY, "3".to_owned()).await.unwrap();
    let waited = tokio::time::timeout(std::time::Duration::from_secs(2), open(password)).await;
    assert!(waited.is_err(), "the attempt did not wait");
}

/// A password asked again before an action is counted like any other attempt and gives
/// false when wrong, without an error.
#[tokio::test]
async fn check_password_counts_attempts() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let password = "correct horse";
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &store,
        None,
        password.to_owned(),
    )
    .await
    .unwrap();

    assert!(
        !wallet
            .check_password("wrong password".to_owned())
            .await
            .unwrap()
    );
    assert_eq!(
        store.read(FAILURES_KEY).await.unwrap().as_deref(),
        Some("1")
    );

    assert!(wallet.check_password(password.to_owned()).await.unwrap());
    assert_eq!(store.read(FAILURES_KEY).await.unwrap(), None);

    wallet.lock();
    assert_eq!(
        kind(wallet.check_password(password.to_owned()).await),
        WalletErrorKind::Locked
    );
}

/// An app store that works, except that writing the vault fails.
fn store_refusing_the_vault() -> AppSecretStore {
    use crate::api::secret_store::SecretReply;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    let values: Arc<Mutex<BTreeMap<String, String>>> = Arc::default();
    let (read, write, delete) = (values.clone(), values.clone(), values);
    AppSecretStore::new(
        move |key| {
            let value = read.lock().unwrap().get(&key).cloned();
            Box::pin(async move { SecretReply { ok: true, value } })
        },
        move |key, value| {
            let ok = key != VAULT_KEY;
            if ok {
                write.lock().unwrap().insert(key, value);
            }
            Box::pin(async move { SecretReply { ok, value: None } })
        },
        move |key| {
            delete.lock().unwrap().remove(&key);
            Box::pin(async {
                SecretReply {
                    ok: true,
                    value: None,
                }
            })
        },
    )
    .unwrap()
}

fn database_files(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("wallet."))
        .collect();
    names.sort();
    names
}

/// A create whose vault could not be stored leaves no database behind, so creating again,
/// with a new seed, works.
#[tokio::test]
async fn a_create_that_could_not_store_its_vault_can_be_retried() {
    let fixture = Fixture::new();
    let failing = store_refusing_the_vault();
    let created = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &failing,
        None,
        "password".to_owned(),
    )
    .await;
    assert_eq!(kind(created), WalletErrorKind::SecretStore);
    assert_eq!(database_files(fixture.dir.path()), Vec::<String>::new());

    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    assert!(
        created
            .wallet
            .mnemonic_with_pin(PIN.to_owned(), created.sealed_password)
            .await
            .is_ok()
    );
}

/// A database that existed before the create, such as the wallet's own on a restore, is kept
/// when the vault cannot be stored.
#[tokio::test]
async fn a_failed_restore_keeps_the_database_that_was_there() {
    let fixture = Fixture::new();
    let phrase = Some(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon art"
            .to_owned(),
    );
    let first = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &AppSecretStore::in_memory(),
        phrase.clone(),
        "password".to_owned(),
    )
    .await
    .unwrap();
    drop(first);
    let before = database_files(fixture.dir.path());
    assert!(before.contains(&lepic_wallet::ENCRYPTED_DATABASE_FILE.to_owned()));

    let restored = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &store_refusing_the_vault(),
        phrase,
        "password".to_owned(),
    )
    .await;
    assert_eq!(kind(restored), WalletErrorKind::SecretStore);
    assert!(
        database_files(fixture.dir.path())
            .contains(&lepic_wallet::ENCRYPTED_DATABASE_FILE.to_owned())
    );
}

/// A damaged database reaches the app as its own kind, once; it is kept beside the wallet and
/// the next open rebuilds the wallet from its vault.
#[tokio::test]
async fn a_damaged_database_is_reported_once_and_then_rebuilt() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    drop(created);
    let database = fixture
        .dir
        .path()
        .join(lepic_wallet::ENCRYPTED_DATABASE_FILE);
    std::fs::write(&database, [0x5a; 8192]).unwrap();

    let damaged = fixture.open_with_pin(&store, PIN, &sealed).await;
    assert_eq!(kind(damaged), WalletErrorKind::DamagedDatabase);
    assert_eq!(WalletErrorKind::DamagedDatabase.code(), 37);
    assert!(
        database_files(fixture.dir.path())
            .iter()
            .any(|name| name.contains(".damaged-"))
    );

    let wallet = fixture.open_with_pin(&store, PIN, &sealed).await.unwrap();
    assert!(wallet.summary(false).await.is_ok());
}

/// Removes the wallet's encrypted database and puts an empty plain one of an earlier build in
/// its place, under `phrase`'s keys.
fn plain_database_in_place_of_the_encrypted_one(fixture: &Fixture, phrase: &str) {
    for suffix in ["", "-wal", "-shm", ".check"] {
        let path = fixture
            .dir
            .path()
            .join(format!("{}{suffix}", lepic_wallet::ENCRYPTED_DATABASE_FILE));
        drop(std::fs::remove_file(path));
    }
    let seed = lepic_keychain::Seed::from_mnemonic(phrase).unwrap();
    drop(
        lepic_store::SqliteStore::open(
            &fixture.dir.path().join(lepic_wallet::DATABASE_FILE),
            lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
            lepic_store::AtRest::Plain,
        )
        .unwrap(),
    );
}

/// An open reports how it found the database: a new wallet's is encrypted, a plain one of an
/// earlier build is moved into an encrypted one at the first open, which the next open finds.
#[tokio::test]
async fn an_open_reports_the_move_of_a_plain_database_to_encryption() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let at_rest = created.wallet.store_at_rest().await.unwrap();
    assert_eq!(at_rest.state, StoreAtRestState::Encrypted);
    assert!(!at_rest.rollback_set_aside);
    let phrase = created
        .wallet
        .mnemonic_with_pin(PIN.to_owned(), sealed.clone())
        .await
        .unwrap();
    drop(created);
    plain_database_in_place_of_the_encrypted_one(&fixture, &phrase);

    let wallet = fixture.open_with_pin(&store, PIN, &sealed).await.unwrap();
    let at_rest = wallet.store_at_rest().await.unwrap();
    assert_eq!(at_rest.state, StoreAtRestState::MigratedNow, "{at_rest:?}");
    assert!(at_rest.reason.is_empty());
    let names = database_files(fixture.dir.path());
    assert!(
        names.contains(&lepic_wallet::ENCRYPTED_DATABASE_FILE.to_owned()),
        "{names:?}"
    );
    assert!(names.contains(&"wallet.sqlite3.pre-encryption".to_owned()));
    assert!(!names.contains(&lepic_wallet::DATABASE_FILE.to_owned()));
    // The plain copy stays until the app retires it.
    let retired = wallet.retire_plain_store(30).await.unwrap();
    assert_eq!(
        retired.deleted,
        vec!["wallet.sqlite3.pre-encryption".to_owned()]
    );
    drop(wallet);

    let wallet = fixture.open_with_pin(&store, PIN, &sealed).await.unwrap();
    assert_eq!(
        wallet.store_at_rest().await.unwrap().state,
        StoreAtRestState::Encrypted
    );
}

/// An encrypted database whose key check refuses the vault's seed reaches the app as
/// `WrongKey`, with nothing moved.
#[tokio::test]
async fn a_database_of_another_key_is_wrong_key_and_nothing_moves() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    drop(created);
    // Another wallet's encrypted database copied over this one's.
    let other = Fixture::new();
    drop(
        other
            .create_with_pin(&AppSecretStore::in_memory(), PIN)
            .await,
    );
    for suffix in ["", ".check"] {
        let name = format!("{}{suffix}", lepic_wallet::ENCRYPTED_DATABASE_FILE);
        std::fs::copy(other.dir.path().join(&name), fixture.dir.path().join(&name)).unwrap();
    }
    let before: Vec<(String, Vec<u8>)> = database_files(fixture.dir.path())
        .into_iter()
        .filter(|name| !name.ends_with("-shm"))
        .map(|name| {
            let bytes = std::fs::read(fixture.dir.path().join(&name)).unwrap();
            (name, bytes)
        })
        .collect();

    let refused = fixture.open_with_pin(&store, PIN, &sealed).await;
    assert_eq!(kind(refused), WalletErrorKind::WrongKey);
    assert_eq!(WalletErrorKind::WrongKey.code(), 90);
    let after: Vec<(String, Vec<u8>)> = database_files(fixture.dir.path())
        .into_iter()
        .filter(|name| !name.ends_with("-shm"))
        .map(|name| {
            let bytes = std::fs::read(fixture.dir.path().join(&name)).unwrap();
            (name, bytes)
        })
        .collect();
    assert_eq!(after, before);
}

/// Deleting a wallet removes its encrypted database, key check and the plain copies set aside.
#[tokio::test]
async fn delete_wallet_removes_the_encrypted_database_and_the_plain_copies() {
    let fixture = Fixture::new();
    let store = AppSecretStore::in_memory();
    let created = fixture.create_with_pin(&store, PIN).await;
    let sealed = created.sealed_password.clone();
    let phrase = created
        .wallet
        .mnemonic_with_pin(PIN.to_owned(), sealed.clone())
        .await
        .unwrap();
    drop(created);
    plain_database_in_place_of_the_encrypted_one(&fixture, &phrase);
    drop(fixture.open_with_pin(&store, PIN, &sealed).await.unwrap());
    std::fs::write(
        fixture
            .dir
            .path()
            .join("wallet.sqlite3.after-rollback-1700000000"),
        b"x",
    )
    .unwrap();
    assert!(database_files(fixture.dir.path()).len() > 2);

    crate::api::wallet::delete_wallet(&fixture.runtime, fixture.config(), &store)
        .await
        .unwrap();
    assert_eq!(database_files(fixture.dir.path()), Vec::<String>::new());
}
