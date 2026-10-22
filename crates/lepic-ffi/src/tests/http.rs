//! Direct transactions over HTTP between two wallets of one runtime on the scripted chain,
//! through the listener on loopback.

use std::sync::{Arc, Mutex};

use lepic_foreign::{ClientSettings, ForeignClient, ForeignUrl, PlainHttp, webpki_tls_config};
use lepic_wallet::slate::{MediaType, WireSlate};
use zeroize::Zeroizing;

use super::{eventually, kind};
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::http::{HttpExposure, HttpListenerEvent, HttpListenerEventKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, TxStatus, WalletConfig};
use crate::session::{SeedOrigin, Session};

const EPIC: u64 = 100_000_000;

async fn sends(session: &Session) -> Vec<crate::api::types::TransactionDetails> {
    let mut stored = session.transactions().await.unwrap();
    stored.retain(|tx| tx.direction == crate::api::types::TxDirection::Outgoing);
    stored
}

struct Pair {
    chain: MockChain,
    _runtime: LepicRuntime,
    _dirs: [tempfile::TempDir; 2],
    alice: Arc<Session>,
    bob: Arc<Session>,
}

fn password() -> Zeroizing<String> {
    Zeroizing::new("password".to_owned())
}

fn session(runtime: &LepicRuntime, dir: &tempfile::TempDir) -> Arc<Session> {
    let mut config = WalletConfig {
        data_dir: dir.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url: "http://127.0.0.1:1".to_owned(),
        node_api_secret: None,
        epicbox_domain: String::new(),
        epicbox_port: 443,
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    Arc::new(
        Session::new(
            &runtime.inner,
            &config,
            &secret,
            AppSecretStore::in_memory(),
        )
        .unwrap(),
    )
}

/// Alice holds 10 EPIC; Bob holds nothing.
async fn funded_pair() -> Pair {
    let chain = MockChain::new(1).unwrap();
    let runtime = chain.runtime(LogLevel::Warn).unwrap();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let alice = session(&runtime, &dirs[0]);
    alice
        .create(SeedOrigin::Generate, password())
        .await
        .unwrap();
    let phrase = alice.recovery_phrase(password()).await.unwrap();
    chain.fund(phrase, Chain::Floonet, 10 * EPIC, 0).unwrap();
    chain.set_height(20);
    alice.scan_to_tip().await;
    let bob = session(&runtime, &dirs[1]);
    bob.create(SeedOrigin::Generate, password()).await.unwrap();
    bob.scan_to_tip().await;
    Pair {
        chain,
        _runtime: runtime,
        _dirs: dirs,
        alice,
        bob,
    }
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<HttpListenerEvent>>>);

impl Events {
    fn report(&self) -> crate::session::HttpReport {
        let events = Arc::clone(&self.0);
        Arc::new(move |event| events.lock().unwrap().push(event))
    }

    fn kinds(&self) -> Vec<HttpListenerEventKind> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.kind)
            .collect()
    }

    fn last(&self) -> HttpListenerEvent {
        self.0.lock().unwrap().last().cloned().unwrap()
    }
}

/// Starts `session`'s listener on a port the system picks and returns the port.
async fn listen(session: &Arc<Session>, events: &Events) -> u16 {
    session
        .start_http_listener(HttpExposure::LocalOnly, 0, events.report())
        .await
        .unwrap();
    let started = events.last();
    assert_eq!(started.kind, HttpListenerEventKind::Started);
    assert_eq!(started.exposure, Some(HttpExposure::LocalOnly));
    let status = session.http_listener_status().unwrap();
    assert_eq!(Some(status.port), started.port);
    status.port
}

fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// A loopback port nothing listens on.
fn closed_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_send_is_answered_then_finalized_and_posted() {
    let pair = funded_pair().await;
    let events = Events::default();
    let port = listen(&pair.bob, &events).await;

    let sent = pair
        .alice
        .send_http(2 * EPIC, 1, &url(port), false, None)
        .await
        .unwrap();

    assert!(sent.posted);
    assert_eq!(sent.amount, 2 * EPIC);
    assert_eq!(pair.chain.pushed_count(), 1);
    let alice_tx = pair.alice.transaction(sent.tx_id).await.unwrap();
    assert_eq!(alice_tx.status, TxStatus::Posted);
    assert_eq!(alice_tx.transport.as_deref(), Some("http"));
    let received = events.last();
    assert_eq!(received.kind, HttpListenerEventKind::Received);
    assert_eq!(received.amount, Some(2 * EPIC));
    assert!(!received.repeated);
    let bob_tx = pair.bob.transaction(received.tx_id.unwrap()).await.unwrap();
    assert_eq!(bob_tx.status, TxStatus::Received);
    assert_eq!(bob_tx.slate_id, Some(sent.slate_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_slate_posted_again_gets_the_same_answer() {
    let pair = funded_pair().await;
    let events = Events::default();
    let port = listen(&pair.bob, &events).await;
    let slate = pair.alice.create_send_slate(EPIC, 1, None).await.unwrap();
    let client = ForeignClient::new(ClientSettings::default(), webpki_tls_config().unwrap());
    let to = ForeignUrl::parse(&url(port), PlainHttp::LoopbackOnly).unwrap();
    let wire = WireSlate::text(MediaType::JSON, slate.json);

    let first = client.receive_tx(&to, &wire).await.unwrap();
    let second = client.receive_tx(&to, &wire).await.unwrap();

    assert_eq!(first.as_text(), second.as_text());
    let received: Vec<_> = events.0.lock().unwrap().clone();
    let [_, first_event, second_event] = received.as_slice() else {
        panic!("{received:?}");
    };
    assert!(!first_event.repeated);
    assert!(second_event.repeated);
    assert_eq!(first_event.tx_id, second_event.tx_id);
    let finalized = pair
        .alice
        .finalize_slate(second.as_text().unwrap().to_owned())
        .await
        .unwrap();
    assert_eq!(finalized.tx_id, slate.tx_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undelivered_http_send_is_finalized_by_its_resend() {
    let pair = funded_pair().await;

    let undelivered = pair
        .alice
        .send_http(EPIC, 1, &url(closed_port()), false, None)
        .await;
    assert_eq!(kind(undelivered), WalletErrorKind::TransportFailed);
    let stored = sends(&pair.alice).await;
    let [sent] = stored.as_slice() else {
        panic!("{stored:?}");
    };
    assert_eq!(sent.status, TxStatus::Sent);

    let events = Events::default();
    let port = listen(&pair.bob, &events).await;
    let resent = pair
        .alice
        .resend_http(sent.tx_id, &url(port), false)
        .await
        .unwrap();

    assert!(resent.posted);
    assert_eq!(Some(resent.slate_id), sent.slate_id);
    assert_eq!(pair.chain.pushed_count(), 1);
    assert_eq!(events.last().kind, HttpListenerEventKind::Received);
    let again = pair.alice.resend_http(sent.tx_id, &url(port), false).await;
    assert_eq!(kind(again), WalletErrorKind::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_to_another_computer_needs_consent() {
    let pair = funded_pair().await;

    let refused = pair
        .alice
        .send_http(EPIC, 1, "http://203.0.113.7:3415", false, None)
        .await;
    assert_eq!(kind(refused), WalletErrorKind::PlainHttpNotAllowed);
    for invalid in ["203.0.113.7:3415", "ftp://host", "http://abcdefgh.onion"] {
        let refused = pair.alice.send_http(EPIC, 1, invalid, true, None).await;
        assert_eq!(kind(refused), WalletErrorKind::HttpUrlInvalid, "{invalid}");
    }
    assert!(sends(&pair.alice).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_listener_on_a_taken_port_reports_it() {
    let pair = funded_pair().await;
    let port = listen(&pair.alice, &Events::default()).await;
    let events = Events::default();

    pair.bob
        .start_http_listener(HttpExposure::LocalOnly, port, events.report())
        .await
        .unwrap();

    let refused = events.last();
    assert_eq!(refused.kind, HttpListenerEventKind::PortInUse);
    assert_eq!(refused.port, Some(port));
    assert_eq!(pair.bob.http_listener_status(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wallet_runs_one_http_listener() {
    let pair = funded_pair().await;
    let first = Events::default();
    let port = listen(&pair.bob, &first).await;
    let second = Events::default();

    pair.bob
        .start_http_listener(HttpExposure::LocalOnly, 0, second.report())
        .await
        .unwrap();

    assert!(second.kinds().is_empty());
    assert_eq!(pair.bob.http_listener_status().unwrap().port, port);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_stops_the_http_listener_and_frees_its_port() {
    let pair = funded_pair().await;
    let events = Events::default();
    let port = listen(&pair.bob, &events).await;

    pair.bob.lock();

    assert_eq!(pair.bob.http_listener_status(), None);
    assert!(eventually(|| events.kinds().last() == Some(&HttpListenerEventKind::Stopped)).await);
    std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let locked = pair
        .bob
        .start_http_listener(HttpExposure::LocalOnly, 0, events.report())
        .await;
    assert_eq!(kind(locked), WalletErrorKind::Locked);
}

/// `slate` under slate id number `n`, so each is a new payment.
fn numbered(slate: &str, slate_id: &str, n: u32) -> WireSlate {
    let renumbered = slate.replace(slate_id, &format!("00000000-0000-4000-8000-{n:012x}"));
    assert_ne!(renumbered, slate);
    WireSlate::text(MediaType::JSON, renumbered)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_caps_open_receipts_and_still_answers_a_payment_received_before() {
    let pair = funded_pair().await;
    let events = Events::default();
    let receiver = pair.bob.http_receiver(events.report());
    let slate = pair.alice.create_send_slate(EPIC, 1, None).await.unwrap();
    let slate_id = slate.slate_id.clone();
    let cap = u32::try_from(lepic_wallet::inbox::MAX_OPEN_RECEIPTS).unwrap();
    let mut answers = Vec::new();
    for n in 0..cap {
        answers.push(
            receiver
                .receive(numbered(&slate.json, &slate_id, n))
                .await
                .unwrap(),
        );
    }
    let receipts: Vec<u32> = events
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.tx_id.unwrap())
        .collect();

    receiver
        .receive(numbered(&slate.json, &slate_id, cap))
        .await
        .unwrap();

    let oldest = pair.bob.transaction(receipts[0]).await.unwrap();
    assert_eq!(oldest.status, TxStatus::Cancelled);
    let next = pair.bob.transaction(receipts[1]).await.unwrap();
    assert_eq!(next.status, TxStatus::Received);
    let again = receiver
        .receive(numbered(&slate.json, &slate_id, 7))
        .await
        .unwrap();
    assert_eq!(again.as_text(), answers[7].as_text());
    assert!(events.last().repeated);

    pair.chain.set_node_unreachable(true);
    let before = pair.bob.transactions().await.unwrap().len();
    let refused = receiver
        .receive(numbered(&slate.json, &slate_id, cap + 1))
        .await;

    assert_eq!(refused, Err(lepic_foreign::Refusal::Unavailable));
    let last = events.last();
    assert_eq!(last.kind, HttpListenerEventKind::Refused);
    assert_eq!(
        last.refusal,
        Some(crate::api::http::HttpRefusal::Unavailable)
    );
    assert_eq!(pair.bob.transactions().await.unwrap().len(), before);
}
