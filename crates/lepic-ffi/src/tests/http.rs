// SPDX-License-Identifier: Apache-2.0
//! Direct transactions over HTTP between two wallets of one runtime on the scripted chain,
//! through the listener on loopback.

use std::sync::{Arc, Mutex};

use lepic_methods::http::{ListenerUrl, PlainHttp, RpcClient, webpki_tls_config};
use lepic_wallet::slate::{MediaType, WireSlate};
use zeroize::Zeroizing;

use super::{eventually, kind};
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::http::{HttpCoinbase, HttpExposure, HttpListenerEvent, HttpListenerEventKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, SendDialect, SlateWire, TxStatus, WalletConfig};
use crate::api::wallet::EpicWallet;
use crate::session::{SeedOrigin, Session};

pub(super) const EPIC: u64 = 100_000_000;

pub(super) async fn sends(session: &Session) -> Vec<crate::api::types::TransactionDetails> {
    let mut stored = session.transactions().await.unwrap();
    stored.retain(|tx| tx.direction == crate::api::types::TxDirection::Outgoing);
    stored
}

pub(super) struct Pair {
    pub(super) chain: MockChain,
    _runtime: LepicRuntime,
    pub(super) dirs: [tempfile::TempDir; 2],
    pub(super) alice: Arc<Session>,
    pub(super) bob: Arc<Session>,
}

pub(super) fn password() -> Zeroizing<String> {
    Zeroizing::new("password".to_owned())
}

async fn session(runtime: &LepicRuntime, dir: &tempfile::TempDir) -> Arc<Session> {
    session_on(runtime, dir, AppSecretStore::in_memory()).await
}

/// A session on `dir` with the app store `store`: a fresh handle on a wallet when `store` is
/// the one the wallet was created with.
async fn session_on(
    runtime: &LepicRuntime,
    dir: &tempfile::TempDir,
    store: AppSecretStore,
) -> Arc<Session> {
    session_with_policy(runtime, dir, store, Default::default()).await
}

/// A session as [`session_on`] makes it, under the host's `policy`.
async fn session_with_policy(
    runtime: &LepicRuntime,
    dir: &tempfile::TempDir,
    store: AppSecretStore,
    policy: crate::api::policy::HostPolicy,
) -> Arc<Session> {
    let mut config = WalletConfig {
        policy,
        data_dir: dir.path().to_string_lossy().into_owned(),
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
        profile: 0,
        domain: None,
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    Arc::new(
        Session::new(&runtime.inner, &config, &secret, store)
            .await
            .unwrap(),
    )
}

impl Pair {
    pub(super) const fn runtime(&self) -> &LepicRuntime {
        &self._runtime
    }
}

/// Opens a fresh handle on Alice's wallet, as the app does after a lock.
async fn reopen_alice(pair: &Pair) -> Arc<Session> {
    let fresh = session_on(&pair._runtime, &pair.dirs[0], pair.alice.store().clone()).await;
    fresh.open(password()).await.unwrap();
    fresh
}

/// Alice holds 10 EPIC; Bob holds nothing.
pub(super) async fn funded_pair() -> Pair {
    funded_pair_with(Default::default()).await
}

/// A pair as [`funded_pair`] makes it, with Bob under the host's `bob_policy`.
pub(super) async fn funded_pair_with(bob_policy: crate::api::policy::HostPolicy) -> Pair {
    let chain = MockChain::new(1).unwrap();
    let runtime = chain.runtime(LogLevel::Warn).unwrap();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let alice = session(&runtime, &dirs[0]).await;
    alice
        .create(SeedOrigin::Generate, password())
        .await
        .unwrap();
    let phrase = alice.recovery_phrase(password()).await.unwrap();
    chain.fund(phrase, Chain::Floonet, 10 * EPIC, 0).unwrap();
    chain.set_height(20);
    alice.scan_to_tip().await;
    let bob =
        session_with_policy(&runtime, &dirs[1], AppSecretStore::in_memory(), bob_policy).await;
    bob.create(SeedOrigin::Generate, password()).await.unwrap();
    bob.scan_to_tip().await;
    Pair {
        chain,
        _runtime: runtime,
        dirs,
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
        .start_http_listener(
            HttpExposure::LocalOnly,
            0,
            HttpCoinbase::Off,
            events.report(),
        )
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

/// A loopback port that accepts connections and never answers, as a receiving wallet that
/// hangs. It answers nothing until the returned guard is dropped.
fn stalled_port() -> (u16, std::sync::mpsc::Sender<()>) {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let (guard, released) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        socket.set_nonblocking(true).unwrap();
        while released
            .recv_timeout(std::time::Duration::from_millis(10))
            .is_err()
        {
            if let Ok((stream, _)) = socket.accept() {
                held.push(stream);
            }
        }
    });
    (port, guard)
}

/// Posts `body` to the foreign API on `port` and returns the JSON answer.
async fn post_foreign(port: u16, body: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "POST /v2/foreign HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    let (_, json) = answer.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(json).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_with_coinbase_builds_a_block_reward() {
    let pair = funded_pair().await;
    let events = Events::default();
    pair.bob
        .start_http_listener(
            HttpExposure::LocalOnly,
            0,
            HttpCoinbase::LocalOnly,
            events.report(),
        )
        .await
        .unwrap();
    let port = pair.bob.http_listener_status().unwrap().port;

    let answer = post_foreign(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"build_coinbase",
            "params":{"block_fees":{"fees":0,"height":30,"key_id":null}}}"#,
    )
    .await;

    let built = &answer["result"]["Ok"];
    assert_eq!(built["output"]["features"], "Coinbase", "{answer}");
    assert_eq!(built["kernel"]["features"], "Coinbase");
    let commit = built["output"]["commit"].as_str().unwrap();
    let stored = pair.bob.outputs().unwrap();
    let candidate = stored
        .iter()
        .find(|output| output.commitment == commit)
        .unwrap();
    assert!(candidate.is_coinbase);
    assert_eq!(
        candidate.status,
        crate::api::types::OutputStatus::Unconfirmed
    );
    assert_eq!(candidate.category, None);
    assert_eq!(candidate.height, 30);
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
    let client = RpcClient::new(shipped().send, webpki_tls_config().unwrap());
    let to = ListenerUrl::parse(&url(port), PlainHttp::LoopbackOnly).unwrap();
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
        .resend_http(sent.tx_id, &url(port), false, false)
        .await
        .unwrap();

    assert!(resent.posted);
    assert_eq!(Some(resent.slate_id), sent.slate_id);
    assert_eq!(pair.chain.pushed_count(), 1);
    assert_eq!(events.last().kind, HttpListenerEventKind::Received);
    let again = pair
        .alice
        .resend_http(sent.tx_id, &url(port), false, false)
        .await;
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
    for invalid in [
        "203.0.113.7:3415".to_owned(),
        "ftp://host".to_owned(),
        format!("http://{}.onion", "abcdefgh"),
    ] {
        let refused = pair.alice.send_http(EPIC, 1, &invalid, true, None).await;
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
        .start_http_listener(
            HttpExposure::LocalOnly,
            port,
            HttpCoinbase::Off,
            events.report(),
        )
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
        .start_http_listener(
            HttpExposure::LocalOnly,
            0,
            HttpCoinbase::Off,
            second.report(),
        )
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
        .start_http_listener(
            HttpExposure::LocalOnly,
            0,
            HttpCoinbase::Off,
            events.report(),
        )
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
    let receiver = pair.bob.http_receiver(
        events.report(),
        lepic_methods::http::TRANSPORT_ID,
        lepic_wallet::ProofKey::Payments,
    );
    let slate = pair.alice.create_send_slate(EPIC, 1, None).await.unwrap();
    let slate_id = slate.slate_id.clone();
    let cap = u32::try_from(lepic_wallet::WalletPolicy::DEFAULT.max_open_receipts).unwrap();
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

    let at_cap = receiver
        .receive(numbered(&slate.json, &slate_id, cap))
        .await;

    assert_eq!(at_cap, Err(lepic_methods::http::Refusal::Unavailable));
    let oldest = pair.bob.transaction(receipts[0]).await.unwrap();
    assert_eq!(oldest.status, TxStatus::Received);
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

    assert_eq!(refused, Err(lepic_methods::http::Refusal::Unavailable));
    let last = events.last();
    assert_eq!(last.kind, HttpListenerEventKind::Refused);
    assert_eq!(
        last.refusal,
        Some(crate::api::http::HttpRefusal::Unavailable)
    );
    assert_eq!(pair.bob.transactions().await.unwrap().len(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payment_over_the_listener_rate_is_reported_refused_as_unavailable() {
    let pair = funded_pair().await;
    let events = Events::default();
    let port = listen(&pair.bob, &events).await;
    let client = RpcClient::new(shipped().send, webpki_tls_config().unwrap());
    let to = ListenerUrl::parse(&url(port), PlainHttp::LoopbackOnly).unwrap();
    let budget = shipped().listen.receives_per_minute;
    // Slates the wallet refuses as invalid leave the budget to real payments, as many a
    // minute as the budget.
    for n in 0..budget {
        let junk = format!(r#"{{"id":"{n}","amount":"1","participant_data":[]}}"#);
        let refused = client
            .receive_tx(&to, &WireSlate::text(MediaType::JSON, junk))
            .await;
        assert!(refused.is_err());
    }
    let slate = pair.alice.create_send_slate(EPIC, 1, None).await.unwrap();
    for n in 0..budget {
        client
            .receive_tx(&to, &numbered(&slate.json, &slate.slate_id, n))
            .await
            .unwrap();
    }
    let over = client
        .receive_tx(&to, &numbered(&slate.json, &slate.slate_id, budget))
        .await;
    assert!(over.is_err());

    let refusals: Vec<_> = events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == HttpListenerEventKind::Refused)
        .map(|event| event.refusal)
        .collect();
    let (last, checked) = refusals.split_last().unwrap();
    assert_eq!(*last, Some(crate::api::http::HttpRefusal::Unavailable));
    assert_eq!(checked.len(), usize::try_from(budget).unwrap());
    assert!(
        checked
            .iter()
            .all(|refusal| *refusal == Some(crate::api::http::HttpRefusal::Rejected))
    );
}

/// The app locks while a store write runs, on a phone one that takes well over the moment a
/// claim used to wait, and opens anew at once: the open waits for the write, which finishes,
/// and sees what it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_during_a_slow_store_write_leaves_its_result_to_the_next_open() {
    let pair = funded_pair().await;
    let undelivered = pair
        .alice
        .send_http(EPIC, 1, &url(closed_port()), false, None)
        .await;
    assert_eq!(kind(undelivered), WalletErrorKind::TransportFailed);
    let [sent] = sends(&pair.alice).await.try_into().unwrap();
    let claim = Arc::clone(pair.alice.directory_claim());
    let writes_before = claim.writes_begun();
    claim.delay_writes(std::time::Duration::from_millis(300));
    let handle = EpicWallet::of_session(Arc::clone(&pair.alice));
    let cancelling = tokio::spawn({
        let handle = EpicWallet::of_session(Arc::clone(&pair.alice));
        async move { handle.cancel_transaction(sent.tx_id).await }
    });
    assert!(eventually(|| claim.writes_begun() > writes_before).await);

    handle.lock();
    let reopened = reopen_alice(&pair).await;

    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(5), cancelling)
        .await
        .expect("the cancel ended at the lock")
        .unwrap();
    assert_eq!(kind(cancelled), WalletErrorKind::Cancelled);
    let stored = reopened.transaction(sent.tx_id).await.unwrap();
    assert_eq!(stored.status, TxStatus::Cancelled);
}

/// The app locks while a send waits on the receiving wallet: the send is stored and its
/// delivery ends, so a fresh handle finds it waiting for its answer and delivers it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_during_an_http_delivery_leaves_a_resendable_send_to_a_fresh_handle() {
    let pair = funded_pair().await;
    let (stalled, _receiver) = stalled_port();
    let handle = EpicWallet::of_session(Arc::clone(&pair.alice));
    let sending = tokio::spawn({
        let handle = EpicWallet::of_session(Arc::clone(&pair.alice));
        async move {
            handle
                .send_http(EPIC, 1, url(stalled), false, None, None)
                .await
        }
    });
    assert!(eventually(|| handle.session().in_flight.len() == 1).await);
    // The task is listed before it stores the send: wait for the store too.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut stored = sends(&pair.alice).await;
    while stored.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        stored = sends(&pair.alice).await;
    }
    let [sent] = stored.as_slice() else {
        panic!("{stored:?}");
    };
    assert_eq!(sent.status, TxStatus::Sent);

    handle.lock();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), sending)
        .await
        .expect("the send ended at the lock")
        .unwrap();
    assert_eq!(kind(ended), WalletErrorKind::Cancelled);
    let reopened = reopen_alice(&pair).await;

    let [waiting] = sends(&reopened).await.try_into().unwrap();
    assert_eq!(
        (waiting.tx_id, waiting.status),
        (sent.tx_id, TxStatus::Sent)
    );
    assert!(
        waiting.undelivered,
        "no attempt got through before the lock"
    );
    let events = Events::default();
    let port = listen(&pair.bob, &events).await;
    let resent = reopened
        .resend_http(sent.tx_id, &url(port), false, false)
        .await
        .unwrap();
    assert!(resent.posted);
    assert!(!reopened.transaction(sent.tx_id).await.unwrap().undelivered);
    assert_eq!(pair.chain.pushed_count(), 1);
    assert_eq!(events.last().kind, HttpListenerEventKind::Received);
}

fn shipped() -> crate::tuning::Tuning {
    crate::tuning::Tuning::check(&crate::tuning::shipped()).unwrap()
}

/// Opens a fresh handle on Bob's wallet with native slates set as `native_direct`, so the
/// setting is in use.
async fn reopen_bob_native(pair: &Pair, native_direct: bool) -> Arc<Session> {
    pair.bob.set_native_direct(native_direct).unwrap();
    EpicWallet::of_session(Arc::clone(&pair.bob)).lock();
    let fresh = session_on(&pair._runtime, &pair.dirs[1], pair.bob.store().clone()).await;
    fresh.open(password()).await.unwrap();
    fresh
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_native_slates_off_a_send_is_legacy_and_pins_nothing() {
    let pair = funded_pair().await;
    assert!(!pair.alice.native_direct_active());
    let events = Events::default();
    let port = listen(&pair.bob, &events).await;

    let sent = pair
        .alice
        .send_http(EPIC, 1, &url(port), false, None)
        .await
        .unwrap();
    assert!(sent.posted);
    assert_eq!(sent.dialect, SendDialect::Legacy);
    assert_eq!(sent.format, SlateWire::Legacy);
    assert!(pair.alice.peer_pins().unwrap().is_empty());
    assert!(!pair.alice.forget_peer_pin(&url(port)).unwrap());
}

// A native post never goes to this device, so a native send to a listener on loopback is
// refused after the advert is read and before anything is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_native_send_to_this_device_is_refused_before_it_stores_and_legacy_can_be_asked_for() {
    let pair = funded_pair().await;
    pair.alice.set_native_direct(true).unwrap();
    EpicWallet::of_session(Arc::clone(&pair.alice)).lock();
    let alice = reopen_alice(&pair).await;
    assert!(alice.native_direct_active());
    let bob = reopen_bob_native(&pair, true).await;
    let events = Events::default();
    let port = listen(&bob, &events).await;
    let before = alice.transactions().await.unwrap().len();

    let refused = alice
        .send_http_with(EPIC, 1, &url(port), false, None, None, false)
        .await
        .unwrap_err();
    assert_eq!(refused.kind, WalletErrorKind::ThisComputer);
    assert_eq!(refused.tx_id, None);
    assert_eq!(refused.origin.as_deref(), Some(url(port).as_str()));
    assert_eq!(alice.transactions().await.unwrap().len(), before);
    assert_eq!(pair.chain.pushed_count(), 0);
    assert!(alice.peer_pins().unwrap().is_empty());

    // Nothing is locked, so the user's retry in the legacy dialect selects the same coins.
    let sent = alice
        .send_http_with(EPIC, 1, &url(port), false, None, None, true)
        .await
        .unwrap();
    assert!(sent.posted);
    assert_eq!(sent.dialect, SendDialect::Legacy);
    assert_eq!(alice.transactions().await.unwrap().len(), before + 1);
    assert_eq!(pair.chain.pushed_count(), 1);
}
