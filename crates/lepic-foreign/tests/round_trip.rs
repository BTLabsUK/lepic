// SPDX-License-Identifier: Apache-2.0
//! The client against the listener on loopback, with a wallet that answers every S1 with a
//! fixed S2.

// Helpers outside #[test] functions unwrap too; a failure there is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lepic_foreign::{
    BlockFees, ClientError, CoinbaseAccess, CoinbaseAnswer, Exposure, ForeignClient, ForeignUrl,
    ListenError, ListenSettings, PlainHttp, ReceiveHandler, Refusal, RpcError, listen,
    webpki_tls_config,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::transport::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[{"id":"0"}]}"#;
const S2: &str =
    r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[]}"#;
/// Shaped like an S1, so it takes the payment budget, but refused by the wallet.
const JUNK: &str = r#"{"id":"x","amount":"1","participant_data":[]}"#;

struct Answering {
    calls: AtomicUsize,
    refused: AtomicUsize,
    refuse: Option<Refusal>,
    answer: String,
}

impl ReceiveHandler for Answering {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if slate.as_text() != Some(S1) {
                return Err(Refusal::Rejected);
            }
            match self.refuse {
                Some(refusal) => Err(refusal),
                None => Ok(WireSlate::text(MediaType::JSON, self.answer.clone())),
            }
        })
    }

    fn refused(&self, _refusal: Refusal) {
        self.refused.fetch_add(1, Ordering::SeqCst);
    }
}

fn handler(refuse: Option<Refusal>) -> Arc<Answering> {
    answering(refuse, S2.to_owned())
}

fn answering(refuse: Option<Refusal>, answer: String) -> Arc<Answering> {
    Arc::new(Answering {
        calls: AtomicUsize::new(0),
        refused: AtomicUsize::new(0),
        refuse,
        answer,
    })
}

fn receive_tx_request(slate: &str) -> String {
    let body =
        format!(r#"{{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{slate},null,null]}}"#);
    format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn client() -> ForeignClient {
    ForeignClient::new(
        lepic_foreign::testing::client_settings(),
        webpki_tls_config().unwrap(),
    )
}

fn url(port: u16) -> ForeignUrl {
    ForeignUrl::parse(&format!("http://127.0.0.1:{port}"), PlainHttp::LoopbackOnly).unwrap()
}

fn s1() -> WireSlate {
    WireSlate::text(MediaType::JSON, S1.to_owned())
}

async fn raw_exchange(port: u16, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    String::from_utf8_lossy(&answer).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_an_s1_and_gets_the_s2_back() {
    let wallet = handler(None);
    let listener = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        wallet.clone(),
    )
    .await
    .unwrap();
    assert!(listener.local_addr().ip().is_loopback());
    let port = listener.local_addr().port();
    let version = client().check_version(&url(port)).await.unwrap();
    assert!(version.v2 && version.v3);
    let reply = client().receive_tx(&url(port), &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    listener.shutdown().await;
}

/// Connects every stream to the listener on loopback and records the host and port asked for.
struct ToListener {
    port: u16,
    asked: std::sync::Mutex<Vec<(String, u16)>>,
}

impl lepic_foreign::ForeignDialer for ToListener {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> lepic_foreign::ForeignDialFuture<'a> {
        Box::pin(async move {
            self.asked.lock().unwrap().push((host.to_owned(), port));
            let stream = TcpStream::connect(("127.0.0.1", self.port)).await?;
            Ok(Box::new(stream) as Box<dyn lepic_foreign::ForeignStream>)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialer_opens_every_connection_for_the_host_of_the_url() {
    let wallet = handler(None);
    let listener = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        wallet.clone(),
    )
    .await
    .unwrap();
    let dialer = Arc::new(ToListener {
        port: listener.local_addr().port(),
        asked: std::sync::Mutex::default(),
    });
    let client = ForeignClient::with_dialer(
        lepic_foreign::testing::client_settings(),
        webpki_tls_config().unwrap(),
        dialer.clone(),
    );
    // Nothing resolves this name: only the dialer can reach the wallet.
    let url = ForeignUrl::parse("http://wallet.invalid:3415", PlainHttp::Allowed).unwrap();
    let reply = client.receive_tx(&url, &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    assert_eq!(
        dialer.asked.lock().unwrap().first(),
        Some(&("wallet.invalid".to_owned(), 3415))
    );
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_reaches_the_sender_as_refused() {
    let listener = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(Some(Refusal::Rejected)),
    )
    .await
    .unwrap();
    let error = client()
        .receive_tx(&url(listener.local_addr().port()), &s1())
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Rpc(RpcError::Refused)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn takes_only_so_many_payments_a_minute() {
    let wallet = handler(None);
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.receives_per_minute = 2;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    for _ in 0..2 {
        client().receive_tx(&url(port), &s1()).await.unwrap();
    }
    let error = client().receive_tx(&url(port), &s1()).await.unwrap_err();
    assert!(matches!(error, ClientError::Rpc(RpcError::Refused)));
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 2);
    assert_eq!(wallet.refused.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slate_that_is_not_an_s1_does_not_spend_the_payment_budget() {
    let wallet = handler(None);
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.receives_per_minute = 1;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    for slate in ["{}", r#"{"id":"a","amount":"1"}"#, "[]"] {
        let answer = raw_exchange(port, receive_tx_request(slate).as_bytes()).await;
        assert!(!answer.contains("wallet not ready"), "{answer}");
    }
    let reply = client().receive_tx(&url(port), &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    let error = client().receive_tx(&url(port), &s1()).await.unwrap_err();
    assert!(matches!(error, ClientError::Rpc(RpcError::Refused)));
    assert_eq!(wallet.refused.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn takes_only_so_many_requests_a_minute() {
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.requests_per_minute = 2;
    let listener = listen(settings, handler(None)).await.unwrap();
    let port = listener.local_addr().port();
    for _ in 0..2 {
        let answer = raw_exchange(port, receive_tx_request("{}").as_bytes()).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }
    let error = client().check_version(&url(port)).await.unwrap_err();
    assert!(
        matches!(error, ClientError::Status { status: 503 }),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_that_are_not_payments_leave_room_for_payments() {
    let wallet = handler(None);
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.requests_per_minute = 2;
    settings.receives_per_minute = 2;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    for _ in 0..2 {
        client().check_version(&url(port)).await.unwrap();
    }
    let flood = client().check_version(&url(port)).await.unwrap_err();
    assert!(
        matches!(flood, ClientError::Status { status: 503 }),
        "{flood:?}"
    );
    let reply = client().receive_tx(&url(port), &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_junk_requests_leaves_room_for_payments() {
    let wallet = handler(None);
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.requests_per_minute = 3;
    settings.receives_per_minute = 2;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    for _ in 0..8 {
        let answer = raw_exchange(
            port,
            b"GET /elsewhere HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1"), "{answer}");
    }
    for _ in 0..4 {
        let _ = client().check_version(&url(port)).await;
    }
    let reply = client().receive_tx(&url(port), &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_request_budget_only_so_many_payments_are_read() {
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.requests_per_minute = 1;
    settings.receives_per_minute = 1;
    let listener = listen(settings, handler(None)).await.unwrap();
    let port = listener.local_addr().port();
    client().check_version(&url(port)).await.unwrap();
    client().receive_tx(&url(port), &s1()).await.unwrap();
    let error = client().receive_tx(&url(port), &s1()).await.unwrap_err();
    assert!(
        matches!(error, ClientError::Status { status: 503 }),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payment_refused_as_invalid_gives_its_budget_back() {
    let wallet = handler(None);
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.receives_per_minute = 1;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    let answer = raw_exchange(port, receive_tx_request(JUNK).as_bytes()).await;
    assert!(answer.contains("slate refused"), "{answer}");
    let reply = client().receive_tx(&url(port), &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    let error = client().receive_tx(&url(port), &s1()).await.unwrap_err();
    assert!(matches!(error, ClientError::Rpc(RpcError::Refused)));
    assert_eq!(wallet.refused.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_so_many_refused_payments_give_their_budget_back() {
    let wallet = handler(None);
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.receives_per_minute = 2;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    let mut refused = 0;
    for _ in 0..10 {
        let answer = raw_exchange(port, receive_tx_request(JUNK).as_bytes()).await;
        if answer.contains("slate refused") {
            refused += 1;
        } else {
            assert!(answer.contains("wallet not ready"), "{answer}");
        }
    }
    // Two given back, then the two slots of the minute: the wallet saw twice the budget.
    assert_eq!(refused, 4);
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 4);
    let error = client().receive_tx(&url(port), &s1()).await.unwrap_err();
    assert!(matches!(error, ClientError::Rpc(RpcError::Refused)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_only_post_to_the_foreign_endpoint() {
    let listener = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(None),
    )
    .await
    .unwrap();
    let port = listener.local_addr().port();
    let get = raw_exchange(port, b"GET /v2/foreign HTTP/1.1\r\nhost: x\r\n\r\n").await;
    assert!(get.starts_with("HTTP/1.1 405"), "{get}");
    let owner = raw_exchange(
        port,
        b"POST /v3/owner HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\n\r\n{}",
    )
    .await;
    assert!(owner.starts_with("HTTP/1.1 404"), "{owner}");
    let big = format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n",
        64 * 1024 * 1024
    );
    let big = raw_exchange(port, big.as_bytes()).await;
    assert!(big.starts_with("HTTP/1.1 413"), "{big}");
    let invoice = br#"{"jsonrpc":"2.0","method":"finalize_invoice_tx","id":1,"params":[{}]}"#;
    let request = format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{}",
        invoice.len(),
        std::str::from_utf8(invoice).unwrap()
    );
    let answer = raw_exchange(port, request.as_bytes()).await;
    assert!(answer.contains("-32601"), "{answer}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_caller_is_dropped_after_the_header_timeout() {
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.header_timeout = std::time::Duration::from_millis(200);
    let listener = listen(settings, handler(None)).await.unwrap();
    let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
    stream
        .write_all(b"POST /v2/foreign HTTP/1.1\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "the connection stayed open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_sent_too_slowly_is_answered_408() {
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.body_timeout = std::time::Duration::from_millis(200);
    let listener = listen(settings, handler(None)).await.unwrap();
    let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
    stream
        .write_all(b"POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n{")
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut answer),
    )
    .await
    .unwrap()
    .unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_chunked_body_is_answered_413() {
    let listener = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(None),
    )
    .await
    .unwrap();
    let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
    let length = lepic_foreign::rpc::MAX_BODY_LEN + 1;
    stream
        .write_all(
            format!("POST /v2/foreign HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n{length:x}\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let (mut read, mut write) = stream.into_split();
    let writing = tokio::spawn(async move {
        let block = vec![b' '; 64 * 1024];
        let mut left = length;
        while left > 0 {
            let size = left.min(block.len());
            if write.write_all(&block[..size]).await.is_err() {
                return;
            }
            left -= size;
        }
        let _ = write.write_all(b"\r\n0\r\n\r\n").await;
    });
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read.read_to_end(&mut answer),
    )
    .await
    .unwrap();
    writing.abort();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 413"), "{answer}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_that_never_takes_its_answer_is_dropped_and_frees_its_slot() {
    let big = format!(
        r#"{{"id":"0436430c-2b02-624c-2032-570501212b00","pad":"{}"}}"#,
        "x".repeat(4 * 1024 * 1024)
    );
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.max_connections = 1;
    settings.header_timeout = std::time::Duration::from_millis(300);
    settings.request_timeout = std::time::Duration::from_millis(300);
    settings.answer_timeout = std::time::Duration::from_millis(300);
    let listener = listen(settings, answering(None, big)).await.unwrap();
    let port = listener.local_addr().port();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stalled = socket.connect(listener.local_addr()).await.unwrap();
    stalled
        .write_all(receive_tx_request(S1).as_bytes())
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let version = client().check_version(&url(port)).await;
    assert!(version.is_ok(), "the slot stayed taken: {version:?}");
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_address_holds_only_its_share_of_the_connections() {
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.max_connections_per_address = 2;
    let listener = listen(settings, handler(None)).await.unwrap();
    let port = listener.local_addr().port();
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
        stream
            .write_all(b"POST /v2/foreign HTTP/1.1\r\n")
            .await
            .unwrap();
        held.push(stream);
    }
    // Accepted in order, so the held connections have their share before the next one.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let refused = client().check_version(&url(port)).await;
    assert!(refused.is_err(), "{refused:?}");

    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    client().check_version(&url(port)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_port_is_reported_as_in_use() {
    let first = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(None),
    )
    .await
    .unwrap();
    let port = first.local_addr().port();
    let second = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            port,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(None),
    )
    .await;
    assert!(matches!(second, Err(ListenError::PortInUse { port: p }) if p == port));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_listener_frees_its_port() {
    let listener = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            0,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(None),
    )
    .await
    .unwrap();
    let port = listener.local_addr().port();
    listener.shutdown().await;
    let error = client().check_version(&url(port)).await.unwrap_err();
    assert!(matches!(error, ClientError::Unreachable(_)));
    let again = listen(
        ListenSettings::new(
            Exposure::LocalOnly,
            port,
            lepic_foreign::testing::listen_limits(),
        ),
        handler(None),
    )
    .await;
    assert!(again.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wallet_without_the_foreign_api_is_not_found() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let error = client().check_version(&url(port)).await.unwrap_err();
    assert!(matches!(error, ClientError::NotFound));
}

/// A wallet that builds a fixed coinbase answer, keyed to the height it is asked for.
struct Mining;

impl ReceiveHandler for Mining {
    fn receive(&self, _slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async { Err(Refusal::Rejected) })
    }

    fn build_coinbase(&self, fees: BlockFees) -> BoxFuture<'_, Result<CoinbaseAnswer, Refusal>> {
        Box::pin(async move {
            if fees.height == 0 {
                return Err(Refusal::Unavailable);
            }
            Ok(CoinbaseAnswer {
                commit: [8; 33],
                proof: vec![1, 2],
                excess: [9; 33],
                excess_sig: [3; 64],
                key_id: [u8::try_from(fees.height % 256).unwrap(); 17],
            })
        })
    }
}

fn build_coinbase_request(height: u64) -> String {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{{"block_fees":{{"fees":"0","height":"{height}","key_id":null}}}}}}"#
    );
    format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn answer_body(answer: &str) -> serde_json::Value {
    let (_, body) = answer.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_build_coinbase_only_when_turned_on() {
    let settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    let off = listen(settings, Arc::new(Mining)).await.unwrap();
    let answer = raw_exchange(
        off.local_addr().port(),
        build_coinbase_request(5).as_bytes(),
    )
    .await;
    assert_eq!(answer_body(&answer)["error"]["code"], -32601);
    off.shutdown().await;

    let on = listen(
        settings.with_coinbase(CoinbaseAccess::LocalOnly),
        Arc::new(Mining),
    )
    .await
    .unwrap();
    let port = on.local_addr().port();
    let answer = answer_body(&raw_exchange(port, build_coinbase_request(5).as_bytes()).await);
    assert!(answer["error"].is_null());
    assert_eq!(answer["result"]["Ok"]["output"]["features"], "Coinbase");
    assert_eq!(answer["result"]["Ok"]["key_id"], "05".repeat(17));
    let refused = answer_body(&raw_exchange(port, build_coinbase_request(0).as_bytes()).await);
    assert_eq!(refused["result"]["Err"]["GenericError"], "wallet not ready");
    on.shutdown().await;
}

#[cfg(unix)]
async fn unix_exchange(path: &std::path::Path, request: &[u8]) -> serde_json::Value {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    answer_body(&String::from_utf8_lossy(&answer))
}

/// A caller beyond loopback gets the answer of a listener with the method off, unless the host
/// opened it. A Unix socket's callers are such callers, and Tor's reach the wallet that way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_opt_in_serves_a_caller_beyond_loopback() {
    let path = std::env::temp_dir().join(format!("lepic-coinbase-{}.sock", std::process::id()));
    let settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    let request = build_coinbase_request(5);

    let off = lepic_foreign::listen_unix(&path, settings, Arc::new(Mining))
        .await
        .unwrap();
    let unknown = unix_exchange(&path, request.as_bytes()).await;
    assert_eq!(unknown["error"]["code"], -32601);
    off.shutdown().await;

    let local = lepic_foreign::listen_unix(
        &path,
        settings.with_coinbase(CoinbaseAccess::LocalOnly),
        Arc::new(Mining),
    )
    .await
    .unwrap();
    assert_eq!(unix_exchange(&path, request.as_bytes()).await, unknown);
    local.shutdown().await;

    let remote = lepic_foreign::listen_unix(
        &path,
        settings.with_coinbase(CoinbaseAccess::Remote),
        Arc::new(Mining),
    )
    .await
    .unwrap();
    let served = unix_exchange(&path, request.as_bytes()).await;
    assert_eq!(served["result"]["Ok"]["output"]["features"], "Coinbase");
    remote.shutdown().await;
}

fn check_version_request() -> String {
    let body = r#"{"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}"#;
    format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Past every budget other requests are turned away and the node on this computer is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loopback_node_spends_no_request_budget() {
    let mut limits = lepic_foreign::testing::listen_limits();
    limits.requests_per_minute = 1;
    limits.receives_per_minute = 1;
    let settings = ListenSettings::new(Exposure::LocalOnly, 0, limits)
        .with_coinbase(CoinbaseAccess::LocalOnly);
    let listener = listen(settings, Arc::new(Mining)).await.unwrap();
    let port = listener.local_addr().port();

    let version = raw_exchange(port, check_version_request().as_bytes()).await;
    assert!(version.starts_with("HTTP/1.1 200"), "{version}");
    let spent = raw_exchange(port, check_version_request().as_bytes()).await;
    assert!(spent.starts_with("HTTP/1.1 503"), "{spent}");

    for height in 1..=5 {
        let request = build_coinbase_request(height);
        let answer = answer_body(&raw_exchange(port, request.as_bytes()).await);
        assert_eq!(answer["result"]["Ok"]["output"]["features"], "Coinbase");
    }
    listener.shutdown().await;
}

/// The address this computer reaches others from, when it has one beyond loopback.
fn address_beyond_loopback() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

/// Connections from beyond loopback that fill the listener leave a loopback node its own. Over
/// TCP they also get the answer of a listener with the method off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loopback_node_is_not_held_back_by_the_connection_cap() {
    let Some(address) = address_beyond_loopback() else {
        return;
    };
    let mut limits = lepic_foreign::testing::listen_limits();
    limits.max_connections = 1;
    let settings =
        ListenSettings::new(Exposure::Internet, 0, limits).with_coinbase(CoinbaseAccess::LocalOnly);
    let listener = listen(settings, Arc::new(Mining)).await.unwrap();
    let port = listener.local_addr().port();

    let mut stream = TcpStream::connect((address, port)).await.unwrap();
    stream
        .write_all(build_coinbase_request(5).as_bytes())
        .await
        .unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let answer = answer_body(&String::from_utf8_lossy(&answer));
    assert_eq!(answer["error"]["code"], -32601);

    let _held = TcpStream::connect((address, port)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let request = build_coinbase_request(5);
    let served = answer_body(&raw_exchange(port, request.as_bytes()).await);
    assert_eq!(served["result"]["Ok"]["output"]["features"], "Coinbase");
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wallet_without_a_coinbase_builder_refuses() {
    let wallet = handler(None);
    let settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    )
    .with_coinbase(CoinbaseAccess::LocalOnly);
    let listener = listen(settings, wallet).await.unwrap();
    let answer = answer_body(
        &raw_exchange(
            listener.local_addr().port(),
            build_coinbase_request(5).as_bytes(),
        )
        .await,
    );
    assert_eq!(answer["result"]["Err"]["GenericError"], "wallet not ready");
    listener.shutdown().await;
}
