//! The client against the listener on loopback, with a wallet that answers every S1 with a
//! fixed S2.

// Helpers outside #[test] functions unwrap too; a failure there is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lepic_foreign::{
    ClientError, ClientSettings, Exposure, ForeignClient, ForeignUrl, HttpTransport, ListenError,
    ListenSettings, PlainHttp, ReceiveHandler, Refusal, RpcError, listen, webpki_tls_config,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[{"id":"0"}]}"#;
const S2: &str =
    r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[]}"#;

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
    ForeignClient::new(ClientSettings::default(), webpki_tls_config().unwrap())
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
    let listener = listen(ListenSettings::new(Exposure::LocalOnly, 0), wallet.clone())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_holds_the_answer_for_its_slate() {
    let listener = listen(ListenSettings::new(Exposure::LocalOnly, 0), handler(None))
        .await
        .unwrap();
    let transport = HttpTransport::new(client());
    let to = Destination::new(url(listener.local_addr().port()).as_uri());
    transport.deliver(&to, &s1()).await.unwrap();
    assert_eq!(transport.take_reply("other"), None);
    let reply = transport
        .take_reply("0436430C-2B02-624C-2032-570501212B00")
        .unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b00"),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_refuses_an_answer_for_another_slate() {
    let other = S2.replace("212b00", "212b01");
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
        answering(None, other),
    )
    .await
    .unwrap();
    let transport = HttpTransport::new(client());
    let to = Destination::new(url(listener.local_addr().port()).as_uri());

    let error = transport.deliver(&to, &s1()).await.unwrap_err();

    let TransportError::Backend { source, .. } = error else {
        panic!("{error:?}");
    };
    assert!(matches!(
        source.downcast_ref::<ClientError>(),
        Some(ClientError::Rpc(RpcError::Malformed))
    ));
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b01"),
        None
    );
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b00"),
        None
    );
}

#[test]
fn transport_hands_nothing_out_inbound() {
    let transport = HttpTransport::new(client());
    assert!(Transport::inbound(&transport).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_reaches_the_sender_as_refused() {
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
async fn past_the_request_budget_only_so_many_payments_are_read() {
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
    settings.receives_per_minute = 1;
    let listener = listen(settings, wallet.clone()).await.unwrap();
    let port = listener.local_addr().port();
    let junk = r#"{"id":"x","amount":"1","participant_data":[]}"#;
    for _ in 0..3 {
        let answer = raw_exchange(port, receive_tx_request(junk).as_bytes()).await;
        assert!(answer.contains("slate refused"), "{answer}");
    }
    let reply = client().receive_tx(&url(port), &s1()).await.unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    let error = client().receive_tx(&url(port), &s1()).await.unwrap_err();
    assert!(matches!(error, ClientError::Rpc(RpcError::Refused)));
    assert_eq!(wallet.refused.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_only_post_to_the_foreign_endpoint() {
    let listener = listen(ListenSettings::new(Exposure::LocalOnly, 0), handler(None))
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let listener = listen(ListenSettings::new(Exposure::LocalOnly, 0), handler(None))
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
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
    let first = listen(ListenSettings::new(Exposure::LocalOnly, 0), handler(None))
        .await
        .unwrap();
    let port = first.local_addr().port();
    let second = listen(
        ListenSettings::new(Exposure::LocalOnly, port),
        handler(None),
    )
    .await;
    assert!(matches!(second, Err(ListenError::PortInUse { port: p }) if p == port));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_listener_frees_its_port() {
    let listener = listen(ListenSettings::new(Exposure::LocalOnly, 0), handler(None))
        .await
        .unwrap();
    let port = listener.local_addr().port();
    listener.shutdown().await;
    let error = client().check_version(&url(port)).await.unwrap_err();
    assert!(matches!(error, ClientError::Unreachable(_)));
    let again = listen(
        ListenSettings::new(Exposure::LocalOnly, port),
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
