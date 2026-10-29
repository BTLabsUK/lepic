// SPDX-License-Identifier: Apache-2.0
//! Hostile callers of the listener, speaking HTTP and JSON-RPC the way a client never does:
//! batches and pipelines that try to carry more payments than the budget allows, framing that
//! disagrees with itself, declared sizes far past the limit, header floods, deep JSON and paths
//! that are almost the endpoint. The listener answers each with an error or a bounded answer,
//! hands the wallet no more payments than its budget, and keeps serving the next caller.

// Helpers outside #[test] functions unwrap too; a failure there is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lepic_foreign::{
    Exposure, ForeignClient, ForeignUrl, ListenSettings, ListenerHandle, PlainHttp, ReceiveHandler,
    Refusal, listen, webpki_tls_config,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::transport::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[{"id":"0"}]}"#;
const S2: &str =
    r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[]}"#;

struct Counting {
    calls: AtomicUsize,
}

impl ReceiveHandler for Counting {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if slate.as_text() == Some(S1) {
                Ok(WireSlate::text(MediaType::JSON, S2.to_owned()))
            } else {
                Err(Refusal::Rejected)
            }
        })
    }
}

async fn listener(receives_per_minute: u32) -> (ListenerHandle, Arc<Counting>, u16) {
    let wallet = Arc::new(Counting {
        calls: AtomicUsize::new(0),
    });
    let mut settings = ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_foreign::testing::listen_limits(),
    );
    settings.receives_per_minute = receives_per_minute;
    let handle = listen(settings, wallet.clone()).await.unwrap();
    let port = handle.local_addr().port();
    (handle, wallet, port)
}

fn post(body: &str) -> String {
    format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn receive_tx(id: u32) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"receive_tx","id":{id},"params":[{S1},null,null]}}"#)
}

/// Everything the listener sends back within a few seconds, or until it closes.
async fn exchange(port: u16, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // A listener may close mid-write on a request it refuses early; that is an answer too.
    let _ = stream.write_all(request).await;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut answer)).await;
    String::from_utf8_lossy(&answer).into_owned()
}

/// The listener still takes an honest payment after whatever came before.
async fn assert_still_serving(port: u16) {
    let client = ForeignClient::new(
        lepic_foreign::testing::client_settings(),
        webpki_tls_config().unwrap(),
    );
    let url =
        ForeignUrl::parse(&format!("http://127.0.0.1:{port}"), PlainHttp::LoopbackOnly).unwrap();
    client.check_version(&url).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_json_rpc_batch_carries_no_payment_past_the_budget() {
    let (_handle, wallet, port) = listener(2).await;
    let batch = format!(
        "[{}]",
        (0..50).map(receive_tx).collect::<Vec<_>>().join(",")
    );
    let answer = exchange(port, post(&batch).as_bytes()).await;
    assert!(answer.starts_with("HTTP/1.1"), "{answer}");
    assert!(
        wallet.calls.load(Ordering::SeqCst) <= 1,
        "one request handed the wallet {} payments",
        wallet.calls.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipelined_payments_on_one_connection_stay_within_the_budget() {
    let (_handle, wallet, port) = listener(2).await;
    let pipelined: String = (0..20).map(|id| post(&receive_tx(id))).collect();
    let _ = exchange(port, pipelined.as_bytes()).await;
    assert!(
        wallet.calls.load(Ordering::SeqCst) <= 2,
        "one connection handed the wallet {} payments",
        wallet.calls.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_framing_is_refused_before_the_wallet_sees_it() {
    let (_handle, wallet, port) = listener(10).await;
    let body = receive_tx(1);
    let smuggled = [
        // Both a length and chunked encoding.
        format!(
            "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len(),
            body.len()
        ),
        // Two lengths that disagree.
        format!(
            "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\ncontent-length: 5\r\n\r\n{body}",
            body.len()
        ),
        // A length that is not a number.
        format!(
            "POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: +{}\r\n\r\n{body}",
            body.len()
        ),
    ];
    for (index, request) in smuggled.iter().enumerate() {
        let answer = exchange(port, request.as_bytes()).await;
        // RFC 9112 6.3: with both headers the chunked body is the message and the connection
        // must close after the answer, so nothing can follow it on the same connection.
        let closed_after_chunked = index == 0 && answer.contains("connection: close");
        assert!(
            answer.is_empty() || answer.starts_with("HTTP/1.1 4") || closed_after_chunked,
            "{request:?} -> {answer}"
        );
    }
    assert!(wallet.calls.load(Ordering::SeqCst) <= 1);
    assert_still_serving(port).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_length_past_the_limit_is_refused_without_waiting_for_the_body() {
    let (_handle, wallet, port) = listener(10).await;
    let started = std::time::Instant::now();
    let answer = exchange(
        port,
        b"POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: 1000000000000\r\n\r\n{",
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 413"), "{answer}");
    assert!(started.elapsed() < Duration::from_secs(3));
    let answer = exchange(
        port,
        b"POST /v2/foreign HTTP/1.1\r\nhost: x\r\ncontent-length: 99999999999999999999999\r\n\r\n{",
    )
    .await;
    assert!(
        answer.is_empty() || answer.starts_with("HTTP/1.1 4"),
        "{answer}"
    );
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    assert_still_serving(port).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_headers_is_refused() {
    let (_handle, wallet, port) = listener(10).await;
    let body = receive_tx(1);
    let headers: String = (0..5_000)
        .map(|n| format!("x-h{n}: {}\r\n", "a".repeat(64)))
        .collect();
    let request = format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: x\r\n{headers}content-length: {}\r\n\r\n{body}",
        body.len()
    );
    let answer = exchange(port, request.as_bytes()).await;
    assert!(
        answer.is_empty() || answer.starts_with("HTTP/1.1 4"),
        "{answer:.200}"
    );
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    assert_still_serving(port).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deeply_nested_json_is_answered_with_an_error() {
    let (_handle, wallet, port) = listener(10).await;
    for depth in [200usize, 100_000] {
        let nested = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        for body in [
            nested.clone(),
            format!(r#"{{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{nested}]}}"#),
            format!(
                r#"{{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{{"id":{nested}}},null,null]}}"#
            ),
        ] {
            let answer = exchange(port, post(&body).as_bytes()).await;
            assert!(
                answer.starts_with("HTTP/1.1"),
                "depth {depth}: {answer:.200}"
            );
            assert!(!answer.contains(S2), "depth {depth}: answered as a payment");
        }
    }
    assert!(wallet.calls.load(Ordering::SeqCst) <= 2);
    assert_still_serving(port).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_that_are_almost_a_payment_are_not_one() {
    let (_handle, wallet, port) = listener(10).await;
    let bodies = [
        // The method named twice.
        format!(
            r#"{{"jsonrpc":"2.0","method":"check_version","method":"receive_tx","id":1,"params":[{S1},null,null]}}"#
        ),
        // A method name that differs only in case or by a trailing character.
        format!(r#"{{"jsonrpc":"2.0","method":"Receive_tx","id":1,"params":[{S1},null,null]}}"#),
        format!(
            r#"{{"jsonrpc":"2.0","method":"receive_tx\u0000","id":1,"params":[{S1},null,null]}}"#
        ),
        // Owner-API methods a foreign caller must never reach.
        format!(r#"{{"jsonrpc":"2.0","method":"finalize_tx","id":1,"params":[{S1}]}}"#),
        r#"{"jsonrpc":"2.0","method":"init_send_tx","id":1,"params":[{"amount":1}]}"#.to_owned(),
        r#"{"jsonrpc":"2.0","method":"retrieve_summary_info","id":1,"params":[true,1]}"#.to_owned(),
        // An id far past any sensible length.
        format!(
            r#"{{"jsonrpc":"2.0","method":"receive_tx","id":"{}","params":[{S1},null,null]}}"#,
            "9".repeat(100_000)
        ),
        // Not UTF-8.
        String::from_utf8_lossy(&[0xff, 0xfe, b'{', b'}']).into_owned(),
    ];
    for body in &bodies {
        let answer = exchange(port, post(body).as_bytes()).await;
        assert!(
            answer.starts_with("HTTP/1.1"),
            "{body:.120} -> {answer:.200}"
        );
        assert!(
            !answer.contains("participant_data"),
            "{body:.120} was answered as a payment"
        );
    }
    // Only the duplicated-method case may have reached the wallet, and then as one payment.
    assert!(wallet.calls.load(Ordering::SeqCst) <= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paths_that_are_almost_the_endpoint_are_not_found() {
    let (_handle, wallet, port) = listener(10).await;
    let body = receive_tx(1);
    for path in [
        "/v2/foreign/",
        "//v2/foreign",
        "/v2/foreign/../owner",
        "/v2/owner",
        "/v2/Foreign",
        "/v2/foreign%00",
        "http://evil.example/v2/owner",
        "*",
    ] {
        let request = format!(
            "POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let answer = exchange(port, request.as_bytes()).await;
        assert!(
            answer.is_empty() || answer.starts_with("HTTP/1.1 4"),
            "{path} -> {answer:.200}"
        );
    }
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    assert_still_serving(port).await;
}
