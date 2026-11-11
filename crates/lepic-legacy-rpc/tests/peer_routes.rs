// SPDX-License-Identifier: Apache-2.0
//! The native endpoint on the listener's sockets: served and advertised only when the listener
//! is given one, under the key of the socket a request came in on.

// Helpers outside #[test] functions unwrap too; a failure there is a test failure.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lepic_legacy_rpc::{
    Exposure, ListenSettings, ListenerHandle, ListenerUrl, PlainHttp, ReceiveHandler, Refusal,
    RpcClient, listen, listen_with, webpki_tls_config,
};
use lepic_peer::{
    Advert, HandlerFuture, Network, PeerClient, PeerClientError, PeerClientSettings, PeerEndpoint,
    PeerRefusal, PeerTarget, SlateHandler, WebScheme,
};
use lepic_slate::codec::WireSlate;
use lepic_transport::transport::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const KEY_A: [u8; 32] = [0xa1; 32];
const KEY_B: [u8; 32] = [0xb2; 32];

/// The foreign API is not used here.
struct NoLegacy;

impl ReceiveHandler for NoLegacy {
    fn receive(&self, _slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async { Err(Refusal::Rejected) })
    }
}

/// Answers an envelope with its bytes reversed, counting calls; refuses an envelope that starts
/// with `I` and does not read one that starts with `X`.
#[derive(Default)]
struct Reversing {
    calls: AtomicUsize,
}

impl SlateHandler for Reversing {
    fn receive(&self, envelope: Vec<u8>) -> HandlerFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if envelope.first() == Some(&b'I') {
                return Err(PeerRefusal::Refused);
            }
            Ok(envelope.into_iter().rev().collect())
        })
    }

    /// Bytes that start with `X` are not an envelope.
    fn check(&self, envelope: &[u8]) -> Result<(), PeerRefusal> {
        if envelope.first() == Some(&b'X') {
            return Err(PeerRefusal::UnsupportedFormat);
        }
        Ok(())
    }
}

fn settings() -> ListenSettings {
    ListenSettings::new(
        Exposure::LocalOnly,
        0,
        lepic_legacy_rpc::testing::listen_limits(),
    )
}

async fn serving(settings: ListenSettings, seal: [u8; 32]) -> (ListenerHandle, Arc<Reversing>) {
    let wallet = Arc::new(Reversing::default());
    let endpoint = PeerEndpoint::new(wallet.clone(), seal, Network::Floonet);
    let listener = listen_with(settings, Arc::new(NoLegacy), Some(Arc::new(endpoint)))
        .await
        .unwrap();
    (listener, wallet)
}

fn target(port: u16) -> PeerTarget {
    PeerTarget::new(WebScheme::Http, "127.0.0.1", port, "/api/v1/inbox").unwrap()
}

fn peer_client() -> PeerClient {
    PeerClient::new(PeerClientSettings::default(), webpki_tls_config().unwrap())
}

fn rpc_client() -> RpcClient {
    RpcClient::new(
        lepic_legacy_rpc::testing::client_settings(),
        webpki_tls_config().unwrap(),
    )
}

fn url(port: u16) -> ListenerUrl {
    ListenerUrl::parse(&format!("http://127.0.0.1:{port}"), PlainHttp::LoopbackOnly).unwrap()
}

/// Writes `request` and reads the answer's head and as much body as comes in a short while,
/// without writing anything more.
async fn exchange(port: u16, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await;
        match read {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                answer.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&answer);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
        }
    }
    String::from_utf8_lossy(&answer).into_owned()
}

fn check_version_request(host: &str) -> String {
    let body = r#"{"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}"#;
    format!(
        "POST /v2/foreign HTTP/1.1\r\nhost: {host}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_endpoint_there_is_no_advert_and_no_route() {
    let listener = listen(settings(), Arc::new(NoLegacy)).await.unwrap();
    let port = listener.local_addr().port();
    let version = rpc_client().check_version(&url(port)).await.unwrap();
    assert!(version.v2 && version.v3);
    assert_eq!(version.lepic, None);
    let raw = exchange(port, &check_version_request("x").into_bytes()).await;
    assert!(!raw.contains("lepic"), "{raw}");
    let error = peer_client().info(&target(port)).await.unwrap_err();
    assert!(matches!(error, PeerClientError::NotFound), "{error:?}");
    let error = peer_client()
        .post_slate(&target(port), b"envelope")
        .await
        .unwrap_err();
    assert!(matches!(error, PeerClientError::NotFound), "{error:?}");
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertises_the_endpoint_and_describes_it() {
    let (listener, _) = serving(settings(), KEY_A).await;
    let port = listener.local_addr().port();
    let version = rpc_client().check_version(&url(port)).await.unwrap();
    assert!(version.v2 && version.v3);
    assert_eq!(version.lepic, Some(Advert::new(KEY_A)));
    let info = peer_client().info(&target(port)).await.unwrap();
    assert_eq!(info.protocol, 2);
    assert_eq!(info.formats, ["lepic.v1"]);
    assert_eq!(info.network, "floonet");
    assert_eq!(info.seal_key().unwrap(), KEY_A);
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_key_is_the_sockets_whatever_host_is_named() {
    let (a, _) = serving(settings(), KEY_A).await;
    let (b, _) = serving(settings(), KEY_B).await;
    let port_a = a.local_addr().port();
    let port_b = b.local_addr().port();
    let other_host = format!("127.0.0.1:{port_b}");
    let raw = exchange(port_a, &check_version_request(&other_host).into_bytes()).await;
    assert!(raw.contains(&"a1".repeat(32)), "{raw}");
    assert!(!raw.contains(&"b2".repeat(32)), "{raw}");
    let get =
        format!("GET /api/v1/inbox HTTP/1.1\r\nhost: {other_host}\r\nconnection: close\r\n\r\n");
    let raw = exchange(port_a, get.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(raw.contains(&"a1".repeat(32)), "{raw}");
    assert!(!raw.contains(&"b2".repeat(32)), "{raw}");
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_envelope_gets_the_same_reply_once_taken() {
    let (listener, wallet) = serving(settings(), KEY_A).await;
    let port = listener.local_addr().port();
    let first = peer_client()
        .post_slate(&target(port), b"S1 envelope")
        .await
        .unwrap();
    let again = peer_client()
        .post_slate(&target(port), b"S1 envelope")
        .await
        .unwrap();
    assert_eq!(first, b"epolevne 1S");
    assert_eq!(again, first);
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_slate_is_422_refused() {
    let (listener, _) = serving(settings(), KEY_A).await;
    let port = listener.local_addr().port();
    let error = peer_client()
        .post_slate(&target(port), b"I1 envelope")
        .await
        .unwrap_err();
    assert!(matches!(error, PeerClientError::Refused), "{error:?}");
    let body = "I1 envelope";
    let post = format!(
        "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let raw = exchange(port, post.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 422"), "{raw}");
    assert!(raw.contains("application/problem+json"), "{raw}");
    assert!(raw.contains(r#""code":"refused""#), "{raw}");
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_body_is_refused_before_it_is_read() {
    let (listener, wallet) = serving(settings(), KEY_A).await;
    let port = listener.local_addr().port();
    // Only the head is written: the answer comes without the body.
    let post = "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: 69633\r\n\r\n";
    let raw = exchange(port, post.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 413"), "{raw}");
    assert!(raw.contains(r#""code":"too_large""#), "{raw}");
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_media_type_is_415_and_another_method_405() {
    let (listener, wallet) = serving(settings(), KEY_A).await;
    let port = listener.local_addr().port();
    let body = "{}";
    let post = format!(
        "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let raw = exchange(port, post.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 415"), "{raw}");
    assert!(raw.contains(r#""code":"unsupported_format""#), "{raw}");
    let put = "PUT /api/v1/inbox HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n";
    let raw = exchange(port, put.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 405"), "{raw}");
    let old = "GET /api/v1/inbox/slates HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n";
    let raw = exchange(port, old.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 404"), "{raw}");
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_the_payment_budget_is_rate_limited_with_retry_after() {
    let mut limited = settings();
    limited.receives_per_minute = 1;
    let (listener, wallet) = serving(limited, KEY_A).await;
    let port = listener.local_addr().port();
    // A refused slate gives its place back.
    peer_client()
        .post_slate(&target(port), b"I1 envelope")
        .await
        .unwrap_err();
    peer_client()
        .post_slate(&target(port), b"first")
        .await
        .unwrap();
    let error = peer_client()
        .post_slate(&target(port), b"second")
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PeerClientError::RateLimited {
                retry_after: Some(retry)
            } if retry == Duration::from_secs(60)
        ),
        "{error:?}"
    );
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 2);
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_that_is_not_an_envelope_is_refused_before_the_payment_budget() {
    let mut limited = settings();
    limited.receives_per_minute = 1;
    let (listener, wallet) = serving(limited, KEY_A).await;
    let port = listener.local_addr().port();
    peer_client()
        .post_slate(&target(port), b"first")
        .await
        .unwrap();
    // The budget is spent; each of these is answered for what it is, not as over the budget.
    let json = "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
    let raw = exchange(port, json.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 415"), "{raw}");
    let long = "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: 2000000\r\n\r\n";
    let raw = exchange(port, long.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 413"), "{raw}");
    let junk = "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: 4\r\nconnection: close\r\n\r\nXjnk";
    let raw = exchange(port, junk.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 415"), "{raw}");
    assert!(raw.contains(r#""code":"unsupported_format""#), "{raw}");
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_still_arriving_holds_no_payment_place() {
    let mut limited = settings();
    limited.receives_per_minute = 1;
    let (listener, wallet) = serving(limited, KEY_A).await;
    let port = listener.local_addr().port();
    // A post whose body has not all come in yet.
    let mut slow = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let head = "POST /api/v1/inbox HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: 10\r\n\r\nslow";
    slow.write_all(head.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reply = peer_client()
        .post_slate(&target(port), b"first")
        .await
        .unwrap();
    assert_eq!(reply, b"tsrif");
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    drop(slow);
    listener.shutdown().await;
}

/// The socket a local tor reaches, as behind an onion: it serves the endpoint it was given, and
/// none without one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unix_socket_serves_its_endpoint_as_behind_an_onion() {
    let path = std::env::temp_dir().join(format!("lepic-peer-routes-{}.sock", std::process::id()));
    let get = b"GET /api/v1/inbox HTTP/1.1\r\nhost: x.onion\r\nconnection: close\r\n\r\n";
    let unix_exchange = |request: &'static [u8]| {
        let path = path.clone();
        async move {
            let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
            stream.write_all(request).await.unwrap();
            let mut answer = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut answer)).await;
            String::from_utf8_lossy(&answer).into_owned()
        }
    };

    let without = lepic_legacy_rpc::listen_unix(&path, settings(), Arc::new(NoLegacy))
        .await
        .unwrap();
    let raw = unix_exchange(get).await;
    assert!(raw.starts_with("HTTP/1.1 404"), "{raw}");
    without.shutdown().await;

    let endpoint = PeerEndpoint::new(Arc::new(Reversing::default()), KEY_B, Network::Mainnet);
    let with = lepic_legacy_rpc::listen_unix_with(
        &path,
        settings(),
        Arc::new(NoLegacy),
        Some(Arc::new(endpoint)),
    )
    .await
    .unwrap();
    let raw = unix_exchange(get).await;
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(raw.contains(r#""network":"mainnet""#), "{raw}");
    assert!(raw.contains(&"b2".repeat(32)), "{raw}");
    with.shutdown().await;
}

/// A public listener serves the inbox and `/v2/foreign` only: the owner API's paths under
/// `/api/v1/` are never served on it, with or without an endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_api_v1_paths_are_not_found_on_a_public_listener() {
    let (listener, wallet) = serving(settings(), KEY_A).await;
    let port = listener.local_addr().port();
    for request in [
        "GET /api/v1/status HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
        "POST /api/v1/payments HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
        "GET /api/v1/ HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
        "GET /api/v1/inbox/ HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
    ] {
        let raw = exchange(port, request.as_bytes()).await;
        assert!(raw.starts_with("HTTP/1.1 404"), "{request}: {raw}");
    }
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    listener.shutdown().await;
}
