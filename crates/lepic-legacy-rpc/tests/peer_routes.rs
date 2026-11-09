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
/// with `I`.
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
    PeerTarget::new(WebScheme::Http, "127.0.0.1", port, "/v1/peer").unwrap()
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
    assert_eq!(info.protocol, 1);
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
    let get = format!("GET /v1/peer HTTP/1.1\r\nhost: {other_host}\r\nconnection: close\r\n\r\n");
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
        "POST /v1/peer/slates HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
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
    let post = "POST /v1/peer/slates HTTP/1.1\r\nhost: x\r\ncontent-type: application/vnd.lepic.epictx\r\ncontent-length: 69633\r\n\r\n";
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
        "POST /v1/peer/slates HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let raw = exchange(port, post.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 415"), "{raw}");
    assert!(raw.contains(r#""code":"unsupported_format""#), "{raw}");
    let get = "GET /v1/peer/slates HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n";
    let raw = exchange(port, get.as_bytes()).await;
    assert!(raw.starts_with("HTTP/1.1 405"), "{raw}");
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
