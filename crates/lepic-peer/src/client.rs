// SPDX-License-Identifier: Apache-2.0
//! Reads a listener's endpoint and posts an envelope to it: hyper over rustls, bounded answers
//! and timeouts, no redirects. Each problem the endpoint answers with is its own error.

use std::error::Error;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tower_service::Service;
use tracing::debug;

use crate::error::PeerClientError;
use crate::origin::PeerTarget;
use crate::problem::{MAX_PROBLEM_LEN, PROBLEM_MEDIA_TYPE};
use crate::{ENVELOPE_MEDIA_TYPE, MAX_ENVELOPE_LEN};

/// Limits of [`PeerClient`].
#[derive(Debug, Clone, Copy)]
pub struct PeerClientSettings {
    pub connect_timeout: Duration,
    /// From sending a request to the last byte of its answer.
    pub request_timeout: Duration,
    /// The longest reply envelope read.
    pub max_response_bytes: usize,
}

impl Default for PeerClientSettings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            request_timeout: Duration::from_secs(60),
            max_response_bytes: MAX_ENVELOPE_LEN,
        }
    }
}

/// A byte stream to a listener, before TLS.
pub trait PeerStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> PeerStream for T {}

pub type PeerDialFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn PeerStream>>> + Send + 'a>>;

/// Opens the stream for each new connection, such as through tor. `host` and `port` are those
/// of the target; the dialer chooses where the bytes go and bounds the time it takes.
pub trait PeerDialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> PeerDialFuture<'a>;
}

/// The kind of this computer's own address a host resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Loopback,
    Unspecified,
}

impl AddressClass {
    /// The class of `ip` when it is this computer's own.
    pub fn of_this_computer(ip: IpAddr) -> Option<Self> {
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            Some(Self::Loopback)
        } else if ip.is_unspecified() {
            Some(Self::Unspecified)
        } else {
            None
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified",
        }
    }
}

/// Why an address is not connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    ThisComputer(AddressClass),
    LocalNetwork,
}

/// A [`Refusal`], carried inside the connector's [`io::Error`] until the client turns it into
/// [`PeerClientError::ThisComputer`] or [`PeerClientError::LocalNetwork`].
#[derive(Debug, thiserror::Error)]
#[error("the address is not one the client connects to ({0:?})")]
struct Refused(Refusal);

/// The [`Refused`] refusal in `error` or one of its causes.
fn refusal_in(error: &(dyn Error + 'static)) -> Option<Refusal> {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if let Some(Refused(refusal)) = error.downcast_ref::<Refused>() {
            return Some(*refusal);
        }
        let inner = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<Refused>());
        if let Some(Refused(refusal)) = inner {
            return Some(*refusal);
        }
        cause = error.source();
    }
    None
}

/// The addresses a connection may not go to: this computer's own, and with `local_network` the
/// addresses that rule names.
#[derive(Clone, Copy)]
struct AddressRule {
    this_computer: fn(IpAddr) -> Option<AddressClass>,
    local_network: Option<fn(IpAddr) -> bool>,
}

impl AddressRule {
    const OTHER_COMPUTERS: Self = Self {
        this_computer: AddressClass::of_this_computer,
        local_network: None,
    };

    fn refusal(&self, ip: IpAddr) -> Option<Refusal> {
        let ip = ip.to_canonical();
        if let Some(class) = (self.this_computer)(ip) {
            return Some(Refusal::ThisComputer(class));
        }
        match self.local_network {
            Some(is_local) if is_local(ip) => Some(Refusal::LocalNetwork),
            _ => None,
        }
    }
}

fn refused(refusal: Refusal) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, Refused(refusal))
}

/// Resolves `host` and connects to the first of its addresses that `rule` allows. The rule is
/// checked on each resolved address before connecting and again on the address connected to.
async fn connect_under_rule(host: &str, port: u16, rule: AddressRule) -> io::Result<TcpStream> {
    let mut refusal = None;
    let mut failed = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        if let Some(found) = rule.refusal(address.ip()) {
            refusal = Some(found);
            continue;
        }
        match TcpStream::connect(address).await {
            Ok(stream) => {
                if let Some(found) = rule.refusal(stream.peer_addr()?.ip()) {
                    return Err(refused(found));
                }
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => failed = Some(error),
        }
    }
    Err(failed.unwrap_or_else(|| match refusal {
        Some(found) => refused(found),
        None => io::Error::new(io::ErrorKind::NotFound, "the host has no address"),
    }))
}

#[derive(Clone)]
enum PeerConnector {
    Direct(HttpConnector),
    Ruled {
        connect_timeout: Duration,
        rule: AddressRule,
    },
    Dialed(Arc<dyn PeerDialer>),
}

struct Dialed(TokioIo<Box<dyn PeerStream>>);

impl Connection for Dialed {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for Dialed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for Dialed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Service<Uri> for PeerConnector {
    type Response = Dialed;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Dialed>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Direct(http) => http.poll_ready(cx).map_err(io::Error::other),
            Self::Ruled { .. } | Self::Dialed(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            Self::Direct(http) => {
                let connecting = http.call(uri);
                Box::pin(async move {
                    let stream = connecting.await.map_err(io::Error::other)?.into_inner();
                    Ok(Dialed(
                        TokioIo::new(Box::new(stream) as Box<dyn PeerStream>),
                    ))
                })
            }
            Self::Ruled {
                connect_timeout,
                rule,
            } => {
                let (connect_timeout, rule) = (*connect_timeout, *rule);
                Box::pin(async move {
                    let (host, port) = dial_target(&uri)?;
                    let stream = tokio::time::timeout(
                        connect_timeout,
                        connect_under_rule(&host, port, rule),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "connecting took too long")
                    })??;
                    Ok(Dialed(
                        TokioIo::new(Box::new(stream) as Box<dyn PeerStream>),
                    ))
                })
            }
            Self::Dialed(dialer) => {
                let dialer = Arc::clone(dialer);
                Box::pin(async move {
                    let (host, port) = dial_target(&uri)?;
                    let stream = dialer.dial(&host, port).await?;
                    Ok(Dialed(TokioIo::new(stream)))
                })
            }
        }
    }
}

/// The host, without brackets around an IPv6 literal, and the port, the scheme's default when
/// the URL gives none.
fn dial_target(uri: &Uri) -> io::Result<(String, u16)> {
    let host = uri
        .host()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .filter(|host| !host.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "url has no host"))?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("http") => 80,
        _ => 443,
    });
    Ok((host.to_owned(), port))
}

/// Talks to listeners' native endpoints. Cheap to clone; clones share the connection pool.
#[derive(Clone)]
pub struct PeerClient {
    client: Client<HttpsConnector<PeerConnector>, Full<Bytes>>,
    settings: PeerClientSettings,
}

impl std::fmt::Debug for PeerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerClient").finish_non_exhaustive()
    }
}

impl PeerClient {
    /// Construction does no I/O; requests need a Tokio runtime.
    pub fn new(settings: PeerClientSettings, tls: Arc<ClientConfig>) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(settings.connect_timeout));
        http.set_nodelay(true);
        Self::build(settings, tls, PeerConnector::Direct(http))
    }

    /// As [`PeerClient::new`], but it never connects to this computer: a host that is, or
    /// resolves to, a loopback or unspecified address fails with
    /// [`PeerClientError::ThisComputer`] naming the class. The check is made on the addresses
    /// each connection resolves.
    pub fn to_other_computers(settings: PeerClientSettings, tls: Arc<ClientConfig>) -> Self {
        Self::ruled(settings, tls, AddressRule::OTHER_COMPUTERS)
    }

    /// The client for a host a payment link names. As [`PeerClient::to_other_computers`], and
    /// an address `is_local_network` names fails with [`PeerClientError::LocalNetwork`]. Both
    /// checks are made on the addresses each connection resolves and on the address it
    /// connects to, so a public name that resolves to a local address is refused too. The
    /// caller gives the local ranges; there is no rule that allows every address.
    pub fn to_link_hosts(
        settings: PeerClientSettings,
        tls: Arc<ClientConfig>,
        is_local_network: fn(IpAddr) -> bool,
    ) -> Self {
        let rule = AddressRule {
            local_network: Some(is_local_network),
            ..AddressRule::OTHER_COMPUTERS
        };
        Self::ruled(settings, tls, rule)
    }

    fn ruled(settings: PeerClientSettings, tls: Arc<ClientConfig>, rule: AddressRule) -> Self {
        let route = PeerConnector::Ruled {
            connect_timeout: settings.connect_timeout,
            rule,
        };
        Self::build(settings, tls, route)
    }

    /// As [`PeerClient::new`], but every connection is opened by `dialer`. TLS and the `Host`
    /// header still use the target's host.
    pub fn with_dialer(
        settings: PeerClientSettings,
        tls: Arc<ClientConfig>,
        dialer: Arc<dyn PeerDialer>,
    ) -> Self {
        Self::build(settings, tls, PeerConnector::Dialed(dialer))
    }

    fn build(settings: PeerClientSettings, tls: Arc<ClientConfig>, route: PeerConnector) -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(Arc::unwrap_or_clone(tls))
            .https_or_http()
            .enable_http1()
            .wrap_connector(route);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { client, settings }
    }

    /// Posts `envelope` to `target` and returns the reply envelope as it came.
    pub async fn post_slate(
        &self,
        target: &PeerTarget,
        envelope: &[u8],
    ) -> Result<Vec<u8>, PeerClientError> {
        if envelope.len() > MAX_ENVELOPE_LEN {
            return Err(PeerClientError::EnvelopeTooLarge {
                len: envelope.len(),
                max: MAX_ENVELOPE_LEN,
            });
        }
        let request = Request::builder()
            .method(Method::POST)
            .uri(parse_uri(&target.envelope_uri())?)
            .header(CONTENT_TYPE, ENVELOPE_MEDIA_TYPE)
            .header(ACCEPT, ENVELOPE_MEDIA_TYPE)
            .body(Full::new(Bytes::copy_from_slice(envelope)))
            .map_err(|error| PeerClientError::Unreachable(Box::new(error)))?;
        let (headers, body) = self.send(request, self.settings.max_response_bytes).await?;
        if !media_is(&headers, ENVELOPE_MEDIA_TYPE) {
            return Err(PeerClientError::NotEnvelope);
        }
        Ok(body)
    }

    async fn send(
        &self,
        request: Request<Full<Bytes>>,
        max: usize,
    ) -> Result<(HeaderMap, Vec<u8>), PeerClientError> {
        tokio::time::timeout(self.settings.request_timeout, self.exchange(request, max))
            .await
            .map_err(|_| PeerClientError::Timeout)?
    }

    async fn exchange(
        &self,
        request: Request<Full<Bytes>>,
        max: usize,
    ) -> Result<(HeaderMap, Vec<u8>), PeerClientError> {
        let response =
            self.client
                .request(request)
                .await
                .map_err(|error| match refusal_in(&error) {
                    Some(Refusal::ThisComputer(class)) => PeerClientError::ThisComputer { class },
                    Some(Refusal::LocalNetwork) => PeerClientError::LocalNetwork,
                    None => PeerClientError::Unreachable(Box::new(error)),
                })?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = retry_after(response.headers());
            if media_is(response.headers(), PROBLEM_MEDIA_TYPE) {
                // Read so the connection can be reused; what it says is the status's.
                let _ = Limited::new(response.into_body(), MAX_PROBLEM_LEN)
                    .collect()
                    .await;
            }
            debug!(status = status.as_u16(), "endpoint answered with an error");
            return Err(status_error(status, retry_after));
        }
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX)) {
            return Err(PeerClientError::ResponseTooLarge { max });
        }
        let (parts, body) = response.into_parts();
        let collected = Limited::new(body, max).collect().await.map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                PeerClientError::ResponseTooLarge { max }
            } else {
                PeerClientError::Unreachable(error)
            }
        })?;
        Ok((parts.headers, collected.to_bytes().to_vec()))
    }
}

fn parse_uri(text: &str) -> Result<Uri, PeerClientError> {
    text.parse()
        .map_err(|_| PeerClientError::Target(crate::OriginError::Host))
}

/// The error of a status that is not a success. Each problem code has its own status.
fn status_error(status: StatusCode, retry_after: Option<Duration>) -> PeerClientError {
    match status {
        StatusCode::SERVICE_UNAVAILABLE => PeerClientError::NotReady { retry_after },
        StatusCode::UNPROCESSABLE_ENTITY => PeerClientError::Refused,
        StatusCode::PAYLOAD_TOO_LARGE => PeerClientError::TooLarge,
        StatusCode::TOO_MANY_REQUESTS => PeerClientError::RateLimited { retry_after },
        StatusCode::UNSUPPORTED_MEDIA_TYPE => PeerClientError::UnsupportedFormat,
        StatusCode::NOT_FOUND => PeerClientError::NotFound,
        other => PeerClientError::Status {
            status: other.as_u16(),
        },
    }
}

/// `Retry-After` in seconds; a date is not read.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn media_is(headers: &HeaderMap, media: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|found| found.trim().eq_ignore_ascii_case(media))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_problem_status_has_its_error() {
        let after = Some(Duration::from_secs(5));
        assert!(matches!(
            status_error(StatusCode::SERVICE_UNAVAILABLE, after),
            PeerClientError::NotReady { retry_after } if retry_after == after
        ));
        assert!(matches!(
            status_error(StatusCode::UNPROCESSABLE_ENTITY, None),
            PeerClientError::Refused
        ));
        assert!(matches!(
            status_error(StatusCode::PAYLOAD_TOO_LARGE, None),
            PeerClientError::TooLarge
        ));
        assert!(matches!(
            status_error(StatusCode::TOO_MANY_REQUESTS, after),
            PeerClientError::RateLimited { retry_after } if retry_after == after
        ));
        assert!(matches!(
            status_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, None),
            PeerClientError::UnsupportedFormat
        ));
        assert!(matches!(
            status_error(StatusCode::NOT_FOUND, None),
            PeerClientError::NotFound
        ));
        assert!(matches!(
            status_error(StatusCode::BAD_GATEWAY, None),
            PeerClientError::Status { status: 502 }
        ));
    }

    #[tokio::test]
    async fn refuses_hosts_that_resolve_to_this_computer_with_their_class() {
        for (host, class) in [
            ("127.0.0.1", AddressClass::Loopback),
            ("localhost", AddressClass::Loopback),
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("0.0.0.0", AddressClass::Unspecified),
        ] {
            let error = connect_under_rule(host, 9, AddressRule::OTHER_COMPUTERS)
                .await
                .unwrap_err();
            assert_eq!(
                refusal_in(&error),
                Some(Refusal::ThisComputer(class)),
                "{host}"
            );
        }
    }

    mod link_hosts {
        use std::convert::Infallible;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use hyper::Response;
        use hyper::body::Incoming;
        use rustls::RootCertStore;

        use super::*;
        use crate::{HandlerFuture, PEER_PATH, PeerEndpoint, PeerRefusal, SlateHandler, WebScheme};

        /// Answers an envelope with its bytes reversed and counts the envelopes.
        #[derive(Default)]
        struct Reversing {
            calls: AtomicUsize,
        }

        impl SlateHandler for Reversing {
            fn receive(&self, envelope: Vec<u8>) -> HandlerFuture<'_> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(envelope.into_iter().rev().collect()) })
            }

            fn check(&self, _envelope: &[u8]) -> Result<(), PeerRefusal> {
                Ok(())
            }
        }

        /// The endpoint over plain HTTP on a loopback port; counts every connection accepted.
        async fn serve(handler: Arc<Reversing>) -> (SocketAddr, Arc<AtomicUsize>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint = Arc::new(PeerEndpoint::new(handler));
            let accepted = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&accepted);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let endpoint = Arc::clone(&endpoint);
                    tokio::spawn(async move {
                        let service =
                            hyper::service::service_fn(move |request: Request<Incoming>| {
                                let endpoint = Arc::clone(&endpoint);
                                async move {
                                    let inbox = request.uri().path() == PEER_PATH
                                        && request.method() == Method::POST;
                                    let response = if inbox {
                                        endpoint
                                            .answer(request, Duration::from_secs(5))
                                            .await
                                            .response
                                    } else {
                                        Response::builder()
                                            .status(StatusCode::NOT_FOUND)
                                            .body(Full::new(Bytes::new()))
                                            .unwrap()
                                    };
                                    Ok::<_, Infallible>(response)
                                }
                            });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            (address, accepted)
        }

        fn tls() -> Arc<ClientConfig> {
            Arc::new(
                ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
            )
        }

        fn settings() -> PeerClientSettings {
            PeerClientSettings {
                connect_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(5),
                max_response_bytes: MAX_ENVELOPE_LEN,
            }
        }

        fn target(host: &str, port: u16) -> PeerTarget {
            PeerTarget::new(WebScheme::Http, host, port, PEER_PATH).unwrap()
        }

        fn loopback_is_local(ip: IpAddr) -> bool {
            ip.is_loopback()
        }

        fn nothing_is_local(_ip: IpAddr) -> bool {
            false
        }

        /// The link-host client with the test's own rule: the loopback server stands for a
        /// public or a local-network host, as `is_local_network` says.
        fn client_where(is_local_network: fn(IpAddr) -> bool) -> PeerClient {
            let rule = AddressRule {
                this_computer: |_| None,
                local_network: Some(is_local_network),
            };
            PeerClient::ruled(settings(), tls(), rule)
        }

        #[tokio::test]
        async fn a_link_host_on_this_computer_is_refused_before_connecting() {
            let handler = Arc::new(Reversing::default());
            let (address, accepted) = serve(Arc::clone(&handler)).await;
            let client = PeerClient::to_link_hosts(settings(), tls(), nothing_is_local);
            for host in ["127.0.0.1", "localhost"] {
                let error = client
                    .post_slate(&target(host, address.port()), b"envelope")
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        error,
                        PeerClientError::ThisComputer {
                            class: AddressClass::Loopback
                        }
                    ),
                    "{host}: {error:?}"
                );
            }
            assert_eq!(accepted.load(Ordering::SeqCst), 0);
            assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn a_link_host_that_resolves_to_the_local_network_is_refused_before_connecting() {
            let handler = Arc::new(Reversing::default());
            let (address, accepted) = serve(Arc::clone(&handler)).await;
            let client = client_where(loopback_is_local);
            for host in ["127.0.0.1", "localhost"] {
                let error = client
                    .post_slate(&target(host, address.port()), b"envelope")
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, PeerClientError::LocalNetwork),
                    "{host}: {error:?}"
                );
            }
            assert_eq!(accepted.load(Ordering::SeqCst), 0);
            assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn a_public_link_host_gets_the_envelope_and_answers_the_reply() {
            let handler = Arc::new(Reversing::default());
            let (address, accepted) = serve(Arc::clone(&handler)).await;
            let client = client_where(nothing_is_local);
            let reply = client
                .post_slate(&target("127.0.0.1", address.port()), b"envelope")
                .await
                .unwrap();
            assert_eq!(reply, b"epolevne");
            assert_eq!(accepted.load(Ordering::SeqCst), 1);
            assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn the_rule_is_checked_on_each_resolved_address() {
            let local = AddressRule {
                this_computer: |_| None,
                local_network: Some(loopback_is_local),
            };
            let error = connect_under_rule("localhost", 9, local).await.unwrap_err();
            assert_eq!(refusal_in(&error), Some(Refusal::LocalNetwork));
            assert_eq!(
                local.refusal("::ffff:127.0.0.1".parse().unwrap()),
                Some(Refusal::LocalNetwork)
            );
            assert_eq!(local.refusal("203.0.113.7".parse().unwrap()), None);
        }
    }
}
