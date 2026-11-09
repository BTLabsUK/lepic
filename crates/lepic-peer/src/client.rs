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
use crate::{ENVELOPE_MEDIA_TYPE, MAX_ENVELOPE_LEN, PeerFormatError, PeerInfo};

/// The longest `GET /v1/peer` answer read.
const MAX_INFO_LEN: usize = 4096;

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

    /// The class of `host` when it names this computer by itself: `localhost` or an address
    /// literal of this computer's own, with or without the brackets of an IPv6 literal. No name
    /// is resolved.
    pub fn of_host(host: &str) -> Option<Self> {
        if host.eq_ignore_ascii_case("localhost") {
            return Some(Self::Loopback);
        }
        let literal = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        literal.parse().ok().and_then(Self::of_this_computer)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified",
        }
    }
}

/// The refusal of an address that is this computer's own, carried inside the connector's
/// [`io::Error`] until the client turns it into [`PeerClientError::ThisComputer`].
#[derive(Debug, thiserror::Error)]
#[error("the address is one of this computer's own ({})", .0.as_str())]
struct ThisComputer(AddressClass);

/// The class of a [`ThisComputer`] refusal in `error` or one of its causes.
fn refused_this_computer(error: &(dyn Error + 'static)) -> Option<AddressClass> {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if let Some(ThisComputer(class)) = error.downcast_ref::<ThisComputer>() {
            return Some(*class);
        }
        let inner = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<ThisComputer>());
        if let Some(ThisComputer(class)) = inner {
            return Some(*class);
        }
        cause = error.source();
    }
    None
}

/// Resolves `host` and connects to the first of its addresses that is not this computer's own.
/// The check is on the resolved addresses, the ones connected to.
async fn connect_to_other_computer(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut refused = None;
    let mut failed = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        if let Some(class) = AddressClass::of_this_computer(address.ip()) {
            refused = Some(class);
            continue;
        }
        match TcpStream::connect(address).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => failed = Some(error),
        }
    }
    Err(failed.unwrap_or_else(|| match refused {
        Some(class) => io::Error::new(io::ErrorKind::PermissionDenied, ThisComputer(class)),
        None => io::Error::new(io::ErrorKind::NotFound, "the host has no address"),
    }))
}

#[derive(Clone)]
enum PeerConnector {
    Direct(HttpConnector),
    OtherComputers { connect_timeout: Duration },
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
            Self::OtherComputers { .. } | Self::Dialed(_) => Poll::Ready(Ok(())),
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
            Self::OtherComputers { connect_timeout } => {
                let connect_timeout = *connect_timeout;
                Box::pin(async move {
                    let (host, port) = dial_target(&uri)?;
                    let stream = tokio::time::timeout(
                        connect_timeout,
                        connect_to_other_computer(&host, port),
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
        let route = PeerConnector::OtherComputers {
            connect_timeout: settings.connect_timeout,
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

    /// The endpoint's description at `target`.
    pub async fn info(&self, target: &PeerTarget) -> Result<PeerInfo, PeerClientError> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(parse_uri(&target.info_uri())?)
            .header(ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .map_err(|error| PeerClientError::Unreachable(Box::new(error)))?;
        let (_, body) = self.send(request, MAX_INFO_LEN).await?;
        let info: PeerInfo =
            serde_json::from_slice(&body).map_err(|_| PeerFormatError::Malformed)?;
        info.check()?;
        Ok(info)
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
            .uri(parse_uri(&target.slates_uri())?)
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
        let response = self.client.request(request).await.map_err(|error| {
            match refused_this_computer(&error) {
                Some(class) => PeerClientError::ThisComputer { class },
                None => PeerClientError::Unreachable(Box::new(error)),
            }
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

    #[test]
    fn a_host_names_this_computer_by_itself_only_as_localhost_or_its_literal() {
        for (host, class) in [
            ("localhost", Some(AddressClass::Loopback)),
            ("LocalHost", Some(AddressClass::Loopback)),
            ("127.0.0.1", Some(AddressClass::Loopback)),
            ("[::1]", Some(AddressClass::Loopback)),
            ("::1", Some(AddressClass::Loopback)),
            ("0.0.0.0", Some(AddressClass::Unspecified)),
            ("[::]", Some(AddressClass::Unspecified)),
            ("wallet.example", None),
            ("10.1.2.3", None),
        ] {
            assert_eq!(AddressClass::of_host(host), class, "{host}");
        }
    }

    #[tokio::test]
    async fn refuses_hosts_that_resolve_to_this_computer_with_their_class() {
        for (host, class) in [
            ("127.0.0.1", AddressClass::Loopback),
            ("localhost", AddressClass::Loopback),
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("0.0.0.0", AddressClass::Unspecified),
        ] {
            let error = connect_to_other_computer(host, 9).await.unwrap_err();
            assert_eq!(refused_this_computer(&error), Some(class), "{host}");
        }
    }
}
