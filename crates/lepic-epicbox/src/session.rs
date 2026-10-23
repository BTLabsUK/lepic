//! One websocket connection to a relay: connecting, framing, keepalive, and the greeting every
//! session starts with.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lepic_transport::transport::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tracing::{debug, info, warn};

use crate::address::{DEFAULT_PORT, Domain};
use crate::client::{Awaiting, ClientError, ClientSettings};
use crate::frame::{ClientFrame, MAX_FRAME_LEN, RelayFrame, WalletMode};

/// The port of a relay reached without TLS when the address names none, as `epic-wallet` does.
pub const DEFAULT_PLAIN_PORT: u16 = 80;

/// How long closing a connection may take before it is dropped.
const CLOSE_GRACE: Duration = Duration::from_millis(250);

/// Whether the websocket runs over TLS. `Plain` is `epic-wallet`'s insecure flag, for local
/// relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Security {
    Tls,
    Plain,
}

/// The relay a client connects to. The port is always explicit on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayEndpoint {
    domain: Domain,
    port: u16,
    security: Security,
}

impl RelayEndpoint {
    /// Without a port, TLS uses 443 and plain websockets use 80.
    pub fn new(domain: Domain, port: Option<u16>, security: Security) -> Self {
        let port = port.unwrap_or(match security {
            Security::Tls => DEFAULT_PORT,
            Security::Plain => DEFAULT_PLAIN_PORT,
        });
        Self {
            domain,
            port,
            security,
        }
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn security(&self) -> Security {
        self.security
    }

    /// Refuses a plain websocket to a host that is not loopback; TLS may reach any host.
    pub fn check_security(&self) -> Result<(), EndpointError> {
        if self.security == Security::Plain && !self.domain.is_loopback() {
            return Err(EndpointError::PlainToRemoteHost);
        }
        Ok(())
    }

    /// `wss://domain:port` or `ws://domain:port`.
    pub fn url(&self) -> String {
        let scheme = match self.security {
            Security::Tls => "wss",
            Security::Plain => "ws",
        };
        format!("{scheme}://{}:{}", self.domain, self.port)
    }
}

impl Default for RelayEndpoint {
    fn default() -> Self {
        Self::new(Domain::default(), None, Security::Tls)
    }
}

/// A byte stream to a relay, before the websocket handshake.
pub trait RelayStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> RelayStream for T {}

/// Opens byte streams to relays. [`TcpConnector`] reaches real relays; the mock relay provides
/// an in-memory one.
pub trait Connector: Send + Sync {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>>;

    /// The limit for the handshakes of a connection to `endpoint`, given the configured one.
    fn connect_timeout(&self, endpoint: &RelayEndpoint, configured: Duration) -> Duration {
        let _ = endpoint;
        configured
    }

    /// Which way a connection to `endpoint` made now would take, as a number that changes when
    /// the way does.
    fn route(&self, endpoint: &RelayEndpoint) -> u64 {
        let _ = endpoint;
        0
    }

    /// Resolves once [`Connector::route`] of `endpoint` is no longer `route`, so a connection
    /// held open can be replaced by one that takes the new way. Cancel-safe.
    fn route_changed<'a>(&'a self, endpoint: &'a RelayEndpoint, route: u64) -> BoxFuture<'a, ()> {
        let _ = (endpoint, route);
        Box::pin(std::future::pending())
    }
}

/// Why [`TcpConnector`] refused an endpoint without connecting. Carried inside the
/// [`io::Error`] it returns, with kind [`io::ErrorKind::InvalidInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    #[error("plain websocket relay is not a loopback host")]
    PlainToRemoteHost,
}

/// TCP, with TLS from the given rustls configuration when the endpoint asks for it (ADR 0006).
/// A plain endpoint is refused unless its host is loopback.
pub struct TcpConnector {
    tls: Arc<ClientConfig>,
}

impl TcpConnector {
    pub fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    /// `stream` as the endpoint asks for it: with TLS for the endpoint's domain, whatever
    /// host the stream reaches, or as it is for a plain endpoint.
    pub async fn secure<S: RelayStream + 'static>(
        &self,
        endpoint: &RelayEndpoint,
        stream: S,
    ) -> io::Result<Box<dyn RelayStream>> {
        match endpoint.security() {
            Security::Plain => Ok(Box::new(stream)),
            Security::Tls => {
                let name = ServerName::try_from(endpoint.domain().as_str().to_owned())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let tls = TlsConnector::from(Arc::clone(&self.tls))
                    .connect(name, stream)
                    .await?;
                Ok(Box::new(tls))
            }
        }
    }
}

impl fmt::Debug for TcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnector").finish_non_exhaustive()
    }
}

impl Connector for TcpConnector {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move {
            endpoint
                .check_security()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let tcp = TcpStream::connect((endpoint.domain().as_str(), endpoint.port())).await?;
            tcp.set_nodelay(true)?;
            self.secure(endpoint, tcp).await
        })
    }
}

/// The protocol version a relay reports through `GetVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    /// The version LEPIC speaks without extensions, which the public relay supports.
    pub const BASELINE: Self = Self {
        major: 3,
        minor: 0,
        patch: 0,
    };

    /// `major.minor.patch` in decimal; anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.').map(|part| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                part.parse::<u16>().ok()
            }
        });
        let version = Self {
            major: parts.next()??,
            minor: parts.next()??,
            patch: parts.next()??,
        };
        parts.next().is_none().then_some(version)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What a relay said while a session was set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Greeting {
    /// The most recent challenge, which the next `Subscribe` signs.
    pub(crate) challenge: String,
    /// `None` when the relay did not answer `GetVersion`; only the baseline is used then.
    pub(crate) version: Option<ProtocolVersion>,
}

pub(crate) struct Connection {
    ws: WebSocketStream<Box<dyn RelayStream>>,
    last_heard: Instant,
    /// The connector's route when the connection was opened.
    pub(crate) route: u64,
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_LEN))
        .max_frame_size(Some(MAX_FRAME_LEN))
}

fn websocket_error(error: tokio_tungstenite::tungstenite::Error) -> ClientError {
    ClientError::Websocket(Box::new(error))
}

impl Connection {
    pub(crate) async fn open(
        connector: &dyn Connector,
        endpoint: &RelayEndpoint,
        connect_timeout: Duration,
    ) -> Result<Self, ClientError> {
        let route = connector.route(endpoint);
        let attempt = async {
            let stream = connector
                .connect(endpoint)
                .await
                .map_err(ClientError::Connect)?;
            let (ws, _response) = tokio_tungstenite::client_async_with_config(
                endpoint.url(),
                stream,
                Some(websocket_config()),
            )
            .await
            .map_err(websocket_error)?;
            Ok::<_, ClientError>(ws)
        };
        let ws = timeout(
            connector.connect_timeout(endpoint, connect_timeout),
            attempt,
        )
        .await
        .map_err(|_| ClientError::Timeout {
            awaiting: Awaiting::Connection,
        })??;
        Ok(Self {
            ws,
            last_heard: Instant::now(),
            route,
        })
    }

    pub(crate) async fn send(&mut self, frame: &ClientFrame) -> Result<(), ClientError> {
        let text = frame.to_json().map_err(ClientError::Frame)?;
        self.ws
            .send(Message::text(text))
            .await
            .map_err(websocket_error)
    }

    /// Sends `frame`, or times out at `deadline` awaiting the answer that the frame requests.
    pub(crate) async fn send_before(
        &mut self,
        frame: &ClientFrame,
        deadline: Instant,
    ) -> Result<(), ClientError> {
        timeout_at(deadline, self.send(frame))
            .await
            .map_err(|_| ClientError::Timeout {
                awaiting: Awaiting::Answer,
            })?
    }

    /// A websocket ping frame, which keeps proxies from closing an idle connection. Never the
    /// JSON `ping`, whose answer is not JSON.
    pub(crate) async fn ping(&mut self) -> Result<(), ClientError> {
        self.ws
            .send(Message::Ping(Bytes::new()))
            .await
            .map_err(websocket_error)
    }

    /// Time since the relay last sent anything, control frames included.
    pub(crate) fn idle_for(&self) -> Duration {
        self.last_heard.elapsed()
    }

    /// The next protocol frame. Control frames, keepalive text, unknown types and frames that do
    /// not parse are skipped, so none of them ends the session. Cancel-safe.
    pub(crate) async fn receive(&mut self) -> Result<RelayFrame, ClientError> {
        loop {
            let message = self
                .ws
                .next()
                .await
                .ok_or_else(|| {
                    info!("epicbox relay ended the stream without a close frame");
                    ClientError::Closed
                })?
                .map_err(|error| {
                    let error = websocket_error(error);
                    warn!(error = %crate::client::ErrorChain(&error), "epicbox websocket failed");
                    error
                })?;
            self.last_heard = Instant::now();
            let text = match message {
                Message::Text(text) => text,
                Message::Close(frame) => {
                    match frame {
                        Some(frame) => info!(
                            code = u16::from(frame.code),
                            error = %frame.reason,
                            "epicbox relay sent a close frame"
                        ),
                        None => info!("epicbox relay sent a close frame without a reason"),
                    }
                    return Err(ClientError::Closed);
                }
                Message::Binary(_) => {
                    debug!("epicbox binary frame ignored");
                    continue;
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            };
            match RelayFrame::from_json(text.as_str()) {
                Ok(RelayFrame::Keepalive) => debug!("epicbox keepalive ignored"),
                Ok(RelayFrame::Unknown { .. }) => debug!("epicbox frame of unknown type ignored"),
                Ok(frame) => return Ok(frame),
                Err(error) => {
                    debug!(error = %crate::client::ErrorChain(&error), "epicbox frame ignored");
                }
            }
        }
    }

    /// The next frame, or a timeout naming what was awaited.
    async fn receive_before(
        &mut self,
        deadline: Instant,
        awaiting: Awaiting,
    ) -> Result<RelayFrame, ClientError> {
        timeout_at(deadline, self.receive())
            .await
            .map_err(|_| ClientError::Timeout { awaiting })?
    }

    /// Sends a close frame and waits briefly for the relay to acknowledge it.
    pub(crate) async fn close(mut self) {
        let _ = timeout(CLOSE_GRACE, self.ws.close(None)).await;
    }

    /// Waits for the relay's challenge, then sends `ClientDetails` and asks the relay's version.
    /// Requests go one at a time because the relay's `Ok` does not say what it answers.
    pub(crate) async fn greet(
        &mut self,
        mode: WalletMode,
        settings: &ClientSettings,
    ) -> Result<Greeting, ClientError> {
        let mut challenge = self.first_challenge(settings.response_timeout).await?;

        let deadline = deadline_after(settings.response_timeout);
        self.send_before(
            &ClientFrame::client_details(&settings.wallet_version, mode),
            deadline,
        )
        .await?;
        loop {
            match self.receive_before(deadline, Awaiting::Answer).await? {
                RelayFrame::Ok => break,
                RelayFrame::Challenge { str } => challenge = str,
                RelayFrame::Error { kind, .. } => return Err(ClientError::Relay { kind }),
                _ => debug!("epicbox frame ignored before client details were accepted"),
            }
        }

        let deadline = deadline_after(settings.response_timeout);
        // A version request that cannot be written fails the session, unlike an unanswered one.
        self.send_before(&ClientFrame::GetVersion, deadline).await?;
        let version = loop {
            match self.receive_before(deadline, Awaiting::Answer).await {
                Ok(RelayFrame::GetVersion { str }) => break ProtocolVersion::parse(&str),
                Ok(RelayFrame::Challenge { str }) => challenge = str,
                Ok(RelayFrame::Error { .. }) | Err(ClientError::Timeout { .. }) => break None,
                Ok(_) => debug!("epicbox frame ignored while the version was asked"),
                Err(error) => return Err(error),
            }
        };
        if let Some(version) = version
            && version.major < ProtocolVersion::BASELINE.major
        {
            return Err(ClientError::UnsupportedRelayVersion { version });
        }
        debug!("epicbox relay greeted");
        Ok(Greeting { challenge, version })
    }

    async fn first_challenge(&mut self, wait: Duration) -> Result<String, ClientError> {
        let deadline = deadline_after(wait);
        loop {
            match self.receive_before(deadline, Awaiting::Challenge).await? {
                RelayFrame::Challenge { str } => return Ok(str),
                _ => debug!("epicbox frame ignored before the first challenge"),
            }
        }
    }

    /// Waits until `deadline` for the answer to a request that the relay answers with `Ok` or
    /// `Error`.
    pub(crate) async fn answer(&mut self, deadline: Instant) -> Result<(), ClientError> {
        loop {
            match self.receive_before(deadline, Awaiting::Answer).await? {
                RelayFrame::Ok => return Ok(()),
                RelayFrame::Error { kind, .. } => return Err(ClientError::Relay { kind }),
                _ => debug!("epicbox frame ignored while an answer was awaited"),
            }
        }
    }
}

/// `now + wait`, or the furthest representable instant when that overflows.
pub(crate) fn deadline_after(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or_else(|| {
        now.checked_add(Duration::from_secs(86_400 * 365))
            .unwrap_or(now)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotted_decimal_versions_only() {
        assert_eq!(
            ProtocolVersion::parse("3.0.0"),
            Some(ProtocolVersion::BASELINE)
        );
        assert_eq!(
            ProtocolVersion::parse("3.10.2"),
            Some(ProtocolVersion {
                major: 3,
                minor: 10,
                patch: 2
            })
        );
        for text in [
            "",
            "3",
            "3.0",
            "3.0.0.0",
            "3.0.x",
            "3..0",
            "+3.0.0",
            "3.0.0 ",
            "70000.0.0",
        ] {
            assert_eq!(ProtocolVersion::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn versions_order_numerically() {
        let parse = |text| ProtocolVersion::parse(text).unwrap();
        assert!(parse("3.10.0") > parse("3.9.9"));
        assert!(parse("2.0.0") < ProtocolVersion::BASELINE);
    }

    #[test]
    fn endpoint_defaults_port_by_security() {
        let tls = RelayEndpoint::new(Domain::default(), None, Security::Tls);
        let plain = RelayEndpoint::new(Domain::default(), None, Security::Plain);
        assert_eq!(tls.url(), "wss://epicbox.epiccash.com:443");
        assert_eq!(plain.url(), "ws://epicbox.epiccash.com:80");
        let custom = RelayEndpoint::new(
            Domain::parse("relay.local").unwrap(),
            Some(3423),
            Security::Plain,
        );
        assert_eq!(custom.url(), "ws://relay.local:3423");
    }
}
