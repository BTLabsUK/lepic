// SPDX-License-Identifier: Apache-2.0
//! Reaching the relay through a tunnel, such as the wallet's tor (ADR 0021). Only the byte
//! stream goes another way: to the relay's onion when one is known, else to the relay's domain
//! through the tunnel's exit. The TLS server name and the websocket URL stay the relay's
//! domain, so the relay must still show that domain's certificate.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use lepic_transport::transport::BoxFuture;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, OnceCell, watch};
use tokio::time::Instant;
use tokio_rustls::rustls::ClientConfig;
use tracing::debug;

use crate::address::{DEFAULT_PORT, Domain};
use crate::session::{
    Connector, RelayEndpoint, RelayStream, Security, TcpConnector, refuse_loopback_name,
};

/// Where a relay may say which onion it is also reachable at.
pub const DISCOVERY_PATH: &str = "/.well-known/epicbox.json";

/// The largest discovery document read.
pub const MAX_DISCOVERY_LEN: usize = 4096;

/// The largest discovery answer read, headers included.
const MAX_RESPONSE_LEN: usize = 2 * MAX_DISCOVERY_LEN;

/// Another way to reach hosts, such as tor's SOCKS proxy.
pub trait Tunnel: Send + Sync {
    /// Whether relay connections go through the tunnel, now and as it changes. While it is
    /// true, no relay connection is made directly.
    fn active(&self) -> watch::Receiver<bool>;

    /// A byte stream to `host:port` through the tunnel. The tunnel resolves `host`.
    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>>;

    /// Whether `host` is a valid onion host name.
    fn is_onion(&self, host: &str) -> bool;
}

/// The host and port a connection through the tunnel asks for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialTarget {
    pub host: String,
    pub port: u16,
}

/// A relay that is also an onion service: its domain and port, and the onion and port to dial
/// instead. The onion must present the domain's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionRoute {
    pub domain: Domain,
    pub port: u16,
    /// `<56 characters>.onion`.
    pub onion: String,
    pub onion_port: u16,
}

/// The hosts known to be onion services, relays and nodes, as the caller gave them: none
/// until given, for example from the host app's settings or a signed list it fetched. Shared
/// by the connectors that use it. A route wins over discovery.
#[derive(Debug, Default)]
pub struct OnionRoutes(RwLock<Vec<OnionRoute>>);

impl OnionRoutes {
    pub fn new(routes: Vec<OnionRoute>) -> Self {
        Self(RwLock::new(routes))
    }

    /// Replaces every route. Connections made from now on use them.
    pub fn replace(&self, routes: Vec<OnionRoute>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = routes;
    }

    /// The onion of `endpoint`, if it has one.
    pub fn route(&self, endpoint: &RelayEndpoint) -> Option<DialTarget> {
        self.route_to(endpoint.domain().as_str(), endpoint.port())
    }

    /// The onion of the host `host:port`, if it has one.
    pub fn route_to(&self, host: &str, port: u16) -> Option<DialTarget> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|route| route.domain.as_str().eq_ignore_ascii_case(host) && route.port == port)
            .map(|route| DialTarget {
                host: route.onion.clone(),
                port: route.onion_port,
            })
    }
}

/// Why a relay's discovery document was not used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    #[error("discovery connection failed")]
    Io(#[source] io::Error),
    #[error("discovery took too long")]
    Timeout,
    #[error("discovery answer is not a complete 200 response")]
    Http,
    #[error("discovery answer is too large")]
    TooLarge,
    #[error("discovery document does not parse")]
    Malformed,
    #[error("discovery document names another relay")]
    OtherRelay,
    #[error("discovery document names no valid onion")]
    NotOnion,
}

#[derive(Deserialize)]
struct Document {
    domain: String,
    port: u16,
    onion: String,
    onion_port: u16,
    tls_name: String,
}

/// The onion a discovery answer gives for `endpoint`. The document must name the relay's own
/// domain, port and TLS name, and a valid onion.
pub fn parse_discovery(
    response: &[u8],
    endpoint: &RelayEndpoint,
    is_onion: impl Fn(&str) -> bool,
) -> Result<DialTarget, DiscoveryError> {
    let body = response_body(response)?;
    if body.len() > MAX_DISCOVERY_LEN {
        return Err(DiscoveryError::TooLarge);
    }
    let document: Document = serde_json::from_slice(body).map_err(|_| DiscoveryError::Malformed)?;
    let relay = endpoint.domain().as_str();
    if !document.domain.eq_ignore_ascii_case(relay)
        || !document.tls_name.eq_ignore_ascii_case(relay)
        || document.port != endpoint.port()
    {
        return Err(DiscoveryError::OtherRelay);
    }
    let onion = document.onion.to_ascii_lowercase();
    if document.onion_port == 0 || !is_onion(&onion) {
        return Err(DiscoveryError::NotOnion);
    }
    Ok(DialTarget {
        host: onion,
        port: document.onion_port,
    })
}

/// The body of a complete HTTP/1.x `200` answer without chunked encoding.
fn response_body(response: &[u8]) -> Result<&[u8], DiscoveryError> {
    let (head, body) = split_head(response).ok_or(DiscoveryError::Http)?;
    let head = std::str::from_utf8(head).map_err(|_| DiscoveryError::Http)?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split(' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) || parts.next() != Some("200") {
        return Err(DiscoveryError::Http);
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(DiscoveryError::Http)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(DiscoveryError::Http);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed: usize = value.parse().map_err(|_| DiscoveryError::Http)?;
            if parsed > MAX_DISCOVERY_LEN {
                return Err(DiscoveryError::TooLarge);
            }
            length = Some(parsed);
        }
    }
    match length {
        Some(length) => body.get(..length).ok_or(DiscoveryError::Http),
        None => Ok(body),
    }
}

/// The head of an HTTP answer and what follows the blank line after it.
fn split_head(response: &[u8]) -> Option<(&[u8], &[u8])> {
    const END: &[u8] = b"\r\n\r\n";
    let at = response
        .windows(END.len())
        .position(|window| window == END)?;
    let (head, rest) = response.split_at_checked(at)?;
    Some((head, rest.get(END.len()..)?))
}

/// Asks for the discovery document of `domain` over `stream` and reads the answer, at most
/// [`MAX_RESPONSE_LEN`] bytes. A connection closed without TLS `close_notify` ends the answer.
async fn fetch<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    domain: &Domain,
) -> Result<Vec<u8>, DiscoveryError> {
    let request = format!(
        "GET {DISCOVERY_PATH} HTTP/1.1\r\nHost: {domain}\r\nAccept: application/json\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(DiscoveryError::Io)?;
    stream.flush().await.map_err(DiscoveryError::Io)?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = match stream.read(&mut buffer).await {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => 0,
            Err(error) => return Err(DiscoveryError::Io(error)),
        };
        if read == 0 {
            return Ok(response);
        }
        response.extend_from_slice(buffer.get(..read).unwrap_or_default());
        if response.len() > MAX_RESPONSE_LEN {
            return Err(DiscoveryError::TooLarge);
        }
        if complete(&response) {
            return Ok(response);
        }
    }
}

/// Whether an answer with a `Content-Length` holds its whole body.
fn complete(response: &[u8]) -> bool {
    let Some((head, body)) = split_head(response) else {
        return false;
    };
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    head.split("\r\n")
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .is_some_and(|length| body.len() >= length)
}

/// Connects to relays through a [`Tunnel`] while it is active, and directly otherwise. A
/// loopback relay is always reached directly.
pub struct TunnelConnector {
    direct: TcpConnector,
    tunnel: Arc<dyn Tunnel>,
    routes: Arc<OnionRoutes>,
    timings: TunnelTimings,
    /// Discovery outcomes of this connector, by relay; `None` when the relay named no onion.
    /// Only answers are kept: a discovery that could not reach the relay is tried again.
    discovered: Mutex<HashMap<RelayKey, Arc<OnceCell<Option<DialTarget>>>>>,
    /// Relays whose discovery could not reach them, and when to try them again.
    retry_after: Mutex<HashMap<RelayKey, Instant>>,
}

type RelayKey = (String, u16);

/// The caller's timeouts for connections through a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelTimings {
    /// The least a connection through the tunnel is given, whatever the client's own
    /// connect timeout: room for a first circuit.
    pub connect_timeout: Duration,
    /// Asking a relay for its onion.
    pub discovery_timeout: Duration,
    /// How long a relay whose discovery could not reach it is not asked again.
    pub discovery_retry: Duration,
}

impl TunnelConnector {
    /// With no onion routes.
    pub fn new(tls: Arc<ClientConfig>, tunnel: Arc<dyn Tunnel>, timings: TunnelTimings) -> Self {
        Self::with_routes(tls, tunnel, Arc::default(), timings)
    }

    /// With `routes`, which the caller may replace while the connector is in use.
    pub fn with_routes(
        tls: Arc<ClientConfig>,
        tunnel: Arc<dyn Tunnel>,
        routes: Arc<OnionRoutes>,
        timings: TunnelTimings,
    ) -> Self {
        Self {
            direct: TcpConnector::new(tls),
            tunnel,
            routes,
            timings,
            discovered: Mutex::default(),
            retry_after: Mutex::default(),
        }
    }

    /// Where a connection to `endpoint` through the tunnel goes: its onion route, else the
    /// onion the relay names in its discovery document, asked once per connector, else the
    /// relay's own domain and port.
    pub async fn dial_target(&self, endpoint: &RelayEndpoint) -> DialTarget {
        self.dial_target_given(endpoint, None).await
    }

    /// As [`Self::dial_target`], with `given`, an onion a contact named for the relay, used
    /// when the relay has no onion route and `given` is a valid onion host. Discovery is then
    /// not asked.
    pub async fn dial_target_given(
        &self,
        endpoint: &RelayEndpoint,
        given: Option<&DialTarget>,
    ) -> DialTarget {
        if let Some(target) = self.routes.route(endpoint) {
            return target;
        }
        if let Some(onion) = given {
            if onion.port != 0 && self.tunnel.is_onion(&onion.host.to_ascii_lowercase()) {
                return DialTarget {
                    host: onion.host.to_ascii_lowercase(),
                    port: onion.port,
                };
            }
            debug!("epicbox onion given for the relay is not valid, ignored");
        }
        let key = (
            endpoint.domain().as_str().to_ascii_lowercase(),
            endpoint.port(),
        );
        let cell = Arc::clone(self.discovered.lock().await.entry(key.clone()).or_default());
        let found = cell
            .get_or_try_init(|| async {
                if self
                    .retry_after
                    .lock()
                    .await
                    .get(&key)
                    .is_some_and(|until| Instant::now() < *until)
                {
                    return Err(());
                }
                match self.discover(endpoint).await {
                    Ok(target) => Ok(Some(target)),
                    Err(error @ (DiscoveryError::Io(_) | DiscoveryError::Timeout)) => {
                        debug!(error = %error, "epicbox relay could not be asked for its onion");
                        if let Some(until) =
                            Instant::now().checked_add(self.timings.discovery_retry)
                        {
                            self.retry_after.lock().await.insert(key.clone(), until);
                        }
                        Err(())
                    }
                    Err(error) => {
                        debug!(error = %error, "epicbox relay names no onion");
                        Ok(None)
                    }
                }
            })
            .await
            .ok()
            .and_then(Option::clone);
        found.unwrap_or_else(|| DialTarget {
            host: endpoint.domain().as_str().to_owned(),
            port: endpoint.port(),
        })
    }

    async fn discover(&self, endpoint: &RelayEndpoint) -> Result<DialTarget, DiscoveryError> {
        let site = RelayEndpoint::new(endpoint.domain().clone(), None, Security::Tls);
        let response = tokio::time::timeout(self.timings.discovery_timeout, async {
            let stream = self
                .tunnel
                .open(site.domain().as_str(), DEFAULT_PORT)
                .await
                .map_err(DiscoveryError::Io)?;
            let mut stream = self
                .direct
                .secure(&site, stream)
                .await
                .map_err(DiscoveryError::Io)?;
            fetch(&mut stream, site.domain()).await
        })
        .await
        .map_err(|_| DiscoveryError::Timeout)??;
        parse_discovery(&response, endpoint, |host| self.tunnel.is_onion(host))
    }

    #[cfg(test)]
    pub(crate) async fn remember(&self, endpoint: &RelayEndpoint, target: Option<DialTarget>) {
        self.discovered.lock().await.insert(
            (
                endpoint.domain().as_str().to_ascii_lowercase(),
                endpoint.port(),
            ),
            Arc::new(OnceCell::new_with(Some(target))),
        );
    }

    fn tunnelled(&self, endpoint: &RelayEndpoint) -> bool {
        !endpoint.domain().is_loopback() && *self.tunnel.active().borrow()
    }
}

impl fmt::Debug for TunnelConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConnector").finish_non_exhaustive()
    }
}

impl TunnelConnector {
    async fn connect_given(
        &self,
        endpoint: &RelayEndpoint,
        onion: Option<&DialTarget>,
    ) -> io::Result<Box<dyn RelayStream>> {
        if !self.tunnelled(endpoint) {
            return self.direct.connect(endpoint).await;
        }
        endpoint
            .check_security()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let target = self.dial_target_given(endpoint, onion).await;
        debug!(
            onion = target.host.ends_with(".onion"),
            "epicbox relay through tor"
        );
        let stream = self.tunnel.open(&target.host, target.port).await?;
        self.direct.secure(endpoint, stream).await
    }
}

impl Connector for TunnelConnector {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        Box::pin(self.connect_given(endpoint, None))
    }

    fn connect_to_onion<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
        onion: &'a DialTarget,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        Box::pin(self.connect_given(endpoint, Some(onion)))
    }

    /// Through the tunnel only the name is checked: Tor resolves it at the exit, so no address
    /// is seen here. Directly, as [`TcpConnector`] checks.
    fn connect_untrusted<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move {
            if !self.tunnelled(endpoint) {
                return self.direct.connect_untrusted(endpoint).await;
            }
            refuse_loopback_name(endpoint)?;
            self.connect_given(endpoint, None).await
        })
    }

    fn connect_timeout(&self, endpoint: &RelayEndpoint, configured: Duration) -> Duration {
        if self.tunnelled(endpoint) {
            configured.max(self.timings.connect_timeout)
        } else {
            configured
        }
    }

    fn route(&self, endpoint: &RelayEndpoint) -> u64 {
        u64::from(self.tunnelled(endpoint))
    }

    fn route_changed<'a>(&'a self, endpoint: &'a RelayEndpoint, route: u64) -> BoxFuture<'a, ()> {
        let mut active = self.tunnel.active();
        Box::pin(async move {
            if active
                .wait_for(|_| self.route(endpoint) != route)
                .await
                .is_err()
            {
                std::future::pending::<()>().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn routes_start_empty_and_name_a_host_by_name_and_port() {
        assert!(OnionRoutes::default().route_to(MAPPED, 443).is_none());
        let node_onion = format!("{}.onion", "c".repeat(56));
        let routes = OnionRoutes::new(vec![
            route(MAPPED, &onion()),
            route("node.example", &node_onion),
        ]);
        let node = routes.route_to("Node.Example", 443).unwrap();
        assert_eq!(node.host, node_onion);
        assert_eq!(node.port, 443);
        assert!(routes.route_to(MAPPED, 443).is_some());
        assert!(routes.route_to("node.example", 3413).is_none());
        assert!(routes.route_to("other.example", 443).is_none());
    }

    use std::sync::Mutex as StdMutex;

    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::crypto::ring;

    use super::*;

    /// The relay the test connectors know an onion for, [`onion`].
    const MAPPED: &str = "mapped.example";

    fn onion() -> String {
        format!("{}.onion", "a".repeat(56))
    }

    fn route(domain: &str, onion: &str) -> OnionRoute {
        OnionRoute {
            domain: Domain::parse(domain).unwrap(),
            port: 443,
            onion: onion.to_owned(),
            onion_port: 443,
        }
    }
    const REFUSED: &str = "tunnel refused";

    struct FakeTunnel {
        active: watch::Sender<bool>,
        opened: StdMutex<Vec<(String, u16)>>,
        /// Gets the far end of each stream opened; without it every open fails.
        serve: Option<mpsc::UnboundedSender<DuplexStream>>,
        /// Opens to this host never finish.
        hang: Option<&'static str>,
    }

    impl FakeTunnel {
        fn new(active: bool) -> Self {
            Self {
                active: watch::Sender::new(active),
                opened: StdMutex::default(),
                serve: None,
                hang: None,
            }
        }

        fn opened(&self) -> Vec<(String, u16)> {
            self.opened.lock().unwrap().clone()
        }
    }

    impl Tunnel for FakeTunnel {
        fn active(&self) -> watch::Receiver<bool> {
            self.active.subscribe()
        }

        fn open<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
            self.opened.lock().unwrap().push((host.to_owned(), port));
            Box::pin(async move {
                if self.hang == Some(host) {
                    std::future::pending::<()>().await;
                }
                let Some(serve) = &self.serve else {
                    return Err(io::Error::other(REFUSED));
                };
                let (near, far) = tokio::io::duplex(64 * 1024);
                serve.send(far).unwrap();
                Ok(Box::new(near) as Box<dyn RelayStream>)
            })
        }

        fn is_onion(&self, host: &str) -> bool {
            looks_like_onion(host)
        }
    }

    /// A v3 onion host: 56 characters and `.onion`.
    fn looks_like_onion(host: &str) -> bool {
        host.len() == 62 && host.ends_with(".onion")
    }

    fn tls() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    fn relay(domain: &str, port: u16) -> RelayEndpoint {
        RelayEndpoint::new(Domain::parse(domain).unwrap(), Some(port), Security::Tls)
    }

    fn connector(tunnel: &Arc<FakeTunnel>) -> TunnelConnector {
        TunnelConnector::with_routes(
            tls(),
            Arc::clone(tunnel) as Arc<dyn Tunnel>,
            Arc::new(OnionRoutes::new(vec![route(MAPPED, &onion())])),
            crate::testing::tunnel_timings(),
        )
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[tokio::test]
    async fn a_mapped_relay_is_dialled_at_its_onion_with_the_relay_name_for_tls() {
        let (serve, mut streams) = mpsc::unbounded_channel();
        let tunnel = Arc::new(FakeTunnel {
            serve: Some(serve),
            ..FakeTunnel::new(true)
        });
        let connector = connector(&tunnel);
        let endpoint = relay(MAPPED, 443);
        let connecting = tokio::spawn(async move { connector.connect(&endpoint).await.err() });
        let mut far = streams.recv().await.unwrap();
        let mut hello = vec![0u8; 4096];
        let read = far.read(&mut hello).await.unwrap();
        let hello = hello.get(..read).unwrap();
        assert!(contains(hello, MAPPED.as_bytes()), "server name");
        assert!(!contains(hello, onion().as_bytes()));
        drop(far);
        assert!(connecting.await.unwrap().is_some());
        assert_eq!(tunnel.opened(), [(onion(), 443)]);
    }

    #[test]
    fn only_the_mapped_port_has_an_onion() {
        let routes = OnionRoutes::new(vec![route(MAPPED, &onion())]);
        assert_eq!(
            routes.route(&relay("Mapped.Example", 443)),
            Some(DialTarget {
                host: onion(),
                port: 443
            })
        );
        assert_eq!(routes.route(&relay(MAPPED, 3420)), None);
        assert_eq!(routes.route(&relay("other.example", 443)), None);
    }

    #[tokio::test]
    async fn replaced_routes_are_dialled_and_the_old_one_is_gone() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let routes = Arc::new(OnionRoutes::new(vec![route(MAPPED, &onion())]));
        let connector = TunnelConnector::with_routes(
            tls(),
            Arc::clone(&tunnel) as Arc<dyn Tunnel>,
            Arc::clone(&routes),
            crate::testing::tunnel_timings(),
        );
        let other = format!("{}.onion", "b".repeat(56));
        routes.replace(vec![OnionRoute {
            domain: Domain::parse("relay.example").unwrap(),
            port: 443,
            onion: other.clone(),
            onion_port: 8443,
        }]);
        connector.remember(&relay(MAPPED, 443), None).await;
        assert!(
            connector
                .connect(&relay("Relay.Example", 443))
                .await
                .is_err()
        );
        assert!(connector.connect(&relay(MAPPED, 443)).await.is_err());
        assert_eq!(tunnel.opened(), [(other, 8443), (MAPPED.to_owned(), 443)]);
    }

    fn plain(endpoint: &RelayEndpoint) -> DialTarget {
        DialTarget {
            host: endpoint.domain().as_str().to_owned(),
            port: endpoint.port(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_discovery_does_not_hold_up_other_relays() {
        let tunnel = Arc::new(FakeTunnel {
            hang: Some("slow.example"),
            ..FakeTunnel::new(true)
        });
        let connector = Arc::new(connector(&tunnel));
        let slow = relay("slow.example", 443);
        let quick = relay("quick.example", 443);
        let asking = Arc::clone(&connector);
        let waiting = tokio::spawn(async move { asking.dial_target(&slow).await });
        tokio::task::yield_now().await;
        let target = tokio::time::timeout(Duration::from_secs(1), connector.dial_target(&quick))
            .await
            .unwrap();
        assert_eq!(target, plain(&quick));
        assert!(!waiting.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovery_that_could_not_connect_is_tried_again_later() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let endpoint = relay("relay.example", 443);
        let asked = || {
            tunnel
                .opened()
                .iter()
                .filter(|(host, _)| host == "relay.example")
                .count()
        };
        assert_eq!(connector.dial_target(&endpoint).await, plain(&endpoint));
        assert_eq!(connector.dial_target(&endpoint).await, plain(&endpoint));
        assert_eq!(asked(), 1);
        tokio::time::advance(
            crate::testing::tunnel_timings().discovery_retry + Duration::from_secs(1),
        )
        .await;
        assert_eq!(connector.dial_target(&endpoint).await, plain(&endpoint));
        assert_eq!(asked(), 2);
    }

    #[tokio::test]
    async fn the_direct_connector_never_resolves_an_onion_name() {
        let direct = TcpConnector::new(tls());
        for domain in [
            format!("{}.onion", "a".repeat(56)),
            format!("{}.ONION.", "a".repeat(56)),
        ] {
            let error = direct.connect(&relay(&domain, 443)).await.err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{domain}");
            assert!(error.to_string().contains("needs Tor"), "{domain}");
        }
    }

    #[tokio::test]
    async fn an_untrusted_relay_on_a_loopback_or_unspecified_host_is_refused() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let direct = TcpConnector::new(tls());
        for domain in ["localhost", "relay.localhost", "127.0.0.1", "0.0.0.0"] {
            let endpoint = relay(domain, 443);
            for error in [
                direct.connect_untrusted(&endpoint).await.err().unwrap(),
                connector.connect_untrusted(&endpoint).await.err().unwrap(),
            ] {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{domain}");
                assert_eq!(
                    error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<crate::EndpointError>()),
                    Some(&crate::EndpointError::LoopbackHost),
                    "{domain}"
                );
            }
        }
        assert!(tunnel.opened().is_empty());
    }

    #[tokio::test]
    async fn a_discovered_onion_is_dialled() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let endpoint = relay("relay.example", 443);
        let onion = format!("{}.onion", "a".repeat(56));
        connector
            .remember(
                &endpoint,
                Some(DialTarget {
                    host: onion.clone(),
                    port: 8443,
                }),
            )
            .await;
        assert!(connector.connect(&endpoint).await.is_err());
        assert_eq!(tunnel.opened(), [(onion, 8443)]);
    }

    #[tokio::test]
    async fn an_onion_given_for_the_relay_is_dialled_without_asking_discovery() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let endpoint = relay("relay.example", 443);
        let given = DialTarget {
            host: format!("{}.ONION", "b".repeat(56)),
            port: 9443,
        };
        assert!(connector.connect_to_onion(&endpoint, &given).await.is_err());
        assert_eq!(
            tunnel.opened(),
            [(format!("{}.onion", "b".repeat(56)), 9443)]
        );
    }

    #[tokio::test]
    async fn a_routed_onion_wins_over_a_given_one() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let given = DialTarget {
            host: format!("{}.onion", "b".repeat(56)),
            port: 443,
        };
        let _ = connector
            .connect_to_onion(&relay(MAPPED, 443), &given)
            .await;
        assert_eq!(tunnel.opened(), [(onion(), 443)]);
    }

    #[tokio::test]
    async fn an_invalid_given_onion_is_ignored() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let endpoint = relay("relay.example", 443);
        connector.remember(&endpoint, None).await;
        for given in [
            DialTarget {
                host: "evil.example".to_owned(),
                port: 443,
            },
            DialTarget {
                host: format!("{}.onion", "b".repeat(56)),
                port: 0,
            },
        ] {
            let _ = connector.connect_to_onion(&endpoint, &given).await;
        }
        let exit = ("relay.example".to_owned(), 443);
        assert_eq!(tunnel.opened(), [exit.clone(), exit]);
    }

    #[tokio::test]
    async fn a_given_onion_is_not_used_while_the_tunnel_is_inactive() {
        let tunnel = Arc::new(FakeTunnel::new(false));
        let connector = connector(&tunnel);
        let endpoint = RelayEndpoint::new(
            Domain::parse("relay.example").unwrap(),
            Some(80),
            Security::Plain,
        );
        let given = DialTarget {
            host: format!("{}.onion", "b".repeat(56)),
            port: 443,
        };
        let error = connector
            .connect_to_onion(&endpoint, &given)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(tunnel.opened().is_empty());
    }

    #[tokio::test]
    async fn a_relay_without_an_onion_is_dialled_through_the_exit_and_asked_once() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let endpoint = relay("relay.example", 3420);
        for _ in 0..2 {
            let error = connector.connect(&endpoint).await.err().unwrap();
            assert_eq!(error.to_string(), REFUSED);
        }
        let exit = ("relay.example".to_owned(), 3420);
        assert_eq!(
            tunnel.opened(),
            [
                ("relay.example".to_owned(), 443),
                exit.clone(),
                exit.clone()
            ]
        );
    }

    #[tokio::test]
    async fn an_active_tunnel_that_fails_is_never_bypassed() {
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        connector.remember(&relay("relay.example", 443), None).await;
        let error = connector
            .connect(&relay("relay.example", 443))
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            REFUSED,
            "the tunnel's error, not a direct one"
        );
        assert_eq!(tunnel.opened(), [("relay.example".to_owned(), 443)]);
    }

    #[tokio::test]
    async fn an_inactive_tunnel_is_not_used() {
        let tunnel = Arc::new(FakeTunnel::new(false));
        let connector = connector(&tunnel);
        // The direct path refuses a plain websocket to a remote host before connecting.
        let endpoint = RelayEndpoint::new(
            Domain::parse("relay.example").unwrap(),
            Some(80),
            Security::Plain,
        );
        let error = connector.connect(&endpoint).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(tunnel.opened().is_empty());
        assert_eq!(
            connector.connect_timeout(&endpoint, Duration::from_secs(15)),
            Duration::from_secs(15)
        );
    }

    #[tokio::test]
    async fn a_loopback_relay_is_reached_directly_with_the_tunnel_active() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tunnel = Arc::new(FakeTunnel::new(true));
        let connector = connector(&tunnel);
        let endpoint = RelayEndpoint::new(
            Domain::parse("127.0.0.1").unwrap(),
            Some(port),
            Security::Plain,
        );
        let (connected, accepted) = tokio::join!(connector.connect(&endpoint), listener.accept());
        assert!(connected.is_ok() && accepted.is_ok());
        assert!(tunnel.opened().is_empty());
    }

    #[test]
    fn a_tunnelled_connection_gets_time_for_a_first_circuit() {
        let connector = connector(&Arc::new(FakeTunnel::new(true)));
        let endpoint = relay("relay.example", 443);
        assert_eq!(
            connector.connect_timeout(&endpoint, Duration::from_secs(15)),
            crate::testing::tunnel_timings().connect_timeout
        );
        assert_eq!(
            connector.connect_timeout(&endpoint, Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }

    fn answer(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn document(domain: &str, port: u16, onion: &str, tls_name: &str) -> String {
        format!(
            r#"{{"domain":"{domain}","port":{port},"onion":"{onion}","onion_port":443,"tls_name":"{tls_name}"}}"#
        )
    }

    fn parse(response: &[u8]) -> Result<DialTarget, DiscoveryError> {
        parse_discovery(response, &relay(MAPPED, 443), looks_like_onion)
    }

    #[test]
    fn a_discovery_document_for_the_relay_gives_its_onion() {
        let relay = MAPPED;
        let found = parse(&answer(&document(relay, 443, &onion(), relay))).unwrap();
        assert_eq!(
            found,
            DialTarget {
                host: onion(),
                port: 443
            }
        );
        let upper = onion().to_ascii_uppercase().replace(".ONION", ".onion");
        assert_eq!(
            parse(&answer(&document(relay, 443, &upper, relay)))
                .unwrap()
                .host,
            onion()
        );
    }

    #[test]
    fn a_discovery_document_for_another_relay_is_refused() {
        let relay = MAPPED;
        for body in [
            document("other.example", 443, &onion(), relay),
            document(relay, 443, &onion(), "other.example"),
            document(relay, 3420, &onion(), relay),
        ] {
            assert!(
                matches!(parse(&answer(&body)), Err(DiscoveryError::OtherRelay)),
                "{body}"
            );
        }
    }

    #[test]
    fn a_discovery_document_without_a_valid_onion_is_refused() {
        let relay = MAPPED;
        for onion in ["relay.example", &format!("{}.onion", "abc"), ""] {
            assert!(matches!(
                parse(&answer(&document(relay, 443, onion, relay))),
                Err(DiscoveryError::NotOnion)
            ));
        }
        let zero_port = document(relay, 443, &onion(), relay)
            .replace(r#""onion_port":443"#, r#""onion_port":0"#);
        assert!(matches!(
            parse(&answer(&zero_port)),
            Err(DiscoveryError::NotOnion)
        ));
    }

    #[test]
    fn a_discovery_answer_that_is_not_a_plain_200_is_refused() {
        let relay = MAPPED;
        let body = document(relay, 443, &onion(), relay);
        let not_found = String::from_utf8(answer(&body))
            .unwrap()
            .replace("200 OK", "404 Not Found");
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
        let short = String::from_utf8(answer(&body)).unwrap();
        let short = short.get(..short.len() - 1).unwrap();
        for response in [
            not_found.as_str(),
            chunked.as_str(),
            short,
            "HTTP/1.1 200 OK",
        ] {
            assert!(
                matches!(parse(response.as_bytes()), Err(DiscoveryError::Http)),
                "{response}"
            );
        }
        assert!(matches!(
            parse(&answer("{\"domain\":")),
            Err(DiscoveryError::Malformed)
        ));
        let large = answer(&" ".repeat(MAX_DISCOVERY_LEN + 1));
        assert!(matches!(parse(&large), Err(DiscoveryError::TooLarge)));
    }

    #[tokio::test]
    async fn fetch_reads_an_answer_that_arrives_in_parts_on_a_kept_alive_connection() {
        let (mut near, mut far) = tokio::io::duplex(1024);
        let relay = MAPPED;
        let response = answer(&document(relay, 443, &onion(), relay));
        let expected = response.clone();
        let server = tokio::spawn(async move {
            let mut request = vec![0u8; 1024];
            let read = far.read(&mut request).await.unwrap();
            let request = String::from_utf8(request.get(..read).unwrap().to_vec()).unwrap();
            let (first, second) = response.split_at(40);
            far.write_all(first).await.unwrap();
            far.write_all(second).await.unwrap();
            // Kept open: the answer ends at its length.
            (request, far)
        });
        let read = fetch(&mut near, &Domain::parse(relay).unwrap())
            .await
            .unwrap();
        assert_eq!(read, expected);
        let (request, _far) = server.await.unwrap();
        assert!(request.starts_with("GET /.well-known/epicbox.json HTTP/1.1\r\n"));
        assert!(request.contains(&format!("\r\nHost: {MAPPED}\r\n")));
    }

    #[tokio::test]
    async fn fetch_stops_reading_at_its_limit() {
        let (mut near, mut far) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 256];
            let _ = far.read(&mut request).await.unwrap();
            let _ = far.write_all(&vec![b'x'; MAX_RESPONSE_LEN + 10]).await;
            far
        });
        assert!(matches!(
            fetch(&mut near, &Domain::parse("relay.example").unwrap()).await,
            Err(DiscoveryError::TooLarge)
        ));
        drop(server.await.unwrap());
    }

    #[tokio::test]
    async fn the_route_changes_when_the_tunnel_turns_on_or_off() {
        let tunnel = Arc::new(FakeTunnel::new(false));
        let connector = connector(&tunnel);
        let endpoint = relay("relay.example", 443);
        let direct = connector.route(&endpoint);
        let mut changed = std::pin::pin!(connector.route_changed(&endpoint, direct));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), changed.as_mut())
                .await
                .is_err()
        );
        tunnel.active.send_replace(true);
        changed.await;
        let tunnelled = connector.route(&endpoint);
        assert_ne!(tunnelled, direct);
        tunnel.active.send_replace(false);
        connector.route_changed(&endpoint, tunnelled).await;

        let loopback =
            RelayEndpoint::new(Domain::parse("localhost").unwrap(), None, Security::Plain);
        let route = connector.route(&loopback);
        tunnel.active.send_replace(true);
        let changed = connector.route_changed(&loopback, route);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), changed)
                .await
                .is_err(),
            "a loopback relay keeps its direct connection"
        );
    }
}
