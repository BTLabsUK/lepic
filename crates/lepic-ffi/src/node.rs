//! How node requests leave the binding: over HTTP to the configured node, or, in a `mock` build,
//! to an in-process scripted chain.

use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use lepic_epicbox::tunnel::OnionRoutes;
use lepic_node::{
    CallPolicy, DialFuture, HttpSettings, HttpTransport, NodeClient, NodeDialer, NodeError,
    NodeStream, RpcTransport, is_loopback_host, webpki_tls_config,
};
use lepic_tor::{RelayTor, RelayTorError};
use tokio::net::TcpStream;

use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::WalletConfig;

pub(crate) type Node = NodeClient<SwitchableBackend>;

/// The node a session talks to, which [`SwitchableBackend::replace`] changes while the
/// session stays open. Clones share it. A request goes to the node set when it starts.
#[derive(Clone)]
pub(crate) struct SwitchableBackend(Arc<RwLock<NodeBackend>>);

impl SwitchableBackend {
    pub(crate) fn new(backend: NodeBackend) -> Self {
        Self(Arc::new(RwLock::new(backend)))
    }

    pub(crate) fn replace(&self, backend: NodeBackend) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = backend;
    }

    fn current(&self) -> NodeBackend {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RpcTransport for SwitchableBackend {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        self.current().post(endpoint, body).await
    }

    // The label is borrowed from the backend, which a switch may replace while it is
    // borrowed; the switch logs the host it moves to instead.
    fn node_label(&self) -> &str {
        "configured node"
    }
}

#[derive(Clone)]
pub(crate) enum NodeBackend {
    Http(Box<HttpTransport>),
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockBackend),
}

impl RpcTransport for NodeBackend {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        match self {
            Self::Http(http) => http.post(endpoint, body).await,
            #[cfg(feature = "mock")]
            Self::Mock(mock) => mock.post(endpoint, body).await,
        }
    }

    fn node_label(&self) -> &str {
        match self {
            Self::Http(http) => http.node_label(),
            #[cfg(feature = "mock")]
            Self::Mock(mock) => mock.node_label(),
        }
    }
}

/// Where the runtime sends node requests.
#[derive(Clone)]
pub(crate) enum NodeFactory {
    Http,
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockBackend),
}

/// The node API secret of a [`WalletConfig`], in a buffer wiped on drop.
pub(crate) struct NodeSecret(Zeroizing<Option<String>>);

impl NodeSecret {
    /// Moves the secret out of `config`. Every binding call that receives a config does this
    /// first, so no early return leaves the secret behind in a buffer that is not wiped.
    pub(crate) fn take(config: &mut WalletConfig) -> Self {
        Self(Zeroizing::new(config.node_api_secret.take()))
    }
}

impl NodeFactory {
    /// A client for the node `config` names, authenticating with `secret`.
    pub(crate) fn client(
        &self,
        config: &WalletConfig,
        secret: &NodeSecret,
        tor: &Arc<RelayTor>,
        routes: &Arc<OnionRoutes>,
    ) -> Result<Node, WalletError> {
        let backend = SwitchableBackend::new(self.backend(config, secret, tor, routes)?);
        Ok(NodeClient::new(backend, self.policy()))
    }

    /// The backend for the node `config` names: `InvalidArgument` for a URL that is not one
    /// of a node.
    pub(crate) fn backend(
        &self,
        config: &WalletConfig,
        secret: &NodeSecret,
        tor: &Arc<RelayTor>,
        routes: &Arc<OnionRoutes>,
    ) -> Result<NodeBackend, WalletError> {
        match self {
            Self::Http => {
                let settings = HttpSettings {
                    api_secret: secret.0.as_deref().map(Into::into),
                    connect_timeout: Duration::from_secs(15),
                    // Room for a first circuit to the node's onion.
                    request_timeout: Duration::from_secs(90),
                    ..HttpSettings::default()
                };
                let tls = webpki_tls_config().map_err(|error| node_config_error(&error))?;
                let dialer = Arc::new(TorNodeDialer {
                    tor: Arc::clone(tor),
                    routes: Arc::clone(routes),
                    connect_timeout: settings.connect_timeout,
                });
                let http = HttpTransport::with_dialer(&config.node_url, &settings, tls, dialer)
                    .map_err(|error| node_config_error(&error))?;
                Ok(NodeBackend::Http(Box::new(http)))
            }
            #[cfg(feature = "mock")]
            Self::Mock(mock) => Ok(NodeBackend::Mock(mock.at(&config.node_url))),
        }
    }

    fn policy(&self) -> CallPolicy {
        match self {
            Self::Http => CallPolicy::default(),
            #[cfg(feature = "mock")]
            Self::Mock(_) => crate::mock::MockBackend::policy(),
        }
    }
}

/// Opens node connections through the wallet's tor while the setting is on and a tor runs or
/// is expected, and directly otherwise. A loopback node stays direct. Plain `http` is refused
/// for any other node before a dialer is used, except for an onion, which tor encrypts. A tor
/// that fails is an error: nothing goes around it.
struct TorNodeDialer {
    tor: Arc<RelayTor>,
    routes: Arc<OnionRoutes>,
    connect_timeout: Duration,
}

fn is_onion_host(host: &str) -> bool {
    host.rsplit('.')
        .next()
        .is_some_and(|label| label.eq_ignore_ascii_case("onion"))
}

impl TorNodeDialer {
    async fn connect_directly(&self, host: &str, port: u16) -> io::Result<Box<dyn NodeStream>> {
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}

impl NodeDialer for TorNodeDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a> {
        Box::pin(async move {
            if is_loopback_host(host) {
                return self.connect_directly(host, port).await;
            }
            let (target_host, target_port) = match self.routes.route_to(host, port) {
                Some(onion) => (onion.host, onion.port),
                None => (host.to_owned(), port),
            };
            match self.tor.open(&target_host, target_port).await {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn NodeStream>),
                // An onion has no address to resolve without tor.
                Err(RelayTorError::Off) if !is_onion_host(host) => {
                    self.connect_directly(host, port).await
                }
                Err(error) => Err(io::Error::other(error)),
            }
        })
    }
}

fn node_config_error(error: &NodeError) -> WalletError {
    WalletError::new(
        WalletErrorKind::InvalidArgument,
        lepic_telemetry::ErrorChain(error).to_string(),
    )
}

/// The node's error as a binding error.
pub(crate) fn node_error(error: &NodeError) -> WalletError {
    WalletError::new(
        WalletErrorKind::NodeUnreachable,
        lepic_telemetry::ErrorChain(error).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use lepic_node::NodeApi as _;
    use lepic_tor::FixedSocks;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const NODE_ONION: &str = "5drwoknehnzducfsxsl45dazaw3cwcmpx3ycamynagmcpv6aalrbrtqd.onion";

    fn dialer(tor: &Arc<RelayTor>) -> TorNodeDialer {
        TorNodeDialer {
            tor: Arc::clone(tor),
            routes: Arc::new(OnionRoutes::default()),
            connect_timeout: Duration::from_secs(5),
        }
    }

    /// A SOCKS5 server that accepts one connection and returns what it was asked to connect to.
    async fn socks_server() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 2 + 32 + 1 + 32];
            stream.read_exact(&mut auth).await.unwrap();
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = vec![0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            let mut name_len = [0u8; 1];
            stream.read_exact(&mut name_len).await.unwrap();
            let mut rest = vec![0u8; usize::from(name_len[0]) + 2];
            stream.read_exact(&mut rest).await.unwrap();
            request.extend_from_slice(&name_len);
            request.extend(rest);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            request
        });
        (address, served)
    }

    /// Manual: `LEPIC_TEST_TOR_SOCKS=127.0.0.1:19150 cargo test -p lepic-ffi
    /// live_node_through_tor -- --ignored` with a tor listening there. Asks the BT Labs node
    /// for its tip at its onion, with TLS for `node.btlabs.uk`.
    #[tokio::test]
    #[ignore = "needs a running tor and the public node"]
    async fn live_node_through_tor() {
        let socks: SocketAddr = std::env::var("LEPIC_TEST_TOR_SOCKS")
            .unwrap()
            .parse()
            .unwrap();
        let tor = Arc::new(RelayTor::new(true));
        tor.attach_socks(FixedSocks(socks));
        let http = HttpTransport::with_dialer(
            "https://node.btlabs.uk",
            &HttpSettings {
                request_timeout: Duration::from_secs(120),
                ..HttpSettings::default()
            },
            webpki_tls_config().unwrap(),
            Arc::new(dialer(&tor)),
        )
        .unwrap();
        let tip = NodeClient::new(NodeBackend::Http(Box::new(http)), CallPolicy::default())
            .get_tip()
            .await
            .unwrap();
        println!("tip height {}", tip.height.value());
    }

    #[tokio::test]
    async fn a_listed_node_is_asked_of_tor_as_its_onion_by_name() {
        let (socks, served) = socks_server().await;
        let tor = Arc::new(RelayTor::new(true));
        tor.attach_socks(FixedSocks(socks));
        dialer(&tor).dial("node.btlabs.uk", 443).await.unwrap();
        assert_eq!(
            served.await.unwrap(),
            lepic_tor::socks::encode_connect(NODE_ONION, 443).unwrap()
        );
    }

    #[tokio::test]
    async fn another_node_is_asked_of_tor_by_name_so_tor_resolves_it() {
        let (socks, served) = socks_server().await;
        let tor = Arc::new(RelayTor::new(true));
        tor.attach_socks(FixedSocks(socks));
        dialer(&tor).dial("node.example", 3413).await.unwrap();
        assert_eq!(
            served.await.unwrap(),
            lepic_tor::socks::encode_connect("node.example", 3413).unwrap()
        );
    }

    #[tokio::test]
    async fn a_connection_waits_for_a_tor_that_is_expected_and_never_goes_direct() {
        let tor = Arc::new(RelayTor::new(true));
        tor.expect();
        let waiting = tokio::time::timeout(
            Duration::from_millis(200),
            dialer(&tor).dial("node.example", 3413),
        )
        .await;
        assert!(waiting.is_err(), "waits for tor");
    }

    #[tokio::test]
    async fn a_tor_that_cannot_connect_is_an_error_and_not_a_direct_connection() {
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socks = closed.local_addr().unwrap();
        drop(closed);
        let tor = Arc::new(RelayTor::new(true));
        tor.attach_socks(FixedSocks(socks));
        assert!(dialer(&tor).dial("node.example", 3413).await.is_err());
    }

    #[tokio::test]
    async fn a_loopback_node_stays_direct_while_tor_is_expected() {
        let node = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = node.local_addr().unwrap().port();
        let tor = Arc::new(RelayTor::new(true));
        tor.expect();
        dialer(&tor).dial("127.0.0.1", port).await.unwrap();
        node.accept().await.unwrap();
    }

    #[tokio::test]
    async fn with_tor_off_or_the_setting_off_the_node_is_reached_directly() {
        let node = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = node.local_addr().unwrap().port();
        let tor = Arc::new(RelayTor::new(true));
        dialer(&tor).dial("127.0.0.1", port).await.unwrap();
        node.accept().await.unwrap();

        let (socks, _served) = socks_server().await;
        tor.attach_socks(FixedSocks(socks));
        tor.set_enabled(false);
        dialer(&tor).dial("127.0.0.1", port).await.unwrap();
        node.accept().await.unwrap();
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    use crate::api::types::WalletConfig;

    fn config(node_url: &str) -> WalletConfig {
        WalletConfig {
            data_dir: String::new(),
            chain: crate::api::types::Chain::Floonet,
            node_url: node_url.to_owned(),
            node_api_secret: None,
            epicbox_domain: String::new(),
            epicbox_port: 443,
        }
    }

    #[test]
    fn a_plain_http_node_is_refused_unless_it_is_loopback_or_an_onion() {
        let tor = Arc::new(RelayTor::new(true));
        let routes = Arc::new(OnionRoutes::default());
        let secret = |config: &mut WalletConfig| NodeSecret::take(config);
        for url in ["http://node.btlabs.uk", "http://203.0.113.5:3413"] {
            let mut config = config(url);
            let secret = secret(&mut config);
            let error = NodeFactory::Http
                .client(&config, &secret, &tor, &routes)
                .err()
                .unwrap();
            assert_eq!(error.kind, WalletErrorKind::InvalidArgument, "{url}");
        }
        for url in [
            "https://node.btlabs.uk",
            "http://127.0.0.1:3413",
            "http://localhost:3413",
            "http://abc.onion:3413",
        ] {
            let mut config = config(url);
            let secret = secret(&mut config);
            assert!(
                NodeFactory::Http
                    .client(&config, &secret, &tor, &routes)
                    .is_ok(),
                "{url}"
            );
        }
    }
}
