// SPDX-License-Identifier: Apache-2.0
//! What the CLI takes from the machine it runs on.

use std::future::Future;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use lepic_epicbox::tunnel::OnionRoutes;
use lepic_epicbox::tunnel::{Tunnel, TunnelConnector};
use lepic_epicbox::{Connector, RelayStream, TcpConnector};
use lepic_keychain::KdfParams;
use lepic_node::{
    CallPolicy, DialFuture, HttpTransport, NodeClient, NodeError, NodeStream, RpcTransport,
    is_loopback_host,
};
use lepic_primitives::params::Network;
use lepic_wallet::ports::Clock;
use lepic_wallet_contacts::{PeerDialFuture, PeerDialer, PeerStream};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::app_config::ApiLimits;
use crate::exit::CliError;
use crate::settings::{RelayTor, Settings};

pub type Interrupt = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The node client a [`Host`] hands out: the host's transport behind the connection mode.
pub type HostNode<H> = NodeClient<ModeGate<<H as Host>::Transport>>;

/// How long `lepic serve` waits for its connections and creates to end after it was told to
/// stop, before it drops what is left. Longer than the 30 s a listener gets to settle its
/// message in hand, and under the 90 s a service manager waits by default.
pub const DRAIN_DEADLINE: Duration = Duration::from_secs(45);

/// Longer than any node API secret.
const MAX_API_SECRET_LEN: u64 = 1024;

/// The outside world of one command. [`ProcessHost`] is the real one; tests substitute a mock
/// node, an in-memory relay and a cheap key derivation.
pub trait Host {
    /// How node requests leave the process. The client around it is always a [`NodeClient`],
    /// so a command can start it from the tip the wallet stored.
    type Transport: RpcTransport + Clone + 'static;

    /// The node transport the settings ask for, and the policy of the client around it.
    fn node_transport(
        &self,
        settings: &Settings,
    ) -> Result<(Self::Transport, CallPolicy), CliError>;

    /// The node client of a command. Every node request goes through it, so the connection
    /// mode is kept here: offline, each request fails with [`NodeError::Offline`] before
    /// anything is resolved or connected. Not overridden.
    fn node(&self, settings: &Settings) -> Result<HostNode<Self>, CliError> {
        let (transport, policy) = self.node_transport(settings)?;
        let gate = ModeGate {
            inner: transport,
            offline: settings.offline().is_some(),
        };
        Ok(NodeClient::new(gate, policy))
    }

    /// The relay connector of a command, from [`Self::relay_connector`]; offline, one that
    /// connects nowhere. Not overridden.
    fn relay(&self, settings: &Settings) -> Result<Arc<dyn Connector>, CliError> {
        match settings.offline() {
            Some(reason) => Ok(Arc::new(OfflineRelay(reason))),
            None => self.relay_connector(settings),
        }
    }

    /// The chain the host forces on the settings of a command, `None` when the settings
    /// decide (the flag, `LEPIC_NETWORK`, the config file, then mainnet). The scripted node of
    /// the tests is on a chain of its own.
    fn network(&self) -> Option<Network> {
        None
    }

    /// Reaches the relay directly, or through tor when the settings name one.
    fn relay_connector(&self, settings: &Settings) -> Result<Arc<dyn Connector>, CliError>;

    /// The Argon2 setting of a new vault. Opening a vault reads the setting from the file.
    fn vault_kdf(&self) -> KdfParams;

    /// Resolves when the user asks the command to stop. Called once per command, inside its
    /// runtime, before anything is read, so that an interrupt at a prompt reaches the CLI.
    fn interrupted(&self) -> Interrupt;

    /// Resolves at the next stop signal after the one `serve` is draining for: a second Ctrl-C
    /// or SIGTERM, which ends the drain at once. Called once the drain starts, so the signal
    /// that began it does not count. Never by default.
    fn hurried(&self) -> Interrupt {
        self.interrupted()
    }

    /// How long a stopping `lepic serve` waits for its connections and creates to end. Tests
    /// shorten it.
    fn drain_deadline(&self) -> Duration {
        DRAIN_DEADLINE
    }

    /// Resolves when the process is told to end, as a service manager does with SIGTERM. The
    /// interactive shell leaves on it; Ctrl+C there only cancels what runs. Never by default.
    fn terminated(&self) -> Interrupt {
        Box::pin(std::future::pending())
    }

    /// How often `lepic serve` refreshes the wallet against the node, about once a block, when
    /// no boost runs. Tests shorten it.
    fn maintenance_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    /// How often `lepic serve` runs the delivery layer's tick when no boost runs. Tests shorten
    /// it.
    fn collect_interval(&self) -> Duration {
        Duration::from_secs(30)
    }

    /// How `tor` entries of links are reached: through the tor the settings name. `None` with
    /// Tor off, and such an entry is not posted.
    fn peer_dialer(&self, _settings: &Settings) -> Option<Arc<dyn PeerDialer>> {
        None
    }

    /// The wallet's clock. Tests move it.
    fn clock(&self) -> Arc<dyn Clock> {
        Arc::new(SystemClock)
    }

    /// The bounds of serve's API, from the configured ones. Tests tighten them.
    fn api_limits(&self, configured: ApiLimits) -> ApiLimits {
        configured
    }

    /// How many invoices opened by hand serve holds for approval at once. Tests lower it.
    fn max_held_invoices(&self) -> usize {
        100
    }
}

/// A node transport that refuses every request while the command is offline.
#[derive(Clone)]
pub struct ModeGate<T> {
    inner: T,
    offline: bool,
}

impl<T: RpcTransport> RpcTransport for ModeGate<T> {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        if self.offline {
            return Err(NodeError::Offline);
        }
        self.inner.post(endpoint, body).await
    }

    fn node_label(&self) -> &str {
        self.inner.node_label()
    }
}

/// Why an offline command reached for the relay, carried inside the connector's error.
#[derive(Debug, thiserror::Error)]
#[error("no relay connection: {0}")]
pub struct RelayOffline(pub crate::settings::OfflineReason);

/// Whether `error` is a [`RelayOffline`], or an I/O error that carries one.
pub fn is_relay_offline(error: &(dyn std::error::Error + 'static)) -> bool {
    error.is::<RelayOffline>()
        || error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<RelayOffline>)
}

/// The relay connector of an offline command: every connection fails with [`RelayOffline`].
struct OfflineRelay(crate::settings::OfflineReason);

impl Connector for OfflineRelay {
    fn connect<'a>(
        &'a self,
        _: &'a lepic_epicbox::RelayEndpoint,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn RelayStream>>> + Send + 'a>> {
        let reason = self.0;
        Box::pin(async move { Err(std::io::Error::other(RelayOffline(reason))) })
    }
}

/// The node over HTTP, the relay over TCP and TLS, Ctrl-C.
#[derive(Default)]
pub struct ProcessHost {
    /// The tor the settings name, shared by the relay and the node so one command runs one tor.
    tor: std::sync::OnceLock<Option<Arc<CliTor>>>,
}

impl ProcessHost {
    fn tor(&self, settings: &Settings) -> Option<Arc<CliTor>> {
        self.tor.get_or_init(|| cli_tor(settings)).clone()
    }
}

impl Host for ProcessHost {
    type Transport = HttpTransport;

    fn node_transport(
        &self,
        settings: &Settings,
    ) -> Result<(Self::Transport, CallPolicy), CliError> {
        let api_secret = match &settings.node_api_secret_file {
            Some(path) => Some(read_api_secret(path)?),
            None => None,
        };
        let http = settings.tuning.node_http(api_secret);
        let tls = lepic_node::webpki_tls_config()?;
        let transport = match self.tor(settings).filter(|_| settings.node_over_tor) {
            Some(tor) => HttpTransport::with_dialer(
                settings.node.as_str(),
                &http,
                tls,
                Arc::new(CliNodeDialer {
                    tor,
                    routes: OnionRoutes::new(settings.servers.onion_routes.clone()),
                }),
            )?,
            None => HttpTransport::new(settings.node.as_str(), &http, tls)?,
        };
        Ok((transport, settings.tuning.call_policy))
    }

    fn relay_connector(&self, settings: &Settings) -> Result<Arc<dyn Connector>, CliError> {
        let tls = lepic_node::webpki_tls_config()?;
        Ok(match self.tor(settings) {
            None => Arc::new(TcpConnector::new(tls)),
            Some(tor) => Arc::new(TunnelConnector::with_routes(
                tls,
                Arc::new(RelayTunnel {
                    tor,
                    active: tokio::sync::watch::Sender::new(true),
                }),
                Arc::new(OnionRoutes::new(settings.servers.onion_routes.clone())),
                settings.tuning.tunnel,
            )),
        })
    }

    fn peer_dialer(&self, settings: &Settings) -> Option<Arc<dyn PeerDialer>> {
        let tor = self.tor(settings)?;
        Some(Arc::new(CliPeerDialer { tor }))
    }

    fn vault_kdf(&self) -> KdfParams {
        KdfParams::DEFAULT
    }

    /// Ctrl-C or SIGTERM, the signal a service manager stops a service with. The handlers are
    /// installed here, not on first poll, so no signal between this call and the first prompt
    /// can end the process with echo off. A signal whose handler cannot be installed is not
    /// waited for.
    #[cfg(unix)]
    fn interrupted(&self) -> Interrupt {
        Box::pin(first_signal(vec![
            unix_signal(tokio::signal::unix::SignalKind::interrupt()),
            unix_signal(tokio::signal::unix::SignalKind::terminate()),
        ]))
    }

    /// SIGTERM, with its handler installed here as [`Self::interrupted`] does.
    #[cfg(unix)]
    fn terminated(&self) -> Interrupt {
        Box::pin(first_signal(vec![unix_signal(
            tokio::signal::unix::SignalKind::terminate(),
        )]))
    }

    /// Ctrl+C, or a console event that ends the process ([`Self::terminated`]), with the
    /// handlers installed here as on Unix. While one is installed, an event no longer ends the
    /// process at once and the command can restore the console.
    #[cfg(not(unix))]
    fn interrupted(&self) -> Interrupt {
        let mut signals = console_endings();
        signals.push(console_ctrl_c());
        Box::pin(first_signal(signals))
    }

    /// The console events Windows ends a process with, as SIGTERM does on Unix. Windows ends
    /// the process a few seconds after a close, logoff or shutdown event whatever the handler
    /// does, so the shell has that long to leave.
    #[cfg(not(unix))]
    fn terminated(&self) -> Interrupt {
        Box::pin(first_signal(console_endings()))
    }
}

/// One signal's next delivery: `None` when its handler could not be installed or its stream
/// ended.
type Signal = Pin<Box<dyn Future<Output = Option<()>> + Send>>;

/// Resolves on the first delivery of any of `signals`, and never when none can be delivered.
async fn first_signal(signals: Vec<Signal>) {
    use futures_util::StreamExt as _;
    let mut waiting: futures_util::stream::FuturesUnordered<Signal> = signals.into_iter().collect();
    while let Some(delivered) = waiting.next().await {
        if delivered.is_some() {
            return;
        }
    }
    std::future::pending::<()>().await;
}

#[cfg(unix)]
fn unix_signal(kind: tokio::signal::unix::SignalKind) -> Signal {
    let signal = tokio::signal::unix::signal(kind).ok();
    Box::pin(async move { signal?.recv().await })
}

/// The next event of a tokio console event stream, its handler installed now. The streams
/// share a `recv` but no trait.
#[cfg(not(unix))]
macro_rules! console_signal {
    ($install:expr) => {{
        let installed = $install.ok();
        let signal: Signal = Box::pin(async move { installed?.recv().await });
        signal
    }};
}

/// Ctrl+Break, the console being closed, the user logging off and the system shutting down.
/// Ctrl+Break is also what a process manager sends a console process group to stop it.
#[cfg(not(unix))]
fn console_endings() -> Vec<Signal> {
    use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_logoff, ctrl_shutdown};
    vec![
        console_signal!(ctrl_break()),
        console_signal!(ctrl_close()),
        console_signal!(ctrl_logoff()),
        console_signal!(ctrl_shutdown()),
    ]
}

#[cfg(not(unix))]
fn console_ctrl_c() -> Signal {
    console_signal!(tokio::signal::windows::ctrl_c())
}

/// The directory inside the data directory that holds the files of the relay's tor, apart from
/// those of `tor listen`, which may run at the same time.
const RELAY_TOR_DIR: &str = "tor-epicbox";

/// The tor the settings name. While there is one, the relay is never reached directly, nor the
/// node when `node_over_tor` is set.
fn cli_tor(settings: &Settings) -> Option<Arc<CliTor>> {
    let relay = lepic_methods::tor::RelayTor::new(true, settings.tuning.tor_connect);
    let start = match &settings.relay_tor {
        RelayTor::Off => return None,
        RelayTor::Socks(address) => {
            relay.attach_socks(lepic_methods::tor::FixedSocks(*address));
            None
        }
        RelayTor::Binary { binary, lib_dir } => {
            let mut tor = lepic_methods::tor::TorSettings::new(
                binary.clone(),
                settings.data_dir.join(RELAY_TOR_DIR),
                settings.tuning.tor_timings(),
            );
            tor.lib_dir.clone_from(lib_dir);
            tor.withheld_env = vec![crate::secret::PASSWORD_ENV.to_owned()];
            Some(tor)
        }
    };
    Some(Arc::new(CliTor {
        relay,
        start: std::sync::Mutex::new(start),
    }))
}

/// Tor for the relay and node connections, started on the first connection when the CLI runs it.
struct CliTor {
    relay: lepic_methods::tor::RelayTor,
    start: std::sync::Mutex<Option<lepic_methods::tor::TorSettings>>,
}

impl CliTor {
    async fn open(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        let start = self
            .start
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(start) = start {
            self.relay
                .attach(Arc::new(lepic_methods::tor::TorProcess::start(start)));
        }
        self.relay
            .open(host, port)
            .await
            .map_err(std::io::Error::other)
    }
}

struct RelayTunnel {
    tor: Arc<CliTor>,
    /// Always on: the relay goes through tor for the whole command.
    active: tokio::sync::watch::Sender<bool>,
}

impl Tunnel for RelayTunnel {
    fn active(&self) -> tokio::sync::watch::Receiver<bool> {
        self.active.subscribe()
    }

    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn RelayStream>>> + Send + 'a>> {
        Box::pin(async move {
            let stream = self.tor.open(host, port).await?;
            Ok(Box::new(stream) as Box<dyn RelayStream>)
        })
    }

    fn is_onion(&self, host: &str) -> bool {
        lepic_methods::tor::RelayTor::is_onion(host)
    }
}

/// Node connections through tor: to the node's onion when one is known, else to its name
/// through the exit. A loopback node is reached directly. Never directly otherwise.
struct CliNodeDialer {
    tor: Arc<CliTor>,
    routes: OnionRoutes,
}

impl lepic_node::NodeDialer for CliNodeDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = if is_loopback_host(host) {
                tokio::net::TcpStream::connect((host, port)).await?
            } else {
                match self.routes.route_to(host, port) {
                    Some(onion) => self.tor.open(&onion.host, onion.port).await?,
                    None => self.tor.open(host, port).await?,
                }
            };
            Ok(Box::new(stream) as Box<dyn NodeStream>)
        })
    }
}

/// Connections to `tor` entries of links, each through tor on a circuit of its own.
struct CliPeerDialer {
    tor: Arc<CliTor>,
}

impl PeerDialer for CliPeerDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> PeerDialFuture<'a> {
        Box::pin(async move {
            let stream = self.tor.open(host, port).await?;
            Ok(Box::new(stream) as Box<dyn PeerStream>)
        })
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// The node's `.foreign_api_secret`, as `epic-wallet` reads it: the file's text, trimmed, cut at
/// [`MAX_API_SECRET_LEN`] bytes.
fn read_api_secret(path: &std::path::Path) -> Result<SecretString, CliError> {
    let file = std::fs::File::open(path).map_err(CliError::io("read the node api secret file"))?;
    let mut bytes = api_secret_buffer();
    file.take(MAX_API_SECRET_LEN)
        .read_to_end(&mut bytes)
        .map_err(CliError::io("read the node api secret file"))?;
    api_secret_from(&bytes)
}

/// Holds the most a read takes from the start, and one byte more so a full read never makes the
/// reader grow it: a growing `Vec` leaves the bytes it moved out of in freed memory, where
/// `Zeroizing` cannot wipe them.
fn api_secret_buffer() -> Zeroizing<Vec<u8>> {
    let capacity = usize::try_from(MAX_API_SECRET_LEN)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    Zeroizing::new(Vec::with_capacity(capacity))
}

/// The one copy that leaves is sized exactly, so the secret type keeps it without moving it.
fn api_secret_from(bytes: &[u8]) -> Result<SecretString, CliError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        CliError::io("read the node api secret file")(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the node api secret is not valid utf-8",
        ))
    })?;
    Ok(SecretString::from(text.trim()))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn the_longest_api_secret_is_read_without_moving_the_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".foreign_api_secret");
        let limit = usize::try_from(MAX_API_SECRET_LEN).unwrap();
        std::fs::write(&path, "k".repeat(limit + 10)).unwrap();
        let mut bytes = api_secret_buffer();
        let start = bytes.as_ptr();
        std::fs::File::open(&path)
            .unwrap()
            .take(MAX_API_SECRET_LEN)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), limit);
        assert_eq!(bytes.as_ptr(), start);
    }

    #[test]
    fn reads_the_api_secret_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".foreign_api_secret");
        std::fs::write(&path, "  s3cret\r\n").unwrap();
        assert_eq!(read_api_secret(&path).unwrap().expose_secret(), "s3cret");
        std::fs::write(&path, [0xff, b'\n']).unwrap();
        assert!(matches!(
            read_api_secret(&path),
            Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    /// A signal whose handler is missing or whose stream ended leaves the others waited for.
    #[test]
    fn the_first_delivered_signal_resolves_past_an_ended_one() {
        use futures_util::FutureExt as _;
        let (deliver, delivery) = tokio::sync::oneshot::channel::<()>();
        let ended: Signal = Box::pin(std::future::ready(None));
        let pending: Signal = Box::pin(async move { delivery.await.ok() });
        let mut waiting = Box::pin(first_signal(vec![ended, pending]));
        assert!(waiting.as_mut().now_or_never().is_none());
        deliver.send(()).unwrap();
        assert!(waiting.as_mut().now_or_never().is_some());
    }

    #[test]
    fn no_deliverable_signal_never_resolves() {
        use futures_util::FutureExt as _;
        let ended = || -> Signal { Box::pin(std::future::ready(None)) };
        let mut waiting = Box::pin(first_signal(vec![ended(), ended()]));
        assert!(waiting.as_mut().now_or_never().is_none());
        assert!(
            Box::pin(first_signal(Vec::new()))
                .as_mut()
                .now_or_never()
                .is_none()
        );
    }

    /// Each console event gets its handler: one that failed would read as ended at once.
    #[cfg(not(unix))]
    #[test]
    fn every_console_event_handler_installs() {
        use futures_util::FutureExt as _;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut signals = console_endings();
            signals.push(console_ctrl_c());
            assert_eq!(signals.len(), 5);
            for mut signal in signals {
                assert!(signal.as_mut().now_or_never().is_none());
            }
        });
    }
}
