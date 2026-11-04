// SPDX-License-Identifier: Apache-2.0
//! What the CLI takes from the machine it runs on.

use std::future::Future;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use lepic_epicbox::tunnel::OnionRoutes;
use lepic_epicbox::tunnel::{Tunnel, TunnelConnector};
use lepic_epicbox::{Connector, RelayStream, TcpConnector};
use lepic_keychain::KdfParams;
use lepic_node::{
    DialFuture, HttpTransport, NodeClient, NodeStream, RpcTransport, is_loopback_host,
};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::exit::CliError;
use crate::settings::{RelayTor, Settings};

pub type Interrupt = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The node client a [`Host`] hands out.
pub type HostNode<H> = NodeClient<<H as Host>::Transport>;

/// The host feature bits the wallet's marker claims: the directory bit when built with the
/// `directory-host` feature, none otherwise.
#[cfg(feature = "directory-host")]
pub const HOST_FEATURES: u32 = lepic_epicbox::marker::features::DIRECTORY;
#[cfg(not(feature = "directory-host"))]
pub const HOST_FEATURES: u32 = 0;

/// Longer than any node API secret.
const MAX_API_SECRET_LEN: u64 = 1024;

/// The outside world of one command. [`ProcessHost`] is the real one; tests substitute a mock
/// node, an in-memory relay and a cheap key derivation.
pub trait Host {
    /// How node requests leave the process. The client around it is always a [`NodeClient`],
    /// so a command can start it from the tip the wallet stored.
    type Transport: RpcTransport + Clone + 'static;

    fn node(&self, settings: &Settings) -> Result<HostNode<Self>, CliError>;

    /// Reaches the relay directly, or through tor when the settings name one.
    fn relay_connector(&self, settings: &Settings) -> Result<Arc<dyn Connector>, CliError>;

    /// The Argon2 setting of a new vault. Opening a vault reads the setting from the file.
    fn vault_kdf(&self) -> KdfParams;

    /// Resolves when the user asks the command to stop. Called once per command, inside its
    /// runtime, before anything is read, so that an interrupt at a prompt reaches the CLI.
    fn interrupted(&self) -> Interrupt;

    /// How often `lepic serve` collects the contact mailboxes and refreshes the wallet, as the
    /// app's foreground tick does. Tests shorten it.
    fn maintenance_interval(&self) -> Duration {
        Duration::from_secs(60)
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

    fn node(&self, settings: &Settings) -> Result<HostNode<Self>, CliError> {
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
        Ok(NodeClient::new(transport, settings.tuning.call_policy))
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

    fn vault_kdf(&self) -> KdfParams {
        KdfParams::DEFAULT
    }

    /// Ctrl-C or SIGTERM, the signal a service manager stops a service with. The handlers are
    /// installed here, not on first poll, so no signal between this call and the first prompt
    /// can end the process with echo off. A signal whose handler cannot be installed is not
    /// waited for.
    #[cfg(unix)]
    fn interrupted(&self) -> Interrupt {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt()).ok();
        let mut terminate = signal(SignalKind::terminate()).ok();
        Box::pin(async move {
            tokio::select! {
                Some(()) = next_signal(interrupt.as_mut()) => {}
                Some(()) = next_signal(terminate.as_mut()) => {}
                else => std::future::pending::<()>().await,
            }
        })
    }

    #[cfg(not(unix))]
    fn interrupted(&self) -> Interrupt {
        Box::pin(async {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        })
    }
}

/// The next delivery of `signal`; `None` when it has no handler or its stream ended.
#[cfg(unix)]
async fn next_signal(signal: Option<&mut tokio::signal::unix::Signal>) -> Option<()> {
    signal?.recv().await
}

/// The directory inside the data directory that holds the files of the relay's tor, apart from
/// those of `tor listen`, which may run at the same time.
const RELAY_TOR_DIR: &str = "tor-epicbox";

/// The tor the settings name. While there is one, the relay is never reached directly, nor the
/// node when `node_over_tor` is set.
fn cli_tor(settings: &Settings) -> Option<Arc<CliTor>> {
    let relay = lepic_tor::RelayTor::new(true, settings.tuning.tor_connect);
    let start = match &settings.relay_tor {
        RelayTor::Off => return None,
        RelayTor::Socks(address) => {
            relay.attach_socks(lepic_tor::FixedSocks(*address));
            None
        }
        RelayTor::Binary { binary, lib_dir } => {
            let mut tor = lepic_tor::TorSettings::new(
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
    relay: lepic_tor::RelayTor,
    start: std::sync::Mutex<Option<lepic_tor::TorSettings>>,
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
                .attach(Arc::new(lepic_tor::TorProcess::start(start)));
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
        lepic_tor::RelayTor::is_onion(host)
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
    fn the_directory_bit_is_claimed_only_with_the_directory_host_feature() {
        let expected = if cfg!(feature = "directory-host") {
            32
        } else {
            0
        };
        assert_eq!(HOST_FEATURES, expected);
    }

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
}
