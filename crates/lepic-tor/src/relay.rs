// SPDX-License-Identifier: Apache-2.0
//! The wallet's tor for its Epicbox relay connection (ADR 0021): streams to the relay's onion,
//! or to its domain through an exit, while the setting is on. With the setting on it never
//! goes directly until the host detaches tor or turns the setting off.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::onion::OnionAddress;
use crate::process::{FixedSocks, SocksProxy, TorFailure, TorProcess};
use crate::socks::{self, DEFAULT_CONNECT_TIMEOUT, SocksCredentials, SocksError};

/// Why no stream to the relay was opened through tor.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayTorError {
    #[error("tor is off")]
    Off,
    #[error("tor is not connected to the tor network")]
    Tor(#[source] TorFailure),
    #[error("tor could not reach the relay")]
    Socks(#[source] SocksError),
}

#[derive(Clone)]
enum Source {
    /// A tor that is expected and is not attached yet.
    Pending,
    /// The wallet's own tor, which may still be starting.
    Process(Arc<TorProcess>),
    /// A tor the wallet does not run.
    Fixed(FixedSocks),
}

struct Inner {
    enabled: bool,
    /// `None` only after [`RelayTor::detach`] or for [`RelayTor::direct`].
    source: Option<Source>,
}

/// Whether the relay connection goes through tor, and the tor it goes through. It does while
/// the setting is on and tor has not been detached: a tor attached, being started or still
/// to come. Only [`RelayTor::detach`] or turning the setting off lets it go directly.
pub struct RelayTor {
    inner: Mutex<Inner>,
    active: watch::Sender<bool>,
    /// Counts changes of the source, for an open that waits for a pending tor.
    changes: watch::Sender<u64>,
}

impl RelayTor {
    /// Waiting for a tor while `enabled`: connections wait until one is attached, and never
    /// go directly until [`RelayTor::detach`] or [`RelayTor::set_enabled`] with `false`.
    pub fn new(enabled: bool) -> Self {
        Self::with_source(enabled, Some(Source::Pending))
    }

    /// Detached from the start: connections go directly until a tor is expected or
    /// attached. For a host that knows no tor is wanted.
    pub fn direct(enabled: bool) -> Self {
        Self::with_source(enabled, None)
    }

    fn with_source(enabled: bool, source: Option<Source>) -> Self {
        let active = enabled && source.is_some();
        Self {
            inner: Mutex::new(Inner { enabled, source }),
            active: watch::Sender::new(active),
            changes: watch::Sender::new(0),
        }
    }

    fn change(&self, change: impl FnOnce(&mut Inner)) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        change(&mut inner);
        let active = inner.enabled && inner.source.is_some();
        self.active.send_if_modified(|now| {
            let changed = *now != active;
            *now = active;
            changed
        });
        drop(inner);
        self.changes
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    fn source(&self) -> Option<Source> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.enabled.then(|| inner.source.clone()).flatten()
    }

    /// The setting: with it off, the relay is reached directly even while tor runs.
    pub fn set_enabled(&self, enabled: bool) {
        self.change(|inner| inner.enabled = enabled);
    }

    pub fn enabled(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .enabled
    }

    /// A tor is being started: relay connections wait for it from now on instead of going
    /// directly, until [`RelayTor::attach`] or [`RelayTor::detach`].
    pub fn expect(&self) {
        self.change(|inner| inner.source = Some(Source::Pending));
    }

    /// Relay connections go through `tor` from now on, waiting for it to bootstrap.
    pub fn attach(&self, tor: Arc<TorProcess>) {
        self.change(|inner| inner.source = Some(Source::Process(tor)));
    }

    /// Relay connections go through the SOCKS proxy at `socks` from now on.
    pub fn attach_socks(&self, socks: FixedSocks) {
        self.change(|inner| inner.source = Some(Source::Fixed(socks)));
    }

    /// No tor any more: relay connections go directly from now on, and a connection
    /// waiting for a tor fails.
    pub fn detach(&self) {
        self.change(|inner| inner.source = None);
    }

    /// Whether relay connections go through tor, now and as it changes.
    pub fn active(&self) -> watch::Receiver<bool> {
        self.active.subscribe()
    }

    /// A stream to `host:port` through tor, on a circuit of its own. Waits for a tor that is
    /// still being started or bootstrapping; the caller bounds the wait.
    pub async fn open(&self, host: &str, port: u16) -> Result<TcpStream, RelayTorError> {
        let mut changes = self.changes.subscribe();
        let proxy: SocketAddr = loop {
            changes.borrow_and_update();
            match self.source().ok_or(RelayTorError::Off)? {
                Source::Pending => {
                    if changes.changed().await.is_err() {
                        return Err(RelayTorError::Off);
                    }
                }
                Source::Process(tor) => {
                    break tor.wait_bootstrapped().await.map_err(RelayTorError::Tor)?;
                }
                Source::Fixed(socks) => break socks.socks_address().ok_or(RelayTorError::Off)?,
            }
        };
        let credentials = SocksCredentials::random().map_err(RelayTorError::Socks)?;
        socks::connect(proxy, host, port, &credentials, DEFAULT_CONNECT_TIMEOUT)
            .await
            .map_err(RelayTorError::Socks)
    }

    /// Whether `host` is a v3 onion host as tor is asked for it: `<56 characters>.onion`.
    pub fn is_onion(host: &str) -> bool {
        OnionAddress::parse(host).is_ok_and(|onion| onion.host() == host)
    }
}

impl std::fmt::Debug for RelayTor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTor")
            .field("active", &*self.active.borrow())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn it_is_active_only_with_the_setting_on_and_tor_not_detached() {
        let relay = RelayTor::direct(true);
        let active = relay.active();
        assert!(!*active.borrow());
        relay.attach_socks(FixedSocks(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050))));
        assert!(*active.borrow());
        relay.set_enabled(false);
        assert!(!*active.borrow() && !relay.enabled());
        relay.set_enabled(true);
        assert!(*active.borrow());
        relay.detach();
        assert!(!*active.borrow());
    }

    #[tokio::test]
    async fn a_tor_being_started_makes_connections_wait_for_it() {
        let relay = Arc::new(RelayTor::new(true));
        relay.expect();
        assert!(*relay.active().borrow(), "never direct while tor starts");
        let opening = tokio::spawn({
            let relay = Arc::clone(&relay);
            async move { relay.open("relay.example", 443).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!opening.is_finished(), "waits for the tor");
        relay.detach();
        assert!(matches!(opening.await.unwrap(), Err(RelayTorError::Off)));
    }

    #[tokio::test]
    async fn with_the_setting_on_it_waits_for_a_tor_until_one_is_attached_or_detached() {
        let relay = Arc::new(RelayTor::new(true));
        assert!(
            *relay.active().borrow(),
            "never direct before a tor is attached"
        );
        let opening = tokio::spawn({
            let relay = Arc::clone(&relay);
            async move { relay.open("relay.example", 443).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!opening.is_finished(), "waits for a tor");
        relay.detach();
        assert!(!*relay.active().borrow());
        assert!(matches!(opening.await.unwrap(), Err(RelayTorError::Off)));
    }

    #[test]
    fn with_the_setting_off_it_goes_directly_until_the_setting_is_on() {
        let relay = RelayTor::new(false);
        assert!(!*relay.active().borrow());
        relay.set_enabled(true);
        assert!(*relay.active().borrow(), "still waiting for a tor");
    }

    #[tokio::test]
    async fn without_tor_or_with_the_setting_off_nothing_is_opened() {
        let relay = RelayTor::direct(true);
        assert!(matches!(
            relay.open("relay.example", 443).await,
            Err(RelayTorError::Off)
        ));
        relay.attach_socks(FixedSocks(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050))));
        relay.set_enabled(false);
        assert!(matches!(
            relay.open("relay.example", 443).await,
            Err(RelayTorError::Off)
        ));
    }

    #[tokio::test]
    async fn a_stream_goes_through_the_socks_proxy_to_the_host_asked() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 2 + 32 + 1 + 32];
            stream.read_exact(&mut auth).await.unwrap();
            stream.write_all(&[1, 0]).await.unwrap();
            let host = "relay.example";
            let mut connect = vec![0u8; 5 + host.len() + 2];
            stream.read_exact(&mut connect).await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            connect
        });
        let relay = RelayTor::new(true);
        relay.attach_socks(FixedSocks(address));
        relay.open("relay.example", 443).await.unwrap();
        let connect = server.await.unwrap();
        assert_eq!(
            connect,
            socks::encode_connect("relay.example", 443).unwrap()
        );
    }

    #[test]
    fn only_a_v3_onion_host_is_an_onion() {
        let onion = "j2xf5rizkow5jtrdf6edotk5qam4kohavip23dqeuih5bq4yqisbz5ad.onion";
        assert!(RelayTor::is_onion(onion));
        for host in [
            "j2xf5rizkow5jtrdf6edotk5qam4kohavip23dqeuih5bq4yqisbz5ad",
            "J2XF5RIZKOW5JTRDF6EDOTK5QAM4KOHAVIP23DQEUIH5BQ4YQISBZ5AD.onion",
            "j2xf5rizkow5jtrdf6edotk5qam4kohavip23dqeuih5bq4yqisbz5ae.onion",
            "http://j2xf5rizkow5jtrdf6edotk5qam4kohavip23dqeuih5bq4yqisbz5ad.onion",
            "relay.example",
        ] {
            assert!(!RelayTor::is_onion(host), "{host}");
        }
    }
}
