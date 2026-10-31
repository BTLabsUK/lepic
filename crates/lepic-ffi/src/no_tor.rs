// SPDX-License-Identifier: Apache-2.0
//! What the build without the `tor` feature has in place of `lepic-tor` (ADR 0026): a way
//! through tor that is never on, so node requests and the relay connection always go directly
//! and an onion host fails at once.

use std::fmt;

use tokio::net::TcpStream;
use tokio::sync::watch;

/// Why a connection could not go through tor: this build has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayTorError {
    Off,
}

impl fmt::Display for RelayTorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("this build of LEPIC has no Tor")
    }
}

impl std::error::Error for RelayTorError {}

/// The wallet's tor as a way to a host, in a build that has no tor: never active.
#[derive(Debug)]
pub(crate) struct RelayTor {
    active: watch::Sender<bool>,
}

impl RelayTor {
    pub(crate) fn new(_enabled: bool, _connect_timeout: std::time::Duration) -> Self {
        Self {
            active: watch::Sender::new(false),
        }
    }

    pub(crate) fn direct(enabled: bool, connect_timeout: std::time::Duration) -> Self {
        Self::new(enabled, connect_timeout)
    }

    /// Always `false`.
    pub(crate) fn active(&self) -> watch::Receiver<bool> {
        self.active.subscribe()
    }

    /// Always [`RelayTorError::Off`].
    pub(crate) async fn open(&self, _host: &str, _port: u16) -> Result<TcpStream, RelayTorError> {
        Err(RelayTorError::Off)
    }

    /// Always [`RelayTorError::Off`].
    pub(crate) async fn open_in(
        &self,
        _host: &str,
        _port: u16,
        _group: &StreamGroup,
    ) -> Result<TcpStream, RelayTorError> {
        Err(RelayTorError::Off)
    }
}

/// Streams that would share a tor circuit; this build has no tor. Braced rather than a unit
/// struct, so the callers' `StreamGroup::default()` reads the same in both builds.
#[derive(Debug, Default)]
pub(crate) struct StreamGroup {}
