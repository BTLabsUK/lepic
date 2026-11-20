// SPDX-License-Identifier: Apache-2.0
//! The wallet's tor in a build without the `tor` feature (ADR 0026): the session has none.
//! Every call that needs tor fails with `Unsupported`, Tor reports as off, and the settings of
//! Epicbox and node requests over Tor read as off and change nothing, so the relay and the
//! node are always reached directly.

use std::sync::Arc;

use super::Session;
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::http::{HttpResentTx, HttpSentTx};
use crate::api::tor::{OnionRoute, TorEvent, TorStatus, TorStatusKind};
use crate::api::types::SendOptions;

/// Where the tor events of a session would go.
pub(crate) type TorReport = Arc<dyn Fn(TorEvent) + Send + Sync>;

fn tor_not_built() -> WalletError {
    WalletError::new(
        WalletErrorKind::Unsupported,
        "this build of LEPIC has no Tor",
    )
}

impl Session {
    pub(crate) fn onion_address(&self) -> Result<String, WalletError> {
        Err(tor_not_built())
    }

    pub(crate) fn previous_onion_address(&self) -> Result<String, WalletError> {
        Err(tor_not_built())
    }

    /// Fails with `Unsupported`, reporting nothing.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) async fn start_tor(
        self: &Arc<Self>,
        _tor_binary: String,
        _lib_dir: Option<String>,
        _publish_onion: bool,
        _report: TorReport,
    ) -> Result<(), WalletError> {
        Err(tor_not_built())
    }

    pub(crate) fn stop_tor(&self) {}

    pub(super) fn stop_tor_for_lock(&self) {}

    pub(crate) fn tor_status(&self) -> TorStatus {
        TorStatus {
            kind: TorStatusKind::Off,
            progress: None,
            onion: None,
            socks_port: None,
            failure: None,
        }
    }

    pub(crate) async fn refresh_tor(&self, _network_changed: bool) -> Result<(), WalletError> {
        Err(tor_not_built())
    }

    /// Nothing to do: no tor runs.
    pub(crate) async fn tor_network_lost(&self) -> Result<(), WalletError> {
        Ok(())
    }

    /// Fails with `Unsupported` before anything is checked or stored.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) async fn send_tor(
        &self,
        _amount: u64,
        _minimum_confirmations: u64,
        _to: &str,
        _message: Option<String>,
        _options: Option<SendOptions>,
    ) -> Result<HttpSentTx, WalletError> {
        Err(tor_not_built())
    }

    pub(crate) async fn resend_tor(
        &self,
        _tx_id: u32,
        _to: &str,
    ) -> Result<HttpResentTx, WalletError> {
        Err(tor_not_built())
    }

    pub(crate) fn set_epicbox_over_tor(&self, _enabled: bool) {}

    pub(crate) fn epicbox_over_tor(&self) -> bool {
        false
    }

    /// Accepts any list and keeps none: without tor no connection goes to an onion.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn set_onion_routes(&self, _routes: Vec<OnionRoute>) -> Result<(), WalletError> {
        Ok(())
    }

    pub(crate) fn set_node_over_tor(&self, _enabled: bool) {}

    pub(crate) fn node_over_tor(&self) -> bool {
        false
    }

    pub(crate) fn set_http_over_tor(&self, _enabled: bool) {}

    pub(crate) fn http_over_tor(&self) -> bool {
        false
    }

    /// Nothing to wait for, as on iOS. Fails with `Locked` while the wallet is locked.
    pub(crate) fn expect_tor(&self) -> Result<(), WalletError> {
        self.ensure_unlocked()
    }
}
