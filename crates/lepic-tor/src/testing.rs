// SPDX-License-Identifier: Apache-2.0
//! The settings the app ships, for tests: the library has no defaults of its own.

use std::time::Duration;

use crate::{OnionClientSettings, TorNetworkTimings, TorTimings};

/// Reaching a host through tor.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(75);

/// The app's tor network timings.
#[must_use]
pub const fn network_timings() -> TorNetworkTimings {
    TorNetworkTimings {
        stall: Duration::from_secs(60),
        bootstrap: Duration::from_secs(120),
        cold_stall: Duration::from_secs(120),
        cold_bootstrap: Duration::from_secs(240),
        publish: Duration::from_secs(180),
    }
}

/// [`network_timings`] with the crate's local waits.
#[must_use]
pub const fn tor_timings() -> TorTimings {
    TorTimings::new(network_timings())
}

/// The app's limits of a send over tor.
#[must_use]
pub const fn onion_client_settings() -> OnionClientSettings {
    OnionClientSettings {
        connect_timeout: CONNECT_TIMEOUT,
        request_timeout: Duration::from_secs(120),
        max_response_bytes: lepic_legacy_rpc::rpc::MAX_BODY_LEN,
    }
}
