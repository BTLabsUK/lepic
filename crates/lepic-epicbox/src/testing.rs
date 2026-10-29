// SPDX-License-Identifier: Apache-2.0
//! The settings the app ships, for tests: the library has no defaults of its own.

use std::time::Duration;

use crate::tunnel::TunnelTimings;
use crate::{Backoff, ClientSettings, ClientTimings, RelayEndpoint};

/// The app's relay client timeouts and reconnect backoff.
#[must_use]
pub const fn client_timings() -> ClientTimings {
    ClientTimings {
        connect_timeout: Duration::from_secs(15),
        response_timeout: Duration::from_secs(15),
        ping_interval: Duration::from_secs(25),
        backoff: Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
        },
        drain_timeout: Duration::from_secs(120),
    }
}

/// A client of `endpoint` with [`client_timings`].
#[must_use]
pub fn client_settings(endpoint: RelayEndpoint) -> ClientSettings {
    ClientSettings::new(endpoint, client_timings())
}

/// The app's timeouts through a tunnel.
#[must_use]
pub const fn tunnel_timings() -> TunnelTimings {
    TunnelTimings {
        connect_timeout: Duration::from_secs(90),
        discovery_timeout: Duration::from_secs(45),
        discovery_retry: Duration::from_secs(600),
    }
}
