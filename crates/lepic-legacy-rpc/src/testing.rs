// SPDX-License-Identifier: Apache-2.0
//! The settings the app ships, for tests: the library has no defaults of its own.

use std::time::Duration;

use crate::rpc::MAX_BODY_LEN;
use crate::{ClientSettings, ListenLimits};

/// The app's listener limits.
#[must_use]
pub const fn listen_limits() -> ListenLimits {
    ListenLimits {
        max_connections: 16,
        max_connections_per_address: 4,
        header_timeout: Duration::from_secs(10),
        body_timeout: Duration::from_secs(15),
        request_timeout: Duration::from_secs(60),
        answer_timeout: Duration::from_secs(10),
        requests_per_minute: 120,
        receives_per_minute: 30,
    }
}

/// The app's limits of a send to another wallet's listener.
#[must_use]
pub const fn client_settings() -> ClientSettings {
    ClientSettings {
        connect_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(60),
        max_response_bytes: MAX_BODY_LEN,
    }
}
