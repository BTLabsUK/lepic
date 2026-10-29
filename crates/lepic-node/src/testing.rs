// SPDX-License-Identifier: Apache-2.0
//! The settings the app ships, for tests: the library has no defaults of its own.

use std::time::Duration;

use crate::{CallPolicy, HttpSettings, MAX_RESPONSE_BYTES, RetryPolicy};

/// HTTP settings with the app's node timeouts and no API secret.
#[must_use]
pub fn http_settings() -> HttpSettings {
    HttpSettings {
        connect_timeout: Duration::from_secs(15),
        request_timeout: Duration::from_secs(90),
        max_response_bytes: MAX_RESPONSE_BYTES,
        pool_idle_timeout: Duration::from_secs(10),
        api_secret: None,
    }
}

/// The app's retries and request spread.
#[must_use]
pub const fn call_policy() -> CallPolicy {
    CallPolicy {
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(4),
        },
        outputs_per_request: 500,
        max_concurrent_requests: 4,
    }
}
