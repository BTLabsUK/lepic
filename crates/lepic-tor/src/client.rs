// SPDX-License-Identifier: Apache-2.0
//! The limits of a send over Tor.

use std::time::Duration;

/// Limits of a send over Tor.
#[derive(Debug, Clone, Copy)]
pub struct OnionClientSettings {
    /// Reaching the onion through tor; a `check_version` that times out is tried once more on a
    /// new circuit.
    pub connect_timeout: Duration,
    /// From sending a request to the last byte of its answer.
    pub request_timeout: Duration,
    /// The largest answer taken, in bytes.
    pub max_response_bytes: usize,
}
