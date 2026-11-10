// SPDX-License-Identifier: Apache-2.0
//! The limits of a send over Tor.

use std::time::Duration;

/// Limits of a send over Tor.
#[derive(Debug, Clone, Copy)]
pub struct OnionClientSettings {
    /// Reaching the onion through tor, per try. A connect that fails in a way waiting can mend is
    /// tried again on a new circuit, after a short wait, until twice this time has passed.
    pub connect_timeout: Duration,
    /// From sending a request to the last byte of its answer.
    pub request_timeout: Duration,
    /// The largest answer taken, in bytes.
    pub max_response_bytes: usize,
}
