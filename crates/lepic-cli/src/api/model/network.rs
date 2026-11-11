// SPDX-License-Identifier: Apache-2.0
//! `Relay`, `Peer` and `Profile`.

use serde::{Deserialize, Serialize};

/// An old relay that is still read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Draining {
    pub(crate) host: String,
    pub(crate) until_at: String,
}

/// The home relay and the connection to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Relay {
    pub(crate) host: String,
    pub(crate) connection: String,
    pub(crate) address: String,
    pub(crate) waiting_deliveries: u64,
    pub(crate) draining: Vec<Draining>,
}

impl Relay {
    /// The relay `host`, with the old relays `draining` as `(host, until)`.
    pub(crate) fn new(
        host: String,
        connection: &str,
        address: String,
        waiting_deliveries: u64,
        draining: Vec<(String, String)>,
    ) -> Self {
        Self {
            host,
            connection: connection.to_owned(),
            address,
            waiting_deliveries,
            draining: draining
                .into_iter()
                .map(|(host, until_at)| Draining { host, until_at })
                .collect(),
        }
    }
}

/// A LEPIC wallet whose native endpoint this wallet pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Peer {
    pub(crate) origin: String,
    pub(crate) key: String,
    pub(crate) first_seen_at: String,
    pub(crate) last_seen_at: String,
}

/// What this wallet tells its contacts about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    pub(crate) flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) domain_proof: Option<String>,
}
