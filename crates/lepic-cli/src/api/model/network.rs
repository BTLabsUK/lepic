// SPDX-License-Identifier: Apache-2.0
//! `Relay`, `Mailbox` and `Profile`.

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

/// One mailbox of the list native mail goes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mailbox {
    pub(crate) host: String,
    /// `shipped` or `added`.
    pub(crate) origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) push: Option<bool>,
    /// The mailbox is known to lack mux/1.
    #[serde(default)]
    pub(crate) no_mux: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_success_at: Option<String>,
    pub(crate) failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
}

/// The mailbox list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mailboxes {
    pub(crate) mailboxes: Vec<Mailbox>,
    /// Hosts the settings name that are not used, because the list holds at most 16.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) left_out: Vec<String>,
}

/// One step of a mailbox test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProbeStep {
    /// `passed`, `failed` or `not_reached`.
    pub(crate) result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// What a test of one mailbox found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MailboxProbe {
    pub(crate) host: String,
    pub(crate) tls: ProbeStep,
    pub(crate) greeting: ProbeStep,
    pub(crate) push: ProbeStep,
    pub(crate) passed: bool,
}

/// A mailbox added, with the test it passed (or failed, when added anyway) and the list after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MailboxAdded {
    pub(crate) added: bool,
    pub(crate) probe: MailboxProbe,
    pub(crate) mailboxes: Vec<Mailbox>,
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
