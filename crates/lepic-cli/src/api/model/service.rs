// SPDX-License-Identifier: Apache-2.0
//! `Status` and `Event`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A running serve: facts only, which a monitor compares with its own thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Status {
    /// The LEPIC version serve runs.
    pub(crate) version: String,
    /// Seconds since serve started.
    pub(crate) uptime_s: u64,
    pub(crate) listeners: Listeners,
    /// The owner TLS listener; absent without `--owner-tls`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) owner_tls: Option<OwnerTls>,
    /// The wallet refresh serve runs on its own.
    pub(crate) refresh: Task,
    /// The contact mailbox collect serve runs on its own.
    pub(crate) collect: Task,
    pub(crate) requests: Requests,
}

/// The listeners serve runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Listeners {
    pub(crate) epicbox: EpicboxListener,
    /// Absent without `--http`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) http: Option<HttpListener>,
}

/// The Epicbox listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EpicboxListener {
    /// `connecting`, `connected`, `disconnected` or `stopped`; absent before its first report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
}

/// The HTTP listener of `serve --http`, with its counts so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HttpListener {
    pub(crate) port: u16,
    /// `local` or `internet`.
    pub(crate) exposure: String,
    pub(crate) received: u32,
    /// Payments answered again with the reply stored the first time.
    pub(crate) repeated: u32,
    pub(crate) refused: u32,
    /// Who `build_coinbase` is answered to: `off`, `local` or `remote`.
    pub(crate) coinbase: String,
}

/// The owner TLS listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerTls {
    /// `ip:port`.
    pub(crate) address: String,
    /// The SHA-256 of the certificate's public key info, in hex, which clients pin.
    pub(crate) fingerprint: String,
}

/// A task serve repeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Task {
    /// Failures since the last success.
    pub(crate) failures: u32,
    /// Absent before the first success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_success_at: Option<String>,
    /// The error of the latest failure, kept after a success; absent before any failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
}

/// The API's requests since serve started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Requests {
    /// Answered, problems included.
    pub(crate) served: u64,
    /// Being answered now; an event stream counts while it is open.
    pub(crate) in_flight: u64,
    /// Connections closed unanswered: over the connection cap, from another user, or with a
    /// failed TLS handshake.
    pub(crate) refused: u64,
}

/// One entry of the event log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Event {
    /// Rises; never reused.
    pub(crate) id: u64,
    /// `resource.what_happened`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) created_at: String,
    /// `{object, from_state?, to_state?, reason?, changed?}`; `{count}` for `events.skipped`.
    pub(crate) data: Value,
}
