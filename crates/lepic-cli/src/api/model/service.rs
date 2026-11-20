// SPDX-License-Identifier: Apache-2.0
//! `Status`, `Event` and `Webhook`.

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
    pub(crate) node: NodeStatus,
    pub(crate) payments: PaymentsStatus,
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
    /// The push sessions, one for each relay and group; empty when serve holds none.
    pub(crate) relays: Vec<EpicboxRelay>,
}

/// A push session serve holds on a relay. The times are this serve's: absent until it saw
/// them, and gone after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EpicboxRelay {
    /// `domain:port`.
    pub(crate) host: String,
    /// `wallet`; `payments` or `contacts` when `relay_sockets` is `split`.
    pub(crate) group: String,
    /// `connecting`, `attached`, `waiting`, `not_offered` or `stopped`.
    pub(crate) state: String,
    /// Whether the relay offers mux/1; absent before it answered the first greeting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) push: Option<bool>,
    /// Why the session last lost its socket, as plain text; absent once it attached again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
    /// Since when the session is attached; absent while it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) connected_since: Option<String>,
    /// When the relay last pushed mail to the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_mail_at: Option<String>,
}

/// The node as serve's refresh saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NodeStatus {
    /// The node's tip at the last refresh that reached it; absent before the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tip_height: Option<u64>,
    /// When a refresh first saw the tip at `tip_height`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tip_changed_at: Option<String>,
}

/// The payments that are not over yet, as `GET /payments` lists them over every account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PaymentsStatus {
    pub(crate) open: OpenPayments,
    /// The `awaiting_answer` payment created first; absent when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oldest_awaiting_answer: Option<OldestPayment>,
    /// The `finalized` payment created first; absent when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oldest_finalized: Option<OldestPayment>,
}

/// How many payments are in each state that is not over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpenPayments {
    pub(crate) needs_approval: u64,
    pub(crate) awaiting_answer: u64,
    pub(crate) finalized: u64,
    pub(crate) posted: u64,
}

/// One payment by its id, with when it was created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OldestPayment {
    pub(crate) id: String,
    /// The payment's `created_at`.
    pub(crate) since: String,
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
    /// The boost that runs now, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) boost: Option<Boost>,
}

/// A poller's boost (ADR 0058): it runs every `interval_seconds` until `until`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Boost {
    /// The boost a `POST /sync/boost` started, to end with `DELETE /sync/boost/{id}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<u64>,
    pub(crate) poller: String,
    pub(crate) until: String,
    pub(crate) interval_seconds: u64,
}

impl Boost {
    pub(crate) fn of(window: lepic_wallet::boost::Window) -> Self {
        Self {
            id: None,
            poller: match window.poller {
                lepic_wallet::boost::Poller::Relays => "relays",
                lepic_wallet::boost::Poller::Node => "node",
            }
            .to_owned(),
            until: window.until.to_string(),
            interval_seconds: window.interval.as_secs(),
        }
    }
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

/// The webhook of serve: where its events go and how the delivery stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Webhook {
    pub(crate) url: String,
    /// The event types it sends; none means all.
    pub(crate) types: Vec<String>,
    /// `active`, `retrying`, `config_error` or `disabled`.
    pub(crate) state: String,
    /// The id of the last event delivered, or passed over by the types filter.
    pub(crate) cursor: u64,
    /// Failed attempts at the next event.
    pub(crate) attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_attempt_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
}
