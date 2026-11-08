// SPDX-License-Identifier: Apache-2.0
//! The caller's [`NetTuning`], checked once and turned into the settings of each crate.

use std::time::Duration;

use lepic_epicbox::tunnel::TunnelTimings;
use lepic_epicbox::{Backoff, ClientTimings};
use lepic_methods::http::ListenLimits;
use lepic_node::{CallPolicy, HttpSettings, MAX_RESPONSE_BYTES, RetryPolicy};

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::NetTuning;

/// A [`NetTuning`] with no zero and no minimum above its maximum.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tuning {
    node_connect: Duration,
    node_request: Duration,
    node_idle: Duration,
    pub(crate) call_policy: CallPolicy,
    pub(crate) relay: ClientTimings,
    // A build without tor has no tunnel to the relay.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    pub(crate) tunnel: TunnelTimings,
    pub(crate) listen: ListenLimits,
    pub(crate) send: lepic_methods::http::ClientSettings,
    tor: TorTimes,
}

// Checked in every build so one app configuration fits both; only a tor build reads most of it.
#[cfg_attr(not(feature = "tor"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TorTimes {
    bootstrap: Duration,
    cold_bootstrap: Duration,
    stall: Duration,
    cold_stall: Duration,
    publish: Duration,
    connect: Duration,
    request: Duration,
}

fn invalid(key: &str) -> WalletError {
    WalletError::new(
        WalletErrorKind::InvalidArgument,
        format!("tuning {key} is out of range"),
    )
}

fn positive(value: u32, key: &str) -> Result<u32, WalletError> {
    if value == 0 {
        Err(invalid(key))
    } else {
        Ok(value)
    }
}

fn seconds(value: u32, key: &str) -> Result<Duration, WalletError> {
    positive(value, key).map(|value| Duration::from_secs(u64::from(value)))
}

fn millis(value: u32, key: &str) -> Result<Duration, WalletError> {
    positive(value, key).map(|value| Duration::from_millis(u64::from(value)))
}

fn count(value: u32, key: &str) -> Result<usize, WalletError> {
    usize::try_from(positive(value, key)?).map_err(|_| invalid(key))
}

fn ordered(min: Duration, max: Duration, key: &str) -> Result<(), WalletError> {
    if min > max { Err(invalid(key)) } else { Ok(()) }
}

impl Tuning {
    /// `InvalidArgument` naming the first key that is zero, or whose minimum is above its
    /// maximum.
    pub(crate) fn check(tuning: &NetTuning) -> Result<Self, WalletError> {
        let NetTuning {
            node,
            epicbox,
            http,
            tor,
        } = tuning;
        let retry = RetryPolicy {
            max_attempts: positive(node.retry_attempts, "node.retry_attempts")?,
            initial_backoff: millis(node.retry_backoff_min_ms, "node.retry_backoff_min_ms")?,
            max_backoff: millis(node.retry_backoff_max_ms, "node.retry_backoff_max_ms")?,
        };
        ordered(
            retry.initial_backoff,
            retry.max_backoff,
            "node.retry_backoff_min_ms",
        )?;
        let backoff = Backoff {
            initial: seconds(epicbox.reconnect_min_s, "epicbox.reconnect_min_s")?,
            max: seconds(epicbox.reconnect_max_s, "epicbox.reconnect_max_s")?,
        };
        ordered(backoff.initial, backoff.max, "epicbox.reconnect_min_s")?;
        Ok(Self {
            node_connect: seconds(node.connect_timeout_s, "node.connect_timeout_s")?,
            node_request: seconds(node.request_timeout_s, "node.request_timeout_s")?,
            node_idle: seconds(node.idle_timeout_s, "node.idle_timeout_s")?,
            call_policy: CallPolicy {
                retry,
                outputs_per_request: count(node.outputs_per_request, "node.outputs_per_request")?,
                max_concurrent_requests: count(
                    node.concurrent_requests,
                    "node.concurrent_requests",
                )?,
            },
            relay: ClientTimings {
                connect_timeout: seconds(epicbox.connect_timeout_s, "epicbox.connect_timeout_s")?,
                response_timeout: seconds(
                    epicbox.response_timeout_s,
                    "epicbox.response_timeout_s",
                )?,
                ping_interval: seconds(epicbox.ping_interval_s, "epicbox.ping_interval_s")?,
                backoff,
                drain_timeout: seconds(epicbox.drain_timeout_s, "epicbox.drain_timeout_s")?,
            },
            tunnel: TunnelTimings {
                connect_timeout: seconds(
                    epicbox.tor_connect_timeout_s,
                    "epicbox.tor_connect_timeout_s",
                )?,
                discovery_timeout: seconds(
                    epicbox.onion_discovery_timeout_s,
                    "epicbox.onion_discovery_timeout_s",
                )?,
                discovery_retry: seconds(
                    epicbox.onion_discovery_retry_s,
                    "epicbox.onion_discovery_retry_s",
                )?,
            },
            listen: ListenLimits {
                max_connections: count(http.max_connections, "http.max_connections")?,
                max_connections_per_address: count(
                    http.max_connections_per_address,
                    "http.max_connections_per_address",
                )?,
                header_timeout: seconds(http.header_timeout_s, "http.header_timeout_s")?,
                body_timeout: seconds(http.body_timeout_s, "http.body_timeout_s")?,
                request_timeout: seconds(http.request_timeout_s, "http.request_timeout_s")?,
                answer_timeout: seconds(http.answer_timeout_s, "http.answer_timeout_s")?,
                requests_per_minute: positive(
                    http.requests_per_minute,
                    "http.requests_per_minute",
                )?,
                receives_per_minute: positive(
                    http.receives_per_minute,
                    "http.receives_per_minute",
                )?,
            },
            send: lepic_methods::http::ClientSettings {
                connect_timeout: seconds(
                    http.send_connect_timeout_s,
                    "http.send_connect_timeout_s",
                )?,
                request_timeout: seconds(
                    http.send_request_timeout_s,
                    "http.send_request_timeout_s",
                )?,
                max_response_bytes: lepic_methods::http::MAX_BODY_LEN,
            },
            tor: TorTimes {
                bootstrap: seconds(tor.bootstrap_timeout_s, "tor.bootstrap_timeout_s")?,
                cold_bootstrap: seconds(
                    tor.cold_bootstrap_timeout_s,
                    "tor.cold_bootstrap_timeout_s",
                )?,
                stall: seconds(tor.stall_timeout_s, "tor.stall_timeout_s")?,
                cold_stall: seconds(tor.cold_stall_timeout_s, "tor.cold_stall_timeout_s")?,
                publish: seconds(tor.publish_timeout_s, "tor.publish_timeout_s")?,
                connect: seconds(tor.connect_timeout_s, "tor.connect_timeout_s")?,
                request: seconds(tor.request_timeout_s, "tor.request_timeout_s")?,
            },
        })
    }

    /// The node's HTTP settings, with `api_secret`.
    pub(crate) fn node_http(&self, api_secret: Option<&str>) -> HttpSettings {
        HttpSettings {
            connect_timeout: self.node_connect,
            request_timeout: self.node_request,
            max_response_bytes: MAX_RESPONSE_BYTES,
            pool_idle_timeout: self.node_idle,
            api_secret: api_secret.map(Into::into),
        }
    }

    /// Reaching a host or an onion through tor.
    pub(crate) const fn tor_connect_timeout(&self) -> Duration {
        self.tor.connect
    }

    #[cfg(feature = "tor")]
    pub(crate) const fn tor_timings(&self) -> lepic_methods::tor::TorTimings {
        lepic_methods::tor::TorTimings::new(lepic_methods::tor::TorNetworkTimings {
            stall: self.tor.stall,
            bootstrap: self.tor.bootstrap,
            cold_stall: self.tor.cold_stall,
            cold_bootstrap: self.tor.cold_bootstrap,
            publish: self.tor.publish,
        })
    }

    #[cfg(feature = "tor")]
    pub(crate) const fn onion_client(&self) -> lepic_methods::tor::OnionClientSettings {
        lepic_methods::tor::OnionClientSettings {
            connect_timeout: self.tor.connect,
            request_timeout: self.tor.request,
            max_response_bytes: lepic_methods::http::MAX_BODY_LEN,
        }
    }
}

/// The app's shipped tuning, for tests.
#[cfg(test)]
pub(crate) const fn shipped() -> NetTuning {
    use crate::api::types::{EpicboxTuning, HttpTuning, NodeTuning, TorTuning};
    NetTuning {
        node: NodeTuning {
            connect_timeout_s: 15,
            request_timeout_s: 90,
            idle_timeout_s: 10,
            retry_attempts: 3,
            retry_backoff_min_ms: 500,
            retry_backoff_max_ms: 4000,
            outputs_per_request: 500,
            concurrent_requests: 4,
        },
        epicbox: EpicboxTuning {
            connect_timeout_s: 15,
            response_timeout_s: 15,
            ping_interval_s: 25,
            reconnect_min_s: 1,
            reconnect_max_s: 60,
            drain_timeout_s: 120,
            tor_connect_timeout_s: 90,
            onion_discovery_timeout_s: 45,
            onion_discovery_retry_s: 600,
        },
        http: HttpTuning {
            header_timeout_s: 10,
            body_timeout_s: 15,
            request_timeout_s: 60,
            answer_timeout_s: 10,
            max_connections: 16,
            max_connections_per_address: 4,
            requests_per_minute: 120,
            receives_per_minute: 30,
            send_connect_timeout_s: 10,
            send_request_timeout_s: 60,
        },
        tor: TorTuning {
            bootstrap_timeout_s: 120,
            cold_bootstrap_timeout_s: 240,
            stall_timeout_s: 60,
            cold_stall_timeout_s: 120,
            publish_timeout_s: 180,
            connect_timeout_s: 75,
            request_timeout_s: 120,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_tuning_is_taken_as_it_is() {
        let tuning = Tuning::check(&shipped()).unwrap();
        assert_eq!(tuning.relay.ping_interval, Duration::from_secs(25));
        assert_eq!(tuning.call_policy.retry.max_backoff, Duration::from_secs(4));
        assert_eq!(tuning.listen.receives_per_minute, 30);
        assert_eq!(tuning.tor_connect_timeout(), Duration::from_secs(75));
    }

    #[test]
    fn a_zero_or_a_minimum_above_its_maximum_is_refused() {
        let kind = |tuning: NetTuning| Tuning::check(&tuning).unwrap_err().kind;
        let mut zero = shipped();
        zero.http.max_connections = 0;
        assert_eq!(kind(zero), WalletErrorKind::InvalidArgument);
        let mut zero = shipped();
        zero.tor.publish_timeout_s = 0;
        assert_eq!(kind(zero), WalletErrorKind::InvalidArgument);
        let mut reversed = shipped();
        reversed.epicbox.reconnect_min_s = 61;
        assert_eq!(kind(reversed), WalletErrorKind::InvalidArgument);
        let mut reversed = shipped();
        reversed.node.retry_backoff_min_ms = 4001;
        assert_eq!(kind(reversed), WalletErrorKind::InvalidArgument);
    }
}
