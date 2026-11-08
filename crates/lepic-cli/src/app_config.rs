// SPDX-License-Identifier: Apache-2.0
//! The CLI's built-in configuration, `lepic-config.toml`, compiled into the binary: the
//! timeouts, ports and limits of every server connection, the server of an address written
//! without one and the servers' onions. The library crates hold none of these; the user's
//! choices are in `settings.toml` ([`crate::settings_file`]).

use std::num::{NonZeroU16, NonZeroU32};
use std::path::Path;
use std::time::Duration;

use lepic_epicbox::tunnel::{OnionRoute, TunnelTimings};
use lepic_epicbox::{Backoff, ClientTimings, Domain};
use lepic_foreign::ListenLimits;
use lepic_node::{CallPolicy, HttpSettings, MAX_RESPONSE_BYTES, RetryPolicy};
use lepic_tor::{OnionClientSettings, TorNetworkTimings, TorTimings};
use lepic_wallet::NodeEndpoint;
use secrecy::SecretString;
use serde::Deserialize;

use crate::settings::SettingsError;

/// The configuration the CLI is built with.
pub const LEPIC_CONFIG: &str = include_str!("../lepic-config.toml");

/// The name errors give the built-in configuration.
const CONFIG_NAME: &str = "lepic-config.toml";

/// As many onion routes as the FFI takes.
pub const MAX_ONION_ROUTES: usize = 256;

/// The built-in configuration, checked.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// The server of an Epicbox address written without one.
    pub address_default: Domain,
    /// How many of the user's first Epicbox servers pairing words go to.
    pub pairing_servers: usize,
    /// The node of a floonet wallet that names none.
    pub floonet_node: NodeEndpoint,
    /// Hosts under these refuse Tor exits.
    pub onion_only_domains: Vec<Domain>,
    /// The hosts known to be TLS onion services.
    pub onion_routes: Vec<OnionRoute>,
    pub tuning: Tuning,
}

/// The timeouts, retries and limits of the CLI's server connections.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    node_connect: Duration,
    node_request: Duration,
    node_idle: Duration,
    pub call_policy: CallPolicy,
    pub relay: ClientTimings,
    pub tunnel: TunnelTimings,
    /// The port `listen` takes unless `--port` names another.
    pub listen_port: u16,
    pub listen: ListenLimits,
    pub api: ApiLimits,
    pub send: lepic_foreign::ClientSettings,
    tor_network: TorNetworkTimings,
    pub tor_connect: Duration,
    tor_request: Duration,
}

/// The bounds of the wallet API, on serve's socket and its owner TLS listener alike.
#[derive(Debug, Clone, Copy)]
pub struct ApiLimits {
    /// Connections served at once; more are closed unanswered.
    pub max_connections: usize,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub max_body: usize,
}

impl Tuning {
    /// The node's HTTP settings, with `api_secret`.
    pub fn node_http(&self, api_secret: Option<SecretString>) -> HttpSettings {
        HttpSettings {
            connect_timeout: self.node_connect,
            request_timeout: self.node_request,
            max_response_bytes: MAX_RESPONSE_BYTES,
            pool_idle_timeout: self.node_idle,
            api_secret,
        }
    }

    pub const fn tor_timings(&self) -> TorTimings {
        TorTimings::new(self.tor_network)
    }

    pub const fn onion_client(&self) -> OnionClientSettings {
        OnionClientSettings {
            connect_timeout: self.tor_connect,
            request_timeout: self.tor_request,
            max_response_bytes: lepic_foreign::rpc::MAX_BODY_LEN,
        }
    }
}

// Every key is required: a configuration that lacks one is a build defect, not a default.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(rename = "version")]
    _version: u32,
    node: NodeTable,
    floonet: FloonetTable,
    epicbox: EpicboxTable,
    http: HttpTable,
    api: ApiTable,
    tor: TorTable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeTable {
    connect_timeout_s: NonZeroU32,
    request_timeout_s: NonZeroU32,
    idle_timeout_s: NonZeroU32,
    retry_attempts: NonZeroU32,
    retry_backoff_min_ms: NonZeroU32,
    retry_backoff_max_ms: NonZeroU32,
    outputs_per_request: NonZeroU32,
    concurrent_requests: NonZeroU32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FloonetTable {
    node: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpicboxTable {
    address_default: String,
    pairing_servers: NonZeroU32,
    connect_timeout_s: NonZeroU32,
    response_timeout_s: NonZeroU32,
    ping_interval_s: NonZeroU32,
    reconnect_min_s: NonZeroU32,
    reconnect_max_s: NonZeroU32,
    drain_timeout_s: NonZeroU32,
    tor_connect_timeout_s: NonZeroU32,
    onion_discovery_timeout_s: NonZeroU32,
    onion_discovery_retry_s: NonZeroU32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTable {
    listen_port: NonZeroU16,
    header_timeout_s: NonZeroU32,
    body_timeout_s: NonZeroU32,
    request_timeout_s: NonZeroU32,
    answer_timeout_s: NonZeroU32,
    max_connections: NonZeroU32,
    max_connections_per_address: NonZeroU32,
    requests_per_minute: NonZeroU32,
    receives_per_minute: NonZeroU32,
    send_connect_timeout_s: NonZeroU32,
    send_request_timeout_s: NonZeroU32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiTable {
    max_connections: NonZeroU32,
    header_timeout_s: NonZeroU32,
    body_timeout_s: NonZeroU32,
    max_body_kib: NonZeroU32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TorTable {
    bootstrap_timeout_s: NonZeroU32,
    cold_bootstrap_timeout_s: NonZeroU32,
    stall_timeout_s: NonZeroU32,
    cold_stall_timeout_s: NonZeroU32,
    publish_timeout_s: NonZeroU32,
    connect_timeout_s: NonZeroU32,
    request_timeout_s: NonZeroU32,
    onion_only_domains: Vec<String>,
    onions: Vec<OnionTable>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OnionTable {
    host: String,
    port: u16,
    onion: String,
    onion_port: u16,
    tls: bool,
}

fn seconds(value: NonZeroU32) -> Duration {
    Duration::from_secs(u64::from(value.get()))
}

fn millis(value: NonZeroU32) -> Duration {
    Duration::from_millis(u64::from(value.get()))
}

fn count(value: NonZeroU32) -> usize {
    usize::try_from(value.get()).unwrap_or(usize::MAX)
}

impl AppConfig {
    /// The configuration the CLI is built with.
    pub fn built_in() -> Result<Self, SettingsError> {
        Self::parse(LEPIC_CONFIG)
    }

    /// The configuration `text` holds.
    pub fn parse(text: &str) -> Result<Self, SettingsError> {
        let path = Path::new(CONFIG_NAME);
        let file: File = toml::from_str(text).map_err(|source| SettingsError::SettingsSyntax {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        let invalid = |key| SettingsError::SettingsValue {
            path: path.to_owned(),
            key,
        };
        let File {
            node,
            floonet,
            epicbox,
            http,
            api,
            tor,
            ..
        } = file;
        let tuning = tuning(&node, &epicbox, &http, &api, &tor).map_err(invalid)?;
        if tor.onions.len() > MAX_ONION_ROUTES {
            return Err(invalid("tor.onions"));
        }
        let onion_routes = tor
            .onions
            .iter()
            .filter(|route| route.tls)
            .map(|route| onion_route(route).ok_or_else(|| invalid("tor.onions")))
            .collect::<Result<_, _>>()?;
        let onion_only_domains = tor
            .onion_only_domains
            .iter()
            .map(|domain| Domain::parse(domain).map_err(|_| invalid("tor.onion_only_domains")))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            address_default: Domain::parse(&epicbox.address_default)
                .map_err(|_| invalid("epicbox.address_default"))?,
            pairing_servers: count(epicbox.pairing_servers),
            floonet_node: NodeEndpoint::parse(&floonet.node)
                .map_err(|_| invalid("floonet.node"))?,
            onion_only_domains,
            onion_routes,
            tuning,
        })
    }
}

/// The tuning of the five tables, or the key whose minimum is above its maximum.
fn tuning(
    node: &NodeTable,
    epicbox: &EpicboxTable,
    http: &HttpTable,
    api: &ApiTable,
    tor: &TorTable,
) -> Result<Tuning, &'static str> {
    let retry = RetryPolicy {
        max_attempts: node.retry_attempts.get(),
        initial_backoff: millis(node.retry_backoff_min_ms),
        max_backoff: millis(node.retry_backoff_max_ms),
    };
    if retry.initial_backoff > retry.max_backoff {
        return Err("node.retry_backoff_min_ms");
    }
    let backoff = Backoff {
        initial: seconds(epicbox.reconnect_min_s),
        max: seconds(epicbox.reconnect_max_s),
    };
    if backoff.initial > backoff.max {
        return Err("epicbox.reconnect_min_s");
    }
    Ok(Tuning {
        node_connect: seconds(node.connect_timeout_s),
        node_request: seconds(node.request_timeout_s),
        node_idle: seconds(node.idle_timeout_s),
        call_policy: CallPolicy {
            retry,
            outputs_per_request: count(node.outputs_per_request),
            max_concurrent_requests: count(node.concurrent_requests),
        },
        relay: ClientTimings {
            connect_timeout: seconds(epicbox.connect_timeout_s),
            response_timeout: seconds(epicbox.response_timeout_s),
            ping_interval: seconds(epicbox.ping_interval_s),
            backoff,
            drain_timeout: seconds(epicbox.drain_timeout_s),
        },
        tunnel: TunnelTimings {
            connect_timeout: seconds(epicbox.tor_connect_timeout_s),
            discovery_timeout: seconds(epicbox.onion_discovery_timeout_s),
            discovery_retry: seconds(epicbox.onion_discovery_retry_s),
        },
        listen_port: http.listen_port.get(),
        listen: ListenLimits {
            max_connections: count(http.max_connections),
            max_connections_per_address: count(http.max_connections_per_address),
            header_timeout: seconds(http.header_timeout_s),
            body_timeout: seconds(http.body_timeout_s),
            request_timeout: seconds(http.request_timeout_s),
            answer_timeout: seconds(http.answer_timeout_s),
            requests_per_minute: http.requests_per_minute.get(),
            receives_per_minute: http.receives_per_minute.get(),
        },
        api: ApiLimits {
            max_connections: count(api.max_connections),
            header_timeout: seconds(api.header_timeout_s),
            body_timeout: seconds(api.body_timeout_s),
            max_body: count(api.max_body_kib).saturating_mul(1024),
        },
        send: lepic_foreign::ClientSettings {
            connect_timeout: seconds(http.send_connect_timeout_s),
            request_timeout: seconds(http.send_request_timeout_s),
            max_response_bytes: lepic_foreign::rpc::MAX_BODY_LEN,
        },
        tor_network: TorNetworkTimings {
            stall: seconds(tor.stall_timeout_s),
            bootstrap: seconds(tor.bootstrap_timeout_s),
            cold_stall: seconds(tor.cold_stall_timeout_s),
            cold_bootstrap: seconds(tor.cold_bootstrap_timeout_s),
            publish: seconds(tor.publish_timeout_s),
        },
        tor_connect: seconds(tor.connect_timeout_s),
        tor_request: seconds(tor.request_timeout_s),
    })
}

/// A route to a host name and an onion v3 host on ports that are not 0.
fn onion_route(route: &OnionTable) -> Option<OnionRoute> {
    let domain = Domain::parse(&route.host).ok()?;
    let onion = lepic_tor::parse_onion(&route.onion).ok()?;
    (route.port != 0 && route.onion_port != 0).then(|| OnionRoute {
        domain,
        port: route.port,
        onion: onion.host(),
        onion_port: route.onion_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(key: &str, value: &str) -> String {
        LEPIC_CONFIG
            .lines()
            .map(|line| {
                if line.split('=').next().map(str::trim) == Some(key) {
                    format!("{key} = {value}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_built_in_configuration_parses_with_its_values() {
        let config = AppConfig::built_in().unwrap();
        assert_eq!(config.address_default.as_str(), "epicbox.epiccash.com");
        assert_eq!(config.pairing_servers, 3);
        assert_eq!(config.onion_routes.len(), 2);
        assert_eq!(config.onion_only_domains.len(), 1);
        let tuning = config.tuning;
        assert_eq!(tuning.listen_port, 3415);
        assert_eq!(tuning.relay.ping_interval, Duration::from_secs(25));
        assert_eq!(tuning.call_policy.retry.max_attempts, 3);
        assert_eq!(tuning.listen.receives_per_minute, 30);
        assert_eq!(tuning.api.max_connections, 32);
        assert_eq!(tuning.api.max_body, 8192 * 1024);
        assert_eq!(tuning.tor_connect, Duration::from_secs(75));
        assert_eq!(tuning.tor_timings().publish, Duration::from_secs(180));
    }

    #[test]
    fn a_zero_a_missing_key_or_an_unknown_one_is_refused() {
        let syntax = |text: &str| {
            matches!(
                AppConfig::parse(text),
                Err(SettingsError::SettingsSyntax { .. })
            )
        };
        assert!(syntax(&with("ping_interval_s", "0")));
        assert!(syntax(&with("listen_port", "0")));
        assert!(syntax(&LEPIC_CONFIG.replace("drain_timeout_s = 120\n", "")));
        assert!(syntax(
            &LEPIC_CONFIG.replace("[http]\n", "[http]\nretry_forever = true\n")
        ));
    }

    #[test]
    fn a_minimum_above_its_maximum_is_refused() {
        let value = |text: &str| match AppConfig::parse(text) {
            Err(SettingsError::SettingsValue { key, .. }) => Some(key),
            _ => None,
        };
        assert_eq!(
            value(&with("reconnect_min_s", "61")),
            Some("epicbox.reconnect_min_s")
        );
        assert_eq!(
            value(&with("retry_backoff_min_ms", "4001")),
            Some("node.retry_backoff_min_ms")
        );
    }
}
