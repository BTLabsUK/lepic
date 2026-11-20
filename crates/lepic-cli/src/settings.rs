// SPDX-License-Identifier: Apache-2.0
//! Settings, resolved once per command: a flag, then its `LEPIC_*` variable, then the config
//! file, then the default.
//!
//! The config file is a flat list of `key = value` lines, a subset of TOML: values are bare
//! words or double-quoted strings, `#` starts a comment. Unknown and repeated keys are refused so
//! that a typo never silently falls back to a default.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use lepic_epicbox::{Domain, RelayEndpoint, Security};
use lepic_primitives::params::Network;
use lepic_wallet::NodeEndpoint;
use lepic_wallet::epicbox_invoice::InvoiceExpiry;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::app_config::{AppConfig, Tuning};
use crate::cli::{GlobalArgs, LogFormatArg, NetworkArg, OutputArg};
use crate::secret::{NEW_PASSWORD_ENV, PASSWORD_ENV};
use crate::settings_file::{self, Servers};

/// Config files are a few lines; anything larger is not one.
pub const MAX_CONFIG_LEN: u64 = 64 * 1024;

const CONFIG_FILE: &str = "config.toml";
pub(crate) const HOME_DIR: &str = ".lepic";

/// Keys and variables an older release read. A config file or environment that still sets one
/// loads; the key has no effect, and the CLI says so once per run.
pub const RETIRED: &[(&str, &str)] = &[("native_direct", "LEPIC_NATIVE_DIRECT")];

/// Every config key, its variable, and what it sets.
pub const SETTINGS: &[(&str, &str, &str)] = &[
    ("data_dir", "LEPIC_DATA_DIR", "wallet directory"),
    ("network", "LEPIC_NETWORK", "mainnet or floonet"),
    ("log_level", "LEPIC_LOG_LEVEL", "log filter"),
    ("log_format", "LEPIC_LOG_FORMAT", "pretty, compact or json"),
    ("output", "LEPIC_OUTPUT", "human or json"),
    ("node_url", "LEPIC_NODE_URL", "node api root"),
    (
        "node_api_secret_file",
        "LEPIC_NODE_API_SECRET_FILE",
        "file holding the node's foreign api secret",
    ),
    (
        "password_file",
        "LEPIC_PASSWORD_FILE",
        "file holding the wallet password, readable by its owner only",
    ),
    (
        "epicbox_relay",
        "LEPIC_EPICBOX_RELAY",
        "relay as wss://host[:port], or ws://host[:port] for a loopback host",
    ),
    (
        "local_mailbox",
        "LEPIC_LOCAL_MAILBOX",
        "true to make a loopback epicbox_relay the whole mailbox list, for a stack on this device",
    ),
    (
        "epicbox_tor_socks",
        "LEPIC_EPICBOX_TOR_SOCKS",
        "reach the relay through the tor whose socks5 proxy is at this loopback address",
    ),
    (
        "epicbox_tor_binary",
        "LEPIC_EPICBOX_TOR_BINARY",
        "reach the relay through a tor that the cli runs from this binary",
    ),
    (
        "epicbox_tor_lib_dir",
        "LEPIC_EPICBOX_TOR_LIB_DIR",
        "directory of the libraries that tor binary needs",
    ),
    (
        "node_over_tor",
        "LEPIC_NODE_OVER_TOR",
        "true to reach the node through the tor named by the epicbox_tor settings",
    ),
    (
        "connection_mode",
        "LEPIC_CONNECTION_MODE",
        "all, tor-only or offline: tor-only connects only through the tor the epicbox_tor \
         settings name and is offline without one; offline connects nowhere",
    ),
    (
        "http_direct",
        "LEPIC_HTTP_DIRECT",
        "true to reach http payees, http entries of links and the webhook directly while a tor \
         is named; refused with connection_mode tor-only",
    ),
    (
        "relay_sockets",
        "LEPIC_RELAY_SOCKETS",
        "shared or split: whether lepic serve reads payments and contacts on one mailbox socket \
         or on separate ones; split when a tor is named, shared otherwise",
    ),
    (
        "refuse_unsolicited_payments",
        "LEPIC_REFUSE_UNSOLICITED_PAYMENTS",
        "true to refuse payments nobody asked for and tell a lepic sender they were declined",
    ),
    (
        "refuse_unsolicited_invoices",
        "LEPIC_REFUSE_UNSOLICITED_INVOICES",
        "true to refuse invoices from contacts instead of keeping them to pay",
    ),
    (
        "max_open_receipts",
        "LEPIC_MAX_OPEN_RECEIPTS",
        "payments nobody asked for that wait for their senders to finalize, over all senders, \
         1 to 100000 (default 100); a further payment is refused while the cap is full",
    ),
    (
        "max_open_receipts_per_sender",
        "LEPIC_MAX_OPEN_RECEIPTS_PER_SENDER",
        "the same count for one sender key, 1 to 100000 (default 10)",
    ),
    (
        "epic1_web_listener",
        "LEPIC_EPIC1_WEB_LISTENER",
        "true to take payments to the wallet's epic1 addresses at the http listener",
    ),
    (
        "epic1_onion_listener",
        "LEPIC_EPIC1_ONION_LISTENER",
        "true to take payments to the wallet's epic1 addresses at the onion listener",
    ),
    (
        "invoice_expiry_hours",
        "LEPIC_INVOICE_EXPIRY_HOURS",
        "hours an unpaid invoice is kept, 1 to 48",
    ),
    (
        "send_ttl_blocks",
        "LEPIC_SEND_TTL_BLOCKS",
        "blocks after which an unanswered send expires when --ttl-blocks or ttl_blocks names none, \
         1 to 525600 (default 10080, 7 days)",
    ),
    (
        "final_confirmations",
        "LEPIC_FINAL_CONFIRMATIONS",
        "confirmations after which a payment is final: serve marks it `final` and logs \
         payment.confirmations_reached, 1 to 1440 (default 6)",
    ),
    (
        "payment_confirmations",
        "LEPIC_PAYMENT_CONFIRMATIONS",
        "the old name of final_confirmations, read when that is not set",
    ),
    (
        "host_features",
        "LEPIC_HOST_FEATURES",
        "host feature bits the wallet claims to paired contacts, by name, comma-separated: \
         device-forwarding, name-service",
    ),
    (
        "profile",
        "LEPIC_PROFILE",
        "profile bits told to paired contacts: names (no-payments, automated), \
         comma-separated, or a number 0 to 65535",
    ),
    (
        "domain",
        "LEPIC_DOMAIN",
        "domain the wallet claims to paired contacts, like example.com; its well-known file \
         proves the claim",
    ),
    (
        "shell_idle_lock_minutes",
        "LEPIC_SHELL_IDLE_LOCK_MINUTES",
        "minutes with no line entered before the interactive shell locks the wallet; 0 never",
    ),
    (
        "webhook_url",
        "LEPIC_WEBHOOK_URL",
        "https:// endpoint serve posts each API event to; http:// only with webhook_allow_private",
    ),
    (
        "webhook_secret_file",
        "LEPIC_WEBHOOK_SECRET_FILE",
        "file only its owner can read, one whsec_ secret per line, that signs each webhook",
    ),
    (
        "webhook_types",
        "LEPIC_WEBHOOK_TYPES",
        "event types the webhook sends, as GET /events takes them (payment.*); all when unset",
    ),
    (
        "webhook_allow_private",
        "LEPIC_WEBHOOK_ALLOW_PRIVATE",
        "true lets the webhook url be http:// and name a loopback, private or link-local host",
    ),
    (
        "settings_file",
        "LEPIC_SETTINGS",
        "settings.toml with the servers: [node] servers, [epicbox] servers, [api] owner_tls",
    ),
];

/// The chain nothing names: mainnet. A build with the `floonet-harness` feature, which only the
/// interop suites make, is on floonet.
const DEFAULT_NETWORK: NetworkArg = if cfg!(feature = "floonet-harness") {
    NetworkArg::Floonet
} else {
    NetworkArg::Mainnet
};

/// Minutes without input before the interactive shell locks the wallet, unless set.
pub const DEFAULT_SHELL_IDLE_LOCK_MINUTES: u64 = 15;

/// The variable a config file path comes from when `--config` is not given.
pub const CONFIG_ENV: &str = "LEPIC_CONFIG";
/// The variable that names the node.
pub(crate) const NODE_URL_ENV: &str = "LEPIC_NODE_URL";

/// The process environment as the CLI sees it: captured once, so tests pass their own.
#[derive(Clone, Default)]
pub struct Env(BTreeMap<String, String>);

impl Env {
    pub fn new(vars: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(vars.into_iter().collect())
    }

    /// The `LEPIC_*` variables, the home directory and what the terminal says of itself, from
    /// the running process. Variables that are not Unicode are left out.
    pub fn from_process() -> Self {
        Self::new(std::env::vars_os().filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            let wanted = key.starts_with("LEPIC_")
                || matches!(
                    key.as_str(),
                    "HOME"
                        | "USERPROFILE"
                        | "NO_COLOR"
                        | "WT_SESSION"
                        | "TERM"
                        | "TERM_PROGRAM"
                        | "COLORTERM"
                        | "COLORFGBG"
                );
            wanted.then_some((key, value.into_string().ok()?))
        }))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// Sets the variable, as if the process had started with it.
    pub(crate) fn set(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_owned(), value.to_owned());
    }

    /// Removes the variable and returns its value, wiped when dropped. For secrets, so the copy
    /// the environment holds does not outlive its one use.
    pub fn take(&mut self, key: &str) -> Option<Zeroizing<String>> {
        self.0
            .remove(key)
            .map(Zeroizing::new)
            .filter(|value| !value.is_empty())
    }

    fn home(&self) -> Option<PathBuf> {
        self.get("HOME")
            .or_else(|| self.get("USERPROFILE"))
            .map(PathBuf::from)
    }
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(key, value)| {
                let shown = if key == PASSWORD_ENV || key == NEW_PASSWORD_ENV {
                    "[redacted]"
                } else {
                    value
                };
                (key, shown)
            }))
            .finish()
    }
}

/// Where a setting's value came from, for error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Flag,
    Env(&'static str),
    Config(PathBuf),
    Default,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flag => f.write_str("the command line"),
            Self::Env(name) => write!(f, "{name}"),
            Self::Config(path) => write!(f, "{}", path.display()),
            Self::Default => f.write_str("the default"),
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsError {
    #[error("config file {} could not be read", path.display())]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config file {} is larger than {MAX_CONFIG_LEN} bytes", path.display())]
    ConfigTooLarge { path: PathBuf },
    #[error("config file {} line {line} is not `key = value`", path.display())]
    ConfigSyntax { path: PathBuf, line: usize },
    #[error("config file {} line {line} sets unknown key {key}", path.display())]
    UnknownKey {
        path: PathBuf,
        line: usize,
        key: String,
    },
    #[error("config file {} line {line} sets {key} again", path.display())]
    DuplicateKey {
        path: PathBuf,
        line: usize,
        key: String,
    },
    #[error("{}", invalid_value(key, origin))]
    InvalidValue { key: &'static str, origin: Origin },
    #[error("no home directory is set; give --data-dir")]
    NoHome,
    #[error("data directory could not be resolved")]
    DataDir(#[source] std::io::Error),
    #[error("settings file {} could not be read", path.display())]
    SettingsRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("settings file {} is larger than {} bytes", path.display(), crate::settings_file::MAX_SETTINGS_LEN)]
    SettingsTooLarge { path: PathBuf },
    #[error("settings file {} is not valid", path.display())]
    SettingsSyntax {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("settings file {} has no valid {key}", path.display())]
    SettingsValue { path: PathBuf, key: &'static str },
}

/// Why a setting is refused, when the key's own description does not say: a combination of
/// settings, or a value that has more rules than its one-line description gives.
fn refusal(key: &str) -> Option<&'static str> {
    Some(match key {
        "node_url" => {
            "it must be an http:// or https:// address with a host, like http://127.0.0.1:3413; \
             an empty value is not one"
        }
        "local_mailbox" => "it needs epicbox_relay to name a loopback host",
        "http_direct" => "it cannot be set with connection_mode tor-only",
        "node_over_tor" => {
            "it needs epicbox_tor_socks or epicbox_tor_binary, which connection_mode tor-only \
             also asks for"
        }
        "epicbox_tor_binary" => "set epicbox_tor_socks or epicbox_tor_binary, not both",
        "epicbox_tor_lib_dir" => "it goes with epicbox_tor_binary and not with epicbox_tor_socks",
        "webhook_url" => {
            "it must be an https:// address with a host and no user name or password; http:// \
             only with webhook_allow_private"
        }
        "webhook_secret_file" => "webhook_url and webhook_secret_file are set together",
        "webhook_types" => "it is set with webhook_url, as event types GET /events takes",
        "webhook_allow_private" => "it is set with webhook_url",
        _ => return None,
    })
}

/// The message of [`SettingsError::InvalidValue`]: the key, where its value came from, and what
/// the key takes. A key nothing sets reads as not set, not as a bad value.
fn invalid_value(key: &str, origin: &Origin) -> String {
    let variable = SETTINGS
        .iter()
        .find(|(name, _, _)| *name == key)
        .map(|(_, variable, what)| (*variable, *what));
    let reason = refusal(key).or_else(|| variable.map(|(_, what)| what));
    match (origin, variable, reason) {
        (Origin::Default, Some((variable, _)), reason) => format!(
            "{key} is not set: give it as {variable} or in the config file{}; an empty \
             variable counts as not set",
            reason.map_or_else(String::new, |reason| format!(" ({reason})")),
        ),
        (_, _, Some(reason)) => {
            format!("{key} from {origin} is invalid: {reason}")
        }
        _ => format!("{key} from {origin} is invalid"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

/// The tor the relay connection goes through (ADR 0021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayTor {
    /// The relay is reached directly.
    Off,
    /// A tor that runs already, at this loopback SOCKS5 address.
    Socks(std::net::SocketAddr),
    /// A tor the CLI runs from this binary when the relay is first reached.
    Binary {
        binary: PathBuf,
        lib_dir: Option<PathBuf>,
    },
}

/// Which connections a command may make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionMode {
    /// Every connection the other settings allow.
    #[default]
    All,
    /// Only connections through the tor the settings name; with none named, as [`Self::Offline`].
    /// Never directly, except to this computer.
    TorOnly,
    /// No connection at all. Local work, such as slate files, signing and listing, still runs.
    Offline,
}

/// Why a command makes no connections, as the errors and hints of offline mode say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineReason {
    /// `connection_mode` is `offline`.
    Offline,
    /// `connection_mode` is `tor-only` and no tor is named.
    TorOnlyWithoutTor,
}

impl fmt::Display for OfflineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Offline => "connection_mode is offline",
            Self::TorOnlyWithoutTor => "connection_mode is tor-only and no tor is named",
        })
    }
}

/// How `lepic serve` spreads its mail over relay sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySockets {
    /// Payments and contacts share a socket per relay: the relay can link the payments address
    /// with every contact.
    Shared,
    /// Payments and contacts have sockets of their own, which hides the link only when they
    /// reach the relay through tor.
    Split,
}

/// Everything a command runs with.
#[derive(Debug, Clone)]
pub struct Settings {
    pub network: Network,
    /// Absolute.
    pub data_dir: PathBuf,
    pub log_filter: String,
    pub log_format: lepic_telemetry::LogFormat,
    pub output: OutputFormat,
    pub node: NodeEndpoint,
    pub node_api_secret_file: Option<PathBuf>,
    /// Read for the wallet password before `LEPIC_PASSWORD` and the prompt.
    pub password_file: Option<PathBuf>,
    pub relay: RelayEndpoint,
    /// The servers of the settings file and the built-in configuration.
    pub servers: Servers,
    /// The timeouts, retries and limits of the built-in configuration.
    pub tuning: Tuning,
    pub relay_tor: RelayTor,
    /// Node requests go through the same tor as the relay (ADR 0022). Only with a tor named.
    pub node_over_tor: bool,
    /// How serve spreads its mail over relay sockets; split when a tor is named, shared
    /// otherwise.
    pub relay_sockets: RelaySockets,
    /// Refuse an S1 nobody asked for, answered `declined` (ADR 0045). Off unless set.
    pub refuse_unsolicited_payments: bool,
    /// Refuse a contact's invoice instead of parking it, answered `declined`. Off unless set.
    pub refuse_unsolicited_invoices: bool,
    /// The most open receipts over all senders (D3b); a further payment nobody asked for is
    /// refused while the cap is full.
    pub max_open_receipts: usize,
    /// The most open receipts for one sender key.
    pub max_open_receipts_per_sender: usize,
    /// The retired keys ([`RETIRED`]) the config file or the environment still sets.
    pub retired: Vec<&'static str>,
    /// The HTTP listener's native endpoint also opens envelopes sealed to the wallet's epic1
    /// addresses. Off unless set: without it the listener answers them as envelopes no key
    /// opens, so an epic1 does not tell which listener is its wallet.
    pub epic1_web_listener: bool,
    /// As `epic1_web_listener`, for the onion listener.
    pub epic1_onion_listener: bool,
    /// How long an unpaid invoice is kept, on either side.
    pub invoice_expiry: InvoiceExpiry,
    /// The blocks after which a send nobody answered expires, when the send names none: a CLI
    /// send, a send through `lepic serve` and an epic1 or in-person send.
    pub send_ttl_blocks: u64,
    /// The confirmations after which a payment is final: serve marks it `final` and logs
    /// `payment.confirmations_reached` (ADR 0058).
    pub final_confirmations: u64,
    /// The host bits the wallet claims to paired contacts (ADR 0034), only bits of
    /// `features::HOST_FEATURES`; none unless `host_features` names them.
    pub host_features: u32,
    /// The profile told to paired contacts (ADR 0041); none unless `profile` says so.
    pub profile: u16,
    /// The domain claimed to paired contacts, normalized; none unless `domain` says so.
    pub domain: Option<String>,
    /// Minutes without input before the interactive shell locks the wallet; 0 never.
    pub shell_idle_lock_minutes: u64,
    /// Where `lepic serve` posts the API events; none unless `webhook_url` says so.
    pub webhook: Option<Webhook>,
    /// Which connections the command may make; all unless `connection_mode` says so.
    pub connection_mode: ConnectionMode,
    /// HTTP payees, `http` entries of links and the webhook are reached directly while a tor
    /// is named. Off unless set; never with [`ConnectionMode::TorOnly`].
    pub http_direct: bool,
}

impl Settings {
    /// Why the command makes no connections, or `None` when it may make some.
    pub fn offline(&self) -> Option<OfflineReason> {
        match self.connection_mode {
            ConnectionMode::Offline => Some(OfflineReason::Offline),
            ConnectionMode::TorOnly if self.relay_tor == RelayTor::Off => {
                Some(OfflineReason::TorOnlyWithoutTor)
            }
            ConnectionMode::All | ConnectionMode::TorOnly => None,
        }
    }

    /// Whether a connection to another computer that would not go through tor is refused: a
    /// tor is named or the mode is not `all`, and `http_direct` is off (ADR 0021).
    pub fn refuses_direct(&self) -> bool {
        let tor_expected =
            self.relay_tor != RelayTor::Off || self.connection_mode != ConnectionMode::All;
        tor_expected && !self.http_direct
    }
}

/// The webhook of `lepic serve` (ADR 0058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Webhook {
    /// `https://`, or `http://` with `allow_private`.
    pub url: String,
    pub secret_file: PathBuf,
    /// Event type patterns; all events when empty.
    pub types: Vec<String>,
    /// Allows `http://` and a loopback, private or link-local address.
    pub allow_private: bool,
}

/// The output format alone, for reporting errors that happen before the rest resolves.
pub fn output_format(args: &GlobalArgs, env: &Env) -> OutputFormat {
    let parsed = args.output.or_else(|| {
        env.get("LEPIC_OUTPUT")
            .and_then(|value| OutputArg::from_str(value, false).ok())
    });
    match parsed {
        Some(OutputArg::Json) => OutputFormat::Json,
        Some(OutputArg::Human) | None => OutputFormat::Human,
    }
}

impl Settings {
    /// These settings on the chain the host forces, when it forces one.
    #[must_use]
    pub fn on_host_network(self, forced: Option<Network>) -> Self {
        match forced {
            Some(network) => Self { network, ..self },
            None => self,
        }
    }

    #[allow(clippy::too_many_lines)] // One line per setting.
    pub fn resolve(args: &GlobalArgs, env: &Env) -> Result<Self, SettingsError> {
        let config = Config::load(args, env)?;
        let lookup = Lookup {
            env,
            config: &config,
        };

        let network = match args.network {
            Some(network) => network,
            None => lookup
                .parse("network", |text| NetworkArg::from_str(text, false).ok())?
                .unwrap_or(DEFAULT_NETWORK),
        };
        let network = match network {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Floonet => Network::Floonet,
        };

        let data_dir = match &args.data_dir {
            Some(dir) => dir.clone(),
            None => match lookup.path("data_dir")? {
                Some(dir) => dir,
                None => env
                    .home()
                    .ok_or(SettingsError::NoHome)?
                    .join(HOME_DIR)
                    .join(network.as_str()),
            },
        };
        let data_dir = std::path::absolute(&data_dir).map_err(SettingsError::DataDir)?;

        let log_filter = match &args.log_level {
            Some(filter) => filter.clone(),
            None => lookup
                .text("log_level")?
                .unwrap_or_else(|| "warn".to_owned()),
        };
        let log_format = match args.log_format {
            Some(format) => format,
            None => lookup
                .parse("log_format", |text| {
                    LogFormatArg::from_str(text, false).ok()
                })?
                .unwrap_or(LogFormatArg::Compact),
        };
        let output = match args.output {
            Some(output) => output,
            None => lookup
                .parse("output", |text| OutputArg::from_str(text, false).ok())?
                .unwrap_or(OutputArg::Human),
        };

        let config = AppConfig::built_in(network)?;
        let mut servers = servers(args, env, &lookup, &config)?;
        let node = node(&lookup, &servers)?;
        let relay = relay(&lookup, &servers)?;
        if lookup.switch("local_mailbox")? {
            if !relay.domain().is_loopback() {
                let origin = lookup
                    .raw("local_mailbox")
                    .map_or(Origin::Default, |(_, origin)| origin);
                return Err(SettingsError::InvalidValue {
                    key: "local_mailbox",
                    origin,
                });
            }
            servers.mailboxes = servers.mailboxes.local(&relay)?;
        } else {
            // An upgraded wallet keeps reading its legacy relay as a mailbox.
            servers.mailboxes = servers.mailboxes.carrying(&relay);
        }
        let relay_tor = relay_tor(&lookup)?;
        let host_features = lookup
            .parse("host_features", parse_host_features)?
            .unwrap_or(0);
        let connection_mode = match args.connection_mode {
            Some(mode) => mode.into(),
            None => lookup
                .parse("connection_mode", |text| {
                    crate::cli::ConnectionModeArg::from_str(text, false).ok()
                })?
                .map_or(ConnectionMode::All, ConnectionMode::from),
        };
        let http_direct = lookup.switch("http_direct")?;
        if http_direct && connection_mode == ConnectionMode::TorOnly {
            let origin = lookup
                .raw("http_direct")
                .map_or(Origin::Default, |(_, origin)| origin);
            return Err(SettingsError::InvalidValue {
                key: "http_direct",
                origin,
            });
        }
        // Tor-only sends the node's requests through the tor too; a loopback node is still
        // reached directly.
        let node_over_tor = lookup.switch("node_over_tor")?
            || (connection_mode == ConnectionMode::TorOnly && relay_tor != RelayTor::Off);
        if node_over_tor && relay_tor == RelayTor::Off {
            let origin = lookup
                .raw("node_over_tor")
                .map_or(Origin::Default, |(_, origin)| origin);
            return Err(SettingsError::InvalidValue {
                key: "node_over_tor",
                origin,
            });
        }

        Ok(Self {
            network,
            data_dir,
            log_filter,
            log_format: match log_format {
                LogFormatArg::Pretty => lepic_telemetry::LogFormat::Pretty,
                LogFormatArg::Compact => lepic_telemetry::LogFormat::Compact,
                LogFormatArg::Json => lepic_telemetry::LogFormat::Json,
            },
            output: match output {
                OutputArg::Human => OutputFormat::Human,
                OutputArg::Json => OutputFormat::Json,
            },
            node,
            node_api_secret_file: lookup.path("node_api_secret_file")?,
            password_file: lookup.path("password_file")?,
            relay,
            servers,
            tuning: config.tuning,
            relay_sockets: lookup
                .parse("relay_sockets", parse_relay_sockets)?
                .unwrap_or(if relay_tor == RelayTor::Off {
                    RelaySockets::Shared
                } else {
                    RelaySockets::Split
                }),
            relay_tor,
            node_over_tor,
            refuse_unsolicited_payments: lookup.switch("refuse_unsolicited_payments")?,
            refuse_unsolicited_invoices: lookup.switch("refuse_unsolicited_invoices")?,
            max_open_receipts: receipt_cap(&lookup, "max_open_receipts")?
                .unwrap_or(lepic_wallet::WalletPolicy::DEFAULT.max_open_receipts),
            max_open_receipts_per_sender: receipt_cap(&lookup, "max_open_receipts_per_sender")?
                .unwrap_or(lepic_wallet::WalletPolicy::DEFAULT.max_open_receipts_per_sender),
            retired: lookup.retired(),
            epic1_web_listener: lookup.switch("epic1_web_listener")?,
            epic1_onion_listener: lookup.switch("epic1_onion_listener")?,
            invoice_expiry: lookup
                .parse("invoice_expiry_hours", parse_expiry_hours)?
                .unwrap_or_default(),
            send_ttl_blocks: send_ttl_blocks(&lookup)?,
            final_confirmations: final_confirmations(&lookup)?,
            host_features,
            profile: profile(args, &lookup)?,
            domain: domain(args, &lookup)?,
            shell_idle_lock_minutes: shell_idle_lock_minutes(&lookup)?,
            webhook: webhook(&lookup)?,
            connection_mode,
            http_direct,
        })
    }
}

/// The blocks a send is kept for when it names no cutoff: 7 days at one block a minute.
pub const DEFAULT_SEND_TTL_BLOCKS: u64 = lepic_wallet::DEFAULT_TTL_BLOCKS;

/// The most a receipt cap takes.
const MAX_RECEIPT_CAP: usize = 100_000;

/// A receipt cap: 1 to [`MAX_RECEIPT_CAP`], or `None` when unset.
fn receipt_cap(lookup: &Lookup<'_>, key: &'static str) -> Result<Option<usize>, SettingsError> {
    lookup.parse(key, |text| {
        text.parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_RECEIPT_CAP).contains(n))
    })
}

/// The most `send_ttl_blocks` takes: a year of blocks.
const MAX_SEND_TTL_BLOCKS: u64 = 525_600;

/// The blocks a send waits for an answer: 1 to 525600, [`DEFAULT_SEND_TTL_BLOCKS`] unless set.
fn send_ttl_blocks(lookup: &Lookup<'_>) -> Result<u64, SettingsError> {
    Ok(lookup
        .parse("send_ttl_blocks", |text| {
            text.parse::<u64>()
                .ok()
                .filter(|n| (1..=MAX_SEND_TTL_BLOCKS).contains(n))
        })?
        .unwrap_or(DEFAULT_SEND_TTL_BLOCKS))
}

/// The confirmations after which a payment is final: 1 to 1440, 6 unless set. `final_confirmations`
/// wins; `payment_confirmations`, its old name, is read when that is not set.
fn final_confirmations(lookup: &Lookup<'_>) -> Result<u64, SettingsError> {
    let confirmations = |text: &str| text.parse::<u64>().ok().filter(|n| (1..=1440).contains(n));
    Ok(match lookup.parse("final_confirmations", confirmations)? {
        Some(set) => set,
        None => lookup
            .parse("payment_confirmations", confirmations)?
            .unwrap_or(6),
    })
}

/// The webhook the `webhook_*` keys describe. Without `webhook_url` the other three must be unset.
fn webhook(lookup: &Lookup<'_>) -> Result<Option<Webhook>, SettingsError> {
    let invalid = |key| {
        let origin = lookup
            .raw(key)
            .map_or(Origin::Default, |(_, origin)| origin);
        SettingsError::InvalidValue { key, origin }
    };
    let allow_private = lookup.switch("webhook_allow_private")?;
    let types = lookup
        .parse("webhook_types", parse_event_types)?
        .unwrap_or_default();
    let secret_file = lookup.path("webhook_secret_file")?;
    let Some((url, _)) = lookup.raw("webhook_url") else {
        for key in ["webhook_secret_file", "webhook_types"] {
            if lookup.raw(key).is_some() {
                return Err(invalid(key));
            }
        }
        if allow_private {
            return Err(invalid("webhook_allow_private"));
        }
        return Ok(None);
    };
    let uri = url
        .parse::<hyper::Uri>()
        .map_err(|_| invalid("webhook_url"))?;
    let scheme_ok = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => allow_private,
        _ => false,
    };
    let host_ok = uri.host().is_some_and(|host| !host.is_empty())
        && uri
            .authority()
            .is_some_and(|authority| !authority.as_str().contains('@'));
    if !scheme_ok || !host_ok {
        return Err(invalid("webhook_url"));
    }
    let secret_file = secret_file.ok_or_else(|| invalid("webhook_secret_file"))?;
    Ok(Some(Webhook {
        url,
        secret_file,
        types,
        allow_private,
    }))
}

/// A comma list of event types, `payment.*` style wildcards allowed, at most
/// `MAX_API_KIND_PATTERNS` of them: what `GET /events` takes as `types`.
pub(crate) fn parse_event_types(text: &str) -> Option<Vec<String>> {
    let types: Vec<String> = text.split(',').map(str::to_owned).collect();
    if types.len() > lepic_store::MAX_API_KIND_PATTERNS {
        return None;
    }
    let valid = types.iter().all(|kind| {
        let name = kind.strip_suffix(".*").unwrap_or(kind);
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte == b'.')
    });
    valid.then_some(types)
}

/// The minutes with no line entered before the shell locks the wallet; 0 never.
fn shell_idle_lock_minutes(lookup: &Lookup<'_>) -> Result<u64, SettingsError> {
    Ok(lookup
        .parse("shell_idle_lock_minutes", |text| text.parse::<u64>().ok())?
        .unwrap_or(DEFAULT_SHELL_IDLE_LOCK_MINUTES))
}

/// The servers of the settings file a flag, its variable or the config file names, else of
/// `~/.lepic/settings.toml`.
fn servers(
    args: &GlobalArgs,
    env: &Env,
    lookup: &Lookup<'_>,
    config: &AppConfig,
) -> Result<Servers, SettingsError> {
    let named = match &args.settings {
        Some(path) => Some(path.clone()),
        None => lookup.path("settings_file")?,
    };
    match named {
        Some(path) => settings_file::load(Some(&path), true, config),
        None => settings_file::load(
            env.home()
                .map(|home| settings_file::default_path(&home, config.network))
                .as_deref(),
            false,
            config,
        ),
    }
}

/// `node_url`, else the first node of the settings file.
fn node(lookup: &Lookup<'_>, servers: &Servers) -> Result<NodeEndpoint, SettingsError> {
    if let Some(node) = lookup.parse("node_url", |text| NodeEndpoint::parse(text).ok())? {
        return Ok(node);
    }
    servers.node.clone().ok_or(SettingsError::InvalidValue {
        key: "node_url",
        origin: Origin::Default,
    })
}

/// `epicbox_relay`, else the first Epicbox server of the settings file.
fn relay(lookup: &Lookup<'_>, servers: &Servers) -> Result<RelayEndpoint, SettingsError> {
    match lookup.parse("epicbox_relay", parse_relay)? {
        Some(relay) => Ok(relay),
        None => servers.epicbox.clone().ok_or(SettingsError::InvalidValue {
            key: "epicbox_relay",
            origin: Origin::Default,
        }),
    }
}

const SECONDS_PER_HOUR: u64 = 60 * 60;

/// A whole number of hours, at least 1, as an invoice expiry. The CLI sets no upper bound.
fn parse_expiry_hours(text: &str) -> Option<InvoiceExpiry> {
    let hours: u64 = text.parse().ok()?;
    let seconds = hours.checked_mul(SECONDS_PER_HOUR)?;
    InvoiceExpiry::new(std::time::Duration::from_secs(seconds)).ok()
}

/// The profile a flag, `LEPIC_PROFILE` or the config file gives; a flag that is invalid is a usage
/// error like any setting.
fn profile(args: &GlobalArgs, lookup: &Lookup<'_>) -> Result<u16, SettingsError> {
    Ok(profile_flag(args)?
        .or(lookup.parse("profile", crate::profile::parse_setting)?)
        .unwrap_or(0))
}

/// The domain a flag, `LEPIC_DOMAIN` or the config file gives, lowercased and without a trailing
/// dot; one that is not a domain name is a usage error like any setting.
fn domain(args: &GlobalArgs, lookup: &Lookup<'_>) -> Result<Option<String>, SettingsError> {
    let parse = |text: &str| {
        lepic_wallet_contacts::DomainName::new(text)
            .ok()
            .map(|name| name.to_string())
    };
    match &args.domain {
        Some(text) => parse(text).map(Some).ok_or(SettingsError::InvalidValue {
            key: "domain",
            origin: Origin::Flag,
        }),
        None => lookup.parse("domain", parse),
    }
}

/// The profile `--profile` or `--profile-bits` gives.
pub fn profile_flag(args: &GlobalArgs) -> Result<Option<u16>, SettingsError> {
    let invalid = || SettingsError::InvalidValue {
        key: "profile",
        origin: Origin::Flag,
    };
    if let Some(names) = &args.profile {
        return crate::profile::parse_names(names)
            .map(Some)
            .ok_or_else(invalid);
    }
    args.profile_bits
        .as_deref()
        .map(|bits| crate::profile::parse_bits(bits).ok_or_else(invalid))
        .transpose()
}

/// The host bits a `host_features` value names. Each name is one bit of
/// `features::HOST_FEATURES`; an unknown name refuses the whole value. Empty names none.
fn parse_host_features(text: &str) -> Option<u32> {
    use lepic_transport::features;
    let mut bits = 0;
    for name in text
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        bits |= match name {
            "device-forwarding" => features::DEVICE_FORWARDING,
            "name-service" => features::NAME_SERVICE,
            _ => return None,
        };
    }
    Some(bits & features::HOST_FEATURES)
}

/// At most one way through tor: a running tor's SOCKS address, or a tor binary to run.
fn relay_tor(lookup: &Lookup<'_>) -> Result<RelayTor, SettingsError> {
    let socks = lookup.parse("epicbox_tor_socks", |text| {
        text.parse::<std::net::SocketAddr>()
            .ok()
            .filter(|address| address.ip().is_loopback())
    })?;
    let binary = lookup.path("epicbox_tor_binary")?;
    let lib_dir = lookup.path("epicbox_tor_lib_dir")?;
    let invalid = |key| {
        let origin = lookup
            .raw(key)
            .map_or(Origin::Default, |(_, origin)| origin);
        SettingsError::InvalidValue { key, origin }
    };
    match (socks, binary) {
        (Some(_), Some(_)) => Err(invalid("epicbox_tor_binary")),
        (Some(_), None) if lib_dir.is_some() => Err(invalid("epicbox_tor_lib_dir")),
        (None, None) if lib_dir.is_some() => Err(invalid("epicbox_tor_lib_dir")),
        (Some(address), None) => Ok(RelayTor::Socks(address)),
        (None, Some(binary)) => Ok(RelayTor::Binary { binary, lib_dir }),
        (None, None) => Ok(RelayTor::Off),
    }
}

/// `wss://host[:port]`, `ws://host[:port]` to a loopback host, or `host[:port]` for TLS.
fn parse_relay(text: &str) -> Option<RelayEndpoint> {
    let (security, rest) = if let Some(rest) = text.strip_prefix("wss://") {
        (Security::Tls, rest)
    } else if let Some(rest) = text.strip_prefix("ws://") {
        (Security::Plain, rest)
    } else {
        (Security::Tls, text)
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
        None => (rest, None),
    };
    let domain = Domain::parse(host).ok()?;
    let endpoint = RelayEndpoint::new(domain, port, security);
    endpoint.check_security().ok()?;
    Some(endpoint)
}

/// `shared` or `split`.
fn parse_relay_sockets(text: &str) -> Option<RelaySockets> {
    match text {
        "shared" => Some(RelaySockets::Shared),
        "split" => Some(RelaySockets::Split),
        _ => None,
    }
}

/// `true` or `false`.
fn parse_switch(text: &str) -> Option<bool> {
    match text {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

struct Lookup<'a> {
    env: &'a Env,
    config: &'a Config,
}

impl Lookup<'_> {
    fn raw(&self, key: &'static str) -> Option<(String, Origin)> {
        let variable = SETTINGS
            .iter()
            .find(|(name, _, _)| *name == key)
            .map(|(_, variable, _)| *variable);
        if let Some(variable) = variable
            && let Some(value) = self.env.get(variable)
        {
            return Some((value.to_owned(), Origin::Env(variable)));
        }
        self.config.values.get(key).map(|value| {
            (
                value.clone(),
                Origin::Config(self.config.path.clone().unwrap_or_default()),
            )
        })
    }

    fn text(&self, key: &'static str) -> Result<Option<String>, SettingsError> {
        Ok(self.raw(key).map(|(value, _)| value))
    }

    fn parse<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Result<Option<T>, SettingsError> {
        match self.raw(key) {
            None => Ok(None),
            Some((value, origin)) => parse(&value)
                .map(Some)
                .ok_or(SettingsError::InvalidValue { key, origin }),
        }
    }

    /// The retired keys set by a variable or the config file, whatever their value.
    fn retired(&self) -> Vec<&'static str> {
        RETIRED
            .iter()
            .filter(|(key, variable)| {
                self.env.get(variable).is_some() || self.config.values.contains_key(*key)
            })
            .map(|(key, _)| *key)
            .collect()
    }

    /// `true` or `false`; off unless set.
    fn switch(&self, key: &'static str) -> Result<bool, SettingsError> {
        Ok(self.parse(key, parse_switch)?.unwrap_or(false))
    }

    /// A path from the config file is relative to the file's directory.
    fn path(&self, key: &'static str) -> Result<Option<PathBuf>, SettingsError> {
        Ok(self.raw(key).map(|(value, origin)| match origin {
            Origin::Config(file) => file
                .parent()
                .map_or_else(|| PathBuf::from(&value), |dir| dir.join(&value)),
            Origin::Flag | Origin::Env(_) | Origin::Default => PathBuf::from(value),
        }))
    }
}

#[derive(Debug, Default)]
struct Config {
    path: Option<PathBuf>,
    values: BTreeMap<String, String>,
}

impl Config {
    /// An explicit config file must exist; the default one is read only when it does.
    fn load(args: &GlobalArgs, env: &Env) -> Result<Self, SettingsError> {
        let explicit = args
            .config
            .clone()
            .or_else(|| env.get(CONFIG_ENV).map(PathBuf::from));
        let path = match explicit {
            Some(path) => path,
            None => match env.home() {
                Some(home) => {
                    let path = home.join(HOME_DIR).join(CONFIG_FILE);
                    if !path.is_file() {
                        return Ok(Self::default());
                    }
                    path
                }
                None => return Ok(Self::default()),
            },
        };
        let text = read_bounded(&path)?;
        let values = parse_config(&path, &text)?;
        Ok(Self {
            path: Some(path),
            values,
        })
    }
}

/// Keeps `url` as `node_url` in the config file the settings are read from, the default one
/// when none is named, and returns its path. The file is made when it is not there; every
/// other line of it stays as it is.
pub(crate) fn save_node_url(args: &GlobalArgs, env: &Env, url: &str) -> io::Result<PathBuf> {
    let path = args
        .config
        .clone()
        .or_else(|| env.get(CONFIG_ENV).map(PathBuf::from))
        .or_else(|| env.home().map(|home| home.join(HOME_DIR).join(CONFIG_FILE)))
        .ok_or_else(|| io::Error::other("there is no home directory for the config file"))?;
    let before = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, with_node_url(&before, url))?;
    Ok(path)
}

/// The config text `text` with `node_url` set to `url`: its line replaced, or one added.
fn with_node_url(text: &str, url: &str) -> String {
    let quoted = url.replace('\\', "\\\\").replace('"', "\\\"");
    let entry = format!("node_url = \"{quoted}\"");
    let mut replaced = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        let names_node = line
            .split_once('=')
            .is_some_and(|(key, _)| key.trim() == "node_url");
        if names_node {
            if !replaced {
                lines.push(&entry);
            }
            replaced = true;
        } else {
            lines.push(line);
        }
    }
    if !replaced {
        lines.push(&entry);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

fn read_bounded(path: &Path) -> Result<String, SettingsError> {
    let read_error = |source| SettingsError::ConfigRead {
        path: path.to_owned(),
        source,
    };
    let file = std::fs::File::open(path).map_err(read_error)?;
    let mut text = String::new();
    file.take(MAX_CONFIG_LEN.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(read_error)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_LEN {
        return Err(SettingsError::ConfigTooLarge {
            path: path.to_owned(),
        });
    }
    Ok(text)
}

fn parse_config(path: &Path, text: &str) -> Result<BTreeMap<String, String>, SettingsError> {
    let mut values = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let number = index.saturating_add(1);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let syntax = || SettingsError::ConfigSyntax {
            path: path.to_owned(),
            line: number,
        };
        let (key, value) = line.split_once('=').ok_or_else(syntax)?;
        let key = key.trim();
        let value = parse_value(value.trim()).ok_or_else(syntax)?;
        if !SETTINGS.iter().any(|(name, _, _)| *name == key)
            && !RETIRED.iter().any(|(name, _)| *name == key)
        {
            return Err(SettingsError::UnknownKey {
                path: path.to_owned(),
                line: number,
                key: key.to_owned(),
            });
        }
        if values.insert(key.to_owned(), value).is_some() {
            return Err(SettingsError::DuplicateKey {
                path: path.to_owned(),
                line: number,
                key: key.to_owned(),
            });
        }
    }
    Ok(values)
}

/// A quoted string with `\"` and `\\` escapes and an optional trailing comment, or a bare word.
fn parse_value(text: &str) -> Option<String> {
    let Some(quoted) = text.strip_prefix('"') else {
        let bare = text.split_once('#').map_or(text, |(bare, _)| bare).trim();
        let valid = !bare.is_empty() && !bare.contains(['"', '\'', ' ', '\t']);
        return valid.then(|| bare.to_owned());
    };
    let mut value = String::new();
    let mut chars = quoted.chars();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                escaped @ ('"' | '\\') => value.push(escaped),
                _ => return None,
            },
            other => value.push(other),
        }
    }
    let rest = chars.as_str().trim();
    (rest.is_empty() || rest.starts_with('#')).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_shows_the_password_variable() {
        let env = Env::new([
            (PASSWORD_ENV.to_owned(), "hunter2".to_owned()),
            ("LEPIC_OUTPUT".to_owned(), "json".to_owned()),
        ]);
        let shown = format!("{env:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(
            shown.contains("[redacted]") && shown.contains("json"),
            "{shown}"
        );
    }

    #[test]
    fn the_node_is_kept_in_the_config_text_beside_its_other_lines() {
        let url = "https://node.example.org";
        assert_eq!(
            with_node_url("", url),
            "node_url = \"https://node.example.org\"\n"
        );
        let before = "# mine\nlog_level = info\nnode_url = \"http://127.0.0.1:3413\" # old\n";
        let after = with_node_url(before, url);
        assert_eq!(
            after,
            "# mine\nlog_level = info\nnode_url = \"https://node.example.org\"\n"
        );
        let read = parse_config(Path::new("config.toml"), &after).unwrap();
        assert_eq!(read.get("node_url").map(String::as_str), Some(url));
        // A commented line is not the setting.
        let commented = with_node_url("# node_url = \"x\"\n", url);
        assert!(
            commented.starts_with("# node_url = \"x\"\nnode_url = "),
            "{commented}"
        );
    }

    #[test]
    fn config_values_are_bare_words_or_quoted_strings() {
        assert_eq!(parse_value("mainnet"), Some("mainnet".to_owned()));
        assert_eq!(parse_value("mainnet # comment"), Some("mainnet".to_owned()));
        assert_eq!(parse_value(r#""a b""#), Some("a b".to_owned()));
        assert_eq!(parse_value(r#""a\"b\\c" # x"#), Some(r#"a"b\c"#.to_owned()));
        for bad in ["", r#""open"#, r#""a" b"#, r#""\n""#, "a b", "'x'"] {
            assert_eq!(parse_value(bad), None, "{bad}");
        }
    }

    #[test]
    fn invoice_expiry_is_whole_hours_of_at_least_one() {
        let hours = |h: u64| Some(std::time::Duration::from_secs(h * SECONDS_PER_HOUR));
        assert_eq!(parse_expiry_hours("1").map(InvoiceExpiry::window), hours(1));
        assert_eq!(
            parse_expiry_hours("48").map(InvoiceExpiry::window),
            hours(48)
        );
        assert_eq!(
            parse_expiry_hours("720").map(InvoiceExpiry::window),
            hours(720)
        );
        for bad in ["0", "-1", "1.5", "", "24h", "18446744073709551615"] {
            assert!(parse_expiry_hours(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn host_features_are_host_bits_by_name() {
        use lepic_transport::features;
        assert_eq!(parse_host_features(""), Some(0));
        assert_eq!(
            parse_host_features("name-service"),
            Some(features::NAME_SERVICE)
        );
        assert_eq!(
            parse_host_features(" name-service , device-forwarding,"),
            Some(features::NAME_SERVICE | features::DEVICE_FORWARDING)
        );
        for bad in [
            "marker",
            "pair-requests",
            "32",
            "name-service,other",
            "Name-Service",
        ] {
            assert_eq!(parse_host_features(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_wallet_claims_no_host_bit_unless_the_setting_names_one() {
        assert_eq!(resolve(&[]).unwrap().host_features, 0);
        assert_eq!(
            resolve(&[("LEPIC_HOST_FEATURES", "name-service")])
                .unwrap()
                .host_features,
            lepic_transport::features::NAME_SERVICE
        );
        assert!(matches!(
            resolve(&[("LEPIC_HOST_FEATURES", "everything")]),
            Err(SettingsError::InvalidValue {
                key: "host_features",
                ..
            })
        ));
    }

    #[test]
    fn a_refused_setting_says_what_it_takes() {
        let error = resolve(&[("LEPIC_NODE_URL", "ftp://node.example")]).unwrap_err();
        let text = error.to_string();
        assert!(
            text.starts_with("node_url from LEPIC_NODE_URL is invalid: ")
                && text.contains("http:// or https://")
                && text.contains("empty"),
            "{text}"
        );
        // A key nothing sets reads as not set, and names the variable to set it with.
        let text = invalid_value("node_url", &Origin::Default);
        assert!(
            text.starts_with(
                "node_url is not set: give it as LEPIC_NODE_URL or in the config file"
            ),
            "{text}"
        );
        // A combination says which settings go together.
        let text = invalid_value("http_direct", &Origin::Env("LEPIC_HTTP_DIRECT"));
        assert!(text.contains("tor-only"), "{text}");
        // Every key has some reason to give.
        for (key, _, _) in SETTINGS {
            let text = invalid_value(key, &Origin::Flag);
            assert!(text.contains(": "), "{key}: {text}");
        }
    }

    #[test]
    fn domain_setting_parses_and_rejects() {
        assert_eq!(resolve(&[]).unwrap().domain, None);
        assert_eq!(
            resolve(&[("LEPIC_DOMAIN", "BTLabs.UK.")]).unwrap().domain,
            Some("btlabs.uk".to_owned())
        );
        assert!(matches!(
            resolve(&[("LEPIC_DOMAIN", "not a domain")]),
            Err(SettingsError::InvalidValue { key: "domain", .. })
        ));
    }

    #[test]
    fn the_profile_comes_from_a_flag_before_the_variable_and_is_zero_by_default() {
        assert_eq!(resolve(&[]).unwrap().profile, 0);
        assert_eq!(
            resolve(&[("LEPIC_PROFILE", "automated")]).unwrap().profile,
            2
        );
        assert_eq!(
            resolve(&[("LEPIC_PROFILE", "0x8001")]).unwrap().profile,
            0x8001
        );
        assert!(matches!(
            resolve(&[("LEPIC_PROFILE", "65536")]),
            Err(SettingsError::InvalidValue { key: "profile", .. })
        ));
        let env = Env::new(vec![
            ("HOME".to_owned(), "/home/test".to_owned()),
            ("LEPIC_PROFILE".to_owned(), "automated".to_owned()),
        ]);
        let flag = GlobalArgs {
            profile_bits: Some("0x1".to_owned()),
            ..GlobalArgs::default()
        };
        assert_eq!(Settings::resolve(&flag, &env).unwrap().profile, 1);
        let bad = GlobalArgs {
            profile: Some("everything".to_owned()),
            ..GlobalArgs::default()
        };
        assert!(matches!(
            Settings::resolve(&bad, &env),
            Err(SettingsError::InvalidValue {
                key: "profile",
                origin: Origin::Flag
            })
        ));
    }

    #[test]
    fn relay_settings_name_scheme_host_and_port() {
        let tls = parse_relay("wss://relay.example.org").unwrap();
        assert_eq!((tls.port(), tls.security()), (443, Security::Tls));
        let plain = parse_relay("ws://127.0.0.1:3423/").unwrap();
        assert_eq!((plain.port(), plain.security()), (3423, Security::Plain));
        assert_eq!(parse_relay("relay.example.org:8443").unwrap().port(), 8443);
        assert!(parse_relay("ws://host:notaport").is_none());
        assert!(parse_relay("ws://localhost:3423").is_some());
        assert!(parse_relay("ws://relay.example.org").is_none());
        assert!(parse_relay("").is_none());
    }

    fn resolve(vars: &[(&str, &str)]) -> Result<Settings, SettingsError> {
        let mut all = vec![("HOME".to_owned(), "/home/test".to_owned())];
        all.extend(
            vars.iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        );
        Settings::resolve(&GlobalArgs::default(), &Env::new(all))
    }

    /// Settings resolved with a temporary home, the flags `args` and the variables `vars`.
    fn resolve_in(
        home: &Path,
        args: &GlobalArgs,
        vars: &[(&str, &str)],
    ) -> Result<Settings, SettingsError> {
        let mut all = vec![("HOME".to_owned(), home.to_str().unwrap().to_owned())];
        all.extend(
            vars.iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        );
        Settings::resolve(args, &Env::new(all))
    }

    fn write_config(home: &Path, text: &str) {
        std::fs::create_dir_all(home.join(HOME_DIR)).unwrap();
        std::fs::write(home.join(HOME_DIR).join(CONFIG_FILE), text).unwrap();
    }

    fn named(network: NetworkArg) -> GlobalArgs {
        GlobalArgs {
            network: Some(network),
            ..GlobalArgs::default()
        }
    }

    #[cfg(not(feature = "floonet-harness"))]
    #[test]
    fn nothing_naming_a_network_is_mainnet() {
        let home = tempfile::tempdir().unwrap();
        let settings = resolve_in(home.path(), &GlobalArgs::default(), &[]).unwrap();
        assert_eq!(settings.network, Network::Mainnet);
        assert_eq!(settings.data_dir, home.path().join(".lepic/mainnet"));
    }

    #[cfg(feature = "floonet-harness")]
    #[test]
    fn the_harness_build_is_on_floonet_when_nothing_names_a_network() {
        let home = tempfile::tempdir().unwrap();
        let settings = resolve_in(home.path(), &GlobalArgs::default(), &[]).unwrap();
        assert_eq!(settings.network, Network::Floonet);
        assert_eq!(settings.data_dir, home.path().join(".lepic/floonet"));
        // A name still wins, in the harness build too.
        let settings = resolve_in(
            home.path(),
            &GlobalArgs::default(),
            &[("LEPIC_NETWORK", "mainnet")],
        )
        .unwrap();
        assert_eq!(settings.network, Network::Mainnet);
    }

    #[test]
    fn the_network_comes_from_a_flag_before_the_variable_before_the_config_file() {
        let home = tempfile::tempdir().unwrap();
        let none = GlobalArgs::default();
        write_config(home.path(), "network = \"floonet\"\n");
        let network = |args: &GlobalArgs, vars: &[(&str, &str)]| {
            resolve_in(home.path(), args, vars).unwrap().network
        };

        assert_eq!(network(&none, &[]), Network::Floonet, "config file");
        assert_eq!(
            network(&none, &[("LEPIC_NETWORK", "mainnet")]),
            Network::Mainnet,
            "variable over the file"
        );
        assert_eq!(
            network(&named(NetworkArg::Floonet), &[("LEPIC_NETWORK", "mainnet")]),
            Network::Floonet,
            "flag over the variable"
        );
        assert_eq!(
            network(&named(NetworkArg::Mainnet), &[("LEPIC_NETWORK", "floonet")]),
            Network::Mainnet,
            "flag over the variable, the other way"
        );
    }

    #[test]
    fn a_network_that_is_not_one_of_the_two_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let result = resolve_in(
            home.path(),
            &GlobalArgs::default(),
            &[("LEPIC_NETWORK", "testnet")],
        );
        assert!(matches!(
            result,
            Err(SettingsError::InvalidValue {
                key: "network",
                origin: Origin::Env(_)
            })
        ));
    }

    #[test]
    fn floonet_has_its_own_directory_settings_file_and_servers() {
        let home = tempfile::tempdir().unwrap();
        let settings = resolve_in(home.path(), &named(NetworkArg::Floonet), &[]).unwrap();
        assert_eq!(settings.network, Network::Floonet);
        assert_eq!(settings.data_dir, home.path().join(".lepic/floonet"));
        assert_eq!(settings.node.as_str(), "https://floo-node.btlabs.uk");
        assert_eq!(settings.relay.domain().as_str(), "epicbox.btlabs.uk");
        let mailboxes: Vec<String> = settings
            .servers
            .mailboxes
            .current()
            .endpoints()
            .iter()
            .map(lepic_wallet_contacts::mailbox_host)
            .collect();
        assert_eq!(mailboxes, ["epicbox.btlabs.uk"]);
        assert_eq!(
            settings.servers.default_epicbox_domain.as_str(),
            "epicbox.btlabs.uk"
        );
        let nodes: Vec<&str> = settings
            .servers
            .nodes
            .iter()
            .map(lepic_wallet::NodeEndpoint::as_str)
            .collect();
        assert_eq!(nodes, ["https://floo-node.btlabs.uk"]);
        // The settings file is written on first use, beside the mainnet one, which is not.
        let written = home.path().join(".lepic/settings-floonet.toml");
        assert_eq!(
            std::fs::read_to_string(written).unwrap(),
            crate::settings_file::SHIPPED_SETTINGS_FLOONET
        );
        assert!(!home.path().join(".lepic/settings.toml").exists());
    }

    #[test]
    fn mainnet_keeps_its_servers_and_file_when_floonet_exists() {
        let home = tempfile::tempdir().unwrap();
        resolve_in(home.path(), &named(NetworkArg::Floonet), &[]).unwrap();
        let settings = resolve_in(home.path(), &named(NetworkArg::Mainnet), &[]).unwrap();
        assert_eq!(settings.network, Network::Mainnet);
        assert_eq!(settings.data_dir, home.path().join(".lepic/mainnet"));
        assert_ne!(settings.node.as_str(), "https://floo-node.btlabs.uk");
        assert!(settings.servers.mailboxes.current().endpoints().len() > 1);
        assert!(home.path().join(".lepic/settings.toml").is_file());
    }

    #[test]
    fn a_named_settings_file_wins_on_floonet() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("mine.toml");
        std::fs::write(
            &path,
            "[node]\nservers = [\"http://127.0.0.1:3413\"]\n[epicbox]\nservers = [\"epicbox.example.org\"]\n",
        )
        .unwrap();
        let args = GlobalArgs {
            settings: Some(path),
            ..named(NetworkArg::Floonet)
        };
        let settings = resolve_in(home.path(), &args, &[]).unwrap();
        assert_eq!(settings.node.as_str(), "http://127.0.0.1:3413");
        assert_eq!(settings.relay.domain().as_str(), "epicbox.example.org");
        assert!(!home.path().join(".lepic/settings-floonet.toml").exists());
    }

    #[test]
    fn the_node_relay_and_data_dir_overrides_work_on_floonet() {
        let home = tempfile::tempdir().unwrap();
        let data = home.path().join("data");
        let settings = resolve_in(
            home.path(),
            &named(NetworkArg::Floonet),
            &[
                ("LEPIC_NODE_URL", "http://127.0.0.1:3413"),
                ("LEPIC_EPICBOX_RELAY", "ws://127.0.0.1:3423"),
                ("LEPIC_DATA_DIR", data.to_str().unwrap()),
            ],
        )
        .unwrap();
        assert_eq!(settings.node.as_str(), "http://127.0.0.1:3413");
        assert_eq!(settings.relay.port(), 3423);
        assert_eq!(settings.data_dir, data);
        assert_eq!(settings.network, Network::Floonet);
    }

    #[test]
    fn a_host_that_forces_a_network_changes_only_the_network() {
        let home = tempfile::tempdir().unwrap();
        let settings = resolve_in(home.path(), &named(NetworkArg::Mainnet), &[]).unwrap();
        let data_dir = settings.data_dir.clone();
        let same = settings.clone().on_host_network(None);
        assert_eq!(same.network, Network::Mainnet);
        let forced = settings.on_host_network(Some(Network::Floonet));
        assert_eq!(forced.network, Network::Floonet);
        assert_eq!(forced.data_dir, data_dir);
    }

    #[test]
    fn an_upgraded_wallet_carries_its_legacy_relay_into_the_mailbox_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let old = "version = 1\n[node]\nservers = [\"http://127.0.0.1:3413\"]\n\
                   [epicbox]\nservers = [\"relay.pool.example.org:8443\", \"epicbox.btlabs.uk\"]\n";
        std::fs::write(&path, old).unwrap();
        let file = ("LEPIC_SETTINGS", path.to_str().unwrap());
        let relay = parse_relay("relay.pool.example.org:8443").unwrap();

        let settings = resolve(&[file]).unwrap();
        let list = settings.servers.mailboxes.current();
        let listed = list.listed();
        let carried = listed
            .iter()
            .find(|entry| entry.endpoint == relay)
            .unwrap_or_else(|| panic!("{relay:?} is not in {listed:?}"));
        assert_eq!(carried.origin, lepic_wallet_contacts::MailboxOrigin::Added);
        assert_eq!(
            list.shipped().len(),
            listed.len() - 1,
            "the shipped ones stay"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            old,
            "loading writes nothing"
        );

        // Removing it keeps it removed: the next load does not carry it again.
        assert!(settings.servers.mailboxes.remove(&relay).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("removed = [\"relay.pool.example.org:8443\"]"),
            "{text}"
        );
        let again = resolve(&[file]).unwrap().servers.mailboxes.current();
        assert!(!again.contains(&relay));
        assert_eq!(again.endpoints(), again.shipped());
    }

    #[test]
    fn a_legacy_relay_that_cannot_be_a_mailbox_or_is_one_already_is_not_carried() {
        let shipped = resolve(&[]).unwrap().servers.mailboxes.current();
        assert!(
            shipped.added().is_empty(),
            "a fresh install carries nothing"
        );
        // A loopback relay is not a public name, a plain one is not TLS.
        let relay = "ws://localhost:3423";
        let list = resolve(&[("LEPIC_EPICBOX_RELAY", relay)])
            .unwrap()
            .servers
            .mailboxes
            .current();
        assert_eq!(list.endpoints(), shipped.endpoints(), "{relay}");
        // The setting beats the file, and a public relay it names is carried.
        let list = resolve(&[("LEPIC_EPICBOX_RELAY", "wss://relay.example.org")])
            .unwrap()
            .servers
            .mailboxes
            .current();
        assert_eq!(
            list.added(),
            [parse_relay("wss://relay.example.org").unwrap()]
        );
    }

    #[test]
    fn local_mailbox_makes_a_loopback_relay_the_whole_list() {
        let relay = ("LEPIC_EPICBOX_RELAY", "ws://localhost:3423");
        let on = ("LEPIC_LOCAL_MAILBOX", "true");
        let list = resolve(&[relay, on]).unwrap().servers.mailboxes.current();
        let listed = list.listed();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].endpoint,
            parse_relay("ws://localhost:3423").unwrap()
        );
        assert!(list.holds_shipped());
        assert!(list.added().is_empty() && list.removed().is_empty());

        let off = resolve(&[relay]).unwrap().servers.mailboxes.current();
        assert!(
            off.listed().len() > 1,
            "the shipped list stays without the key"
        );

        let public = ("LEPIC_EPICBOX_RELAY", "wss://relay.example.org");
        assert!(matches!(
            resolve(&[public, on]),
            Err(SettingsError::InvalidValue {
                key: "local_mailbox",
                origin: Origin::Env("LEPIC_LOCAL_MAILBOX")
            })
        ));
    }

    #[test]
    fn connection_mode_and_a_named_tor_decide_what_connects() {
        let tor = ("LEPIC_EPICBOX_TOR_SOCKS", "127.0.0.1:9050");
        let plain = resolve(&[]).unwrap();
        assert_eq!((plain.offline(), plain.refuses_direct()), (None, false));
        let named = resolve(&[tor]).unwrap();
        assert_eq!((named.offline(), named.refuses_direct()), (None, true));
        let direct = resolve(&[tor, ("LEPIC_HTTP_DIRECT", "true")]).unwrap();
        assert!(!direct.refuses_direct());

        let only = ("LEPIC_CONNECTION_MODE", "tor-only");
        let through = resolve(&[tor, only]).unwrap();
        assert_eq!(through.offline(), None);
        assert!(through.refuses_direct() && through.node_over_tor);
        assert_eq!(
            resolve(&[only]).unwrap().offline(),
            Some(OfflineReason::TorOnlyWithoutTor)
        );
        assert!(matches!(
            resolve(&[tor, only, ("LEPIC_HTTP_DIRECT", "true")]),
            Err(SettingsError::InvalidValue {
                key: "http_direct",
                ..
            })
        ));
        let offline = resolve(&[("LEPIC_CONNECTION_MODE", "offline")]).unwrap();
        assert_eq!(offline.offline(), Some(OfflineReason::Offline));
        assert!(resolve(&[("LEPIC_CONNECTION_MODE", "sometimes")]).is_err());
    }

    #[test]
    fn the_relay_goes_through_tor_only_when_a_tor_is_named() {
        assert_eq!(resolve(&[]).unwrap().relay_tor, RelayTor::Off);
        assert_eq!(
            resolve(&[("LEPIC_EPICBOX_TOR_SOCKS", "127.0.0.1:9050")])
                .unwrap()
                .relay_tor,
            RelayTor::Socks("127.0.0.1:9050".parse().unwrap())
        );
        assert_eq!(
            resolve(&[
                ("LEPIC_EPICBOX_TOR_BINARY", "/opt/tor/tor"),
                ("LEPIC_EPICBOX_TOR_LIB_DIR", "/opt/tor"),
            ])
            .unwrap()
            .relay_tor,
            RelayTor::Binary {
                binary: PathBuf::from("/opt/tor/tor"),
                lib_dir: Some(PathBuf::from("/opt/tor")),
            }
        );
    }

    #[test]
    fn serve_splits_its_relay_sockets_under_tor_unless_told_otherwise() {
        let tor = ("LEPIC_EPICBOX_TOR_SOCKS", "127.0.0.1:9050");
        assert_eq!(resolve(&[]).unwrap().relay_sockets, RelaySockets::Shared);
        assert_eq!(resolve(&[tor]).unwrap().relay_sockets, RelaySockets::Split);
        assert_eq!(
            resolve(&[tor, ("LEPIC_RELAY_SOCKETS", "shared")])
                .unwrap()
                .relay_sockets,
            RelaySockets::Shared
        );
        assert_eq!(
            resolve(&[("LEPIC_RELAY_SOCKETS", "split")])
                .unwrap()
                .relay_sockets,
            RelaySockets::Split
        );
        assert!(matches!(
            resolve(&[("LEPIC_RELAY_SOCKETS", "each")]),
            Err(SettingsError::InvalidValue {
                key: "relay_sockets",
                ..
            })
        ));
    }

    #[test]
    fn the_node_goes_through_tor_only_when_asked_and_a_tor_is_named() {
        let tor = ("LEPIC_EPICBOX_TOR_SOCKS", "127.0.0.1:9050");
        assert!(!resolve(&[tor]).unwrap().node_over_tor);
        assert!(
            resolve(&[tor, ("LEPIC_NODE_OVER_TOR", "true")])
                .unwrap()
                .node_over_tor
        );
        assert!(
            !resolve(&[tor, ("LEPIC_NODE_OVER_TOR", "false")])
                .unwrap()
                .node_over_tor
        );
        for vars in [
            &[("LEPIC_NODE_OVER_TOR", "true")][..],
            &[tor, ("LEPIC_NODE_OVER_TOR", "yes")][..],
        ] {
            assert!(
                matches!(
                    resolve(vars),
                    Err(SettingsError::InvalidValue {
                        key: "node_over_tor",
                        ..
                    })
                ),
                "{vars:?}"
            );
        }
    }

    #[test]
    fn the_refusal_switches_are_off_unless_set_and_independent() {
        let none = resolve(&[]).unwrap();
        assert!(!none.refuse_unsolicited_payments);
        assert!(!none.refuse_unsolicited_invoices);
        let payments = resolve(&[("LEPIC_REFUSE_UNSOLICITED_PAYMENTS", "true")]).unwrap();
        assert!(payments.refuse_unsolicited_payments);
        assert!(!payments.refuse_unsolicited_invoices);
        let invoices = resolve(&[("LEPIC_REFUSE_UNSOLICITED_INVOICES", "true")]).unwrap();
        assert!(!invoices.refuse_unsolicited_payments);
        assert!(invoices.refuse_unsolicited_invoices);
        assert!(matches!(
            resolve(&[("LEPIC_REFUSE_UNSOLICITED_PAYMENTS", "yes")]),
            Err(SettingsError::InvalidValue {
                key: "refuse_unsolicited_payments",
                ..
            })
        ));
    }

    #[test]
    fn a_retired_key_loads_from_the_environment_or_a_config_file_and_is_named() {
        assert!(resolve(&[]).unwrap().retired.is_empty());
        let from_env = resolve(&[("LEPIC_NATIVE_DIRECT", "1")]).unwrap();
        assert_eq!(from_env.retired, ["native_direct"]);
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "native_direct = true\n").unwrap();
        let from_file = resolve(&[(CONFIG_ENV, config.to_str().unwrap())]).unwrap();
        assert_eq!(from_file.retired, ["native_direct"]);
    }

    #[test]
    fn epic1_at_the_listeners_is_off_unless_set() {
        let none = resolve(&[]).unwrap();
        assert!(!none.epic1_web_listener);
        assert!(!none.epic1_onion_listener);
        let web = resolve(&[("LEPIC_EPIC1_WEB_LISTENER", "true")]).unwrap();
        assert!(web.epic1_web_listener);
        assert!(!web.epic1_onion_listener);
        let onion = resolve(&[("LEPIC_EPIC1_ONION_LISTENER", "true")]).unwrap();
        assert!(!onion.epic1_web_listener);
        assert!(onion.epic1_onion_listener);
        assert!(matches!(
            resolve(&[("LEPIC_EPIC1_ONION_LISTENER", "on")]),
            Err(SettingsError::InvalidValue {
                key: "epic1_onion_listener",
                ..
            })
        ));
    }

    #[test]
    fn a_relay_tor_that_is_remote_ambiguous_or_incomplete_is_refused() {
        for vars in [
            &[("LEPIC_EPICBOX_TOR_SOCKS", "192.0.2.1:9050")][..],
            &[("LEPIC_EPICBOX_TOR_SOCKS", "localhost:9050")][..],
            &[
                ("LEPIC_EPICBOX_TOR_SOCKS", "127.0.0.1:9050"),
                ("LEPIC_EPICBOX_TOR_BINARY", "/opt/tor/tor"),
            ][..],
            &[("LEPIC_EPICBOX_TOR_LIB_DIR", "/opt/tor")][..],
        ] {
            assert!(
                matches!(resolve(vars), Err(SettingsError::InvalidValue { .. })),
                "{vars:?}"
            );
        }
    }
}
