// SPDX-License-Identifier: Apache-2.0
//! Settings, resolved once per command: a flag, then its `LEPIC_*` variable, then the config
//! file, then the default.
//!
//! The config file is a flat list of `key = value` lines, a subset of TOML: values are bare
//! words or double-quoted strings, `#` starts a comment. Unknown and repeated keys are refused so
//! that a typo never silently falls back to a default.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read as _;
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
use crate::secret::PASSWORD_ENV;
use crate::settings_file::{self, Servers};

/// Config files are a few lines; anything larger is not one.
pub const MAX_CONFIG_LEN: u64 = 64 * 1024;

const CONFIG_FILE: &str = "config.toml";
pub(crate) const HOME_DIR: &str = ".lepic";

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
        "invoice_expiry_hours",
        "LEPIC_INVOICE_EXPIRY_HOURS",
        "hours an unpaid invoice is kept, 1 to 48",
    ),
    (
        "host_features",
        "LEPIC_HOST_FEATURES",
        "host feature bits the wallet's marker claims, by name, comma-separated: \
         device-forwarding, name-service",
    ),
    (
        "settings_file",
        "LEPIC_SETTINGS",
        "settings.toml with the servers: [node] servers, [epicbox] servers",
    ),
];

/// The variable a config file path comes from when `--config` is not given.
pub const CONFIG_ENV: &str = "LEPIC_CONFIG";

/// The process environment as the CLI sees it: captured once, so tests pass their own.
#[derive(Clone, Default)]
pub struct Env(BTreeMap<String, String>);

impl Env {
    pub fn new(vars: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(vars.into_iter().collect())
    }

    /// The `LEPIC_*` variables and the home directory of the running process. Variables that
    /// are not Unicode are left out.
    pub fn from_process() -> Self {
        Self::new(std::env::vars_os().filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            let wanted = key.starts_with("LEPIC_") || key == "HOME" || key == "USERPROFILE";
            wanted.then_some((key, value.into_string().ok()?))
        }))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
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
                let shown = if key == PASSWORD_ENV {
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
    #[error("{key} from {origin} is invalid")]
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
    /// How long an unpaid invoice is kept, on either side.
    pub invoice_expiry: InvoiceExpiry,
    /// The host bits the wallet's marker claims (ADR 0034), only bits of
    /// `features::HOST_FEATURES`; none unless `host_features` names them.
    pub host_features: u32,
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
                .unwrap_or(NetworkArg::Mainnet),
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

        let config = AppConfig::built_in()?;
        let servers = servers(args, env, &lookup, &config)?;
        let node = node(&lookup, network, &servers, &config)?;
        let relay = relay(&lookup, &servers)?;
        let invoice_expiry = lookup
            .parse("invoice_expiry_hours", parse_expiry_hours)?
            .unwrap_or_default();
        let relay_tor = relay_tor(&lookup)?;
        let host_features = lookup
            .parse("host_features", parse_host_features)?
            .unwrap_or(0);
        let node_over_tor = lookup
            .parse("node_over_tor", |text| match text {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            })?
            .unwrap_or(false);
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
            relay_tor,
            node_over_tor,
            invoice_expiry,
            host_features,
        })
    }
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
                .map(|home| settings_file::default_path(&home))
                .as_deref(),
            false,
            config,
        ),
    }
}

/// `node_url`, else the first node of the settings file on mainnet and the built-in floonet node.
fn node(
    lookup: &Lookup<'_>,
    network: Network,
    servers: &Servers,
    config: &AppConfig,
) -> Result<NodeEndpoint, SettingsError> {
    if let Some(node) = lookup.parse("node_url", |text| NodeEndpoint::parse(text).ok())? {
        return Ok(node);
    }
    match network {
        Network::Mainnet => servers.node.clone().ok_or(SettingsError::InvalidValue {
            key: "node_url",
            origin: Origin::Default,
        }),
        Network::Floonet => Ok(config.floonet_node.clone()),
    }
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

/// The host bits a `host_features` value names. Each name is one bit of
/// `features::HOST_FEATURES`; an unknown name refuses the whole value. Empty names none.
fn parse_host_features(text: &str) -> Option<u32> {
    use lepic_epicbox::marker::features;
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
        if !SETTINGS.iter().any(|(name, _, _)| *name == key) {
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
            ("LEPIC_NETWORK".to_owned(), "floonet".to_owned()),
        ]);
        let shown = format!("{env:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(
            shown.contains("[redacted]") && shown.contains("floonet"),
            "{shown}"
        );
    }

    #[test]
    fn config_values_are_bare_words_or_quoted_strings() {
        assert_eq!(parse_value("floonet"), Some("floonet".to_owned()));
        assert_eq!(parse_value("floonet # comment"), Some("floonet".to_owned()));
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
        use lepic_epicbox::marker::features;
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
            lepic_epicbox::marker::features::NAME_SERVICE
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
