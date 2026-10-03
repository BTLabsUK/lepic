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
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cli::{GlobalArgs, LogFormatArg, NetworkArg, OutputArg};
use crate::secret::PASSWORD_ENV;

/// Config files are a few lines; anything larger is not one.
pub const MAX_CONFIG_LEN: u64 = 64 * 1024;

const CONFIG_FILE: &str = "config.toml";
const HOME_DIR: &str = ".lepic";

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
        "epicbox_relay",
        "LEPIC_EPICBOX_RELAY",
        "relay as wss://host[:port], or ws://host[:port] for a loopback host",
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
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
    pub relay: RelayEndpoint,
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

        let node = match lookup.parse("node_url", |text| NodeEndpoint::parse(text).ok())? {
            Some(node) => node,
            None => NodeEndpoint::parse(default_node_url(network)).map_err(|_| {
                SettingsError::InvalidValue {
                    key: "node_url",
                    origin: Origin::Default,
                }
            })?,
        };
        let relay = lookup
            .parse("epicbox_relay", parse_relay)?
            .unwrap_or_default();

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
            relay,
        })
    }
}

/// The ports `epic-wallet`'s default node configuration listens on.
fn default_node_url(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "http://127.0.0.1:3413",
        Network::Floonet => "http://127.0.0.1:13413",
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
}
