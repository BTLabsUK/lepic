// SPDX-License-Identifier: Apache-2.0
//! The user's settings file, `settings.toml`: which node and Epicbox servers the CLI uses, in
//! the layout of the Epic Cash wallet app's file of that name. The library crates hold no
//! address of their own; every one the CLI uses comes from here, from the built-in
//! configuration ([`crate::app_config`]), or from a flag, variable or config key that
//! overrides it.
//!
//! Only `[node] servers`, `[epicbox] servers` and `[api] owner_tls` are read. Every other key and
//! section is ignored, so the app's file, which has many more, works unchanged.

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use lepic_epicbox::tunnel::OnionRoute;
use lepic_epicbox::{Domain, RelayEndpoint};
use lepic_wallet::NodeEndpoint;
use serde::Deserialize;

use crate::app_config::AppConfig;
use crate::settings::SettingsError;

/// The file the CLI writes when it finds none. Its servers are the app's shipped defaults.
pub const SHIPPED_SETTINGS: &str = include_str!("../settings.default.toml");

pub(crate) const SETTINGS_FILE: &str = "settings.toml";

/// The app's file has every server and link of the app; this leaves room for many more.
pub const MAX_SETTINGS_LEN: u64 = 256 * 1024;

/// The servers of the settings file and the built-in configuration, checked.
#[derive(Debug, Clone)]
pub struct Servers {
    /// The relay of an address written without one.
    pub default_epicbox_domain: Domain,
    /// The node in use on mainnet: the first of `[node] servers`, `None` when it lists none.
    pub node: Option<NodeEndpoint>,
    /// The relay in use: the first of `[epicbox] servers`, `None` when it lists none.
    pub epicbox: Option<RelayEndpoint>,
    /// Where pairing words are posted and looked for: the first few of `[epicbox] servers`.
    pub meeting_relays: Vec<RelayEndpoint>,
    /// The hosts known to be TLS onion services.
    pub onion_routes: Vec<OnionRoute>,
    /// Where `serve --owner-tls` listens: `[api] owner_tls`, `None` when it is not set.
    pub owner_tls: Option<SocketAddr>,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    node: ServerList,
    #[serde(default)]
    epicbox: ServerList,
    #[serde(default)]
    api: ApiTable,
}

#[derive(Default, Deserialize)]
struct ApiTable {
    owner_tls: Option<String>,
}

#[derive(Default, Deserialize)]
struct ServerList {
    #[serde(default)]
    servers: Vec<String>,
}

/// The servers of the settings file at `path`, with those of `config`. Without `explicit`, a
/// missing file is first written from [`SHIPPED_SETTINGS`]; when that fails too, as without a
/// home directory, the shipped servers are used as they are.
pub(crate) fn load(
    path: Option<&Path>,
    explicit: bool,
    config: &AppConfig,
) -> Result<Servers, SettingsError> {
    let Some(path) = path else {
        return parse(Path::new(SETTINGS_FILE), SHIPPED_SETTINGS, config);
    };
    if !explicit && !path.exists() {
        // A home that cannot be written to still runs, on the same servers it would have
        // written.
        let _ = write_shipped(path);
        if !path.is_file() {
            return parse(path, SHIPPED_SETTINGS, config);
        }
    }
    parse(path, &read_bounded(path)?, config)
}

fn write_shipped(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, SHIPPED_SETTINGS.as_bytes()))
}

fn read_bounded(path: &Path) -> Result<String, SettingsError> {
    let read_error = |source| SettingsError::SettingsRead {
        path: path.to_owned(),
        source,
    };
    let file = std::fs::File::open(path).map_err(read_error)?;
    let mut text = String::new();
    file.take(MAX_SETTINGS_LEN.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(read_error)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_SETTINGS_LEN {
        return Err(SettingsError::SettingsTooLarge {
            path: path.to_owned(),
        });
    }
    Ok(text)
}

/// The servers `text` names, with those of `config`. `path` is only for errors.
pub fn parse(path: &Path, text: &str, config: &AppConfig) -> Result<Servers, SettingsError> {
    let file: File = toml::from_str(text).map_err(|source| SettingsError::SettingsSyntax {
        path: path.to_owned(),
        source: Box::new(source),
    })?;
    let invalid = |key| SettingsError::SettingsValue {
        path: path.to_owned(),
        key,
    };
    let node = match file.node.servers.first() {
        Some(url) => Some(NodeEndpoint::parse(url).map_err(|_| invalid("node.servers"))?),
        None => None,
    };
    let relays = if file.epicbox.servers.is_empty() {
        Vec::new()
    } else {
        lepic_wallet_contacts::meeting_relays(&file.epicbox.servers)
            .map_err(|_| invalid("epicbox.servers"))?
    };
    let owner_tls = match &file.api.owner_tls {
        Some(address) => Some(address.parse().map_err(|_| invalid("api.owner_tls"))?),
        None => None,
    };
    Ok(Servers {
        default_epicbox_domain: config.address_default.clone(),
        node,
        epicbox: relays.first().cloned(),
        meeting_relays: relays.into_iter().take(config.pairing_servers).collect(),
        onion_routes: config.onion_routes.clone(),
        owner_tls,
    })
}

/// `~/.lepic/settings.toml` under `home`.
pub(crate) fn default_path(home: &Path) -> PathBuf {
    home.join(crate::settings::HOME_DIR).join(SETTINGS_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AppConfig {
        AppConfig::built_in().unwrap()
    }

    fn parse_text(text: &str) -> Result<Servers, SettingsError> {
        parse(Path::new("settings.toml"), text, &config())
    }

    fn hosts(relays: &[RelayEndpoint]) -> Vec<String> {
        relays
            .iter()
            .map(lepic_wallet_contacts::meeting_host)
            .collect()
    }

    #[test]
    fn the_shipped_file_parses() {
        let servers = parse_text(SHIPPED_SETTINGS).unwrap();
        assert_eq!(
            servers.node.as_ref().map(NodeEndpoint::as_str),
            Some("http://127.0.0.1:3413")
        );
        assert_eq!(
            servers.epicbox.map(|relay| relay.domain().to_string()),
            Some("epicbox.btlabs.uk".to_owned())
        );
        assert_eq!(servers.meeting_relays.len(), 3);
        assert_eq!(servers.onion_routes.len(), 2);
        assert_eq!(servers.owner_tls, None);
        assert_eq!(
            servers.default_epicbox_domain.as_str(),
            "epicbox.epiccash.com"
        );
    }

    #[test]
    fn the_first_servers_are_used_and_every_other_key_ignored() {
        let text = r#"
version = 7
[node]
servers = ["https://node.example.invalid", "https://other.example.invalid"]
use = "https://ignored.example.invalid"
[epicbox]
servers = ["Relay.Example.Invalid", "relay.example.invalid:443", "two.example.invalid:8443", "three.example.invalid", "four.example.invalid"]
removed = []
[online]
price = "https://price.example.invalid"
[links]
website = "https://site.example.invalid"
"#;
        let servers = parse_text(text).unwrap();
        assert_eq!(
            servers.node.as_ref().map(NodeEndpoint::as_str),
            Some("https://node.example.invalid")
        );
        assert_eq!(
            servers.epicbox.map(|relay| relay.domain().to_string()),
            Some("relay.example.invalid".to_owned())
        );
        assert_eq!(
            hosts(&servers.meeting_relays),
            [
                "relay.example.invalid",
                "two.example.invalid:8443",
                "three.example.invalid"
            ],
            "pairing takes the first servers, each once"
        );
    }

    #[test]
    fn no_servers_are_allowed() {
        let servers = parse_text("").unwrap();
        assert!(servers.node.is_none());
        assert!(servers.epicbox.is_none());
        assert!(servers.meeting_relays.is_empty());
    }

    #[test]
    fn a_bad_server_is_refused() {
        let cases = [
            ("[node]\nservers = [\"not a url\"]\n", "node.servers"),
            (
                "[epicbox]\nservers = [\"a.example.invalid:0\"]\n",
                "epicbox.servers",
            ),
            ("[epicbox]\nservers = [\"bad host!\"]\n", "epicbox.servers"),
            ("[api]\nowner_tls = \"no address\"\n", "api.owner_tls"),
        ];
        for (text, key) in cases {
            assert!(
                matches!(
                    parse_text(text),
                    Err(SettingsError::SettingsValue { key: found, .. }) if found == key
                ),
                "{text}"
            );
        }
        assert!(matches!(
            parse_text("[epicbox\n"),
            Err(SettingsError::SettingsSyntax { .. })
        ));
        assert!(matches!(
            parse_text("[epicbox]\nservers = 7\n"),
            Err(SettingsError::SettingsSyntax { .. })
        ));
    }

    #[test]
    fn a_missing_default_file_is_written_once_and_an_explicit_one_must_exist() {
        let home = tempfile::tempdir().unwrap();
        let path = default_path(home.path());
        load(Some(&path), false, &config()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SHIPPED_SETTINGS);

        std::fs::write(&path, "[epicbox]\nservers = [\"relay.example.invalid\"]\n").unwrap();
        let servers = load(Some(&path), false, &config()).unwrap();
        assert_eq!(
            servers.epicbox.map(|relay| relay.domain().to_string()),
            Some("relay.example.invalid".to_owned()),
            "the user's file is read, not replaced"
        );

        let absent = home.path().join("absent.toml");
        assert!(matches!(
            load(Some(&absent), true, &config()),
            Err(SettingsError::SettingsRead { .. })
        ));
        assert!(!absent.exists());
    }
}
