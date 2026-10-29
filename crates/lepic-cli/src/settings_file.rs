// SPDX-License-Identifier: Apache-2.0
//! The settings file, `settings.toml`: the servers the CLI talks to, in the layout of the Epic
//! Cash wallet app's file of that name. The library crates hold no address of their own; every
//! one the CLI uses comes from here, or from a flag, variable or config key that overrides it.
//!
//! Only `[epicbox] default`, `[pairing] servers` and `[[tor.onions]]` are read. Every other key
//! and section is ignored, so the app's file, which has many more, works unchanged.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use lepic_epicbox::tunnel::OnionRoute;
use lepic_epicbox::{Domain, RelayEndpoint};
use serde::Deserialize;

use crate::settings::SettingsError;

/// The file the CLI writes when it finds none. Its servers are the app's shipped defaults.
pub const SHIPPED_SETTINGS: &str = include_str!("../settings.toml");

pub(crate) const SETTINGS_FILE: &str = "settings.toml";

/// The app's file has every server and link of the app; this leaves room for many more.
pub const MAX_SETTINGS_LEN: u64 = 256 * 1024;

/// As many onion routes as the FFI takes.
pub const MAX_ONION_ROUTES: usize = 256;

/// The servers a settings file names, checked.
#[derive(Debug, Clone)]
pub struct Servers {
    /// The relay of a new wallet, and of an address written without one.
    pub default_epicbox_domain: Domain,
    /// Where pairing words are posted and looked for; empty when the file names none.
    pub meeting_relays: Vec<RelayEndpoint>,
    /// The hosts known to be TLS onion services.
    pub onion_routes: Vec<OnionRoute>,
}

#[derive(Deserialize)]
struct File {
    epicbox: Option<EpicboxTable>,
    #[serde(default)]
    pairing: PairingTable,
    #[serde(default)]
    tor: TorTable,
}

#[derive(Deserialize)]
struct EpicboxTable {
    default: Option<String>,
}

#[derive(Default, Deserialize)]
struct PairingTable {
    #[serde(default)]
    servers: Vec<String>,
}

#[derive(Default, Deserialize)]
struct TorTable {
    #[serde(default)]
    onions: Vec<OnionTable>,
}

#[derive(Deserialize)]
struct OnionTable {
    host: String,
    port: u16,
    onion: String,
    onion_port: u16,
    tls: bool,
}

/// The servers of the settings file at `path`. Without `explicit`, a missing file is first
/// written from [`SHIPPED_SETTINGS`]; when that fails too, as without a home directory, the
/// shipped servers are used as they are.
pub(crate) fn load(path: Option<&Path>, explicit: bool) -> Result<Servers, SettingsError> {
    let Some(path) = path else {
        return parse(Path::new(SETTINGS_FILE), SHIPPED_SETTINGS);
    };
    if !explicit && !path.exists() {
        // A home that cannot be written to still runs, on the same servers it would have
        // written.
        let _ = write_shipped(path);
        if !path.is_file() {
            return parse(path, SHIPPED_SETTINGS);
        }
    }
    parse(path, &read_bounded(path)?)
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

/// The servers `text` names. `path` is only for errors.
pub fn parse(path: &Path, text: &str) -> Result<Servers, SettingsError> {
    let file: File = toml::from_str(text).map_err(|source| SettingsError::SettingsSyntax {
        path: path.to_owned(),
        source: Box::new(source),
    })?;
    let invalid = |key| SettingsError::SettingsValue {
        path: path.to_owned(),
        key,
    };
    let default_epicbox_domain = file
        .epicbox
        .and_then(|epicbox| epicbox.default)
        .ok_or_else(|| invalid("epicbox.default"))?;
    let default_epicbox_domain =
        Domain::parse(&default_epicbox_domain).map_err(|_| invalid("epicbox.default"))?;
    let meeting_relays = if file.pairing.servers.is_empty() {
        Vec::new()
    } else {
        lepic_wallet_contacts::meeting_relays(&file.pairing.servers)
            .map_err(|_| invalid("pairing.servers"))?
    };
    if file.tor.onions.len() > MAX_ONION_ROUTES {
        return Err(invalid("tor.onions"));
    }
    let onion_routes = file
        .tor
        .onions
        .into_iter()
        .filter(|route| route.tls)
        .map(|route| onion_route(&route).ok_or_else(|| invalid("tor.onions")))
        .collect::<Result<_, _>>()?;
    Ok(Servers {
        default_epicbox_domain,
        meeting_relays,
        onion_routes,
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

/// `~/.lepic/settings.toml` under `home`.
pub(crate) fn default_path(home: &Path) -> PathBuf {
    home.join(crate::settings::HOME_DIR).join(SETTINGS_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion() -> String {
        lepic_tor::OnionAddress::from_public_key(&[3; 32]).host()
    }

    fn parse_text(text: &str) -> Result<Servers, SettingsError> {
        parse(Path::new("settings.toml"), text)
    }

    #[test]
    fn the_shipped_file_parses() {
        let servers = parse_text(SHIPPED_SETTINGS).unwrap();
        assert_eq!(servers.meeting_relays.len(), 3);
        assert_eq!(servers.onion_routes.len(), 2);
    }

    #[test]
    fn the_read_keys_are_taken_and_every_other_one_ignored() {
        let text = format!(
            r#"
version = 7
[node]
default = "https://node.example.invalid"
[epicbox]
default = "relay.example.invalid"
removed = []
[[epicbox.servers]]
host = "other.example.invalid"
[pairing]
servers = ["Meet.Example.Invalid", "meet.example.invalid:443", "two.example.invalid:8443"]
[tor]
onion_only_domains = ["example.invalid"]
[[tor.onions]]
host = "relay.example.invalid"
port = 443
onion = "{onion}"
onion_port = 443
tls = true
[[tor.onions]]
host = "plain.example.invalid"
port = 80
onion = "{onion}"
onion_port = 80
tls = false
[links]
website = "https://site.example.invalid"
"#,
            onion = onion()
        );
        let servers = parse_text(&text).unwrap();
        assert_eq!(
            servers.default_epicbox_domain.as_str(),
            "relay.example.invalid"
        );
        let meeting: Vec<String> = servers
            .meeting_relays
            .iter()
            .map(lepic_wallet_contacts::meeting_host)
            .collect();
        assert_eq!(
            meeting,
            ["meet.example.invalid", "two.example.invalid:8443"]
        );
        assert_eq!(
            servers.onion_routes,
            [OnionRoute {
                domain: Domain::parse("relay.example.invalid").unwrap(),
                port: 443,
                onion: onion(),
                onion_port: 443,
            }],
            "a route without tls is left out"
        );
    }

    #[test]
    fn no_pairing_servers_and_no_onions_are_allowed() {
        let servers = parse_text("[epicbox]\ndefault = \"relay.example.invalid\"\n").unwrap();
        assert!(servers.meeting_relays.is_empty());
        assert!(servers.onion_routes.is_empty());
    }

    #[test]
    fn a_file_without_a_default_relay_or_with_a_bad_value_is_refused() {
        let route = |host: &str, onion: &str, port: u16| {
            format!(
                "[epicbox]\ndefault = \"relay.example.invalid\"\n[[tor.onions]]\nhost = \"{host}\"\n\
                 port = {port}\nonion = \"{onion}\"\nonion_port = 443\ntls = true\n"
            )
        };
        let cases = [
            ("[pairing]\nservers = []\n".to_owned(), "epicbox.default"),
            ("[epicbox]\nremoved = []\n".to_owned(), "epicbox.default"),
            ("[epicbox]\ndefault = \"not a host\"\n".to_owned(), "epicbox.default"),
            (
                "[epicbox]\ndefault = \"relay.example.invalid\"\n[pairing]\nservers = [\"a.example.invalid:0\"]\n"
                    .to_owned(),
                "pairing.servers",
            ),
            (route("bad host!", &onion(), 443), "tor.onions"),
            (route("relay.example.invalid", "notanonion", 443), "tor.onions"),
            (route("relay.example.invalid", &onion(), 0), "tor.onions"),
        ];
        for (text, key) in cases {
            assert!(
                matches!(
                    parse_text(&text),
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
            parse_text("[epicbox]\ndefault = 7\n"),
            Err(SettingsError::SettingsSyntax { .. })
        ));
    }

    #[test]
    fn a_missing_default_file_is_written_once_and_an_explicit_one_must_exist() {
        let home = tempfile::tempdir().unwrap();
        let path = default_path(home.path());
        load(Some(&path), false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SHIPPED_SETTINGS);

        std::fs::write(&path, "[epicbox]\ndefault = \"relay.example.invalid\"\n").unwrap();
        let servers = load(Some(&path), false).unwrap();
        assert_eq!(
            servers.default_epicbox_domain.as_str(),
            "relay.example.invalid",
            "the user's file is read, not replaced"
        );

        let absent = home.path().join("absent.toml");
        assert!(matches!(
            load(Some(&absent), true),
            Err(SettingsError::SettingsRead { .. })
        ));
        assert!(!absent.exists());
    }
}
