// SPDX-License-Identifier: Apache-2.0
//! The user's settings file, `settings.toml`: which node and Epicbox servers the CLI uses, in
//! the layout of the Epic Cash wallet app's file of that name. The library crates hold no
//! address of their own; every one the CLI uses comes from here, from the built-in
//! configuration ([`crate::app_config`]), or from a flag, variable or config key that
//! overrides it.
//!
//! Only `[node] servers`, `[epicbox] servers`, `[mailboxes] added` and `removed`, and
//! `[api] owner_tls` are read. Every other key and section is ignored, so the app's file, which
//! has many more, works unchanged. `lepic mailbox add` and `remove` write `[mailboxes] added`
//! and `removed` and leave every other line as it was.

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use lepic_epicbox::tunnel::OnionRoute;
use lepic_epicbox::{Domain, RelayEndpoint, Security};
use lepic_primitives::params::Network;
use lepic_wallet::NodeEndpoint;
use lepic_wallet_contacts::{MAX_MAILBOXES, MailboxList, MailboxListError, parse_mailbox};
use serde::Deserialize;
use thiserror::Error;

use crate::app_config::AppConfig;
use crate::settings::SettingsError;

/// The file the CLI writes when it finds none. Its servers are the app's shipped defaults.
pub const SHIPPED_SETTINGS: &str = include_str!("../settings.default.toml");

/// The same for floonet, the test chain.
pub const SHIPPED_SETTINGS_FLOONET: &str = include_str!("../settings.floonet.toml");

pub(crate) const SETTINGS_FILE: &str = "settings.toml";

/// The settings file of floonet, next to the mainnet one.
pub(crate) const SETTINGS_FILE_FLOONET: &str = "settings-floonet.toml";

/// The file the CLI writes on `network` when it finds none.
pub(crate) const fn shipped_settings(network: Network) -> &'static str {
    match network {
        Network::Mainnet => SHIPPED_SETTINGS,
        Network::Floonet => SHIPPED_SETTINGS_FLOONET,
    }
}

const fn settings_file_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => SETTINGS_FILE,
        Network::Floonet => SETTINGS_FILE_FLOONET,
    }
}

/// The app's file has every server and link of the app; this leaves room for many more.
pub const MAX_SETTINGS_LEN: u64 = 256 * 1024;

/// The servers of the settings file and the built-in configuration, checked.
#[derive(Debug, Clone)]
pub struct Servers {
    /// The relay of an address written without one.
    pub default_epicbox_domain: Domain,
    /// The node in use on mainnet: the first of `[node] servers`, `None` when it lists none.
    pub node: Option<NodeEndpoint>,
    /// Every node known: those of `[node] servers`, then the public ones of the built-in
    /// configuration, each once.
    pub nodes: Vec<NodeEndpoint>,
    /// The relay of the Epicbox address: the first of `[epicbox] servers`, `None` when it lists
    /// none.
    pub epicbox: Option<RelayEndpoint>,
    /// The mailboxes of native mail: the built-in shipped list with `[mailboxes] added` and
    /// `removed`, or with `local_mailbox` the relay alone.
    pub mailboxes: Mailboxes,
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
    mailboxes: MailboxesTable,
    #[serde(default)]
    api: ApiTable,
}

/// The user's changes to the shipped mailbox list; the shipped list itself is never stored.
#[derive(Default, Deserialize)]
struct MailboxesTable {
    #[serde(default)]
    added: Vec<String>,
    #[serde(default)]
    removed: Vec<String>,
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
/// missing file is first written from [`SHIPPED_SETTINGS`] ([`SHIPPED_SETTINGS_FLOONET`] on
/// floonet); when that fails too, as without a
/// home directory, the shipped servers are used as they are.
pub(crate) fn load(
    path: Option<&Path>,
    explicit: bool,
    config: &AppConfig,
) -> Result<Servers, SettingsError> {
    let shipped = shipped_settings(config.network);
    let Some(path) = path else {
        return parse(
            Path::new(settings_file_name(config.network)),
            shipped,
            config,
        );
    };
    let text = if !explicit && !path.exists() {
        // A home that cannot be written to still runs, on the same servers it would have
        // written.
        let _ = write_shipped(path, shipped);
        if path.is_file() {
            read_bounded(path)?
        } else {
            shipped.to_owned()
        }
    } else {
        read_bounded(path)?
    };
    let mut servers = parse(path, &text, config)?;
    servers.mailboxes = Mailboxes::new(
        servers.mailboxes.current(),
        config.shipped_mailboxes.clone(),
        Some(path.to_owned()),
        shipped,
    );
    Ok(servers)
}

fn write_shipped(path: &Path, shipped: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, shipped.as_bytes()))
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
    let listed = file
        .node
        .servers
        .iter()
        .filter_map(|url| NodeEndpoint::parse(url).ok());
    let mut nodes: Vec<NodeEndpoint> = Vec::new();
    for known in listed.chain(config.public_nodes.iter().cloned()) {
        if !nodes.iter().any(|seen| seen.as_str() == known.as_str()) {
            nodes.push(known);
        }
    }
    let relays = file
        .epicbox
        .servers
        .iter()
        .map(|host| parse_server(host).ok_or_else(|| invalid("epicbox.servers")))
        .collect::<Result<Vec<_>, _>>()?;
    let mailboxes = mailboxes(&file.mailboxes, &config.shipped_mailboxes).map_err(invalid)?;
    let owner_tls = match &file.api.owner_tls {
        Some(address) => Some(address.parse().map_err(|_| invalid("api.owner_tls"))?),
        None => None,
    };
    Ok(Servers {
        default_epicbox_domain: config.address_default.clone(),
        node,
        nodes,
        epicbox: relays.into_iter().next(),
        mailboxes: Mailboxes::new(
            mailboxes,
            config.shipped_mailboxes.clone(),
            None,
            shipped_settings(config.network),
        ),
        onion_routes: config.onion_routes.clone(),
        owner_tls,
    })
}

/// `host` or `host:port` of an Epicbox server, over TLS.
fn parse_server(host: &str) -> Option<RelayEndpoint> {
    let host = host.trim().to_ascii_lowercase();
    let (domain, port) = match host.rsplit_once(':') {
        Some((domain, port)) => (
            domain,
            Some(port.parse::<u16>().ok().filter(|port| *port != 0)?),
        ),
        None => (host.as_str(), None),
    };
    Some(RelayEndpoint::new(
        Domain::parse(domain).ok()?,
        port,
        Security::Tls,
    ))
}

/// The `shipped` mailboxes with the user's `table`, or the key that is wrong: an entry that is
/// not a public name, more than [`MAX_MAILBOXES`] added, or a list left empty.
fn mailboxes(
    table: &MailboxesTable,
    shipped: &[RelayEndpoint],
) -> Result<MailboxList, &'static str> {
    let parse = |hosts: &[String], key| {
        if hosts.len() > MAX_MAILBOXES {
            return Err(key);
        }
        hosts
            .iter()
            .map(|host| parse_mailbox(host).map_err(|_| key))
            .collect::<Result<Vec<_>, _>>()
    };
    let added = parse(&table.added, "mailboxes.added")?;
    let removed = parse(&table.removed, "mailboxes.removed")?;
    MailboxList::new(shipped.to_vec(), added, removed).map_err(|_| "mailboxes.removed")
}

/// Why `lepic mailbox add` or `remove` changed nothing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MailboxChangeError {
    #[error(transparent)]
    List(#[from] MailboxListError),
    #[error("there is no settings file to keep the mailbox list in: no home directory is known")]
    NoFile,
    #[error("the mailbox list is fixed by local_mailbox: it is the mailbox epicbox_relay names")]
    Local,
    #[error(transparent)]
    Settings(#[from] SettingsError),
    /// The file sets the mailboxes in a form this writer does not edit, such as a dotted key or
    /// an inline table.
    #[error(
        "settings file {} sets [mailboxes] in a form lepic does not edit: change it by hand",
        path.display()
    )]
    Form { path: PathBuf },
    #[error("could not write settings file {}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// The mailbox list in use, which every part of the process reads, and the settings file its
/// changes are kept in. A change shows at once to every clone, and so to the running sessions of
/// `lepic serve`, whose next tick claims the new list.
#[derive(Clone)]
pub struct Mailboxes {
    shared: Arc<SharedMailboxes>,
}

struct SharedMailboxes {
    list: Mutex<MailboxList>,
    shipped: Vec<RelayEndpoint>,
    file: Option<PathBuf>,
    /// The text a missing file is first written from.
    shipped_file: &'static str,
    /// Set by `local_mailbox`: the list is the relay alone and takes no change.
    local: bool,
    /// The legacy relay of an upgraded wallet, listed as an added mailbox though the file does
    /// not store it, until the user removes it or the file names it.
    carried: Option<RelayEndpoint>,
    changed: tokio::sync::Notify,
}

impl std::fmt::Debug for Mailboxes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailboxes")
            .field("list", &self.current())
            .field("file", &self.shared.file)
            .finish_non_exhaustive()
    }
}

impl Mailboxes {
    fn new(
        list: MailboxList,
        shipped: Vec<RelayEndpoint>,
        file: Option<PathBuf>,
        shipped_file: &'static str,
    ) -> Self {
        Self {
            shared: Arc::new(SharedMailboxes {
                list: Mutex::new(list),
                shipped,
                file,
                shipped_file,
                local: false,
                carried: None,
                changed: tokio::sync::Notify::new(),
            }),
        }
    }

    /// `relay` as the shipped list and the whole list, for `local_mailbox`. Fails with the key
    /// of the settings file when it adds or removes a mailbox.
    pub(crate) fn local(&self, relay: &RelayEndpoint) -> Result<Self, SettingsError> {
        let stored = self.current();
        let set = if !stored.added().is_empty() {
            Some("mailboxes.added")
        } else if !stored.removed().is_empty() {
            Some("mailboxes.removed")
        } else {
            None
        };
        let file = self.shared.file.clone();
        let invalid = |key| SettingsError::SettingsValue {
            path: file.clone().unwrap_or_else(|| PathBuf::from(SETTINGS_FILE)),
            key,
        };
        if let Some(key) = set {
            return Err(invalid(key));
        }
        let shipped = vec![relay.clone()];
        let list =
            MailboxList::shipped_only(shipped.clone()).map_err(|_| invalid("local_mailbox"))?;
        Ok(Self {
            shared: Arc::new(SharedMailboxes {
                list: Mutex::new(list),
                shipped,
                file,
                shipped_file: self.shared.shipped_file,
                local: true,
                carried: None,
                changed: tokio::sync::Notify::new(),
            }),
        })
    }

    /// The list with `relay`, the relay of the legacy Epicbox address, carried into it as an
    /// added mailbox, so a wallet upgraded from a release that read its mail there keeps
    /// reading it there. Nothing is carried when `relay` is not a public name over TLS, is
    /// listed already, was removed by the user, or the list is full. The settings file is not
    /// written until the list is changed: then the carried mailbox is stored as added, or as
    /// removed when the change removed it.
    #[must_use]
    pub(crate) fn carrying(&self, relay: &RelayEndpoint) -> Self {
        let list = carried_into(&self.current(), relay);
        Self {
            shared: Arc::new(SharedMailboxes {
                list: Mutex::new(list),
                shipped: self.shared.shipped.clone(),
                file: self.shared.file.clone(),
                shipped_file: self.shared.shipped_file,
                local: self.shared.local,
                carried: Some(relay.clone()),
                changed: tokio::sync::Notify::new(),
            }),
        }
    }

    /// Refuses a change to a list `local_mailbox` fixed.
    pub(crate) fn editable(&self) -> Result<(), MailboxChangeError> {
        if self.shared.local {
            return Err(MailboxChangeError::Local);
        }
        Ok(())
    }

    /// The list as it is now.
    pub fn current(&self) -> MailboxList {
        self.shared
            .list
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Adds `endpoint` and keeps the change in the settings file. `Ok(false)` when it is
    /// already listed.
    pub(crate) fn add(&self, endpoint: RelayEndpoint) -> Result<bool, MailboxChangeError> {
        self.change(|list| list.add(endpoint))
    }

    /// Removes `endpoint` and keeps the change in the settings file. `Ok(false)` when it is not
    /// listed.
    pub(crate) fn remove(&self, endpoint: &RelayEndpoint) -> Result<bool, MailboxChangeError> {
        self.change(|list| list.remove(endpoint))
    }

    /// Returns once the list changed after the last return; a change made before the first call
    /// is seen too. Only `lepic serve`, which is Unix only, waits for it.
    #[cfg(unix)]
    pub(crate) async fn changed(&self) {
        self.shared.changed.notified().await;
    }

    /// Makes `edit` on the list the settings file holds now, which may differ from the one in
    /// use when the file was edited since, and writes the file when the list changed.
    fn change(
        &self,
        edit: impl FnOnce(&mut MailboxList) -> Result<bool, MailboxListError>,
    ) -> Result<bool, MailboxChangeError> {
        self.editable()?;
        let path = self
            .shared
            .file
            .as_deref()
            .ok_or(MailboxChangeError::NoFile)?;
        let mut in_use = self
            .shared
            .list
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let text = if path.is_file() {
            read_bounded(path)?
        } else {
            self.shared.shipped_file.to_owned()
        };
        let mut list = self.stored(path, &text)?;
        let carried_before = self.carried_listed(&list);
        let changed = edit(&mut list)?;
        if carried_before && !self.carried_listed(&list) {
            // The user removed the mailbox carried from the old settings: keep it removed.
            if let Some(carried) = &self.shared.carried {
                let mut removed = list.removed().to_vec();
                removed.push(carried.clone());
                list = MailboxList::new(list.shipped().to_vec(), list.added().to_vec(), removed)?;
            }
        }
        if changed {
            let edited = with_mailboxes(&text, &hosts_of(list.added()), &hosts_of(list.removed()));
            let kept = self.stored(path, &edited).ok();
            if !same_but_mailboxes(&text, &edited)
                || kept.as_ref().map(|kept| hosts_of(kept.added())) != Some(hosts_of(list.added()))
                || kept.as_ref().map(|kept| hosts_of(kept.removed()))
                    != Some(hosts_of(list.removed()))
            {
                return Err(MailboxChangeError::Form {
                    path: path.to_owned(),
                });
            }
            let write_error = |source| MailboxChangeError::Write {
                path: path.to_owned(),
                source,
            };
            if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(write_error)?;
            }
            lepic_store::file::write_owner_only_atomic(path, edited.as_bytes())
                .map_err(write_error)?;
        }
        *in_use = list;
        drop(in_use);
        if changed {
            self.shared.changed.notify_one();
        }
        Ok(changed)
    }

    /// Whether the carried mailbox, if there is one, is listed in `list`.
    fn carried_listed(&self, list: &MailboxList) -> bool {
        self.shared
            .carried
            .as_ref()
            .is_some_and(|carried| list.contains(carried))
    }

    /// The list of the settings file `text` at `path`, with the carried mailbox.
    fn stored(&self, path: &Path, text: &str) -> Result<MailboxList, SettingsError> {
        let file: File = toml::from_str(text).map_err(|source| SettingsError::SettingsSyntax {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        let list = mailboxes(&file.mailboxes, &self.shared.shipped).map_err(|key| {
            SettingsError::SettingsValue {
                path: path.to_owned(),
                key,
            }
        })?;
        Ok(match &self.shared.carried {
            Some(relay) => carried_into(&list, relay),
            None => list,
        })
    }
}

/// `list` with `relay` added, unless it cannot be a mailbox, is listed, or was removed.
fn carried_into(list: &MailboxList, relay: &RelayEndpoint) -> MailboxList {
    let removed = list
        .removed()
        .iter()
        .any(|gone| gone.domain() == relay.domain() && gone.port() == relay.port());
    let mut carried = list.clone();
    if removed || carried.add(relay.clone()).is_err() {
        return list.clone();
    }
    carried
}

fn hosts_of(endpoints: &[RelayEndpoint]) -> Vec<String> {
    endpoints
        .iter()
        .map(lepic_wallet_contacts::mailbox_host)
        .collect()
}

/// Whether `before` and `after` hold the same keys and values once `[mailboxes] added` and
/// `removed` are left out of both.
fn same_but_mailboxes(before: &str, after: &str) -> bool {
    let without = |text: &str| {
        let mut table: toml::Table = toml::from_str(text).ok()?;
        if let Some(toml::Value::Table(mailboxes)) = table.get_mut("mailboxes") {
            mailboxes.remove("added");
            mailboxes.remove("removed");
            if mailboxes.is_empty() {
                table.remove("mailboxes");
            }
        }
        Some(table)
    };
    match (without(before), without(after)) {
        (Some(before), Some(after)) => before == after,
        _ => false,
    }
}

/// `text` with `[mailboxes] added` and `removed` set to `added` and `removed`, each other line
/// as it was. The keys go after the last line of the section, which is added at the end when
/// the file has none. The caller checks the result: a form this does not follow, such as a
/// dotted key, gives a file that does not parse to the list.
fn with_mailboxes(text: &str, added: &[String], removed: &[String]) -> String {
    let array = |hosts: &[String]| {
        let quoted: Vec<String> = hosts.iter().map(|host| format!("\"{host}\"")).collect();
        format!("[{}]", quoted.join(", "))
    };
    let keys = format!("added = {}\nremoved = {}\n", array(added), array(removed));
    let mut out = String::with_capacity(text.len().saturating_add(keys.len()));
    let mut in_section = false;
    let mut found = false;
    let mut keys_at: Option<usize> = None;
    let mut depth: usize = 0;
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        if depth > 0 {
            depth = depth_after(line, depth);
            if !skipping {
                out.push_str(line);
                keys_at = keys_at.map(|_| out.len());
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if let Some(at) = keys_at.take() {
                insert_keys(&mut out, at, &keys);
            }
            in_section = header_name(trimmed) == Some("mailboxes");
            found |= in_section;
            out.push_str(line);
            if in_section {
                keys_at = Some(out.len());
            }
            skipping = false;
            continue;
        }
        depth = depth_after(line, 0);
        skipping = in_section && (is_key(trimmed, "added") || is_key(trimmed, "removed"));
        if skipping {
            continue;
        }
        out.push_str(line);
        if in_section && !trimmed.is_empty() {
            keys_at = Some(out.len());
        }
    }
    match keys_at {
        Some(at) => insert_keys(&mut out, at, &keys),
        None if !found => {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("\n[mailboxes]\n");
            out.push_str(&keys);
        }
        None => {}
    }
    out
}

fn insert_keys(out: &mut String, at: usize, keys: &str) {
    if at > 0 && !out[..at].ends_with('\n') {
        out.insert_str(at, &format!("\n{keys}"));
    } else {
        out.insert_str(at, keys);
    }
}

/// The name of the table a header line opens, `None` for an array of tables.
fn header_name(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('[')?;
    if inner.starts_with('[') {
        return None;
    }
    let (name, _) = inner.split_once(']')?;
    Some(name.trim())
}

/// Whether `line` sets the bare key `key`.
fn is_key(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// The brackets still open after `line`, of `depth` open before it: those outside strings and
/// before a comment.
fn depth_after(line: &str, mut depth: usize) -> usize {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in line.chars() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => break,
                '[' => depth = depth.saturating_add(1),
                ']' => depth = depth.saturating_sub(1),
                _ => {}
            },
        }
    }
    depth
}

/// `~/.lepic/settings.toml` under `home`; `~/.lepic/settings-floonet.toml` on floonet.
pub(crate) fn default_path(home: &Path, network: Network) -> PathBuf {
    home.join(crate::settings::HOME_DIR)
        .join(settings_file_name(network))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AppConfig {
        AppConfig::built_in(Network::Mainnet).unwrap()
    }

    fn parse_text(text: &str) -> Result<Servers, SettingsError> {
        parse(Path::new("settings.toml"), text, &config())
    }

    fn hosts(relays: &[RelayEndpoint]) -> Vec<String> {
        relays
            .iter()
            .map(lepic_wallet_contacts::mailbox_host)
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
        assert_eq!(
            servers
                .nodes
                .iter()
                .map(NodeEndpoint::as_str)
                .collect::<Vec<_>>(),
            [
                "http://127.0.0.1:3413",
                "https://node.btlabs.uk",
                "https://node.epiccash.com:3413",
                "https://node.epicnet.us:3413",
                "https://epic.stackwallet.com:3413"
            ]
        );
        assert_eq!(
            hosts(&servers.mailboxes.current().endpoints()),
            hosts(&config().shipped_mailboxes),
            "the shipped file changes nothing of the shipped list"
        );
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
            servers.mailboxes.current().endpoints(),
            config().shipped_mailboxes,
            "parsing the file alone does not make an Epicbox server a mailbox; resolving the settings carries the relay"
        );
    }

    #[test]
    fn no_servers_are_allowed() {
        let servers = parse_text("").unwrap();
        assert!(servers.node.is_none());
        assert!(servers.epicbox.is_none());
        assert_eq!(
            servers.mailboxes.current().endpoints(),
            config().shipped_mailboxes
        );
    }

    #[test]
    fn a_file_with_only_its_changes_follows_a_changed_shipped_list() {
        let file = "[mailboxes]\nadded = [\"Mine.Example.Org:8443\"]\nremoved = [\"epicbox.epiccash.com\"]\n";
        let with_shipped = |shipped: &str| {
            let text = crate::app_config::LEPIC_CONFIG.replace(
                "shipped = [\"epicbox.btlabs.uk\", \"epicbox.epiccash.com\", \"epicbox.epicnet.us\"]",
                &format!("shipped = {shipped}"),
            );
            let config = AppConfig::parse(&text, Network::Mainnet).unwrap();
            parse(Path::new("settings.toml"), file, &config).unwrap()
        };

        let today =
            with_shipped(r#"["epicbox.btlabs.uk", "epicbox.epiccash.com", "epicbox.epicnet.us"]"#);
        assert_eq!(
            hosts(&today.mailboxes.current().endpoints()),
            [
                "epicbox.btlabs.uk",
                "epicbox.epicnet.us",
                "mine.example.org:8443"
            ]
        );

        let next = with_shipped(
            r#"["epicbox.btlabs.uk", "epicbox.epicnet.us", "mailbox.example.org", "epicbox.epiccash.com"]"#,
        );
        assert_eq!(
            hosts(&next.mailboxes.current().endpoints()),
            [
                "epicbox.btlabs.uk",
                "epicbox.epicnet.us",
                "mailbox.example.org",
                "mine.example.org:8443"
            ],
            "a shipped mailbox the release adds is listed, one the user removed stays removed"
        );
    }

    #[test]
    fn a_bad_mailbox_change_is_refused() {
        let all_removed = "[mailboxes]\nremoved = [\"epicbox.btlabs.uk\", \"epicbox.epiccash.com\", \"epicbox.epicnet.us\"]\n";
        let cases = [
            ("[mailboxes]\nadded = [\"127.0.0.1\"]\n", "mailboxes.added"),
            ("[mailboxes]\nadded = [\"relay.lan\"]\n", "mailboxes.added"),
            (
                "[mailboxes]\nadded = [\"localhost:8443\"]\n",
                "mailboxes.added",
            ),
            (
                "[mailboxes]\nremoved = [\"bad host!\"]\n",
                "mailboxes.removed",
            ),
            (all_removed, "mailboxes.removed"),
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
        let replaced = format!("{all_removed}added = [\"mailbox.example.org\"]\n");
        assert_eq!(
            hosts(
                &parse_text(&replaced)
                    .unwrap()
                    .mailboxes
                    .current()
                    .endpoints()
            ),
            ["mailbox.example.org"],
            "every shipped mailbox may go when one is added"
        );
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

    fn floonet_config() -> AppConfig {
        AppConfig::built_in(Network::Floonet).unwrap()
    }

    #[test]
    fn the_shipped_floonet_file_parses_with_the_floonet_servers() {
        let servers = parse(
            Path::new(SETTINGS_FILE_FLOONET),
            SHIPPED_SETTINGS_FLOONET,
            &floonet_config(),
        )
        .unwrap();
        assert_eq!(
            servers.node.as_ref().map(NodeEndpoint::as_str),
            Some("https://floo-node.btlabs.uk")
        );
        assert_eq!(
            servers.epicbox.map(|relay| relay.domain().to_string()),
            Some("epicbox.btlabs.uk".to_owned())
        );
        assert_eq!(
            hosts(&servers.mailboxes.current().endpoints()),
            ["epicbox.btlabs.uk"]
        );
        assert_eq!(servers.default_epicbox_domain.as_str(), "epicbox.btlabs.uk");
    }

    #[test]
    fn each_network_has_its_own_settings_path() {
        let home = Path::new("/h");
        assert_eq!(
            default_path(home, Network::Mainnet),
            Path::new("/h/.lepic/settings.toml")
        );
        assert_eq!(
            default_path(home, Network::Floonet),
            Path::new("/h/.lepic/settings-floonet.toml")
        );
    }

    #[test]
    fn a_missing_floonet_file_is_written_from_the_floonet_copy() {
        let home = tempfile::tempdir().unwrap();
        let path = default_path(home.path(), Network::Floonet);
        load(Some(&path), false, &floonet_config()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            SHIPPED_SETTINGS_FLOONET
        );
        // An explicit file is never written.
        let named = home.path().join("named.toml");
        assert!(load(Some(&named), true, &floonet_config()).is_err());
        assert!(!named.exists());
    }

    #[test]
    fn a_mailbox_added_on_floonet_is_kept_in_the_floonet_file() {
        let home = tempfile::tempdir().unwrap();
        let path = default_path(home.path(), Network::Floonet);
        let servers = load(Some(&path), false, &floonet_config()).unwrap();
        let relay = parse_mailbox("mine.example.org").unwrap();
        servers.mailboxes.add(relay).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("mine.example.org"), "{text}");
        assert!(text.contains("floo-node.btlabs.uk"), "{text}");
        assert!(!home.path().join(".lepic/settings.toml").exists());
    }

    #[test]
    fn a_missing_default_file_is_written_once_and_an_explicit_one_must_exist() {
        let home = tempfile::tempdir().unwrap();
        let path = default_path(home.path(), Network::Mainnet);
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

    fn endpoint(host: &str) -> RelayEndpoint {
        lepic_wallet_contacts::parse_mailbox(host).unwrap()
    }

    #[test]
    fn a_mailbox_change_is_written_and_keeps_the_rest_of_the_file() {
        let home = tempfile::tempdir().unwrap();
        let path = default_path(home.path(), Network::Mainnet);
        let servers = load(Some(&path), false, &config()).unwrap();
        let seen = servers.mailboxes.clone();

        assert!(
            servers
                .mailboxes
                .add(endpoint("Mine.Example.Org:8443"))
                .unwrap()
        );
        assert!(
            servers
                .mailboxes
                .remove(&endpoint("epicbox.epiccash.com"))
                .unwrap()
        );
        assert!(
            !servers
                .mailboxes
                .add(endpoint("mine.example.org:8443"))
                .unwrap()
        );
        assert!(
            !servers
                .mailboxes
                .remove(&endpoint("gone.example.org"))
                .unwrap()
        );

        let written = std::fs::read_to_string(&path).unwrap();
        let expected = SHIPPED_SETTINGS.replace(
            "# removed = []\n",
            "# removed = []\nadded = [\"mine.example.org:8443\"]\nremoved = [\"epicbox.epiccash.com\"]\n",
        );
        assert_eq!(written, expected, "only the two keys are new");
        let listed = [
            "epicbox.btlabs.uk",
            "epicbox.epicnet.us",
            "mine.example.org:8443",
        ];
        assert_eq!(
            hosts(&seen.current().endpoints()),
            listed,
            "a clone, as serve's sessions hold, sees the change"
        );
        let reloaded = load(Some(&path), false, &config()).unwrap();
        assert_eq!(hosts(&reloaded.mailboxes.current().endpoints()), listed);

        assert!(
            servers
                .mailboxes
                .add(endpoint("epicbox.epiccash.com"))
                .unwrap()
        );
        assert!(
            servers
                .mailboxes
                .remove(&endpoint("mine.example.org:8443"))
                .unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            SHIPPED_SETTINGS.replace(
                "# removed = []\n",
                "# removed = []\nadded = []\nremoved = []\n"
            ),
            "a shipped mailbox added back leaves the removed list"
        );
    }

    #[test]
    fn a_mailbox_change_follows_the_file_as_it_is_now() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("settings.toml");
        std::fs::write(&path, "[node]\nservers = []\n").unwrap();
        let servers = load(Some(&path), true, &config()).unwrap();
        std::fs::write(
            &path,
            "[node]\nservers = []\n[mailboxes]\nadded = [\n  \"hand.example.org\",\n]\n[api]\n",
        )
        .unwrap();

        assert!(servers.mailboxes.add(endpoint("mine.example.org")).unwrap());

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[node]\nservers = []\n[mailboxes]\nadded = [\"hand.example.org\", \"mine.example.org\"]\nremoved = []\n[api]\n",
            "an entry made by hand since the file was read is kept"
        );
        let bare = home.path().join("bare.toml");
        std::fs::write(&bare, "[node]\nservers = []").unwrap();
        let servers = load(Some(&bare), true, &config()).unwrap();
        assert!(servers.mailboxes.add(endpoint("mine.example.org")).unwrap());
        assert_eq!(
            std::fs::read_to_string(&bare).unwrap(),
            "[node]\nservers = []\n\n[mailboxes]\nadded = [\"mine.example.org\"]\nremoved = []\n"
        );
    }

    #[test]
    fn a_mailbox_change_that_cannot_be_kept_changes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("settings.toml");
        let dotted = "mailboxes.added = [\"hand.example.org\"]\n";
        std::fs::write(&path, dotted).unwrap();
        let servers = load(Some(&path), true, &config()).unwrap();
        let before = servers.mailboxes.current();
        assert!(matches!(
            servers.mailboxes.add(endpoint("mine.example.org")),
            Err(MailboxChangeError::Form { .. })
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), dotted);
        assert_eq!(servers.mailboxes.current(), before);

        let one = home.path().join("one.toml");
        std::fs::write(
            &one,
            "[mailboxes]\nadded = [\"mine.example.org\"]\nremoved = [\"epicbox.btlabs.uk\", \"epicbox.epiccash.com\", \"epicbox.epicnet.us\"]\n",
        )
        .unwrap();
        let servers = load(Some(&one), true, &config()).unwrap();
        assert!(matches!(
            servers.mailboxes.remove(&endpoint("mine.example.org")),
            Err(MailboxChangeError::List(MailboxListError::Last))
        ));

        let unwritten = parse_text(SHIPPED_SETTINGS).unwrap();
        assert!(matches!(
            unwritten.mailboxes.add(endpoint("mine.example.org")),
            Err(MailboxChangeError::NoFile)
        ));
        assert_eq!(
            unwritten.mailboxes.current().endpoints(),
            config().shipped_mailboxes
        );
    }
}
