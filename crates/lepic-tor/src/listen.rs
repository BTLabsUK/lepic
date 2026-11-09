// SPDX-License-Identifier: Apache-2.0
//! The listener the wallet's onion forwards to.

use std::path::{Path, PathBuf};

use lepic_legacy_rpc::{Exposure, ListenLimits, ListenSettings};

/// Where the onion forwards its senders: the listener's port on `127.0.0.1`, or its Unix-domain
/// socket. Any program on the device (on Android any app) can connect to a loopback port; a
/// socket in tor's own folder only the wallet's user can reach. The onion's key and address are
/// the same either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionTarget {
    Port(u16),
    Unix(PathBuf),
}

/// The socket's name in tor's folder.
pub const ONION_SOCKET: &str = "onion.sock";

/// The name of the socket behind the previous onion, the one LEPIC 0.3.1 and earlier published
/// (ADR 0044), in tor's folder.
pub const PREVIOUS_ONION_SOCKET: &str = "previous-onion.sock";

/// The longest socket path used: a Unix socket address holds 104 bytes on macOS and 108 on
/// Linux, with the closing zero.
const MAX_SOCKET_PATH: usize = 100;

/// The Unix socket for the onion's listener in tor's folder `tor_dir`, or `None` where the
/// listener stays on a loopback port: on Windows, whose tor takes no `unix:` target, and for a
/// path too long for a socket address or with a character `ADD_ONION`'s `Port=` cannot carry
/// unquoted (a space, a comma, a quote, a backslash; macOS's `Application Support` has a space).
#[must_use]
pub fn onion_socket_path(tor_dir: &Path) -> Option<PathBuf> {
    socket_path(tor_dir, ONION_SOCKET)
}

/// [`onion_socket_path`] for the listener behind the previous onion.
#[must_use]
pub fn previous_onion_socket_path(tor_dir: &Path) -> Option<PathBuf> {
    socket_path(tor_dir, PREVIOUS_ONION_SOCKET)
}

fn socket_path(tor_dir: &Path, name: &str) -> Option<PathBuf> {
    if cfg!(not(unix)) {
        return None;
    }
    let path = tor_dir.join(name);
    usable_socket_path(&path).then_some(path)
}

/// Whether `path` can go into `ADD_ONION ... Port=80,unix:<path>` and a socket address.
pub(crate) fn usable_socket_path(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.starts_with('/')
            && text.len() <= MAX_SOCKET_PATH
            && text
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b',' | b'"' | b'\\'))
    })
}

/// Settings for the listener behind the onion, on `127.0.0.1` at a free port, within
/// `limits`. Tor connects
/// to it from `127.0.0.1` for every sender, so a limit per remote address would make all
/// senders share it: the listener's whole connection cap is the limit per address instead,
/// and tor limits each sender's circuit to
/// [`MAX_STREAMS_PER_CIRCUIT`](crate::control::MAX_STREAMS_PER_CIRCUIT) streams. The
/// connection cap and the request and payment budgets still bound the work of all senders
/// together.
#[must_use]
pub const fn listen_settings(limits: ListenLimits) -> ListenSettings {
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0, limits);
    settings.max_connections_per_address = settings.max_connections;
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_path_tor_can_take_or_none() {
        assert!(usable_socket_path(Path::new(
            "/data/user/0/app/files/w/tor/onion.sock"
        )));
        for unusable in [
            "/Users/a/Library/Application Support/w/tor/onion.sock",
            "/w/a,b/onion.sock",
            "/w/a\"b/onion.sock",
            "relative/onion.sock",
            "/w/\u{e9}/onion.sock",
        ] {
            assert!(!usable_socket_path(Path::new(unusable)), "{unusable}");
        }
        let long = format!("/{}/onion.sock", "a".repeat(MAX_SOCKET_PATH));
        assert!(!usable_socket_path(Path::new(&long)));
        #[cfg(unix)]
        assert_eq!(
            onion_socket_path(Path::new("/w/tor")),
            Some(PathBuf::from("/w/tor/onion.sock"))
        );
        #[cfg(unix)]
        assert_eq!(
            previous_onion_socket_path(Path::new("/w/tor")),
            Some(PathBuf::from("/w/tor/previous-onion.sock"))
        );
        #[cfg(not(unix))]
        assert_eq!(onion_socket_path(Path::new("/w/tor")), None);
    }

    #[test]
    fn every_sender_shares_only_the_whole_connection_cap() {
        let limits = lepic_legacy_rpc::testing::listen_limits();
        let settings = listen_settings(limits);
        let plain = ListenSettings::new(Exposure::LocalOnly, 0, limits);
        assert_eq!(settings.exposure, Exposure::LocalOnly);
        assert_eq!(settings.port, 0);
        assert_eq!(settings.max_connections, plain.max_connections);
        assert_eq!(
            settings.max_connections_per_address,
            settings.max_connections
        );
        assert_eq!(settings.requests_per_minute, plain.requests_per_minute);
        assert_eq!(settings.receives_per_minute, plain.receives_per_minute);
    }
}
