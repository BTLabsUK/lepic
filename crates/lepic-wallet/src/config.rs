// SPDX-License-Identifier: Apache-2.0
use std::fmt;
use std::path::PathBuf;

use lepic_primitives::params::Network;
use lepic_transport::transport::TransportId;
use thiserror::Error;

pub const MAX_WALLET_NAME_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("wallet name has {actual} bytes, expected 1 to {MAX_WALLET_NAME_LEN}")]
    WalletNameLength { actual: usize },
    #[error("wallet name byte {position} is not a lowercase letter, digit, '-' or '_'")]
    WalletNameCharacter { position: usize },
    #[error("node endpoint is not an http or https url with a host")]
    NodeEndpoint,
    #[error("transport {transport} is configured but not registered")]
    UnknownTransport { transport: TransportId },
}

/// Names one wallet instance in logs and events. Not secret: it is neither the seed nor an
/// address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WalletName(String);

impl WalletName {
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        if name.is_empty() || name.len() > MAX_WALLET_NAME_LEN {
            return Err(ConfigError::WalletNameLength { actual: name.len() });
        }
        let allowed =
            |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte);
        match name.bytes().position(|byte| !allowed(byte)) {
            Some(position) => Err(ConfigError::WalletNameCharacter { position }),
            None => Ok(Self(name.to_owned())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WalletName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The node the wallet talks to. The host builds the node client from it; the engine keeps it
/// for logs and for the host to read back.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeEndpoint {
    url: String,
    host_start: usize,
    host_end: usize,
}

impl NodeEndpoint {
    pub fn parse(url: &str) -> Result<Self, ConfigError> {
        let host_start = ["http://", "https://"]
            .iter()
            .find(|scheme| url.starts_with(**scheme))
            .map(|scheme| scheme.len())
            .ok_or(ConfigError::NodeEndpoint)?;
        let authority = url.get(host_start..).ok_or(ConfigError::NodeEndpoint)?;
        let authority_len = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        let authority = authority
            .get(..authority_len)
            .ok_or(ConfigError::NodeEndpoint)?;
        let host_len = if authority.starts_with('[') {
            authority
                .find(']')
                .and_then(|end| end.checked_add(1))
                .ok_or(ConfigError::NodeEndpoint)?
        } else {
            authority.find(':').unwrap_or(authority.len())
        };
        let host = authority.get(..host_len).ok_or(ConfigError::NodeEndpoint)?;
        if host.is_empty() || authority.contains('@') || url.chars().any(char::is_whitespace) {
            return Err(ConfigError::NodeEndpoint);
        }
        let host_end = host_start
            .checked_add(host_len)
            .ok_or(ConfigError::NodeEndpoint)?;
        Ok(Self {
            url: url.to_owned(),
            host_start,
            host_end,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// The host part, the only part of the endpoint that appears in logs.
    pub fn host(&self) -> &str {
        self.url
            .get(self.host_start..self.host_end)
            .unwrap_or_default()
    }
}

impl fmt::Display for NodeEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

/// What one wallet instance is: everything except the ports it runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletConfig {
    pub name: WalletName,
    pub network: Network,
    /// Where the wallet database lives. The host creates the directory.
    pub data_dir: PathBuf,
    pub node: NodeEndpoint,
    /// The transaction methods this wallet offers. Each must be registered in the
    /// [`crate::Ports::transports`] registry.
    pub transports: Vec<TransportId>,
    /// The session never asks the node. Payment stages use the highest tip a refresh
    /// confirmed, unchecked, and finalizing stores the transaction `finalized` without a push.
    /// The host builds the session's node and relay ports to refuse every call as well. Fixed
    /// for the session: a change means opening the wallet again.
    pub offline: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_wallet_names() {
        for name in ["default", "w-1", "a_b", "0", &"x".repeat(64)] {
            assert_eq!(WalletName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_wallet_names_outside_the_alphabet_or_length() {
        assert_eq!(
            WalletName::new(""),
            Err(ConfigError::WalletNameLength { actual: 0 })
        );
        assert_eq!(
            WalletName::new(&"x".repeat(65)),
            Err(ConfigError::WalletNameLength { actual: 65 })
        );
        for (name, position) in [("Main", 0), ("a b", 1), ("a/b", 1), ("a.b", 1)] {
            assert_eq!(
                WalletName::new(name),
                Err(ConfigError::WalletNameCharacter { position })
            );
        }
    }

    #[test]
    fn node_endpoint_exposes_only_the_host() {
        for (url, host) in [
            ("http://127.0.0.1:3413", "127.0.0.1"),
            ("https://node.example.org/v2/foreign", "node.example.org"),
            ("http://[::1]:3413/", "[::1]"),
            ("https://example.org?x=1", "example.org"),
        ] {
            assert_eq!(NodeEndpoint::parse(url).unwrap().host(), host, "{url}");
        }
    }

    #[test]
    fn rejects_node_endpoints_without_http_scheme_or_host() {
        for url in [
            "",
            "127.0.0.1:3413",
            "ftp://example.org",
            "http://",
            "http://:3413",
            "https:///path",
            "http://user:secret@example.org",
            "http://[::1",
            "http://exa mple.invalid",
        ] {
            assert_eq!(
                NodeEndpoint::parse(url),
                Err(ConfigError::NodeEndpoint),
                "{url}"
            );
        }
    }
}
