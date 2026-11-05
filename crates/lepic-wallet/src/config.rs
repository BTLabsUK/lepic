// SPDX-License-Identifier: Apache-2.0
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

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
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("{what} must be at least 1")]
    PolicyOutOfRange { what: &'static str },
    #[error("{what} must be at most {max}")]
    PolicyAboveBound { what: &'static str, max: u64 },
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
    /// The session never asks the node. Payment stages use the highest tip a refresh
    /// confirmed, unchecked, and finalizing stores the transaction `finalized` without a push.
    /// The host builds the session's node and relay ports to refuse every call as well. Fixed
    /// for the session: a change means opening the wallet again.
    pub offline: bool,
    /// The feature bits the host app claims, a constant of its build, never a setting. Only
    /// the host bits ([`lepic_epicbox::marker::features::HOST_FEATURES`]) are kept.
    pub host_features: u32,
    /// Values the host chooses; [`WalletPolicy::default`] is what LEPIC did before they were
    /// parameters.
    pub policy: WalletPolicy,
}

/// How many receipts nobody asked for a wallet keeps open, the confirmations a wallet counts as
/// spendable before the user sets their own, how often a contact's checks are answered, and how
/// long a contact message that fails is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletPolicy {
    /// Open receipts, payments received over Epicbox and answered with S2 that the sender has
    /// not finalized, kept from one sender key. A paying wallet finalizes as soon as the S2
    /// arrives, so a sender with this many open is not finalizing; a further S1 from its key
    /// is refused and acknowledged without being signed or stored, unless a refresh, made
    /// first at most once a minute, confirms some of them. The same cap applies to parked
    /// invoices.
    pub max_open_receipts_per_sender: usize,
    /// Open receipts kept over every sender. Each holds an unconfirmed output, a transaction
    /// and its slates, so this bounds what unsolicited payments can store. At the cap the
    /// inbox first refreshes, at most once a minute, so receipts already mined are confirmed
    /// and leave the open set. Then one open receipt is cancelled to make room, as
    /// [`crate::Wallet::cancel`] does, so a payment completed later is still restored: the
    /// sender key with the most open receipts gives one up first, oldest first, and a receipt
    /// the node's pool or chain holds is kept. When none can be cancelled, the new S1 is
    /// refused without being signed or stored; the sender can send it again. A node that
    /// cannot be asked holds the S1 only to the hold bound before it is refused the same way.
    pub max_open_receipts: usize,
    /// The minimum confirmations of a wallet that never stored its own
    /// ([`crate::Wallet::set_minimum_confirmations`]). At least 1.
    pub default_minimum_confirmations: u64,
    /// Contact checks (RFC 0002 8.5) one contact gets answered in an hour. A further check is
    /// acknowledged and dropped without an answer. At least 1, at most
    /// [`Self::contact_check_answers_per_day`].
    pub contact_check_answers_per_hour: u32,
    /// Contact checks one contact gets answered in a day. At least 1, at most
    /// [`Self::MAX_CONTACT_CHECK_ANSWERS_PER_DAY`].
    pub contact_check_answers_per_day: u32,
    /// Times a contact mailbox message whose taking fails for a lasting reason is kept for the
    /// next collect before it is acknowledged and dropped. A failure that passes (the node, the
    /// relay or the store not answering, the wallet locked) keeps the message without counting.
    /// At least 1, at most [`Self::MAX_CONTACT_HOLD_ATTEMPTS`].
    pub contact_hold_attempts: u32,
    /// How long after it was first kept such a message is still kept. At least a second, at
    /// most [`Self::MAX_CONTACT_HOLD_PATIENCE`].
    pub contact_hold_patience: Duration,
}

impl WalletPolicy {
    /// The values every wallet used before they were parameters: 10 and 100 receipts, 6
    /// confirmations, a contact's checks answered once an hour and three times a day, and a
    /// failing contact message kept 3 times within 3 minutes.
    pub const DEFAULT: Self = Self {
        max_open_receipts_per_sender: 10,
        max_open_receipts: 100,
        default_minimum_confirmations: 6,
        contact_check_answers_per_hour: 1,
        contact_check_answers_per_day: 3,
        contact_hold_attempts: 3,
        contact_hold_patience: Duration::from_secs(3 * 60),
    };

    /// The bound on [`Self::contact_check_answers_per_day`]: each answer is a contact update,
    /// which a contact takes at most three times a day from one pairing and a hundred times an
    /// hour in all (RFC 0002 8.5), so more answers only load the relay.
    pub const MAX_CONTACT_CHECK_ANSWERS_PER_DAY: u32 = 24;

    /// The bound on [`Self::contact_hold_attempts`]. A relay discards everything queued for a
    /// mailbox when one message stays unacknowledged for long, and every message behind a kept
    /// one waits meanwhile.
    pub const MAX_CONTACT_HOLD_ATTEMPTS: u32 = 10;

    /// The bound on [`Self::contact_hold_patience`], for the same reason: a day, after which the
    /// count of a kept message is forgotten.
    pub const MAX_CONTACT_HOLD_PATIENCE: Duration = Duration::from_secs(24 * 60 * 60);
}

impl WalletPolicy {
    /// Fails with [`ConfigError::PolicyOutOfRange`] for a value below 1 and
    /// [`ConfigError::PolicyAboveBound`] for one above its bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (what, value) in [
            (
                "max open receipts per sender",
                self.max_open_receipts_per_sender as u64,
            ),
            ("max open receipts", self.max_open_receipts as u64),
            (
                "default minimum confirmations",
                self.default_minimum_confirmations,
            ),
            (
                "contact check answers per hour",
                u64::from(self.contact_check_answers_per_hour),
            ),
            (
                "contact check answers per day",
                u64::from(self.contact_check_answers_per_day),
            ),
            (
                "contact hold attempts",
                u64::from(self.contact_hold_attempts),
            ),
            (
                "contact hold patience in seconds",
                self.contact_hold_patience.as_secs(),
            ),
        ] {
            if value == 0 {
                return Err(ConfigError::PolicyOutOfRange { what });
            }
        }
        for (what, value, max) in [
            (
                "contact check answers per hour",
                self.contact_check_answers_per_hour,
                self.contact_check_answers_per_day,
            ),
            (
                "contact check answers per day",
                self.contact_check_answers_per_day,
                Self::MAX_CONTACT_CHECK_ANSWERS_PER_DAY,
            ),
            (
                "contact hold attempts",
                self.contact_hold_attempts,
                Self::MAX_CONTACT_HOLD_ATTEMPTS,
            ),
        ] {
            if value > max {
                return Err(ConfigError::PolicyAboveBound {
                    what,
                    max: u64::from(max),
                });
            }
        }
        if self.contact_hold_patience > Self::MAX_CONTACT_HOLD_PATIENCE {
            return Err(ConfigError::PolicyAboveBound {
                what: "contact hold patience in seconds",
                max: Self::MAX_CONTACT_HOLD_PATIENCE.as_secs(),
            });
        }
        Ok(())
    }
}

impl Default for WalletPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl WalletConfig {
    /// The feature bits this wallet claims to peers: LEPIC's own and the host's.
    pub fn claimed_features(&self) -> u32 {
        lepic_epicbox::marker::features::claimed(self.host_features)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_host_bits_of_the_host_features_are_claimed() {
        use lepic_epicbox::marker::features::{LEPIC_FEATURES, NAME_SERVICE};
        let config = |host_features| WalletConfig {
            name: WalletName::new("w").unwrap(),
            network: Network::Floonet,
            data_dir: PathBuf::from("/w"),
            node: NodeEndpoint::parse("http://127.0.0.1:1").unwrap(),
            offline: false,
            host_features,
            policy: WalletPolicy::default(),
        };
        assert_eq!(config(0).claimed_features(), LEPIC_FEATURES);
        assert_eq!(
            config(NAME_SERVICE | 0b1110 | 1 << 31).claimed_features(),
            LEPIC_FEATURES | NAME_SERVICE
        );
    }

    #[test]
    fn the_default_policy_is_what_wallets_did_before_it_was_a_parameter() {
        let policy = WalletPolicy::default();
        assert_eq!(policy.max_open_receipts_per_sender, 10);
        assert_eq!(policy.max_open_receipts, 100);
        assert_eq!(policy.default_minimum_confirmations, 6);
        assert_eq!(policy.contact_check_answers_per_hour, 1);
        assert_eq!(policy.contact_check_answers_per_day, 3);
        assert_eq!(policy.contact_hold_attempts, 3);
        assert_eq!(policy.contact_hold_patience, Duration::from_secs(180));
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn contact_paces_and_holds_are_bounded() {
        let with = |change: fn(&mut WalletPolicy)| {
            let mut policy = WalletPolicy::default();
            change(&mut policy);
            policy.validate()
        };
        assert!(matches!(
            with(|policy| policy.contact_check_answers_per_hour = 0),
            Err(ConfigError::PolicyOutOfRange { .. })
        ));
        assert!(matches!(
            with(|policy| policy.contact_check_answers_per_hour = 4),
            Err(ConfigError::PolicyAboveBound { max: 3, .. })
        ));
        assert!(matches!(
            with(|policy| {
                policy.contact_check_answers_per_hour = 24;
                policy.contact_check_answers_per_day = 24;
            }),
            Ok(())
        ));
        assert!(matches!(
            with(|policy| policy.contact_check_answers_per_day = 25),
            Err(ConfigError::PolicyAboveBound { max: 24, .. })
        ));
        assert!(matches!(
            with(|policy| policy.contact_hold_attempts = 11),
            Err(ConfigError::PolicyAboveBound { max: 10, .. })
        ));
        assert!(matches!(
            with(|policy| policy.contact_hold_patience = Duration::ZERO),
            Err(ConfigError::PolicyOutOfRange { .. })
        ));
        assert!(matches!(
            with(|policy| {
                policy.contact_hold_patience = WalletPolicy::MAX_CONTACT_HOLD_PATIENCE;
            }),
            Ok(())
        ));
        assert!(matches!(
            with(|policy| {
                policy.contact_hold_patience =
                    WalletPolicy::MAX_CONTACT_HOLD_PATIENCE + Duration::from_secs(1);
            }),
            Err(ConfigError::PolicyAboveBound { .. })
        ));
    }

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
