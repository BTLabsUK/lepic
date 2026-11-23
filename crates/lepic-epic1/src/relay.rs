// SPDX-License-Identifier: Apache-2.0
//! The relay host of an `epicbox=` entry (RFC 0003 Appendix B.2, `relay-domain`): labels of
//! letters and digits, the rule Epicbox relays apply to every address they carry, so no hyphens.
//! A last label that starts with a digit makes the host an IPv4 literal; no IPv6 literal can be
//! written. The host of a direct `http` route (RFC 0003 5.20) may also hold hyphens inside its
//! labels ([`RelayHost::parse_web`]).

use std::fmt;
use std::net::Ipv4Addr;

use thiserror::Error;

/// Longest `domain[:port]` text, in octets (B.2).
pub const MAX_HOST_PORT_LEN: usize = 128;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RelayHostError {
    #[error("relay host is empty or longer than 128 octets with its port")]
    Length,
    #[error(
        "relay host has an empty label, a label over 63 octets or a character outside letters, digits and dots"
    )]
    Label,
    #[error("relay host looks like an IPv4 literal but is not four decimal numbers up to 255")]
    NotAnAddress,
    #[error("relay port is not a number from 1 to 65535")]
    Port,
}

/// A relay host name or IPv4 literal, lower-cased.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayHost(String);

impl RelayHost {
    /// Checks `text` against `relay-domain`. A name whose last label starts with a digit is read
    /// as an IPv4 literal and must be exactly four decimal numbers up to 255 without leading
    /// zeros, so a short, octal or hex form cannot hide an address.
    pub fn parse(text: &str) -> Result<Self, RelayHostError> {
        checked_host(text, false).map(Self)
    }

    /// Checks `text` as the host of a direct `http` route (RFC 0003 5.20): as [`Self::parse`],
    /// but a label may also hold hyphens, never as its first or last character, so any DNS host
    /// name a web shop runs on is taken. Never for an `epicbox=` or a link's `http=` entry.
    pub fn parse_web(text: &str) -> Result<Self, RelayHostError> {
        checked_host(text, true).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelayHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `text` lower-cased once it is a host name or IPv4 literal: labels of letters and digits, and
/// hyphens inside a label when `hyphens`.
fn checked_host(text: &str, hyphens: bool) -> Result<String, RelayHostError> {
    if text.is_empty() || text.len() > MAX_HOST_PORT_LEN {
        return Err(RelayHostError::Length);
    }
    let mut last = "";
    for label in text.split('.') {
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || (hyphens && byte == b'-'))
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !valid {
            return Err(RelayHostError::Label);
        }
        last = label;
    }
    if last.starts_with(|c: char| c.is_ascii_digit()) && text.parse::<Ipv4Addr>().is_err() {
        return Err(RelayHostError::NotAnAddress);
    }
    Ok(text.to_ascii_lowercase())
}

/// Reads `host[:port]`; the port is 1–65535 in digits only (at most five).
pub fn parse_host_port(text: &str) -> Result<(RelayHost, Option<u16>), RelayHostError> {
    host_port_with(text, RelayHost::parse)
}

/// Reads `host[:port]` of a direct `http` route, its host as [`RelayHost::parse_web`].
pub fn parse_web_host_port(text: &str) -> Result<(RelayHost, Option<u16>), RelayHostError> {
    host_port_with(text, RelayHost::parse_web)
}

fn host_port_with(
    text: &str,
    host: fn(&str) -> Result<RelayHost, RelayHostError>,
) -> Result<(RelayHost, Option<u16>), RelayHostError> {
    if text.len() > MAX_HOST_PORT_LEN {
        return Err(RelayHostError::Length);
    }
    match text.split_once(':') {
        None => Ok((host(text)?, None)),
        Some((name, port)) => {
            let digits = !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit());
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| digits && *port != 0)
                .ok_or(RelayHostError::Port)?;
            Ok((host(name)?, Some(port)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_names_and_ipv4_literals() {
        for text in [
            "relay.example",
            "payshop.example.org",
            "a",
            "1a.example",
            "Relay.EXAMPLE",
        ] {
            assert!(RelayHost::parse(text).is_ok(), "{text}");
        }
        assert_eq!(
            RelayHost::parse("Relay.EXAMPLE").unwrap().as_str(),
            "relay.example"
        );
        assert_eq!(
            RelayHost::parse("192.168.1.20").unwrap().as_str(),
            "192.168.1.20"
        );
    }

    #[test]
    fn refuses_bad_labels_and_hyphens() {
        for (text, error) in [
            ("", RelayHostError::Length),
            ("a..b", RelayHostError::Label),
            (".a", RelayHostError::Label),
            ("a.", RelayHostError::Label),
            ("a_b.example", RelayHostError::Label),
            ("a b", RelayHostError::Label),
            ("é.example", RelayHostError::Label),
            ("[::1]", RelayHostError::Label),
            ("pay-shop.example", RelayHostError::Label),
            ("-a.example", RelayHostError::Label),
            ("a-.example", RelayHostError::Label),
            ("a.-b", RelayHostError::Label),
        ] {
            assert_eq!(RelayHost::parse(text), Err(error), "{text:?}");
        }
        assert_eq!(
            RelayHost::parse(&format!("{}.example", "a".repeat(64))),
            Err(RelayHostError::Label)
        );
    }

    #[test]
    fn a_web_host_takes_hyphens_inside_labels_only() {
        for text in [
            "shop-demo.example",
            "a-b-c.pay-shop.example",
            "xn--bcher-kva.example",
        ] {
            assert_eq!(RelayHost::parse_web(text).unwrap().as_str(), text);
        }
        assert_eq!(
            parse_web_host_port("Shop-Demo.example:8443").unwrap(),
            (
                RelayHost::parse_web("shop-demo.example").unwrap(),
                Some(8443)
            )
        );
        for text in [
            "-a.example",
            "a-.example",
            "a.-b",
            "a_b.example",
            "a..b",
            "1-2.3-4",
        ] {
            assert!(RelayHost::parse_web(text).is_err(), "{text:?}");
        }
        assert_eq!(
            RelayHost::parse_web("127.1"),
            Err(RelayHostError::NotAnAddress)
        );
    }

    #[test]
    fn refuses_short_octal_and_oversized_numeric_forms() {
        for text in [
            "127.1",
            "1.2.3",
            "2130706433",
            "999.1.1.1",
            "010.0.0.1",
            "1.2.3.4.5",
            "example.123",
            "example.1a",
            "0x7f.0.0.1",
        ] {
            assert_eq!(
                RelayHost::parse(text),
                Err(RelayHostError::NotAnAddress),
                "{text}"
            );
        }
    }

    #[test]
    fn reads_host_and_port() {
        assert_eq!(parse_host_port("relay.example:8443").unwrap().1, Some(8443));
        assert_eq!(parse_host_port("relay.example").unwrap().1, None);
        assert_eq!(parse_host_port("relay.example:00443").unwrap().1, Some(443));
        for text in [
            "relay.example:",
            "relay.example:0",
            "relay.example:65536",
            "relay.example:+1",
            "relay.example:1:2",
            "relay.example:123456",
            "relay.example:-1",
        ] {
            assert!(parse_host_port(text).is_err(), "{text}");
        }
        let long = format!("{}.example:443", "a".repeat(120));
        assert_eq!(parse_host_port(&long), Err(RelayHostError::Length));
    }
}
