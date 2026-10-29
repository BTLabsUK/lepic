// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The vault713 Developers
// Ported from EpicCash/epic-wallet libwallet/src/epicbox_address.rs, libwallet/src/base58.rs
// (Apache-2.0); see NOTICE and upstream.toml.

use std::fmt;

use lepic_crypto::{CryptoError, PublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The port `Display` leaves out; it is also the relay port when an address names none.
pub const DEFAULT_PORT: u16 = 443;
/// Longer text is rejected before it is parsed.
pub const MAX_ADDRESS_LEN: usize = 512;
/// The longest DNS name.
pub const MAX_DOMAIN_LEN: usize = 253;

const SCHEME: &str = "epicbox://";
const KEY_TEXT_LEN: usize = 52;
const VERSION_LEN: usize = 2;
const CHECKSUM_LEN: usize = 4;

/// The chain an address belongs to. Its version bytes keep mainnet and floonet keys apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    fn version_bytes(self) -> [u8; VERSION_LEN] {
        match self {
            Self::Mainnet => [0x01, 0x00],
            Self::Floonet => [0x01, 0x88],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AddressError {
    #[error("address has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("address key has {actual} characters, expected 52")]
    KeyLength { actual: usize },
    #[error("address key is not base58")]
    NotBase58,
    #[error("address checksum does not match")]
    Checksum,
    #[error("address is not a {expected:?} address")]
    WrongNetwork { expected: Network },
    #[error("address key is not a valid public key")]
    InvalidPublicKey(#[source] CryptoError),
    #[error("address domain is empty, too long or has characters outside [a-zA-Z0-9.]")]
    InvalidDomain,
    #[error("address port is not a number from 0 to 65535")]
    InvalidPort,
    #[error("address names no domain and no default domain was given")]
    MissingDomain,
}

/// A relay host name, restricted to the characters `epic-wallet` accepts. Case is kept.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

impl Domain {
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '.';
        if text.is_empty() || text.len() > MAX_DOMAIN_LEN || !text.chars().all(allowed) {
            return Err(AddressError::InvalidDomain);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `localhost` or an IPv4 loopback address: the only hosts a plain websocket may reach.
    /// IPv6 `::1` is absent because a domain cannot hold an IPv6 literal.
    pub fn is_loopback(&self) -> bool {
        self.0.eq_ignore_ascii_case("localhost")
            || self
                .0
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback())
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An Epicbox address: a public key on one network, and the relay that holds its messages.
///
/// The port is kept exactly as given, `None` included, because the encrypted message carries the
/// destination's port and `epic-wallet` writes it as it was parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EpicboxAddress {
    public_key: PublicKey,
    network: Network,
    domain: Domain,
    port: Option<u16>,
}

impl EpicboxAddress {
    pub fn new(public_key: PublicKey, network: Network, domain: Domain, port: Option<u16>) -> Self {
        Self {
            public_key,
            network,
            domain,
            port,
        }
    }

    /// Parses `[epicbox://]<key>@<domain>[:<port>]`. Fails with
    /// [`AddressError::MissingDomain`] for an address without `@`: LEPIC holds no default
    /// relay.
    pub fn parse(text: &str, network: Network) -> Result<Self, AddressError> {
        Self::parse_inner(text, network, None)
    }

    /// Parses `[epicbox://]<key>[@<domain>[:<port>]]`, with `default_domain` and no port for
    /// an address without `@`.
    pub fn parse_with_default(
        text: &str,
        network: Network,
        default_domain: &Domain,
    ) -> Result<Self, AddressError> {
        Self::parse_inner(text, network, Some(default_domain))
    }

    /// The public key of `[epicbox://]<key>[@<domain>[:<port>]]`, whose relay part must parse
    /// when it is there.
    pub fn parse_key(text: &str, network: Network) -> Result<PublicKey, AddressError> {
        let key_only = Domain(String::new());
        Self::parse_inner(text, network, Some(&key_only)).map(|address| address.public_key)
    }

    fn parse_inner(
        text: &str,
        network: Network,
        default_domain: Option<&Domain>,
    ) -> Result<Self, AddressError> {
        if text.len() > MAX_ADDRESS_LEN {
            return Err(AddressError::TooLong {
                actual: text.len(),
                max: MAX_ADDRESS_LEN,
            });
        }
        let text = text.strip_prefix(SCHEME).unwrap_or(text);
        let (key_text, relay) = match text.split_once('@') {
            Some((key_text, relay)) => (key_text, Some(relay)),
            None => (text, None),
        };
        let public_key = decode_key(key_text, network)?;
        let (domain, port) = match relay {
            None => (
                default_domain.ok_or(AddressError::MissingDomain)?.clone(),
                None,
            ),
            Some(relay) => match relay.split_once(':') {
                None => (Domain::parse(relay)?, None),
                Some((domain, port)) => (Domain::parse(domain)?, Some(parse_port(port)?)),
            },
        };
        Ok(Self::new(public_key, network, domain, port))
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The base58check key alone, as `Subscribe`, `Made` and `Unsubscribe` send it.
    pub fn key_text(&self) -> String {
        encode_key(&self.public_key, self.network)
    }

    /// [`EpicboxAddress::key_text`] of an address with `public_key` on `network`.
    pub fn key_text_of(public_key: &PublicKey, network: Network) -> String {
        encode_key(public_key, network)
    }
}

/// `key@domain`, with `:port` only when a port other than 443 was given.
impl fmt::Display for EpicboxAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.key_text(), self.domain)?;
        match self.port {
            Some(port) if port != DEFAULT_PORT => write!(f, ":{port}"),
            _ => Ok(()),
        }
    }
}

/// The JSON object `epic-wallet` writes for an address: `public_key`, `domain`, `port`.
impl Serialize for EpicboxAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Json<'a> {
            public_key: String,
            domain: &'a str,
            port: Option<u16>,
        }
        Json {
            public_key: self.key_text(),
            domain: self.domain.as_str(),
            port: self.port,
        }
        .serialize(serializer)
    }
}

/// Decodes a base58check public key, checking the checksum before the version bytes as
/// `epic-wallet` does.
pub(crate) fn decode_key(text: &str, network: Network) -> Result<PublicKey, AddressError> {
    let actual = text.chars().count();
    if actual != KEY_TEXT_LEN {
        return Err(AddressError::KeyLength { actual });
    }
    let payload = bs58::decode(text)
        .into_vec()
        .map_err(|_| AddressError::NotBase58)?;
    let body_len = payload
        .len()
        .checked_sub(CHECKSUM_LEN)
        .filter(|len| *len > 0)
        .ok_or(AddressError::Checksum)?;
    let (body, checksum) = payload.split_at(body_len);
    if checksum != checksum_of(body) {
        return Err(AddressError::Checksum);
    }
    let (version, key) = body
        .split_at_checked(VERSION_LEN)
        .ok_or(AddressError::WrongNetwork { expected: network })?;
    if version != network.version_bytes() {
        return Err(AddressError::WrongNetwork { expected: network });
    }
    PublicKey::from_bytes(key).map_err(AddressError::InvalidPublicKey)
}

pub(crate) fn encode_key(key: &PublicKey, network: Network) -> String {
    let mut payload = Vec::with_capacity(VERSION_LEN + PublicKey::LEN + CHECKSUM_LEN);
    payload.extend_from_slice(&network.version_bytes());
    payload.extend_from_slice(&key.to_bytes());
    let checksum = checksum_of(&payload);
    payload.extend_from_slice(&checksum);
    bs58::encode(payload).into_string()
}

fn checksum_of(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(Sha256::digest(body));
    let mut checksum = [0u8; CHECKSUM_LEN];
    for (out, byte) in checksum.iter_mut().zip(digest.iter()) {
        *out = *byte;
    }
    checksum
}

/// Decimal digits only, leading zeros allowed, as `epic-wallet` reads them.
fn parse_port(text: &str) -> Result<u16, AddressError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AddressError::InvalidPort);
    }
    let trimmed = text.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed.parse().map_err(|_| AddressError::InvalidPort)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET_KEY: &str = "esYTimgooNuxKXdEEXJk3fbXoy2HWyyY2CaRXYU8Z8B7fSPyz6YL";

    fn parse(text: &str) -> Result<EpicboxAddress, AddressError> {
        EpicboxAddress::parse(text, Network::Mainnet)
    }

    fn relay() -> Domain {
        Domain::parse("relay.example.org").unwrap()
    }

    #[test]
    fn an_address_without_a_domain_needs_a_default_one() {
        assert_eq!(parse(MAINNET_KEY), Err(AddressError::MissingDomain));
        let address =
            EpicboxAddress::parse_with_default(MAINNET_KEY, Network::Mainnet, &relay()).unwrap();
        assert_eq!((address.domain(), address.port()), (&relay(), None));
        let named = EpicboxAddress::parse_with_default(
            &format!("{MAINNET_KEY}@other.example.org:13420"),
            Network::Mainnet,
            &relay(),
        )
        .unwrap();
        assert_eq!(named.domain().as_str(), "other.example.org");
        assert_eq!(named.port(), Some(13420));
    }

    #[test]
    fn a_key_parses_with_or_without_its_relay() {
        let bare = EpicboxAddress::parse_key(MAINNET_KEY, Network::Mainnet).unwrap();
        let full = EpicboxAddress::parse_key(
            &format!("{MAINNET_KEY}@relay.example.org"),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(bare, full);
        assert_eq!(
            EpicboxAddress::parse_key(&format!("{MAINNET_KEY}@"), Network::Mainnet),
            Err(AddressError::InvalidDomain)
        );
    }

    #[test]
    fn rejects_text_over_the_length_limit() {
        let text = format!("{MAINNET_KEY}@{}", "a".repeat(MAX_ADDRESS_LEN));
        assert!(matches!(parse(&text), Err(AddressError::TooLong { .. })));
    }

    #[test]
    fn rejects_domain_over_the_dns_limit() {
        let text = format!("{MAINNET_KEY}@{}", "a".repeat(MAX_DOMAIN_LEN + 1));
        assert_eq!(parse(&text), Err(AddressError::InvalidDomain));
    }

    #[test]
    fn accepts_domain_at_the_dns_limit() {
        let text = format!("{MAINNET_KEY}@{}", "a".repeat(MAX_DOMAIN_LEN));
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn rejects_port_with_a_sign() {
        assert_eq!(
            parse(&format!("{MAINNET_KEY}@relay.example.org:+443")),
            Err(AddressError::InvalidPort)
        );
    }

    #[test]
    fn rejects_second_port_separator() {
        assert_eq!(
            parse(&format!("{MAINNET_KEY}@relay.example.org:80:81")),
            Err(AddressError::InvalidPort)
        );
    }

    #[test]
    fn accepts_port_with_many_leading_zeros() {
        let address = parse(&format!("{MAINNET_KEY}@relay.example.org:0000000000443")).unwrap();
        assert_eq!(address.port(), Some(443));
    }

    #[test]
    fn rejects_scheme_in_another_case() {
        assert_eq!(
            parse(&format!("EPICBOX://{MAINNET_KEY}")),
            Err(AddressError::KeyLength { actual: 62 })
        );
    }

    #[test]
    fn rejects_multibyte_key_of_the_right_byte_length() {
        let key = format!("{}é", &MAINNET_KEY[..50]);
        assert_eq!(key.len(), KEY_TEXT_LEN);
        assert_eq!(parse(&key), Err(AddressError::KeyLength { actual: 51 }));
    }

    #[test]
    fn rejects_all_zero_payload_by_checksum() {
        assert_eq!(
            decode_key(&"1".repeat(KEY_TEXT_LEN), Network::Mainnet),
            Err(AddressError::Checksum)
        );
    }

    #[test]
    fn display_omits_only_port_443() {
        let address = parse(&format!("{MAINNET_KEY}@relay.example.org")).unwrap();
        let with =
            |port| EpicboxAddress::new(*address.public_key(), Network::Mainnet, relay(), port);
        assert_eq!(with(Some(443)).to_string(), with(None).to_string());
        assert!(with(Some(80)).to_string().ends_with(":80"));
    }
}
