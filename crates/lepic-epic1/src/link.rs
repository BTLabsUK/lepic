// SPDX-License-Identifier: Apache-2.0
//! The epic1 payment link (RFC 0003 §5.14, Appendix B.2):
//! `epic:<epic1>?epicbox=<mailbox>@<relay>[:<port>]&amount=5&message=Dinner`.
//!
//! The address part is the epic1 alone. Transport entries (`epicbox=`) say how to deliver and
//! never who is paid: the mailbox is held as a key for the delivery layer, not as an address.
//! A link that carries an Epicbox address instead is not an epic1 link, and no parameter of
//! either link is read as a second address.

use lepic_crypto::PublicKey;
use lepic_epicbox::{AddressError, DEFAULT_PORT, EpicboxAddress, Network};
use lepic_primitives::amount::Amount;
use thiserror::Error;

use crate::address::{Epic1Address, Epic1Error};
use crate::amount::{AmountError, format_amount, parse_amount};
use crate::relay::{RelayHost, RelayHostError, parse_host_port};

const SCHEME: &str = "epic:";
const ADDRESS_PREFIXES: [&str; 2] = ["epic1", "tepic1"];

/// Longest link text read, in bytes. Three transports with long domains and a 256-byte
/// message stay well below it.
pub const MAX_LINK_LEN: usize = 2048;
/// Transport entries read, and written, per link.
pub const MAX_TRANSPORTS: usize = 3;
/// Longest decoded `message` or `label`, in bytes: the participant message limit.
pub const MAX_VALUE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LinkError {
    #[error("link has {len} bytes, the limit is {max}")]
    TooLong { len: usize, max: usize },
    #[error("not an epic1 link")]
    NotAnEpic1Link,
    #[error("epic1 address: {0}")]
    Address(#[source] Epic1Error),
    #[error("amount: {0}")]
    Amount(#[source] AmountError),
    #[error("amount is not valid percent-encoded text")]
    AmountEncoding,
}

/// Why a transport entry cannot be used. The entry is skipped and reported.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TransportFault {
    #[error("value is not percent-encoded UTF-8")]
    Encoding,
    #[error("no `@` between mailbox and relay")]
    NoRelay,
    #[error("mailbox address: {0}")]
    Mailbox(#[source] AddressError),
    #[error("mailbox is not of the epic1's network")]
    Network,
    #[error("relay: {0}")]
    Relay(#[source] RelayHostError),
}

/// What a reader left out of a link and says so.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Skipped {
    /// The `epicbox=` entry at `index` (counting every `epicbox=`, from 0) is not usable.
    Transport { index: usize, fault: TransportFault },
    /// Entries after the third are not read.
    TransportsOverLimit { count: usize },
    /// A `message` or `label` that is longer than [`MAX_VALUE_LEN`], not valid percent-encoded
    /// UTF-8 or holds control characters.
    Value { key: &'static str },
}

/// One delivery method: an Epicbox mailbox on a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpicboxTransport {
    mailbox: PublicKey,
    relay: RelayHost,
    port: Option<u16>,
}

impl EpicboxTransport {
    pub fn new(mailbox: PublicKey, relay: RelayHost, port: Option<u16>) -> Self {
        Self {
            mailbox,
            relay,
            port,
        }
    }

    /// The mailbox key. Its network is the epic1's (checked at parse).
    pub fn mailbox(&self) -> &PublicKey {
        &self.mailbox
    }

    pub fn relay(&self) -> &RelayHost {
        &self.relay
    }

    /// The port as written; [`EpicboxTransport::port_or_default`] gives the one to connect to.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }

    /// `<mailbox base58>@<relay>[:<port>]` for `network`.
    pub fn to_value(&self, network: Network) -> String {
        let mut text = format!(
            "{}@{}",
            EpicboxAddress::key_text_of(&self.mailbox, network),
            self.relay
        );
        if let Some(port) = self.port {
            text.push(':');
            text.push_str(&port.to_string());
        }
        text
    }

    fn parse(value: &str, network: Network) -> Result<Self, TransportFault> {
        let (key_text, relay) = value.split_once('@').ok_or(TransportFault::NoRelay)?;
        let mailbox =
            EpicboxAddress::parse_key(key_text, network).map_err(|error| match error {
                AddressError::WrongNetwork { .. } => TransportFault::Network,
                other => TransportFault::Mailbox(other),
            })?;
        let (relay, port) = parse_host_port(relay).map_err(TransportFault::Relay)?;
        Ok(Self {
            mailbox,
            relay,
            port,
        })
    }
}

/// How the payer can deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery<'a> {
    /// Usable entries, in the order to try them.
    Usable(&'a [EpicboxTransport]),
    /// "Cannot pay this code": no usable transport. There is no default relay for an epic1.
    CannotPay,
}

/// A parsed epic1 link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Link {
    pub address: Epic1Address,
    /// Usable entries in link order, at most [`MAX_TRANSPORTS`] read.
    pub transports: Vec<EpicboxTransport>,
    pub amount: Option<Amount>,
    pub message: Option<String>,
    pub label: Option<String>,
    /// What was left out, in link order.
    pub ignored: Vec<Skipped>,
}

impl Epic1Link {
    /// A link to `address` with no transport yet.
    pub fn new(address: Epic1Address) -> Self {
        Self {
            address,
            transports: Vec::new(),
            amount: None,
            message: None,
            label: None,
            ignored: Vec::new(),
        }
    }

    pub fn delivery(&self) -> Delivery<'_> {
        if self.transports.is_empty() {
            Delivery::CannotPay
        } else {
            Delivery::Usable(&self.transports)
        }
    }

    /// Reads an `epic:epic1…` or `epic:tepic1…` link. The network is the address's own.
    /// An Epicbox link, or anything whose address part is not an epic1, is
    /// [`LinkError::NotAnEpic1Link`].
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        if text.len() > MAX_LINK_LEN {
            return Err(LinkError::TooLong {
                len: text.len(),
                max: MAX_LINK_LEN,
            });
        }
        let rest = text.strip_prefix(SCHEME).ok_or(LinkError::NotAnEpic1Link)?;
        let (address_text, query) = match rest.split_once('?') {
            Some((address, query)) => (address, Some(query)),
            None => (rest, None),
        };
        if !ADDRESS_PREFIXES
            .iter()
            .any(|prefix| address_text.starts_with(prefix))
        {
            return Err(LinkError::NotAnEpic1Link);
        }
        let address = Epic1Address::decode_any(address_text).map_err(LinkError::Address)?;
        let mut link = Self::new(address);
        let mut seen_transports = 0usize;
        let (mut amount_seen, mut message_seen, mut label_seen) = (false, false, false);
        for pair in query.unwrap_or_default().split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key {
                "epicbox" => {
                    let index = seen_transports;
                    seen_transports = seen_transports.saturating_add(1);
                    if index >= MAX_TRANSPORTS {
                        continue;
                    }
                    let parsed = percent_decode(value)
                        .ok_or(TransportFault::Encoding)
                        .and_then(|value| EpicboxTransport::parse(&value, address.network()));
                    match parsed {
                        Ok(transport) => link.transports.push(transport),
                        Err(fault) => link.ignored.push(Skipped::Transport { index, fault }),
                    }
                }
                "amount" if !amount_seen => {
                    amount_seen = true;
                    let decoded = percent_decode(value).ok_or(LinkError::AmountEncoding)?;
                    link.amount = Some(parse_amount(&decoded).map_err(LinkError::Amount)?);
                }
                "message" | "note" | "memo" if !message_seen => {
                    message_seen = true;
                    link.message = text_value(value, "message", &mut link.ignored);
                }
                "label" if !label_seen => {
                    label_seen = true;
                    link.label = text_value(value, "label", &mut link.ignored);
                }
                // `method`, `direct`, `require`, `min`, a repeated pay parameter and every
                // unknown key have no meaning in an epic1 link.
                _ => {}
            }
        }
        if seen_transports > MAX_TRANSPORTS {
            link.ignored.push(Skipped::TransportsOverLimit {
                count: seen_transports.saturating_sub(MAX_TRANSPORTS),
            });
        }
        Ok(link)
    }

    /// The link as text, in lower case: the address, then at most [`MAX_TRANSPORTS`]
    /// `epicbox=` entries, then `amount`, `message` and `label` when set.
    pub fn to_uri(&self) -> String {
        let network = self.address.network();
        let mut pairs: Vec<String> = self
            .transports
            .iter()
            .take(MAX_TRANSPORTS)
            .map(|transport| format!("epicbox={}", percent_encode(&transport.to_value(network))))
            .collect();
        if let Some(amount) = self.amount {
            pairs.push(format!("amount={}", format_amount(amount)));
        }
        if let Some(message) = &self.message {
            pairs.push(format!("message={}", percent_encode(message)));
        }
        if let Some(label) = &self.label {
            pairs.push(format!("label={}", percent_encode(label)));
        }
        let mut text = format!("{SCHEME}{}", self.address);
        if !pairs.is_empty() {
            text.push('?');
            text.push_str(&pairs.join("&"));
        }
        text
    }
}

fn text_value(value: &str, key: &'static str, ignored: &mut Vec<Skipped>) -> Option<String> {
    match percent_decode(value) {
        Some(text) if text.len() <= MAX_VALUE_LEN && !text.chars().any(char::is_control) => {
            Some(text)
        }
        _ => {
            ignored.push(Skipped::Value { key });
            None
        }
    }
}

/// RFC 3986 percent-decoding to UTF-8; `+` stays a plus.
fn percent_decode(value: &str) -> Option<String> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = hex_value(bytes.next()?)?;
            let low = hex_value(bytes.next()?)?;
            out.push(high.checked_mul(16)?.checked_add(low)?);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// Everything outside RFC 3986's unreserved characters is written as `%XX`.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
