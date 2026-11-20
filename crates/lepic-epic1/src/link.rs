// SPDX-License-Identifier: Apache-2.0
//! The epic1 payment link (RFC 0003 §5.14, Appendix B.2):
//! `epic:<epic1>?http=<host>&tor=<onion>&amount=5&message=Dinner`.
//!
//! The address part is the epic1 alone, and it carries its own mailbox: the delivery key is the
//! mailbox on every relay. Route entries (`http=`, `tor=`) say how else to deliver and never who
//! is paid. An `epicbox=` entry is not read: it is reported with the other parameters left out.
//! A link that carries an Epicbox address instead is not an epic1 link, and no parameter of
//! either link is read as a second address.

use lepic_primitives::amount::Amount;
use thiserror::Error;

use crate::address::{Epic1Address, Epic1Error};
use crate::amount::{AmountError, format_amount, parse_amount};
use crate::relay::{RelayHostError, parse_host_port};
use crate::route::{MethodId, RouteEntry, onion_host_port};

const SCHEME: &str = "epic:";
const ADDRESS_PREFIXES: [&str; 2] = ["epic1", "tepic1"];

/// Longest link text read, in bytes. Three route entries with long domains and a 256-byte
/// message stay well below it.
pub const MAX_LINK_LEN: usize = 2048;
/// Route entries a link may hold, across `http=` and `tor=`. A link with more is refused.
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
    /// A link of 0.5 and before: its address has no version byte. `mailbox` is the relay
    /// (`host[:port]`) of the first `epicbox=` entry the link carries, when it carries one.
    #[error("{}", earlier_text(.mailbox.as_deref()))]
    EarlierAddress { mailbox: Option<String> },
    #[error("amount: {0}")]
    Amount(#[source] AmountError),
    #[error("amount is not valid percent-encoded text")]
    AmountEncoding,
    /// More `http=` and `tor=` entries than [`MAX_TRANSPORTS`], usable or not.
    #[error("link has {count} route entries, the limit is {max}")]
    TooManyEntries { count: usize, max: usize },
}

impl LinkError {
    /// Whether the link is one of 0.5 and before, which this version cannot read.
    #[must_use]
    pub fn is_earlier_address(&self) -> bool {
        matches!(
            self,
            Self::EarlierAddress { .. } | Self::Address(Epic1Error::EarlierAddress)
        )
    }
}

fn earlier_text(mailbox: Option<&str>) -> String {
    let advice = "use the wallet's Epicbox address (the one with an @), or an epic1 address or \
                  link from an updated wallet";
    match mailbox {
        Some(mailbox) => format!(
            "epic1 link of an older wallet version, which names the mailbox {mailbox} and \
             which this version cannot read: {advice}"
        ),
        None => format!(
            "epic1 link of an older wallet version, which this version cannot read: {advice}"
        ),
    }
}

/// The relay, `host[:port]`, of the first `epicbox=<mailbox>@<relay>` entry of `query`: where
/// the link of an earlier release said its payee's mailbox was. Nothing else of the entry is
/// kept.
fn earlier_mailbox(query: Option<&str>) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if !key.eq_ignore_ascii_case("epicbox") {
            return None;
        }
        let value = percent_decode(value)?;
        let (_, relay) = value.split_once('@')?;
        let (host, port) = parse_host_port(relay).ok()?;
        Some(match port {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        })
    })
}

/// Why a route entry cannot be used. The entry is skipped and reported.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TransportFault {
    #[error("value is not percent-encoded UTF-8")]
    Encoding,
    /// An `http=` value that is not `<host>[:<port>]` under the host rule.
    #[error("http host: {0}")]
    Http(#[source] RelayHostError),
    /// A `tor=` value that is not `<56 base32>.onion[:<port>]` in lower case.
    #[error("tor value is not an onion name with an optional port")]
    Onion,
}

/// What a reader left out of a link and says so.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Skipped {
    /// The route entry at `index` (counting every `http=` and `tor=`, from 0) is not usable.
    Transport { index: usize, fault: TransportFault },
    /// An `epicbox=` entry, one per entry. The address's delivery key is its mailbox on every
    /// relay, so a link names no other.
    Epicbox,
    /// A `mailbox=` entry, one per entry. A payer posts through its own mailbox list, so a link
    /// names no mailbox to pay through.
    Mailbox,
    /// A `message` or `label` that is longer than [`MAX_VALUE_LEN`], not valid percent-encoded
    /// UTF-8 or holds control characters.
    Value { key: &'static str },
}

/// A parsed epic1 link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Link {
    pub address: Epic1Address,
    /// Usable route entries in link order, at most [`MAX_TRANSPORTS`]. Each value is in its
    /// canonical form: `<host>[:<port>]` or `<56 base32>.onion[:<port>]`.
    pub routes: Vec<RouteEntry>,
    pub amount: Option<Amount>,
    pub message: Option<String>,
    pub label: Option<String>,
    /// What was left out, in link order.
    pub ignored: Vec<Skipped>,
}

impl Epic1Link {
    /// A link to `address` with no route entry yet.
    pub fn new(address: Epic1Address) -> Self {
        Self {
            address,
            routes: Vec::new(),
            amount: None,
            message: None,
            label: None,
            ignored: Vec::new(),
        }
    }

    /// Reads an `epic:epic1…` or `epic:tepic1…` link. The network is the address's own.
    /// An Epicbox link, or anything whose address part is not an epic1, is
    /// [`LinkError::NotAnEpic1Link`]; a link with more than [`MAX_TRANSPORTS`] `http=` and
    /// `tor=` entries is [`LinkError::TooManyEntries`]. The scheme, the address and the keys are
    /// read in either case, so a link written in upper case for a QR reads as the same link.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        if text.len() > MAX_LINK_LEN {
            return Err(LinkError::TooLong {
                len: text.len(),
                max: MAX_LINK_LEN,
            });
        }
        let rest = text
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .and_then(|_| text.get(SCHEME.len()..))
            .ok_or(LinkError::NotAnEpic1Link)?;
        let (address_text, query) = match rest.split_once('?') {
            Some((address, query)) => (address, Some(query)),
            None => (rest, None),
        };
        if !ADDRESS_PREFIXES.iter().any(|prefix| {
            address_text
                .get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
        }) {
            return Err(LinkError::NotAnEpic1Link);
        }
        let address = Epic1Address::decode_any(address_text).map_err(|error| match error {
            Epic1Error::EarlierAddress => LinkError::EarlierAddress {
                mailbox: earlier_mailbox(query),
            },
            other => LinkError::Address(other),
        })?;
        let mut link = Self::new(address);
        let mut seen_routes = 0usize;
        let (mut amount_seen, mut message_seen, mut label_seen) = (false, false, false);
        for pair in query.unwrap_or_default().split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let key = key.to_ascii_lowercase();
            let method = match key.as_str() {
                "http" => Some(MethodId::Http),
                "tor" => Some(MethodId::Tor),
                _ => None,
            };
            if let Some(method) = method {
                let index = seen_routes;
                seen_routes = seen_routes.saturating_add(1);
                let parsed = percent_decode(value)
                    .ok_or(TransportFault::Encoding)
                    .and_then(|value| canonical_value(method, &value));
                match parsed {
                    Ok(value) => link.routes.push(RouteEntry { method, value }),
                    Err(fault) => link.ignored.push(Skipped::Transport { index, fault }),
                }
                continue;
            }
            match key.as_str() {
                "epicbox" => link.ignored.push(Skipped::Epicbox),
                "mailbox" => link.ignored.push(Skipped::Mailbox),
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
        if seen_routes > MAX_TRANSPORTS {
            return Err(LinkError::TooManyEntries {
                count: seen_routes,
                max: MAX_TRANSPORTS,
            });
        }
        Ok(link)
    }

    /// The link as text: the address, then at most [`MAX_TRANSPORTS`] route entries in order,
    /// each under its own key, then `amount`, `message` and `label` when set. The scheme,
    /// address and keys are lower case. Only `http` and `tor` entries are written.
    pub fn to_uri(&self) -> String {
        let mut pairs: Vec<String> = self
            .link_routes()
            .take(MAX_TRANSPORTS)
            .map(route_pair)
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
        with_query(format!("{SCHEME}{}", self.address), &pairs)
    }

    /// The link for a QR code: the address, the first route entry and the amount only, written
    /// as [`Epic1Link::to_uri`] writes them. A link with none of them is written in upper case,
    /// which a QR code holds in its smaller alphanumeric mode.
    pub fn to_qr(&self) -> String {
        let mut pairs: Vec<String> = self
            .link_routes()
            .next()
            .map(route_pair)
            .into_iter()
            .collect();
        if let Some(amount) = self.amount {
            pairs.push(format!("amount={}", format_amount(amount)));
        }
        let link = with_query(format!("{SCHEME}{}", self.address), &pairs);
        if pairs.is_empty() {
            link.to_ascii_uppercase()
        } else {
            link
        }
    }

    /// The route entries a link may carry: `http` and `tor`.
    fn link_routes(&self) -> impl Iterator<Item = &RouteEntry> {
        self.routes
            .iter()
            .filter(|route| matches!(route.method, MethodId::Http | MethodId::Tor))
    }
}

fn with_query(mut text: String, pairs: &[String]) -> String {
    if !pairs.is_empty() {
        text.push('?');
        text.push_str(&pairs.join("&"));
    }
    text
}

fn route_pair(route: &RouteEntry) -> String {
    format!("{}={}", route.method, percent_encode(&route.value))
}

/// The canonical form of a decoded `http` or `tor` value, or why it cannot be used.
fn canonical_value(method: MethodId, value: &str) -> Result<String, TransportFault> {
    let (host, port) = if method == MethodId::Tor {
        let (host, port) = onion_host_port(value).ok_or(TransportFault::Onion)?;
        (host.to_owned(), port)
    } else {
        let (host, port) = parse_host_port(value).map_err(TransportFault::Http)?;
        (host.to_string(), port)
    };
    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
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
