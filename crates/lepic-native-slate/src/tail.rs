// SPDX-License-Identifier: Apache-2.0
//! The extension tail: records after the slate body, each a `u8` type, a big-endian `u16` length
//! and the value, with types strictly increasing.
//!
//! Types `01` (reply key) and `02` (reply mailbox) are known and must have exactly their defined
//! form. An unknown type below `0x80` refuses the slate; one from `0x80` up is kept verbatim and
//! in order, so that encoding a decoded slate gives back its bytes.
//!
//! Two known types sit in the ignorable range, so a reader that predates them passes over them:
//! `81` (direct route) and `F0` (request claim). Both belong to a checkout request and are allowed
//! on an I1 only. The request claim is always the last record, because its signature covers every
//! byte before it.

use lepic_crypto::PublicKey;
use lepic_slate::stage::{Stage, Step};

use crate::error::TailError;

/// Record type of the reply key.
pub const REPLY_KEY: u8 = 0x01;
/// Record type of the reply mailbox.
pub const REPLY_MAILBOX: u8 = 0x02;
/// Record type of the direct route of a checkout request.
pub const DIRECT_ROUTE: u8 = 0x81;
/// Record type of the request claim of a checkout request; always the last record.
pub const REQUEST_CLAIM: u8 = 0xF0;
/// Lowest record type a reader that does not know it may skip.
pub const FIRST_IGNORABLE: u8 = 0x80;
/// The most entries a direct route holds.
pub const MAX_DIRECT_ENTRIES: usize = 4;
/// Longest `host[:port]` of a direct route entry, in bytes.
pub const MAX_DIRECT_ADDRESS_LEN: usize = 128;
/// Longest domain of a request claim, in bytes, as in DNS.
pub const MAX_CLAIM_DOMAIN_LEN: usize = 253;
/// Characters in the name of an onion service, before `.onion`.
const ONION_NAME_LEN: usize = 56;
/// Longest relay `domain[:port]` in a reply mailbox, in bytes.
pub const MAX_MAILBOX_ADDRESS_LEN: usize = 128;

/// An X25519 public key the answer to a raw S1 or I1 is sealed to.
///
/// Only its length is checked here: the key is decoded where it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyKey([u8; ReplyKey::LEN]);

impl ReplyKey {
    pub const LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// The Epicbox mailbox the answer to a raw S1 or I1 is posted to: its key and its relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyMailbox {
    key: PublicKey,
    address: String,
}

impl ReplyMailbox {
    /// Accepts a relay `domain[:port]` of 1–128 ASCII bytes, the domain a `relay-domain` (labels
    /// of letters and digits as Epicbox addresses allow, or an IPv4 literal) and the port
    /// 1–65535. Case is kept.
    pub fn new(key: PublicKey, address: String) -> Result<Self, TailError> {
        if !is_mailbox_address(&address) {
            return Err(TailError::MailboxAddress);
        }
        Ok(Self { key, address })
    }

    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The relay as `domain[:port]`.
    pub fn address(&self) -> &str {
        &self.address
    }

    fn decode(value: &[u8]) -> Result<Self, TailError> {
        let length = || TailError::Length {
            record_type: REPLY_MAILBOX,
            len: value.len(),
        };
        let (key, address) = value.split_at_checked(PublicKey::LEN).ok_or_else(length)?;
        if address.is_empty() || address.len() > MAX_MAILBOX_ADDRESS_LEN {
            return Err(length());
        }
        let key = PublicKey::from_bytes(key).map_err(TailError::MailboxKey)?;
        let address = std::str::from_utf8(address).map_err(|_| TailError::MailboxAddress)?;
        Self::new(key, address.to_owned())
    }
}

/// How the payer reaches a direct route entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirectMethod {
    /// HTTPS to `host[:port]`, port 443 when none is given.
    Http,
    /// Tor to a v3 onion service `<56 base32>.onion[:port]`, port 80 when none is given.
    Tor,
}

impl DirectMethod {
    /// The method byte on the wire: 1 for http, 2 for tor.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Http => 1,
            Self::Tor => 2,
        }
    }

    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Http),
            2 => Some(Self::Tor),
            _ => None,
        }
    }

    /// The text form, as in an epic1 link entry: `http` or `tor`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tor => "tor",
        }
    }
}

/// One place the payer posts its sealed answer to directly, besides the reply mailbox.
///
/// The address is canonical lower-case text. For http it is `host[:port]` of at most 128 bytes,
/// where the host is a DNS name (labels of `a-z`, `0-9` and `-`, 1–63 bytes, not led or ended by
/// a hyphen, no trailing dot) or an IPv4 literal, and never a `.onion` name. Hyphens are allowed,
/// unlike the relay rule epic1 links use, because a shop's own host often has them. For tor it is
/// `<56 of a-z2-7>.onion[:port]`, the form of an epic1 tor entry. Only the form is checked: the
/// poster applies the host rule of `lepic-transport` (no loopback) and the onion checksum before
/// it connects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirectEntry {
    method: DirectMethod,
    address: String,
}

impl DirectEntry {
    /// Accepts an address of 1–128 bytes in the canonical form of `method`.
    pub fn new(method: DirectMethod, address: String) -> Result<Self, TailError> {
        let valid = match method {
            DirectMethod::Http => is_http_address(&address),
            DirectMethod::Tor => is_onion_address(&address),
        };
        if !valid {
            return Err(TailError::DirectAddress);
        }
        Ok(Self { method, address })
    }

    pub const fn method(&self) -> DirectMethod {
        self.method
    }

    /// The address as `host[:port]`.
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// The direct route of a checkout request: 1–4 distinct entries, in the payee's order.
///
/// Wire value: each entry as `method (1) || len (1) || address`, back to back. An unknown method
/// byte refuses the record, so a new method needs a new record type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirectRoute(Vec<DirectEntry>);

impl DirectRoute {
    pub fn new(entries: Vec<DirectEntry>) -> Result<Self, TailError> {
        if entries.is_empty() || entries.len() > MAX_DIRECT_ENTRIES {
            return Err(TailError::DirectEntryCount {
                count: entries.len(),
            });
        }
        for (at, entry) in entries.iter().enumerate() {
            if entries.iter().take(at).any(|earlier| earlier == entry) {
                return Err(TailError::DirectDuplicate);
            }
        }
        Ok(Self(entries))
    }

    pub fn entries(&self) -> &[DirectEntry] {
        &self.0
    }

    fn encode(&self) -> Vec<u8> {
        let mut value = Vec::new();
        for entry in &self.0 {
            // An address is at most 128 bytes, checked when the entry was built.
            let len = u8::try_from(entry.address.len()).unwrap_or(u8::MAX);
            value.push(entry.method.byte());
            value.push(len);
            value.extend_from_slice(entry.address.as_bytes());
        }
        value
    }

    fn decode(value: &[u8]) -> Result<Self, TailError> {
        let mut rest = value;
        let mut entries = Vec::new();
        while let Some((&[method, len], after)) = rest.split_first_chunk::<2>() {
            if entries.len() == MAX_DIRECT_ENTRIES {
                return Err(TailError::DirectEntryCount {
                    count: entries.len().saturating_add(1),
                });
            }
            let method =
                DirectMethod::from_byte(method).ok_or(TailError::DirectMethod { byte: method })?;
            let (address, after) = after
                .split_at_checked(usize::from(len))
                .ok_or(TailError::Truncated)?;
            let address = std::str::from_utf8(address).map_err(|_| TailError::DirectAddress)?;
            entries.push(DirectEntry::new(method, address.to_owned())?);
            rest = after;
        }
        if !rest.is_empty() {
            return Err(TailError::Truncated);
        }
        Self::new(entries)
    }
}

/// The request claim of a checkout request: the payee says it speaks for `domain` and signs the
/// whole code with its domain key (ADR 0043).
///
/// Wire value: `key (32) || issued_at (u64 BE, 8) || signature (64) || domain (1–253)`. The
/// domain is a lower-case DNS name: labels of `a-z`, `0-9` and `-`, not led or ended by a hyphen,
/// at least two labels, no trailing dot. Neither the key nor the signature is checked here; the
/// signature covers the code up to the start of this record (see [`RequestClaim::signed_part`])
/// and is checked by `lepic-seal`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestClaim {
    key: [u8; RequestClaim::KEY_LEN],
    issued_at: u64,
    signature: [u8; RequestClaim::SIGNATURE_LEN],
    domain: String,
}

impl RequestClaim {
    pub const KEY_LEN: usize = 32;
    pub const SIGNATURE_LEN: usize = 64;
    /// The bytes of the value before the domain.
    const FIXED_LEN: usize = Self::KEY_LEN + 8 + Self::SIGNATURE_LEN;

    /// Accepts a domain in the canonical form above.
    pub fn new(
        key: [u8; Self::KEY_LEN],
        issued_at: u64,
        signature: [u8; Self::SIGNATURE_LEN],
        domain: String,
    ) -> Result<Self, TailError> {
        if !is_claim_domain(&domain) {
            return Err(TailError::ClaimDomain);
        }
        Ok(Self {
            key,
            issued_at,
            signature,
            domain,
        })
    }

    /// The Ed25519 domain key that signed the code.
    pub const fn key(&self) -> &[u8; Self::KEY_LEN] {
        &self.key
    }

    /// Unix seconds when the code was signed.
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn signature(&self) -> &[u8; Self::SIGNATURE_LEN] {
        &self.signature
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The record value, as written after the type and length.
    pub fn value(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(Self::FIXED_LEN.saturating_add(self.domain.len()));
        value.extend_from_slice(&self.key);
        value.extend_from_slice(&self.issued_at.to_be_bytes());
        value.extend_from_slice(&self.signature);
        value.extend_from_slice(self.domain.as_bytes());
        value
    }

    /// The whole record: type `F0`, the length and the value.
    pub fn record(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_record(&mut out, REQUEST_CLAIM, &self.value());
        out
    }

    /// The bytes the signature covers: `code` up to the start of this record, when `code` ends
    /// with exactly this record. `None` otherwise.
    pub fn signed_part<'a>(&self, code: &'a [u8]) -> Option<&'a [u8]> {
        let record = self.record();
        let start = code.len().checked_sub(record.len())?;
        let (signed, last) = code.split_at_checked(start)?;
        (last == record.as_slice()).then_some(signed)
    }

    fn decode(value: &[u8]) -> Result<Self, TailError> {
        let length = || TailError::Length {
            record_type: REQUEST_CLAIM,
            len: value.len(),
        };
        let (key, rest) = value
            .split_first_chunk::<{ Self::KEY_LEN }>()
            .ok_or_else(length)?;
        let (issued_at, rest) = rest.split_first_chunk::<8>().ok_or_else(length)?;
        let (signature, domain) = rest
            .split_first_chunk::<{ Self::SIGNATURE_LEN }>()
            .ok_or_else(length)?;
        if domain.is_empty() || domain.len() > MAX_CLAIM_DOMAIN_LEN {
            return Err(length());
        }
        let domain = std::str::from_utf8(domain).map_err(|_| TailError::ClaimDomain)?;
        Self::new(
            *key,
            u64::from_be_bytes(*issued_at),
            *signature,
            domain.to_owned(),
        )
    }
}

/// A record of a type this build does not know, from `0x80` up, kept as it came.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownRecord {
    record_type: u8,
    value: Vec<u8>,
}

impl UnknownRecord {
    /// Accepts types from `0x80` up, other than the known [`DIRECT_ROUTE`] and
    /// [`REQUEST_CLAIM`], and values of at most 65,535 bytes.
    pub fn new(record_type: u8, value: Vec<u8>) -> Result<Self, TailError> {
        if record_type < FIRST_IGNORABLE {
            return Err(TailError::UnknownRequired { record_type });
        }
        if matches!(record_type, DIRECT_ROUTE | REQUEST_CLAIM) {
            return Err(TailError::KnownType { record_type });
        }
        if u16::try_from(value.len()).is_err() {
            return Err(TailError::Length {
                record_type,
                len: value.len(),
            });
        }
        Ok(Self { record_type, value })
    }

    pub const fn record_type(&self) -> u8 {
        self.record_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// The records of an extension tail.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tail {
    reply_key: Option<ReplyKey>,
    reply_mailbox: Option<ReplyMailbox>,
    direct_route: Option<DirectRoute>,
    request_claim: Option<RequestClaim>,
    unknown: Vec<UnknownRecord>,
}

impl Tail {
    /// The tail of every slate inside an envelope.
    pub const fn empty() -> Self {
        Self {
            reply_key: None,
            reply_mailbox: None,
            direct_route: None,
            request_claim: None,
            unknown: Vec::new(),
        }
    }

    /// Checks that a mailbox comes with a key and that unknown record types strictly increase.
    pub fn new(
        reply_key: Option<ReplyKey>,
        reply_mailbox: Option<ReplyMailbox>,
        unknown: Vec<UnknownRecord>,
    ) -> Result<Self, TailError> {
        if reply_mailbox.is_some() && reply_key.is_none() {
            return Err(TailError::MailboxWithoutKey);
        }
        for pair in unknown.windows(2) {
            if let [previous, next] = pair
                && next.record_type <= previous.record_type
            {
                return Err(TailError::Order {
                    previous: previous.record_type,
                    found: next.record_type,
                });
            }
        }
        Ok(Self {
            reply_key,
            reply_mailbox,
            direct_route: None,
            request_claim: None,
            unknown,
        })
    }

    /// This tail with `route` as its direct route.
    #[must_use]
    pub fn with_direct_route(mut self, route: DirectRoute) -> Self {
        self.direct_route = Some(route);
        self
    }

    /// This tail with `claim` as its request claim. Refused when an unknown record would follow
    /// the claim, which is always last.
    pub fn with_request_claim(mut self, claim: RequestClaim) -> Result<Self, TailError> {
        if self
            .unknown
            .iter()
            .any(|record| record.record_type > REQUEST_CLAIM)
        {
            return Err(TailError::ClaimNotLast);
        }
        self.request_claim = Some(claim);
        Ok(self)
    }

    /// This tail without its request claim: the tail a code is signed over.
    #[must_use]
    pub fn without_request_claim(mut self) -> Self {
        self.request_claim = None;
        self
    }

    pub const fn reply_key(&self) -> Option<&ReplyKey> {
        self.reply_key.as_ref()
    }

    pub const fn reply_mailbox(&self) -> Option<&ReplyMailbox> {
        self.reply_mailbox.as_ref()
    }

    pub const fn direct_route(&self) -> Option<&DirectRoute> {
        self.direct_route.as_ref()
    }

    pub const fn request_claim(&self) -> Option<&RequestClaim> {
        self.request_claim.as_ref()
    }

    /// Records of unknown types, in the order they came.
    pub fn unknown(&self) -> &[UnknownRecord] {
        &self.unknown
    }

    pub fn is_empty(&self) -> bool {
        self.reply_key.is_none()
            && self.reply_mailbox.is_none()
            && self.direct_route.is_none()
            && self.request_claim.is_none()
            && self.unknown.is_empty()
    }

    /// Known records are allowed only while a slate is proposed (S1, I1), and those of a checkout
    /// request on an I1 only.
    pub(crate) fn check_stage(&self, stage: Stage) -> Result<(), TailError> {
        if stage != Stage::I1 {
            let request = if self.direct_route.is_some() {
                Some(DIRECT_ROUTE)
            } else if self.request_claim.is_some() {
                Some(REQUEST_CLAIM)
            } else {
                None
            };
            if let Some(record_type) = request {
                return Err(TailError::NotAllowed { record_type, stage });
            }
        }
        if stage.step() == Step::Proposed {
            return Ok(());
        }
        let record_type = if self.reply_key.is_some() {
            REPLY_KEY
        } else if self.reply_mailbox.is_some() {
            REPLY_MAILBOX
        } else {
            return Ok(());
        };
        Err(TailError::NotAllowed { record_type, stage })
    }

    /// Reads every record up to the end of `bytes`.
    pub(crate) fn decode(bytes: &[u8], stage: Stage) -> Result<Self, TailError> {
        let mut rest = bytes;
        let mut previous: Option<u8> = None;
        let mut reply_key = None;
        let mut reply_mailbox = None;
        let mut direct_route = None;
        let mut request_claim = None;
        let mut unknown = Vec::new();
        while let Some((&record_type, after_type)) = rest.split_first() {
            if request_claim.is_some() {
                return Err(TailError::ClaimNotLast);
            }
            let (length, after_length) = after_type
                .split_first_chunk::<2>()
                .ok_or(TailError::Truncated)?;
            let (value, after_value) = after_length
                .split_at_checked(usize::from(u16::from_be_bytes(*length)))
                .ok_or(TailError::Truncated)?;
            if let Some(previous) = previous
                && record_type <= previous
            {
                return Err(TailError::Order {
                    previous,
                    found: record_type,
                });
            }
            match record_type {
                REPLY_KEY => {
                    let key =
                        <[u8; ReplyKey::LEN]>::try_from(value).map_err(|_| TailError::Length {
                            record_type,
                            len: value.len(),
                        })?;
                    reply_key = Some(ReplyKey(key));
                }
                REPLY_MAILBOX => reply_mailbox = Some(ReplyMailbox::decode(value)?),
                DIRECT_ROUTE => direct_route = Some(DirectRoute::decode(value)?),
                REQUEST_CLAIM => request_claim = Some(RequestClaim::decode(value)?),
                FIRST_IGNORABLE.. => unknown.push(UnknownRecord {
                    record_type,
                    value: value.to_vec(),
                }),
                _ => return Err(TailError::UnknownRequired { record_type }),
            }
            previous = Some(record_type);
            rest = after_value;
        }
        let mut tail = Self::new(reply_key, reply_mailbox, unknown)?;
        tail.direct_route = direct_route;
        if let Some(claim) = request_claim {
            tail = tail.with_request_claim(claim)?;
        }
        tail.check_stage(stage)?;
        Ok(tail)
    }

    /// Writes every record in increasing type order: the known ones and the unknown ones
    /// between them.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let mut records: Vec<(u8, Vec<u8>)> = Vec::new();
        if let Some(key) = &self.reply_key {
            records.push((REPLY_KEY, key.as_bytes().to_vec()));
        }
        if let Some(mailbox) = &self.reply_mailbox {
            let mut value = mailbox.key.to_bytes().to_vec();
            value.extend_from_slice(mailbox.address.as_bytes());
            records.push((REPLY_MAILBOX, value));
        }
        if let Some(route) = &self.direct_route {
            records.push((DIRECT_ROUTE, route.encode()));
        }
        if let Some(claim) = &self.request_claim {
            records.push((REQUEST_CLAIM, claim.value()));
        }
        records.extend(
            self.unknown
                .iter()
                .map(|record| (record.record_type, record.value.clone())),
        );
        // Types are distinct: known ones once each, unknown ones increasing and never a known
        // type, so this order is the one decoding requires.
        records.sort_by_key(|(record_type, _)| *record_type);
        for (record_type, value) in &records {
            write_record(out, *record_type, value);
        }
    }
}

/// Every value written here was checked to fit a `u16` length when its record was built.
fn write_record(out: &mut Vec<u8>, record_type: u8, value: &[u8]) {
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    out.push(record_type);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.get(..usize::from(len)).unwrap_or(value));
}

/// `relay-domain [":" port]`, 1–128 bytes, as in the specification's Appendix B.2.
fn is_mailbox_address(address: &str) -> bool {
    if address.is_empty() || address.len() > MAX_MAILBOX_ADDRESS_LEN {
        return false;
    }
    let (domain, port) = match address.split_once(':') {
        Some((domain, port)) => (domain, Some(port)),
        None => (address, None),
    };
    if !domain.split('.').all(is_label) || !port.is_none_or(is_port) {
        return false;
    }
    // A last label led by a digit makes the domain an IPv4 literal: four decimal numbers up to
    // 255 without leading zeros, which is what `Ipv4Addr` parses.
    let last = domain.rsplit('.').next().unwrap_or(domain);
    !last.starts_with(|c: char| c.is_ascii_digit()) || domain.parse::<std::net::Ipv4Addr>().is_ok()
}

/// 1–63 letters and digits: Epicbox's own address rule, which has no hyphens.
fn is_label(label: &str) -> bool {
    (1..=63).contains(&label.len()) && label.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// An http entry: `host[:port]` of 1–128 bytes, the host a lower-case DNS name or an IPv4
/// literal, and not an onion name (tor has its own method).
fn is_http_address(address: &str) -> bool {
    if address.is_empty() || address.len() > MAX_DIRECT_ADDRESS_LEN {
        return false;
    }
    let (host, port) = match address.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (address, None),
    };
    if !host.split('.').all(is_dns_label) || host.ends_with(".onion") || !port.is_none_or(is_port) {
        return false;
    }
    // As for a mailbox address: a last label led by a digit makes the host an IPv4 literal.
    let last = host.rsplit('.').next().unwrap_or(host);
    !last.starts_with(|c: char| c.is_ascii_digit()) || host.parse::<std::net::Ipv4Addr>().is_ok()
}

/// A DNS label: 1–63 bytes of `a-z`, `0-9` and `-`, not led or ended by a hyphen.
fn is_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A tor entry: exactly `<56 of a-z2-7>.onion[:port]`.
fn is_onion_address(address: &str) -> bool {
    let (host, port) = match address.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (address, None),
    };
    let Some(name) = host.strip_suffix(".onion") else {
        return false;
    };
    name.len() == ONION_NAME_LEN
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
        && port.is_none_or(is_port)
}

/// A lower-case DNS name of 1–253 bytes with at least two labels.
fn is_claim_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_CLAIM_DOMAIN_LEN {
        return false;
    }
    let mut labels = 0usize;
    for label in domain.split('.') {
        labels = labels.saturating_add(1);
        if !is_dns_label(label) {
            return false;
        }
    }
    labels >= 2
}

fn is_port(port: &str) -> bool {
    (1..=5).contains(&port.len())
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests;
