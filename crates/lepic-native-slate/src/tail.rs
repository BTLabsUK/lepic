// SPDX-License-Identifier: Apache-2.0
//! The extension tail: records after the slate body, each a `u8` type, a big-endian `u16` length
//! and the value, with types strictly increasing.
//!
//! Types `01` (reply key) and `02` (reply mailbox) are known and must have exactly their defined
//! form. An unknown type below `0x80` refuses the slate; one from `0x80` up is kept verbatim and
//! in order, so that encoding a decoded slate gives back its bytes.

use lepic_crypto::PublicKey;
use lepic_slate::stage::{Stage, Step};

use crate::error::TailError;

/// Record type of the reply key.
pub const REPLY_KEY: u8 = 0x01;
/// Record type of the reply mailbox.
pub const REPLY_MAILBOX: u8 = 0x02;
/// Lowest record type a reader that does not know it may skip.
pub const FIRST_IGNORABLE: u8 = 0x80;
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

/// A record of a type this build does not know, from `0x80` up, kept as it came.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownRecord {
    record_type: u8,
    value: Vec<u8>,
}

impl UnknownRecord {
    /// Accepts types from `0x80` up and values of at most 65,535 bytes.
    pub fn new(record_type: u8, value: Vec<u8>) -> Result<Self, TailError> {
        if record_type < FIRST_IGNORABLE {
            return Err(TailError::UnknownRequired { record_type });
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
    unknown: Vec<UnknownRecord>,
}

impl Tail {
    /// The tail of every slate inside an envelope.
    pub const fn empty() -> Self {
        Self {
            reply_key: None,
            reply_mailbox: None,
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
            unknown,
        })
    }

    pub const fn reply_key(&self) -> Option<&ReplyKey> {
        self.reply_key.as_ref()
    }

    pub const fn reply_mailbox(&self) -> Option<&ReplyMailbox> {
        self.reply_mailbox.as_ref()
    }

    /// Records of unknown types, in the order they came.
    pub fn unknown(&self) -> &[UnknownRecord] {
        &self.unknown
    }

    pub fn is_empty(&self) -> bool {
        self.reply_key.is_none() && self.reply_mailbox.is_none() && self.unknown.is_empty()
    }

    /// Known records are allowed only while a slate is proposed (S1, I1).
    pub(crate) fn check_stage(&self, stage: Stage) -> Result<(), TailError> {
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
        let mut unknown = Vec::new();
        while let Some((&record_type, after_type)) = rest.split_first() {
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
                FIRST_IGNORABLE.. => unknown.push(UnknownRecord {
                    record_type,
                    value: value.to_vec(),
                }),
                _ => return Err(TailError::UnknownRequired { record_type }),
            }
            previous = Some(record_type);
            rest = after_value;
        }
        let tail = Self::new(reply_key, reply_mailbox, unknown)?;
        tail.check_stage(stage)?;
        Ok(tail)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        if let Some(key) = &self.reply_key {
            write_record(out, REPLY_KEY, key.as_bytes());
        }
        if let Some(mailbox) = &self.reply_mailbox {
            let mut value = mailbox.key.to_bytes().to_vec();
            value.extend_from_slice(mailbox.address.as_bytes());
            write_record(out, REPLY_MAILBOX, &value);
        }
        for record in &self.unknown {
            write_record(out, record.record_type, &record.value);
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

fn is_port(port: &str) -> bool {
    (1..=5).contains(&port.len())
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests;
