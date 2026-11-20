// SPDX-License-Identifier: Apache-2.0
//! The `epiccash://<kind>/<version>/<payload>` links and the checksummed base64url payload they
//! and the armor share: `base64url(bytes || H(H(bytes))[0..4])`, without padding.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{DecodeError, Malformed};
use crate::hash::checksum;

const SCHEME: &str = "epiccash://";

/// The base64url length of `n` bytes without padding, rounded up.
fn encoded_len(bytes: usize) -> usize {
    bytes.saturating_mul(4).div_ceil(3)
}

pub fn encode_checked(bytes: &[u8]) -> String {
    let mut payload = Vec::with_capacity(bytes.len().saturating_add(4));
    payload.extend_from_slice(bytes);
    payload.extend_from_slice(&checksum(bytes));
    URL_SAFE_NO_PAD.encode(payload)
}

/// Decodes a checksummed payload whose bytes may be at most `max_bytes` long; the text length is
/// checked first, so nothing larger than the input is allocated.
pub fn decode_checked(text: &str, max_bytes: usize) -> Result<Vec<u8>, DecodeError> {
    let limit = encoded_len(max_bytes.saturating_add(4));
    if text.len() > limit {
        return Err(DecodeError::Oversized {
            limit,
            found: text.len(),
        });
    }
    let mut payload = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Malformed::PayloadText)?;
    let split = payload.len().checked_sub(4).ok_or(Malformed::Truncated)?;
    let sum = payload.split_off(split);
    if sum != checksum(&payload) {
        return Err(DecodeError::Damaged);
    }
    Ok(payload)
}

/// The kinds of `epiccash://` link this crate reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// `contact/1/`: a contact card (RFC 0002 6.2).
    Contact,
    /// `pair/1/`: an invite (7.1).
    Pair,
    /// `pair-reply/1/`: a pairing reply envelope sent by hand (7.2).
    PairReply,
    /// `pair-confirm/1/`: a pairing confirm envelope sent by hand (7.3).
    PairConfirm,
}

impl LinkKind {
    fn path(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Pair => "pair",
            Self::PairReply => "pair-reply",
            Self::PairConfirm => "pair-confirm",
        }
    }
}

const LINK_VERSION: u8 = 1;

pub fn encode_link(kind: LinkKind, bytes: &[u8]) -> String {
    format!(
        "{SCHEME}{}/{LINK_VERSION}/{}",
        kind.path(),
        encode_checked(bytes)
    )
}

/// Reads a link of `kind`. Surrounding whitespace is ignored and the scheme matches in any case,
/// as URI schemes do; a higher version than this crate writes is "made by a newer wallet".
pub fn decode_link(text: &str, kind: LinkKind, max_bytes: usize) -> Result<Vec<u8>, DecodeError> {
    let text = text.trim();
    let scheme = text
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .ok_or(Malformed::LinkPrefix)?;
    let rest = text
        .get(scheme.len()..)
        .and_then(|rest| rest.strip_prefix(kind.path()))
        .and_then(|rest| rest.strip_prefix('/'))
        .ok_or(Malformed::LinkPrefix)?;
    let (version, payload) = rest.split_once('/').ok_or(Malformed::LinkPrefix)?;
    let version = parse_version(version)?;
    if version > LINK_VERSION {
        return Err(DecodeError::NewerVersion { found: version });
    }
    if version != LINK_VERSION {
        return Err(Malformed::LinkPrefix.into());
    }
    decode_checked(payload, max_bytes)
}

fn parse_version(text: &str) -> Result<u8, DecodeError> {
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Malformed::LinkPrefix.into());
    }
    text.parse::<u8>().map_err(|_| Malformed::LinkPrefix.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_link() {
        let link = encode_link(LinkKind::Pair, b"invite bytes");
        assert!(link.starts_with("epiccash://pair/1/"));
        assert_eq!(
            decode_link(&link, LinkKind::Pair, 64).unwrap(),
            b"invite bytes"
        );
        let shouted = link.replacen("epiccash", "EPICCASH", 1);
        assert_eq!(
            decode_link(&format!("  {shouted}\n"), LinkKind::Pair, 64).unwrap(),
            b"invite bytes"
        );
    }

    #[test]
    fn rejects_another_kind_of_link() {
        let link = encode_link(LinkKind::Pair, b"x");
        assert_eq!(
            decode_link(&link, LinkKind::PairReply, 64),
            Err(Malformed::LinkPrefix.into())
        );
        assert_eq!(
            decode_link(&link, LinkKind::Contact, 64),
            Err(Malformed::LinkPrefix.into())
        );
    }

    #[test]
    fn a_higher_link_version_is_from_a_newer_wallet() {
        let link = encode_link(LinkKind::Contact, b"x").replacen("/1/", "/2/", 1);
        assert_eq!(
            decode_link(&link, LinkKind::Contact, 64),
            Err(DecodeError::NewerVersion { found: 2 })
        );
    }

    #[test]
    fn a_changed_character_is_damage() {
        let link = encode_link(LinkKind::Contact, b"some card bytes");
        let mut bytes = link.into_bytes();
        let last = bytes.len() - 3;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let link = String::from_utf8(bytes).unwrap();
        assert_eq!(
            decode_link(&link, LinkKind::Contact, 64),
            Err(DecodeError::Damaged)
        );
    }

    #[test]
    fn rejects_padding_and_foreign_characters() {
        let payload = encode_checked(b"ab");
        assert_eq!(
            decode_checked(&format!("{payload}="), 64),
            Err(Malformed::PayloadText.into())
        );
        assert_eq!(
            decode_checked("a+b/", 64),
            Err(Malformed::PayloadText.into())
        );
    }

    #[test]
    fn checks_the_length_before_decoding() {
        let payload = encode_checked(&[0; 100]);
        assert!(matches!(
            decode_checked(&payload, 99),
            Err(DecodeError::Oversized { .. })
        ));
        assert!(decode_checked(&payload, 100).is_ok());
    }
}
