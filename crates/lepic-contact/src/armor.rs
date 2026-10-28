// SPDX-License-Identifier: Apache-2.0
//! Armored text of an envelope (RFC 0002 3.5): `BEGINEPICSEALED. <payload>. ENDEPICSEALED.`,
//! framed as RFC 0001 section 7 frames slatepack-style text.

use crate::envelope::MAX_ENVELOPE_LEN;
use crate::error::{DecodeError, Malformed};
use crate::link::{decode_checked, encode_checked};

pub const MAX_ARMOR_LEN: usize = 96 * 1024;
pub const SEALED_FILE_EXTENSION: &str = "epicsealed";

const HEADER: &str = "BEGINEPICSEALED";
const FOOTER: &str = "ENDEPICSEALED";
const LINE_LEN: usize = 76;
/// The header, the footer, their periods and the spaces after them.
const FRAMING_LEN: usize = HEADER.len() + FOOTER.len() + 4;

fn is_framing_noise(c: char) -> bool {
    matches!(c, '>' | '\n' | '\r' | '\t' | ' ')
}

/// The armored text of an envelope, `BEGINEPICSEALED. <payload>. ENDEPICSEALED.`, its payload
/// broken into lines of 76 characters.
pub fn armor(envelope: &[u8]) -> String {
    let payload = encode_checked(envelope);
    let mut text = String::with_capacity(
        payload
            .len()
            .saturating_add(payload.len().checked_div(LINE_LEN).unwrap_or(0))
            .saturating_add(FRAMING_LEN),
    );
    text.push_str(HEADER);
    text.push_str(". ");
    let mut rest = payload.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(LINE_LEN));
        text.push_str(line);
        if !tail.is_empty() {
            text.push('\n');
        }
        rest = tail;
    }
    text.push_str(". ");
    text.push_str(FOOTER);
    text.push('.');
    text
}

/// The envelope bytes inside armored text. The length is checked before anything is decoded;
/// a wrong checksum is [`DecodeError::Damaged`].
pub fn dearmor(text: &str) -> Result<Vec<u8>, DecodeError> {
    if text.len() > MAX_ARMOR_LEN {
        return Err(DecodeError::Oversized {
            limit: MAX_ARMOR_LEN,
            found: text.len(),
        });
    }
    let mut parts = text.splitn(4, '.');
    let (Some(header), Some(payload), Some(footer)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Malformed::Framing.into());
    };
    if header.trim_matches(is_framing_noise) != HEADER
        || footer.trim_matches(is_framing_noise) != FOOTER
    {
        return Err(Malformed::Framing.into());
    }
    let payload: String = payload.chars().filter(|c| !is_framing_noise(*c)).collect();
    decode_checked(&payload, MAX_ENVELOPE_LEN)
}

/// Whether text from a mailbox or a paste is armored sealed text rather than a plain slate.
pub fn looks_sealed(text: &str) -> bool {
    text.trim_start().starts_with(HEADER)
}
