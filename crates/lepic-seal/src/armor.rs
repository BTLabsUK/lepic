// SPDX-License-Identifier: Apache-2.0
//! Armored text of an envelope (RFC 0002 3.5): `BEGINEPICSEALED. <payload>. ENDEPICSEALED.`,
//! framed as RFC 0001 section 7 frames slatepack-style text. A `lepic.v1` slate envelope uses
//! `BEGINEPICTX. <payload>. ENDEPICTX.` (RFC 0003 5.11); readers take either pair.

use crate::envelope::MAX_ENVELOPE_LEN;
use thiserror::Error;

use crate::error::{DecodeError, Malformed};
use crate::link::{decode_checked, encode_checked};

pub const MAX_ARMOR_LEN: usize = 96 * 1024;
pub const SEALED_FILE_EXTENSION: &str = "epicsealed";

const HEADER: &str = "BEGINEPICSEALED";
const FOOTER: &str = "ENDEPICSEALED";
const TX_HEADER: &str = "BEGINEPICTX";
const TX_FOOTER: &str = "ENDEPICTX";
const LINE_LEN: usize = 76;
/// The longer header, its footer, their periods and the spaces after them.
const FRAMING_LEN: usize = HEADER.len() + FOOTER.len() + 4;

/// Which marker pair frames armored text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmorMarker {
    /// `BEGINEPICSEALED.` and `ENDEPICSEALED.`: every RFC 0002 envelope.
    Sealed,
    /// `BEGINEPICTX.` and `ENDEPICTX.`: a `lepic.v1` slate envelope (type 0A) only.
    Tx,
}

impl ArmorMarker {
    fn header(self) -> &'static str {
        match self {
            Self::Sealed => HEADER,
            Self::Tx => TX_HEADER,
        }
    }

    fn footer(self) -> &'static str {
        match self {
            Self::Sealed => FOOTER,
            Self::Tx => TX_FOOTER,
        }
    }
}

fn is_framing_noise(c: char) -> bool {
    matches!(c, '>' | '\n' | '\r' | '\t' | ' ')
}

/// The armored text of an envelope, `BEGINEPICSEALED. <payload>. ENDEPICSEALED.`, its payload
/// broken into lines of 76 characters.
pub fn armor(envelope: &[u8]) -> String {
    armor_with(envelope, ArmorMarker::Sealed)
}

/// The armored text of a `lepic.v1` slate envelope, `BEGINEPICTX. <payload>. ENDEPICTX.`, its
/// payload broken into lines of 76 characters.
pub fn armor_tx(envelope: &[u8]) -> String {
    armor_with(envelope, ArmorMarker::Tx)
}

fn armor_with(envelope: &[u8], marker: ArmorMarker) -> String {
    let payload = encode_checked(envelope);
    let mut text = String::with_capacity(
        payload
            .len()
            .saturating_add(payload.len().checked_div(LINE_LEN).unwrap_or(0))
            .saturating_add(FRAMING_LEN),
    );
    text.push_str(marker.header());
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
    text.push_str(marker.footer());
    text.push('.');
    text
}

/// The envelope bytes inside armored text of either marker pair. The length is checked before
/// anything is decoded; a wrong checksum is [`DecodeError::Damaged`].
pub fn dearmor(text: &str) -> Result<Vec<u8>, DecodeError> {
    Ok(dearmor_marked(text)?.0)
}

/// [`dearmor`], with the marker pair that framed the text. The header and the footer must be
/// of the same pair.
pub fn dearmor_marked(text: &str) -> Result<(Vec<u8>, ArmorMarker), DecodeError> {
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
    let marker = match header.trim_matches(is_framing_noise) {
        HEADER => ArmorMarker::Sealed,
        TX_HEADER => ArmorMarker::Tx,
        _ => return Err(Malformed::Framing.into()),
    };
    if footer.trim_matches(is_framing_noise) != marker.footer() {
        return Err(Malformed::Framing.into());
    }
    let payload: String = payload.chars().filter(|c| !is_framing_noise(*c)).collect();
    Ok((decode_checked(&payload, MAX_ENVELOPE_LEN)?, marker))
}

/// Whether text from a mailbox or a paste is armored sealed text rather than a plain slate.
/// Only the RFC 0002 marker counts; [`classify`] knows both.
pub fn looks_sealed(text: &str) -> bool {
    text.trim_start().starts_with(HEADER)
}

/// What a payment file holds, by its content (RFC 0003 5.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentFile {
    /// Armored text of either marker pair.
    Armour,
    /// A JSON slate.
    LegacyJson,
}

/// Why a file is not a payment file this wallet reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClassifyError {
    /// Hex digits only, of even length: a saved transaction of the stock wallet, not a slate.
    #[error("the file is a saved transaction, not a slate")]
    StockSavedTx,
    #[error("the file is not a payment file")]
    NotPaymentFile,
}

/// Classifies a payment file by content (RFC 0003 5.12). After leading whitespace and `>`: an
/// armor marker is [`PaymentFile::Armour`]; else hex digits only, of even length once trailing
/// whitespace is cut, are [`ClassifyError::StockSavedTx`]; else `{` is
/// [`PaymentFile::LegacyJson`]; anything else is [`ClassifyError::NotPaymentFile`].
pub fn classify(data: &[u8]) -> Result<PaymentFile, ClassifyError> {
    let start = data
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'>'))
        .unwrap_or(data.len());
    let text = data.get(start..).unwrap_or_default();
    if text.starts_with(TX_HEADER.as_bytes()) || text.starts_with(HEADER.as_bytes()) {
        return Ok(PaymentFile::Armour);
    }
    let end = text
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |at| at.saturating_add(1));
    let trimmed = text.get(..end).unwrap_or_default();
    if !trimmed.is_empty() && trimmed.len() % 2 == 0 && trimmed.iter().all(u8::is_ascii_hexdigit) {
        return Err(ClassifyError::StockSavedTx);
    }
    if text.starts_with(b"{") {
        return Ok(PaymentFile::LegacyJson);
    }
    Err(ClassifyError::NotPaymentFile)
}
