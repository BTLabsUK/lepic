// SPDX-License-Identifier: Apache-2.0
//! Slate text as animated QR codes (`ur:epic-slate`), without a wallet.

use lepic_wallet::slate::ur_slate::{
    SINGLE_CODE_MAX_LEN, UrBinary, UrBinaryEncodeError, UrContent, UrContentError, UrDecodeError,
    UrEncodeError, decode_ur_parts, encode_ur_binary_split, encode_ur_slate_split,
};

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{InPersonQrProgress, UrSlateProgress};

/// The parts of an animated QR code for slate text: the deflated text, payload version 1.
/// Without `single_code_max_len` a payload that fits one fragment is one code.
pub(crate) fn encode(
    json: String,
    max_fragment_len: u32,
    single_code_max_len: Option<u32>,
) -> Result<Vec<String>, WalletError> {
    let single_code_max_len = single_code_max_len.unwrap_or(max_fragment_len);
    encode_ur_slate_split(json, len_of(single_code_max_len), len_of(max_fragment_len))
        .map_err(|error| WalletError::chained(encode_kind(&error), &error))
}

/// A length from Dart; one past `usize` stays out of every range the encoders accept.
fn len_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// How far the scanned parts of a payment-file code got: the slate text of payload version 1.
/// Version 2 carries in-person codes and answers, a foreign code here.
pub(crate) fn decode(parts: &[String]) -> Result<UrSlateProgress, WalletError> {
    let progress = decode_ur_parts(parts).map_err(|error| content_error(&error))?;
    let json = match progress.content {
        None => None,
        Some(UrContent::Json(json)) => Some(json),
        Some(UrContent::Binary(_)) => {
            return Err(WalletError::new(
                WalletErrorKind::ForeignUrCode,
                "the code is an in-person code or answer, not a payment file",
            ));
        }
    };
    // The decoder bounds both counts by the sequence limit, far below u32::MAX.
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    Ok(UrSlateProgress {
        complete: json.is_some(),
        received_fragments: count(progress.resolved_fragments),
        fragment_count: count(progress.fragment_count),
        json,
    })
}

/// A payment-file code's content error as the decoder's kind.
fn content_error(error: &UrContentError) -> WalletError {
    let kind = match error {
        UrContentError::Decode(decode) => decode_kind(decode),
        UrContentError::UnknownMagic => WalletErrorKind::InvalidUrCode,
        UrContentError::TooLong { .. } => WalletErrorKind::UrCodeTooLarge,
    };
    WalletError::chained(kind, error)
}

/// The parts of an animated QR code for the bytes of an in-person code or answer. Without
/// `single_code_max_len` the payload default, [`SINGLE_CODE_MAX_LEN`], applies.
pub(crate) fn encode_binary(
    bytes: &[u8],
    max_fragment_len: u32,
    single_code_max_len: Option<u32>,
) -> Result<Vec<String>, WalletError> {
    let single_code_max_len = single_code_max_len.map_or(SINGLE_CODE_MAX_LEN, len_of);
    encode_ur_binary_split(bytes, single_code_max_len, len_of(max_fragment_len))
        .map_err(|error| WalletError::chained(encode_binary_kind(&error), &error))
}

/// How far the scanned parts of an in-person code or answer got. Parts of a payment-file code,
/// slate text, are not an in-person code.
pub(crate) fn decode_binary(parts: &[String]) -> Result<InPersonQrProgress, WalletError> {
    let progress = decode_ur_parts(parts).map_err(|error| {
        let kind = match &error {
            UrContentError::Decode(decode) => decode_kind(decode),
            UrContentError::UnknownMagic => WalletErrorKind::InvalidSlate,
            UrContentError::TooLong { .. } => WalletErrorKind::UrCodeTooLarge,
        };
        WalletError::chained(kind, &error)
    })?;
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    let bytes = match progress.content {
        None => None,
        Some(UrContent::Binary(UrBinary::NativeSlate(bytes) | UrBinary::Envelope(bytes))) => {
            Some(bytes)
        }
        Some(UrContent::Json(_)) => {
            return Err(WalletError::new(
                WalletErrorKind::InvalidSlate,
                "the code holds slate text, not an in-person code",
            ));
        }
    };
    Ok(InPersonQrProgress {
        complete: bytes.is_some(),
        received_fragments: count(progress.resolved_fragments),
        fragment_count: count(progress.fragment_count),
        bytes,
    })
}

fn encode_binary_kind(error: &UrBinaryEncodeError) -> WalletErrorKind {
    match error {
        UrBinaryEncodeError::UnknownMagic => WalletErrorKind::InvalidSlate,
        UrBinaryEncodeError::FragmentLength { .. }
        | UrBinaryEncodeError::SingleCodeLength { .. } => WalletErrorKind::InvalidArgument,
        UrBinaryEncodeError::TooLong { .. } | UrBinaryEncodeError::TooManyFragments { .. } => {
            WalletErrorKind::UrCodeTooLarge
        }
        UrBinaryEncodeError::Framing => WalletErrorKind::Other,
    }
}

fn encode_kind(error: &UrEncodeError) -> WalletErrorKind {
    match error {
        UrEncodeError::Empty | UrEncodeError::NotJson => WalletErrorKind::InvalidSlate,
        UrEncodeError::FragmentLength { .. } | UrEncodeError::SingleCodeLength { .. } => {
            WalletErrorKind::InvalidArgument
        }
        UrEncodeError::TextTooLong { .. } | UrEncodeError::TooManyFragments { .. } => {
            WalletErrorKind::UrCodeTooLarge
        }
        UrEncodeError::Framing => WalletErrorKind::Other,
    }
}

fn decode_kind(error: &UrDecodeError) -> WalletErrorKind {
    match error {
        UrDecodeError::NotUr => WalletErrorKind::NotUrCode,
        UrDecodeError::OtherType { .. } => WalletErrorKind::ForeignUrCode,
        UrDecodeError::MixedCodes => WalletErrorKind::MixedUrCodes,
        UrDecodeError::TooManyParts { .. }
        | UrDecodeError::TooMuchText { .. }
        | UrDecodeError::PartTooLong { .. }
        | UrDecodeError::SequenceTooLong { .. }
        | UrDecodeError::InflatesTooLarge { .. } => WalletErrorKind::UrCodeTooLarge,
        UrDecodeError::InvalidPart(_)
        | UrDecodeError::MalformedPayload(_)
        | UrDecodeError::UnsupportedVersion { .. }
        | UrDecodeError::InvalidDeflate
        | UrDecodeError::NotUtf8
        | UrDecodeError::NotJson => WalletErrorKind::InvalidUrCode,
    }
}
