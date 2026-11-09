// SPDX-License-Identifier: Apache-2.0
//! Slate text as animated QR codes (`ur:epic-slate`), without a wallet.

use lepic_wallet::slate::ur_slate::{
    UrBinary, UrBinaryEncodeError, UrContent, UrContentError, UrDecodeError, UrEncodeError,
    UrProgress, decode_ur_parts, decode_ur_slate, encode_ur_binary, encode_ur_slate,
};

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{InPersonQrProgress, UrSlateProgress};

pub(crate) fn encode(json: String, max_fragment_len: u32) -> Result<Vec<String>, WalletError> {
    let max_fragment_len = usize::try_from(max_fragment_len).unwrap_or(usize::MAX);
    encode_ur_slate(json, max_fragment_len)
        .map_err(|error| WalletError::chained(encode_kind(&error), &error))
}

pub(crate) fn decode(parts: &[String]) -> Result<UrSlateProgress, WalletError> {
    let progress = decode_ur_slate(parts)
        .map_err(|error| WalletError::chained(decode_kind(&error), &error))?;
    Ok(progress_of(progress))
}

/// The parts of an animated QR code for the bytes of an in-person code or answer.
pub(crate) fn encode_binary(
    bytes: &[u8],
    max_fragment_len: u32,
) -> Result<Vec<String>, WalletError> {
    let max_fragment_len = usize::try_from(max_fragment_len).unwrap_or(usize::MAX);
    encode_ur_binary(bytes, max_fragment_len)
        .map_err(|error| WalletError::chained(encode_binary_kind(&error), &error))
}

/// How far the scanned parts of an in-person code or answer got. Parts of a JSON slate code
/// are not an in-person code.
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
        UrBinaryEncodeError::FragmentLength { .. } => WalletErrorKind::InvalidArgument,
        UrBinaryEncodeError::TooLong { .. } | UrBinaryEncodeError::TooManyFragments { .. } => {
            WalletErrorKind::UrCodeTooLarge
        }
        UrBinaryEncodeError::Framing => WalletErrorKind::Other,
    }
}

fn encode_kind(error: &UrEncodeError) -> WalletErrorKind {
    match error {
        UrEncodeError::Empty | UrEncodeError::NotJson => WalletErrorKind::InvalidSlate,
        UrEncodeError::FragmentLength { .. } => WalletErrorKind::InvalidArgument,
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

fn progress_of(progress: UrProgress) -> UrSlateProgress {
    // The decoder bounds both counts by the sequence limit, far below u32::MAX.
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    UrSlateProgress {
        complete: progress.is_complete(),
        received_fragments: count(progress.resolved_fragments),
        fragment_count: count(progress.fragment_count),
        json: progress.json,
    }
}
