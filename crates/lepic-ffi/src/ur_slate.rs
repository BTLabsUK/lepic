// SPDX-License-Identifier: Apache-2.0
//! Slate text as animated QR codes (`ur:epic-slate`), without a wallet.

use lepic_wallet::slate::ur_slate::{
    UrDecodeError, UrEncodeError, UrProgress, decode_ur_slate, encode_ur_slate,
};

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::UrSlateProgress;

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
