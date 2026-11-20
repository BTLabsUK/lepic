// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Portions Copyright 2023 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/backends/db.rs, impls/src/backends/lmdb.rs,
// impls/src/serialization.rs, libwallet/src/types.rs, libwallet/src/slate.rs (Apache-2.0); see
// NOTICE and upstream.toml.

//! Turns one row of the `data` table into a typed record, or says why it cannot be imported.

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use serde::de::DeserializeOwned;
use thiserror::Error;
use uuid::Uuid;

use super::wire::{
    WireAccount, WireMessage, WireOutput, WireOutputStatus, WireTxLogEntry, WireTxType,
};
use super::{
    LegacyAccount, LegacyChildCounter, LegacyMessage, LegacyOutput, LegacyOutputStatus,
    LegacyTxKind, LegacyTxLogEntry,
};
use crate::output::{COMMITMENT_LEN, KEY_ID_LEN, KeyId};

/// Upstream truncates its own messages to 256 bytes; a peer's may be longer.
pub(super) const MAX_LABEL_CHARS: usize = 256;
pub(super) const MAX_MESSAGE_CHARS: usize = 1024;
pub(super) const MAX_PUBLIC_ADDR_CHARS: usize = 512;
pub(super) const MAX_STORED_TX_CHARS: usize = 512;
/// Two-party transactions carry two messages.
pub(super) const MAX_MESSAGES: usize = 16;
/// Key ids name at most four derivation levels below the root.
const MAX_KEY_DEPTH: u8 = 4;
const PUBLIC_KEY_LEN: usize = 33;
const SIGNATURE_LEN: usize = 64;
const DERIVATION_PREFIX: u8 = b'd';
/// `epic_store::to_key` puts this byte between the prefix and the rest of a key.
const KEY_SEPARATOR: u8 = b':';

/// Why a row was skipped. Never carries a value from the row, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum RowRejection {
    #[error("row is not text")]
    NotText,
    #[error("row is not the expected json ({0:?})")]
    Json(serde_json::error::Category),
    #[error("row is larger than the import allows")]
    TooLarge,
    #[error("{field} is not hex of the expected length")]
    Hex { field: &'static str },
    #[error("{field} is deeper than four levels")]
    KeyDepth { field: &'static str },
    #[error("{field} is out of range")]
    OutOfRange { field: &'static str },
    #[error("{field} is longer than the import allows")]
    TooLong { field: &'static str },
    #[error("{field} is not an rfc 3339 timestamp")]
    Timestamp { field: &'static str },
    #[error("slate id is not a uuid")]
    SlateId,
    #[error("row key is malformed")]
    RowKey,
    #[error("transaction has more messages than the import allows")]
    TooManyMessages,
}

pub(super) fn parse_account(data: &[u8]) -> Result<LegacyAccount, RowRejection> {
    let wire: WireAccount = json(data)?;
    Ok(LegacyAccount {
        label: bounded(wire.label, MAX_LABEL_CHARS, "label")?,
        path: key_id(&wire.path, "path")?,
    })
}

/// `key` is the row key as upstream stores it: the `{:?}` text of the key bytes, here `d:` and
/// the parent key id. `data` is `Serializable::Numeric`, a bare JSON number.
pub(super) fn parse_counter(key: &[u8], data: &[u8]) -> Result<LegacyChildCounter, RowRejection> {
    let key = debug_bytes(key)?;
    let parent = match key.as_slice() {
        [DERIVATION_PREFIX, KEY_SEPARATOR, rest @ ..] => {
            let bytes: [u8; KEY_ID_LEN] = rest.try_into().map_err(|_| RowRejection::RowKey)?;
            checked_depth(KeyId(bytes), "parent key id")?
        }
        _ => return Err(RowRejection::RowKey),
    };
    let value: u64 = json(data)?;
    let next_child = u32::try_from(value).map_err(|_| RowRejection::OutOfRange {
        field: "derivation counter",
    })?;
    Ok(LegacyChildCounter { parent, next_child })
}

pub(super) fn parse_transaction(data: &[u8]) -> Result<LegacyTxLogEntry, RowRejection> {
    let wire: WireTxLogEntry = json(data)?;
    let messages = match wire.messages {
        Some(messages) if messages.messages.len() > MAX_MESSAGES => {
            return Err(RowRejection::TooManyMessages);
        }
        Some(messages) => messages
            .messages
            .into_iter()
            .map(message)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    Ok(LegacyTxLogEntry {
        id: wire.id,
        parent_key_id: key_id(&wire.parent_key_id, "parent key id")?,
        slate_id: wire
            .tx_slate_id
            .map(|id| Uuid::try_parse(&id).map_err(|_| RowRejection::SlateId))
            .transpose()?,
        kind: tx_kind(wire.tx_type),
        created_at: timestamp(&wire.creation_ts, "creation time")?,
        confirmed_at: wire
            .confirmation_ts
            .map(|time| timestamp(&time, "confirmation time"))
            .transpose()?,
        confirmed: wire.confirmed,
        confirmation_height: wire.confirmation_height.map(Height::new),
        num_inputs: count(wire.num_inputs, "input count")?,
        num_outputs: count(wire.num_outputs, "output count")?,
        amount_credited: Amount::new(wire.amount_credited),
        amount_debited: Amount::new(wire.amount_debited),
        fee: wire.fee.map(Fee::new),
        ttl_cutoff_height: wire.ttl_cutoff_height.map(Height::new),
        messages,
        stored_tx: wire
            .stored_tx
            .map(|name| bounded(name, MAX_STORED_TX_CHARS, "stored transaction"))
            .transpose()?,
        kernel_excess: wire
            .kernel_excess
            .map(|hex| hex_array::<COMMITMENT_LEN>(&hex, "kernel excess"))
            .transpose()?,
        kernel_lookup_min_height: wire.kernel_lookup_min_height.map(Height::new),
        public_addr: wire
            .public_addr
            .map(|addr| bounded(addr, MAX_PUBLIC_ADDR_CHARS, "public address"))
            .transpose()?,
    })
}

pub(super) fn parse_output(data: &[u8]) -> Result<LegacyOutput, RowRejection> {
    let wire: WireOutput = json(data)?;
    Ok(LegacyOutput {
        root_key_id: key_id(&wire.root_key_id, "root key id")?,
        key_id: key_id(&wire.key_id, "key id")?,
        n_child: wire.n_child,
        commitment: wire
            .commit
            .map(|hex| hex_array::<COMMITMENT_LEN>(&hex, "commitment"))
            .transpose()?,
        mmr_index: wire.mmr_index,
        value: Amount::new(wire.value),
        status: output_status(wire.status),
        height: Height::new(wire.height),
        lock_height: Height::new(wire.lock_height),
        is_coinbase: wire.is_coinbase,
        tx_log_entry: wire.tx_log_entry,
    })
}

fn message(wire: WireMessage) -> Result<LegacyMessage, RowRejection> {
    Ok(LegacyMessage {
        participant: wire.id,
        public_key: hex_array::<PUBLIC_KEY_LEN>(&wire.public_key, "message public key")?,
        text: wire
            .message
            .map(|text| bounded(text, MAX_MESSAGE_CHARS, "message"))
            .transpose()?,
        signature: wire
            .message_sig
            .map(|hex| hex_array::<SIGNATURE_LEN>(&hex, "message signature"))
            .transpose()?,
    })
}

fn tx_kind(wire: WireTxType) -> LegacyTxKind {
    match wire {
        WireTxType::ConfirmedCoinbase => LegacyTxKind::ConfirmedCoinbase,
        WireTxType::TxReceived => LegacyTxKind::TxReceived,
        WireTxType::TxSent => LegacyTxKind::TxSent,
        WireTxType::TxReceivedCancelled => LegacyTxKind::TxReceivedCancelled,
        WireTxType::TxSentCancelled => LegacyTxKind::TxSentCancelled,
        WireTxType::TxSentMempool => LegacyTxKind::TxSentMempool,
        WireTxType::TxReceivedMempool => LegacyTxKind::TxReceivedMempool,
        WireTxType::TxSentCreated => LegacyTxKind::TxSentCreated,
    }
}

fn output_status(wire: WireOutputStatus) -> LegacyOutputStatus {
    match wire {
        WireOutputStatus::Unconfirmed => LegacyOutputStatus::Unconfirmed,
        WireOutputStatus::Unspent => LegacyOutputStatus::Unspent,
        WireOutputStatus::Locked => LegacyOutputStatus::Locked,
        WireOutputStatus::Spent => LegacyOutputStatus::Spent,
        WireOutputStatus::Deleted => LegacyOutputStatus::Deleted,
    }
}

fn json<T: DeserializeOwned>(data: &[u8]) -> Result<T, RowRejection> {
    serde_json::from_slice(data).map_err(|error| RowRejection::Json(error.classify()))
}

fn bounded(text: String, max_chars: usize, field: &'static str) -> Result<String, RowRejection> {
    if text.chars().nth(max_chars).is_some() {
        Err(RowRejection::TooLong { field })
    } else {
        Ok(text)
    }
}

fn count(value: u64, field: &'static str) -> Result<u32, RowRejection> {
    u32::try_from(value).map_err(|_| RowRejection::OutOfRange { field })
}

fn timestamp(text: &str, field: &'static str) -> Result<Timestamp, RowRejection> {
    text.parse().map_err(|_| RowRejection::Timestamp { field })
}

/// `Identifier` serializes as the lowercase hex of its 17 bytes.
pub(super) fn key_id(hex: &str, field: &'static str) -> Result<KeyId, RowRejection> {
    checked_depth(KeyId(hex_array(hex, field)?), field)
}

fn checked_depth(id: KeyId, field: &'static str) -> Result<KeyId, RowRejection> {
    match id.0.first() {
        Some(depth) if *depth <= MAX_KEY_DEPTH => Ok(id),
        _ => Err(RowRejection::KeyDepth { field }),
    }
}

/// Exactly `2 * N` hex digits, either case, nothing else.
pub(super) fn hex_array<const N: usize>(
    hex: &str,
    field: &'static str,
) -> Result<[u8; N], RowRejection> {
    let digits = hex.as_bytes();
    if digits.len() != N.saturating_mul(2) {
        return Err(RowRejection::Hex { field });
    }
    let (pairs, _) = digits.as_chunks::<2>();
    let mut bytes = [0_u8; N];
    for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
        let high = nibble(*high).ok_or(RowRejection::Hex { field })?;
        let low = nibble(*low).ok_or(RowRejection::Hex { field })?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn nibble(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// Parses the `format!("{:?}", bytes)` text upstream stores keys as, `[100, 58, 2, ...]`.
pub(super) fn debug_bytes(text: &[u8]) -> Result<Vec<u8>, RowRejection> {
    let text = std::str::from_utf8(text).map_err(|_| RowRejection::RowKey)?;
    let inner = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or(RowRejection::RowKey)?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(", ")
        .map(|element| {
            let canonical = !element.is_empty()
                && element.bytes().all(|digit| digit.is_ascii_digit())
                && (element == "0" || !element.starts_with('0'));
            if canonical {
                element.parse::<u8>().map_err(|_| RowRejection::RowKey)
            } else {
                Err(RowRejection::RowKey)
            }
        })
        .collect()
}
