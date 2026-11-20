// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Portions Copyright 2023 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/backends/db.rs, impls/src/backends/lmdb.rs,
// impls/src/serialization.rs, libwallet/src/types.rs, libwallet/src/slate.rs (Apache-2.0); see
// NOTICE and upstream.toml.

//! The JSON shapes `epic-wallet` stores in the `data` column, field for field.
//!
//! Field presence follows serde's derive rules as upstream applies them: a plain `Option` may be
//! missing, an `Option` read through a `with` helper must be present unless upstream also marks
//! it `#[serde(default)]`. Unknown fields are ignored, as upstream ignores them. Values stay raw
//! here; `rows` checks lengths, hex and ranges.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

#[derive(Debug, Deserialize)]
pub(super) struct WireAccount {
    pub(super) label: String,
    pub(super) path: String,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub(super) enum WireTxType {
    ConfirmedCoinbase,
    TxReceived,
    TxSent,
    TxReceivedCancelled,
    TxSentCancelled,
    TxSentMempool,
    TxReceivedMempool,
    TxSentCreated,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireTxLogEntry {
    #[serde(default)]
    pub(super) confirmation_height: Option<u64>,
    pub(super) parent_key_id: String,
    pub(super) id: u32,
    pub(super) tx_slate_id: Option<String>,
    pub(super) tx_type: WireTxType,
    pub(super) creation_ts: String,
    pub(super) confirmation_ts: Option<String>,
    pub(super) confirmed: bool,
    pub(super) num_inputs: u64,
    pub(super) num_outputs: u64,
    #[serde(deserialize_with = "string_or_u64")]
    pub(super) amount_credited: u64,
    #[serde(deserialize_with = "string_or_u64")]
    pub(super) amount_debited: u64,
    #[serde(deserialize_with = "opt_string_or_u64")]
    pub(super) fee: Option<u64>,
    #[serde(default, deserialize_with = "opt_string_or_u64")]
    pub(super) ttl_cutoff_height: Option<u64>,
    pub(super) messages: Option<WireMessages>,
    pub(super) stored_tx: Option<String>,
    #[serde(default)]
    pub(super) kernel_excess: Option<String>,
    #[serde(default)]
    pub(super) kernel_lookup_min_height: Option<u64>,
    #[serde(default)]
    pub(super) public_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireMessages {
    pub(super) messages: Vec<WireMessage>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireMessage {
    #[serde(deserialize_with = "string_or_u64")]
    pub(super) id: u64,
    pub(super) public_key: String,
    pub(super) message: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub(super) message_sig: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub(super) enum WireOutputStatus {
    Unconfirmed,
    Unspent,
    Locked,
    Spent,
    Deleted,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireOutput {
    pub(super) root_key_id: String,
    pub(super) key_id: String,
    pub(super) n_child: u32,
    pub(super) commit: Option<String>,
    #[serde(deserialize_with = "opt_string_or_u64")]
    pub(super) mmr_index: Option<u64>,
    #[serde(deserialize_with = "string_or_u64")]
    pub(super) value: u64,
    pub(super) status: WireOutputStatus,
    #[serde(deserialize_with = "string_or_u64")]
    pub(super) height: u64,
    #[serde(deserialize_with = "string_or_u64")]
    pub(super) lock_height: u64,
    pub(super) is_coinbase: bool,
    pub(super) tx_log_entry: Option<u32>,
}

/// An `Option` that must be present, as `null` or a value, like upstream's `with` helpers.
fn present_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// `secp_ser::string_or_u64`: a JSON integer, or a string `u64::from_str` accepts.
fn string_or_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrU64;
    impl Visitor<'_> for StringOrU64 {
        type Value = u64;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a string containing digits or an int fitting into u64")
        }
        fn visit_u64<E>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<u64, E> {
            value.parse().map_err(de::Error::custom)
        }
    }
    deserializer.deserialize_any(StringOrU64)
}

/// `secp_ser::opt_string_or_u64`: `null`, a JSON integer or a digit string.
fn opt_string_or_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptStringOrU64;
    impl Visitor<'_> for OptStringOrU64 {
        type Value = Option<u64>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("null, a string containing digits or an int fitting into u64")
        }
        fn visit_unit<E>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }
        fn visit_u64<E>(self, value: u64) -> Result<Option<u64>, E> {
            Ok(Some(value))
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<Option<u64>, E> {
            value.parse().map(Some).map_err(de::Error::custom)
        }
    }
    deserializer.deserialize_any(OptStringOrU64)
}
