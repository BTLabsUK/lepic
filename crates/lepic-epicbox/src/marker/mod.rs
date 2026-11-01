// SPDX-License-Identifier: Apache-2.0
//! The LEPIC marker: the `"lepic":{"version":1}` key a LEPIC wallet adds to the V2 and V3 JSON
//! slates it sends over Epicbox, so the peer knows it runs LEPIC, and the reply key a file or
//! paste slate may carry in it for a sealed answer (RFC 0002 section 5). It is a LEPIC feature,
//! not Epic compatibility: stock `epic-wallet` ignores and drops the key.
//!
//! Over Epicbox the marker also carries `f`, the [`features`] the wallet claims; only there,
//! inside the encrypted message, never in a file or paste slate that anyone holding it can read.
//! The marker's `version` stays 1 and carries no build version.

pub mod features;
pub mod v2;
pub mod v3;

/// What the marker carries besides its version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerExtra {
    None,
    /// The claimed feature bits, for a slate that goes over Epicbox.
    Features(u32),
    /// An X25519 reply key, for a file or paste slate.
    Reply([u8; 32]),
}

/// What follows the last key of the slate object.
pub(crate) fn marker_text(extra: &MarkerExtra) -> String {
    match extra {
        MarkerExtra::None => ",\"lepic\":{\"version\":1}".to_owned(),
        MarkerExtra::Features(features) => format!(",\"lepic\":{{\"version\":1,\"f\":{features}}}"),
        MarkerExtra::Reply(key) => {
            let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
            format!(",\"lepic\":{{\"version\":1,\"reply\":\"{hex}\"}}")
        }
    }
}
