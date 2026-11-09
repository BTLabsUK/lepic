// SPDX-License-Identifier: Apache-2.0
//! The LEPIC marker: the `"lepic":{"version":1}` key a LEPIC wallet adds to the V2 and V3 JSON
//! slates it sends over Epicbox, so the peer knows it runs LEPIC, and the reply key a file or
//! paste slate may carry in it for a sealed answer (RFC 0002 section 5). It is a LEPIC feature,
//! not Epic compatibility: stock `epic-wallet` ignores and drops the key.
//!
//! Over Epicbox the marker also carries `f`, the [`features`] the wallet claims; only there,
//! inside the encrypted message, never in a file or paste slate that anyone holding it can read.
//! The marker's `version` stays 1 and carries no build version.
//!
//! The marked V2 and V3 codecs live in `lepic-legacy-slate` with the codecs they wrap
//! (ADR 0052); the feature bits stay here, since pairing and contacts use them too.

pub mod features;

pub use lepic_legacy_slate::marker::{v2, v3};
