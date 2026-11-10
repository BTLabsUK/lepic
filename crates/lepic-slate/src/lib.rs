// SPDX-License-Identifier: Apache-2.0
//! The version-free slate model, the codec trait and the codec registry (ADR 0002).
//!
//! A [`model::Slate`] is what two parties agree on while they build a transaction, independent
//! of any wire format. A [`codec::Codec`] maps one wire format to and from it; the registry holds
//! the codecs a wallet speaks and detects which one an unknown slate is in. The codecs
//! themselves live in `lepic-legacy-slate` (V2 and V3 JSON) and `lepic-native-slate`
//! (`lepic.v1`).

pub mod codec;
pub mod error;
pub mod model;
pub mod origin;
pub mod registry;
pub mod role;
pub mod stage;
pub mod ur_slate;
pub mod validate;
