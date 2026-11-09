// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/slate_versions/mod.rs (Apache-2.0); see NOTICE
// and upstream.toml.

//! The JSON slate formats deployed `epic-wallet` versions speak. They are frozen to upstream's
//! behaviour, quirks included: change them only to fix a mismatch a golden vector shows, and put
//! improvements into a new codec.

mod bounded;
mod fields;
pub mod marker;
pub mod v2_json;
pub mod v3_json;
