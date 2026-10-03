//! The JSON slate formats deployed `epic-wallet` versions speak. They are frozen to upstream's
//! behaviour, quirks included: change them only to fix a mismatch a golden vector shows, and put
//! improvements into a new codec.

mod bounded;
mod fields;
pub mod v2_json;
pub mod v3_json;
