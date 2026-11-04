// SPDX-License-Identifier: Apache-2.0
//! Hex text kept in the store, read leniently: a damaged value is `None`, not an error.

pub(crate) use lepic_crypto::hex::{decode_array, encode};

/// The bytes `text` spells, of any length.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    lepic_crypto::hex::decode_bounded(text, 0, usize::MAX).ok()
}
