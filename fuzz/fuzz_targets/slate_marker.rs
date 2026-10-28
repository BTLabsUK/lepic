// SPDX-License-Identifier: Apache-2.0
//! The LEPIC marker probes, which read whole relay-delivered slate JSON before any codec does.

#![no_main]

use lepic_epicbox::marker::v3::{carries_lepic_marker, lepic_marker_reply_key};
use lepic_slate::codec::{MediaType, WireSlate};
use libfuzzer_sys::fuzz_target;
use x25519_dalek::x25519;

fuzz_target!(|data: &[u8]| {
    let wire = WireSlate::binary(MediaType::JSON, data.to_vec());
    let marked = carries_lepic_marker(&wire);
    if let Some(key) = lepic_marker_reply_key(&wire) {
        assert!(marked, "a reply key comes only from a marked slate");
        // Any clamped scalar times a small-order point is the all-zero u-coordinate.
        assert_ne!(
            x25519([9; 32], key),
            [0; 32],
            "a small-order reply key is refused"
        );
    }
});
