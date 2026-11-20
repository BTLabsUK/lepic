// SPDX-License-Identifier: Apache-2.0
//! The native slate codec `lepic.v1`: decoding any bytes, for either network.

#![no_main]

use lepic_native_slate::{NativeSlate, SlateView};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((network, native)) = NativeSlate::decode_any(data) {
        assert_eq!(
            native.encode(network),
            data,
            "an accepted slate encodes to other bytes"
        );
        assert_eq!(
            SlateView::new(network, &native).into_native(),
            Ok((network, native)),
            "an accepted slate's view describes another slate"
        );
    }
});
