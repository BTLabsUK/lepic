//! The legacy V3 JSON slate codec: detection and decoding of any bytes.

#![no_main]

use lepic_fuzz::{BASE_FEE, assert_round_trips};
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, MediaType, WireSlate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codec = V3JsonCodec::new(BASE_FEE);
    let wire = WireSlate::binary(MediaType::JSON, data.to_vec());
    let _ = codec.detect(&wire);
    if let Ok(slate) = codec.decode(&wire) {
        assert_round_trips(&codec, &slate);
    }
});
