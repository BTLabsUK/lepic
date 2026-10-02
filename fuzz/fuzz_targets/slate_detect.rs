//! Codec detection over both legacy codecs, as a transport that does not know the format runs it.

#![no_main]

use lepic_fuzz::{assert_round_trips, legacy_codecs};
use lepic_slate::codec::{MediaType, WireSlate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codecs = legacy_codecs();
    let wire = WireSlate::binary(MediaType::JSON, data.to_vec());
    let Ok(codec) = codecs.detect(&wire) else {
        return;
    };
    if let Ok(slate) = codec.decode(&wire) {
        assert_eq!(
            slate.origin().map(|origin| origin.codec()),
            Some(codec.id()),
            "a decoded slate must name the codec that decoded it"
        );
        assert_round_trips(codec, &slate);
    }
});
