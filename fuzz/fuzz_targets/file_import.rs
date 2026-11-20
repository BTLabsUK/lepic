// SPDX-License-Identifier: Apache-2.0
//! File import: the bytes of a slate file through the file method's format policy, which picks
//! the codec from the header version as upstream does.

#![no_main]

use lepic_fuzz::{assert_round_trips, legacy_codecs};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::file::FilePolicy;
use lepic_transport::policy::FormatPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codecs = legacy_codecs();
    let wire = WireSlate::binary(MediaType::JSON, data.to_vec());
    let Ok(slate) = FilePolicy.decode(&codecs, &wire) else {
        return;
    };
    let codec = slate.origin().and_then(|origin| codecs.get(origin.codec()));
    match codec {
        Some(codec) => assert_round_trips(codec, &slate),
        None => panic!("an imported slate must name a registered codec"),
    }
});
