// SPDX-License-Identifier: Apache-2.0
//! Memory spent decoding legacy slates whose arrays are far longer than any slate LEPIC accepts.
//! It must stay bounded by the counts LEPIC accepts, not grow with the input.
//!
//! Measured as the growth of the process's peak resident set, which only Linux reports in
//! `/proc`. Heap the allocator kept from an earlier case is not counted again, which is far less
//! than the unbounded decoders needed. The file holds a single test so nothing else runs in its
//! process meanwhile.
#![cfg(target_os = "linux")]
// Tests may unwrap, panic and use plain arithmetic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

use lepic_legacy_slate::v2_json::V2JsonCodec;
use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_primitives::amount::Fee;
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, MAX_WIRE_SLATE_LEN, MediaType, WireSlate};

const BASE_FEE: Fee = Network::Floonet.params().default_base_fee();

/// Far below what the unbounded decoders needed for the same input, and comfortably above the
/// arrays at their accepted maximum plus allocator overhead.
const MAX_PEAK_GROWTH_KIB: u64 = 16 * 1024;

/// A slate of the largest accepted size made of one array of empty objects, the densest way to
/// write many elements. `prefix` opens the array and `suffix` closes everything it opened.
fn oversized(prefix: &str, suffix: &str) -> String {
    let mut json = String::with_capacity(MAX_WIRE_SLATE_LEN);
    json.push_str(prefix);
    json.push_str("{}");
    while json.len() + 3 + suffix.len() <= MAX_WIRE_SLATE_LEN {
        json.push_str(",{}");
    }
    json.push_str(suffix);
    json
}

fn status_kib(key: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("{key} missing from /proc/self/status"));
    line.trim().trim_end_matches("kB").trim().parse().unwrap()
}

/// Peak resident growth while `decode` runs. Resetting the peak is best effort: if the kernel
/// refuses, the earlier peak only makes the figure larger, never smaller.
fn peak_growth_kib(decode: impl FnOnce()) -> u64 {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let before = status_kib("VmRSS:");
    decode();
    status_kib("VmHWM:").saturating_sub(before)
}

#[test]
fn decoding_oversized_arrays_uses_bounded_memory() {
    let v2 = V2JsonCodec::new(BASE_FEE);
    let v3 = V3JsonCodec::new(BASE_FEE);
    let codecs: [(&str, &dyn Codec, &str); 2] =
        [("v2", &v2, ""), ("v3", &v3, r#""ttl_cutoff_height":null,"#)];
    let arrays = [
        ("participant_data", r#""participant_data":["#, "]}"),
        ("inputs", r#""tx":{"body":{"inputs":["#, "]}}}"),
        ("outputs", r#""tx":{"body":{"outputs":["#, "]}}}"),
        ("kernels", r#""tx":{"body":{"kernels":["#, "]}}}"),
    ];
    let mut failures = Vec::new();
    for (codec_name, codec, header) in codecs {
        for (array, open, close) in arrays {
            let json = oversized(&format!("{{{header}{open}"), close);
            let wire = WireSlate::text(MediaType::JSON, json);
            let growth = peak_growth_kib(|| {
                assert!(codec.decode(&wire).is_err());
            });
            println!("{codec_name} {array}: peak grew {growth} KiB");
            if growth > MAX_PEAK_GROWTH_KIB {
                failures.push(format!("{codec_name} {array}: {growth} KiB"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "peak growth above {MAX_PEAK_GROWTH_KIB} KiB: {failures:?}"
    );
}
