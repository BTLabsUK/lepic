// SPDX-License-Identifier: Apache-2.0
//! Memory spent decoding relay frames of the largest accepted length whose content is one long
//! array of empty objects, the densest way to write many JSON values. Decoding must not grow
//! with the content the wallet ignores.
//!
//! Measured as the growth of the process's peak resident set, which only Linux reports in
//! `/proc`. The file holds a single test so nothing else runs in its process meanwhile.
#![cfg(target_os = "linux")]
// Tests may unwrap, panic and use plain arithmetic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

use lepic_epicbox::{MAX_FRAME_LEN, RelayFrame};

/// Far below what building a JSON document tree of such a frame needs, and above the frame
/// text plus allocator overhead.
const MAX_PEAK_GROWTH_KIB: u64 = 8 * 1024;

/// A frame within three bytes of the largest accepted length. `prefix` opens the frame and an array, the
/// array is filled with empty objects, and `suffix` closes everything `prefix` opened.
fn oversized(prefix: &str, suffix: &str) -> String {
    let mut json = String::with_capacity(MAX_FRAME_LEN);
    json.push_str(prefix);
    json.push_str("{}");
    while json.len() + 3 + suffix.len() <= MAX_FRAME_LEN {
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
fn decoding_oversized_relay_frames_uses_bounded_memory() {
    let slate_fields = r#""from":"a","str":"s","signature":"30","challenge":"c","#;
    let cases = [
        ("unknown type", r#"{"type":"Nope","x":["#.to_owned(), "]}"),
        (
            "unknown type, array first",
            r#"{"x":["#.to_owned(),
            r#"],"type":"Nope"}"#,
        ),
        ("ok", r#"{"type":"Ok","x":["#.to_owned(), "]}"),
        (
            "challenge",
            r#"{"type":"Challenge","str":"c","x":["#.to_owned(),
            "]}",
        ),
        (
            "slate",
            format!(r#"{{"type":"Slate",{slate_fields}"x":["#),
            "]}",
        ),
        ("missing type", r#"{"x":["#.to_owned(), "]}"),
    ];
    let mut failures = Vec::new();
    for (name, prefix, suffix) in cases {
        let frame = oversized(&prefix, suffix);
        assert!(frame.len() + 3 > MAX_FRAME_LEN, "{name}");
        let growth = peak_growth_kib(|| {
            let _ = std::hint::black_box(RelayFrame::from_json(&frame));
        });
        println!("{name}: peak grew {growth} KiB");
        if growth > MAX_PEAK_GROWTH_KIB {
            failures.push(format!("{name}: {growth} KiB"));
        }
    }
    assert!(
        failures.is_empty(),
        "peak growth above {MAX_PEAK_GROWTH_KIB} KiB: {failures:?}"
    );
}
