//! Memory spent by the file policy on slate files of the largest accepted size that are mostly
//! data no slate needs. Reading the version must not grow with the input, so the bound is the
//! one `lepic-slate` sets for its codecs.
//!
//! Measured as the growth of the process's peak resident set, which only Linux reports in
//! `/proc`. Heap the allocator kept from an earlier case is not counted again. The file holds a
//! single test so nothing else runs in its process meanwhile.
#![cfg(target_os = "linux")]
// Tests may unwrap, panic and use plain arithmetic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use lepic_slate::registry::CodecRegistry;
use lepic_transport::file::FileTransport;
use lepic_transport::transport::Transport;

/// The bound `lepic-slate`'s bounded-decoding test sets for the codecs themselves.
const MAX_PEAK_GROWTH_KIB: u64 = 16 * 1024;

fn legacy_codecs() -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V3JsonCodec::new(Default::default())))
        .unwrap();
    codecs
        .register(Box::new(V2JsonCodec::new(Default::default())))
        .unwrap();
    codecs
}

/// A slate file of the largest accepted size made of one array of empty objects, the densest
/// way to write many JSON values. `prefix` opens the array and `suffix` closes everything it
/// opened.
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
fn file_policy_decodes_oversized_files_in_bounded_memory() {
    let codecs = legacy_codecs();
    let transport = FileTransport::new();
    let cases = [
        (
            "v3 unknown key",
            r#"{"version_info":{"version":3},"x":["#,
            "]}",
        ),
        (
            "v2 unknown key",
            r#"{"version_info":{"version":2},"x":["#,
            "]}",
        ),
        (
            "v2 v3-only key",
            r#"{"version_info":{"version":2},"payment_proof":["#,
            "]}",
        ),
        (
            "v2 with v3-only key, unknown key",
            r#"{"version_info":{"version":2},"ttl_cutoff_height":null,"x":["#,
            "]}",
        ),
        (
            "version_info",
            r#"{"version_info":{"version":3,"x":["#,
            "]}}",
        ),
        ("no version", r#"{"x":["#, "]}"),
        ("top-level array", "[", "]"),
    ];
    let mut failures = Vec::new();
    for (case, open, close) in cases {
        let wire = WireSlate::text(MediaType::JSON, oversized(open, close));
        let growth = peak_growth_kib(|| {
            assert!(transport.policy().decode(&codecs, &wire).is_err());
        });
        println!("{case}: peak grew {growth} KiB");
        if growth > MAX_PEAK_GROWTH_KIB {
            failures.push(format!("{case}: {growth} KiB"));
        }
    }
    assert!(
        failures.is_empty(),
        "peak growth above {MAX_PEAK_GROWTH_KIB} KiB: {failures:?}"
    );
}
