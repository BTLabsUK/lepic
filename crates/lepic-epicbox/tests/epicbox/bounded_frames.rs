// SPDX-License-Identifier: Apache-2.0
//! Memory spent decoding relay frames of the largest accepted length whose content is one long
//! array of empty objects, the densest way to write many JSON values. Decoding must not grow
//! with the content the wallet ignores.
//!
//! Measured as the growth of the process's peak resident set, which only Linux reports in
//! `/proc`. The test binary holds every integration test of the crate, and plain `cargo test`
//! runs them on threads of one process, so the test measures in a child process of the test
//! binary that runs this test alone.
#![cfg(target_os = "linux")]
// Tests may unwrap, panic and use plain arithmetic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

use std::process::Command;

use lepic_epicbox::{MAX_FRAME_LEN, RelayFrame};

/// Set in the child process the test starts, which then measures instead of starting another.
const MEASURING_CHILD: &str = "LEPIC_BOUNDED_FRAMES_CHILD";

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

/// Runs this test's measurement alone in a child process of the test binary: the peak resident
/// set is the process's, and other tests on threads beside it would raise it.
#[test]
fn decoding_oversized_relay_frames_uses_bounded_memory() {
    if std::env::var_os(MEASURING_CHILD).is_some() {
        measure();
        return;
    }
    // The name libtest and nextest know the test by: its path below the binary's crate.
    let (_, module) = module_path!().split_once("::").unwrap();
    let name = format!("{module}::decoding_oversized_relay_frames_uses_bounded_memory");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(MEASURING_CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(child.status.success(), "the measuring child failed");
    // A name that matched nothing would pass with nothing measured.
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the measuring child did not run {name}"
    );
}

fn measure() {
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
