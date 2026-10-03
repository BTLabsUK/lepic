//! Golden vector replays of the engine (docs/rules.md): `cargo xtask vectors verify` runs exactly
//! this target.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

#[path = "finalize/vectors.rs"]
mod finalize_vectors;
#[path = "invoice/harness.rs"]
mod invoice_harness;
#[path = "invoice/vectors.rs"]
mod invoice_vectors;
#[path = "receive/harness.rs"]
mod receive_harness;
#[path = "receive/vectors.rs"]
mod receive_vectors;
mod refresh_support;
mod scan_support;
mod selection_vectors;
mod send_vectors;
mod support;

use lepic_primitives::amount::Height;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use serde_json::Value;

/// The outcome LEPIC's refresh reports for a recorded session. Where the node's tip is below the
/// last refresh's height, upstream applies no output state and LEPIC changes nothing.
fn expected_refresh(vector: &Value) -> Option<RefreshOutcome> {
    let last_confirmed =
        refresh_support::number(&vector["inputs"]["before"]["last_confirmed_height"]);
    let tip = vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| exchange["method"] == "get_tip")
        .map(|exchange| refresh_support::number(&exchange["response"]["result"]["Ok"]["height"]))
        .unwrap();
    (tip < last_confirmed).then(|| RefreshOutcome::NodeBehind {
        tip: Height::new(tip),
        last_confirmed: Height::new(last_confirmed),
    })
}

/// Upstream's update stopped before its scan because it could not reach the node.
fn upstream_update_stopped(vector: &Value) -> bool {
    vector["expected"]["node_unreachable"] == true
}

#[test]
fn restore_vectors_find_exactly_the_outputs_upstream_found() {
    for (name, vector) in scan_support::restore_vectors() {
        let harness = scan_support::harness(&vector);
        let wallet = harness.wallet();
        scan_support::restore(&harness, &wallet, &vector);

        let summary = harness
            .block_on(wallet.scan(scan_support::options(&vector), &ScanCancel::new()))
            .unwrap();

        let expected = vector["expected"]["after"]["outputs"].as_array().unwrap();
        assert_eq!(summary.restored, expected.len() as u64, "{name}");
        assert!(!summary.resumed, "{name}");
        scan_support::assert_matches_upstream(&harness, &wallet, &vector, &name);
    }
}

#[test]
fn refresh_vectors_end_in_the_states_upstream_reached() {
    for (name, vector) in refresh_support::refresh_vectors() {
        let harness = scan_support::harness(&vector);
        let wallet = harness.wallet();
        scan_support::restore(&harness, &wallet, &vector);
        let ids = refresh_support::seed_before(&harness, &vector);

        let outcome = harness.block_on(wallet.refresh()).unwrap();

        match expected_refresh(&vector) {
            Some(behind) => assert_eq!(outcome, behind, "{name}"),
            None => assert!(
                matches!(outcome, RefreshOutcome::Refreshed(_)),
                "{name}: {outcome:?}"
            ),
        }
        refresh_support::assert_matches_upstream(&harness, &wallet, &vector, &ids, &name);
    }
}

#[test]
fn refresh_then_update_scan_ends_where_upstream_update_ended() {
    for (name, vector) in refresh_support::refresh_vectors() {
        let harness = scan_support::harness(&vector);
        let wallet = harness.wallet();
        scan_support::restore(&harness, &wallet, &vector);
        let ids = refresh_support::seed_before(&harness, &vector);

        harness.block_on(wallet.refresh()).unwrap();
        if upstream_update_stopped(&vector) {
            refresh_support::assert_matches_upstream(&harness, &wallet, &vector, &ids, &name);
            refresh_support::assert_scanned_like_upstream(&wallet, &vector, &name);
            continue;
        }
        let options = ScanOptions {
            start: lepic_wallet::scan::ScanStart::LastScanned,
            ..scan_support::options(&vector)
        };
        let summary = harness
            .block_on(wallet.scan(options, &ScanCancel::new()))
            .unwrap();

        assert_eq!(summary.restored, 0, "{name}");
        refresh_support::assert_matches_upstream(&harness, &wallet, &vector, &ids, &name);
        refresh_support::assert_scanned_like_upstream(&wallet, &vector, &name);
    }
}
