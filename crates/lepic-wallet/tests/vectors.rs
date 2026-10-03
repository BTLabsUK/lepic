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

use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::scan::{ScanCancel, ScanOptions};

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

        assert!(
            matches!(outcome, RefreshOutcome::Refreshed(_)),
            "{name}: {outcome:?}"
        );
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
