//! Scan against node answers that cannot be true: a tip far beyond what the chain can have
//! reached, outputs above the tip, a spent output the node does not confirm when asked again,
//! and a stored scan position above the node's tip.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod scan_support;
mod support;

use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;
use lepic_store::OutputStatus;
use lepic_wallet::scan::{ScanCancel, ScanError, ScanOptions, ScanStart, ScannedBlock};
use scan_support::{full_scan_vector, options, rechecking_wallet, restore, snapshot, write};
use support::Harness;

#[test]
fn refuses_a_tip_beyond_any_plausible_chain_height() {
    let vector = full_scan_vector();
    let harness = Harness::new();
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(u64::MAX));

    let result = harness.block_on(wallet.scan(options(&vector), &ScanCancel::new()));

    assert!(
        matches!(result, Err(ScanError::Implausible(_))),
        "{result:?}"
    );
    assert_eq!(wallet.last_scanned_block().unwrap(), None);
    assert!(wallet.restore_scan_required().unwrap());
}

#[test]
fn refuses_outputs_above_the_tip_and_stores_none_of_them() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    wallet.close();
    let wallet = rechecking_wallet(&harness, Vec::new(), 100);

    let result = harness.block_on(wallet.scan(options(&vector), &ScanCancel::new()));

    assert!(
        matches!(result, Err(ScanError::Implausible(_))),
        "{result:?}"
    );
    let stored = snapshot(&harness);
    assert!(stored.outputs.is_empty());
    assert!(stored.last_scanned.is_none());
}

#[test]
fn keeps_a_spent_output_spent_unless_the_node_confirms_it_again() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    harness
        .block_on(wallet.scan(options(&vector), &ScanCancel::new()))
        .unwrap();
    let mut spent = snapshot(&harness).outputs.remove(0);
    spent.status = OutputStatus::Spent;
    write(&harness, |repos| repos.put_output(&spent));
    wallet.close();
    let wallet = rechecking_wallet(&harness, Vec::new(), 0);

    let summary = harness
        .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    assert_eq!(summary.revived, 0);
    let stored = snapshot(&harness)
        .outputs
        .into_iter()
        .find(|output| output.id == spent.id)
        .unwrap();
    assert_eq!(stored.status, OutputStatus::Spent);
}

#[test]
fn an_update_scan_reaches_back_from_the_tip_when_the_stored_position_is_above_it() {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    let ahead = ScannedBlock {
        height: Height::new(1_000_000),
        hash: Hash::from_slice(&[0; 32]).unwrap(),
        start_pmmr_index: 1,
        last_pmmr_index: 1,
    };
    write(&harness, |repos| {
        repos.put_setting(
            "scan.last_scanned",
            &format!(
                "{} {} {} {}",
                ahead.height,
                ahead.hash.to_hex(),
                ahead.start_pmmr_index,
                ahead.last_pmmr_index
            ),
        )
    });
    assert_eq!(wallet.last_scanned_block().unwrap(), Some(ahead));

    let summary = harness
        .block_on(wallet.scan(
            ScanOptions {
                start: ScanStart::LastScanned,
                ..options(&vector)
            },
            &ScanCancel::new(),
        ))
        .unwrap();

    assert_eq!(summary.start_height, Height::ZERO);
    assert!(summary.restored > 0);
    let scanned = wallet.last_scanned_block().unwrap().unwrap();
    assert_eq!(scanned.height, summary.end_height);
}
