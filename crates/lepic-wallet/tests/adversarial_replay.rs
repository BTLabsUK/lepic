// SPDX-License-Identifier: Apache-2.0
//! An output the wallet spent shows up unspent again: a node that lies about it, or the chain
//! after someone replays the transaction that created it (Mimblewimble lets a spent output
//! appear twice in the output set). A confirmed send is history the chain recorded; what a node
//! says later about one of its inputs must not cancel it, and a scan must not count that input
//! twice in the balance.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod scan_support;
mod support;

use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, OutputRecord, OutputStatus, TransactionEntry, TxDirection, TxId, TxState,
};
use lepic_wallet::Event;
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use scan_support::{full_scan_vector, options, restore, snapshot, write};
use support::{Harness, fixed_time};

fn scanned() -> (Harness, support::TestWallet) {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let wallet = harness.wallet();
    restore(&harness, &wallet, &vector);
    harness
        .block_on(wallet.scan(options(&vector), &ScanCancel::new()))
        .unwrap();
    (harness, wallet)
}

fn output_by_child(harness: &Harness, child: u8) -> OutputRecord {
    snapshot(harness)
        .outputs
        .into_iter()
        .find(|output| {
            output.key_id.0[12] == child
                && output.key_id.0[..12] == [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        })
        .unwrap_or_else(|| panic!("no output with child {child}"))
}

fn transaction_state(harness: &Harness, tx: TxId) -> TxState {
    snapshot(harness)
        .transactions
        .into_iter()
        .find(|stored| stored.id == tx)
        .unwrap()
        .entry
        .state
}

/// A send the chain confirmed, which spent the output at `child`.
fn confirmed_send_of(harness: &Harness, child: u8) -> (TxId, OutputRecord) {
    let mut output = output_by_child(harness, child);
    let original = output.clone();
    let spending = write(harness, |repos| {
        repos.insert_transaction(&TransactionEntry {
            account: AccountIndex(0),
            direction: TxDirection::Outgoing,
            state: TxState::Confirmed,
            slate_id: None,
            transport: None,
            amount_credited: Amount::ZERO,
            amount_debited: output.amount,
            fee: None,
            created_at: fixed_time(),
            updated_at: fixed_time(),
        })
    });
    output.status = OutputStatus::Spent;
    output.tx = Some(spending);
    write(harness, |repos| repos.put_output(&output));
    (spending, original)
}

fn unspent_total(harness: &Harness) -> u64 {
    snapshot(harness)
        .outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Unspent)
        .map(|output| output.amount.value())
        .sum()
}

#[test]
fn a_confirmed_send_stays_confirmed_when_a_scan_finds_its_input_unspent_again() {
    let (harness, wallet) = scanned();
    let (spending, original) = confirmed_send_of(&harness, 3);
    wallet.close();
    // The node holds the spent output again, as after a replay of the transaction that made it.
    let wallet =
        scan_support::rechecking_wallet(&harness, vec![scan_support::location(&original)], 0);
    let mut events = wallet.subscribe();

    harness
        .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    assert_eq!(
        transaction_state(&harness, spending),
        TxState::Confirmed,
        "a send the chain confirmed was undone by what a node said later"
    );
    let cancelled = std::iter::from_fn(|| events.try_recv().ok())
        .any(|event| matches!(event, Event::Transaction(change) if change.tx_id == spending));
    assert!(!cancelled, "the confirmed send changed state");
}

#[test]
fn a_spent_input_found_again_is_not_counted_twice_in_the_balance() {
    let (harness, wallet) = scanned();
    let before = unspent_total(&harness);
    let (_, original) = confirmed_send_of(&harness, 3);
    let after_send = unspent_total(&harness);
    assert_eq!(after_send, before - original.amount.value());
    wallet.close();
    let wallet =
        scan_support::rechecking_wallet(&harness, vec![scan_support::location(&original)], 0);

    harness
        .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()))
        .unwrap();

    // The confirmed send still debits the input, so the output cannot also be unspent: either
    // it stays spent, or the wallet records where the new copy came from.
    let revived = output_by_child(&harness, 3).status == OutputStatus::Unspent;
    let entries = snapshot(&harness).transactions;
    let debited_and_unspent = revived
        && entries.iter().any(|stored| {
            stored.entry.direction == TxDirection::Outgoing
                && stored.entry.state == TxState::Confirmed
                && stored.entry.amount_debited == original.amount
        });
    let explained = entries.iter().any(|stored| {
        stored.entry.direction == TxDirection::Incoming
            && stored.entry.amount_credited == original.amount
            && stored.entry.state == TxState::Confirmed
    });
    assert!(
        !debited_and_unspent || explained,
        "the balance shows the spent input again ({} -> {}) beside the send that spent it, \
         with no entry that says where it came from",
        after_send,
        unspent_total(&harness)
    );
}
