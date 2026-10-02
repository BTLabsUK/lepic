//! Output selection beyond the upstream vectors: inputs upstream does not handle, accounts, and
//! the guarantees the send stage relies on.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::num::NonZeroUsize;

use lepic_crypto::{Commitment, SecretKey};
use lepic_primitives::amount::{Amount, Fee, Height, MILLI_EPIC};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_store::{AccountIndex, KEY_ID_LEN, KeyId, OutputRecord, OutputStatus};
use lepic_wallet::selection::{
    SelectionError, SelectionRequest, SelectionStrategy, eligible_to_spend, estimate, select,
};

const TIP: Height = Height::new(100);

fn output(n: u8, value: u64, status: OutputStatus) -> OutputRecord {
    let blinding = SecretKey::from_array([n + 1; 32]).unwrap();
    let mut key_id = [0; KEY_ID_LEN];
    key_id[0] = 3;
    key_id[12] = n;
    OutputRecord {
        id: OutputIdentifier::new(
            OutputFeatures::Plain,
            Commitment::commit(value, &blinding).unwrap(),
        ),
        key_id: KeyId(key_id),
        account: AccountIndex(0),
        amount: Amount::new(value),
        status,
        height: Height::new(10),
        lock_height: Height::ZERO,
        mmr_index: None,
        tx: None,
    }
}

fn unspent(values: &[u64]) -> Vec<OutputRecord> {
    values
        .iter()
        .enumerate()
        .map(|(n, value)| output(u8::try_from(n).unwrap(), *value, OutputStatus::Unspent))
        .collect()
}

fn request(amount: u64) -> SelectionRequest {
    SelectionRequest {
        account: AccountIndex(0),
        amount: Amount::new(amount),
        tip: TIP,
        minimum_confirmations: 1,
        max_outputs: NonZeroUsize::new(500).unwrap(),
        change_outputs: NonZeroUsize::new(1).unwrap(),
        strategy: SelectionStrategy::Smallest,
        base_fee: Fee::new(MILLI_EPIC),
    }
}

fn values(outputs: &[OutputRecord]) -> Vec<u64> {
    outputs.iter().map(|output| output.amount.value()).collect()
}

#[test]
fn reports_a_shortfall_where_no_set_within_or_past_the_limit_covers_the_amount() {
    let outputs = unspent(&[100_000_000, 200_000_000, 300_000_000]);
    let request = SelectionRequest {
        max_outputs: NonZeroUsize::new(2).unwrap(),
        ..request(1_000_000_000)
    };
    let expected = SelectionError::NotEnoughFunds {
        available: Amount::new(500_000_000),
        needed: Amount::new(1_000_700_000),
    };
    assert_eq!(select(&outputs, &request), Err(expected));
    assert_eq!(estimate(&outputs, &request), Err(expected));
}

#[test]
fn ignores_outputs_of_other_accounts() {
    let mut outputs = unspent(&[100_000_000, 900_000_000]);
    outputs[0].account = AccountIndex(1);
    let selected = select(&outputs, &request(50_000_000)).unwrap();
    assert_eq!(values(&selected.inputs), [900_000_000]);
}

#[test]
fn never_spends_spent_or_locked_outputs_or_an_unconfirmed_coinbase() {
    let mut coinbase = output(2, 400_000_000, OutputStatus::Unconfirmed);
    coinbase.id.features = OutputFeatures::Coinbase;
    let outputs = [
        output(0, 100_000_000, OutputStatus::Spent),
        output(1, 200_000_000, OutputStatus::Locked),
        coinbase,
    ];
    for output in &outputs {
        assert!(!eligible_to_spend(output, TIP, 0));
    }
    let request = SelectionRequest {
        minimum_confirmations: 0,
        ..request(1)
    };
    assert_eq!(
        select(&outputs, &request),
        Err(SelectionError::NotEnoughFunds {
            available: Amount::ZERO,
            needed: Amount::new(500_001),
        })
    );
}

#[test]
fn an_output_above_the_tip_has_no_confirmations() {
    let mut output = output(0, 100, OutputStatus::Unspent);
    output.height = TIP.checked_add_blocks(1).unwrap();
    assert!(eligible_to_spend(&output, TIP, 0));
    assert!(!eligible_to_spend(&output, TIP, 1));
}

#[test]
fn change_always_adds_up_to_the_inputs_minus_amount_and_fee() {
    // 3 base units of change over 2 outputs, and 5 over 3, where upstream's remainder rule
    // would drop value.
    for (input, change_outputs, expected) in [
        (1 + 1_200_000 + 3, 2, vec![1, 2]),
        (1 + 1_600_000 + 5, 3, vec![1, 1, 3]),
    ] {
        let outputs = unspent(&[input]);
        let request = SelectionRequest {
            change_outputs: NonZeroUsize::new(change_outputs).unwrap(),
            ..request(1)
        };
        let selected = select(&outputs, &request).unwrap();
        let change: Vec<u64> = selected.change.iter().map(|value| value.value()).collect();
        assert_eq!(change, expected);
        assert_eq!(
            change.iter().sum::<u64>() + selected.fee.value() + selected.amount.value(),
            selected.total.value()
        );
    }
}

#[test]
fn rejects_change_too_small_to_split() {
    let outputs = unspent(&[1 + 1_600_000 + 2]);
    let request = SelectionRequest {
        change_outputs: NonZeroUsize::new(3).unwrap(),
        ..request(1)
    };
    assert_eq!(
        select(&outputs, &request),
        Err(SelectionError::ChangeTooSmall {
            change: Amount::new(2),
            outputs: 3,
        })
    );
    assert_eq!(estimate(&outputs, &request).unwrap().fee.value(), 1_600_000);
}

#[test]
fn rejects_a_send_over_the_transaction_weight_limit() {
    let outputs = unspent(&[u64::MAX / 2]);
    let request = SelectionRequest {
        change_outputs: NonZeroUsize::new(2_000).unwrap(),
        ..request(1)
    };
    assert_eq!(
        select(&outputs, &request),
        Err(SelectionError::TooHeavy {
            inputs: 1,
            outputs: 2_001,
        })
    );
}

#[test]
fn rejects_input_values_whose_sum_overflows() {
    let outputs = unspent(&[u64::MAX, u64::MAX]);
    let request = SelectionRequest {
        strategy: SelectionStrategy::All,
        ..request(1)
    };
    assert!(matches!(
        select(&outputs, &request),
        Err(SelectionError::Arithmetic(_))
    ));
}

#[test]
fn estimate_reports_the_total_and_fee_of_the_send() {
    let outputs = unspent(&[500_000_000, 100_000_000, 300_000_000, 1_000_000_000]);
    for strategy in [SelectionStrategy::Smallest, SelectionStrategy::All] {
        let request = SelectionRequest {
            strategy,
            ..request(200_000_000)
        };
        let estimated = estimate(&outputs, &request).unwrap();
        let selected = select(&outputs, &request).unwrap();
        assert_eq!(
            (estimated.total, estimated.fee),
            (selected.total, selected.fee)
        );
    }
}

#[test]
fn all_strategy_takes_the_whole_first_covering_window() {
    let outputs = unspent(&[
        100_000_000,
        200_000_000,
        300_000_000,
        400_000_000,
        500_000_000,
    ]);
    let request = SelectionRequest {
        max_outputs: NonZeroUsize::new(3).unwrap(),
        strategy: SelectionStrategy::All,
        ..request(250_000_000)
    };
    let selected = select(&outputs, &request).unwrap();
    assert_eq!(
        values(&selected.inputs),
        [100_000_000, 200_000_000, 300_000_000]
    );
    assert_eq!(selected.fee, Fee::new(600_000));
}

#[test]
fn past_the_limit_takes_the_smallest_outputs_that_cover_the_amount_whatever_the_strategy() {
    let outputs = unspent(&[
        100_000_000,
        110_000_000,
        120_000_000,
        130_000_000,
        140_000_000,
    ]);
    for strategy in [SelectionStrategy::Smallest, SelectionStrategy::All] {
        let request = SelectionRequest {
            max_outputs: NonZeroUsize::new(2).unwrap(),
            strategy,
            ..request(300_000_000)
        };
        let selected = select(&outputs, &request).unwrap();
        assert_eq!(
            values(&selected.inputs),
            [100_000_000, 110_000_000, 120_000_000],
            "{strategy:?}"
        );
        assert_eq!(selected.fee, Fee::new(600_000));
    }
}

#[test]
fn equal_values_are_taken_in_the_order_given() {
    let outputs = unspent(&[200_000_000, 200_000_000, 200_000_000]);
    let selected = select(&outputs, &request(300_000_000)).unwrap();
    assert_eq!(selected.inputs, outputs[..2]);
}
