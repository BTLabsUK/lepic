// SPDX-License-Identifier: Apache-2.0
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
use lepic_primitives::params::MAX_TX_WEIGHT;
use lepic_store::{AccountIndex, KEY_ID_LEN, KeyId, OutputRecord, OutputStatus};
use lepic_wallet::selection::{
    Selection, SelectionError, SelectionRequest, SelectionStrategy, SelfInputs, SelfOutputs,
    SelfSendRequest, eligible_to_spend, estimate, select, select_max, select_to_self,
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
fn selection_error_text_carries_no_amounts() {
    let errors = [
        SelectionError::NotEnoughFunds {
            available: Amount::new(123_456_789),
            needed: Amount::new(987_654_321),
        },
        SelectionError::ChangeTooSmall {
            change: Amount::new(123_456_789),
            outputs: 3,
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(
            !text.contains("123456789") && !text.contains("987654321"),
            "{text}"
        );
    }
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

#[test]
fn the_largest_amount_spends_every_output_into_one() {
    let outputs = unspent(&[100_000_000, 200_000_000, 300_000_000]);
    for strategy in [SelectionStrategy::Smallest, SelectionStrategy::All] {
        let request = SelectionRequest {
            strategy,
            ..request(0)
        };
        let max = select_max(&outputs, &request).unwrap();
        // Three inputs and one output weigh 4 + 1 - 3 = 2.
        assert_eq!(max.amount, Amount::new(600_000_000 - 2 * MILLI_EPIC));
        assert_eq!(max.fee, Fee::new(2 * MILLI_EPIC));
        assert_eq!(max.inputs.len(), 3);
        assert!(max.change.is_empty());
        assert_eq!(
            select(
                &outputs,
                &SelectionRequest {
                    amount: max.amount,
                    ..request
                }
            ),
            Ok(max.clone())
        );
        assert!(
            select(
                &outputs,
                &SelectionRequest {
                    amount: Amount::new(max.amount.value() + 1),
                    ..request
                }
            )
            .is_err()
        );
    }
}

#[test]
fn the_largest_amount_spends_even_an_output_smaller_than_the_fee() {
    // Each input lowers the fee by one weight unit, so a small output still adds its value.
    let outputs = unspent(&[1_000 * MILLI_EPIC, 2 * MILLI_EPIC]);
    let max = select_max(&outputs, &request(0)).unwrap();
    assert_eq!(max.amount, Amount::new(999 * MILLI_EPIC));
    assert_eq!(values(&max.inputs), [2 * MILLI_EPIC, 1_000 * MILLI_EPIC]);
    assert!(max.change.is_empty());
    assert!(select(&outputs, &request(999 * MILLI_EPIC + 1)).is_err());
}

#[test]
fn the_largest_amount_of_nothing_spendable_is_a_shortfall() {
    let outputs = vec![output(0, 100_000_000, OutputStatus::Locked)];
    assert_eq!(
        select_max(&outputs, &request(0)),
        Err(SelectionError::NotEnoughFunds {
            available: Amount::ZERO,
            needed: Amount::new(1 + 5 * MILLI_EPIC),
        })
    );
}

#[test]
fn past_the_weight_limit_the_largest_amount_is_found_below_the_bound() {
    // More inputs than one transaction may weigh, so spending every output is refused.
    let count = usize::try_from(MAX_TX_WEIGHT).unwrap();
    let outputs = vec![output(0, 10 * MILLI_EPIC, OutputStatus::Unspent); count];
    let request = SelectionRequest {
        max_outputs: NonZeroUsize::new(2).unwrap(),
        ..request(0)
    };
    let bound = 10 * MILLI_EPIC * MAX_TX_WEIGHT - MILLI_EPIC;
    assert!(matches!(
        select(
            &outputs,
            &SelectionRequest {
                amount: Amount::new(bound),
                ..request
            }
        ),
        Err(SelectionError::TooHeavy { .. })
    ));

    let max = select_max(&outputs, &request).unwrap();
    assert!(max.amount < Amount::new(bound));
    assert!(max.amount > Amount::ZERO);
    assert!(max.inputs.len() < count);
    // The search ends between an accepted amount and a refused one next to it.
    assert!(
        select(
            &outputs,
            &SelectionRequest {
                amount: Amount::new(max.amount.value() + 1),
                ..request
            }
        )
        .is_err()
    );
    assert_eq!(
        select(
            &outputs,
            &SelectionRequest {
                amount: max.amount,
                ..request
            }
        ),
        Ok(max)
    );
}

#[test]
fn sends_need_by_default_the_confirmations_the_balance_counts_as_spendable() {
    let account = AccountIndex(0);
    let defaults = [
        lepic_wallet::selection::SelectionOptions::new(account).minimum_confirmations,
        lepic_wallet::send::SendRequest::new(account, Amount::new(1)).minimum_confirmations,
        lepic_wallet::invoice::PayRequest::new(account, Amount::new(1)).minimum_confirmations,
    ];
    assert_eq!(
        defaults,
        [lepic_wallet::refresh::DEFAULT_MINIMUM_CONFIRMATIONS; 3]
    );
    assert_eq!(lepic_wallet::refresh::DEFAULT_MINIMUM_CONFIRMATIONS, 6);
}

/// `count` unspent outputs of `value` each, more than one byte can number.
fn many_unspent(count: usize, value: u64) -> Vec<OutputRecord> {
    (0..count)
        .map(|n| {
            let n = u16::try_from(n).unwrap();
            let mut record = output(0, value, OutputStatus::Unspent);
            let blinding = {
                let mut bytes = [1; 32];
                bytes[..2].copy_from_slice(&n.to_be_bytes());
                SecretKey::from_array(bytes).unwrap()
            };
            record.id = OutputIdentifier::new(
                OutputFeatures::Plain,
                Commitment::commit(value, &blinding).unwrap(),
            );
            record.key_id.0[11..13].copy_from_slice(&n.to_be_bytes());
            record
        })
        .collect()
}

fn to_self(
    outputs: &[OutputRecord],
    inputs: SelfInputs,
    wanted: SelfOutputs,
) -> Result<Selection, SelectionError> {
    select_to_self(
        outputs,
        &request(0),
        &SelfSendRequest {
            inputs,
            outputs: wanted,
        },
    )
}

fn self_send(outputs: &[OutputRecord], wanted: SelfOutputs) -> Result<Selection, SelectionError> {
    to_self(outputs, SelfInputs::All, wanted)
}

fn amounts(values: &[u64]) -> SelfOutputs {
    SelfOutputs::Amounts(values.iter().copied().map(Amount::new).collect())
}

/// The value of every output a selection makes, the amount first.
fn made(selection: &Selection) -> Vec<u64> {
    std::iter::once(selection.amount)
        .chain(selection.change.iter().copied())
        .map(Amount::value)
        .collect()
}

#[test]
fn a_self_send_spends_at_most_the_output_limit_taking_the_smallest() {
    let mut outputs = many_unspent(501, 1_000 * MILLI_EPIC);
    outputs[7].amount = Amount::new(5_000 * MILLI_EPIC);
    for count in [1, 3] {
        let shape = SelfOutputs::Count(count);
        let selection = self_send(&outputs, shape.clone()).unwrap();

        assert_eq!(selection.inputs.len(), 500, "{shape:?}");
        assert!(
            selection
                .inputs
                .iter()
                .all(|input| input.amount.value() == 1_000 * MILLI_EPIC),
            "the largest output is left spendable"
        );
        assert_eq!(selection.total, Amount::new(500 * 1_000 * MILLI_EPIC));
        // 500 inputs and `count` outputs weigh 4 * count + 1 - 500, floored at 1.
        let weight = (4 * count as u64 + 1).saturating_sub(500).max(1);
        assert_eq!(selection.fee, Fee::new(weight * MILLI_EPIC));
        let made: u64 =
            selection.amount.value() + selection.change.iter().map(|c| c.value()).sum::<u64>();
        assert_eq!(made + selection.fee.value(), selection.total.value());
        assert_eq!(selection.change.len(), count - 1);
    }
}

#[test]
fn refuses_to_consolidate_fewer_than_two_spendable_outputs() {
    for outputs in [Vec::new(), unspent(&[100 * MILLI_EPIC])] {
        assert_eq!(
            self_send(&outputs, SelfOutputs::Count(1)),
            Err(SelectionError::NothingToConsolidate {
                outputs: outputs.len()
            })
        );
    }
    let two = unspent(&[100 * MILLI_EPIC, 100 * MILLI_EPIC]);
    let selection = self_send(&two, SelfOutputs::Count(1)).unwrap();
    assert_eq!(selection.inputs.len(), 2);
    assert!(selection.change.is_empty());
    // Two inputs and one output weigh 4 + 1 - 2 = 3.
    assert_eq!(
        selection.amount,
        Amount::new(200 * MILLI_EPIC - 3 * MILLI_EPIC)
    );
}

#[test]
fn a_split_of_one_output_is_allowed_and_splits_it_evenly() {
    let outputs = unspent(&[1_000 * MILLI_EPIC + 5]);
    let selection = self_send(&outputs, SelfOutputs::Count(4)).unwrap();

    // One input and four outputs weigh 16 + 1 - 1 = 16.
    let left = 1_000 * MILLI_EPIC + 5 - 16 * MILLI_EPIC;
    let share = left / 4;
    assert_eq!(selection.amount, Amount::new(share));
    assert_eq!(
        selection.change,
        vec![
            Amount::new(share),
            Amount::new(share),
            Amount::new(share + left % 4)
        ]
    );
}

#[test]
fn amounts_are_paid_one_output_each_and_the_remainder_comes_back_as_one_more() {
    let outputs = unspent(&[300 * MILLI_EPIC, 500 * MILLI_EPIC]);
    let selection = self_send(&outputs, amounts(&[100 * MILLI_EPIC, 200 * MILLI_EPIC])).unwrap();

    // Two inputs and three outputs weigh 12 + 1 - 2 = 11.
    assert_eq!(selection.fee, Fee::new(11 * MILLI_EPIC));
    assert_eq!(
        made(&selection),
        vec![100 * MILLI_EPIC, 200 * MILLI_EPIC, (500 - 11) * MILLI_EPIC]
    );
    assert_eq!(selection.inputs.len(), 2);
}

#[test]
fn amounts_that_take_everything_but_the_fee_leave_no_remainder() {
    // Two inputs and two outputs weigh 8 + 1 - 2 = 7.
    let outputs = unspent(&[300 * MILLI_EPIC, 500 * MILLI_EPIC]);
    let selection = self_send(&outputs, amounts(&[100 * MILLI_EPIC, 693 * MILLI_EPIC])).unwrap();
    assert_eq!(selection.fee, Fee::new(7 * MILLI_EPIC));
    assert_eq!(made(&selection), vec![100 * MILLI_EPIC, 693 * MILLI_EPIC]);
}

#[test]
fn amounts_refuse_a_remainder_too_small_for_its_own_output() {
    // Exactly: fee 7. With a remainder: three outputs, fee 11, so 4 milli would not even
    // pay for the remainder's output.
    let outputs = unspent(&[300 * MILLI_EPIC, 500 * MILLI_EPIC]);
    assert_eq!(
        self_send(&outputs, amounts(&[100 * MILLI_EPIC, 690 * MILLI_EPIC])),
        Err(SelectionError::NotEnoughFunds {
            available: Amount::new(800 * MILLI_EPIC),
            needed: Amount::new(801 * MILLI_EPIC + 1),
        })
    );
    assert!(matches!(
        self_send(&outputs, amounts(&[900 * MILLI_EPIC])),
        Err(SelectionError::NotEnoughFunds { .. })
    ));
}

#[test]
fn the_smallest_inputs_are_the_fewest_smallest_that_cover_the_amounts_and_the_fee() {
    let outputs = unspent(&[
        50 * MILLI_EPIC,
        900 * MILLI_EPIC,
        60 * MILLI_EPIC,
        70 * MILLI_EPIC,
    ]);
    let selection = to_self(
        &outputs,
        SelfInputs::Smallest,
        amounts(&[60 * MILLI_EPIC, 60 * MILLI_EPIC]),
    )
    .unwrap();

    // 50 + 60 + 70 = 180 pays 120 and the fee of three inputs and three outputs, 12 + 1 - 3
    // = 10, with 50 left over.
    assert_eq!(
        values(&selection.inputs),
        [50, 60, 70].map(|v| v * MILLI_EPIC).to_vec()
    );
    assert_eq!(selection.fee, Fee::new(10 * MILLI_EPIC));
    assert_eq!(
        made(&selection),
        vec![60 * MILLI_EPIC, 60 * MILLI_EPIC, 50 * MILLI_EPIC]
    );
}

#[test]
fn the_smallest_inputs_take_a_second_rather_than_move_one_output_into_one() {
    // One input and one output weigh 4 + 1 - 1 = 4, so 54 alone pays 50 exactly.
    let outputs = unspent(&[54 * MILLI_EPIC, 100 * MILLI_EPIC]);
    let selection = to_self(&outputs, SelfInputs::Smallest, amounts(&[50 * MILLI_EPIC])).unwrap();
    assert_eq!(selection.inputs.len(), 2);

    let alone = unspent(&[54 * MILLI_EPIC]);
    assert_eq!(
        to_self(&alone, SelfInputs::Smallest, amounts(&[50 * MILLI_EPIC])),
        Err(SelectionError::NothingToConsolidate { outputs: 1 })
    );
}

#[test]
fn the_smallest_inputs_report_what_all_of_them_lack() {
    let outputs = unspent(&[50 * MILLI_EPIC, 60 * MILLI_EPIC]);
    assert!(matches!(
        to_self(&outputs, SelfInputs::Smallest, amounts(&[500 * MILLI_EPIC])),
        Err(SelectionError::NotEnoughFunds { available, .. })
            if available == Amount::new(110 * MILLI_EPIC)
    ));
}

#[test]
fn every_input_into_one_output_of_its_value_is_refused_for_a_single_output() {
    // One input into exactly one output only moves it.
    let outputs = unspent(&[54 * MILLI_EPIC]);
    assert_eq!(
        self_send(&outputs, amounts(&[50 * MILLI_EPIC])),
        Err(SelectionError::NothingToConsolidate { outputs: 1 })
    );
}

#[test]
fn named_inputs_are_spent_as_named_even_one_into_one() {
    let outputs = unspent(&[50 * MILLI_EPIC, 60 * MILLI_EPIC, 70 * MILLI_EPIC]);
    let named = vec![outputs[2].id.commitment, outputs[0].id.commitment];
    let selection = to_self(
        &outputs,
        SelfInputs::Named(named),
        amounts(&[20 * MILLI_EPIC]),
    )
    .unwrap();
    assert_eq!(
        values(&selection.inputs),
        vec![50 * MILLI_EPIC, 70 * MILLI_EPIC]
    );
    // Two inputs and two outputs weigh 8 + 1 - 2 = 7.
    assert_eq!(made(&selection), vec![20 * MILLI_EPIC, 93 * MILLI_EPIC]);

    let one = to_self(
        &outputs,
        SelfInputs::Named(vec![outputs[1].id.commitment]),
        SelfOutputs::Count(1),
    )
    .unwrap();
    // One input and one output weigh 4.
    assert_eq!(made(&one), vec![56 * MILLI_EPIC]);
}

#[test]
fn named_inputs_refuse_none_twice_or_unknown() {
    let outputs = unspent(&[50 * MILLI_EPIC, 60 * MILLI_EPIC]);
    let other = unspent(&[1, 2, 3])[2].id.commitment;
    let named = |commitments| {
        to_self(
            &outputs,
            SelfInputs::Named(commitments),
            SelfOutputs::Count(1),
        )
    };
    assert_eq!(named(Vec::new()), Err(SelectionError::NoOutputsNamed));
    assert_eq!(
        named(vec![outputs[0].id.commitment, outputs[0].id.commitment]),
        Err(SelectionError::NamedOutputUnavailable { position: 1 })
    );
    assert_eq!(
        named(vec![other]),
        Err(SelectionError::NamedOutputUnavailable { position: 0 })
    );
}

#[test]
fn refuses_outputs_out_of_range_zero_amounts_and_smallest_with_a_count() {
    let outputs = unspent(&[500 * MILLI_EPIC, 500 * MILLI_EPIC]);
    for wanted in [SelfOutputs::Count(0), SelfOutputs::Count(11), amounts(&[])] {
        assert!(
            matches!(
                self_send(&outputs, wanted.clone()),
                Err(SelectionError::SelfSendOutputs { .. })
            ),
            "{wanted:?}"
        );
    }
    assert_eq!(
        self_send(&outputs, amounts(&[MILLI_EPIC; 11])),
        Err(SelectionError::SelfSendOutputs { outputs: 11 })
    );
    assert_eq!(
        self_send(&outputs, amounts(&[MILLI_EPIC; 10])),
        Err(SelectionError::SelfSendOutputs { outputs: 11 }),
        "ten amounts leave a remainder that would be the eleventh"
    );
    assert_eq!(
        self_send(&outputs, amounts(&[MILLI_EPIC, 0])),
        Err(SelectionError::ZeroAmount { position: 1 })
    );
    assert_eq!(
        to_self(&outputs, SelfInputs::Smallest, SelfOutputs::Count(2)),
        Err(SelectionError::SmallestNeedsAmounts)
    );
}
