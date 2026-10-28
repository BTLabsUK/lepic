// SPDX-License-Identifier: Apache-2.0
//! Output selection for arbitrary wallets: whatever it returns pays for itself, spends only what
//! may be spent, and accounts for every base unit.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashSet;
use std::num::NonZeroUsize;

use lepic_crypto::{Commitment, SecretKey};
use lepic_primitives::amount::{Amount, Fee, Height, MILLI_EPIC};
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::MAX_TX_WEIGHT;
use lepic_store::{AccountIndex, KEY_ID_LEN, KeyId, OutputRecord, OutputStatus};
use lepic_wallet::selection::{
    SelectionRequest, SelectionStrategy, eligible_to_spend, estimate, select, select_max,
};
use proptest::prelude::*;

const TIP: Height = Height::new(100);

fn output(n: usize, value: u64, status: OutputStatus, account: u32, height: u64) -> OutputRecord {
    let blinding = SecretKey::from_array([u8::try_from(n % 250).unwrap() + 1; 32]).unwrap();
    let mut key_id = [0; KEY_ID_LEN];
    key_id[0] = 3;
    key_id[8..12].copy_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
    OutputRecord {
        id: OutputIdentifier::new(
            OutputFeatures::Plain,
            Commitment::commit(value, &blinding).unwrap(),
        ),
        key_id: KeyId(key_id),
        account: AccountIndex(account),
        amount: Amount::new(value),
        status,
        height: Height::new(height),
        lock_height: Height::ZERO,
        mmr_index: None,
        tx: None,
    }
}

fn status() -> impl Strategy<Value = OutputStatus> {
    prop_oneof![
        6 => Just(OutputStatus::Unspent),
        1 => Just(OutputStatus::Unconfirmed),
        1 => Just(OutputStatus::Locked),
        1 => Just(OutputStatus::Spent),
    ]
}

fn wallet() -> impl Strategy<Value = Vec<OutputRecord>> {
    prop::collection::vec((1u64..5_000_000_000, status(), 0u32..2, 1u64..120), 0..40).prop_map(
        |specs| {
            specs
                .into_iter()
                .enumerate()
                .map(|(n, (value, status, account, height))| {
                    output(n, value, status, account, height)
                })
                .collect()
        },
    )
}

fn request(
    amount: u64,
    base_fee: u64,
    strategy: SelectionStrategy,
    change_outputs: usize,
    max_outputs: usize,
    minimum_confirmations: u64,
) -> SelectionRequest {
    SelectionRequest {
        account: AccountIndex(0),
        amount: Amount::new(amount),
        tip: TIP,
        minimum_confirmations,
        max_outputs: NonZeroUsize::new(max_outputs).unwrap(),
        change_outputs: NonZeroUsize::new(change_outputs).unwrap(),
        strategy,
        base_fee: Fee::new(base_fee),
    }
}

fn strategy() -> impl Strategy<Value = SelectionStrategy> {
    prop_oneof![
        Just(SelectionStrategy::Smallest),
        Just(SelectionStrategy::All)
    ]
}

fn any_request() -> impl Strategy<Value = SelectionRequest> {
    (
        1u64..6_000_000_000,
        prop_oneof![Just(MILLI_EPIC), 1u64..2_000_000],
        strategy(),
        1usize..4,
        1usize..60,
        0u64..15,
    )
        .prop_map(|(amount, base_fee, strategy, change, max, confirmations)| {
            request(amount, base_fee, strategy, change, max, confirmations)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn a_selection_covers_amount_and_fee_and_accounts_for_every_base_unit(
        outputs in wallet(),
        request in any_request(),
    ) {
        let Ok(selection) = select(&outputs, &request) else {
            return Ok(());
        };
        let inputs = selection.inputs.len() as u64;
        let change_count = selection.change.len() as u64;
        let sum: u64 = selection.inputs.iter().map(|input| input.amount.value()).sum();

        prop_assert_eq!(selection.total.value(), sum);
        prop_assert_eq!(selection.amount, request.amount);
        prop_assert!(!selection.inputs.is_empty());
        // Inputs cover the amount and the fee.
        prop_assert!(sum >= request.amount.value() + selection.fee.value());
        // The fee is the weight fee of the body that is built: the inputs, the change, the
        // receiver's output and the one kernel.
        let counts = BodyCounts::new(inputs, change_count + 1, 1);
        prop_assert!(selection.fee.value() >= counts.tx_fee(request.base_fee).unwrap().value());
        prop_assert!(selection.fee.value() > 0);
        // Change and fee and amount add up exactly to the inputs.
        let change: u64 = selection.change.iter().map(|change| change.value()).sum();
        prop_assert_eq!(sum, request.amount.value() + selection.fee.value() + change);
        prop_assert!(selection.change.iter().all(|change| change.value() > 0));
        prop_assert!(selection.change.len() <= request.change_outputs.get());
        prop_assert!(counts.weight_as_block() <= MAX_TX_WEIGHT);
    }

    #[test]
    fn a_selection_spends_only_spendable_outputs_of_its_account_once(
        outputs in wallet(),
        request in any_request(),
    ) {
        let Ok(selection) = select(&outputs, &request) else {
            return Ok(());
        };
        let mut seen = HashSet::new();
        for input in &selection.inputs {
            prop_assert_eq!(input.account, request.account);
            // Only an unconfirmed output of the wallet's own, and only with no confirmations
            // required, may stand in for an unspent one.
            prop_assert!(
                input.status == OutputStatus::Unspent
                    || (input.status == OutputStatus::Unconfirmed
                        && request.minimum_confirmations == 0)
            );
            prop_assert!(eligible_to_spend(input, request.tip, request.minimum_confirmations));
            prop_assert!(seen.insert(input.id.commitment.to_hex()), "an input was chosen twice");
            prop_assert!(outputs.iter().any(|own| own.id == input.id));
        }
    }

    #[test]
    fn an_estimate_agrees_with_the_selection_it_stands_for(
        outputs in wallet(),
        request in any_request(),
    ) {
        if let Ok(selection) = select(&outputs, &request) {
            let estimated = estimate(&outputs, &request).unwrap();
            prop_assert_eq!(estimated.total, selection.total);
            prop_assert_eq!(estimated.fee, selection.fee);
        }
    }

    #[test]
    fn the_largest_selection_leaves_no_change_to_spare_and_covers_its_fee(
        outputs in wallet(),
        request in any_request(),
    ) {
        if let Ok(selection) = select_max(&outputs, &request) {
            let change: u64 = selection.change.iter().map(|change| change.value()).sum();
            let sum: u64 = selection.inputs.iter().map(|input| input.amount.value()).sum();
            prop_assert_eq!(sum, selection.amount.value() + selection.fee.value() + change);
            prop_assert!(selection.amount.value() >= 1);
        }
    }
}
