// SPDX-License-Identifier: Apache-2.0
//! How sends and estimates through the binding choose inputs and change.

use super::http::{EPIC, Pair, funded_pair, password};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::types::{Chain, OutputStatus, SelectionStrategy, SendOptions};

/// Alice holds 10 EPIC and 1 EPIC in two outputs.
async fn funded_with_two_outputs() -> Pair {
    let pair = funded_pair().await;
    let phrase = pair.alice.recovery_phrase(password()).await.unwrap();
    pair.chain.fund(phrase, Chain::Floonet, EPIC, 1).unwrap();
    pair.chain.set_height(40);
    pair.alice.scan_to_tip().await;
    pair
}

const fn options(strategy: SelectionStrategy, change_outputs: u32) -> Option<SendOptions> {
    Some(SendOptions {
        strategy,
        change_outputs,
        exclude_outputs: Vec::new(),
        payment_proof_recipient: None,
    })
}

fn excluding(commitments: Vec<String>) -> Option<SendOptions> {
    Some(SendOptions {
        exclude_outputs: commitments,
        ..options(SelectionStrategy::Smallest, 1).unwrap()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn excluded_outputs_are_left_out_of_every_estimate_and_send() {
    let pair = funded_with_two_outputs().await;
    let alice = &pair.alice;
    let outputs = alice.outputs().unwrap();
    let small = outputs
        .iter()
        .find(|output| output.value == EPIC)
        .unwrap()
        .commitment
        .clone();

    let estimate = alice
        .estimate_fee(EPIC / 2, 1, excluding(vec![small.clone()]))
        .await
        .unwrap();
    assert_eq!((estimate.input_count, estimate.locked), (1, 10 * EPIC));
    let max = alice
        .estimate_max(1, excluding(vec![small.clone()]))
        .await
        .unwrap();
    assert_eq!(max.locked, 10 * EPIC);
    let sent = alice
        .create_send_slate_with(EPIC / 2, 1, None, excluding(vec![small.clone()]))
        .await
        .unwrap();
    let locked: Vec<_> = alice
        .outputs()
        .unwrap()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .map(|output| output.commitment)
        .collect();
    assert!(!locked.contains(&small), "{locked:?}");
    assert!(alice.transaction(sent.tx_id).await.is_ok());
    assert_eq!(
        kind(
            alice
                .estimate_fee(EPIC / 2, 1, excluding(vec!["zz".to_owned()]))
                .await
        ),
        WalletErrorKind::InvalidArgument
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_without_options_spends_the_smallest_outputs_that_cover_it() {
    let pair = funded_with_two_outputs().await;
    let alice = &pair.alice;

    let smallest = alice.estimate_fee(EPIC / 2, 1, None).await.unwrap();
    let all = alice
        .estimate_fee(EPIC / 2, 1, options(SelectionStrategy::All, 1))
        .await
        .unwrap();

    assert_eq!((smallest.input_count, smallest.locked), (1, EPIC));
    assert_eq!(smallest.change_outputs, 1);
    assert_eq!(
        smallest.locked,
        smallest.amount + smallest.fee + smallest.change
    );
    assert_eq!((all.input_count, all.locked), (2, 11 * EPIC));
    let sent = alice.create_send_slate(EPIC / 2, 1, None).await.unwrap();
    let outputs = alice.outputs().unwrap();
    let locked: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .map(|output| output.value)
        .collect();
    assert_eq!(locked, [EPIC], "the 10 EPIC output stays spendable");
    let fee = alice.transaction(sent.tx_id).await.unwrap().fee;
    assert_eq!(fee, Some(smallest.fee));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_split_into_outputs_costs_the_estimated_fee() {
    let pair = funded_with_two_outputs().await;
    let alice = &pair.alice;
    let split = options(SelectionStrategy::Smallest, 3);

    let estimate = alice
        .estimate_fee(2 * EPIC, 1, split.clone())
        .await
        .unwrap();
    let single = alice.estimate_fee(2 * EPIC, 1, None).await.unwrap();

    assert_eq!(estimate.change_outputs, 3);
    assert!(
        estimate.fee > single.fee,
        "each change output adds to the fee"
    );
    let path = pair.dirs[0].path().join("split.slate");
    let sent = alice
        .send_file(2 * EPIC, 1, path, None, split)
        .await
        .unwrap();
    assert_eq!(sent.fee, estimate.fee);
    let change: Vec<_> = alice
        .outputs()
        .unwrap()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .map(|output| output.value)
        .collect();
    assert_eq!(change.len(), 3);
    assert_eq!(change.iter().sum::<u64>(), estimate.change);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_outputs_outside_one_to_ten_are_refused_before_anything_is_stored() {
    let pair = funded_with_two_outputs().await;
    let alice = &pair.alice;
    for count in [0, 11] {
        let refused = alice
            .create_send_slate_with(EPIC, 1, None, options(SelectionStrategy::Smallest, count))
            .await;
        assert_eq!(kind(refused), WalletErrorKind::InvalidArgument, "{count}");
        let estimate = alice
            .estimate_max(1, options(SelectionStrategy::All, count))
            .await;
        assert_eq!(kind(estimate), WalletErrorKind::InvalidArgument, "{count}");
    }
    assert!(
        alice
            .transactions()
            .await
            .unwrap()
            .iter()
            .all(|tx| tx.direction == crate::api::types::TxDirection::Incoming)
    );
}
