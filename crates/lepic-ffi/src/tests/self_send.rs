// SPDX-License-Identifier: Apache-2.0
//! Sends to the wallet itself through the binding, mined on the scripted chain.

use super::http::{EPIC, funded_pair, password};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::types::{
    Chain, OutputStatus, SelfInputs, SelfOutputs, SelfSendRequest, TxDirection, TxStatus,
};
use crate::api::wallet::EpicWallet;

/// Every spendable output into `count` outputs, as a split tool asks.
pub(super) fn split(count: u32) -> SelfSendRequest {
    SelfSendRequest {
        inputs: SelfInputs::All,
        named: Vec::new(),
        outputs: SelfOutputs::Count,
        count,
        amounts: Vec::new(),
    }
}

fn unspent(values: &[crate::api::types::WalletOutput]) -> Vec<u64> {
    values
        .iter()
        .filter(|output| output.status == OutputStatus::Unspent)
        .map(|output| output.value)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_is_mined_into_that_many_spendable_outputs() {
    let pair = funded_pair().await;
    let alice = &pair.alice;
    let estimate = alice.estimate_send_to_self(split(4), 1).await.unwrap();

    let sent = alice.send_to_self(split(4), 1).await.unwrap();

    assert_eq!(
        (sent.fee, sent.input_count, sent.output_count),
        (estimate.fee, 1, 4)
    );
    assert_eq!(estimate.change_outputs, 3);
    assert_eq!(pair.chain.pushed_count(), 1);
    pair.chain.mine_pushed();
    pair.chain.set_height(30);
    let summary = alice.refresh().await.unwrap();
    assert_eq!(summary.total, 10 * EPIC - sent.fee);
    let outputs = unspent(&alice.outputs().unwrap());
    assert_eq!(outputs.len(), 4);
    assert_eq!(outputs.iter().sum::<u64>(), 10 * EPIC - sent.fee);
    for tx_id in [sent.tx_id, sent.received_tx_id] {
        let tx = alice.transaction(tx_id).await.unwrap();
        assert_eq!(tx.status, TxStatus::Confirmed, "{tx_id}");
        assert_eq!(tx.transport.as_deref(), Some("self"));
    }
    let received = alice.transaction(sent.received_tx_id).await.unwrap();
    assert_eq!(received.direction, TxDirection::Incoming);
    assert_eq!(received.amount_credited, sent.amount);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consolidation_is_mined_into_one_output() {
    let pair = funded_pair().await;
    let alice = &pair.alice;
    let phrase = alice.recovery_phrase(password()).await.unwrap();
    pair.chain.fund(phrase, Chain::Floonet, EPIC, 1).unwrap();
    pair.chain.set_height(40);
    alice.scan_to_tip().await;

    let sent = alice.send_to_self(split(1), 1).await.unwrap();

    assert_eq!((sent.input_count, sent.output_count), (2, 1));
    pair.chain.mine_pushed();
    pair.chain.set_height(50);
    alice.refresh().await.unwrap();
    assert_eq!(unspent(&alice.outputs().unwrap()), [11 * EPIC - sent.fee]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_outputs_are_paid_out_in_the_amounts_asked_for_and_the_rest() {
    let pair = funded_pair().await;
    let alice = &pair.alice;
    let funding = alice.outputs().unwrap().remove(0).commitment;
    let request = SelfSendRequest {
        inputs: SelfInputs::Named,
        named: vec![funding.to_ascii_uppercase()],
        outputs: SelfOutputs::Amounts,
        count: 0,
        amounts: vec![EPIC, 2 * EPIC],
    };
    let estimate = alice
        .estimate_send_to_self(request.clone(), 1)
        .await
        .unwrap();

    let sent = alice.send_to_self(request, 1).await.unwrap();

    assert_eq!(
        (sent.amount, sent.fee, sent.input_count, sent.output_count),
        (EPIC, estimate.fee, 1, 3)
    );
    assert_eq!(estimate.change, 2 * EPIC + (7 * EPIC - estimate.fee));
    pair.chain.mine_pushed();
    pair.chain.set_height(30);
    alice.refresh().await.unwrap();
    let mut outputs = unspent(&alice.outputs().unwrap());
    outputs.sort_unstable();
    assert_eq!(outputs, [EPIC, 2 * EPIC, 7 * EPIC - sent.fee]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_to_self_refuses_what_its_kinds_do_not_use_or_allow() {
    let pair = funded_pair().await;
    let wallet = EpicWallet::of_session(std::sync::Arc::clone(&pair.alice));
    let amounts = |inputs, amounts: Vec<u64>| SelfSendRequest {
        inputs,
        named: Vec::new(),
        outputs: SelfOutputs::Amounts,
        count: 0,
        amounts,
    };
    let invalid = [
        split(0),
        split(11),
        SelfSendRequest {
            amounts: vec![EPIC],
            ..split(2)
        },
        SelfSendRequest {
            count: 2,
            ..amounts(SelfInputs::All, vec![EPIC])
        },
        SelfSendRequest {
            named: vec!["00".to_owned()],
            ..split(2)
        },
        SelfSendRequest {
            inputs: SelfInputs::Named,
            named: vec!["00".to_owned()],
            ..split(2)
        },
        SelfSendRequest {
            inputs: SelfInputs::Named,
            ..split(2)
        },
        SelfSendRequest {
            inputs: SelfInputs::Smallest,
            ..split(2)
        },
        amounts(SelfInputs::All, vec![EPIC, 0]),
        amounts(SelfInputs::All, Vec::new()),
    ];
    for request in invalid {
        assert_eq!(
            kind(wallet.estimate_send_to_self(request.clone(), 1).await),
            WalletErrorKind::InvalidArgument,
            "{request:?}"
        );
        assert_eq!(
            kind(wallet.send_to_self(request.clone(), 1).await),
            WalletErrorKind::InvalidArgument,
            "{request:?}"
        );
    }
    // The one funding output into one output only moves it.
    assert_eq!(
        kind(wallet.estimate_send_to_self(split(1), 1).await),
        WalletErrorKind::NothingToConsolidate
    );
    assert_eq!(
        kind(wallet.send_to_self(split(1), 1).await),
        WalletErrorKind::NothingToConsolidate
    );
    assert_eq!(
        kind(
            wallet
                .send_to_self(amounts(SelfInputs::All, vec![20 * EPIC]), 1)
                .await
        ),
        WalletErrorKind::NotEnoughFunds
    );
    assert_eq!(pair.chain.pushed_count(), 0);
}
