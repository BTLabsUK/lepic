//! Splits and consolidations through the binding, mined on the scripted chain.

use super::http::{EPIC, funded_pair, password};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::types::{Chain, OutputStatus, TxDirection, TxStatus};

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
    let estimate = alice
        .estimate_self_send(
            lepic_wallet::selection::SelfSendShape::Split(
                lepic_wallet::selection::SplitCount::new(4).unwrap(),
            ),
            1,
        )
        .await
        .unwrap();

    let sent = alice
        .self_send(
            lepic_wallet::selection::SelfSendShape::Split(
                lepic_wallet::selection::SplitCount::new(4).unwrap(),
            ),
            1,
        )
        .await
        .unwrap();

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

    let sent = alice
        .self_send(lepic_wallet::selection::SelfSendShape::Consolidate, 1)
        .await
        .unwrap();

    assert_eq!((sent.input_count, sent.output_count), (2, 1));
    pair.chain.mine_pushed();
    pair.chain.set_height(50);
    alice.refresh().await.unwrap();
    assert_eq!(unspent(&alice.outputs().unwrap()), [11 * EPIC - sent.fee]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_counts_outside_two_to_ten_are_refused() {
    let pair = funded_pair().await;
    let wallet = crate::api::wallet::EpicWallet::of_session(std::sync::Arc::clone(&pair.alice));
    for outputs in [0, 1, 11] {
        assert_eq!(
            kind(wallet.estimate_split(outputs, 1).await),
            WalletErrorKind::InvalidArgument
        );
        assert_eq!(
            kind(wallet.split_outputs(outputs, 1).await),
            WalletErrorKind::InvalidArgument
        );
    }
    assert_eq!(pair.chain.pushed_count(), 0);
}
