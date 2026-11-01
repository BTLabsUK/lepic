// SPDX-License-Identifier: Apache-2.0
//! `EpicWallet::kernel_on_chain` through the binding, on the scripted chain.

use super::http::funded_pair;
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::wallet::EpicWallet;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mined_kernel_is_located_and_an_unknown_one_is_not() {
    let pair = funded_pair().await;
    let alice = &pair.alice;
    let sent = alice
        .self_send(
            lepic_wallet::selection::SelfSendShape::Split(
                lepic_wallet::selection::SplitCount::new(2).unwrap(),
            ),
            1,
        )
        .await
        .unwrap();
    let excess = alice
        .transaction(sent.tx_id)
        .await
        .unwrap()
        .kernel_excess
        .unwrap();
    let wallet = EpicWallet::of_session(std::sync::Arc::clone(alice));

    assert_eq!(
        wallet.kernel_on_chain(excess.clone(), None).await.unwrap(),
        None
    );

    pair.chain.mine_pushed();
    pair.chain.set_height(30);
    alice.refresh().await.unwrap();
    let confirmed = alice
        .transaction(sent.tx_id)
        .await
        .unwrap()
        .confirmed_height
        .unwrap();

    let found = wallet
        .kernel_on_chain(excess.clone(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.height, confirmed);
    let above = wallet
        .kernel_on_chain(excess, Some(confirmed + 1))
        .await
        .unwrap();
    assert_eq!(above, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_excess_is_an_invalid_argument() {
    let pair = funded_pair().await;
    let wallet = EpicWallet::of_session(std::sync::Arc::clone(&pair.alice));

    for excess in ["", "zz", "08", &"00".repeat(34)] {
        assert_eq!(
            kind(wallet.kernel_on_chain(excess.to_owned(), None).await),
            WalletErrorKind::InvalidArgument,
            "{excess:?}"
        );
    }
}
