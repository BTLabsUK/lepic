// SPDX-License-Identifier: Apache-2.0
//! What `node_tip` reports of the node.

use super::Fixture;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_tip_carries_readiness_when_the_node_knows_it_and_the_tip_time() {
    let fixture = Fixture::new();
    fixture.chain.set_height(30);

    let old = crate::api::wallet::node_tip(&fixture.runtime, fixture.config())
        .await
        .unwrap();
    fixture.chain.set_node_ready_for_txs(Some(false));
    let syncing = crate::api::wallet::node_tip(&fixture.runtime, fixture.config())
        .await
        .unwrap();
    fixture.chain.set_node_ready_for_txs(Some(true));
    let ready = crate::api::wallet::node_tip(&fixture.runtime, fixture.config())
        .await
        .unwrap();

    assert_eq!(old.height, 30);
    assert_eq!(
        (
            old.ready_for_txs,
            syncing.ready_for_txs,
            ready.ready_for_txs
        ),
        (None, Some(false), Some(true))
    );
    let block_time = ready.tip_time_ms.unwrap();
    assert_eq!(old.tip_time_ms, Some(block_time));
    fixture.chain.set_height(31);
    let next = crate::api::wallet::node_tip(&fixture.runtime, fixture.config())
        .await
        .unwrap();
    assert!(
        next.tip_time_ms.unwrap() > block_time,
        "a later block, a later time"
    );
}
