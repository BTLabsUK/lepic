// SPDX-License-Identifier: Apache-2.0
//! The scripted mock node, as the engine, CLI and binding tests will drive it.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_node::mock::{ChainOutput, ChainState, MockFailure, MockNode};
use lepic_node::{
    CallPolicy, LocatedKernel, NodeApi, NodeClient, NodeError, NodeVersion, PoolTransaction,
    Propagation, RejectionKind, RetryPolicy, Tip,
};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::Transaction;
use serde_json::Value;

#[cfg(test)]
fn vector(path: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors")
        .join(path);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[cfg(test)]
fn transaction() -> Transaction {
    let vector = vector("primitives/tx_valid_plain_1_in_2_out.json");
    let hex = vector["expected"]["serialized_v2"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    Transaction::decode(&bytes, ProtocolVersion::V2).unwrap()
}

/// A chain whose outputs are those of a real transaction, so proofs and points are genuine.
#[cfg(test)]
fn chain() -> (ChainState, Transaction) {
    let transaction = transaction();
    let mut chain = ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(20),
            last_block_pushed: Hash::from_bytes([7; 32]),
        },
    );
    for (position, output) in transaction.outputs().iter().enumerate() {
        let position = position as u64;
        chain.outputs.push(ChainOutput {
            commitment: output.commitment,
            features: output.features,
            proof: output.proof.clone(),
            height: Height::new(10 + position * 5),
            mmr_index: 4 + position * 3,
            spent: false,
        });
    }
    chain.kernels.push(LocatedKernel {
        kernel: transaction.kernels()[0],
        height: Height::new(10),
        mmr_index: 3,
    });
    (chain, transaction)
}

#[cfg(test)]
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn serves_the_scripted_chain() {
    let (chain, transaction) = chain();
    let node = MockNode::from_chain(chain.clone());
    let client = node.client();

    assert_eq!(block_on(client.get_version()).unwrap(), chain.version);
    assert_eq!(block_on(client.get_tip()).unwrap(), chain.tip);

    let commitments: Vec<Commitment> = chain.outputs.iter().map(|o| o.commitment).collect();
    let input = transaction.inputs()[0].commitment;
    let mut asked = commitments.clone();
    asked.push(input);
    let found = block_on(client.get_outputs(&asked)).unwrap();
    let mut found: Vec<_> = found.iter().map(|location| location.commitment).collect();
    found.sort();
    let mut expected = commitments.clone();
    expected.sort();
    assert_eq!(found, expected);

    let page = block_on(client.get_unspent_outputs(1, None, 1)).unwrap();
    assert_eq!(page.outputs.len(), 1);
    assert_eq!(page.outputs[0].mmr_index, 4);
    assert_eq!(page.last_retrieved_index, 4);
    assert_eq!(page.highest_index, 7);
    assert_eq!(page.outputs[0].proof, chain.outputs[0].proof);
    let rest = block_on(client.get_unspent_outputs(5, None, 10)).unwrap();
    assert_eq!(rest.outputs.len(), 1);
    assert_eq!(rest.last_retrieved_index, 7);

    let indices = block_on(client.get_pmmr_indices(Height::new(11), None)).unwrap();
    assert_eq!((indices.first_index, indices.last_index), (5, 7));

    let excess = transaction.kernels()[0].excess;
    let kernel = block_on(client.get_kernel(&excess, None, None)).unwrap();
    assert_eq!(kernel.unwrap().kernel, transaction.kernels()[0]);
    let missing = block_on(client.get_kernel(&excess, Some(Height::new(11)), None)).unwrap();
    assert_eq!(missing, None);

    assert!(node.violations().is_empty(), "{:?}", node.violations());
}

#[test]
fn lists_the_pool_with_the_kernels_of_each_transaction() {
    let (chain, transaction) = chain();
    let node = MockNode::from_chain(chain);
    let client = node.client();
    assert_eq!(
        block_on(client.get_unconfirmed_transactions()).unwrap(),
        vec![]
    );

    assert!(node.update_chain(|chain| chain.pool.push(transaction.clone())));
    let pool = block_on(client.get_unconfirmed_transactions()).unwrap();

    assert_eq!(
        pool,
        vec![PoolTransaction {
            kernels: transaction.kernels().to_vec()
        }]
    );
    assert!(node.violations().is_empty(), "{:?}", node.violations());
}

#[test]
fn records_pushed_transactions_and_follows_chain_updates() {
    let (chain, transaction) = chain();
    let node = MockNode::from_chain(chain.clone());
    let client = node.client();

    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();
    assert_eq!(node.pushed_transactions(), vec![transaction]);

    let spent = chain.outputs[0].commitment;
    assert!(node.update_chain(|chain| chain.outputs[0].spent = true));
    assert!(block_on(client.get_outputs(&[spent])).unwrap().is_empty());
    let page = block_on(client.get_unspent_outputs(1, None, 10)).unwrap();
    assert!(page.outputs.iter().all(|output| output.commitment != spent));

    // The first answer of a session that places outputs in blocks is checked against a tip,
    // fetched for it.
    assert_eq!(
        node.calls(),
        [
            "push_transaction",
            "get_outputs",
            "get_unspent_outputs",
            "get_tip"
        ]
    );
}

#[test]
fn injected_failures_reach_the_client() {
    let (chain, _) = chain();
    let node = MockNode::from_chain(chain.clone());

    node.fail_next("get_tip", MockFailure::Unreachable);
    let retrying = NodeClient::new(
        node.clone(),
        CallPolicy {
            retry: RetryPolicy {
                max_attempts: 2,
                initial_backoff: std::time::Duration::ZERO,
                max_backoff: std::time::Duration::ZERO,
            },
            ..lepic_node::testing::call_policy()
        },
    );
    assert_eq!(block_on(retrying.get_tip()).unwrap(), chain.tip);
    assert_eq!(node.calls(), ["get_tip", "get_tip"]);

    node.fail_next("get_tip", MockFailure::Rejected(RejectionKind::Internal));
    let error = block_on(node.client().get_tip()).unwrap_err();
    assert!(matches!(
        error,
        NodeError::Rejected { ref rejection, .. } if rejection.kind == RejectionKind::Internal
    ));
    assert_eq!(block_on(node.client().get_tip()).unwrap(), chain.tip);
}

#[test]
fn a_recorded_session_cannot_take_pushes_or_chain_updates() {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/engine/refresh_spent.json"),
    )
    .unwrap();
    let recorded = MockNode::from_recording(&text).unwrap();
    let error = block_on(
        recorded
            .client()
            .push_transaction(&transaction(), Propagation::Stem),
    )
    .unwrap_err();
    assert!(matches!(error, NodeError::Rpc { .. }), "{error:?}");
    let violations = recorded.violations();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].method, "push_transaction");
    assert!(recorded.pushed_transactions().is_empty());
    assert!(!recorded.update_chain(|_| {}));
}

#[test]
fn ready_for_txs_is_unknown_from_a_node_without_the_method() {
    let (mut chain, _) = chain();
    let old = MockNode::from_chain(chain.clone());
    assert_eq!(block_on(old.client().ready_for_txs()).unwrap(), None);
    assert!(old.violations().is_empty());

    for ready in [true, false] {
        chain.ready_for_txs = Some(ready);
        let node = MockNode::from_chain(chain.clone());
        assert_eq!(
            block_on(node.client().ready_for_txs()).unwrap(),
            Some(ready)
        );
    }

    let failing = MockNode::from_chain(chain);
    failing.fail_next("ready_for_txs", MockFailure::Unreachable);
    assert!(matches!(
        block_on(failing.client().ready_for_txs()),
        Err(NodeError::Connect(_))
    ));
}
