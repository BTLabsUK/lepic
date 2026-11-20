// SPDX-License-Identifier: Apache-2.0
//! Node answers that are well formed but cannot be true: a tip far ahead of the one the client
//! saw moments ago, and outputs or kernels in blocks above the tip.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::path::PathBuf;
use std::time::Duration;

use lepic_crypto::Commitment;
use lepic_node::mock::{ChainOutput, ChainState, MockNode};
use lepic_node::{FieldProblem, LocatedKernel, NodeApi, NodeError, NodeVersion, Tip};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::Transaction;
use serde_json::Value;

const TIP: u64 = 20;
/// Blocks the client allows above its reference tip at zero elapsed time.
const ALLOWANCE: u64 = 1_440;

#[cfg(test)]
fn transaction() -> Transaction {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/primitives/tx_valid_plain_1_in_2_out.json");
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = vector["expected"]["serialized_v2"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    Transaction::decode(&bytes, ProtocolVersion::V2).unwrap()
}

/// A chain at height `TIP` holding the outputs and kernel of a real transaction, all mined in
/// block `mined_at`.
#[cfg(test)]
fn node_with_transaction_at(mined_at: u64) -> (MockNode, Transaction) {
    let transaction = transaction();
    let mut chain = ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(TIP),
            last_block_pushed: Hash::from_bytes([7; 32]),
        },
    );
    for (position, output) in transaction.outputs().iter().enumerate() {
        chain.outputs.push(ChainOutput {
            commitment: output.commitment,
            features: output.features,
            proof: output.proof.clone(),
            height: Height::new(mined_at),
            mmr_index: 4 + position as u64,
            spent: false,
        });
    }
    chain.kernels.push(LocatedKernel {
        kernel: transaction.kernels()[0],
        height: Height::new(mined_at),
        mmr_index: 3,
    });
    (MockNode::from_chain(chain), transaction)
}

#[cfg(test)]
fn commitments(transaction: &Transaction) -> Vec<Commitment> {
    transaction
        .outputs()
        .iter()
        .map(|output| output.commitment)
        .collect()
}

#[cfg(test)]
fn set_tip(node: &MockNode, height: u64) {
    assert!(node.update_chain(|chain| chain.tip.height = Height::new(height)));
}

#[cfg(test)]
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(future)
}

#[cfg(test)]
fn assert_above_tip(error: NodeError, expected_field: &str) {
    match error {
        NodeError::InvalidField {
            field,
            problem: FieldProblem::AboveTip,
            ..
        } if field == expected_field => {}
        other => panic!("expected {expected_field} above the tip, got {other:?}"),
    }
}

#[test]
fn rejects_a_tip_implausibly_far_above_the_previous_one() {
    let (node, _) = node_with_transaction_at(10);
    let client = node.client();
    assert_eq!(block_on(client.get_tip()).unwrap().height, Height::new(TIP));

    set_tip(&node, u64::MAX);
    let error = block_on(client.get_tip()).unwrap_err();
    assert!(
        matches!(
            error,
            NodeError::ImplausibleTip { previous, reported }
                if previous == Height::new(TIP) && reported == Height::new(u64::MAX)
        ),
        "{error:?}"
    );
    assert!(!error.is_transient());

    // The refused tip does not become the reference for the next answer.
    set_tip(&node, TIP + 3);
    assert_eq!(
        block_on(client.get_tip()).unwrap().height,
        Height::new(TIP + 3)
    );
}

#[test]
fn accepts_ordinary_tip_movement() {
    let (node, _) = node_with_transaction_at(10);
    let client = node.client();
    block_on(client.get_tip()).unwrap();

    set_tip(&node, TIP + 60);
    assert_eq!(
        block_on(client.get_tip()).unwrap().height,
        Height::new(TIP + 60)
    );
    // A reorganisation or a node that is a little behind may report a lower tip.
    set_tip(&node, TIP + 55);
    assert_eq!(
        block_on(client.get_tip()).unwrap().height,
        Height::new(TIP + 55)
    );
    set_tip(&node, TIP + 62);
    assert_eq!(
        block_on(client.get_tip()).unwrap().height,
        Height::new(TIP + 62)
    );
}

#[test]
fn a_lower_tip_does_not_lower_the_reference() {
    let (node, _) = node_with_transaction_at(10);
    let client = node.client();
    block_on(client.get_tip()).unwrap();

    set_tip(&node, TIP - 10);
    block_on(client.get_tip()).unwrap();
    // Allowed from TIP, but 10 blocks too many if the lower tip had become the reference.
    set_tip(&node, TIP + ALLOWANCE);
    assert_eq!(
        block_on(client.get_tip()).unwrap().height,
        Height::new(TIP + ALLOWANCE)
    );
}

#[test]
fn a_known_tip_bounds_the_first_tip_of_a_session() {
    let known = Height::new(TIP);

    let (node, _) = node_with_transaction_at(10);
    set_tip(&node, known.value() + ALLOWANCE + 1);
    let client = node.client().with_known_tip(known, Duration::ZERO);
    let error = block_on(client.get_tip()).unwrap_err();
    assert!(
        matches!(error, NodeError::ImplausibleTip { previous, .. } if previous == known),
        "{error:?}"
    );

    // An hour since the known tip allows 240 blocks more, four times the target rate.
    let client = node
        .client()
        .with_known_tip(known, Duration::from_secs(3_600));
    assert_eq!(
        block_on(client.get_tip()).unwrap().height,
        Height::new(known.value() + ALLOWANCE + 1)
    );
    set_tip(&node, known.value() + ALLOWANCE + 241);
    let client = node
        .client()
        .with_known_tip(known, Duration::from_secs(3_600));
    assert!(matches!(
        block_on(client.get_tip()),
        Err(NodeError::ImplausibleTip { .. })
    ));
}

#[test]
fn rejects_outputs_above_the_tip() {
    let (node, transaction) = node_with_transaction_at(TIP + 1);
    let client = node.client();
    block_on(client.get_tip()).unwrap();

    let error = block_on(client.get_outputs(&commitments(&transaction))).unwrap_err();
    assert_above_tip(error, "block_height");
    let error = block_on(client.get_unspent_outputs(1, None, 10)).unwrap_err();
    assert_above_tip(error, "block_height");
}

#[test]
fn rejects_kernels_above_the_tip() {
    let (node, transaction) = node_with_transaction_at(TIP + 1);
    let client = node.client();
    block_on(client.get_tip()).unwrap();

    let excess = transaction.kernels()[0].excess;
    let error = block_on(client.get_kernel(&excess, None, None)).unwrap_err();
    assert_above_tip(error, "height");
}

#[test]
fn checks_heights_against_a_fresh_tip_when_none_was_seen() {
    let (node, transaction) = node_with_transaction_at(TIP + 1);
    let client = node.client();

    let error = block_on(client.get_outputs(&commitments(&transaction))).unwrap_err();
    assert_above_tip(error, "block_height");
    assert_eq!(node.calls(), ["get_outputs", "get_tip"]);
}

#[test]
fn accepts_outputs_from_a_block_found_since_the_last_tip() {
    let (node, transaction) = node_with_transaction_at(TIP + 1);
    let client = node.client();
    block_on(client.get_tip()).unwrap();
    set_tip(&node, TIP + 1);

    let found = block_on(client.get_outputs(&commitments(&transaction))).unwrap();
    assert_eq!(found.len(), transaction.outputs().len());
    let excess = transaction.kernels()[0].excess;
    let kernel = block_on(client.get_kernel(&excess, None, None)).unwrap();
    assert_eq!(kernel.unwrap().height, Height::new(TIP + 1));
    assert_eq!(
        node.calls(),
        ["get_tip", "get_outputs", "get_tip", "get_kernel"]
    );
    assert!(node.violations().is_empty(), "{:?}", node.violations());
}
