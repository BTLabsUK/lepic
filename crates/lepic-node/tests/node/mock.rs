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
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::{Transaction, TransactionBody};
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
    vector_transaction("tx_valid_plain_1_in_2_out")
}

#[cfg(test)]
fn vector_transaction(name: &str) -> Transaction {
    let vector = vector(&format!("primitives/{name}.json"));
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

/// The scripted chain with the inputs of `transaction` in place of its outputs, so a node takes it.
#[cfg(test)]
fn chain_spendable_by(transaction: &Transaction) -> ChainState {
    let (mut chain, source) = chain();
    let proof = source.outputs()[0].proof.clone();
    chain.outputs = transaction
        .inputs()
        .iter()
        .enumerate()
        .map(|(position, input)| ChainOutput {
            commitment: input.commitment,
            features: input.features,
            proof: proof.clone(),
            height: Height::new(10),
            mmr_index: 1 + position as u64,
            spent: false,
        })
        .collect();
    chain
}

#[test]
fn records_pushed_transactions_and_follows_chain_updates() {
    let transaction = transaction();
    let chain = chain_spendable_by(&transaction);
    let node = MockNode::from_chain(chain.clone());
    let client = node.client();

    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();
    assert_eq!(node.pushed_transactions(), vec![transaction]);
    assert!(node.violations().is_empty(), "{:?}", node.violations());

    // The next block spends the input and holds the outputs, at the positions `chain` gives them.
    let spent = chain.outputs[0].commitment;
    let (block, _) = self::chain();
    assert!(node.update_chain(|state| {
        state.outputs[0].spent = true;
        state.outputs.extend(block.outputs);
    }));
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

/// A transaction the node refuses, with the chain it is pushed to and the violation reason.
#[cfg(test)]
fn refused_pushes() -> Vec<(&'static str, ChainState, Transaction, &'static str)> {
    let valid = transaction();
    let spendable = chain_spendable_by(&valid);
    let low_fee = {
        let mut kernels = valid.kernels().to_vec();
        kernels[0].features = KernelFeatures::Plain {
            fee: Fee::new(799_999),
        };
        Transaction::new(
            valid.offset().clone(),
            TransactionBody::new(valid.inputs().to_vec(), valid.outputs().to_vec(), kernels),
        )
    };
    let invalid = |name: &str| {
        let transaction = vector_transaction(name);
        (chain_spendable_by(&transaction), transaction)
    };
    let (signature_chain, bad_signature) = invalid("tx_invalid_kernel_signature");
    let (sum_chain, bad_sum) = invalid("tx_invalid_kernel_sum_offset");
    let (proof_chain, bad_proof) = invalid("tx_invalid_range_proof");
    let (locked_chain, locked) = invalid("tx_valid_height_locked_2_in_2_out");
    let mut spent = spendable.clone();
    spent.outputs[0].spent = true;
    let mut output_exists = spendable.clone();
    output_exists.outputs.push(ChainOutput {
        commitment: valid.outputs()[0].commitment,
        features: valid.outputs()[0].features,
        proof: valid.outputs()[0].proof.clone(),
        height: Height::new(12),
        mmr_index: 9,
        spent: false,
    });
    let mut other_features = spendable.clone();
    other_features.outputs[0].features = OutputFeatures::Coinbase;
    vec![
        (
            "Low fee transaction: 800000",
            spendable.clone(),
            low_fee,
            "push_transaction with a fee below the pool's minimum",
        ),
        (
            "Invalid Tx",
            signature_chain,
            bad_signature,
            "push_transaction with a kernel signature that does not verify",
        ),
        (
            "Invalid Tx",
            sum_chain,
            bad_sum,
            "push_transaction with kernel sums that do not balance",
        ),
        (
            "Invalid Tx",
            proof_chain,
            bad_proof,
            "push_transaction with a range proof that does not verify",
        ),
        (
            "Transaction lock height is greater than current block height",
            locked_chain,
            locked,
            "push_transaction locked above the next block",
        ),
        (
            "failed to validate tx",
            chain().0,
            valid.clone(),
            "push_transaction spending an output the chain does not hold unspent",
        ),
        (
            "failed to validate tx",
            spent,
            valid.clone(),
            "push_transaction spending an output the chain does not hold unspent",
        ),
        (
            "failed to validate tx",
            other_features,
            valid.clone(),
            "push_transaction spending an output the chain does not hold unspent",
        ),
        (
            "failed to validate tx",
            output_exists,
            valid,
            "push_transaction creating an output the chain already holds",
        ),
    ]
}

#[test]
fn a_push_the_node_would_refuse_is_answered_with_its_error_and_fails_the_test() {
    for (text, chain, transaction, reason) in refused_pushes() {
        let node = MockNode::from_chain(chain);

        let error = block_on(
            node.client()
                .push_transaction(&transaction, Propagation::Fluff),
        )
        .unwrap_err();

        let NodeError::Rejected { rejection, .. } = error else {
            panic!("{reason}: {error:?}");
        };
        assert_eq!(rejection.kind, RejectionKind::Internal, "{reason}");
        let message = rejection.message.unwrap();
        assert!(message.starts_with("Failed to update pool: "), "{message}");
        assert!(message.contains(text), "{reason}: {message}");
        assert!(node.pushed_transactions().is_empty(), "{reason}");
        let violations = node.violations();
        assert_eq!(violations.len(), 1, "{reason}");
        assert_eq!(violations[0].method, "push_transaction");
        assert_eq!(violations[0].reason, reason);
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(node)));
        assert!(dropped.is_err(), "{reason}: dropping the node did not fail");
    }
}

#[test]
fn a_test_of_a_node_refusal_sees_the_refusal_without_a_violation() {
    for (text, chain, transaction, reason) in refused_pushes() {
        let node = MockNode::from_chain(chain);
        node.expect_invalid_pushes();

        let error = block_on(
            node.client()
                .push_transaction(&transaction, Propagation::Stem),
        )
        .unwrap_err();

        assert!(
            matches!(&error, NodeError::Rejected { rejection, .. }
                if rejection.message.as_deref().is_some_and(|message| message.contains(text))),
            "{reason}: {error:?}"
        );
        assert!(node.violations().is_empty(), "{reason}");
        assert!(node.pushed_transactions().is_empty(), "{reason}");
    }
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

#[cfg(test)]
fn rejection_text(error: NodeError) -> String {
    let NodeError::Rejected { rejection, .. } = error else {
        panic!("not a rejection: {error:?}");
    };
    assert_eq!(rejection.kind, RejectionKind::Internal);
    rejection.message.unwrap()
}

#[test]
fn a_push_enters_the_pool_only_when_the_chain_pools_pushes() {
    let transaction = transaction();
    let node = MockNode::from_chain(chain_spendable_by(&transaction));
    let client = node.client();
    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();
    assert!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .is_empty()
    );
    assert_eq!(node.pushed_transactions().len(), 1);
}

#[test]
fn a_pooled_push_is_on_the_chain_only_after_a_block_is_mined() {
    let transaction = transaction();
    let spent = transaction.inputs()[0].commitment;
    let created = transaction.outputs()[0].commitment;
    let excess = transaction.kernels()[0].excess;
    let mut chain = chain_spendable_by(&transaction).with_node_rules(1440);
    // The shared test chain already holds this transaction's kernel; this one has not seen it.
    chain.kernels.clear();
    let node = MockNode::from_chain(chain);
    let client = node.client();
    let tip = block_on(client.get_tip()).unwrap().height;

    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();

    let pool = block_on(client.get_unconfirmed_transactions()).unwrap();
    assert_eq!(
        pool,
        vec![PoolTransaction {
            kernels: transaction.kernels().to_vec()
        }]
    );
    assert_eq!(block_on(client.get_outputs(&[spent])).unwrap().len(), 1);
    assert!(block_on(client.get_outputs(&[created])).unwrap().is_empty());
    assert_eq!(
        block_on(client.get_kernel(&excess, None, None)).unwrap(),
        None
    );
    assert_eq!(block_on(client.get_tip()).unwrap().height, tip);

    let mined = node.mine_block().unwrap();

    assert_eq!(mined, Height::new(tip.value() + 1));
    assert_eq!(block_on(client.get_tip()).unwrap().height, mined);
    assert!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .is_empty()
    );
    assert!(block_on(client.get_outputs(&[spent])).unwrap().is_empty());
    let found = block_on(client.get_outputs(&[created])).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].height, mined);
    let kernel = block_on(client.get_kernel(&excess, None, None))
        .unwrap()
        .unwrap();
    assert_eq!(kernel.height, mined);
    assert!(node.violations().is_empty(), "{:?}", node.violations());
}

#[test]
fn pushing_a_transaction_twice_is_a_duplicate_while_it_waits_in_the_pool() {
    let transaction = transaction();
    let node = MockNode::from_chain(chain_spendable_by(&transaction).with_node_rules(1440));
    node.expect_invalid_pushes();
    let client = node.client();
    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();

    let text = rejection_text(
        block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap_err(),
    );

    assert_eq!(text, "Failed to update pool: Duplicate tx");
    assert_eq!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(node.pushed_transactions().len(), 1);
}

#[test]
fn pushing_a_mined_transaction_again_is_refused_as_a_spend_of_nothing() {
    let transaction = transaction();
    let node = MockNode::from_chain(chain_spendable_by(&transaction).with_node_rules(1440));
    node.expect_invalid_pushes();
    let client = node.client();
    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();
    node.mine_block().unwrap();

    let text = rejection_text(
        block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap_err(),
    );

    assert_eq!(
        text,
        "Failed to update pool: General pool error: failed to validate tx"
    );
    assert!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_second_transaction_spending_a_pooled_input_is_refused() {
    let transaction = transaction();
    let mut chain = chain_spendable_by(&transaction).with_node_rules(1440);
    // A different transaction already waits in the pool and spends the same output.
    chain.pool.push(Transaction::new(
        transaction.offset().clone(),
        TransactionBody::new(transaction.inputs().to_vec(), Vec::new(), Vec::new()),
    ));
    let node = MockNode::from_chain(chain);
    node.expect_invalid_pushes();
    let client = node.client();

    let text = rejection_text(
        block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap_err(),
    );

    assert_eq!(
        text,
        "Failed to update pool: General pool error: failed to validate tx"
    );
    assert!(node.pushed_transactions().is_empty());
    assert_eq!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_block_drops_a_pool_transaction_whose_input_it_spent() {
    let transaction = transaction();
    let node = MockNode::from_chain(chain_spendable_by(&transaction).with_node_rules(1440));
    let client = node.client();
    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();
    let spent = transaction.inputs()[0].commitment;
    node.update_chain(|chain| {
        for output in &mut chain.outputs {
            if output.commitment == spent {
                output.spent = true;
            }
        }
    });

    node.mine_block().unwrap();

    assert!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .is_empty()
    );
    assert!(
        block_on(client.get_outputs(&[transaction.outputs()[0].commitment]))
            .unwrap()
            .is_empty()
    );
}

/// A chain that holds the coinbase output `spends_coinbase` spends, found at `height`.
#[cfg(test)]
fn chain_with_coinbase(spends_coinbase: &Transaction, height: u64, tip: u64) -> ChainState {
    assert!(
        spends_coinbase
            .inputs()
            .iter()
            .all(|input| input.features == OutputFeatures::Coinbase)
    );
    let mut chain = chain_spendable_by(spends_coinbase);
    for output in &mut chain.outputs {
        output.height = Height::new(height);
    }
    chain.tip.height = Height::new(tip);
    chain.with_node_rules(1440)
}

#[test]
fn a_coinbase_output_cannot_be_spent_before_it_matures() {
    let transaction = vector_transaction("tx_valid_spends_coinbase_1_in_1_out");
    // Found at 100: spendable in block 100 + 1440, so not while the tip is below 1539.
    let node = MockNode::from_chain(chain_with_coinbase(&transaction, 100, 1538));
    node.expect_invalid_pushes();
    let client = node.client();

    let text = rejection_text(
        block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap_err(),
    );

    assert_eq!(text, "Failed to update pool: Immature coinbase");
    assert!(node.pushed_transactions().is_empty());
    assert!(
        block_on(client.get_unconfirmed_transactions())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_coinbase_output_can_be_spent_in_the_block_where_it_matures() {
    let transaction = vector_transaction("tx_valid_spends_coinbase_1_in_1_out");
    let node = MockNode::from_chain(chain_with_coinbase(&transaction, 100, 1539));
    let client = node.client();

    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();

    assert_eq!(node.pushed_transactions(), vec![transaction]);
    assert!(node.violations().is_empty(), "{:?}", node.violations());
}

#[test]
fn mined_blocks_mature_a_coinbase_output() {
    let transaction = vector_transaction("tx_valid_spends_coinbase_1_in_1_out");
    let node = MockNode::from_chain(chain_with_coinbase(&transaction, 100, 1536));
    node.expect_invalid_pushes();
    let client = node.client();
    assert!(block_on(client.push_transaction(&transaction, Propagation::Fluff)).is_err());

    node.update_chain(|chain| {
        chain.mine_blocks(3);
    });

    block_on(client.push_transaction(&transaction, Propagation::Fluff)).unwrap();
}

#[test]
fn the_maturity_rule_is_configurable_and_off_by_default() {
    let transaction = vector_transaction("tx_valid_spends_coinbase_1_in_1_out");
    let mut off = chain_with_coinbase(&transaction, 100, 101);
    off.coinbase_maturity = None;
    let node = MockNode::from_chain(off);
    block_on(
        node.client()
            .push_transaction(&transaction, Propagation::Fluff),
    )
    .unwrap();

    let mut short = chain_with_coinbase(&transaction, 100, 101);
    short.coinbase_maturity = Some(2);
    let node = MockNode::from_chain(short);
    block_on(
        node.client()
            .push_transaction(&transaction, Propagation::Fluff),
    )
    .unwrap();
    assert!(node.violations().is_empty());
}

#[test]
fn a_plain_output_is_spendable_at_any_age_under_the_maturity_rule() {
    let transaction = transaction();
    let mut chain = chain_spendable_by(&transaction).with_node_rules(1440);
    chain.tip.height = Height::new(11);
    let node = MockNode::from_chain(chain);
    block_on(
        node.client()
            .push_transaction(&transaction, Propagation::Fluff),
    )
    .unwrap();
}
