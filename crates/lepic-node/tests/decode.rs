// SPDX-License-Identifier: Apache-2.0
//! Properties of the pure decoders: arbitrary input never panics, and valid answers round-trip.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_node::decode;
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use proptest::prelude::*;
use serde_json::{Value, json};

#[cfg(test)]
fn listed_commitments() -> Vec<Commitment> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/engine/restore_full_scan.json");
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| exchange["method"] == "get_unspent_outputs")
        .unwrap()["response"]["result"]["Ok"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|output| Commitment::from_hex(output["commit"].as_str().unwrap()).unwrap())
        .collect()
}

#[cfg(test)]
fn decode_all(body: &[u8]) {
    let commitments = listed_commitments();
    let requested: BTreeSet<Commitment> = commitments.iter().copied().collect();
    let _ = decode::version(body);
    let _ = decode::tip(body);
    let _ = decode::header(body, Height::new(5));
    let _ = decode::kernel(body, &commitments[0], None, Some(Height::new(5)));
    let _ = decode::outputs(body, &requested);
    let _ = decode::unspent_outputs(body, 1, Some(100), 10);
    let _ = decode::pmmr_indices(body);
    let _ = decode::push_transaction(body);
    let _ = decode::unconfirmed_transactions(body);
}

proptest! {
    #[test]
    fn arbitrary_bodies_are_rejected_without_panicking(body in proptest::collection::vec(any::<u8>(), 0..512)) {
        decode_all(&body);
    }

    #[test]
    fn arbitrary_results_are_rejected_without_panicking(result in "\\PC{0,256}") {
        let body = format!(r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{result}}}}}"#);
        decode_all(body.as_bytes());
        let body = format!(r#"{{"id":1,"jsonrpc":"2.0","result":{{"Err":{result}}}}}"#);
        decode_all(body.as_bytes());
    }

    #[test]
    fn tips_round_trip(height in any::<u64>(), hash in any::<[u8; 32]>()) {
        let hash = Hash::from_bytes(hash);
        let body = json!({"id": 1, "jsonrpc": "2.0", "result": {"Ok": {
            "height": height, "last_block_pushed": hash.to_hex(),
            "prev_block_to_last": hash.to_hex(), "total_difficulty": {}
        }}});
        let tip = decode::tip(&serde_json::to_vec(&body).unwrap()).unwrap();
        prop_assert_eq!(tip.height, Height::new(height));
        prop_assert_eq!(tip.last_block_pushed, hash);
    }

    #[test]
    fn output_locations_round_trip(
        picks in proptest::collection::btree_set(0usize..18, 0..18),
        height in any::<u64>(),
        mmr_index in any::<u64>(),
        coinbase in any::<bool>(),
    ) {
        let commitments = listed_commitments();
        let requested: BTreeSet<Commitment> = commitments.iter().copied().collect();
        let picked: Vec<Commitment> = picks.iter().map(|&i| commitments[i]).collect();
        let outputs: Vec<Value> = picked.iter().map(|commit| json!({
            "output_type": if coinbase { "Coinbase" } else { "Transaction" },
            "commit": commit.to_hex(), "spent": false, "proof": null, "proof_hash": "",
            "block_height": height, "merkle_proof": null, "mmr_index": mmr_index
        })).collect();
        let body = json!({"id": 1, "jsonrpc": "2.0", "result": {"Ok": outputs}});
        let located = decode::outputs(&serde_json::to_vec(&body).unwrap(), &requested).unwrap();
        prop_assert_eq!(located.len(), picked.len());
        for (location, commit) in located.iter().zip(&picked) {
            prop_assert_eq!(location.commitment, *commit);
            prop_assert_eq!(location.height, Height::new(height));
            prop_assert_eq!(location.mmr_index, mmr_index);
            prop_assert_eq!(location.features.is_coinbase(), coinbase);
        }
    }
}

/// A pool listing in the shape of the node's `get_unconfirmed_transactions` example in
/// `api/src/foreign_rpc.rs` (Epic `v4.0.4`), with the kernel from that example. Inputs and
/// outputs are not read, so the output carries a short stand-in for its range proof.
#[cfg(test)]
fn pool_listing(kernels: &[Value]) -> Vec<u8> {
    let body = json!({"id": 1, "jsonrpc": "2.0", "result": {"Ok": [{
        "src": "Broadcast",
        "tx": {
            "body": {
                "inputs": [{
                    "commit": "0992ce1827ec349e9f339ce183ffd01db39bf43999799d8191bfc267a58f0a715c",
                    "features": "Coinbase"
                }],
                "kernels": kernels,
                "outputs": [{
                    "commit": "0873fafd4a0e4f365939e24c68eeb18aafc6674ca244a364dcdbfa8fa525e7bae1",
                    "features": "Plain",
                    "proof": "4b67"
                }]
            },
            "offset": "0eb2c2669ce918675c72697891e5527bd13da5a499396381409219b8bbbd8129"
        },
        "tx_at": "2019-10-07T16:20:08.709114Z"
    }]}});
    serde_json::to_vec(&body).unwrap()
}

#[cfg(test)]
const POOL_EXCESS: &str = "083c49eaaf6380d44596f52cce4cf278cfac6dd34fbef73981002d8f1e8ee8abe4";

#[cfg(test)]
fn pool_kernel() -> Value {
    json!({
        "excess": POOL_EXCESS,
        "excess_sig": "3f011e7e288231d67f42cb4f6416c4720e6170d5e3c805a52d33aa4521328f9be0303be654bc8ddcd3111aadc27c848b9cf07e0a70885ef79be70b7bb70f8c75",
        "features": {"Plain": {"fee": 7_000_000}}
    })
}

#[test]
fn decodes_the_kernels_of_a_pool_listing() {
    let pool = decode::unconfirmed_transactions(&pool_listing(&[pool_kernel()])).unwrap();

    assert_eq!(pool.len(), 1);
    assert_eq!(pool[0].kernels.len(), 1);
    assert_eq!(pool[0].kernels[0].excess.to_hex(), POOL_EXCESS);
}

#[test]
fn refuses_a_pool_listing_above_the_kernel_bound_before_validating_kernels() {
    let unchecked = json!({"excess": "", "excess_sig": "", "features": "Coinbase"});
    let kernels = vec![unchecked; lepic_node::MAX_POOL_KERNELS + 1];

    let error = decode::unconfirmed_transactions(&pool_listing(&kernels)).unwrap_err();

    assert!(
        matches!(
            error,
            lepic_node::NodeError::InvalidField {
                field: "kernels",
                problem: lepic_node::FieldProblem::TooMany,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn refuses_a_pool_kernel_whose_excess_is_not_a_curve_value() {
    let mut kernel = pool_kernel();
    kernel["excess"] = json!(format!("02{}", "ff".repeat(32)));

    let error = decode::unconfirmed_transactions(&pool_listing(&[kernel])).unwrap_err();

    assert!(
        matches!(
            error,
            lepic_node::NodeError::InvalidField {
                field: "excess",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn ready_for_txs_reads_the_flag_and_refuses_anything_else() {
    let answer = |result: &str| format!(r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{result}}}}}"#);
    assert!(
        lepic_node::decode::ready_for_txs(answer(r#"{"ready_for_txs":true}"#).as_bytes()).unwrap()
    );
    assert!(
        !lepic_node::decode::ready_for_txs(answer(r#"{"ready_for_txs":false}"#).as_bytes())
            .unwrap()
    );
    for result in [r#"{}"#, r#"{"ready_for_txs":"yes"}"#, "true"] {
        assert!(
            lepic_node::decode::ready_for_txs(answer(result).as_bytes()).is_err(),
            "{result}"
        );
    }
}

#[cfg(test)]
fn display_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

#[test]
fn malformed_response_errors_carry_none_of_the_node_text() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/engine/restore_full_scan.json");
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut response = vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| exchange["method"] == "get_unspent_outputs")
        .unwrap()["response"]
        .clone();
    let planted = format!("\u{1b}[2J\u{202e}{}", "x".repeat(100_000));
    response["result"]["Ok"]["outputs"][0]["output_type"] = Value::String(planted);
    let body = serde_json::to_vec(&response).unwrap();

    let error = decode::unspent_outputs(&body, 1, None, 1_000).unwrap_err();
    assert!(
        matches!(error, lepic_node::NodeError::MalformedResponse { .. }),
        "{error:?}"
    );
    let text = display_chain(&error);
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains('\u{202e}'), "{text:?}");
    assert!(!text.contains("xxx"), "{text:?}");
    assert!(text.len() < 256, "{text:?}");
}
