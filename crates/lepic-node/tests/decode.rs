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
    let _ = decode::kernel(body, &commitments[0], None, Some(Height::new(5)));
    let _ = decode::outputs(body, &requested);
    let _ = decode::unspent_outputs(body, 1, Some(100), 10);
    let _ = decode::pmmr_indices(body);
    let _ = decode::push_transaction(body);
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
