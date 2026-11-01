// SPDX-License-Identifier: Apache-2.0
//! Replays the store vectors in `testdata/vectors/store`: the row a peer key is kept under, its
//! tag and its sealed bytes, written by an independent implementation of the format. The seed
//! subkeys in them are checked by `lepic-wallet`, which derives them.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use jiff::Timestamp;
use lepic_store::{ContextKey, PeerCompat, PeerTag, PeerTagKey, peer_vectors};
use serde_json::Value;

const NODE_REPO: &str = "https://github.com/EpicCash/epic";
const NODE_COMMIT: &str = "82fa7e813dc3b9bf137b9dd523d847f4210f5ba4";
const CASES: [&str; 2] = ["peer_compat", "peer_compat_migrated"];

fn vector(name: &str) -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/store")
        .join(format!("{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "store", "{name}: area");
    assert_eq!(vector["name"], name, "{name}: name");
    assert_eq!(vector["upstream"]["repo"], NODE_REPO, "{name}: repo");
    assert_eq!(vector["upstream"]["commit"], NODE_COMMIT, "{name}: pin");
    vector
}

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn array<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn time(value: &Value) -> Option<Timestamp> {
    value
        .as_i64()
        .map(|nanos| Timestamp::from_nanosecond(i128::from(nanos)).unwrap())
}

fn compat(record: &Value) -> PeerCompat {
    PeerCompat {
        last_marked_at: time(&record["last_marked_at"]),
        last_unmarked_at: time(&record["last_unmarked_at"]),
        claimed: u32::try_from(record["claimed"].as_u64().unwrap()).unwrap(),
        works: u32::try_from(record["works"].as_u64().unwrap()).unwrap(),
        features_at: time(&record["features_at"]),
    }
}

#[test]
fn finds_rows_under_the_golden_tag() {
    for name in CASES {
        let vector = vector(name);
        let tags = PeerTagKey::from_bytes(array(&vector["expected"]["peer_tag_key"]));
        let tag = tags
            .tag(vector["inputs"]["peer_key"].as_str().unwrap())
            .unwrap();
        assert_eq!(tag.0, array(&vector["expected"]["key_tag"]), "{name}");
    }
}

#[test]
fn seals_the_golden_rows_byte_for_byte_and_opens_them() {
    for name in CASES {
        let vector = vector(name);
        let expected = &vector["expected"];
        let record = compat(&vector["inputs"]["record"]);
        assert_eq!(
            peer_vectors::record(&record).unwrap(),
            bytes(&expected["record"]),
            "{name}: record"
        );
        let key = || ContextKey::from_bytes(array(&expected["context_key"]));
        let tag = PeerTag(array(&expected["key_tag"]));
        let sealed =
            peer_vectors::seal_with_nonce(&key(), &tag, &record, array(&vector["inputs"]["nonce"]))
                .unwrap();
        assert_eq!(sealed, bytes(&expected["sealed"]), "{name}: sealed");
        assert_eq!(
            peer_vectors::open(&key(), &tag, &bytes(&expected["sealed"])).unwrap(),
            record,
            "{name}: opened"
        );
        let mut other = tag;
        other.0[0] ^= 1;
        assert!(
            peer_vectors::open(&key(), &other, &sealed).is_err(),
            "{name}"
        );
    }
}
