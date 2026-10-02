//! Replays the G-03 file vectors in `testdata/vectors/slates`: the file transport writes and
//! reads every file upstream's file method wrote byte for byte, and the file policy picks the
//! shape and header upstream wrote for each of them.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_slate::codec::EncodeContext;
use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::origin::LegacyHeader;
use lepic_transport::file::{FilePolicy, FileTransport};
use lepic_transport::transport::{Exchange, Location};
use serde_json::Value;

const UPSTREAM_WALLET: &str = "465d499f01aad7e570b6cc220d52c6bfcf6a9a44";

/// What `epic-wallet` writes into a slate it creates (`docs/compat/legacy-slates.md`).
const NEW_SLATE_VERSION: u16 = 3;

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/slates")
}

fn read_vector(name: &str) -> Value {
    let path = vector_dir().join(format!("{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "slates", "{name}: area");
    assert_eq!(vector["upstream"]["commit"], UPSTREAM_WALLET, "{name}: pin");
    vector
}

/// Every stage vector in the file encoding, sorted by name.
fn file_vectors() -> Vec<(String, Value)> {
    let mut names: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| name.strip_suffix("_file.json").map(str::to_owned))
        .map(|stem| format!("{stem}_file"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no file vectors");
    names
        .into_iter()
        .map(|name| {
            let vector = read_vector(&name);
            (name, vector)
        })
        .collect()
}

fn slate_json(vector: &Value) -> &str {
    vector["expected"]["json"].as_str().unwrap()
}

fn header_of(slate: &Value) -> LegacyHeader {
    let field = |key: &str| u16::try_from(slate["version_info"][key].as_u64().unwrap()).unwrap();
    LegacyHeader {
        version: field("version"),
        orig_version: field("orig_version"),
        block_header_version: field("block_header_version"),
    }
}

#[tokio::test]
async fn file_transport_round_trips_every_upstream_slate_file_byte_for_byte() {
    let transport = FileTransport::new();
    let dir = tempfile::tempdir().unwrap();
    for (name, vector) in file_vectors() {
        let bytes = slate_json(&vector).as_bytes();
        let path = dir.path().join(&name);
        let location = Location::File(path.clone());
        std::fs::write(&path, bytes).unwrap();

        let imported = transport.import(&location).await.unwrap();
        assert_eq!(imported.as_bytes(), bytes, "{name}: import");

        std::fs::remove_file(&path).unwrap();
        transport.export(&imported, &location).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name}: export");
    }
}

/// For each file vector, the producer's slate after the stage is its `_v3` sibling, header
/// unchanged. The file policy, given what that slate carries, must pick the shape and header
/// upstream's file method wrote.
#[test]
fn file_policy_picks_the_shape_and_header_upstream_wrote() {
    for (name, vector) in file_vectors() {
        let stem = name.strip_suffix("_file").unwrap();
        let producer: Value =
            serde_json::from_str(slate_json(&read_vector(&format!("{stem}_v3")))).unwrap();
        let written: Value = serde_json::from_str(slate_json(&vector)).unwrap();

        let needs_v3 =
            !producer["ttl_cutoff_height"].is_null() || !producer["payment_proof"].is_null();
        let producer_header = header_of(&producer);
        let starts_slate = matches!(vector["inputs"]["stage"].as_str(), Some("S1" | "I1"));
        let received = (!starts_slate).then_some(producer_header);
        let context = EncodeContext {
            block_header_version: producer_header.block_header_version,
        };

        let encoding = FilePolicy::choose(needs_v3, received, &context);

        let expected_codec = match vector["expected"]["shape"].as_str() {
            Some("V2") => LEGACY_V2_JSON,
            Some("V3") => LEGACY_V3_JSON,
            other => panic!("{name}: unexpected shape {other:?}"),
        };
        assert_eq!(encoding.codec, expected_codec, "{name}: codec");
        let header = encoding.legacy_header.unwrap_or(LegacyHeader {
            version: NEW_SLATE_VERSION,
            orig_version: NEW_SLATE_VERSION,
            block_header_version: context.block_header_version,
        });
        assert_eq!(header, header_of(&written), "{name}: header");
    }
}
