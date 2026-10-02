//! Replays the G-03 golden vectors in `testdata/vectors/slates` through the legacy codecs.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_primitives::params::Network;
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::origin::LegacyHeader;
use serde_json::Value;

const UPSTREAM_WALLET: &str = "465d499f01aad7e570b6cc220d52c6bfcf6a9a44";

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/slates")
}

/// Every slate vector, sorted by name.
fn vectors() -> Vec<Value> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(vector_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no slate vectors");
    paths
        .iter()
        .map(|path| {
            let vector: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let name = text(&vector["name"]);
            assert_eq!(vector["schema"], 1, "{name}: schema");
            assert_eq!(vector["area"], "slates", "{name}: area");
            assert_eq!(vector["upstream"]["commit"], UPSTREAM_WALLET, "{name}: pin");
            vector
        })
        .collect()
}

fn stage_vectors() -> impl Iterator<Item = Value> {
    vectors()
        .into_iter()
        .filter(|vector| !text(&vector["name"]).starts_with("malformed_"))
}

fn malformed_vectors() -> impl Iterator<Item = Value> {
    vectors()
        .into_iter()
        .filter(|vector| text(&vector["name"]).starts_with("malformed_"))
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"))
}

fn header(value: &Value) -> LegacyHeader {
    let field = |key: &str| u16::try_from(value[key].as_u64().unwrap()).unwrap();
    LegacyHeader {
        version: field("version"),
        orig_version: field("orig_version"),
        block_header_version: field("block_header_version"),
    }
}

fn codec() -> V3JsonCodec {
    V3JsonCodec::new(Network::Floonet.params().default_base_fee())
}

fn wire(json: &str) -> WireSlate {
    WireSlate::text(MediaType::JSON, json.to_owned())
}

fn encoded_text(wire: &WireSlate) -> &str {
    wire.as_text().unwrap()
}

#[test]
fn v3_vectors_decode_and_encode_to_the_same_json() {
    let codec = codec();
    let mut count = 0;
    for vector in stage_vectors().filter(|vector| vector["expected"]["shape"] == "V3") {
        let name = text(&vector["name"]);
        let expected = &vector["expected"];
        let json = text(&expected["json"]);
        let header = header(&expected["header"]);
        assert!(codec.detect(&wire(json)), "{name}: detect");
        let slate = codec
            .decode(&wire(json))
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(
            slate.stage().as_str(),
            text(&vector["inputs"]["stage"]),
            "{name}"
        );
        assert_eq!(
            slate.id().to_string(),
            text(&expected["slate_id"]),
            "{name}"
        );
        let origin = slate.origin().unwrap();
        assert_eq!(origin.codec(), LEGACY_V3_JSON, "{name}");
        assert_eq!(origin.legacy_header(), Some(header), "{name}");
        // The context must not matter: a decoded slate echoes its own header.
        let context = EncodeContext {
            block_header_version: header.block_header_version.wrapping_add(1),
        };
        let encoded = codec.encode(&slate, &context).unwrap();
        assert_eq!(encoded.media_type(), MediaType::JSON, "{name}");
        assert_eq!(encoded_text(&encoded), json, "{name}: encode");
        count += 1;
    }
    assert!(count >= 61, "only {count} V3 vectors");
}

#[test]
fn new_slates_get_header_three_at_the_context_block_header_version() {
    let codec = codec();
    let mut count = 0;
    for vector in stage_vectors().filter(|vector| {
        vector["expected"]["shape"] == "V3"
            && matches!(text(&vector["inputs"]["stage"]), "S1" | "I1")
    }) {
        let name = text(&vector["name"]);
        let expected = &vector["expected"];
        let header = header(&expected["header"]);
        assert_eq!((header.version, header.orig_version), (3, 3), "{name}");
        let slate = codec
            .decode(&wire(text(&expected["json"])))
            .unwrap()
            .with_origin(None);
        let context = EncodeContext {
            block_header_version: header.block_header_version,
        };
        let encoded = codec.encode(&slate, &context).unwrap();
        assert_eq!(encoded_text(&encoded), text(&expected["json"]), "{name}");
        count += 1;
    }
    assert!(count > 0);
}

#[test]
fn v2_shaped_vectors_are_not_v3() {
    let codec = codec();
    let mut count = 0;
    for vector in stage_vectors().filter(|vector| vector["expected"]["shape"] == "V2") {
        let name = text(&vector["name"]);
        let json = wire(text(&vector["expected"]["json"]));
        assert!(!codec.detect(&json), "{name}: detect");
        assert_eq!(
            codec.decode(&json),
            Err(DecodeError::NotRecognised {
                codec: LEGACY_V3_JSON
            }),
            "{name}"
        );
        count += 1;
    }
    assert!(count > 0);
}

/// A V3-shaped mutation decodes exactly when an upstream parser read it as V3, and then encodes
/// to what upstream writes back for it. Mutations without the V3 shape are left to the V2 codec.
#[test]
fn malformed_v3_vectors_follow_the_upstream_v3_parse() {
    let codec = codec();
    let mut count = 0;
    for vector in malformed_vectors() {
        let name = text(&vector["name"]);
        let json = wire(text(&vector["inputs"]["json"]));
        if vector["inputs"]["shape"] != "V3" {
            assert!(!codec.detect(&json), "{name}: detect");
            assert!(codec.decode(&json).is_err(), "{name}: decode");
            continue;
        }
        assert!(codec.detect(&json), "{name}: detect");
        let expected = &vector["expected"];
        let read_as_v3 = ["file_method", "epicbox_method"]
            .iter()
            .map(|method| &expected[method])
            .find(|outcome| outcome["accepted"] == true && outcome["parsed_as"] == "V3");
        let decoded = codec.decode(&json);
        match read_as_v3 {
            Some(outcome) => {
                let slate = decoded.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                let context = EncodeContext {
                    block_header_version: 0,
                };
                let encoded = codec.encode(&slate, &context).unwrap();
                assert_eq!(
                    encoded_text(&encoded),
                    text(&outcome["reencoded_v3"]),
                    "{name}"
                );
            }
            None => assert!(decoded.is_err(), "{name}: accepted"),
        }
        count += 1;
    }
    assert!(count > 0);
}
