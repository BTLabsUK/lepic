// SPDX-License-Identifier: Apache-2.0
//! Replays `testdata/vectors/slates_native`: each slate decodes to what upstream's V3 JSON of the
//! same slate decodes to, encodes back to its exact bytes, and has the recorded JSON view; each
//! malformed input is refused with its recorded error.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_native_slate::{NativeError, NativeSlate, NativeV1Codec, SlateView};
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::model::Slate;
use serde_json::Value;

/// Every vector of the area, sorted by name.
fn vectors() -> Vec<Value> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/slates_native");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let vector: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(vector["schema"], 1, "{}", path.display());
            assert_eq!(vector["area"], "slates_native", "{}", path.display());
            vector
        })
        .collect()
}

fn name(vector: &Value) -> &str {
    vector["name"].as_str().unwrap()
}

fn is_malformed(vector: &Value) -> bool {
    name(vector).starts_with("malformed_")
}

fn network(value: &Value) -> Network {
    match value.as_str().unwrap() {
        "mainnet" => Network::Mainnet,
        "floonet" => Network::Floonet,
        other => panic!("unknown network {other}"),
    }
}

fn other(network: Network) -> Network {
    match network {
        Network::Mainnet => Network::Floonet,
        Network::Floonet => Network::Mainnet,
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn without_origin(slate: Slate) -> Slate {
    slate.with_origin(None)
}

/// The variant name of a refusal: `Tail.<variant>` and `Model.<variant>` for the wrapped errors.
fn tag(error: &NativeError) -> String {
    fn leading(text: &str) -> &str {
        let end = text
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(text.len());
        &text[..end]
    }
    let debug = format!("{error:?}");
    let head = leading(&debug);
    match head {
        "Tail" | "Model" => format!("{head}.{}", leading(&debug[head.len() + 1..])),
        _ => head.to_owned(),
    }
}

#[test]
fn slates_decode_like_their_v3_json_and_encode_to_the_same_bytes() {
    let v3 = V3JsonCodec::new(Network::Floonet.params().default_base_fee());
    let mut count = 0;
    let mut with_tail = 0;
    for vector in vectors().iter().filter(|vector| !is_malformed(vector)) {
        let name = name(vector);
        let inputs = &vector["inputs"];
        let expected = &vector["expected"];
        let network = network(&inputs["network"]);
        let bytes = unhex(expected["lepic_v1"].as_str().unwrap());
        assert_eq!(expected["size"], bytes.len(), "{name}: size");

        let native = NativeSlate::decode(network, &bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(native.encode(network), bytes, "{name}: re-encode");
        assert!(
            matches!(
                NativeSlate::decode(other(network), &bytes),
                Err(NativeError::WrongNetwork { .. })
            ),
            "{name}: other network"
        );

        let json = inputs["v3_json"].as_str().unwrap();
        let from_v3 = v3
            .decode(&WireSlate::text(MediaType::JSON, json.to_owned()))
            .unwrap_or_else(|e| panic!("{name}: V3 decode: {e}"));
        let from_v3 = NativeSlate::new(without_origin(from_v3), native.tail().clone())
            .unwrap_or_else(|e| panic!("{name}: from V3: {e}"));
        assert_eq!(
            without_origin(from_v3.slate().clone()),
            without_origin(native.slate().clone()),
            "{name}: V3"
        );

        let view = serde_json::to_value(SlateView::new(network, &native)).unwrap();
        assert_eq!(view, expected["view"], "{name}: view");
        let from_view: SlateView = serde_json::from_value(expected["view"].clone()).unwrap();
        assert_eq!(
            from_view.into_native().unwrap(),
            (network, native.clone()),
            "{name}: from view"
        );

        let codec = NativeV1Codec::new(network);
        let wire = WireSlate::binary(lepic_native_slate::MEDIA_TYPE, bytes.clone());
        assert!(codec.detect(&wire), "{name}: detect");
        let decoded = codec.decode(&wire).unwrap();
        assert_eq!(&decoded, native.slate(), "{name}: codec decode");
        let context = EncodeContext {
            block_header_version: vector["expected"]["view"]["header_version"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let encoded = codec.encode(&decoded, &context).unwrap();
        if native.tail().is_empty() {
            assert_eq!(encoded.as_bytes(), bytes, "{name}: codec encode");
        } else {
            with_tail += 1;
            assert!(
                bytes.starts_with(encoded.as_bytes()),
                "{name}: codec encode"
            );
        }
        count += 1;
    }
    assert!(count >= 100, "only {count} slates");
    assert_eq!(with_tail, 5, "slates with a tail");
}

#[test]
fn malformed_slates_are_refused_with_their_error() {
    let mut count = 0;
    for vector in vectors().iter().filter(|vector| is_malformed(vector)) {
        let name = name(vector);
        let inputs = &vector["inputs"];
        let bytes = unhex(inputs["lepic_v1"].as_str().unwrap());
        let network = network(&inputs["decode_network"]);
        let error = NativeSlate::decode(network, &bytes)
            .err()
            .unwrap_or_else(|| panic!("{name}: accepted"));
        assert_eq!(
            tag(&error),
            vector["expected"]["error"],
            "{name}: {error:?}"
        );
        count += 1;
    }
    assert!(count >= 40, "only {count} malformed slates");
}
