// SPDX-License-Identifier: Apache-2.0
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
use lepic_slate::codec::legacy::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{
    DecodeError, EncodeError, FieldProblem, Unrepresentable, ValidationError,
};
use lepic_slate::origin::{LegacyHeader, WireOrigin};
use lepic_slate::registry::CodecRegistry;
use serde_json::Value;

const UPSTREAM_WALLET: &str = "845b3fcf4df12ed0139929c62157015447a9d063";

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

fn v2_codec() -> V2JsonCodec {
    V2JsonCodec::new(Network::Floonet.params().default_base_fee())
}

fn vector_named(name: &str) -> Value {
    vectors()
        .into_iter()
        .find(|vector| vector["name"] == name)
        .unwrap_or_else(|| panic!("no vector {name}"))
}

/// Covers every V2-shaped stage vector: the file method's 2/2/b files, the Epicbox payloads with
/// header 2/3/b, and upstream's V2 conversions.
#[test]
fn v2_vectors_decode_and_encode_to_the_same_json() {
    let codec = v2_codec();
    let mut headers = std::collections::BTreeMap::new();
    for vector in stage_vectors().filter(|vector| vector["expected"]["shape"] == "V2") {
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
        assert_eq!(slate.ttl_cutoff_height(), None, "{name}");
        assert_eq!(slate.payment_proof(), None, "{name}");
        let origin = slate.origin().unwrap();
        assert_eq!(origin.codec(), LEGACY_V2_JSON, "{name}");
        assert_eq!(origin.legacy_header(), Some(header), "{name}");
        // The context must not matter: a decoded slate echoes its own header.
        let context = EncodeContext {
            block_header_version: header.block_header_version.wrapping_add(1),
        };
        let encoded = codec.encode(&slate, &context).unwrap();
        assert_eq!(encoded.media_type(), MediaType::JSON, "{name}");
        assert_eq!(encoded_text(&encoded), json, "{name}: encode");
        *headers
            .entry((header.version, header.orig_version))
            .or_insert(0) += 1;
    }
    assert!(
        headers.get(&(2, 2)).is_some_and(|&count| count >= 49),
        "{headers:?}"
    );
    assert!(
        headers.get(&(2, 3)).is_some_and(|&count| count >= 39),
        "{headers:?}"
    );
    assert_eq!(headers.len(), 2, "{headers:?}");
}

/// Upstream starts every slate at header 3 and converts it to the V2 shape at version 2, which is
/// what its Epicbox sender sends: header 2/3/b.
#[test]
fn new_v2_slates_get_header_two_three_at_the_context_block_header_version() {
    let codec = v2_codec();
    let mut count = 0;
    for vector in stage_vectors().filter(|vector| {
        vector["expected"]["shape"] == "V2"
            && vector["expected"]["header"]["orig_version"] == 3
            && matches!(text(&vector["inputs"]["stage"]), "S1" | "I1")
    }) {
        let name = text(&vector["name"]);
        let expected = &vector["expected"];
        let header = header(&expected["header"]);
        assert_eq!(header.version, 2, "{name}");
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

/// `VersionedSlate::into_version(V2)` of the producer's slate: the `_v2` vector is the V2 encode
/// of the `_v3` sibling's slate with its header, and a slate with a TTL or a payment proof,
/// which upstream converts by dropping them, is refused instead.
#[test]
fn v3_slates_convert_to_the_v2_vectors_or_are_refused() {
    let (v2, v3) = (v2_codec(), codec());
    let (mut converted, mut refused) = (0, 0);
    for vector in stage_vectors().filter(|vector| text(&vector["name"]).ends_with("_v3")) {
        let name = text(&vector["name"]);
        let v2_name = format!("{}_v2", name.strip_suffix("_v3").unwrap());
        let slate = v3.decode(&wire(text(&vector["expected"]["json"]))).unwrap();
        let context = EncodeContext {
            block_header_version: 0,
        };
        let result = v2.encode(&slate, &context);
        let what = if slate.payment_proof().is_some() {
            Some(Unrepresentable::PaymentProof)
        } else if slate.ttl_cutoff_height().is_some() {
            Some(Unrepresentable::TimeToLive)
        } else {
            None
        };
        match what {
            Some(what) => {
                assert_eq!(
                    result,
                    Err(EncodeError::Unrepresentable {
                        codec: LEGACY_V2_JSON,
                        what
                    }),
                    "{name}"
                );
                refused += 1;
            }
            None => {
                let expected = vector_named(&v2_name);
                assert_eq!(
                    encoded_text(&result.unwrap()),
                    text(&expected["expected"]["json"]),
                    "{v2_name}"
                );
                converted += 1;
            }
        }
    }
    assert!(converted > 0 && refused > 0, "{converted} {refused}");
}

#[test]
fn v3_shaped_vectors_are_not_v2() {
    let codec = v2_codec();
    let mut count = 0;
    for vector in stage_vectors().filter(|vector| vector["expected"]["shape"] == "V3") {
        let name = text(&vector["name"]);
        let json = wire(text(&vector["expected"]["json"]));
        assert!(!codec.detect(&json), "{name}: detect");
        assert_eq!(
            codec.decode(&json),
            Err(DecodeError::NotRecognised {
                codec: LEGACY_V2_JSON
            }),
            "{name}"
        );
        count += 1;
    }
    assert!(count > 0);
}

/// Mutations LEPIC refuses although an upstream parser may read them as V2, by the decode checks
/// of `docs/compat/legacy-slates.md` and the header versions upstream writes. Upstream `v4.1.0`
/// refuses the offset case on both paths and the participant cases on its file path only;
/// `v4.0.2` read all three.
fn stricter_than_upstream_v2(name: &str) -> Option<DecodeError> {
    let version = |version| DecodeError::UnsupportedVersion {
        codec: LEGACY_V2_JSON,
        version,
    };
    Some(match name {
        "malformed_duplicate_participant_id" => {
            ValidationError::DuplicateParticipantId { id: 0 }.into()
        }
        "malformed_num_participants_zero" => {
            ValidationError::UnsupportedParticipantCount { declared: 0 }.into()
        }
        "malformed_offset_too_short" => DecodeError::Field {
            field: "tx.offset",
            problem: FieldProblem::Hex(lepic_slate::error::HexError::WrongLength {
                expected: 64,
                actual: 62,
            }),
        },
        "malformed_header_version_1" => version(1),
        "malformed_header_version_4" => version(4),
        _ => return None,
    })
}

/// A V2-shaped mutation decodes exactly when an upstream parser read it as V2 and no stricter
/// LEPIC rule applies, and then decodes to the slate upstream re-encoded. Mutations with the V3
/// shape are the V3 codec's.
#[test]
fn malformed_v2_vectors_follow_the_upstream_v2_parse() {
    let (v2, v3) = (v2_codec(), codec());
    let (mut accepted, mut rejected) = (0, 0);
    for vector in malformed_vectors() {
        let name = text(&vector["name"]);
        let json = wire(text(&vector["inputs"]["json"]));
        if vector["inputs"]["shape"] != "V2" {
            assert!(!v2.detect(&json), "{name}: detect");
            assert!(v2.decode(&json).is_err(), "{name}: decode");
            continue;
        }
        assert!(v2.detect(&json), "{name}: detect");
        let expected = &vector["expected"];
        let read_as_v2 = ["file_method", "epicbox_method"]
            .iter()
            .map(|method| &expected[method])
            .find(|outcome| outcome["accepted"] == true && outcome["parsed_as"] == "V2");
        let decoded = v2.decode(&json);
        match (read_as_v2, stricter_than_upstream_v2(name)) {
            (Some(_), Some(error)) => {
                assert_eq!(decoded, Err(error), "{name}");
                rejected += 1;
            }
            (Some(outcome), None) => {
                let slate = decoded.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                let header = slate.origin().unwrap().legacy_header().unwrap();
                let upstream = v3
                    .decode(&wire(text(&outcome["reencoded_v3"])))
                    .unwrap()
                    .with_origin(Some(WireOrigin::legacy(LEGACY_V2_JSON, header)));
                assert_eq!(slate, upstream, "{name}");
                accepted += 1;
            }
            (None, _) => {
                assert!(decoded.is_err(), "{name}: accepted");
                rejected += 1;
            }
        }
    }
    assert!(accepted > 0 && rejected > 0, "{accepted} {rejected}");
}

/// Both legacy codecs registered V3 first, as transports do: every stage vector is detected as
/// the codec of its shape.
#[test]
fn registry_detects_the_codec_of_each_shape() {
    let mut registry = CodecRegistry::new();
    registry.register(Box::new(codec())).unwrap();
    registry.register(Box::new(v2_codec())).unwrap();
    for vector in stage_vectors() {
        let name = text(&vector["name"]);
        let expected = match text(&vector["expected"]["shape"]) {
            "V2" => LEGACY_V2_JSON,
            "V3" => LEGACY_V3_JSON,
            other => panic!("{name}: shape {other}"),
        };
        let json = wire(text(&vector["expected"]["json"]));
        assert_eq!(registry.detect(&json).unwrap().id(), expected, "{name}");
        assert_eq!(
            registry.decode(&json).unwrap().origin().unwrap().codec(),
            expected,
            "{name}"
        );
    }
}
