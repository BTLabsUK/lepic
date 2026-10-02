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

use lepic_slate::codec::legacy::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::origin::LegacyHeader;
use lepic_slate::registry::CodecRegistry;
use lepic_transport::error::FormatError;
use lepic_transport::file::{FilePolicy, FileTransport};
use lepic_transport::transport::{Exchange, Location, Transport};
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
        let received = (!starts_slate(&vector)).then_some(producer_header);
        let context = EncodeContext {
            block_header_version: producer_header.block_header_version,
        };

        let encoding = FilePolicy::choose(needs_v3, received, &context);

        assert_eq!(
            encoding.codec,
            expected_codec(&name, &vector),
            "{name}: codec"
        );
        let header = encoding.legacy_header.unwrap_or(LegacyHeader {
            version: NEW_SLATE_VERSION,
            orig_version: NEW_SLATE_VERSION,
            block_header_version: context.block_header_version,
        });
        assert_eq!(header, header_of(&written), "{name}: header");
    }
}

/// Both legacy codecs, as a wallet registers them. The base fee is left at zero: the minimum-fee
/// rule belongs to the codecs and is replayed in `lepic-slate`, and this crate may not depend on
/// `lepic-primitives` to name a network's fee.
fn legacy_codecs() -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V3JsonCodec::new(Default::default())))
        .unwrap();
    codecs
        .register(Box::new(V2JsonCodec::new(Default::default())))
        .unwrap();
    codecs
}

fn expected_codec(name: &str, vector: &Value) -> CodecId {
    match vector["expected"]["shape"].as_str() {
        Some("V2") => LEGACY_V2_JSON,
        Some("V3") => LEGACY_V3_JSON,
        other => panic!("{name}: unexpected shape {other:?}"),
    }
}

fn starts_slate(vector: &Value) -> bool {
    matches!(vector["inputs"]["stage"].as_str(), Some("S1" | "I1"))
}

/// Importing each file upstream wrote, through the file policy, yields the codec of its shape,
/// the header as written, the vector's slate id and stage, and the same slate as upstream's
/// own V3 rendering of the producer's slate.
#[tokio::test]
async fn importing_every_upstream_slate_file_yields_the_expected_codec_and_slate() {
    let codecs = legacy_codecs();
    let transport = FileTransport::new();
    let dir = tempfile::tempdir().unwrap();
    for (name, vector) in file_vectors() {
        let bytes = slate_json(&vector);
        let path = dir.path().join(&name);
        std::fs::write(&path, bytes).unwrap();

        let wire = transport.import(&Location::File(path)).await.unwrap();
        let slate = transport.policy().decode(&codecs, &wire).unwrap();

        let origin = slate.origin().unwrap();
        assert_eq!(
            origin.codec(),
            expected_codec(&name, &vector),
            "{name}: codec"
        );
        let written: Value = serde_json::from_str(bytes).unwrap();
        assert_eq!(
            origin.legacy_header(),
            Some(header_of(&written)),
            "{name}: header"
        );
        assert_eq!(
            slate.id().to_string(),
            vector["expected"]["slate_id"].as_str().unwrap(),
            "{name}: slate id"
        );
        assert_eq!(
            slate.stage().as_str(),
            vector["inputs"]["stage"].as_str().unwrap(),
            "{name}: stage"
        );

        let stem = name.strip_suffix("_file").unwrap();
        let producer = codecs
            .decode(&WireSlate::text(
                MediaType::JSON,
                slate_json(&read_vector(&format!("{stem}_v3"))).to_owned(),
            ))
            .unwrap();
        assert_eq!(
            slate.with_origin(None),
            producer.with_origin(None),
            "{name}: slate"
        );
    }
}

/// The producer's slate, encoded by the file policy and exported by the file transport, is the
/// file upstream wrote, byte for byte. A slate the producer started carries no origin; one it
/// answered or finalized keeps the header it was received with.
#[tokio::test]
async fn exported_slate_files_equal_the_upstream_files_byte_for_byte() {
    let codecs = legacy_codecs();
    let transport = FileTransport::new();
    let dir = tempfile::tempdir().unwrap();
    for (name, vector) in file_vectors() {
        let stem = name.strip_suffix("_file").unwrap();
        let producer_json = slate_json(&read_vector(&format!("{stem}_v3"))).to_owned();
        let producer_header = header_of(&serde_json::from_str(&producer_json).unwrap());
        let producer = codecs
            .decode(&WireSlate::text(MediaType::JSON, producer_json))
            .unwrap();
        let context = EncodeContext {
            block_header_version: producer_header.block_header_version,
        };

        let policy = transport.policy();
        let wire = if starts_slate(&vector) {
            policy
                .encode_new_slate(&codecs, &producer.with_origin(None), &context)
                .unwrap()
        } else {
            policy.encode_reply(&codecs, &producer, &context).unwrap()
        };
        let path = dir.path().join(&name);
        transport
            .export(&wire, &Location::File(path.clone()))
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(&path).unwrap(),
            slate_json(&vector).as_bytes(),
            "{name}: file bytes"
        );
    }
}

#[test]
fn encoding_with_a_codec_that_is_not_registered_fails() {
    let (name, vector) = file_vectors().remove(0);
    let codecs = legacy_codecs();
    let slate = codecs
        .decode(&WireSlate::text(
            MediaType::JSON,
            slate_json(&vector).to_owned(),
        ))
        .unwrap();
    let context = EncodeContext {
        block_header_version: 6,
    };

    let error = FileTransport::new()
        .policy()
        .encode_reply(&CodecRegistry::new(), &slate, &context)
        .unwrap_err();

    assert_eq!(
        error,
        FormatError::CodecNotRegistered {
            codec: expected_codec(&name, &vector)
        },
        "{name}"
    );
}
