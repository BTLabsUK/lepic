//! Replays the G-03 file vectors in `testdata/vectors/slates`: the file transport reads every file
//! upstream's file method wrote, byte for byte and as upstream reads it, and writes every slate in
//! the V3 shape with header `3/3/<b>` (ADR 0015).

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
use lepic_slate::error::DecodeError;
use lepic_slate::origin::LegacyHeader;
use lepic_slate::registry::CodecRegistry;
use lepic_transport::error::FormatError;
use lepic_transport::file::{FilePolicy, FileTransport};
use lepic_transport::transport::{Exchange, Location, Transport};
use serde_json::Value;

const UPSTREAM_WALLET: &str = "465d499f01aad7e570b6cc220d52c6bfcf6a9a44";

/// `version` and `orig_version` of every file LEPIC writes (ADR 0015).
const FILE_VERSION: u16 = 3;

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
/// unchanged. Whatever upstream wrote, the file policy picks V3 with version and orig_version 3
/// and the producer's block header version.
#[test]
fn file_policy_picks_v3_with_header_three_for_every_upstream_case() {
    for (name, vector) in file_vectors() {
        let stem = name.strip_suffix("_file").unwrap();
        let producer: Value =
            serde_json::from_str(slate_json(&read_vector(&format!("{stem}_v3")))).unwrap();
        let producer_header = header_of(&producer);
        let received = (!starts_slate(&vector)).then_some(producer_header);
        let context = EncodeContext {
            block_header_version: producer_header.block_header_version,
        };

        let encoding = FilePolicy::choose(received, &context);

        assert_eq!(encoding.codec, LEGACY_V3_JSON, "{name}: codec");
        assert_eq!(
            encoding.legacy_header,
            Some(LegacyHeader {
                version: FILE_VERSION,
                orig_version: FILE_VERSION,
                block_header_version: producer_header.block_header_version,
            }),
            "{name}: header"
        );
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

/// The codec upstream's file method reads a file with: the one its header version names.
fn codec_for_header(name: &str, header: LegacyHeader) -> CodecId {
    match header.version {
        2 => LEGACY_V2_JSON,
        3 => LEGACY_V3_JSON,
        other => panic!("{name}: unexpected header version {other}"),
    }
}

/// Importing each file upstream wrote, through the file policy, yields the codec its header
/// names, the header as written, the vector's slate id and stage, and the slate upstream read:
/// the producer's slate, without TTL and payment proof when a version 2 header made upstream
/// read the file as V2 (`invoice_file_ttl_i2_file`, whose issuer finalizes without the TTL in
/// `invoice_file_ttl_i3_v3`).
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

        let written_header = header_of(&serde_json::from_str(bytes).unwrap());
        let origin = slate.origin().unwrap();
        assert_eq!(
            origin.codec(),
            codec_for_header(&name, written_header),
            "{name}: codec"
        );
        assert_eq!(
            origin.legacy_header(),
            Some(written_header),
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
        let mut producer: Value =
            serde_json::from_str(slate_json(&read_vector(&format!("{stem}_v3")))).unwrap();
        if written_header.version == 2 {
            producer["ttl_cutoff_height"] = Value::Null;
            producer["payment_proof"] = Value::Null;
        }
        let producer = codecs
            .decode(&WireSlate::text(MediaType::JSON, producer.to_string()))
            .unwrap();
        assert_eq!(
            slate.with_origin(None),
            producer.with_origin(None),
            "{name}: slate"
        );
    }
}

/// A version 2 file is read as V2 whether or not it carries the V3-only keys, and V2 refuses a
/// repeated top-level key, as upstream's direct parse into its V2 slate does.
#[test]
fn a_version_two_file_with_a_repeated_key_is_refused_with_or_without_v3_only_keys() {
    let codecs = legacy_codecs();
    let transport = FileTransport::new();
    let decode = |json: String| {
        transport
            .policy()
            .decode(&codecs, &WireSlate::text(MediaType::JSON, json))
    };
    let mut checked = 0;
    for (name, vector) in file_vectors() {
        let json = slate_json(&vector);
        let slate: Value = serde_json::from_str(json).unwrap();
        if header_of(&slate).version != 2 {
            continue;
        }
        let body = json.trim_start().strip_prefix('{').unwrap();
        let with_ttl = format!(r#"{{"ttl_cutoff_height":null,{body}"#);
        let repeated_id = format!(r#"{{"id":{},{body}"#, slate["id"]);
        let both = format!(r#"{{"ttl_cutoff_height":null,"id":{},{body}"#, slate["id"]);

        assert!(decode(with_ttl).is_ok(), "{name}: v3-only key alone");
        for (case, json) in [("repeated key", repeated_id), ("both", both)] {
            assert!(
                matches!(
                    decode(json),
                    Err(DecodeError::Syntax {
                        codec: LEGACY_V2_JSON,
                        ..
                    })
                ),
                "{name}: {case}"
            );
        }
        checked += 1;
    }
    assert!(checked > 0, "no version 2 file vectors");
}

/// Cases where LEPIC refuses a file upstream's parser accepts, because LEPIC's decode checks
/// more than upstream's parse step (`docs/compat/legacy-slates.md`, checks on decode).
const STRICTER_THAN_UPSTREAM: [&str; 3] = [
    "malformed_duplicate_participant_id",
    "malformed_num_participants_zero",
    "malformed_offset_too_short",
];

/// Each malformed file is accepted or refused as upstream's file method does, except the
/// deliberately stricter cases. An accepted file is read with the codec upstream read it with,
/// and re-encoded as V3 it is the V3 JSON upstream wrote back for it.
#[tokio::test]
async fn malformed_files_resolve_as_upstream_file_method_resolves_them() {
    let codecs = legacy_codecs();
    let transport = FileTransport::new();
    let dir = tempfile::tempdir().unwrap();
    let mut names: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| {
            name.strip_suffix(".json")
                .filter(|stem| stem.starts_with("malformed_"))
                .map(str::to_owned)
        })
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no malformed vectors");
    for name in names {
        let vector = read_vector(&name);
        let outcome = &vector["expected"]["file_method"];
        let path = dir.path().join(&name);
        std::fs::write(&path, vector["inputs"]["json"].as_str().unwrap()).unwrap();

        let wire = transport.import(&Location::File(path)).await.unwrap();
        let decoded = transport.policy().decode(&codecs, &wire);

        let upstream_accepts = outcome["accepted"].as_bool().unwrap();
        let stricter = STRICTER_THAN_UPSTREAM.contains(&name.as_str());
        assert!(!stricter || upstream_accepts, "{name}: listed as stricter");
        match decoded {
            Err(_) => assert!(!upstream_accepts || stricter, "{name}: refused"),
            Ok(slate) => {
                assert!(upstream_accepts && !stricter, "{name}: accepted");
                let parsed_as = match outcome["parsed_as"].as_str() {
                    Some("V2") => LEGACY_V2_JSON,
                    Some("V3") => LEGACY_V3_JSON,
                    other => panic!("{name}: unexpected parsed_as {other:?}"),
                };
                let origin = slate.origin().unwrap();
                assert_eq!(origin.codec(), parsed_as, "{name}: codec");
                let header = origin.legacy_header().unwrap();
                let context = EncodeContext {
                    block_header_version: header.block_header_version,
                };
                let v3 = codecs
                    .encode(LEGACY_V3_JSON, &slate, &context)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    v3.as_text().unwrap(),
                    outcome["reencoded_v3"].as_str().unwrap(),
                    "{name}: re-encoded"
                );
            }
        }
    }
}

/// `json` with `version` and `orig_version` set to 3. Upstream serializes the header first, so
/// this rewrites exactly the bytes the header occupies.
fn with_file_header(name: &str, json: &str) -> String {
    let header: Value = serde_json::from_str::<Value>(json).unwrap()["version_info"].clone();
    let written = format!(
        r#"{{"version_info":{{"version":{},"orig_version":{},"#,
        header["version"], header["orig_version"]
    );
    let rest = json
        .strip_prefix(&written)
        .unwrap_or_else(|| panic!("{name}: header is not serialized first"));
    format!(r#"{{"version_info":{{"version":{FILE_VERSION},"orig_version":{FILE_VERSION},{rest}"#)
}

/// The producer's slate, encoded by the file policy and exported by the file transport, is in
/// every case upstream's own V3 serialization of that slate with header `3/3/<b>`. Where
/// upstream's file method also wrote V3, the file equals upstream's file except for a version 2
/// header, which LEPIC raises to 3 so a reader keeps the TTL and payment proof. A slate the
/// producer started carries no origin; one it answered or finalized keeps the header it was
/// received with.
#[tokio::test]
async fn exported_slate_files_are_upstream_v3_with_header_three() {
    let codecs = legacy_codecs();
    let transport = FileTransport::new();
    let dir = tempfile::tempdir().unwrap();
    let mut upstream_v3 = 0;
    for (name, vector) in file_vectors() {
        let stem = name.strip_suffix("_file").unwrap();
        let producer_json = slate_json(&read_vector(&format!("{stem}_v3"))).to_owned();
        let producer_header = header_of(&serde_json::from_str(&producer_json).unwrap());
        let producer = codecs
            .decode(&WireSlate::text(MediaType::JSON, producer_json.clone()))
            .unwrap();
        let context = EncodeContext {
            block_header_version: producer_header.block_header_version,
        };

        let policy = transport.policy();
        let wire = if starts_slate(&vector) {
            policy
                .encode_new_slate(&codecs, &producer.clone().with_origin(None), &context)
                .unwrap()
        } else {
            policy.encode_reply(&codecs, &producer, &context).unwrap()
        };
        let path = dir.path().join(&name);
        transport
            .export(&wire, &Location::File(path.clone()))
            .await
            .unwrap();
        let written = std::fs::read(&path).unwrap();

        assert_eq!(
            written,
            with_file_header(&name, &producer_json).as_bytes(),
            "{name}: file bytes"
        );
        if expected_codec(&name, &vector) == LEGACY_V3_JSON {
            assert_eq!(
                written,
                with_file_header(&name, slate_json(&vector)).as_bytes(),
                "{name}: upstream file"
            );
            upstream_v3 += 1;
        }

        let read_back = policy
            .decode(
                &codecs,
                &transport.import(&Location::File(path)).await.unwrap(),
            )
            .unwrap();
        assert_eq!(
            read_back.with_origin(None),
            producer.with_origin(None),
            "{name}: read back"
        );
    }
    assert!(upstream_v3 > 0, "no upstream V3 file vectors");
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
            codec: LEGACY_V3_JSON
        },
        "{name}"
    );
}
