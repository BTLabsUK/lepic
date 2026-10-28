// SPDX-License-Identifier: Apache-2.0
//! `ur:epic-slate`: each decode rejection, the encoder's limits, round trips through lost and
//! reordered frames, the frame counts of real slates and one snapshot.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_slate::ur_slate::{
    MAX_FRAGMENT_LEN, MAX_PART_TEXT_LEN, MAX_PARTS, MAX_SEQUENCE_LEN, MAX_SLATE_TEXT_LEN,
    MAX_TOTAL_TEXT_LEN, MIN_FRAGMENT_LEN, PartFault, PayloadFault, UrDecodeError, UrEncodeError,
    UrProgress, decode_ur_slate, encode_ur_slate, fountain_part_count,
};
use proptest::prelude::*;
use serde_json::Value;
use ur::bytewords::{self, Style};

const S1: &str = "send_file_plain_s1_file";
const S2: &str = "send_file_plain_s2_file";
const S3: &str = "send_file_plain_s3_file";

/// The exact slate JSON of a G-03 vector.
fn vector_json(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/slates")
        .join(format!("{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vector["expected"]["json"].as_str().unwrap().to_owned()
}

fn decode(parts: &[String]) -> Result<UrProgress, UrDecodeError> {
    decode_ur_slate(parts)
}

fn decoded_json(parts: &[String]) -> String {
    decode(parts).unwrap().json.unwrap()
}

/// The message length in the header of a multipart part: the payload's size.
fn message_len(part: &str) -> u32 {
    let words = part.rsplit('/').next().unwrap().to_ascii_lowercase();
    let cbor = bytewords::decode(&words, Style::Minimal).unwrap();
    let mut decoder = minicbor::Decoder::new(&cbor);
    decoder.array().unwrap();
    decoder.u32().unwrap();
    decoder.u32().unwrap();
    decoder.u32().unwrap()
}

/// The fragment count in the index of a multipart part.
fn sequence_len(part: &str) -> usize {
    let index = part.split('/').nth(1).unwrap();
    index.split_once('-').unwrap().1.parse().unwrap()
}

fn deflate(bytes: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(bytes, 10)
}

/// A CBOR byte string.
fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder.bytes(bytes).unwrap();
    out
}

/// `{1: version, 2: bytes}`.
fn payload(version: u64, deflated: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder
        .map(2)
        .unwrap()
        .u64(1)
        .unwrap()
        .u64(version)
        .unwrap()
        .u64(2)
        .unwrap()
        .bytes(deflated)
        .unwrap();
    out
}

fn single_part(payload: &[u8]) -> String {
    format!(
        "UR:EPIC-SLATE/{}",
        bytewords::encode(payload, Style::Minimal).to_ascii_uppercase()
    )
}

/// A multipart part with every header field chosen by the test.
fn raw_part(index: &str, fields: [u32; 4], fragment: &[u8]) -> String {
    let mut cbor = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut cbor);
    encoder.array(5).unwrap();
    for field in fields {
        encoder.u32(field).unwrap();
    }
    encoder.bytes(fragment).unwrap();
    format!(
        "ur:epic-slate/{index}/{}",
        bytewords::encode(&cbor, Style::Minimal)
    )
}

/// CRC-32/ISO-HDLC, the checksum of BC-UR, computed bit by bit.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[test]
fn real_slates_round_trip_with_the_expected_frame_counts() {
    // (vector, fragment length, fragments)
    let cases = [
        (S1, 150, 9),
        (S1, 200, 7),
        (S1, 250, 6),
        (S2, 150, 15),
        (S2, 200, 12),
        (S2, 250, 9),
    ];
    for (name, fragment_len, fragments) in cases {
        let json = vector_json(name);
        let parts = encode_ur_slate(&json, fragment_len).unwrap();
        let longest = parts.iter().map(String::len).max().unwrap();
        eprintln!(
            "{name} at {fragment_len} B: {} B json, {} B payload, {fragments} fragments, \
             {} parts, longest part {longest} characters",
            json.len(),
            message_len(&parts[0]),
            parts.len()
        );
        assert_eq!(
            sequence_len(&parts[0]),
            fragments,
            "{name} at {fragment_len}"
        );
        assert_eq!(parts.len(), fragments + fountain_part_count(fragments));
        assert!(parts.iter().all(|part| part.starts_with("UR:EPIC-SLATE/")));
        assert_eq!(decoded_json(&parts), json);
        assert_eq!(decoded_json(&parts[..fragments]), json);
    }
}

#[test]
fn a_final_slate_round_trips_too() {
    let json = vector_json(S3);
    let parts = encode_ur_slate(&json, 200).unwrap();
    assert_eq!(decoded_json(&parts), json);
}

#[test]
fn qr_text_uses_only_the_alphanumeric_mode_alphabet() {
    let parts = encode_ur_slate(vector_json(S2), 200).unwrap();
    let alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    assert!(
        parts
            .iter()
            .all(|part| part.chars().all(|c| alphabet.contains(c)))
    );
}

#[test]
fn fountain_parts_stand_in_for_any_one_missed_fragment() {
    for name in [S1, S2] {
        let json = vector_json(name);
        let parts = encode_ur_slate(&json, 200).unwrap();
        let fragments = sequence_len(&parts[0]);
        for missed in 0..fragments {
            let mut seen = parts.clone();
            seen.remove(missed);
            assert_eq!(
                decoded_json(&seen),
                json,
                "{name} without fragment {missed}"
            );
        }
    }
}

#[test]
fn partial_scans_report_progress_without_text() {
    let parts = encode_ur_slate(vector_json(S2), 200).unwrap();
    let progress = decode(&parts[..5]).unwrap();
    assert_eq!(
        progress,
        UrProgress {
            resolved_fragments: 5,
            fragment_count: 12,
            json: None
        }
    );
    assert!(!progress.is_complete());
}

#[test]
fn no_parts_is_no_progress() {
    let progress = decode(&[]).unwrap();
    assert_eq!(progress.fragment_count, 0);
    assert!(progress.json.is_none());
}

#[test]
fn duplicates_and_lowercase_parts_decode() {
    let json = vector_json(S1);
    let mut parts = encode_ur_slate(&json, 200).unwrap();
    parts.push(parts[0].to_ascii_lowercase());
    parts.push(parts[1].clone());
    assert_eq!(decoded_json(&parts), json);
}

#[test]
fn a_short_slate_is_one_single_part_code() {
    let json = r#"{"amount":"1"}"#;
    let parts = encode_ur_slate(json, 200).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].matches('/').count(), 1);
    assert_eq!(decoded_json(&parts), json);
}

#[test]
fn small_encodings_stay_the_same() {
    let json = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"1000000"}"#;
    let mut lines = encode_ur_slate(json, 200).unwrap();
    lines.push(String::new());
    lines.extend(encode_ur_slate(json, 24).unwrap());
    insta::assert_snapshot!("small_encodings", lines.join("\n"));
}

#[test]
fn rejects_text_that_is_no_uniform_resource() {
    for text in [
        "",
        "esgxyz@epicbox.epiccash.com",
        "https://example.org/slate",
        "ur:",
        "ur:epic-slate",
        "ur:/abc",
        "ur:epic_slate/abc",
        "ur:épic/abc",
        "bytes:epic-slate/abc",
    ] {
        assert_eq!(
            decode(&[text.to_owned()]),
            Err(UrDecodeError::NotUr),
            "{text}"
        );
    }
}

#[test]
fn rejects_codes_of_other_types() {
    for (text, ur_type) in [
        (
            "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch",
            "bytes",
        ),
        (
            "UR:CRYPTO-PSBT/1-3/LPADAXCFAXHLCYYNSAMDWSHDGHBG",
            "crypto-psbt",
        ),
    ] {
        assert_eq!(
            decode(&[text.to_owned()]),
            Err(UrDecodeError::OtherType {
                ur_type: ur_type.to_owned()
            })
        );
    }
}

#[test]
fn rejects_parts_of_two_codes() {
    let s1 = encode_ur_slate(vector_json(S1), 200).unwrap();
    let s2 = encode_ur_slate(vector_json(S2), 200).unwrap();
    let short = encode_ur_slate(r#"{"a":1}"#, 200).unwrap();
    let other_short = encode_ur_slate(r#"{"b":2}"#, 200).unwrap();
    let s1_at_250 = encode_ur_slate(vector_json(S1), 250).unwrap();
    for parts in [
        vec![s1[0].clone(), s2[0].clone()],
        vec![s1[0].clone(), s1_at_250[1].clone()],
        vec![short[0].clone(), s1[0].clone()],
        vec![s1[0].clone(), short[0].clone()],
        vec![short[0].clone(), other_short[0].clone()],
        // A complete set followed by a stray part of another code.
        [s1.clone(), vec![s2[0].clone()]].concat(),
    ] {
        assert_eq!(decode(&parts), Err(UrDecodeError::MixedCodes));
    }
}

#[test]
fn rejects_more_parts_or_text_than_one_call_reads() {
    let part = encode_ur_slate(vector_json(S1), 200).unwrap()[0].clone();
    assert_eq!(
        decode(&vec![part; MAX_PARTS + 1]),
        Err(UrDecodeError::TooManyParts {
            count: MAX_PARTS + 1,
            max: MAX_PARTS
        })
    );
    let long = "A".repeat(MAX_PART_TEXT_LEN + 1);
    assert_eq!(
        decode(&[long]),
        Err(UrDecodeError::PartTooLong {
            len: MAX_PART_TEXT_LEN + 1,
            max: MAX_PART_TEXT_LEN
        })
    );
    let count = MAX_TOTAL_TEXT_LEN / MAX_PART_TEXT_LEN + 1;
    let parts = vec!["A".repeat(MAX_PART_TEXT_LEN); count];
    assert!(matches!(
        decode(&parts),
        Err(UrDecodeError::TooMuchText {
            max: MAX_TOTAL_TEXT_LEN,
            ..
        })
    ));
}

#[test]
fn rejects_a_sequence_longer_than_the_limit() {
    let part = raw_part("1-257", [1, 257, 10, 0], &[0; 10]);
    assert_eq!(
        decode(&[part]),
        Err(UrDecodeError::SequenceTooLong {
            len: 257,
            max: MAX_SEQUENCE_LEN
        })
    );
}

#[test]
fn rejects_malformed_sequence_indexes() {
    let words = bytewords::encode(&[0x80], Style::Minimal);
    for index in [
        "0-3",
        "1-0",
        "+1-3",
        "1-+3",
        "a-3",
        "1",
        "1-3-4",
        "-3",
        "99999999999-3",
    ] {
        assert_eq!(
            decode(&[format!("ur:epic-slate/{index}/{words}")]),
            Err(UrDecodeError::InvalidPart(PartFault::Index)),
            "{index}"
        );
    }
}

#[test]
fn rejects_a_body_that_is_no_bytewords() {
    let mut words = bytewords::encode(b"slate", Style::Minimal);
    words.replace_range(0..2, "ae");
    for body in [words.as_str(), "zz", "abc", "ae"] {
        assert_eq!(
            decode(&[format!("ur:epic-slate/1-1/{body}")]),
            Err(UrDecodeError::InvalidPart(PartFault::Bytewords)),
            "{body}"
        );
        assert_eq!(
            decode(&[format!("ur:epic-slate/{body}")]),
            Err(UrDecodeError::InvalidPart(PartFault::Bytewords)),
            "{body}"
        );
    }
}

#[test]
fn rejects_a_fountain_part_that_is_no_valid_cbor() {
    let invalid = |cbor: &[u8]| {
        decode(&[format!(
            "ur:epic-slate/1-1/{}",
            bytewords::encode(cbor, Style::Minimal)
        )])
    };
    for cbor in [
        vec![0x80],
        vec![0x84, 1, 1, 1, 0],
        // Five items whose fragment is text, not bytes.
        vec![0x85, 1, 1, 1, 0, 0x61, b'x'],
        // A fragment followed by another item.
        [vec![0x85, 1, 1, 1, 0], cbor_bytes(b"x"), vec![0]].concat(),
    ] {
        assert_eq!(
            invalid(&cbor),
            Err(UrDecodeError::InvalidPart(PartFault::Cbor)),
            "{cbor:02x?}"
        );
    }
}

#[test]
fn rejects_a_part_whose_index_disagrees_with_its_header() {
    for part in [
        raw_part("2-3", [1, 3, 30, 0], &[0; 10]),
        raw_part("1-4", [1, 3, 30, 0], &[0; 10]),
    ] {
        assert_eq!(
            decode(&[part]),
            Err(UrDecodeError::InvalidPart(PartFault::IndexMismatch))
        );
    }
}

#[test]
fn rejects_empty_or_oversized_fragments() {
    for len in [0, MAX_FRAGMENT_LEN + 1] {
        let part = raw_part("1-1", [1, 1, 1, 0], &vec![0; len]);
        assert!(part.len() <= MAX_PART_TEXT_LEN);
        assert_eq!(
            decode(&[part]),
            Err(UrDecodeError::InvalidPart(PartFault::FragmentLength {
                len
            }))
        );
    }
}

#[test]
fn rejects_a_message_length_the_fragments_cannot_hold() {
    for (count, message_length) in [(1, 11), (1, 0), (3, 20), (3, 31)] {
        let part = raw_part(
            &format!("1-{count}"),
            [1, count, message_length, 0],
            &[0; 10],
        );
        assert_eq!(
            decode(&[part]),
            Err(UrDecodeError::InvalidPart(PartFault::MessageLength)),
            "{count} fragments, {message_length} bytes"
        );
    }
}

#[test]
fn rejects_fragments_that_fail_the_message_checksum() {
    let message = payload(1, &deflate(b"{}"));
    let len = u32::try_from(message.len()).unwrap();
    let part = raw_part("1-1", [1, 1, len, crc32(&message) ^ 1], &message);
    assert_eq!(
        decode(&[part]),
        Err(UrDecodeError::InvalidPart(PartFault::Reassembly))
    );
    let good = raw_part("1-1", [1, 1, len, crc32(&message)], &message);
    assert_eq!(decoded_json(&[good]), "{}");
}

#[test]
fn rejects_a_malformed_payload() {
    let deflated = deflate(b"{}");
    let bytes = cbor_bytes(&deflated);
    let cases: Vec<(Vec<u8>, PayloadFault)> = vec![
        (vec![0x82, 1, 2], PayloadFault::NotAMap),
        (vec![0xbf, 0x01, 0x01, 0xff], PayloadFault::NotAMap),
        (vec![0xa0], PayloadFault::MissingKey { key: 1 }),
        (vec![0xa1, 0x01, 0x01], PayloadFault::MissingKey { key: 2 }),
        (
            [vec![0xa1, 0x02], bytes.clone()].concat(),
            PayloadFault::UnexpectedKey,
        ),
        (
            [vec![0xa2, 0x01, 0x01, 0x03], bytes.clone()].concat(),
            PayloadFault::UnexpectedKey,
        ),
        (
            [
                vec![0xa3, 0x01, 0x01, 0x02],
                bytes.clone(),
                vec![0x03, 0x00],
            ]
            .concat(),
            PayloadFault::UnexpectedKey,
        ),
        (vec![0xa2, 0x01, 0x61, b'1'], PayloadFault::WrongType),
        (
            vec![0xa2, 0x01, 0x01, 0x02, 0x61, b'x'],
            PayloadFault::WrongType,
        ),
        (vec![0xa2, 0x61, b'1', 0x01], PayloadFault::WrongType),
        (
            [payload(1, &deflated), vec![0x00]].concat(),
            PayloadFault::TrailingBytes,
        ),
    ];
    for (cbor, fault) in cases {
        assert_eq!(
            decode(&[single_part(&cbor)]),
            Err(UrDecodeError::MalformedPayload(fault)),
            "{cbor:02x?}"
        );
    }
}

#[test]
fn rejects_an_unknown_payload_version() {
    for version in [0, 2, u64::MAX] {
        assert_eq!(
            decode(&[single_part(&payload(version, &deflate(b"{}")))]),
            Err(UrDecodeError::UnsupportedVersion { version })
        );
    }
}

#[test]
fn rejects_data_that_is_no_deflate_stream() {
    assert_eq!(
        decode(&[single_part(&payload(1, &[0xff, 0xff, 0xff]))]),
        Err(UrDecodeError::InvalidDeflate)
    );
}

#[test]
fn stops_inflating_at_the_limit() {
    let bomb = deflate(&vec![b' '; MAX_SLATE_TEXT_LEN + 1]);
    assert!(bomb.len() < 200);
    assert_eq!(
        decode(&[single_part(&payload(1, &bomb))]),
        Err(UrDecodeError::InflatesTooLarge {
            max: MAX_SLATE_TEXT_LEN
        })
    );
    let full = deflate(&vec![b' '; MAX_SLATE_TEXT_LEN - 2]);
    let text = [b"{", &vec![b' '; MAX_SLATE_TEXT_LEN - 2][..], b"}"].concat();
    assert!(full.len() < 200);
    assert_eq!(
        decoded_json(&[single_part(&payload(1, &deflate(&text)))]).len(),
        MAX_SLATE_TEXT_LEN
    );
}

#[test]
fn rejects_text_that_is_no_utf8_or_no_json() {
    assert_eq!(
        decode(&[single_part(&payload(1, &deflate(&[b'"', 0xff, b'"'])))]),
        Err(UrDecodeError::NotUtf8)
    );
    for text in [&b"slate"[..], b"", b"{\"a\":", b"{} {}"] {
        assert_eq!(
            decode(&[single_part(&payload(1, &deflate(text)))]),
            Err(UrDecodeError::NotJson),
            "{text:?}"
        );
    }
}

#[test]
fn refuses_to_encode_empty_long_or_non_json_text() {
    assert_eq!(encode_ur_slate("", 200), Err(UrEncodeError::Empty));
    assert_eq!(encode_ur_slate("slate", 200), Err(UrEncodeError::NotJson));
    let long = format!("\"{}\"", "a".repeat(MAX_SLATE_TEXT_LEN));
    assert_eq!(
        encode_ur_slate(&long, 200),
        Err(UrEncodeError::TextTooLong {
            len: MAX_SLATE_TEXT_LEN + 2,
            max: MAX_SLATE_TEXT_LEN
        })
    );
}

#[test]
fn refuses_fragment_lengths_outside_the_limits() {
    for len in [0, MIN_FRAGMENT_LEN - 1, MAX_FRAGMENT_LEN + 1] {
        assert_eq!(
            encode_ur_slate("{}", len),
            Err(UrEncodeError::FragmentLength {
                len,
                min: MIN_FRAGMENT_LEN,
                max: MAX_FRAGMENT_LEN
            })
        );
    }
}

#[test]
fn refuses_slates_that_need_too_many_fragments() {
    // Hex of a counter hashed by a cheap mixer is incompressible enough for deflate.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let noise: String = (0..20_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(b"0123456789abcdef"[usize::try_from(state % 16).unwrap()])
        })
        .collect();
    let json = format!("\"{noise}\"");
    assert!(matches!(
        encode_ur_slate(&json, MIN_FRAGMENT_LEN),
        Err(UrEncodeError::TooManyFragments {
            max: MAX_SEQUENCE_LEN,
            ..
        })
    ));
    assert_eq!(decoded_json(&encode_ur_slate(&json, 200).unwrap()), json);
}

/// JSON text of nested objects, arrays, strings and numbers.
fn json_text() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(Value::from),
        "[ -~]{0,40}".prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
        "[0-9a-f]{0,200}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::from),
            prop::collection::btree_map("[a-z_]{1,12}", inner, 0..8)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
    .prop_map(|value| value.to_string())
}

/// Frames a camera sees while the list loops: each shown frame is missed when the next value of
/// a xorshift stream seeded by `seed` falls under `loss_percent`. Returns the distinct parts
/// seen when the decoder completed, after at most `max_loops` loops.
fn scan_while_looping(
    parts: &[String],
    seed: u64,
    loss_percent: u64,
    max_loops: usize,
) -> Option<(Vec<String>, String)> {
    let mut state = seed | 1;
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..max_loops {
        for part in parts {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if state % 100 < loss_percent || seen.contains(part) {
                continue;
            }
            seen.push(part.clone());
            let progress = decode_ur_slate(&seen).unwrap();
            assert!(progress.resolved_fragments <= progress.fragment_count);
            if let Some(json) = progress.json {
                return Some((seen, json));
            }
        }
    }
    None
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn encoded_text_decodes_to_itself_in_any_order(
        json in json_text(),
        fragment_len in MIN_FRAGMENT_LEN..=400usize,
        order_seed in any::<u64>(),
    ) {
        let parts = encode_ur_slate(&json, fragment_len).unwrap();
        let mut shuffled = parts.clone();
        let mut state = order_seed | 1;
        for index in (1..shuffled.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            shuffled.swap(index, usize::try_from(state % (index as u64 + 1)).unwrap());
        }
        prop_assert_eq!(decoded_json(&shuffled), json);
    }

    #[test]
    fn a_looping_code_is_recovered_through_missed_frames(
        json in json_text(),
        fragment_len in MIN_FRAGMENT_LEN..=200usize,
        loss_seed in any::<u64>(),
        loss_percent in 0..60u64,
    ) {
        let parts = encode_ur_slate(&json, fragment_len).unwrap();
        let recovered = scan_while_looping(&parts, loss_seed, loss_percent, 200);
        let (_, decoded) = recovered.expect("a looping code completes");
        prop_assert_eq!(decoded, json);
    }
}
