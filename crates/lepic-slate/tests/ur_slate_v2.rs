// SPDX-License-Identifier: Apache-2.0
//! `ur:epic-slate` payload version 2: native slate and envelope bytes, the single-code
//! threshold, fragments, every refusal, and version 1 reading as before.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use lepic_slate::ur_slate::{
    BINARY_FRAGMENT_LEN, ENVELOPE_MAGIC, MAX_BINARY_LEN, MAX_SEQUENCE_LEN, NATIVE_SLATE_MAGIC,
    PayloadFault, SINGLE_CODE_MAX_LEN, UrBinary, UrBinaryEncodeError, UrContent, UrContentError,
    UrDecodeError, decode_ur_parts, decode_ur_slate, encode_ur_binary, encode_ur_slate,
};
use ur::bytewords::{self, Style};

fn bytes(magic: [u8; 4], len: usize) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend((0..len.saturating_sub(4)).map(|i| u8::try_from(i * 7 % 251).unwrap()));
    out
}

/// A single-part code of `payload` as the CBOR bytes, bypassing the encoder.
fn code_of_payload(payload: &[u8]) -> String {
    format!(
        "ur:epic-slate/{}",
        bytewords::encode(payload, Style::Minimal)
    )
}

fn content(parts: &[String]) -> UrContent {
    decode_ur_parts(parts).unwrap().content.unwrap()
}

#[test]
fn a_short_native_slate_is_one_single_part_code() {
    let slate = bytes(NATIVE_SLATE_MAGIC, 300);
    let parts = encode_ur_binary(&slate, BINARY_FRAGMENT_LEN).unwrap();
    assert_eq!(parts.len(), 1);
    assert!(parts[0].starts_with("UR:EPIC-SLATE/"));
    assert!(!parts[0].contains("1-"));
    assert_eq!(
        content(&parts),
        UrContent::Binary(UrBinary::NativeSlate(slate))
    );
}

#[test]
fn an_envelope_is_told_from_its_fourth_byte() {
    let envelope = bytes(ENVELOPE_MAGIC, 100);
    let parts = encode_ur_binary(&envelope, BINARY_FRAGMENT_LEN).unwrap();
    assert_eq!(
        content(&parts),
        UrContent::Binary(UrBinary::Envelope(envelope))
    );
}

#[test]
fn the_single_code_threshold_is_the_payload_size() {
    // The payload adds a 4-byte map head and a 3-byte byte string head to a body over 255.
    let at = SINGLE_CODE_MAX_LEN - 7;
    let single = encode_ur_binary(&bytes(NATIVE_SLATE_MAGIC, at), BINARY_FRAGMENT_LEN).unwrap();
    assert_eq!(single.len(), 1);
    let multi = encode_ur_binary(&bytes(NATIVE_SLATE_MAGIC, at + 1), BINARY_FRAGMENT_LEN).unwrap();
    assert!(multi.len() > 1);
    assert!(multi[0].starts_with("UR:EPIC-SLATE/1-2/"));
}

#[test]
fn a_long_envelope_uses_200_byte_fragments_and_fountain_parts() {
    let envelope = bytes(ENVELOPE_MAGIC, 3000);
    let parts = encode_ur_binary(&envelope, BINARY_FRAGMENT_LEN).unwrap();
    // 3007 payload bytes in 16 fragments of 188, then 32 fountain parts.
    assert_eq!(parts.len(), 16 + 32);
    assert!(parts[0].starts_with("UR:EPIC-SLATE/1-16/"));
    assert_eq!(
        content(&parts),
        UrContent::Binary(UrBinary::Envelope(envelope.clone()))
    );
    // Missing two pure parts, recovered from fountain parts.
    let lossy: Vec<String> = parts
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 3 && *i != 9)
        .map(|(_, part)| part.clone())
        .collect();
    assert_eq!(
        content(&lossy),
        UrContent::Binary(UrBinary::Envelope(envelope))
    );
}

#[test]
fn progress_is_reported_before_the_last_fragment() {
    let parts = encode_ur_binary(&bytes(NATIVE_SLATE_MAGIC, 3000), BINARY_FRAGMENT_LEN).unwrap();
    let progress = decode_ur_parts(&parts[..5]).unwrap();
    assert_eq!(progress.fragment_count, 16);
    assert_eq!(progress.resolved_fragments, 5);
    assert!(!progress.is_complete());
    assert_eq!(decode_ur_parts::<String>(&[]).unwrap().fragment_count, 0);
}

#[test]
fn version_1_codes_read_through_decode_ur_parts_and_stay_the_same() {
    let json = r#"{"amount":"1"}"#;
    let parts = encode_ur_slate(json, 200).unwrap();
    assert_eq!(content(&parts), UrContent::Json(json.to_owned()));
    assert_eq!(decode_ur_slate(&parts).unwrap().json.as_deref(), Some(json));
}

#[test]
fn the_version_1_reader_refuses_a_version_2_code() {
    let parts = encode_ur_binary(&bytes(NATIVE_SLATE_MAGIC, 50), BINARY_FRAGMENT_LEN).unwrap();
    assert_eq!(
        decode_ur_slate(&parts),
        Err(UrDecodeError::UnsupportedVersion { version: 2 })
    );
}

#[test]
fn refuses_other_magic_at_both_ends() {
    let mut other = bytes(NATIVE_SLATE_MAGIC, 50);
    other[3] = 0x58;
    assert_eq!(
        encode_ur_binary(&other, BINARY_FRAGMENT_LEN),
        Err(UrBinaryEncodeError::UnknownMagic)
    );
    assert_eq!(
        encode_ur_binary(&[0x89, 0x45], BINARY_FRAGMENT_LEN),
        Err(UrBinaryEncodeError::UnknownMagic)
    );
    assert_eq!(
        encode_ur_binary(&[], BINARY_FRAGMENT_LEN),
        Err(UrBinaryEncodeError::UnknownMagic)
    );
    // A hand-built code {1: 2, 2: h'89 45 53 58 ...'}.
    let mut payload = vec![0xa2, 0x01, 0x02, 0x02, 0x44];
    payload.extend_from_slice(&[0x89, 0x45, 0x53, 0x58]);
    let code = code_of_payload(&payload);
    assert_eq!(decode_ur_parts(&[code]), Err(UrContentError::UnknownMagic));
    let mut payload = vec![0xa2, 0x01, 0x02, 0x02, 0x42, 0x89, 0x45];
    let code = code_of_payload(&payload);
    assert_eq!(decode_ur_parts(&[code]), Err(UrContentError::UnknownMagic));
    payload.truncate(5);
    payload[4] = 0x40;
    let code = code_of_payload(&payload);
    assert_eq!(decode_ur_parts(&[code]), Err(UrContentError::UnknownMagic));
}

#[test]
fn refuses_bad_payload_maps_and_versions() {
    let magic = NATIVE_SLATE_MAGIC;
    let mut body = vec![0x44];
    body.extend_from_slice(&magic);
    let cases: [(&str, Vec<u8>, UrContentError); 5] = [
        (
            "version 3",
            [&[0xa2, 0x01, 0x03, 0x02][..], &body].concat(),
            UrDecodeError::UnsupportedVersion { version: 3 }.into(),
        ),
        (
            "missing bytes",
            vec![0xa1, 0x01, 0x02],
            UrDecodeError::MalformedPayload(PayloadFault::MissingKey { key: 2 }).into(),
        ),
        (
            "text instead of bytes",
            vec![0xa2, 0x01, 0x02, 0x02, 0x64, 0x61, 0x62, 0x63, 0x64],
            UrDecodeError::MalformedPayload(PayloadFault::WrongType).into(),
        ),
        (
            "trailing bytes",
            [&[0xa2, 0x01, 0x02, 0x02][..], &body, &[0x00]].concat(),
            UrDecodeError::MalformedPayload(PayloadFault::TrailingBytes).into(),
        ),
        (
            "not a map",
            vec![0x80],
            UrDecodeError::MalformedPayload(PayloadFault::NotAMap).into(),
        ),
    ];
    for (name, payload, expected) in cases {
        assert_eq!(
            decode_ur_parts(&[code_of_payload(&payload)]),
            Err(expected),
            "{name}"
        );
    }
}

#[test]
fn bounds_the_byte_string_and_the_fragment_count() {
    let largest = bytes(ENVELOPE_MAGIC, MAX_BINARY_LEN);
    assert_eq!(
        encode_ur_binary(&bytes(ENVELOPE_MAGIC, MAX_BINARY_LEN + 1), 1024),
        Err(UrBinaryEncodeError::TooLong {
            len: MAX_BINARY_LEN + 1,
            max: MAX_BINARY_LEN
        })
    );
    // At 200 bytes a code holds at most 256 fragments: 51,200 bytes.
    assert!(matches!(
        encode_ur_binary(&largest, BINARY_FRAGMENT_LEN),
        Err(UrBinaryEncodeError::TooManyFragments { max, .. }) if max == MAX_SEQUENCE_LEN
    ));
    let parts = encode_ur_binary(&largest, 1024).unwrap();
    assert_eq!(
        content(&parts),
        UrContent::Binary(UrBinary::Envelope(largest))
    );
    assert!(matches!(
        encode_ur_binary(&bytes(ENVELOPE_MAGIC, 100), 8),
        Err(UrBinaryEncodeError::FragmentLength { .. })
    ));
}

#[test]
fn a_reader_refuses_a_byte_string_over_the_bound() {
    let big = bytes(ENVELOPE_MAGIC, MAX_BINARY_LEN + 1);
    let mut payload = vec![0xa2, 0x01, 0x02, 0x02, 0x5a];
    payload.extend_from_slice(&u32::try_from(big.len()).unwrap().to_be_bytes());
    payload.extend_from_slice(&big);
    let mut encoder = ur::Encoder::new(&payload, 1024, "epic-slate").unwrap();
    let count = encoder.fragment_count();
    let parts: Vec<String> = (0..count).map(|_| encoder.next_part().unwrap()).collect();
    assert_eq!(
        decode_ur_parts(&parts),
        Err(UrContentError::TooLong {
            len: big.len(),
            max: MAX_BINARY_LEN
        })
    );
}

#[test]
fn other_ur_types_and_parts_of_two_codes_are_refused_as_before() {
    assert!(matches!(
        decode_ur_parts(&["ur:bytes/gdaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaetkmwhgmh".to_owned()]),
        Err(UrContentError::Decode(UrDecodeError::OtherType { .. }))
    ));
    let a = encode_ur_binary(&bytes(NATIVE_SLATE_MAGIC, 3000), 200).unwrap();
    let b = encode_ur_binary(&bytes(ENVELOPE_MAGIC, 3000), 200).unwrap();
    assert_eq!(
        decode_ur_parts(&[a[0].clone(), b[1].clone()]),
        Err(UrContentError::Decode(UrDecodeError::MixedCodes))
    );
}
