//! The V2 JSON codec beyond the vector replay: what the V2 shape cannot carry, the decode
//! rejection rules of `docs/compat/legacy-slates.md` on the V2 path, round-trip properties and one
//! snapshot per stage.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_crypto::CryptoError;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::params::{MAX_TX_WEIGHT, Network};
use lepic_slate::codec::legacy::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, EncodeContext, MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use lepic_slate::error::{
    DecodeError, EncodeError, FieldProblem, HexError, SlateError, TextPosition, Unrepresentable,
    ValidationError,
};
use lepic_slate::model::{KernelLock, ParticipantMessage, Slate};
use lepic_slate::origin::{LegacyHeader, WireOrigin};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use proptest::prelude::*;
use serde_json::{Value, json};

const S1: &str = "send_file_messages_s1_file";
const S2: &str = "send_file_messages_s2_file";
const S3: &str = "send_file_messages_s3_file";
const I1: &str = "invoice_file_messages_i1_file";
const I2: &str = "invoice_file_messages_i2_file";
const I3: &str = "invoice_file_messages_i3_file";
/// The Epicbox sender's payload: V2 shape, header 3/3/6.
const EPICBOX_S1: &str = "send_epicbox_message_s1_epicbox";
const PAYMENT_PROOF_S1: &str = "send_file_ttl_payment_proof_messages_s1_v3";

const BASE_FEE: Fee = Network::Floonet.params().default_base_fee();

const CONTEXT: EncodeContext = EncodeContext {
    block_header_version: 6,
};

fn codec() -> V2JsonCodec {
    V2JsonCodec::new(BASE_FEE)
}

/// The exact slate JSON of a G-03 vector.
fn vector_json(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/slates")
        .join(format!("{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vector["expected"]["json"].as_str().unwrap().to_owned()
}

fn wire(json: &str) -> WireSlate {
    WireSlate::text(MediaType::JSON, json.to_owned())
}

fn decode(json: &str) -> Result<Slate, DecodeError> {
    codec().decode(&wire(json))
}

fn encode(slate: &Slate) -> String {
    let encoded = codec().encode(slate, &CONTEXT).unwrap();
    encoded.as_text().unwrap().to_owned()
}

/// Decodes the vector after `mutate` has changed its parsed JSON.
fn decode_mutated(name: &str, mutate: impl FnOnce(&mut Value)) -> Result<Slate, DecodeError> {
    let mut value: Value = serde_json::from_str(&vector_json(name)).unwrap();
    mutate(&mut value);
    decode(&serde_json::to_string(&value).unwrap())
}

fn field(field: &'static str, problem: FieldProblem) -> Result<Slate, DecodeError> {
    Err(DecodeError::Field { field, problem })
}

fn invalid(error: ValidationError) -> Result<Slate, DecodeError> {
    Err(DecodeError::Validation(error))
}

fn model(error: SlateError) -> Result<Slate, DecodeError> {
    Err(DecodeError::Model(error))
}

fn hex_length(expected: usize, actual: usize) -> FieldProblem {
    FieldProblem::Hex(HexError::WrongLength { expected, actual })
}

fn set(pointer: &'static str, new: Value) -> impl FnOnce(&mut Value) {
    move |value| *value.pointer_mut(pointer).unwrap() = new
}

fn unrepresentable(what: Unrepresentable) -> Result<WireSlate, EncodeError> {
    Err(EncodeError::Unrepresentable {
        codec: LEGACY_V2_JSON,
        what,
    })
}

mod what_v2_cannot_carry {
    use super::*;

    fn with_payment_proof() -> Slate {
        V3JsonCodec::new(BASE_FEE)
            .decode(&wire(&vector_json(PAYMENT_PROOF_S1)))
            .unwrap()
    }

    #[test]
    fn refuses_to_encode_a_slate_with_a_payment_proof() {
        let slate = with_payment_proof();
        assert!(slate.payment_proof().is_some());
        assert_eq!(
            codec().encode(&slate, &CONTEXT),
            unrepresentable(Unrepresentable::PaymentProof)
        );
        let mut parts = slate.into_parts();
        parts.ttl_cutoff_height = None;
        let slate = Slate::from_parts(parts).unwrap();
        assert_eq!(
            codec().encode(&slate, &CONTEXT),
            unrepresentable(Unrepresentable::PaymentProof)
        );
    }

    #[test]
    fn refuses_to_encode_a_slate_with_a_ttl() {
        let mut parts = decode(&vector_json(S1)).unwrap().into_parts();
        parts.ttl_cutoff_height = Some(Height::new(40));
        let slate = Slate::from_parts(parts).unwrap();
        assert_eq!(
            codec().encode(&slate, &CONTEXT),
            unrepresentable(Unrepresentable::TimeToLive)
        );
    }

    #[test]
    fn a_slate_with_the_ttl_key_is_not_v2() {
        for ttl in [Value::Null, json!("34")] {
            let mut value: Value = serde_json::from_str(&vector_json(S1)).unwrap();
            value["ttl_cutoff_height"] = ttl;
            let json = serde_json::to_string(&value).unwrap();
            assert!(!codec().detect(&wire(&json)));
            assert_eq!(
                decode(&json),
                Err(DecodeError::NotRecognised {
                    codec: LEGACY_V2_JSON
                })
            );
        }
    }

    #[test]
    fn rejects_a_payment_proof_instead_of_dropping_it() {
        let proof =
            serde_json::from_str::<Value>(&vector_json(PAYMENT_PROOF_S1)).unwrap()["payment_proof"]
                .clone();
        assert_eq!(
            decode_mutated(S1, |value| value["payment_proof"] = proof),
            field("payment_proof", FieldProblem::Unexpected)
        );
        assert_eq!(
            decode_mutated(S1, |value| value["payment_proof"] = json!("x")),
            field("payment_proof", FieldProblem::Unexpected)
        );
    }

    #[test]
    fn a_null_payment_proof_is_no_payment_proof() {
        let slate = decode_mutated(S1, |value| value["payment_proof"] = Value::Null).unwrap();
        assert_eq!(slate.payment_proof(), None);
        assert_eq!(encode(&slate), vector_json(S1));
    }
}

mod header {
    use super::*;

    fn header(version: u16, block_header_version: u16) -> LegacyHeader {
        LegacyHeader {
            version,
            orig_version: version,
            block_header_version,
        }
    }

    #[test]
    fn keeps_the_file_header_and_the_epicbox_header() {
        let epicbox = LegacyHeader {
            version: 2,
            orig_version: 3,
            block_header_version: 6,
        };
        for (name, expected) in [(S1, header(2, 6)), (EPICBOX_S1, epicbox)] {
            let slate = decode(&vector_json(name)).unwrap();
            assert_eq!(
                slate.origin(),
                Some(&WireOrigin::legacy(LEGACY_V2_JSON, expected)),
                "{name}"
            );
        }
    }

    /// The reply keeps `orig_version` and `block_header_version` and, being V2-shaped, says 2.
    #[test]
    fn a_reply_echoes_the_received_header_at_version_two() {
        let received = decode(&vector_json(EPICBOX_S1)).unwrap();
        let mut parts = decode(&vector_json(S2)).unwrap().into_parts();
        parts.origin = received.origin().copied();
        let reply = Slate::from_parts(parts).unwrap();
        let context = EncodeContext {
            block_header_version: 7,
        };
        let encoded = codec().encode(&reply, &context).unwrap();
        assert!(encoded.as_text().unwrap().starts_with(
            r#"{"version_info":{"version":2,"orig_version":3,"block_header_version":6},"#
        ));
    }

    /// `v4.0.2` sent V2-shaped Epicbox slates with `version` 3; they still decode, and the
    /// reply is written at version 2 as `v4.1.0` writes it.
    #[test]
    fn a_version_three_v2_slate_decodes_and_encodes_at_version_two() {
        let slate =
            decode_mutated(S1, |value| value["version_info"]["version"] = json!(3)).unwrap();
        assert_eq!(
            slate.origin().and_then(WireOrigin::legacy_header),
            Some(LegacyHeader {
                version: 3,
                orig_version: 2,
                block_header_version: 6,
            })
        );
        assert_eq!(encode(&slate), vector_json(S1));
    }

    #[test]
    fn a_slate_from_another_codec_keeps_its_header() {
        let v3 = V3JsonCodec::new(BASE_FEE)
            .decode(&wire(&vector_json("send_file_messages_s1_v3")))
            .unwrap();
        assert_eq!(encode(&v3), vector_json("send_file_messages_s1_v2"));
    }

    #[test]
    fn rejects_header_version_other_than_two_or_three() {
        for version in [0, 1, 4] {
            assert_eq!(
                decode_mutated(S1, set("/version_info/version", json!(version))),
                Err(DecodeError::UnsupportedVersion {
                    codec: LEGACY_V2_JSON,
                    version
                })
            );
        }
    }

    #[test]
    fn rejects_header_values_that_are_not_u16_numbers() {
        assert_eq!(
            decode_mutated(S1, set("/version_info/orig_version", json!("2"))),
            field("version_info.orig_version", FieldProblem::WrongType)
        );
        assert_eq!(
            decode_mutated(S1, set("/version_info/block_header_version", json!(65_536))),
            field(
                "version_info.block_header_version",
                FieldProblem::IntegerOutOfRange
            )
        );
        assert_eq!(
            decode_mutated(S1, |value| {
                value.as_object_mut().unwrap().remove("version_info");
            }),
            field("version_info", FieldProblem::Missing)
        );
    }
}

mod shared_rules {
    use super::*;

    #[test]
    fn rejects_values_of_the_wrong_form() {
        let cases: [(&str, &str, Value, &str, FieldProblem); 8] = [
            (
                S1,
                "/tx/offset",
                json!("d2".repeat(31)),
                "tx.offset",
                hex_length(64, 62),
            ),
            (
                S1,
                "/tx/body/inputs/0/commit",
                json!(format!("zz{}", "00".repeat(32))),
                "tx.body.inputs.commit",
                FieldProblem::Hex(HexError::InvalidDigit),
            ),
            (
                S1,
                "/tx/body/outputs/0/commit",
                json!(format!("07{}", "11".repeat(32))),
                "tx.body.outputs.commit",
                FieldProblem::Crypto(CryptoError::InvalidCommitment),
            ),
            (
                S1,
                "/participant_data/0/public_blind_excess",
                json!(format!("05{}", "11".repeat(32))),
                "participant_data.public_blind_excess",
                FieldProblem::Crypto(CryptoError::InvalidPublicKey),
            ),
            (
                S2,
                "/participant_data/1/part_sig",
                json!("ff".repeat(64)),
                "participant_data.part_sig",
                FieldProblem::Crypto(CryptoError::InvalidSignature),
            ),
            (
                S3,
                "/tx/body/kernels/0/excess",
                json!("09"),
                "tx.body.kernels.excess",
                hex_length(66, 2),
            ),
            (
                S1,
                "/amount",
                json!(-1),
                "amount",
                FieldProblem::IntegerOutOfRange,
            ),
            (
                S1,
                "/num_participants",
                json!("2"),
                "num_participants",
                FieldProblem::WrongType,
            ),
        ];
        for (name, pointer, new, name_of_field, problem) in cases {
            assert_eq!(
                decode_mutated(name, set(pointer, new)),
                field(name_of_field, problem),
                "{pointer}"
            );
        }
    }

    #[test]
    fn rejects_inconsistent_participants() {
        assert_eq!(
            decode_mutated(S1, set("/num_participants", json!(3))),
            invalid(ValidationError::UnsupportedParticipantCount { declared: 3 })
        );
        assert_eq!(
            decode_mutated(S2, set("/participant_data/1/id", json!("0"))),
            invalid(ValidationError::DuplicateParticipantId { id: 0 })
        );
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/id", json!("2"))),
            invalid(ValidationError::ParticipantIdOutOfRange { id: 2, declared: 2 })
        );
        assert_eq!(
            decode_mutated(S2, |value| {
                let extra = value["participant_data"][1].clone();
                value["participant_data"]
                    .as_array_mut()
                    .unwrap()
                    .push(extra);
            }),
            invalid(ValidationError::TooManyParticipants {
                count: 3,
                declared: 2
            })
        );
        assert_eq!(
            decode_mutated(S2, |value| {
                let participants = value["participant_data"].as_array_mut().unwrap();
                participants.extend([json!(7), json!("not a participant"), json!([[]])]);
            }),
            invalid(ValidationError::TooManyParticipants {
                count: 5,
                declared: 2
            })
        );
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/message_sig", Value::Null)),
            field("participant_data.message_sig", FieldProblem::Missing)
        );
    }

    #[test]
    fn rejects_inconsistent_kernels_and_fees() {
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels", json!([]))),
            invalid(ValidationError::KernelCount { count: 0 })
        );
        assert_eq!(
            decode_mutated(S1, |value| {
                let kernels = value["tx"]["body"]["kernels"].as_array_mut().unwrap();
                kernels.extend([json!(7), json!("not a kernel"), json!([[]])]);
            }),
            invalid(ValidationError::KernelCount { count: 4 })
        );
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels/0/fee", json!("900000"))),
            invalid(ValidationError::KernelFeeMismatch {
                slate: Fee::new(800_000),
                kernel: Fee::new(900_000)
            })
        );
        assert_eq!(
            decode_mutated(S1, |value| {
                value["fee"] = json!("799999");
                value["tx"]["body"]["kernels"][0]["fee"] = json!("799999");
            }),
            invalid(ValidationError::FeeBelowMinimum {
                fee: Fee::new(799_999),
                minimum: Fee::new(800_000)
            })
        );
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels/0/features", json!("Coinbase"))),
            invalid(ValidationError::CoinbaseKernel)
        );
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels/0/lock_height", json!("5"))),
            invalid(ValidationError::KernelLockMismatch {
                slate: Height::ZERO,
                kernel: Height::new(5)
            })
        );
        assert_eq!(
            decode_mutated(S3, |value| {
                let kernel = &mut value["tx"]["body"]["kernels"][0];
                kernel["excess"] = json!("00".repeat(33));
                kernel["excess_sig"] = json!("00".repeat(64));
            }),
            model(SlateError::MissingKernelExcess { stage: Stage::S3 })
        );
        assert_eq!(
            decode_mutated(I1, |value| {
                value["fee"] = json!("800000");
                value["tx"]["body"]["kernels"][0]["fee"] = json!("800000");
            }),
            model(SlateError::FeeBeforeSender {
                stage: Stage::I1,
                fee: Fee::new(800_000)
            })
        );
    }

    #[test]
    fn rejects_body_above_the_transaction_weight_before_parsing_it() {
        let result = decode_mutated(S1, |value| {
            let input = json!({"features": "Plain", "commit": "not hex"});
            value["tx"]["body"]["inputs"] = Value::Array(vec![input; 40_000]);
        });
        assert!(matches!(
            result,
            Err(DecodeError::Model(SlateError::BodyTooHeavy {
                max: MAX_TX_WEIGHT,
                ..
            }))
        ));
    }

    #[test]
    fn minimum_fee_follows_the_configured_base_fee() {
        let strict = V2JsonCodec::new(Fee::new(BASE_FEE.value() + 1));
        assert_eq!(
            strict.decode(&wire(&vector_json(S2))),
            invalid(ValidationError::FeeBelowMinimum {
                fee: Fee::new(800_000),
                minimum: Fee::new(800_008)
            })
        );
    }

    #[test]
    fn accepts_integers_written_as_numbers_and_writes_them_as_strings() {
        let slate = decode_mutated(S2, |value| {
            value["amount"] = json!(110_000_000_u64);
            value["height"] = json!(4);
            value["participant_data"][1]["id"] = json!(1);
            value["tx"]["body"]["kernels"][0]["fee"] = json!(800_000);
        })
        .unwrap();
        assert_eq!(slate.amount(), Amount::new(110_000_000));
        assert_eq!(encode(&slate), vector_json(S2));
    }

    #[test]
    fn height_locked_kernel_round_trips() {
        let json = vector_json(S1)
            .replace("\"lock_height\":\"0\"", "\"lock_height\":\"40\"")
            .replace(
                "\"features\":\"Plain\",\"fee\"",
                "\"features\":\"HeightLocked\",\"fee\"",
            );
        let slate = decode(&json).unwrap();
        assert_eq!(
            slate.kernel_features(),
            KernelFeatures::HeightLocked {
                fee: Fee::new(800_000),
                lock_height: Height::new(40)
            }
        );
        assert_eq!(encode(&slate), json);
    }

    #[test]
    fn invoice_roles_are_inverted_on_the_wire() {
        let slate = decode(&vector_json(I1)).unwrap();
        assert_eq!(slate.stage(), Stage::I1);
        assert!(slate.participant(Role::Receiver).is_some());
        assert!(slate.participant(Role::Sender).is_none());
        let value: Value = serde_json::from_str(&vector_json(I1)).unwrap();
        assert_eq!(value["participant_data"][0]["id"], "1");
    }
}

mod input_forms {
    use super::*;

    #[test]
    fn rejects_text_that_is_not_json() {
        assert_eq!(
            decode("{version_info: 1}"),
            Err(DecodeError::Syntax {
                codec: LEGACY_V2_JSON,
                position: Some(TextPosition { line: 1, column: 2 })
            })
        );
    }

    #[test]
    fn rejects_truncated_json() {
        let json = vector_json(S1);
        let truncated = &json[..json.len() / 2];
        assert!(!codec().detect(&wire(truncated)));
        assert!(matches!(
            decode(truncated),
            Err(DecodeError::Syntax {
                position: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn rejects_bytes_that_are_not_utf8() {
        let mut bytes = vector_json(S1).into_bytes();
        bytes[1] = 0xff;
        let binary = WireSlate::binary(MediaType::JSON, bytes);
        assert!(!codec().detect(&binary));
        assert_eq!(
            codec().decode(&binary),
            Err(DecodeError::Syntax {
                codec: LEGACY_V2_JSON,
                position: None
            })
        );
    }

    #[test]
    fn rejects_input_above_the_size_limit() {
        let json = format!("{}{}", vector_json(S1), " ".repeat(MAX_WIRE_SLATE_LEN));
        assert!(!codec().detect(&wire(&json)));
        assert!(matches!(decode(&json), Err(DecodeError::TooLarge { .. })));
    }

    #[test]
    fn detects_only_a_json_object_without_the_ttl_key() {
        assert!(codec().detect(&wire(r#" {"version_info": {}}"#)));
        assert!(codec().detect(&wire(r#"{"nested": {"ttl_cutoff_height": 1}}"#)));
        assert!(!codec().detect(&wire(r#"{"ttl_cutoff_height": null}"#)));
        assert!(!codec().detect(&wire("[{}]")));
        assert!(!codec().detect(&wire("")));
    }

    #[test]
    fn binary_wire_slates_decode_like_text() {
        let json = vector_json(S3);
        let binary = WireSlate::binary(MediaType::OCTET_STREAM, json.clone().into_bytes());
        assert!(codec().detect(&binary));
        assert_eq!(codec().decode(&binary), decode(&json));
    }

    #[test]
    fn ignores_unknown_keys_as_upstream_does() {
        let slate = decode_mutated(S2, |value| value["extra"] = json!({"nested": [1, 2]})).unwrap();
        assert_eq!(encode(&slate), vector_json(S2));
    }
}

/// The base slates of the property tests, one per stage.
fn stage_slates() -> Vec<Slate> {
    [S1, S2, S3, I1, I2, I3]
        .iter()
        .map(|name| decode(&vector_json(name)).unwrap())
        .collect()
}

fn header_strategy() -> impl Strategy<Value = Option<LegacyHeader>> {
    prop::option::of((2u16..=3, any::<u16>(), any::<u16>()).prop_map(
        |(version, orig_version, block_header_version)| LegacyHeader {
            version,
            orig_version,
            block_header_version,
        },
    ))
}

/// A signature to attach to generated messages; the codec checks its form, not what it signs.
fn message_signature() -> lepic_crypto::Signature {
    let mut bytes = [0u8; 64];
    bytes[31] = 1;
    bytes[63] = 1;
    lepic_crypto::Signature::from_compact(&bytes).unwrap()
}

/// Rewrites the free-form parts of a stage slate; the result is still a valid V2 slate.
fn vary(
    base: &Slate,
    (amount, extra_fee, height, lock): (u64, u64, u64, u64),
    messages: [Option<String>; 2],
    header: Option<LegacyHeader>,
) -> Slate {
    let mut parts = base.clone().into_parts();
    parts.amount = Amount::new(amount);
    if parts.stage != Stage::I1 {
        parts.fee = Fee::new(parts.fee.value().saturating_add(extra_fee));
    }
    parts.height = Height::new(height);
    parts.lock = KernelLock::at_height(Height::new(lock));
    for (participant, message) in [&mut parts.sender, &mut parts.receiver]
        .into_iter()
        .zip(messages)
    {
        if let Some(participant) = participant {
            participant.message = message.map(|text| {
                ParticipantMessage::new(
                    ParticipantMessage::truncate(&text).to_owned(),
                    message_signature(),
                )
                .unwrap()
            });
        }
    }
    parts.origin = header.map(|header| WireOrigin::legacy(LEGACY_V2_JSON, header));
    Slate::from_parts(parts).unwrap()
}

proptest! {
    #[test]
    fn encoded_slates_decode_to_themselves(
        stage in 0usize..6,
        amount in any::<u64>(),
        extra_fee in 0u64..=u64::from(u32::MAX),
        height in any::<u64>(),
        lock in prop_oneof![Just(0u64), any::<u64>()],
        messages in [prop::option::of(".{0,300}"), prop::option::of(".{0,300}")],
        header in header_strategy(),
    ) {
        let slate = vary(
            &stage_slates()[stage], (amount, extra_fee, height, lock), messages, header,
        );
        let encoded = encode(&slate);
        let decoded = decode(&encoded).unwrap();
        // Every V2-shaped slate is written at version 2; the other two values are kept.
        let expected_header = LegacyHeader {
            version: 2,
            ..header.unwrap_or(LegacyHeader {
                version: 3,
                orig_version: 3,
                block_header_version: CONTEXT.block_header_version,
            })
        };
        prop_assert_eq!(
            &decoded,
            &slate.clone().with_origin(Some(WireOrigin::legacy(LEGACY_V2_JSON, expected_header)))
        );
        prop_assert_eq!(encode(&decoded), encoded);
    }

    #[test]
    fn decode_rejects_corrupted_slates_without_panicking(
        stage in 0usize..6,
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let names = [S1, S2, S3, I1, I2, I3];
        let mut bytes = vector_json(names[stage]).into_bytes();
        for (index, byte) in edits {
            let position = index.index(bytes.len());
            bytes[position] = byte;
        }
        let wire = WireSlate::binary(MediaType::JSON, bytes);
        let _ = codec().detect(&wire);
        if let Ok(slate) = codec().decode(&wire) {
            prop_assert_eq!(decode(&encode(&slate)).unwrap(), slate);
        }
    }
}

/// Indents compact JSON in key order, so a snapshot diff points at the field that changed.
fn pretty(json: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut chars = json.chars().peekable();
    let newline = |out: &mut String, depth: usize| {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    };
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '{' | '[' if matches!(chars.peek(), Some('}' | ']')) => {
                out.push(c);
                out.push(chars.next().unwrap());
            }
            '{' | '[' => {
                out.push(c);
                depth += 1;
                newline(&mut out, depth);
            }
            '}' | ']' => {
                depth -= 1;
                newline(&mut out, depth);
                out.push(c);
            }
            ',' => {
                out.push(c);
                newline(&mut out, depth);
            }
            ':' => out.push_str(": "),
            _ => out.push(c),
        }
    }
    out
}

#[test]
fn snapshot_of_each_stage() {
    let mut settings = insta::Settings::clone_current();
    // Kept beside this file so the V2 snapshots stay in the V2 test paths.
    settings.set_snapshot_path("v2_json_snapshots");
    settings.bind(|| {
        for (stage, name) in [
            ("s1", S1),
            ("s2", S2),
            ("s3", S3),
            ("i1", I1),
            ("i2", I2),
            ("i3", I3),
            ("s1_epicbox", EPICBOX_S1),
        ] {
            let slate = decode(&vector_json(name)).unwrap();
            insta::assert_snapshot!(stage, pretty(&encode(&slate)));
        }
    });
}
