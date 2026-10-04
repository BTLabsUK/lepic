//! The V3 JSON codec beyond the vector replay: each decode rejection rule of
//! `docs/compat/legacy-slates.md`, height-locked kernels, round-trip properties and one snapshot
//! per stage.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_crypto::{CryptoError, RangeProof};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::params::{MAX_TX_WEIGHT, Network};
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec, carries_lepic_marker};
use lepic_slate::codec::{Codec, EncodeContext, MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use lepic_slate::error::{
    DecodeError, FieldProblem, HexError, ProofAddressError, SlateError, ValidationError,
};
use lepic_slate::model::{KernelLock, ParticipantMessage, Slate};
use lepic_slate::origin::{LegacyHeader, WireOrigin};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use proptest::prelude::*;
use serde_json::{Value, json};

const S1: &str = "send_file_ttl_payment_proof_messages_s1_v3";
const S2: &str = "send_file_ttl_payment_proof_messages_s2_v3";
const S3: &str = "send_file_ttl_payment_proof_messages_s3_v3";
const I1: &str = "invoice_file_messages_i1_v3";
const I2: &str = "invoice_file_messages_i2_v3";
const I3: &str = "invoice_file_messages_i3_v3";

const BASE_FEE: Fee = Network::Floonet.params().default_base_fee();

const CONTEXT: EncodeContext = EncodeContext {
    block_header_version: 6,
};

fn codec() -> V3JsonCodec {
    V3JsonCodec::new(BASE_FEE)
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

fn remove(parent: &'static str, key: &'static str) -> impl FnOnce(&mut Value) {
    move |value| {
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key)
            .unwrap();
    }
}

fn set_fee(fee: &'static str) -> impl FnOnce(&mut Value) {
    move |value| {
        value["fee"] = json!(fee);
        value["tx"]["body"]["kernels"][0]["fee"] = json!(fee);
    }
}

mod hex_and_curve_values {
    use super::*;

    #[test]
    fn rejects_offset_of_the_wrong_length() {
        assert_eq!(
            decode_mutated(S1, set("/tx/offset", json!("d2".repeat(31)))),
            field("tx.offset", hex_length(64, 62))
        );
    }

    #[test]
    fn rejects_input_commitment_that_is_not_hex() {
        let commit = format!("zz{}", "00".repeat(32));
        assert_eq!(
            decode_mutated(S1, set("/tx/body/inputs/0/commit", json!(commit))),
            field(
                "tx.body.inputs.commit",
                FieldProblem::Hex(HexError::InvalidDigit)
            )
        );
    }

    #[test]
    fn rejects_output_commitment_that_is_not_a_point() {
        let commit = format!("07{}", "11".repeat(32));
        assert_eq!(
            decode_mutated(S1, set("/tx/body/outputs/0/commit", json!(commit))),
            field(
                "tx.body.outputs.commit",
                FieldProblem::Crypto(CryptoError::InvalidCommitment)
            )
        );
    }

    #[test]
    fn rejects_range_proof_above_the_bulletproof_maximum() {
        let proof = "00".repeat(RangeProof::MAX_LEN + 1);
        assert_eq!(
            decode_mutated(S1, set("/tx/body/outputs/0/proof", json!(proof))),
            field(
                "tx.body.outputs.proof",
                FieldProblem::Hex(HexError::LengthOutOfRange {
                    min: 2,
                    max: RangeProof::MAX_LEN * 2,
                    actual: (RangeProof::MAX_LEN + 1) * 2,
                })
            )
        );
    }

    #[test]
    fn rejects_empty_range_proof() {
        assert!(matches!(
            decode_mutated(S1, set("/tx/body/outputs/0/proof", json!(""))),
            Err(DecodeError::Field {
                field: "tx.body.outputs.proof",
                problem: FieldProblem::Hex(HexError::LengthOutOfRange { actual: 0, .. }),
            })
        ));
    }

    #[test]
    fn rejects_public_blind_excess_that_is_not_a_point() {
        let key = format!("05{}", "11".repeat(32));
        assert_eq!(
            decode_mutated(
                S1,
                set("/participant_data/0/public_blind_excess", json!(key))
            ),
            field(
                "participant_data.public_blind_excess",
                FieldProblem::Crypto(CryptoError::InvalidPublicKey)
            )
        );
    }

    #[test]
    fn rejects_public_nonce_of_the_wrong_length() {
        let key = format!("02{}", "11".repeat(31));
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/public_nonce", json!(key))),
            field("participant_data.public_nonce", hex_length(66, 64))
        );
    }

    #[test]
    fn rejects_partial_signature_that_is_not_a_valid_compact_signature() {
        assert_eq!(
            decode_mutated(
                S2,
                set("/participant_data/1/part_sig", json!("ff".repeat(64)))
            ),
            field(
                "participant_data.part_sig",
                FieldProblem::Crypto(CryptoError::InvalidSignature)
            )
        );
    }

    #[test]
    fn rejects_message_signature_of_the_wrong_length() {
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/message_sig", json!("ab"))),
            field("participant_data.message_sig", hex_length(128, 2))
        );
    }

    #[test]
    fn rejects_kernel_excess_of_the_wrong_length() {
        assert_eq!(
            decode_mutated(S3, set("/tx/body/kernels/0/excess", json!("09"))),
            field("tx.body.kernels.excess", hex_length(66, 2))
        );
    }

    #[test]
    fn rejects_final_kernel_excess_that_is_not_a_point() {
        let excess = format!("07{}", "11".repeat(32));
        assert!(matches!(
            decode_mutated(S3, set("/tx/body/kernels/0/excess", json!(excess))),
            Err(DecodeError::Validation(
                ValidationError::InvalidKernelExcess(_)
            ))
        ));
    }

    #[test]
    fn rejects_payment_proof_address_that_is_not_hex() {
        let address = format!("zz{}", "00".repeat(31));
        assert_eq!(
            decode_mutated(S1, set("/payment_proof/sender_address", json!(address))),
            field(
                "payment_proof.sender_address",
                FieldProblem::Hex(HexError::InvalidDigit)
            )
        );
    }

    #[test]
    fn rejects_payment_proof_address_off_the_curve() {
        // y = 2 has no x on edwards25519.
        let address = format!("02{}", "00".repeat(31));
        assert_eq!(
            decode_mutated(S1, set("/payment_proof/receiver_address", json!(address))),
            field(
                "payment_proof.receiver_address",
                FieldProblem::ProofAddress(ProofAddressError)
            )
        );
    }

    #[test]
    fn rejects_payment_proof_signature_of_the_wrong_length() {
        assert_eq!(
            decode_mutated(
                S2,
                set("/payment_proof/receiver_signature", json!("00".repeat(63)))
            ),
            field("payment_proof.receiver_signature", hex_length(128, 126))
        );
    }

    #[test]
    fn rejects_slate_id_that_is_not_a_hyphenated_uuid() {
        assert!(matches!(
            decode_mutated(S1, set("/id", json!("0436430c2b02624c2032570501212b05"))),
            Err(DecodeError::Field {
                field: "id",
                problem: FieldProblem::SlateId(_),
            })
        ));
    }
}

mod participants {
    use super::*;

    #[test]
    fn rejects_zero_declared_participants() {
        assert_eq!(
            decode_mutated(S1, set("/num_participants", json!(0))),
            invalid(ValidationError::UnsupportedParticipantCount { declared: 0 })
        );
    }

    #[test]
    fn rejects_more_than_two_declared_participants() {
        assert_eq!(
            decode_mutated(S1, set("/num_participants", json!(3))),
            invalid(ValidationError::UnsupportedParticipantCount { declared: 3 })
        );
    }

    #[test]
    fn rejects_declared_participants_written_as_a_string() {
        assert_eq!(
            decode_mutated(S1, set("/num_participants", json!("2"))),
            field("num_participants", FieldProblem::WrongType)
        );
    }

    #[test]
    fn rejects_more_participants_than_declared() {
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
    }

    #[test]
    fn counts_participants_beyond_the_two_kept_without_parsing_them() {
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
    }

    #[test]
    fn reports_an_unsupported_declared_count_before_extra_participants() {
        assert_eq!(
            decode_mutated(S2, |value| {
                value["num_participants"] = json!(3);
                value["participant_data"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({}));
            }),
            invalid(ValidationError::UnsupportedParticipantCount { declared: 3 })
        );
    }

    #[test]
    fn rejects_participant_id_not_below_the_declared_count() {
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/id", json!("2"))),
            invalid(ValidationError::ParticipantIdOutOfRange { id: 2, declared: 2 })
        );
    }

    #[test]
    fn rejects_duplicate_participant_id() {
        assert_eq!(
            decode_mutated(S2, set("/participant_data/1/id", json!("0"))),
            invalid(ValidationError::DuplicateParticipantId { id: 0 })
        );
    }

    #[test]
    fn accepts_participant_id_written_as_a_number() {
        let slate = decode_mutated(S2, set("/participant_data/1/id", json!(1))).unwrap();
        assert_eq!(encode(&slate), vector_json(S2));
    }

    #[test]
    fn rejects_participants_that_match_no_stage() {
        let s2 = decode(&vector_json(S2)).unwrap();
        let receiver = s2.participant(Role::Receiver).unwrap();
        let signature = json!(receiver.partial_signature.unwrap().to_compact_hex());
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/part_sig", signature)),
            invalid(ValidationError::UnrecognisedStage)
        );
    }

    #[test]
    fn rejects_message_without_its_signature() {
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/message_sig", Value::Null)),
            field("participant_data.message_sig", FieldProblem::Missing)
        );
    }

    #[test]
    fn rejects_message_signature_without_a_message() {
        assert_eq!(
            decode_mutated(S1, set("/participant_data/0/message", Value::Null)),
            field("participant_data.message_sig", FieldProblem::Unexpected)
        );
    }

    #[test]
    fn rejects_message_longer_than_upstream_signs() {
        assert_eq!(
            decode_mutated(
                S1,
                set("/participant_data/0/message", json!("m".repeat(257)))
            ),
            model(SlateError::MessageTooLong { len: 257, max: 256 })
        );
    }

    #[test]
    fn reads_an_absent_message_key_as_no_message() {
        let slate = decode_mutated(I1, |value| {
            let data = value["participant_data"][0].as_object_mut().unwrap();
            data.remove("message");
            data.insert("message_sig".into(), Value::Null);
        })
        .unwrap();
        assert_eq!(slate.participant(Role::Receiver).unwrap().message, None);
    }

    #[test]
    fn rejects_payment_proof_in_the_invoice_flow() {
        let proof =
            serde_json::from_str::<Value>(&vector_json(S1)).unwrap()["payment_proof"].clone();
        assert_eq!(
            decode_mutated(I1, set("/payment_proof", proof)),
            model(SlateError::PaymentProofInInvoice)
        );
    }
}

mod kernel_and_fees {
    use super::*;

    #[test]
    fn rejects_slate_without_a_kernel() {
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels", json!([]))),
            invalid(ValidationError::KernelCount { count: 0 })
        );
    }

    #[test]
    fn rejects_slate_with_two_kernels() {
        assert_eq!(
            decode_mutated(S1, |value| {
                let kernel = value["tx"]["body"]["kernels"][0].clone();
                value["tx"]["body"]["kernels"]
                    .as_array_mut()
                    .unwrap()
                    .push(kernel);
            }),
            invalid(ValidationError::KernelCount { count: 2 })
        );
    }

    #[test]
    fn counts_kernels_beyond_the_one_kept_without_parsing_them() {
        assert_eq!(
            decode_mutated(S1, |value| {
                let kernels = value["tx"]["body"]["kernels"].as_array_mut().unwrap();
                kernels.extend([json!(7), json!("not a kernel"), json!([[]])]);
            }),
            invalid(ValidationError::KernelCount { count: 4 })
        );
    }

    #[test]
    fn rejects_outputs_above_the_transaction_weight_before_parsing_them() {
        let result = decode_mutated(S1, |value| {
            value["tx"]["body"]["outputs"] = Value::Array(vec![json!({}); 2_000]);
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
    fn rejects_kernel_fee_that_differs_from_the_slate_fee() {
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels/0/fee", json!("900000"))),
            invalid(ValidationError::KernelFeeMismatch {
                slate: Fee::new(800_000),
                kernel: Fee::new(900_000)
            })
        );
    }

    #[test]
    fn rejects_fee_below_the_minimum_for_the_final_weight() {
        // One input and one change output; the receiver's output makes the weight 8.
        assert_eq!(
            decode_mutated(S1, set_fee("799999")),
            invalid(ValidationError::FeeBelowMinimum {
                fee: Fee::new(799_999),
                minimum: Fee::new(800_000)
            })
        );
        assert_eq!(
            decode_mutated(S3, set_fee("799999")),
            invalid(ValidationError::FeeBelowMinimum {
                fee: Fee::new(799_999),
                minimum: Fee::new(800_000)
            })
        );
    }

    #[test]
    fn minimum_fee_follows_the_configured_base_fee() {
        let strict = V3JsonCodec::new(Fee::new(BASE_FEE.value() + 1));
        assert_eq!(
            strict.decode(&wire(&vector_json(S2))),
            invalid(ValidationError::FeeBelowMinimum {
                fee: Fee::new(800_000),
                minimum: Fee::new(800_008)
            })
        );
    }

    #[test]
    fn invoice_proposal_carries_no_fee() {
        assert_eq!(
            decode_mutated(I1, set_fee("800000")),
            model(SlateError::FeeBeforeSender {
                stage: Stage::I1,
                fee: Fee::new(800_000)
            })
        );
    }

    #[test]
    fn rejects_coinbase_kernel() {
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels/0/features", json!("Coinbase"))),
            invalid(ValidationError::CoinbaseKernel)
        );
    }

    #[test]
    fn rejects_unknown_kernel_features() {
        assert_eq!(
            decode_mutated(
                S1,
                set("/tx/body/kernels/0/features", json!("NoRecentDuplicate"))
            ),
            field("tx.body.kernels.features", FieldProblem::UnsupportedValue)
        );
    }

    #[test]
    fn rejects_plain_kernel_with_a_lock_height() {
        assert_eq!(
            decode_mutated(S1, set("/tx/body/kernels/0/lock_height", json!("5"))),
            invalid(ValidationError::KernelLockMismatch {
                slate: Height::ZERO,
                kernel: Height::new(5)
            })
        );
    }

    #[test]
    fn rejects_slate_lock_height_without_a_height_locked_kernel() {
        assert_eq!(
            decode_mutated(S1, set("/lock_height", json!("5"))),
            invalid(ValidationError::KernelLockMismatch {
                slate: Height::new(5),
                kernel: Height::ZERO
            })
        );
    }

    #[test]
    fn rejects_unknown_output_features() {
        assert_eq!(
            decode_mutated(S1, set("/tx/body/outputs/0/features", json!("Multisig"))),
            field("tx.body.outputs.features", FieldProblem::UnsupportedValue)
        );
    }

    #[test]
    fn rejects_placeholder_kernel_at_the_final_stage() {
        assert_eq!(
            decode_mutated(S3, |value| {
                let kernel = &mut value["tx"]["body"]["kernels"][0];
                kernel["excess"] = json!("00".repeat(33));
                kernel["excess_sig"] = json!("00".repeat(64));
            }),
            model(SlateError::MissingKernelExcess { stage: Stage::S3 })
        );
    }

    #[test]
    fn rejects_final_kernel_before_the_final_stage() {
        let final_kernel =
            serde_json::from_str::<Value>(&vector_json(S3)).unwrap()["tx"]["body"]["kernels"][0]
                .clone();
        assert_eq!(
            decode_mutated(S2, set("/tx/body/kernels/0", final_kernel)),
            model(SlateError::UnexpectedKernelExcess { stage: Stage::S2 })
        );
    }

    #[test]
    fn rejects_half_placeholder_kernel() {
        assert_eq!(
            decode_mutated(
                S3,
                set("/tx/body/kernels/0/excess_sig", json!("00".repeat(64)))
            ),
            invalid(ValidationError::PartialKernelPlaceholder)
        );
    }

    #[test]
    fn rejects_body_above_the_transaction_weight_before_parsing_it() {
        let result = decode_mutated(S1, |value| {
            // Inputs that are not even hex: the weight check must come first.
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

    /// epic-wallet v4.0.2 always creates lock height 0, so no vector has a height-locked kernel;
    /// upstream still reads and writes one with these keys.
    #[test]
    fn height_locked_kernel_round_trips() {
        let json = vector_json(S1)
            .replace("\"lock_height\":\"0\"", "\"lock_height\":\"40\"")
            .replace(
                "\"features\":\"Plain\",\"fee\"",
                "\"features\":\"HeightLocked\",\"fee\"",
            );
        let slate = decode(&json).unwrap();
        assert_eq!(slate.lock(), KernelLock::at_height(Height::new(40)));
        assert_eq!(
            slate.kernel_features(),
            KernelFeatures::HeightLocked {
                fee: Fee::new(800_000),
                lock_height: Height::new(40)
            }
        );
        assert_eq!(encode(&slate), json);
    }
}

mod values_and_shape {
    use super::*;

    #[test]
    fn rejects_header_version_other_than_two_or_three() {
        for version in [0, 1, 4] {
            assert_eq!(
                decode_mutated(S1, set("/version_info/version", json!(version))),
                Err(DecodeError::UnsupportedVersion {
                    codec: LEGACY_V3_JSON,
                    version
                })
            );
        }
    }

    #[test]
    fn rejects_header_version_written_as_a_string() {
        assert_eq!(
            decode_mutated(S1, set("/version_info/version", json!("3"))),
            field("version_info.version", FieldProblem::WrongType)
        );
    }

    #[test]
    fn rejects_header_value_above_u16() {
        assert_eq!(
            decode_mutated(S1, set("/version_info/block_header_version", json!(65_536))),
            field(
                "version_info.block_header_version",
                FieldProblem::IntegerOutOfRange
            )
        );
    }

    #[test]
    fn rejects_missing_required_keys() {
        assert_eq!(
            decode_mutated(S1, remove("", "amount")),
            field("amount", FieldProblem::Missing)
        );
        assert_eq!(
            decode_mutated(S1, remove("", "version_info")),
            field("version_info", FieldProblem::Missing)
        );
        assert_eq!(
            decode_mutated(S1, remove("/tx/body", "kernels")),
            field("tx.body.kernels", FieldProblem::Missing)
        );
        assert_eq!(
            decode_mutated(S2, remove("/participant_data/1", "part_sig")),
            field("participant_data.part_sig", FieldProblem::Missing)
        );
    }

    #[test]
    fn rejects_amounts_that_are_not_u64() {
        for amount in [
            json!(-1),
            json!(1.5),
            json!("18446744073709551616"),
            json!("ten"),
        ] {
            assert_eq!(
                decode_mutated(S1, set("/amount", amount.clone())),
                field("amount", FieldProblem::IntegerOutOfRange),
                "{amount}"
            );
        }
        assert_eq!(
            decode_mutated(S1, set("/amount", json!(true))),
            field("amount", FieldProblem::WrongType)
        );
    }

    #[test]
    fn accepts_integers_written_as_numbers_and_writes_them_as_strings() {
        let slate = decode_mutated(S1, |value| {
            value["amount"] = json!(150_000_000_u64);
            value["height"] = json!(4);
            value["ttl_cutoff_height"] = json!(34);
            value["tx"]["body"]["kernels"][0]["fee"] = json!(800_000);
        })
        .unwrap();
        assert_eq!(slate.amount(), Amount::new(150_000_000));
        assert_eq!(encode(&slate), vector_json(S1));
    }

    #[test]
    fn null_ttl_means_no_ttl() {
        let slate = decode_mutated(S1, set("/ttl_cutoff_height", Value::Null)).unwrap();
        assert_eq!(slate.ttl_cutoff_height(), None);
        assert!(encode(&slate).contains("\"ttl_cutoff_height\":null,"));
    }

    #[test]
    fn absent_payment_proof_key_means_no_payment_proof() {
        let slate = decode_mutated(I2, remove("", "payment_proof")).unwrap();
        assert_eq!(slate.payment_proof(), None);
        assert_eq!(encode(&slate), vector_json(I2));
    }

    #[test]
    fn slate_without_the_ttl_key_is_not_v3() {
        let mut value: Value = serde_json::from_str(&vector_json(S1)).unwrap();
        value.as_object_mut().unwrap().remove("ttl_cutoff_height");
        let json = serde_json::to_string(&value).unwrap();
        assert!(!codec().detect(&wire(&json)));
        assert_eq!(
            decode(&json),
            Err(DecodeError::NotRecognised {
                codec: LEGACY_V3_JSON
            })
        );
    }

    #[test]
    fn ignores_unknown_keys_as_upstream_does() {
        let slate = decode_mutated(S2, |value| {
            value["extra"] = json!({"nested": [1, 2]});
        })
        .unwrap();
        assert_eq!(encode(&slate), vector_json(S2));
    }

    #[test]
    fn rejects_text_that_is_not_json() {
        assert_eq!(
            decode("{ttl_cutoff_height: 1}"),
            Err(DecodeError::Syntax {
                codec: LEGACY_V3_JSON,
                position: Some(lepic_slate::error::TextPosition { line: 1, column: 2 })
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
                codec: LEGACY_V3_JSON,
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
    fn detects_only_a_json_object_with_the_ttl_key() {
        assert!(codec().detect(&wire(r#" {"ttl_cutoff_height": null}"#)));
        assert!(!codec().detect(&wire(r#"[{"ttl_cutoff_height": null}]"#)));
        assert!(!codec().detect(&wire(r#"{"nested": {"ttl_cutoff_height": 1}}"#)));
        assert!(!codec().detect(&wire("")));
    }

    #[test]
    fn binary_wire_slates_decode_like_text() {
        let json = vector_json(S3);
        let binary = WireSlate::binary(MediaType::OCTET_STREAM, json.clone().into_bytes());
        assert!(codec().detect(&binary));
        assert_eq!(codec().decode(&binary), decode(&json));
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

/// Rewrites the free-form parts of a stage slate; the result is still a valid slate.
#[allow(clippy::too_many_arguments)] // One argument per field the property varies.
fn vary(
    base: &Slate,
    amount: u64,
    extra_fee: u64,
    height: u64,
    lock: u64,
    ttl: Option<u64>,
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
    parts.ttl_cutoff_height = ttl.map(Height::new);
    for (participant, message) in [&mut parts.sender, &mut parts.receiver]
        .into_iter()
        .zip(messages)
    {
        if let Some(participant) = participant {
            let signature = message_signature();
            participant.message = message.map(|text| {
                ParticipantMessage::new(ParticipantMessage::truncate(&text).to_owned(), signature)
                    .unwrap()
            });
        }
    }
    parts.origin = header.map(|header| WireOrigin::legacy(LEGACY_V3_JSON, header));
    Slate::from_parts(parts).unwrap()
}

/// A signature to attach to generated messages; the codec checks its form, not what it signs.
fn message_signature() -> lepic_crypto::Signature {
    let mut bytes = [0u8; 64];
    bytes[31] = 1;
    bytes[63] = 1;
    lepic_crypto::Signature::from_compact(&bytes).unwrap()
}

proptest! {
    #[test]
    fn encoded_slates_decode_to_themselves(
        stage in 0usize..6,
        amount in any::<u64>(),
        extra_fee in 0u64..=u64::from(u32::MAX),
        height in any::<u64>(),
        lock in prop_oneof![Just(0u64), any::<u64>()],
        ttl in prop::option::of(any::<u64>()),
        messages in [prop::option::of(".{0,300}"), prop::option::of(".{0,300}")],
        header in header_strategy(),
    ) {
        let slate = vary(
            &stage_slates()[stage], amount, extra_fee, height, lock, ttl, messages, header,
        );
        let encoded = encode(&slate);
        let decoded = decode(&encoded).unwrap();
        let expected_header = header.unwrap_or(LegacyHeader {
            version: 3,
            orig_version: 3,
            block_header_version: CONTEXT.block_header_version,
        });
        prop_assert_eq!(
            &decoded,
            &slate.clone().with_origin(Some(WireOrigin::legacy(LEGACY_V3_JSON, expected_header)))
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

/// Indents compact JSON so a snapshot diff points at the field that changed.
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
    for (stage, name) in [
        ("s1", S1),
        ("s2", S2),
        ("s3", S3),
        ("i1", I1),
        ("i2", I2),
        ("i3", I3),
    ] {
        let slate = decode(&vector_json(name)).unwrap();
        insta::assert_snapshot!(stage, pretty(&encode(&slate)));
    }
}

mod lepic_marker {
    use super::*;

    fn marked(slate: &Slate) -> String {
        let encoded = codec().with_lepic_marker().encode(slate, &CONTEXT).unwrap();
        encoded.as_text().unwrap().to_owned()
    }

    #[test]
    fn a_marked_slate_ends_with_the_marker_and_is_otherwise_unchanged() {
        for name in [S1, I1, I2] {
            let slate = decode(&vector_json(name)).unwrap();
            let plain = encode(&slate);
            let marked = marked(&slate);
            let body = plain.strip_suffix('}').unwrap();
            assert_eq!(marked, format!("{body},\"lepic\":{{\"version\":1}}}}"));
        }
    }

    #[test]
    fn a_marked_slate_decodes_to_the_slate_it_was_written_from() {
        let slate = decode(&vector_json(I1)).unwrap();
        let decoded = decode(&marked(&slate)).unwrap();
        assert_eq!(decoded, slate);
    }

    #[test]
    fn the_codec_writes_no_marker_unless_asked() {
        let slate = decode(&vector_json(I1)).unwrap();
        assert!(!carries_lepic_marker(&wire(&encode(&slate))));
        assert!(carries_lepic_marker(&wire(&marked(&slate))));
    }

    #[test]
    fn only_a_marker_object_with_a_positive_version_counts() {
        let with = |marker: Value| {
            let mut value: Value = serde_json::from_str(&vector_json(I1)).unwrap();
            value["lepic"] = marker;
            carries_lepic_marker(&wire(&serde_json::to_string(&value).unwrap()))
        };
        assert!(with(json!({"version": 1})));
        assert!(with(json!({"version": 2, "other": true})));
        assert!(!with(json!({"version": 0})));
        assert!(!with(json!({"version": "1"})));
        assert!(!with(json!({})));
        assert!(!with(json!("lepic")));
        assert!(!with(Value::Null));
        assert!(!carries_lepic_marker(&wire("[1]")));
        assert!(!carries_lepic_marker(&WireSlate::binary(
            MediaType::JSON,
            vec![0xff]
        )));
    }
}
