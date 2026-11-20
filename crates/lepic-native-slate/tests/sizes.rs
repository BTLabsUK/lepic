// SPDX-License-Identifier: Apache-2.0
//! The slate sizes of EPICTX specification 5.10 and 5.18, and the size limits of the decoder.
//!
//! Slates come from the JSON views of the `slates_native` vectors, changed where the
//! specification's example differs from a flow slate: its answers carry the responder's input and
//! output only, where upstream's carry the sender's change as well.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_native_slate::{
    HEADER_LEN, INPUT_LEN, MAGIC, NativeError, NativeSlate, OUTPUT_LEN, SlateView,
};
use lepic_primitives::params::Network;
use lepic_slate::codec::MAX_WIRE_SLATE_LEN;
use serde_json::{Value, json};

/// The largest slate a QR code or a `u16`-framed transport carries.
const U16_FRAME: usize = 65_535;

fn vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/slates_native")
        .join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn view_of(name: &str) -> Value {
    vector(name)["expected"]["view"].clone()
}

fn size(name: &str) -> usize {
    usize::try_from(vector(name)["expected"]["size"].as_u64().unwrap()).unwrap()
}

/// The flags a view must name for what it carries.
fn set_flags(view: &mut Value) {
    let mut flags = Vec::new();
    if view.get("ttl_cutoff_height").is_some() {
        flags.push("ttl");
    }
    if view.get("payment_proof").is_some() {
        flags.push("proof");
    }
    for role in ["sender", "receiver"] {
        if view[role].get("message").is_some() {
            flags.push(if role == "sender" {
                "sender_message"
            } else {
                "receiver_message"
            });
        }
    }
    view["flags"] = json!(flags);
}

fn encode(mut view: Value) -> Vec<u8> {
    set_flags(&mut view);
    let view: SlateView = serde_json::from_value(view).unwrap();
    let (network, native) = view.into_native().unwrap();
    let bytes = native.encode(network);
    assert_eq!(NativeSlate::decode(network, &bytes).unwrap(), native);
    bytes
}

fn message(text: &str) -> Value {
    let signature =
        view_of("send_file_messages_s1_mainnet")["sender"]["message"]["signature"].clone();
    json!({ "text": text, "signature": signature })
}

/// An answer with only the responder's side of the body, as the specification counts it.
fn responder_body(name: &str, inputs: usize) -> Value {
    let mut view = view_of(name);
    let outputs = view["outputs"].as_array().unwrap();
    view["outputs"] = json!([outputs.last().unwrap()]);
    let spare = view_of("send_file_plain_input_s2_mainnet")["inputs"][0].clone();
    let own = view["inputs"].as_array().unwrap().first().cloned();
    view["inputs"] = json!(
        own.into_iter()
            .chain([spare])
            .take(inputs)
            .collect::<Vec<_>>()
    );
    view
}

#[test]
fn flow_slates_have_the_specified_sizes() {
    for (name, expected) in [
        ("send_file_plain_s1_mainnet", 153),
        ("send_file_messages_s1_mainnet", 247),
        ("send_file_ttl_s1_mainnet", 161),
        ("send_file_payment_proof_s1_mainnet", 217),
        ("send_file_plain_s3_mainnet", 1_896),
        ("send_file_three_change_outputs_s3_mainnet", 3_314),
        ("tail_reply_key_send_file_ttl_s1_mainnet", 196),
        ("tail_reply_mailbox_send_file_ttl_s1_mainnet", 252),
    ] {
        assert_eq!(size(name), expected, "{name}");
    }
}

#[test]
fn answers_with_the_responder_body_have_the_specified_sizes() {
    assert_eq!(
        encode(responder_body("send_file_plain_s2_mainnet", 0)).len(),
        992
    );
    assert_eq!(
        encode(responder_body("send_file_payment_proof_s2_mainnet", 0)).len(),
        1_120
    );
    assert_eq!(
        encode(responder_body("invoice_file_plain_i2_mainnet", 1)).len(),
        1_026
    );
}

#[test]
fn the_largest_proposal_is_555_bytes() {
    let mut view = view_of("send_file_long_messages_s1_mainnet");
    assert_eq!(
        view["sender"]["message"]["text"].as_str().unwrap().len(),
        256
    );
    view["kernel_features"] = json!("height_locked");
    view["lock_height"] = json!("5");
    view["ttl_cutoff_height"] = json!("34");
    view["payment_proof"] = view_of("send_file_payment_proof_s1_mainnet")["payment_proof"].clone();
    assert_eq!(encode(view).len(), 555);
}

#[test]
fn reply_records_with_a_message_have_the_specified_sizes() {
    let base = view_of("tail_reply_mailbox_send_file_ttl_s1_mainnet");
    for (text, expected) in [("x".repeat(6), 324), ("x".repeat(256), 574)] {
        let mut view = base.clone();
        view["sender"]["message"] = message(&text);
        assert_eq!(encode(view).len(), expected, "{} characters", text.len());
    }
}

/// Specification 5.10: an I2 of 1,898 inputs fits a `u16` frame and one of 1,899 does not.
#[test]
fn an_answer_fits_a_u16_frame_up_to_1898_inputs() {
    let one = encode(responder_body("invoice_file_plain_i2_mainnet", 1)).len();
    let two = encode(responder_body("invoice_file_plain_i2_mainnet", 2)).len();
    assert_eq!(two - one, INPUT_LEN);
    assert_eq!(INPUT_LEN, 34);
    assert_eq!(OUTPUT_LEN, 709);
    let with = |inputs: usize| one + (inputs - 1) * INPUT_LEN;
    assert_eq!(with(1_898), 65_524);
    assert!(with(1_898) <= U16_FRAME);
    assert!(with(1_899) > U16_FRAME);
}

#[test]
fn input_over_the_wire_limit_is_refused_before_it_is_read() {
    let mut bytes = MAGIC.to_vec();
    bytes.resize(MAX_WIRE_SLATE_LEN + 1, 0);
    assert_eq!(
        NativeSlate::decode(Network::Mainnet, &bytes),
        Err(NativeError::TooLarge {
            len: MAX_WIRE_SLATE_LEN + 1,
            max: MAX_WIRE_SLATE_LEN
        })
    );
}

#[test]
fn a_body_over_the_transaction_weight_is_refused() {
    let name = "send_file_plain_s2_mainnet";
    let bytes = hex(vector(name)["expected"]["lepic_v1"].as_str().unwrap());
    let view = view_of(name);
    let inputs = view["inputs"].as_array().unwrap().len();
    let outputs = view["outputs"].as_array().unwrap().len();
    let inputs_at = bytes.len() - (2 + inputs * INPUT_LEN + 2 + outputs * OUTPUT_LEN);
    assert!(inputs_at > HEADER_LEN);

    let mut heavy = bytes[..inputs_at].to_vec();
    let count: u16 = 40_000;
    heavy.extend_from_slice(&count.to_be_bytes());
    heavy.resize(heavy.len() + usize::from(count) * INPUT_LEN, 0);
    heavy.extend_from_slice(&0u16.to_be_bytes());
    assert!(matches!(
        NativeSlate::decode(Network::Mainnet, &heavy),
        Err(NativeError::TooHeavy { .. })
    ));
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}
