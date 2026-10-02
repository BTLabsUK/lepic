//! Replays the G-01 golden vectors in `testdata/vectors/keys` that exercise this crate alone:
//! commitments, switch commitments, blinding and commitment sums, and bulletproofs. Key derivation
//! and proof builders are checked by `lepic-keychain`.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod aggsig;

use std::collections::HashMap;
use std::path::PathBuf;

use lepic_crypto::{
    Commitment, CommittedProof, CryptoError, ProofMessage, RangeProof, RewoundProof, SecretKey,
};
use serde_json::Value;

const UPSTREAM_NODE: &str = "9d022b1d521d3f705532e12ab77e0a429f6fde1f";

fn vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/keys")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let vector: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "keys", "{name}: area");
    assert_eq!(vector["upstream"]["commit"], UPSTREAM_NODE, "{name}: pin");
    vector
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, found {value}"))
}

fn amount(value: &Value) -> u64 {
    text(value).parse().unwrap()
}

fn secret(value: &Value) -> SecretKey {
    SecretKey::from_hex(text(value)).unwrap()
}

fn commitment(value: &Value) -> Commitment {
    Commitment::from_hex(text(value)).unwrap()
}

fn message(value: &Value) -> ProofMessage {
    let hex = text(value);
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    ProofMessage::from_bytes(&bytes).unwrap()
}

fn cases(vector: &Value) -> &[Value] {
    vector["expected"]["cases"].as_array().unwrap()
}

#[test]
fn commit_and_blind_switch_match_upstream() {
    let vector = vector("commit_raw");
    let cases = cases(&vector);
    assert_eq!(cases.len(), 24);
    for case in cases {
        let value = amount(&case["amount"]);
        let blind = secret(&case["blind"]);
        let context = format!("amount {value}, blind {}", text(&case["blind"]));

        assert_eq!(
            Commitment::commit(value, &blind).unwrap().to_hex(),
            text(&case["commit"]),
            "commit: {context}"
        );
        let switched = blind.blind_switch(value).unwrap();
        assert_eq!(
            switched.expose_bytes(),
            secret(&case["switched_blind"]).expose_bytes(),
            "blind_switch: {context}"
        );
        assert_eq!(
            Commitment::commit(value, &switched).unwrap().to_hex(),
            text(&case["switched_commit"]),
            "switched commit: {context}"
        );
    }
}

#[test]
fn blinding_and_commitment_sums_match_upstream() {
    let vector = vector("commit_sums");
    let inputs = &vector["inputs"];
    let expected = &vector["expected"];
    let list = |value: &Value| value.as_array().unwrap().clone();

    let positive: Vec<SecretKey> = list(&inputs["positive_blinds"])
        .iter()
        .map(secret)
        .collect();
    let negative: Vec<SecretKey> = list(&inputs["negative_blinds"])
        .iter()
        .map(secret)
        .collect();
    let amounts: Vec<u64> = list(&inputs["amounts"]).iter().map(amount).collect();

    let positive_commits: Vec<Commitment> = positive
        .iter()
        .zip(&amounts)
        .map(|(blind, value)| Commitment::commit(*value, blind).unwrap())
        .collect();
    let negative_commits: Vec<Commitment> = negative
        .iter()
        .map(|blind| Commitment::commit(0, blind).unwrap())
        .collect();
    let expected_positive: Vec<Commitment> = list(&expected["positive_commits"])
        .iter()
        .map(commitment)
        .collect();
    let expected_negative: Vec<Commitment> = list(&expected["negative_commits"])
        .iter()
        .map(commitment)
        .collect();
    assert_eq!(positive_commits, expected_positive);
    assert_eq!(negative_commits, expected_negative);

    assert_eq!(
        SecretKey::sum(&positive, &negative).unwrap().expose_bytes(),
        secret(&expected["blind_sum"]).expose_bytes()
    );
    assert_eq!(
        Commitment::sum(&positive_commits, &negative_commits).unwrap(),
        commitment(&expected["commit_sum"])
    );
}

#[test]
fn bulletproofs_match_upstream_and_rewind() {
    let vector = vector("bulletproof_raw");
    let inputs = &vector["inputs"];
    let blind = secret(&inputs["blind"]);
    let rewind_nonce = secret(&inputs["rewind_nonce"]);
    let private_nonce = secret(&inputs["private_nonce"]);
    let wrong_nonce = secret(&inputs["wrong_nonce"]);
    let proof_message = message(&inputs["message"]);

    // LEPIC does not expose bulletproof extra data: no node or wallet caller sets it. The cases
    // that use it are counted so that a regenerated file adding more of them is noticed.
    let (plain, with_extra_data): (Vec<&Value>, Vec<&Value>) = cases(&vector)
        .iter()
        .partition(|case| case["extra_data"].is_null());
    assert_eq!(plain.len(), 4);
    assert_eq!(with_extra_data.len(), 1);

    let mut verified = Vec::new();
    for case in plain {
        let value = amount(&case["amount"]);
        let committed = commitment(&case["commit"]);
        assert_eq!(
            Commitment::commit(value, &blind),
            Ok(committed),
            "amount {value}"
        );

        let proof =
            RangeProof::create(value, &blind, &rewind_nonce, &private_nonce, &proof_message)
                .unwrap();
        assert_eq!(
            proof.to_hex(),
            text(&case["proof"]),
            "proof bytes, amount {value}"
        );

        let upstream = RangeProof::from_hex(text(&case["proof"])).unwrap();
        assert_eq!(
            upstream.verify(&committed),
            Ok(()),
            "verify, amount {value}"
        );
        assert_eq!(
            upstream.rewind(&committed, &rewind_nonce),
            Ok(RewoundProof {
                value: amount(&case["rewind"]["value"]),
                message: message(&case["rewind"]["message"]),
            }),
            "rewind, amount {value}"
        );
        assert!(!case["wrong_nonce_error"].is_null());
        assert_eq!(
            upstream.rewind(&committed, &wrong_nonce).err(),
            Some(CryptoError::RangeProofRewindFailed),
            "wrong nonce, amount {value}"
        );
        verified.push((committed, upstream));
    }

    let batch: Vec<CommittedProof<'_>> = verified
        .iter()
        .map(|(commitment, proof)| CommittedProof { commitment, proof })
        .collect();
    assert_eq!(RangeProof::verify_batch(&batch), Ok(()));
}

/// Output blinding factors and commitments for one seed, keyed by identifier, amount and switch.
fn output_blinds(name: &str) -> HashMap<(String, String, String), (SecretKey, Commitment)> {
    let vector = vector(name);
    cases(&vector)
        .iter()
        .map(|case| {
            let key = (
                text(&case["identifier"]).to_owned(),
                text(&case["amount"]).to_owned(),
                text(&case["switch"]).to_owned(),
            );
            (key, (secret(&case["blind"]), commitment(&case["commit"])))
        })
        .collect()
}

#[test]
fn wallet_output_commitments_match_upstream() {
    for name in ["commitments_seed16", "commitments_seed32"] {
        let vector = vector(name);
        for case in cases(&vector) {
            let value = amount(&case["amount"]);
            assert_eq!(
                Commitment::commit(value, &secret(&case["blind"])),
                Ok(commitment(&case["commit"])),
                "{name}: {} amount {value} switch {}",
                text(&case["identifier"]),
                text(&case["switch"])
            );
        }
    }
}

// The proof builders' nonces and messages are K-02's to derive; given them, the proof bytes are
// this crate's, so both builders' outputs are replayed here with the recorded inputs.
#[test]
fn wallet_output_proofs_match_upstream() {
    let blinds = output_blinds("commitments_seed32");
    for name in ["proofs_builder_seed32", "proofs_legacy_builder_seed32"] {
        let vector = vector(name);
        assert_eq!(
            vector["inputs"]["seed"],
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        for case in cases(&vector) {
            let key = (
                text(&case["identifier"]).to_owned(),
                text(&case["amount"]).to_owned(),
                text(&case["switch"]).to_owned(),
            );
            let context = format!("{name}: {key:?}");
            let (blind, committed) = blinds
                .get(&key)
                .unwrap_or_else(|| panic!("{context}: no blinding factor"));
            assert_eq!(*committed, commitment(&case["commit"]), "{context}");

            let value = amount(&case["amount"]);
            let rewind_nonce = secret(&case["rewind_nonce"]);
            let proof_message = message(&case["message"]);
            let proof = RangeProof::create(
                value,
                blind,
                &rewind_nonce,
                &secret(&case["private_nonce"]),
                &proof_message,
            )
            .unwrap();
            assert_eq!(
                proof.to_hex(),
                text(&case["proof"]),
                "{context}: proof bytes"
            );
            assert_eq!(proof.verify(committed), Ok(()), "{context}: verify");
            assert_eq!(
                proof.rewind(committed, &rewind_nonce),
                Ok(RewoundProof {
                    value,
                    message: proof_message
                }),
                "{context}: rewind"
            );
        }
    }
}
