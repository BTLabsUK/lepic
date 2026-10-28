// SPDX-License-Identifier: Apache-2.0
//! Replays the G-02 golden vectors in `testdata/vectors/aggsig`. Kernel message hashing and kernel
//! serialization in those files belong to `lepic-primitives`; here the message is an input.

use std::path::PathBuf;

use lepic_crypto::aggsig::{
    add_signatures, calculate_partial_sig, sign_single, verify_completed_sig, verify_partial_sig,
    verify_single_from_commit,
};
use lepic_crypto::{Commitment, CryptoError, Message, PublicKey, SecretKey, Signature};
use serde_json::Value;

const UPSTREAM_NODE: &str = "82fa7e813dc3b9bf137b9dd523d847f4210f5ba4";

fn vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/aggsig")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let vector: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "aggsig", "{name}: area");
    assert_eq!(vector["name"], name, "{name}: name");
    assert_eq!(vector["upstream"]["commit"], UPSTREAM_NODE, "{name}: pin");
    vector
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, found {value}"))
}

fn secret(value: &Value) -> SecretKey {
    SecretKey::from_hex(text(value)).unwrap()
}

fn public(value: &Value) -> PublicKey {
    PublicKey::from_hex(text(value)).unwrap()
}

fn optional_public(value: &Value) -> Option<PublicKey> {
    (!value.is_null()).then(|| public(value))
}

fn signature(value: &Value) -> Signature {
    Signature::from_compact_hex(text(value)).unwrap()
}

fn message(value: &Value) -> Message {
    Message::from_hex(text(value)).unwrap()
}

fn public_of(key: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(key).unwrap()
}

fn verdict(result: Result<(), CryptoError>, name: &str) -> bool {
    match result {
        Ok(()) => true,
        Err(CryptoError::SignatureMismatch) => false,
        Err(other) => panic!("{name}: unexpected error {other:?}"),
    }
}

/// Replays `expected.checks`, each an upstream `verify_single` call and its result.
fn replay_checks(vector: &Value, expected_count: usize) {
    let checks = vector["expected"]["checks"].as_array().unwrap();
    assert_eq!(checks.len(), expected_count);
    for check in checks {
        let name = text(&check["name"]);
        let sig = signature(&check["sig"]);
        let msg = message(&check["msg"]);
        let pubkey = public(&check["pubkey"]);
        let pubkey_sum = optional_public(&check["pubkey_sum"]);
        let nonce_sum = optional_public(&check["pub_nonce_sum"]);
        let result = match (text(&check["kind"]), nonce_sum) {
            ("partial", Some(nonce_sum)) => {
                verify_partial_sig(&sig, &nonce_sum, &pubkey, pubkey_sum.as_ref(), &msg)
            }
            ("completed", None) => verify_completed_sig(&sig, &pubkey, pubkey_sum.as_ref(), &msg),
            (kind, nonce_sum) => panic!("{name}: no upstream call is {kind} with {nonce_sum:?}"),
        };
        assert_eq!(
            verdict(result, name),
            check["valid"].as_bool().unwrap(),
            "{name}"
        );
    }
}

#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn replay_two_party(name: &str) {
    let vector = vector(name);
    let inputs = &vector["inputs"];
    let expected = &vector["expected"];
    let msg = message(&expected["sig_msg"]);

    let sender_excess = SecretKey::sum(
        &[secret(&inputs["sender_excess"])],
        &[secret(&inputs["offset"])],
    )
    .unwrap();
    let sender_nonce = secret(&inputs["sender_nonce"]);
    let receiver_excess = secret(&inputs["receiver_excess"]);
    let receiver_nonce = secret(&inputs["receiver_nonce"]);
    assert_eq!(
        sender_excess.expose_bytes(),
        secret(&expected["sender_excess_split"]).expose_bytes(),
        "{name}: sender_excess_split"
    );

    let public_pairs = [
        (&sender_excess, "sender_public_excess"),
        (&sender_nonce, "sender_public_nonce"),
        (&receiver_excess, "receiver_public_excess"),
        (&receiver_nonce, "receiver_public_nonce"),
    ];
    for (key, field) in public_pairs {
        assert_eq!(public_of(key), public(&expected[field]), "{name}: {field}");
    }

    let nonce_sum =
        public_of(&SecretKey::sum(&[sender_nonce.clone(), receiver_nonce.clone()], &[]).unwrap());
    let excess_sum =
        SecretKey::sum(&[sender_excess.clone(), receiver_excess.clone()], &[]).unwrap();
    let public_excess_sum = public_of(&excess_sum);
    assert_eq!(
        nonce_sum,
        public(&expected["public_nonce_sum"]),
        "{name}: public_nonce_sum"
    );
    assert_eq!(
        public_excess_sum,
        public(&expected["public_excess_sum"]),
        "{name}: public_excess_sum"
    );

    let receiver_partial = calculate_partial_sig(
        &receiver_excess,
        &receiver_nonce,
        &nonce_sum,
        Some(&public_excess_sum),
        &msg,
    )
    .unwrap();
    assert_eq!(
        receiver_partial,
        signature(&expected["receiver_partial_sig"]),
        "{name}: receiver_partial_sig"
    );
    assert_eq!(
        verify_partial_sig(
            &receiver_partial,
            &nonce_sum,
            &public_of(&receiver_excess),
            Some(&public_excess_sum),
            &msg
        ),
        Ok(())
    );

    let sender_partial = calculate_partial_sig(
        &sender_excess,
        &sender_nonce,
        &nonce_sum,
        Some(&public_excess_sum),
        &msg,
    )
    .unwrap();
    assert_eq!(
        sender_partial,
        signature(&expected["sender_partial_sig"]),
        "{name}: sender_partial_sig"
    );

    let final_sig = add_signatures(&[sender_partial, receiver_partial], &nonce_sum).unwrap();
    assert_eq!(
        final_sig,
        signature(&expected["final_sig"]),
        "{name}: final_sig"
    );
    assert_eq!(
        final_sig.to_compact_hex(),
        text(&expected["final_sig"]),
        "{name}: final_sig hex"
    );
    assert_eq!(
        verify_completed_sig(
            &final_sig,
            &public_excess_sum,
            Some(&public_excess_sum),
            &msg
        ),
        Ok(())
    );

    let kernel_excess = Commitment::commit(0, &excess_sum).unwrap();
    assert_eq!(
        kernel_excess.to_hex(),
        text(&expected["kernel_excess"]),
        "{name}: kernel_excess"
    );

    replay_checks(&vector, 11);

    let commit_checks = expected["commit_checks"].as_array().unwrap();
    assert_eq!(commit_checks.len(), 3);
    for check in commit_checks {
        let check_name = text(&check["name"]);
        let result = verify_single_from_commit(
            &signature(&check["sig"]),
            &message(&check["msg"]),
            &Commitment::from_hex(text(&check["commit"])).unwrap(),
        );
        assert_eq!(
            verdict(result, check_name),
            check["valid"].as_bool().unwrap(),
            "{name}: {check_name}"
        );
    }
}

fn replay_single_signer(name: &str, pubkey_in_challenge: bool) {
    let vector = vector(name);
    let inputs = &vector["inputs"];
    let expected = &vector["expected"];
    assert_eq!(inputs["pubkey_for_e"].as_bool(), Some(pubkey_in_challenge));

    let key = secret(&inputs["key"]);
    let pubkey = public_of(&key);
    assert_eq!(pubkey, public(&expected["pubkey"]), "{name}: pubkey");
    let challenge_key = pubkey_in_challenge.then_some(&pubkey);

    let msg = message(&expected["msg"]);
    let sig = sign_single(&msg, &key, &secret(&inputs["nonce"]), challenge_key).unwrap();
    assert_eq!(sig.to_compact_hex(), text(&expected["sig"]), "{name}: sig");
    assert_eq!(
        verify_completed_sig(&sig, &pubkey, challenge_key, &msg),
        Ok(())
    );

    replay_checks(&vector, 4);
}

#[test]
fn two_party_plain_kernel_signature_matches_upstream() {
    replay_two_party("two_party_plain");
}

#[test]
fn two_party_height_locked_kernel_signature_matches_upstream() {
    replay_two_party("two_party_height_locked");
}

#[test]
fn single_signer_message_signature_matches_upstream() {
    replay_single_signer("single_signer_message", true);
}

#[test]
fn single_signer_signature_without_pubkey_in_challenge_matches_upstream() {
    replay_single_signer("single_signer_without_pubkey_in_challenge", false);
}

// LEPIC's `verify_completed_sig` follows the node's kernel rule, not upstream's function of that
// name, so it must agree with `kernel` on every case, including the ones `completed` accepts.
#[test]
fn completed_signature_check_follows_the_kernel_rule_upstream_records() {
    let name = "completed_and_kernel_rules";
    let vector = vector(name);
    let inputs = &vector["inputs"];
    let expected = &vector["expected"];
    let key = secret(&inputs["key"]);
    let pubkey = public_of(&key);
    assert_eq!(pubkey, public(&expected["pubkey"]), "{name}: pubkey");
    assert_eq!(
        public_of(&secret(&inputs["nonce"])),
        public(&expected["public_nonce"]),
        "{name}: public_nonce"
    );
    let commit = Commitment::commit(0, &key).unwrap();
    assert_eq!(commit.to_hex(), text(&expected["commit"]), "{name}: commit");

    let cases = expected["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let mut separating = 0;
    for case in cases {
        let case_name = text(&case["name"]);
        let context = format!("{name}: {case_name}");
        let sig = signature(&case["sig"]);
        let case_msg = message(&case["msg"]);
        let verdict_of = |result| verdict(result, &context);
        let kernel = case["kernel"].as_bool().unwrap();
        assert_eq!(
            verdict_of(verify_partial_sig(
                &sig,
                &public(&case["nonce_sum"]),
                &pubkey,
                Some(&pubkey),
                &case_msg
            )),
            case["partial"].as_bool().unwrap(),
            "{context}: partial"
        );
        assert_eq!(
            verdict_of(verify_completed_sig(
                &sig,
                &pubkey,
                Some(&pubkey),
                &case_msg
            )),
            kernel,
            "{context}: completed"
        );
        assert_eq!(
            verdict_of(verify_single_from_commit(&sig, &case_msg, &commit)),
            kernel,
            "{context}: kernel"
        );
        if case["completed"].as_bool().unwrap() != kernel {
            separating += 1;
        }
    }
    assert_eq!(
        separating, 2,
        "{name}: cases upstream's two checks disagree on"
    );
}
