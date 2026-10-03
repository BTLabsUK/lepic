//! Receive logs in their own binary, for the reason `lifecycle_logs.rs` gives.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod support;

use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
use lepic_primitives::params::Network;
use lepic_telemetry::{assert_no_secrets, capture};
use receive_harness::*;

#[test]
fn receive_runs_in_its_span_and_never_logs_keys_or_nonces() {
    let case = "send_file_ttl_payment_proof_messages";
    let (s1, transport) = delivered_s1(case);
    let s2 = vector(&format!("{case}_s2_v3"));
    let mnemonic = receiver_mnemonic(&s2);
    let receiver = Receiver::new(&mnemonic, slate_height(&s1));
    let key_id = receiver_output_key(&s2);
    receiver.reserve_up_to(key_id);

    let (received, captured) = capture(|| {
        receiver
            .receive(transport, &json(&s1), responder_message(&s2).as_deref())
            .unwrap()
    });

    let keychain = Keychain::from_seed(&receiver.seed, Network::Floonet).unwrap();
    let amount = received.slate.amount().value();
    let blinding = keychain
        .derive_key(amount, &key_id, SwitchCommitment::Regular)
        .unwrap();
    let parent = Identifier::new(2, [0, 0, 0, 0]).unwrap();
    let address_key = keychain.address_key(&parent, 0).unwrap();
    let words: Vec<&str> = mnemonic.split(' ').collect();
    let pairs: Vec<String> = words.windows(2).map(|pair| pair.join(" ")).collect();
    let mut secrets: Vec<&[u8]> = vec![
        receiver.seed.expose_bytes(),
        blinding.expose_bytes(),
        address_key.expose_bytes(),
        // The secret nonce the repeating RNG produces.
        &[1; 32],
    ];
    secrets.extend(pairs.iter().map(String::as_bytes));
    assert_no_secrets(&captured.records, &secrets).unwrap();

    let slate_id = received.slate.id().to_string();
    let record = captured
        .records
        .iter()
        .find(|record| record.message == "slate received")
        .unwrap_or_else(|| panic!("no \"slate received\": {:?}", captured.records));
    assert!(record.spans.contains(&"receive"), "{record}");
    assert_eq!(
        record.field("slate_id"),
        Some(slate_id.as_str()),
        "{record}"
    );
    assert_eq!(record.field("transport"), Some("file"), "{record}");
    assert_eq!(record.field("stage"), Some("S1"), "{record}");
    assert_eq!(record.field("wallet"), Some("receiver"), "{record}");
}
