// SPDX-License-Identifier: Apache-2.0
//! Replays the G-04 golden vectors in `testdata/vectors/epicbox`: address parse and display,
//! signatures over relay texts, and messages encrypted by `epic-wallet`.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_crypto::{EcdsaSignature, PublicKey, SecretKey};
use lepic_epicbox::{
    Domain, EncryptedMessage, EpicboxAddress, Network, Nonce, ReceivedMessage, Salt, SignedMessage,
    sign_text, verify_text,
};
use serde_json::Value;

const UPSTREAM_WALLET: &str = "845b3fcf4df12ed0139929c62157015447a9d063";

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/epicbox")
}

/// Every vector whose name starts with `prefix`, sorted by name.
fn vectors(prefix: &str) -> Vec<Value> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(vector_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "json")
                && path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with(prefix)
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no {prefix} vectors");
    paths
        .iter()
        .map(|path| {
            let vector: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let name = text(&vector["name"]);
            assert_eq!(vector["schema"], 1, "{name}: schema");
            assert_eq!(vector["area"], "epicbox", "{name}: area");
            assert_eq!(vector["upstream"]["commit"], UPSTREAM_WALLET, "{name}: pin");
            vector
        })
        .collect()
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, found {value}"))
}

fn network(value: &Value) -> Network {
    match text(value) {
        "mainnet" => Network::Mainnet,
        "floonet" => Network::Floonet,
        other => panic!("unknown network {other}"),
    }
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn every_vector_has_a_replay() {
    let names: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    for name in &names {
        assert!(
            ["address_", "signature_", "message_"]
                .iter()
                .any(|prefix| name.starts_with(prefix)),
            "{name} is not replayed"
        );
    }
    assert_eq!(names.len(), 40);
}

#[test]
fn addresses_parse_and_display_as_upstream() {
    let vectors = vectors("address_");
    assert_eq!(vectors.len(), 30);
    for vector in &vectors {
        let name = text(&vector["name"]);
        let inputs = &vector["inputs"];
        let expected = &vector["expected"];
        let parsed = EpicboxAddress::parse(text(&inputs["text"]), network(&inputs["network"]));

        if expected["accepted"] == false {
            assert!(parsed.is_err(), "{name}: accepted {parsed:?}");
            continue;
        }
        assert_eq!(expected["accepted"], true, "{name}: accepted flag");
        let address = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(address.key_text(), text(&expected["public_key"]), "{name}");
        assert_eq!(
            address.public_key().to_hex(),
            text(&expected["public_key_hex"]),
            "{name}"
        );
        assert_eq!(
            address.domain().as_str(),
            text(&expected["domain"]),
            "{name}"
        );
        assert_eq!(
            address.port(),
            expected["port"]
                .as_u64()
                .map(|port| u16::try_from(port).unwrap()),
            "{name}"
        );
        assert_eq!(address.to_string(), text(&expected["display"]), "{name}");
        assert_eq!(
            serde_json::to_string(&address).unwrap(),
            text(&expected["json"]),
            "{name}"
        );
        assert_eq!(
            EpicboxAddress::parse(&address.to_string(), address.network())
                .unwrap()
                .to_string(),
            address.to_string(),
            "{name}: display parses back"
        );
    }
}

#[test]
fn signatures_match_upstream() {
    let vectors = vectors("signature_");
    assert_eq!(vectors.len(), 5);
    for vector in &vectors {
        let name = text(&vector["name"]);
        let inputs = &vector["inputs"];
        let expected = &vector["expected"];
        let key = SecretKey::from_hex(text(&inputs["secret_key"])).unwrap();
        let public_key = PublicKey::from_secret_key(&key).unwrap();
        let signed = text(&inputs["text"]);
        assert_eq!(
            public_key.to_hex(),
            text(&expected["public_key_hex"]),
            "{name}"
        );

        let signature = sign_text(signed, &key).unwrap();
        assert_eq!(
            signature.to_der_hex(),
            text(&expected["signature"]),
            "{name}"
        );

        let upstream = EcdsaSignature::from_der_hex(text(&expected["signature"])).unwrap();
        assert_eq!(
            verify_text(signed, &upstream, &public_key),
            Ok(()),
            "{name}"
        );
        assert!(
            verify_text(&format!("{signed}x"), &upstream, &public_key).is_err(),
            "{name}: verified over another text"
        );
    }
}

#[test]
fn messages_match_upstream_in_both_directions() {
    let vectors = vectors("message_");
    assert_eq!(vectors.len(), 5);
    for vector in &vectors {
        let name = text(&vector["name"]);
        let inputs = &vector["inputs"];
        let expected = &vector["expected"];
        let network = network(&inputs["network"]);
        let plaintext = text(&inputs["plaintext"]);
        let sender_key = SecretKey::from_hex(text(&inputs["sender_secret_key"])).unwrap();
        let receiver_key = SecretKey::from_hex(text(&inputs["receiver_secret_key"])).unwrap();
        let sender_public = PublicKey::from_secret_key(&sender_key).unwrap();
        let receiver_public = PublicKey::from_secret_key(&receiver_key).unwrap();
        assert_eq!(
            sender_public.to_hex(),
            text(&expected["sender_public_key_hex"]),
            "{name}"
        );
        assert_eq!(
            receiver_public.to_hex(),
            text(&expected["receiver_public_key_hex"]),
            "{name}"
        );

        let from = EpicboxAddress::new(sender_public, network, Domain::default(), None);
        let to = EpicboxAddress::parse(text(&inputs["to"]), network).unwrap();
        assert_eq!(from.to_string(), text(&expected["from"]), "{name}");
        assert_eq!(to.to_string(), text(&expected["to"]), "{name}");
        assert_eq!(*to.public_key(), receiver_public, "{name}");

        // Given upstream's salt and nonce, LEPIC reproduces the exact posted text and signature.
        let salt = Salt::from(bytes::<8>(text(&expected["salt"])));
        let nonce = Nonce::from(bytes::<12>(text(&expected["nonce"])));
        let sealed = SignedMessage::seal(plaintext, &to, &sender_key, salt, nonce).unwrap();
        assert_eq!(sealed.str, text(&expected["str"]), "{name}: str");
        assert_eq!(
            sealed.signature.to_der_hex(),
            text(&expected["signature"]),
            "{name}: signature"
        );

        // LEPIC reads upstream's message field by field, and both sides derive upstream's key.
        let message = EncryptedMessage::from_json(text(&expected["str"])).unwrap();
        assert_eq!(
            hex(message.ciphertext()),
            text(&expected["encrypted_message"]),
            "{name}"
        );
        assert_eq!(*message.salt(), salt, "{name}");
        assert_eq!(*message.nonce(), nonce, "{name}");
        assert!(message.is_addressed_to(&to), "{name}");
        assert!(!message.is_addressed_to(&from), "{name}");
        for key in [
            message.key(&sender_public, &receiver_key).unwrap(),
            message.key(&receiver_public, &sender_key).unwrap(),
        ] {
            assert_eq!(
                hex(key.expose_bytes()),
                text(&expected["key"]),
                "{name}: key"
            );
        }
        assert_eq!(message.to_json().unwrap(), text(&expected["str"]), "{name}");

        // The receive path opens upstream's frame fields and returns the plaintext.
        let received = ReceivedMessage::open(
            text(&expected["from"]),
            text(&expected["str"]),
            text(&expected["signature"]),
            &to,
            &receiver_key,
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(received.plaintext.expose_str(), plaintext, "{name}");
        assert_eq!(received.sender, from, "{name}");
    }
}
