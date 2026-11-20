// SPDX-License-Identifier: Apache-2.0
//! Message sealing, opening and signatures, and the errors for each malformed part.
// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use lepic_crypto::{CryptoError, PublicKey, SecretKey};
use lepic_epicbox::{
    Domain, EncryptedMessage, EpicboxAddress, MAX_MESSAGE_LEN, MessageError, MessageField, Network,
    Nonce, ReceivedMessage, Salt, SignedMessage, sign_text,
};
use proptest::prelude::*;

const SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const NONCE: [u8; 12] = [9; 12];

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}

fn address(byte: u8) -> EpicboxAddress {
    EpicboxAddress::new(
        PublicKey::from_secret_key(&secret(byte)).unwrap(),
        Network::Mainnet,
        Domain::parse("relay.example.org").unwrap(),
        None,
    )
}

/// A message from key 1 to key 2.
fn signed(plaintext: &str) -> SignedMessage {
    SignedMessage::seal(
        plaintext,
        &address(2),
        &secret(1),
        Salt::from(SALT),
        Nonce::from(NONCE),
    )
    .unwrap()
}

fn open_as_receiver(from: &str, str: &str, signature: &str) -> Result<String, MessageError> {
    ReceivedMessage::open(from, str, signature, &address(2), &secret(2))
        .map(|received| received.plaintext.expose_str().to_owned())
}

fn message_json(ciphertext: &str, salt: &str, nonce: &str) -> String {
    format!(
        r#"{{"destination":{{"public_key":"{}","domain":"relay.example.org","port":null}},"encrypted_message":"{ciphertext}","salt":"{salt}","nonce":"{nonce}"}}"#,
        address(2).key_text()
    )
}

#[test]
fn opens_a_message_it_sealed() {
    let message = signed("slate");
    assert_eq!(
        open_as_receiver(
            &address(1).to_string(),
            &message.str,
            &message.signature.to_der_hex()
        )
        .unwrap(),
        "slate"
    );
}

#[test]
fn rejects_message_over_the_length_limit_before_parsing() {
    let text = "x".repeat(MAX_MESSAGE_LEN + 1);
    assert!(matches!(
        EncryptedMessage::from_json(&text),
        Err(MessageError::TooLong {
            max: MAX_MESSAGE_LEN,
            ..
        })
    ));
}

#[test]
fn rejects_text_that_is_not_the_message_json() {
    for text in ["", "pong", "{}", "[]", r#"{"destination":null}"#] {
        assert!(
            matches!(
                EncryptedMessage::from_json(text),
                Err(MessageError::Json(_))
            ),
            "{text:?}"
        );
    }
}

#[test]
fn rejects_message_without_a_destination_key() {
    let text = r#"{"destination":{"domain":"d","port":null},"encrypted_message":"00","salt":"00","nonce":"00"}"#;
    assert!(matches!(
        EncryptedMessage::from_json(text),
        Err(MessageError::Json(_))
    ));
}

#[test]
fn accepts_destination_without_a_port_key() {
    let text = r#"{"destination":{"public_key":"k","domain":"d"},"encrypted_message":"00000000000000000000000000000000","salt":"0000000000000000","nonce":"000000000000000000000000"}"#;
    let message = EncryptedMessage::from_json(text).unwrap();
    assert_eq!(message.destination().port(), None);
}

#[test]
fn rejects_ciphertext_that_is_not_hex() {
    let text = message_json(&"zz".repeat(16), "0102030405060708", &"09".repeat(12));
    assert!(matches!(
        EncryptedMessage::from_json(&text),
        Err(MessageError::InvalidHex {
            field: MessageField::EncryptedMessage
        })
    ));
    let odd = message_json(&"0".repeat(33), "0102030405060708", &"09".repeat(12));
    assert!(matches!(
        EncryptedMessage::from_json(&odd),
        Err(MessageError::InvalidHex {
            field: MessageField::EncryptedMessage
        })
    ));
}

#[test]
fn rejects_ciphertext_shorter_than_the_tag() {
    let text = message_json(&"00".repeat(15), "0102030405060708", &"09".repeat(12));
    assert!(matches!(
        EncryptedMessage::from_json(&text),
        Err(MessageError::CiphertextTooShort { actual: 15 })
    ));
}

#[test]
fn rejects_salt_of_the_wrong_length() {
    let text = message_json(&"00".repeat(16), "01020304050607", &"09".repeat(12));
    assert!(matches!(
        EncryptedMessage::from_json(&text),
        Err(MessageError::WrongLength {
            field: MessageField::Salt,
            expected: 8,
            actual: 7
        })
    ));
}

#[test]
fn rejects_nonce_of_the_wrong_length() {
    let text = message_json(&"00".repeat(16), "0102030405060708", &"09".repeat(13));
    assert!(matches!(
        EncryptedMessage::from_json(&text),
        Err(MessageError::WrongLength {
            field: MessageField::Nonce,
            expected: 12,
            actual: 13
        })
    ));
}

#[test]
fn rejects_salt_that_is_not_hex() {
    let text = message_json(&"00".repeat(16), "0x02030405060708", &"09".repeat(12));
    assert!(matches!(
        EncryptedMessage::from_json(&text),
        Err(MessageError::InvalidHex {
            field: MessageField::Salt
        })
    ));
}

#[test]
fn rejects_ciphertext_with_a_bad_tag() {
    let text = message_json(&"00".repeat(40), "0102030405060708", &"09".repeat(12));
    let message = EncryptedMessage::from_json(&text).unwrap();
    assert!(matches!(
        message.open(address(1).public_key(), &secret(2)),
        Err(MessageError::Decryption)
    ));
}

#[test]
fn rejects_sender_address_that_does_not_parse() {
    let message = signed("slate");
    let signature = message.signature.to_der_hex();
    assert!(matches!(
        open_as_receiver("not an address", &message.str, &signature),
        Err(MessageError::Sender(_))
    ));
}

#[test]
fn rejects_signature_that_is_not_der() {
    let message = signed("slate");
    for signature in ["", "zz", "3006020101020101ff", &"30".repeat(80)] {
        assert!(
            matches!(
                open_as_receiver(&address(1).to_string(), &message.str, signature),
                Err(MessageError::Signature(_))
            ),
            "{signature:?}"
        );
    }
}

#[test]
fn rejects_signature_by_another_key() {
    let message = signed("slate");
    let forged = sign_text(&message.str, &secret(3)).unwrap().to_der_hex();
    assert!(matches!(
        open_as_receiver(&address(1).to_string(), &message.str, &forged),
        Err(MessageError::Signature(CryptoError::SignatureMismatch))
    ));
}

#[test]
fn rejects_str_changed_after_signing() {
    let message = signed("slate");
    let changed = message
        .str
        .replacen("relay.example.org", "other.example.org", 1);
    assert_ne!(changed, message.str);
    assert!(matches!(
        open_as_receiver(
            &address(1).to_string(),
            &changed,
            &message.signature.to_der_hex()
        ),
        Err(MessageError::Signature(CryptoError::SignatureMismatch))
    ));
}

#[test]
fn rejects_message_addressed_to_another_key() {
    let message = SignedMessage::seal(
        "slate",
        &address(3),
        &secret(1),
        Salt::from(SALT),
        Nonce::from(NONCE),
    )
    .unwrap();
    assert!(matches!(
        open_as_receiver(
            &address(1).to_string(),
            &message.str,
            &message.signature.to_der_hex()
        ),
        Err(MessageError::NotAddressedToUs)
    ));
}

#[test]
fn rejects_sender_on_another_network() {
    let message = signed("slate");
    let floonet_sender = EpicboxAddress::new(
        *address(1).public_key(),
        Network::Floonet,
        Domain::parse("relay.example.org").unwrap(),
        None,
    );
    assert!(matches!(
        open_as_receiver(
            &floonet_sender.to_string(),
            &message.str,
            &message.signature.to_der_hex()
        ),
        Err(MessageError::Sender(_))
    ));
}

proptest! {
    #[test]
    fn seal_and_open_round_trip(
        plaintext in any::<String>(),
        salt in any::<[u8; 8]>(),
        nonce in any::<[u8; 12]>(),
    ) {
        let message = SignedMessage::seal(
            &plaintext,
            &address(2),
            &secret(1),
            Salt::from(salt),
            Nonce::from(nonce),
        )
        .unwrap();
        let parsed = EncryptedMessage::from_json(&message.str).unwrap();
        prop_assert_eq!(parsed.to_json().unwrap(), message.str.clone());
        let opened = open_as_receiver(
            &address(1).to_string(),
            &message.str,
            &message.signature.to_der_hex(),
        )
        .unwrap();
        prop_assert_eq!(opened, plaintext);
    }

    #[test]
    fn message_decoder_never_panics(text in any::<String>()) {
        let _ = EncryptedMessage::from_json(&text);
    }
}
