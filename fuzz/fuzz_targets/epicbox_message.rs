//! The encrypted Epicbox message (the `str` of `PostSlate` and `Slate` frames): parsing, key
//! derivation and decryption, without the signature check that guards it in the client.

#![no_main]

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::EncryptedMessage;
use libfuzzer_sys::fuzz_target;

/// The sender and receiver keys of the Epicbox message vectors, so seeded messages decrypt.
const SENDER_SECRET: [u8; 32] = [1; 32];
const RECEIVER_SECRET: [u8; 32] = [2; 32];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(message) = EncryptedMessage::from_json(text) else {
        return;
    };
    match message.to_json() {
        Ok(written) => assert_eq!(
            EncryptedMessage::from_json(&written).ok(),
            Some(message.clone())
        ),
        Err(error) => panic!("an accepted message does not write: {error}"),
    }
    let (Ok(sender_secret), Ok(receiver)) = (
        SecretKey::from_array(SENDER_SECRET),
        SecretKey::from_array(RECEIVER_SECRET),
    ) else {
        panic!("the vector keys are valid");
    };
    let Ok(sender) = PublicKey::from_secret_key(&sender_secret) else {
        panic!("a valid secret has a public key");
    };
    let _ = message.open(&sender, &receiver);
});
