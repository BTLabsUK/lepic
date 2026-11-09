// SPDX-License-Identifier: Apache-2.0
//! The inner fields of an opened envelope: the TLV fields, the card in tag 07, the sender key and
//! the signature, read by both the RFC 0002 reader and the type 0A reader. `seal_open` reaches
//! them only through a valid AEAD tag, so this target feeds them to the decoders directly. The first byte picks the network and whether the target signs
//! the fuzzer's fields with a fixed key, so the checks after a valid signature see them too.

#![no_main]

use ed25519_dalek::Signer;
use lepic_seal::{
    DecodeError, EncSecretKey, HEADER_LEN, MAGIC, Malformed, Network, SigningKey, decode_content,
    decode_tx_content,
};
use libfuzzer_sys::fuzz_target;

const SIGNATURE_DOMAIN: &[u8] = b"epic-seal/1 sig";

fn field(tag: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("a key or signature fits a field");
    [&[tag][..], &length.to_be_bytes(), value].concat()
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, fields)) = data.split_first() else {
        return;
    };
    let network = if mode & 1 == 0 {
        Network::Mainnet
    } else {
        Network::Floonet
    };
    let [m0, m1, m2, m3] = MAGIC;
    let header: [u8; HEADER_LEN] = [
        m0,
        m1,
        m2,
        m3,
        1,
        u8::from(network == Network::Floonet),
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let recipient = EncSecretKey::from_bytes([11; 32]).public_key();
    let _ = decode_tx_content(fields, network, &header, &recipient);
    let anonymous = decode_content(fields, network, &header, &recipient);
    if mode & 2 == 0 {
        return;
    }
    let signer = SigningKey::from_bytes(&[1; 32]);
    let mut inner = [fields, &field(0x08, signer.verifying_key().as_bytes())].concat();
    let input = [SIGNATURE_DOMAIN, &header, recipient.as_bytes(), &inner].concat();
    inner.extend(field(0xff, &signer.sign(&input).to_bytes()));
    let signed = decode_content(&inner, network, &header, &recipient);
    // Only fields that end where the input ends are followed by the appended ones; otherwise the
    // input's last field swallows them.
    if !anonymous.is_ok_and(|opened| opened.sender.is_none()) {
        return;
    }
    match signed {
        Ok(opened) => assert_eq!(opened.sender, Some(signer.verifying_key())),
        // A card of another key, or fields from tag 08 up that the appended ones must follow.
        Err(DecodeError::Malformed(Malformed::FieldValue { tag: 0x07 })) => {}
        Err(DecodeError::Malformed(Malformed::FieldOrder { tag: 0x08 })) => {}
        Err(error) => panic!("signed fields that decode unsigned were refused: {error:?}"),
    }
});
