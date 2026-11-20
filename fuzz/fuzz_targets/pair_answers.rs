// SPDX-License-Identifier: Apache-2.0
//! The bodies of the pairing messages that answer one another (RFC 0002 7.3 and 7.8): a confirm
//! or refusal, a key check and its answers, and the proofs a found or restored answer carries,
//! checked against fixed cards. Every body that decodes encodes back to the same bytes.

#![no_main]

use lepic_contact::{
    Capabilities, CardFields, Confirm, ContactCard, ContactKind, ContactName, EncSecretKey,
    HintKey, KeyCheck, KeyCheckAnswer, MailboxAddress, Network, ReplyBody, SigningKey,
    accept_found, accept_restored,
};
use libfuzzer_sys::fuzz_target;

const NET: Network = Network::Floonet;

fn card(byte: u8, seq: u32) -> ContactCard {
    let signer = SigningKey::from_bytes(&[byte; 32]);
    let fields = CardFields {
        kind: ContactKind::Person,
        name: ContactName::new("Yan").expect("a plain name"),
        enc_key: EncSecretKey::from_bytes([byte; 32]).public_key(),
        sig_key: signer.verifying_key(),
        hint_key: HintKey::from_bytes([byte; 32]),
        mailbox: MailboxAddress::new("yan@relay.example:443").expect("a mailbox"),
        payments_address: None,
        home_onion: None,
        caps: Capabilities::OPENS_SEALED_FILES,
        max_envelope_version: 1,
        seq,
    };
    ContactCard::sign(NET, fields, &signer).expect("a fixed card signs")
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => {
            let _ = Confirm::decode(rest, NET);
            let _ = ReplyBody::decode(rest, NET);
        }
        1 => {
            if let Ok(check) = KeyCheck::decode(rest) {
                assert_eq!(&check.encode()[..], rest);
            }
        }
        _ => {
            let Ok(answer) = KeyCheckAnswer::decode(rest) else {
                return;
            };
            assert_eq!(answer.encode().as_deref(), Ok(rest));
            // The check and found envelopes the proofs cover: the input's own prefix, so a
            // proof can only verify if the fuzzer forged an Ed25519 signature.
            let answered = rest.get(..rest.len().min(64)).unwrap_or_default();
            let n_x = SigningKey::from_bytes(&[2; 32]).verifying_key();
            let n_y = SigningKey::from_bytes(&[3; 32]).verifying_key();
            assert!(accept_found(&answer, answered, &n_y, &n_x, &card(4, 3)).is_err());
            assert!(accept_restored(&answer, answered, &n_x, &n_y, NET).is_err());
        }
    }
});
