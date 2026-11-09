// SPDX-License-Identifier: Apache-2.0
//! Type 0A envelopes (RFC 0003 5): the body limit with padding, the key classes, the reply
//! mailbox rules and the EPICTX armor.

// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::ScriptedRng;
use lepic_seal::{
    ArmorMarker, Content, DecodeError, EncPublicKey, EncSecretKey, EncodeError, HEADER_LEN,
    HintKey, HintRule, KeyClass, MAX_BODY_LEN, Malformed, MessageType, Network, PADDING_FLOOR,
    ReplyMailbox, SealedEnvelope, SigningKey, TxContent, TxKey, armor, armor_tx, dearmor_marked,
    pad_target, seal, seal_tx,
};

const NET: Network = Network::Floonet;
/// The 32-byte enc and the 16-byte AEAD tag around the inner fields.
const OVERHEAD: usize = HEADER_LEN + 32 + 16;

fn recipient() -> EncSecretKey {
    EncSecretKey::from_bytes([7; 32])
}

fn reply_key() -> EncPublicKey {
    EncSecretKey::from_bytes([9; 32]).public_key()
}

fn content(len: usize) -> TxContent {
    let mut content = TxContent::new(vec![0x5a; len]);
    content.reply_key = Some(reply_key());
    content
}

fn seal_listener(content: &TxContent) -> Result<Vec<u8>, EncodeError> {
    seal_tx(
        NET,
        &recipient().public_key(),
        TxKey::Listener,
        content,
        None,
        &mut ScriptedRng::seeded(3),
    )
}

#[test]
fn a_body_of_the_limit_seals_padded_and_opens() {
    let envelope = seal_listener(&content(MAX_BODY_LEN)).unwrap();
    // Type 01 field (4), body (3 + 65,535), reply key (35) and the padding header (3).
    let unpadded = 4 + 3 + MAX_BODY_LEN + 35 + 3;
    assert_eq!(envelope.len(), pad_target(unpadded) + OVERHEAD);
    assert_eq!(envelope.len(), 67_648);
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    let opened = sealed.open_tx(&recipient(), KeyClass::Listener).unwrap();
    assert_eq!(opened.content.body.len(), MAX_BODY_LEN);
    assert_eq!(opened.padding, Some(pad_target(unpadded) - unpadded));
    assert_eq!(opened.inner_len, pad_target(unpadded));
}

#[test]
fn a_body_over_the_limit_is_refused_with_both_sizes() {
    assert_eq!(
        seal_listener(&content(MAX_BODY_LEN + 1)),
        Err(EncodeError::BodyTooLarge {
            limit: MAX_BODY_LEN,
            found: MAX_BODY_LEN + 1
        })
    );
    let slate = Content::new(MessageType::Slate, vec![b'x'; MAX_BODY_LEN + 1]);
    assert_eq!(
        seal(
            NET,
            &recipient().public_key(),
            HintRule::ReplyKey,
            &slate,
            None,
            &mut ScriptedRng::seeded(1)
        ),
        Err(EncodeError::BodyTooLarge {
            limit: MAX_BODY_LEN,
            found: MAX_BODY_LEN + 1
        })
    );
}

/// Near the limit the padding grows the inner fields past 65,535 bytes; the padding is a field
/// of its own, so only the body counts against the limit.
#[test]
fn padding_near_the_limit_never_refuses_a_body_within_it() {
    let signer = SigningKey::from_bytes(&[4; 32]);
    let hint = HintKey::from_bytes([5; 32]);
    for len in [MAX_BODY_LEN - 2_000, MAX_BODY_LEN - 64, MAX_BODY_LEN - 1] {
        let mut content = TxContent::new(vec![1; len]);
        content.sent_at = Some(1_700_000_000);
        let envelope = seal_tx(
            NET,
            &recipient().public_key(),
            TxKey::Seal(HintRule::Contact(&hint)),
            &content,
            Some(&signer),
            &mut ScriptedRng::seeded(2),
        )
        .unwrap();
        let unpadded = 4 + 3 + len + 35 + 11 + 3 + 67;
        assert!(pad_target(unpadded) > MAX_BODY_LEN);
        assert_eq!(envelope.len(), pad_target(unpadded) + OVERHEAD, "{len}");
        let opened = SealedEnvelope::decode(&envelope, NET)
            .unwrap()
            .open_tx(&recipient(), KeyClass::Seal)
            .unwrap();
        assert_eq!(opened.content.body.len(), len);
        assert_eq!(opened.sender, Some(signer.verifying_key()));
    }
}

#[test]
fn small_slates_pad_to_the_floor_and_open_with_the_rfc_0002_reader() {
    let slate = Content::new(MessageType::Slate, b"{}".to_vec());
    let envelope = seal(
        NET,
        &recipient().public_key(),
        HintRule::ReplyKey,
        &slate,
        None,
        &mut ScriptedRng::seeded(1),
    )
    .unwrap();
    assert_eq!(envelope.len(), PADDING_FLOOR + OVERHEAD);
    let opened = SealedEnvelope::decode(&envelope, NET)
        .unwrap()
        .open(&recipient())
        .unwrap();
    assert_eq!(opened.content.body, b"{}");

    // Other types are not padded.
    let notice = Content::new(MessageType::Notice, b"{}".to_vec());
    let envelope = seal(
        NET,
        &recipient().public_key(),
        HintRule::ReplyKey,
        &notice,
        None,
        &mut ScriptedRng::seeded(1),
    )
    .unwrap();
    assert!(envelope.len() < PADDING_FLOOR);
}

#[test]
fn each_key_class_opens_only_its_own_envelopes() {
    let hint = HintKey::from_bytes([5; 32]);
    let keys = [
        (TxKey::Seal(HintRule::Contact(&hint)), KeyClass::Seal),
        (TxKey::Epic1, KeyClass::Epic1),
        (TxKey::Listener, KeyClass::Listener),
    ];
    for (key, class) in keys {
        let envelope = seal_tx(
            NET,
            &recipient().public_key(),
            key,
            &content(10),
            None,
            &mut ScriptedRng::seeded(6),
        )
        .unwrap();
        let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
        if class != KeyClass::Seal {
            assert_eq!(sealed.hint().as_bytes(), &[0; 8]);
        }
        for other in [KeyClass::Seal, KeyClass::Epic1, KeyClass::Listener] {
            let result = sealed.open_tx(&recipient(), other);
            if other == class {
                assert_eq!(result.unwrap().content, content(10));
            } else {
                assert_eq!(result.err(), Some(DecodeError::CannotOpen));
            }
        }
    }
}

#[test]
fn a_reply_mailbox_needs_a_reply_key_and_no_signer() {
    let mailbox = ReplyMailbox::new([2; 33], "relay.example.org:443").unwrap();
    let mut with_mailbox = content(10);
    with_mailbox.reply_mailbox = Some(mailbox.clone());
    let envelope = seal_listener(&with_mailbox).unwrap();
    let opened = SealedEnvelope::decode(&envelope, NET)
        .unwrap()
        .open_tx(&recipient(), KeyClass::Listener)
        .unwrap();
    assert_eq!(opened.content.reply_mailbox, Some(mailbox.clone()));

    let mut keyless = with_mailbox.clone();
    keyless.reply_key = None;
    assert_eq!(seal_listener(&keyless), Err(EncodeError::ReplyMailbox));

    let signer = SigningKey::from_bytes(&[4; 32]);
    assert_eq!(
        seal_tx(
            NET,
            &recipient().public_key(),
            TxKey::Epic1,
            &with_mailbox,
            Some(&signer),
            &mut ScriptedRng::seeded(3),
        ),
        Err(EncodeError::ReplyMailbox)
    );
    assert_eq!(
        ReplyMailbox::new([4; 33], "relay.example.org").err(),
        Some(Malformed::FieldValue { tag: 0x09 })
    );
}

#[test]
fn the_epictx_armor_round_trips_and_keeps_its_marker() {
    let envelope = seal_listener(&content(100)).unwrap();
    let text = armor_tx(&envelope);
    assert!(text.starts_with("BEGINEPICTX. "));
    assert!(text.ends_with(". ENDEPICTX."));
    assert!(
        text.lines()
            .all(|line| line.len() <= 76 + "BEGINEPICTX. ".len())
    );
    assert_eq!(
        dearmor_marked(&text).unwrap(),
        (envelope.clone(), ArmorMarker::Tx)
    );
    assert_eq!(
        dearmor_marked(&armor(&envelope)).unwrap(),
        (envelope, ArmorMarker::Sealed)
    );
    let mixed = text.replace("ENDEPICTX.", "ENDEPICSEALED.");
    assert_eq!(
        dearmor_marked(&mixed).err(),
        Some(Malformed::Framing.into())
    );
}
