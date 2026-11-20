// SPDX-License-Identifier: Apache-2.0
//! Type 0A envelopes (RFC 0003 5): the body limit with padding, the key classes, the reply
//! route rules and the EPICTX armor.

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
    ReplyEntry, ReplyRoute, SealedEnvelope, SigningKey, TxContent, TxKey, TxKind, armor, armor_tx,
    dearmor_marked, pad_target, seal, seal_epic1_notice, seal_padded, seal_tx,
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
    let envelope = seal_padded(
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
    let envelope = seal_padded(
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

/// With native slates off a slate is sealed as RFC 0002 wrote it: no padding field, so its
/// length follows the body, and the padded form of a build with them on opens the same.
#[test]
fn a_slate_sealed_with_seal_has_no_padding_and_the_padded_one_opens_alike() {
    let slate = Content::new(MessageType::Slate, b"{}".to_vec());
    let seal_with = |padded: bool| {
        let mut rng = ScriptedRng::seeded(1);
        let to = recipient().public_key();
        if padded {
            seal_padded(NET, &to, HintRule::ReplyKey, &slate, None, &mut rng)
        } else {
            seal(NET, &to, HintRule::ReplyKey, &slate, None, &mut rng)
        }
        .unwrap()
    };
    let plain = seal_with(false);
    let padded = seal_with(true);
    // Type 01 field (4) and body (3 + 2) only.
    assert_eq!(plain.len(), OVERHEAD + 4 + 3 + 2);
    assert_eq!(padded.len(), PADDING_FLOOR + OVERHEAD);
    for envelope in [&plain, &padded] {
        let opened = SealedEnvelope::decode(envelope, NET)
            .unwrap()
            .open(&recipient())
            .unwrap();
        assert_eq!(opened.content.kind, MessageType::Slate);
        assert_eq!(opened.content.body, b"{}");
    }
}

#[test]
fn each_key_class_opens_only_its_own_envelopes() {
    let hint = HintKey::from_bytes([5; 32]);
    let keys = [
        (TxKey::Seal(HintRule::Contact(&hint)), KeyClass::Seal),
        (TxKey::Epic1, KeyClass::Epic1),
        (TxKey::Listener, KeyClass::Listener),
        (TxKey::Epicbox, KeyClass::Epicbox),
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
        for other in [
            KeyClass::Seal,
            KeyClass::Epic1,
            KeyClass::Listener,
            KeyClass::Epicbox,
        ] {
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
fn a_reply_route_needs_a_reply_key_and_no_signer() {
    let route = ReplyRoute::epicbox([2; 33]);
    let mut with_route = content(10);
    with_route.reply_route = Some(route.clone());
    let envelope = seal_listener(&with_route).unwrap();
    let opened = SealedEnvelope::decode(&envelope, NET)
        .unwrap()
        .open_tx(&recipient(), KeyClass::Listener)
        .unwrap();
    assert_eq!(opened.content.reply_route, Some(route.clone()));
    assert_eq!(route.epicbox_key(), Some([2; 33]));

    let mut keyless = with_route.clone();
    keyless.reply_key = None;
    assert_eq!(seal_listener(&keyless), Err(EncodeError::ReplyRoute));

    let signer = SigningKey::from_bytes(&[4; 32]);
    assert_eq!(
        seal_tx(
            NET,
            &recipient().public_key(),
            TxKey::Epic1,
            &with_route,
            Some(&signer),
            &mut ScriptedRng::seeded(3),
        ),
        Err(EncodeError::ReplyRoute)
    );
}

/// The writer refuses what a reader would refuse: no entries, a value over 255 bytes, and an
/// epicbox value that is not a 33-byte key with prefix 02 or 03.
#[test]
fn a_reply_route_the_reader_would_refuse_is_not_written() {
    let entry = |method: u8, value: Vec<u8>| ReplyEntry { method, value };
    let refused = [
        ReplyRoute { entries: vec![] },
        ReplyRoute {
            entries: vec![entry(0x07, vec![0; 256])],
        },
        ReplyRoute {
            entries: vec![entry(0x01, vec![4; 33])],
        },
        ReplyRoute {
            entries: vec![entry(0x01, vec![2; 32])],
        },
    ];
    for route in refused {
        assert_eq!(route.to_bytes(), Err(EncodeError::ReplyRoute), "{route:?}");
        let mut with_route = content(10);
        with_route.reply_route = Some(route);
        assert_eq!(seal_listener(&with_route), Err(EncodeError::ReplyRoute));
    }
    let longest = ReplyRoute {
        entries: vec![entry(0x07, vec![0; 255]), entry(0x01, vec![3; 33])],
    };
    let bytes = longest.to_bytes().unwrap();
    assert_eq!(ReplyRoute::from_bytes(&bytes), Ok(longest));
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

/// A notice to an epic1 key is anonymous, hinted zero and padded as a slate; only the epic1
/// opener reads it, and that opener reads a slate to the same key as before.
#[test]
fn a_notice_to_an_epic1_key_opens_only_with_the_epic1_opener() {
    let body = br#"{"notice":"cancelled"}"#;
    let envelope = seal_epic1_notice(
        NET,
        &recipient().public_key(),
        body,
        &mut ScriptedRng::seeded(8),
    )
    .unwrap();
    assert_eq!(envelope.len(), PADDING_FLOOR + OVERHEAD);
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert_eq!(sealed.hint().as_bytes(), &[0; 8]);

    let opened = sealed.open_epic1(&recipient()).unwrap();
    assert_eq!(opened.kind, TxKind::Notice);
    assert_eq!(opened.content, TxContent::new(body.to_vec()));
    assert_eq!(opened.sender, None);
    assert_eq!(opened.inner_len, PADDING_FLOOR);

    assert_eq!(
        sealed.open_tx(&recipient(), KeyClass::Epic1).err(),
        Some(DecodeError::Malformed(Malformed::FieldValue { tag: 0x01 }))
    );
    for other in [KeyClass::Seal, KeyClass::Listener, KeyClass::Epicbox] {
        assert_eq!(
            sealed.open_tx(&recipient(), other).err(),
            Some(DecodeError::CannotOpen)
        );
    }
    assert_eq!(
        sealed.open(&recipient()).err(),
        Some(DecodeError::CannotOpen)
    );

    let slate = seal_tx(
        NET,
        &recipient().public_key(),
        TxKey::Epic1,
        &content(10),
        None,
        &mut ScriptedRng::seeded(9),
    )
    .unwrap();
    let opened = SealedEnvelope::decode(&slate, NET)
        .unwrap()
        .open_epic1(&recipient())
        .unwrap();
    assert_eq!(opened.kind, TxKind::Slate);
    assert_eq!(opened.content, content(10));

    let listener = seal_listener(&content(10)).unwrap();
    assert_eq!(
        SealedEnvelope::decode(&listener, NET)
            .unwrap()
            .open_epic1(&recipient())
            .err(),
        Some(DecodeError::CannotOpen)
    );
}
