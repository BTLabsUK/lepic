// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{ScriptedRng, Side};
use lepic_contact::{
    CARD_FORMAT, Capabilities, Commitment, ConfirmBody, ConfirmCode, ConfirmStatus, ContactCard,
    ContactKind, ContactName, DecodeError, EncodeError, Hint, Invite, InviteFields, InviteId,
    MAX_CARD_LEN, MAX_INVITE_LEN, MailboxAddress, Malformed, Network, Nonce, PairingCode,
    PairingLink, RelayHost, ReplyBody, Sas, SealedEnvelope, open_confirm, open_reply,
    pairing_envelope_from_link, pairing_envelope_link, seal_confirm, seal_reply,
};
use proptest::prelude::*;

const NET: Network = Network::Floonet;

fn invite_for(alice: &Side, card: &ContactCard, nonce: &Nonce) -> Invite {
    Invite::new(
        NET,
        InviteFields {
            kind: ContactKind::Person,
            name: ContactName::new("Alice").unwrap(),
            expires: 1_800_000_000,
            code: PairingCode::from_bytes([0xc0; 16]),
            commit: Commitment::new(nonce, card),
            enc_key: alice.enc_pk(),
            home_relay: RelayHost::new("epicbox.example.org:443").unwrap(),
            service_inbox: None,
            onion: None,
        },
    )
    .unwrap()
}

// Cards.

#[test]
fn card_round_trips_through_bytes_and_link() {
    let alice = Side::new(1);
    let mut fields = alice.fields("Alice 🐼");
    fields.payments_address = Some(MailboxAddress::new("esAbc@epicbox.example.org").unwrap());
    fields.home_onion = Some(RelayHost::new("abcdefghij.onion").unwrap());
    fields.caps = Capabilities::FIXED_HINT.with(Capabilities::ISSUES_INVOICES);
    fields.seq = 7;
    let card = ContactCard::sign(NET, fields.clone(), &alice.sig).unwrap();
    assert_eq!(card.fields(), &fields);
    assert_eq!(ContactCard::decode(card.as_bytes(), NET).unwrap(), card);
    let link = card.to_link();
    assert!(link.starts_with("epiccash://contact/1/"));
    assert_eq!(ContactCard::from_link(&link, NET).unwrap(), card);
    assert!(link.len() < 520, "{}", link.len());
    // The common card, without the optional fields: about 400 characters.
    assert!(alice.card("Alice", NET).to_link().len() < 420);
}

#[test]
fn a_card_signed_by_another_key_is_refused_when_built_and_read() {
    let (alice, mallory) = (Side::new(1), Side::new(31));
    assert_eq!(
        ContactCard::sign(NET, alice.fields("Alice"), &mallory.sig),
        Err(EncodeError::SigningKeyMismatch)
    );
    let mut bytes = alice.card("Alice", NET).as_bytes().to_vec();
    // The name is the fourth field; changing a letter breaks the self-signature.
    let position = bytes.windows(5).position(|w| w == b"Alice").unwrap();
    bytes[position] = b'M';
    assert_eq!(
        ContactCard::decode(&bytes, NET),
        Err(DecodeError::BadSignature)
    );
}

fn card_field(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// Card bytes with `tag` replaced (or removed when `value` is `None`), self-signed again so only
/// the field rule can refuse it.
fn card_with(side: &Side, tag: u8, value: Option<&[u8]>) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let card = side.card("Alice", NET);
    let mut rest = card.as_bytes();
    let mut fields = Vec::new();
    while let [t, h, l, tail @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*h, *l]));
        let (v, tail) = tail.split_at(length);
        if *t == 0x0e {
            break;
        }
        if *t == tag {
            if let Some(value) = value {
                fields.extend(card_field(tag, value));
            }
        } else {
            fields.extend(card_field(*t, v));
        }
        rest = tail;
    }
    let mut input = b"epic-card/1".to_vec();
    input.extend_from_slice(&fields);
    fields.extend(card_field(0x0e, &side.sig.sign(&input).to_bytes()));
    fields
}

#[test]
fn card_rejections_have_their_own_errors() {
    let alice = Side::new(1);
    let value = |tag| -> DecodeError { Malformed::FieldValue { tag }.into() };
    let cases: Vec<(u8, Option<&[u8]>, DecodeError)> = vec![
        (0x01, Some(&[2]), DecodeError::NewerVersion { found: 2 }),
        (0x01, Some(&[0]), Malformed::Version { found: 0 }.into()),
        (0x02, Some(&[0]), DecodeError::WrongNetwork),
        (0x02, Some(&[9]), Malformed::Network { byte: 9 }.into()),
        (0x03, Some(&[4]), value(0x03)),
        (0x04, Some(b""), value(0x04)),
        (0x04, Some(&[b'a'; 49]), value(0x04)),
        (0x04, Some("a\u{202E}b".as_bytes()), value(0x04)),
        (0x04, None, Malformed::MissingField { tag: 0x04 }.into()),
        (0x05, Some(&[0; 32]), value(0x05)),
        (
            0x05,
            Some(&[1; 31]),
            Malformed::FieldLength { tag: 0x05 }.into(),
        ),
        (0x08, Some(b"no-at-sign"), value(0x08)),
        (0x0b, Some(&[0x00, 0x20]), value(0x0b)),
        (0x0c, Some(&[0]), value(0x0c)),
        (0x0d, None, Malformed::MissingField { tag: 0x0d }.into()),
    ];
    for (tag, replacement, expected) in cases {
        let bytes = card_with(&alice, tag, replacement);
        assert_eq!(
            ContactCard::decode(&bytes, NET).err(),
            Some(expected),
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn card_list_rules_apply() {
    let alice = Side::new(1);
    let card = alice.card("Alice", NET);
    let mut unsigned = card.as_bytes().to_vec();
    unsigned.truncate(unsigned.len() - 67);
    assert_eq!(
        ContactCard::decode(&unsigned, NET).err(),
        Some(Malformed::MissingField { tag: 0x0e }.into())
    );
    let mut trailing = card.as_bytes().to_vec();
    trailing.extend(card_field(0x80, b""));
    assert_eq!(
        ContactCard::decode(&trailing, NET).err(),
        Some(Malformed::FieldAfterSignature.into())
    );
    let huge = vec![0u8; MAX_CARD_LEN + 1];
    assert!(matches!(
        ContactCard::decode(&huge, NET),
        Err(DecodeError::Oversized { .. })
    ));
    assert_eq!(
        ContactCard::decode(card.as_bytes(), Network::Mainnet).err(),
        Some(DecodeError::WrongNetwork)
    );
    assert_eq!(card.fields().max_envelope_version, 1);
    assert_eq!(card.as_bytes()[3], CARD_FORMAT);
}

#[test]
fn a_newer_card_link_or_format_is_from_a_newer_wallet() {
    let alice = Side::new(1);
    let link = alice.card("Alice", NET).to_link().replacen("/1/", "/2/", 1);
    assert_eq!(
        ContactCard::from_link(&link, NET).err(),
        Some(DecodeError::NewerVersion { found: 2 })
    );
    // A newer format may use tags this version does not know; the format byte is read first.
    let mut newer = vec![0x01, 0, 1, 2, 0x0f, 0, 0];
    newer.extend_from_slice(&[0; 8]);
    assert_eq!(
        ContactCard::decode(&newer, NET).err(),
        Some(DecodeError::NewerVersion { found: 2 })
    );
}

// Invites.

#[test]
fn invite_round_trips_through_its_link() {
    let alice = Side::new(1);
    let card = alice.card("Alice", NET);
    let invite = invite_for(&alice, &card, &Nonce::from_bytes([0xa1; 16]));
    let link = invite.to_link();
    assert!(link.starts_with("epiccash://pair/1/"));
    assert!(link.len() < 300, "{}", link.len());
    let read = Invite::from_link(&link, NET).unwrap();
    assert_eq!(read, invite);
    assert_eq!(
        read.id(),
        InviteId::from_code(&PairingCode::from_bytes([0xc0; 16]))
    );
    assert!(!read.is_expired(1_799_999_999));
    assert!(read.is_expired(1_800_000_000));
    assert_eq!(
        Invite::from_link(&link, Network::Mainnet).err(),
        Some(DecodeError::WrongNetwork)
    );
}

#[test]
fn invite_rejections_have_their_own_errors() {
    let alice = Side::new(1);
    let mut fields = invite_for(&alice, &alice.card("Alice", NET), &Nonce::zero())
        .fields()
        .clone();
    fields.service_inbox = Some(MailboxAddress::new("esInbox@shop.example.org").unwrap());
    fields.onion = Some(RelayHost::new("abcdefghij.onion").unwrap());
    let invite = Invite::new(NET, fields).unwrap();
    assert_eq!(Invite::decode(invite.as_bytes(), NET).unwrap(), invite);
    let bytes = invite.as_bytes();
    let replace = |tag: u8, value: Option<&[u8]>| {
        let mut rest = bytes;
        let mut out = Vec::new();
        while let [t, h, l, tail @ ..] = rest {
            let length = usize::from(u16::from_be_bytes([*h, *l]));
            let (v, tail) = tail.split_at(length);
            if *t == tag {
                if let Some(value) = value {
                    out.extend(card_field(tag, value));
                }
            } else {
                out.extend(card_field(*t, v));
            }
            rest = tail;
        }
        Invite::decode(&out, NET).err()
    };
    let value = |tag| Some(DecodeError::from(Malformed::FieldValue { tag }));
    assert_eq!(
        replace(0x01, Some(&[3])),
        Some(DecodeError::NewerVersion { found: 3 })
    );
    assert_eq!(replace(0x02, Some(&[0])), Some(DecodeError::WrongNetwork));
    assert_eq!(replace(0x04, Some(b"\x00")), value(0x04));
    assert_eq!(
        replace(0x05, Some(&[0; 4])),
        Some(Malformed::FieldLength { tag: 0x05 }.into())
    );
    assert_eq!(
        replace(0x06, None),
        Some(Malformed::MissingField { tag: 0x06 }.into())
    );
    assert_eq!(replace(0x08, Some(&[0; 32])), value(0x08));
    assert_eq!(replace(0x09, Some(b"relay/path")), value(0x09));
    assert_eq!(replace(0x0a, Some(b"no-at")), value(0x0a));
    assert_eq!(replace(0x0b, Some(b"")), value(0x0b));
    let mut extended = bytes.to_vec();
    extended.extend(card_field(0x0c, b""));
    assert_eq!(
        Invite::decode(&extended, NET).err(),
        Some(Malformed::UnknownField { tag: 0x0c }.into())
    );
    let mut skipped = bytes.to_vec();
    skipped.extend(card_field(0xa0, b"later"));
    assert!(Invite::decode(&skipped, NET).is_ok());
    assert!(matches!(
        Invite::decode(&vec![0; MAX_INVITE_LEN + 1], NET),
        Err(DecodeError::Oversized { .. })
    ));
}

// The pairing flow.

#[test]
fn online_pairing_reaches_the_same_sas_on_both_sides() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let card_a = alice.card("Alice", NET);
    let card_b = bob.card("Bob", NET);
    let na = Nonce::from_bytes([0xa1; 16]);
    let invite = Invite::from_link(&invite_for(&alice, &card_a, &na).to_link(), NET).unwrap();

    // B replies, sealed to the invite's key and hinted with its id.
    let nb = Nonce::from_bytes([0xb2; 16]);
    let reply = ReplyBody {
        code: invite.fields().code.clone(),
        nonce: nb.clone(),
        confirm_code: ConfirmCode::from_bytes([0xcc; 16]),
        card: card_b.clone(),
    };
    let reply_envelope = seal_reply(&invite, &reply, &mut ScriptedRng::seeded(1)).unwrap();
    let link = pairing_envelope_link(PairingLink::Reply, &reply_envelope);
    assert!(link.starts_with("epiccash://pair-reply/1/"));
    let reply_envelope = pairing_envelope_from_link(&link, PairingLink::Reply).unwrap();
    let sealed = SealedEnvelope::decode(&reply_envelope, NET).unwrap();
    assert_eq!(sealed.hint(), Hint::invite(&invite.id()));
    let got = open_reply(&sealed, &alice.enc).unwrap();
    assert_eq!(got, reply);

    // A confirms, signed, to B's card.
    let confirm = ConfirmBody {
        nonce: na.clone(),
        card: card_a.clone(),
        status: ConfirmStatus::Accepted,
    };
    let confirm_envelope =
        seal_confirm(&got.card, &confirm, &alice.sig, &mut ScriptedRng::seeded(2)).unwrap();
    let link = pairing_envelope_link(PairingLink::Confirm, &confirm_envelope);
    assert!(link.starts_with("epiccash://pair-confirm/1/"));
    let confirm_envelope = pairing_envelope_from_link(&link, PairingLink::Confirm).unwrap();
    let sealed = SealedEnvelope::decode(&confirm_envelope, NET).unwrap();
    assert_eq!(sealed.hint(), Hint::contact(&bob.hint, sealed.enc()));
    let got_confirm = open_confirm(&sealed, &bob.enc).unwrap();
    assert_eq!(got_confirm, confirm);
    assert!(got_confirm.matches_invite(&invite));

    let sas_a = Sas::compute(NET, &card_a, &got.card, &na, &got.nonce);
    let sas_b = Sas::compute(NET, &got_confirm.card, &card_b, &got_confirm.nonce, &nb);
    assert_eq!(sas_a, sas_b);
}

#[test]
fn a_changed_invite_fails_the_commitment() {
    let (alice, mallory) = (Side::new(1), Side::new(31));
    let card_a = alice.card("Alice", NET);
    let na = Nonce::from_bytes([0xa1; 16]);
    let honest = invite_for(&alice, &card_a, &na);
    let confirm = ConfirmBody {
        nonce: na.clone(),
        card: card_a.clone(),
        status: ConfirmStatus::Accepted,
    };
    assert!(confirm.matches_invite(&honest));

    // Mallory swaps the enc key in the invite.
    let mut fields = honest.fields().clone();
    fields.enc_key = mallory.enc_pk();
    assert!(!confirm.matches_invite(&Invite::new(NET, fields).unwrap()));
    // Another nonce or card does not match the commitment.
    let other_nonce = ConfirmBody {
        nonce: Nonce::from_bytes([0xa2; 16]),
        ..confirm.clone()
    };
    assert!(!other_nonce.matches_invite(&honest));
    let other_card = ConfirmBody {
        card: mallory.card("Alice", NET),
        ..confirm
    };
    assert!(!other_card.matches_invite(&honest));
}

#[test]
fn a_confirm_must_be_signed_by_its_card() {
    let (alice, bob, mallory) = (Side::new(1), Side::new(11), Side::new(31));
    let card_b = bob.card("Bob", NET);
    let confirm = ConfirmBody {
        nonce: Nonce::zero(),
        card: alice.card("Alice", NET),
        status: ConfirmStatus::AlreadyUsed,
    };
    assert_eq!(
        seal_confirm(&card_b, &confirm, &mallory.sig, &mut ScriptedRng::seeded(2)),
        Err(EncodeError::SigningKeyMismatch)
    );
    // An anonymous envelope of the confirm type is not a confirm.
    let content =
        lepic_contact::Content::new(lepic_contact::MessageType::PairingConfirm, confirm.encode());
    let envelope = lepic_contact::seal(
        NET,
        card_b.enc_key(),
        card_b.hint_rule(),
        &content,
        None,
        &mut ScriptedRng::seeded(3),
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert_eq!(
        open_confirm(&sealed, &bob.enc).err(),
        Some(Malformed::MissingField { tag: 0x08 }.into())
    );
    // Signed by a key other than the card's.
    let envelope = lepic_contact::seal(
        NET,
        card_b.enc_key(),
        card_b.hint_rule(),
        &content,
        Some(&mallory.sig),
        &mut ScriptedRng::seeded(3),
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert_eq!(
        open_confirm(&sealed, &bob.enc).err(),
        Some(DecodeError::BadSignature)
    );
    // A reply is not a confirm.
    assert_eq!(
        open_reply(&sealed, &bob.enc).err(),
        Some(Malformed::FieldValue { tag: 0x01 }.into())
    );
}

#[test]
fn pairing_body_rejections() {
    let alice = Side::new(1);
    let card = alice.card("Alice", NET);
    assert_eq!(
        ReplyBody::decode(&[0; 47], NET).err(),
        Some(Malformed::Truncated.into())
    );
    let mut confirm = ConfirmBody {
        nonce: Nonce::zero(),
        card,
        status: ConfirmStatus::Expired,
    }
    .encode();
    *confirm.last_mut().unwrap() = 9;
    assert_eq!(
        ConfirmBody::decode(&confirm, NET).err(),
        Some(Malformed::Body.into())
    );
    assert_eq!(
        ConfirmBody::decode(&[0; 16], NET).err(),
        Some(Malformed::Truncated.into())
    );
    assert_eq!(
        pairing_envelope_from_link("epiccash://pair-reply/1/", PairingLink::Confirm).err(),
        Some(Malformed::LinkPrefix.into())
    );
}

#[test]
fn reply_refuses_a_card_of_the_other_network() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let invite = invite_for(&alice, &alice.card("Alice", NET), &Nonce::zero());
    let reply = ReplyBody {
        code: invite.fields().code.clone(),
        nonce: Nonce::zero(),
        confirm_code: ConfirmCode::from_bytes([0; 16]),
        card: bob.card("Bob", Network::Mainnet),
    };
    assert_eq!(
        seal_reply(&invite, &reply, &mut ScriptedRng::seeded(1)),
        Err(EncodeError::WrongNetwork)
    );
}

#[test]
fn secrets_do_not_print() {
    assert_eq!(
        format!("{:?}", PairingCode::from_bytes([1; 16])),
        "PairingCode(<redacted>)"
    );
    assert_eq!(format!("{:?}", Nonce::zero()), "Nonce(<redacted>)");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn card_and_invite_links_never_panic(text in "\\PC{0,600}") {
        let _ = ContactCard::from_link(&text, NET);
        let _ = Invite::from_link(&text, NET);
        let _ = pairing_envelope_from_link(&text, PairingLink::Reply);
    }

    #[test]
    fn card_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..700)) {
        if let Ok(card) = ContactCard::decode(&bytes, NET) {
            prop_assert_eq!(card.as_bytes(), &bytes[..]);
        }
        let _ = Invite::decode(&bytes, NET);
    }

    #[test]
    fn names_round_trip_through_a_card(name in "[a-zA-Z0-9 éü🐼]{1,12}", seq in any::<u32>()) {
        let alice = Side::new(1);
        let mut fields = alice.fields(&name);
        fields.seq = seq;
        let card = ContactCard::sign(NET, fields, &alice.sig).unwrap();
        prop_assert_eq!(ContactCard::from_link(&card.to_link(), NET).unwrap(), card);
    }
}
