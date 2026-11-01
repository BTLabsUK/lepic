// SPDX-License-Identifier: Apache-2.0
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
    CARD_FORMAT, Capabilities, Commitment, Confirm, ConfirmBody, ConfirmCode, ContactCard,
    ContactKind, ContactName, DecodeError, EncodeError, Hint, Invite, InviteFields, InviteId,
    MAX_CARD_LEN, MAX_INVITE_LEN, MailboxAddress, Malformed, Network, Nonce, PairingCode,
    PairingLink, Refusal, RelayHost, ReplyBody, Sas, SealedEnvelope, open_confirm, open_reply,
    pairing_envelope_from_link, pairing_envelope_link, seal_confirm, seal_refusal, seal_reply,
};
use lepic_contact::{
    CardFields, Content, HintRule, KeyCheck, KeyCheckAnswer, MessageType, accept_found,
    accept_restored, key_check_tag, open_contact_update, open_key_check, open_key_check_answer,
    seal, seal_contact_update, seal_found, seal_key_check, seal_not_found, seal_restored,
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
            link: None,
            mailbox_key: None,
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
    };
    let confirm_envelope =
        seal_confirm(&got.card, &confirm, &alice.sig, &mut ScriptedRng::seeded(2)).unwrap();
    let link = pairing_envelope_link(PairingLink::Confirm, &confirm_envelope);
    assert!(link.starts_with("epiccash://pair-confirm/1/"));
    let confirm_envelope = pairing_envelope_from_link(&link, PairingLink::Confirm).unwrap();
    let sealed = SealedEnvelope::decode(&confirm_envelope, NET).unwrap();
    assert_eq!(sealed.hint(), Hint::contact(&bob.hint, sealed.enc()));
    let Confirm::Accepted(got_confirm) = open_confirm(&sealed, &bob.enc).unwrap() else {
        panic!("not accepted");
    };
    assert_eq!(*got_confirm, confirm);
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
        Some(Malformed::Unsigned { kind: 4 }.into())
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

/// A confirm body sealed to `card_b`, signed by `signer` or anonymous.
fn confirm_envelope(card_b: &ContactCard, body: Vec<u8>, signer: Option<&Side>) -> Vec<u8> {
    seal(
        NET,
        card_b.enc_key(),
        card_b.hint_rule(),
        &Content::new(MessageType::PairingConfirm, body),
        signer.map(|side| &side.sig),
        &mut ScriptedRng::seeded(7),
    )
    .unwrap()
}

#[test]
fn a_refusal_is_one_anonymous_status_byte() {
    let bob = Side::new(11);
    let card_b = bob.card("Bob", NET);
    for (refusal, byte) in [
        (Refusal::AlreadyUsed, 2),
        (Refusal::Expired, 3),
        (Refusal::CancelledByInviter, 4),
    ] {
        let envelope = seal_refusal(&card_b, refusal, &mut ScriptedRng::seeded(8)).unwrap();
        let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
        assert_eq!(sealed.hint(), Hint::contact(&bob.hint, sealed.enc()));
        let opened = sealed.open(&bob.enc).unwrap();
        assert_eq!(opened.content.body, [byte]);
        assert_eq!(opened.sender, None);
        assert_eq!(opened.content.card, None);
        assert_eq!(
            open_confirm(&sealed, &bob.enc).unwrap(),
            Confirm::Refused(refusal)
        );
    }
}

#[test]
fn confirms_refuse_signed_refusals_anonymous_acceptances_and_bad_statuses() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let card_b = bob.card("Bob", NET);
    let accepted = ConfirmBody {
        nonce: Nonce::zero(),
        card: alice.card("Alice", NET),
    }
    .encode();
    let open = |envelope: Vec<u8>| {
        open_confirm(&SealedEnvelope::decode(&envelope, NET).unwrap(), &bob.enc).err()
    };
    assert_eq!(
        open(confirm_envelope(&card_b, vec![2], Some(&alice))),
        Some(Malformed::Signed { kind: 4 }.into())
    );
    assert_eq!(
        open(confirm_envelope(&card_b, accepted.clone(), None)),
        Some(Malformed::Unsigned { kind: 4 }.into())
    );
    let mut wrong_status = accepted.clone();
    *wrong_status.last_mut().unwrap() = 2;
    for body in [
        vec![1],
        vec![0],
        vec![5],
        Vec::new(),
        vec![0; 17],
        wrong_status,
    ] {
        assert_eq!(
            open(confirm_envelope(&card_b, body.clone(), Some(&alice))),
            Some(Malformed::Body.into()),
            "{body:02x?}"
        );
    }
}

#[test]
fn pairing_body_rejections() {
    assert_eq!(
        ReplyBody::decode(&[0; 47], NET).err(),
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
    let alice = Side::new(1);
    let invite = invite_for(&alice, &alice.card("Alice", NET), &Nonce::zero());
    let shown = format!("{invite:?}");
    assert!(
        shown.contains(&format!("len: {}", invite.as_bytes().len())),
        "{shown}"
    );
    for hidden in ["192", "c0", "Alice", "epicbox"] {
        assert!(!shown.contains(hidden), "{hidden} in {shown}");
    }
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

// Key check (RFC 0002 7.8) and contact update.

fn edited_card(side: &Side, name: &str, edit: impl FnOnce(&mut CardFields)) -> ContactCard {
    let mut fields = side.fields(name);
    edit(&mut fields);
    ContactCard::sign(NET, fields, &side.sig).unwrap()
}

/// One side of a key check: its card and keys for the old and for the new pairing.
struct Party {
    old: Side,
    new: Side,
    old_card: ContactCard,
    new_card: ContactCard,
}

impl Party {
    fn new(old: u8, new: u8, name: &str) -> Self {
        let (old, new) = (Side::new(old), Side::new(new));
        let old_card = edited_card(&old, name, |fields| fields.seq = 3);
        let new_card = new.card(name, NET);
        Self {
            old,
            new,
            old_card,
            new_card,
        }
    }
}

/// X sends the check for its old record with Y; returns the 06 bytes.
fn check_from(x: &Party, y: &Party) -> Vec<u8> {
    seal_key_check(
        &y.new_card,
        &y.old_card,
        &x.new.sig,
        &mut ScriptedRng::seeded(1),
    )
    .unwrap()
}

/// Y answers found with its old slot's card at seq 4.
fn found_from(y: &Party, x: &Party, check: &[u8]) -> (Vec<u8>, ContactCard) {
    let refreshed = edited_card(&y.old, "Yan", |fields| fields.seq = 4);
    let found = seal_found(
        &x.new_card,
        &y.new.sig,
        check,
        &refreshed,
        &y.old.sig,
        &mut ScriptedRng::seeded(2),
    )
    .unwrap();
    (found, refreshed)
}

fn opened_answer(envelope: &[u8], to: &Side, from: &Side) -> KeyCheckAnswer {
    open_key_check_answer(
        &SealedEnvelope::decode(envelope, NET).unwrap(),
        &to.enc,
        &from.sig.verifying_key(),
    )
    .unwrap()
}

#[test]
fn key_check_reveals_only_a_tag_bound_to_the_new_pairing() {
    let (x, y) = (Party::new(1, 11, "Xia"), Party::new(21, 31, "Yan"));
    let envelope = check_from(&x, &y);
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    let check = open_key_check(&sealed, &y.new.enc, &x.new.sig.verifying_key()).unwrap();
    let (n_x, n_y) = (x.new.sig.verifying_key(), y.new.sig.verifying_key());
    assert_eq!(
        check,
        KeyCheck {
            seq: 3,
            tag: key_check_tag(&y.old.hint, &n_y, &n_x)
        }
    );
    assert_ne!(check.tag, key_check_tag(&y.old.hint, &n_x, &n_y));
    assert_eq!(KeyCheck::decode(&check.encode()).unwrap(), check);
    let opened = sealed.open(&y.new.enc).unwrap();
    assert_eq!(opened.content.body.len(), 36);
    assert_eq!(opened.content.card, None);
    assert_eq!(
        open_key_check(&sealed, &y.new.enc, &x.old.sig.verifying_key()),
        Err(DecodeError::KeyChanged)
    );
}

#[test]
fn key_check_bodies_are_exactly_36_bytes() {
    for length in [0, 4, 35, 37] {
        assert_eq!(
            KeyCheck::decode(&vec![0; length]),
            Err(Malformed::Body.into()),
            "{length}"
        );
    }
}

#[test]
fn a_found_answer_with_its_proof_completes_the_check_both_ways() {
    let (x, y) = (Party::new(1, 11, "Xia"), Party::new(21, 31, "Yan"));
    let (n_x, n_y) = (x.new.sig.verifying_key(), y.new.sig.verifying_key());
    let check = check_from(&x, &y);
    let (found, refreshed) = found_from(&y, &x, &check);
    let answer = opened_answer(&found, &x.new, &y.new);
    assert_eq!(
        accept_found(&answer, &check, &n_y, &n_x, &y.old_card).unwrap(),
        refreshed
    );

    let restored = seal_restored(
        &y.new_card,
        &x.new.sig,
        &found,
        &x.old_card,
        &x.old.sig,
        &mut ScriptedRng::seeded(3),
    )
    .unwrap();
    let answer = opened_answer(&restored, &y.new, &x.new);
    assert_eq!(
        accept_restored(&answer, &found, &n_x, &n_y, NET).unwrap(),
        x.old_card
    );
}

#[test]
fn a_found_answer_is_refused_without_the_old_keys_proof() {
    let (x, y) = (Party::new(1, 11, "Xia"), Party::new(21, 31, "Yan"));
    let mallory = Party::new(41, 51, "Yan");
    let (n_x, n_y) = (x.new.sig.verifying_key(), y.new.sig.verifying_key());
    let check = check_from(&x, &y);
    let (found, _) = found_from(&y, &x, &check);
    let answer = opened_answer(&found, &x.new, &y.new);

    // The proof covers the check it answers and both new keys.
    let other_check = check_from(&x, &mallory);
    let not_proven = Err(DecodeError::KeyCheckNotProven);
    assert_eq!(
        accept_found(&answer, &other_check, &n_y, &n_x, &y.old_card),
        not_proven
    );
    assert_eq!(
        accept_found(&answer, &check, &n_x, &n_y, &y.old_card),
        not_proven
    );
    // A party without the old slot key cannot answer found for it, even with a valid card.
    let (forged, _) = found_from(&mallory, &x, &check);
    let forged = opened_answer(&forged, &x.new, &mallory.new);
    assert_eq!(
        accept_found(
            &forged,
            &check,
            &mallory.new.sig.verifying_key(),
            &n_x,
            &y.old_card
        ),
        not_proven
    );
    // Y's own refreshed card, seen elsewhere, with a proof by another key.
    let refreshed = edited_card(&y.old, "Yan", |fields| fields.seq = 4);
    let length = u16::try_from(refreshed.as_bytes().len())
        .unwrap()
        .to_be_bytes();
    let body = [&[2][..], &length, refreshed.as_bytes(), &[9; 64]].concat();
    let replayed = KeyCheckAnswer::decode(&body).unwrap();
    assert_eq!(
        accept_found(&replayed, &check, &n_y, &n_x, &y.old_card),
        not_proven
    );
    // Not-found and restored answers never complete a check.
    assert_eq!(
        accept_found(&KeyCheckAnswer::NotFound, &check, &n_y, &n_x, &y.old_card),
        not_proven
    );
    assert_eq!(
        accept_restored(&answer, &found, &n_x, &n_y, NET),
        not_proven
    );
}

#[test]
fn a_found_card_needs_the_same_keys_and_a_higher_seq() {
    let (x, y) = (Party::new(1, 11, "Xia"), Party::new(21, 31, "Yan"));
    let (n_x, n_y) = (x.new.sig.verifying_key(), y.new.sig.verifying_key());
    let check = check_from(&x, &y);
    let other = Side::new(61);
    for refreshed in [
        edited_card(&y.old, "Yan", |fields| fields.seq = 3),
        edited_card(&y.old, "Yan", |fields| fields.seq = 2),
        edited_card(&y.old, "Yan", |fields| {
            fields.seq = 4;
            fields.enc_key = other.enc_pk();
        }),
        edited_card(&y.old, "Yan", |fields| {
            fields.seq = 4;
            fields.hint_key = other.hint.clone();
        }),
    ] {
        let found = seal_found(
            &x.new_card,
            &y.new.sig,
            &check,
            &refreshed,
            &y.old.sig,
            &mut ScriptedRng::seeded(2),
        )
        .unwrap();
        let answer = opened_answer(&found, &x.new, &y.new);
        assert_eq!(
            accept_found(&answer, &check, &n_y, &n_x, &y.old_card),
            Err(DecodeError::KeyCheckNotProven),
            "{:?}",
            refreshed.fields().seq
        );
    }
    assert_eq!(
        seal_found(
            &x.new_card,
            &y.new.sig,
            &check,
            &y.old_card,
            &y.new.sig,
            &mut ScriptedRng::seeded(2),
        ),
        Err(EncodeError::SigningKeyMismatch)
    );
}

#[test]
fn a_restored_answer_needs_a_proof_by_the_cards_own_key() {
    let (x, y) = (Party::new(1, 11, "Xia"), Party::new(21, 31, "Yan"));
    let mallory = Party::new(41, 51, "Xia");
    let (n_x, n_y) = (x.new.sig.verifying_key(), y.new.sig.verifying_key());
    let check = check_from(&x, &y);
    let (found, _) = found_from(&y, &x, &check);
    // Mallory proves its own card, not X's old one; Y adopts only what the proof covers.
    let restored = seal_restored(
        &y.new_card,
        &x.new.sig,
        &found,
        &mallory.old_card,
        &mallory.old.sig,
        &mut ScriptedRng::seeded(3),
    )
    .unwrap();
    let answer = opened_answer(&restored, &y.new, &x.new);
    assert_eq!(
        accept_restored(&answer, &found, &n_x, &n_y, NET).unwrap(),
        mallory.old_card
    );
    // The proof covers the found answer it answers and both new keys.
    let (other_found, _) = found_from(&y, &mallory, &check);
    assert_eq!(
        accept_restored(&answer, &other_found, &n_x, &n_y, NET),
        Err(DecodeError::KeyCheckNotProven)
    );
    assert_eq!(
        accept_restored(&answer, &found, &n_y, &n_x, NET),
        Err(DecodeError::KeyCheckNotProven)
    );
    assert_eq!(
        seal_restored(
            &y.new_card,
            &x.new.sig,
            &found,
            &x.old_card,
            &x.new.sig,
            &mut ScriptedRng::seeded(3),
        ),
        Err(EncodeError::SigningKeyMismatch)
    );
}

#[test]
fn key_check_answers_round_trip_and_refuse_bad_bodies() {
    let (x, y) = (Party::new(1, 11, "Xia"), Party::new(21, 31, "Yan"));
    let not_found = seal_not_found(&x.new_card, &y.new.sig, &mut ScriptedRng::seeded(2)).unwrap();
    assert_eq!(
        opened_answer(&not_found, &x.new, &y.new),
        KeyCheckAnswer::NotFound
    );
    let (found, _) = found_from(&y, &x, &check_from(&x, &y));
    let answer = opened_answer(&found, &x.new, &y.new);
    let encoded = answer.encode().unwrap();
    assert_eq!(KeyCheckAnswer::decode(&encoded).unwrap(), answer);

    let card = y.old_card.as_bytes();
    let length = u16::try_from(card.len()).unwrap().to_be_bytes();
    let with = |status: u8, length: &[u8], card: &[u8], proof: usize| {
        [&[status][..], length, card, &vec![7; proof]].concat()
    };
    for body in [
        Vec::new(),
        vec![1, 0],
        vec![0],
        vec![4],
        vec![2],
        vec![2, 0],
        with(2, &[0, 0], &[], 64),
        with(2, &length, card, 63),
        with(2, &length, card, 65),
        with(3, &length, &card[1..], 64),
        with(1, &length, card, 64),
    ] {
        assert_eq!(
            KeyCheckAnswer::decode(&body),
            Err(Malformed::Body.into()),
            "{body:02x?}"
        );
    }
    assert!(KeyCheckAnswer::decode(&with(3, &length, card, 64)).is_ok());
}

#[test]
fn key_check_types_must_be_signed() {
    let (x, y) = (Side::new(11), Side::new(31));
    let y_card = y.card("Yan", NET);
    for (kind, body) in [
        (MessageType::KeyCheck, vec![0; 36]),
        (MessageType::KeyCheckAnswer, vec![1]),
        (
            MessageType::ContactUpdate,
            x.card("Xia", NET).as_bytes().to_vec(),
        ),
    ] {
        let envelope = seal(
            NET,
            y_card.enc_key(),
            HintRule::Contact(&y.hint),
            &Content::new(kind, body),
            None,
            &mut ScriptedRng::seeded(3),
        )
        .unwrap();
        let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
        let peer = x.sig.verifying_key();
        let error = match kind {
            MessageType::KeyCheck => open_key_check(&sealed, &y.enc, &peer).err(),
            MessageType::KeyCheckAnswer => open_key_check_answer(&sealed, &y.enc, &peer).err(),
            _ => open_contact_update(&sealed, &y.enc, &peer).err(),
        };
        assert!(
            matches!(
                error,
                Some(DecodeError::Malformed(Malformed::Unsigned { .. }))
            ),
            "{kind:?}: {error:?}"
        );
    }
}

#[test]
fn contact_update_carries_a_card_of_the_signing_key() {
    let (x, y) = (Side::new(11), Side::new(31));
    let newer = edited_card(&x, "Xia", |fields| fields.seq = 2);
    let envelope = seal_contact_update(
        &y.card("Yan", NET),
        &newer,
        &x.sig,
        &mut ScriptedRng::seeded(4),
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert_eq!(
        open_contact_update(&sealed, &y.enc, &x.sig.verifying_key()).unwrap(),
        newer
    );
    assert_eq!(
        seal_contact_update(
            &y.card("Yan", NET),
            &Side::new(41).card("Other", NET),
            &x.sig,
            &mut ScriptedRng::seeded(5),
        ),
        Err(EncodeError::SigningKeyMismatch)
    );
}

#[test]
fn a_signed_pairing_reply_is_refused() {
    let alice = Side::new(1);
    let bob = Side::new(2);
    let card = alice.card("Alice", NET);
    let invite = invite_for(&alice, &card, &Nonce::zero());
    let body = ReplyBody {
        code: invite.fields().code.clone(),
        nonce: Nonce::zero(),
        confirm_code: ConfirmCode::from_bytes([3; 16]),
        card: bob.card("Bob", NET),
    };
    let envelope = seal(
        NET,
        &invite.fields().enc_key,
        HintRule::Invite(invite.id()),
        &Content::new(MessageType::PairingReply, body.encode().to_vec()),
        Some(&bob.sig),
        &mut ScriptedRng::seeded(6),
    )
    .unwrap();
    assert_eq!(
        open_reply(&SealedEnvelope::decode(&envelope, NET).unwrap(), &alice.enc),
        Err(Malformed::Signed { kind: 3 }.into())
    );
}

// Private pairings.

use lepic_contact::{
    ChannelKey, PairingClass, PrivateSecret, SUITE_PSK, open_private_confirm, open_private_reply,
    private_sas, seal_private_confirm, seal_private_reply, seal_psk,
};

fn private_invite(alice: &Side, card: &ContactCard, nonce: &Nonce, link: [u8; 32]) -> Invite {
    Invite::new(
        NET,
        InviteFields {
            link: Some(PrivateSecret::from_bytes(link)),
            mailbox_key: None,
            ..invite_for(alice, card, nonce).fields().clone()
        },
    )
    .unwrap()
}

#[test]
fn a_private_invite_carries_its_link_secret_as_an_extension() {
    let alice = Side::new(1);
    let card = alice.card("Alice", NET);
    let invite = private_invite(&alice, &card, &Nonce::from_bytes([1; 16]), [9; 32]);
    let decoded = Invite::from_link(&invite.to_link(), NET).unwrap();
    assert_eq!(decoded, invite);
    assert_eq!(decoded.class(), PairingClass::Private);
    assert_eq!(
        invite_for(&alice, &card, &Nonce::from_bytes([1; 16])).class(),
        PairingClass::Contact
    );
    // A service inbox never goes with a private invite.
    let mut fields = invite.fields().clone();
    fields.service_inbox = Some(MailboxAddress::new("esInbox@shop.example.org").unwrap());
    assert_eq!(Invite::new(NET, fields), Err(EncodeError::WrongClass));
}

#[test]
fn a_private_reply_opens_only_with_the_link_secret_and_both_sides_derive_one_channel() {
    let (alice, ben) = (Side::new(1), Side::new(2));
    let alice_card = alice.card("Alice", NET);
    let ben_card = ben.card("Ben", NET);
    let n_a = Nonce::from_bytes([1; 16]);
    let invite = private_invite(&alice, &alice_card, &n_a, [9; 32]);
    let body = ReplyBody {
        code: invite.fields().code.clone(),
        nonce: Nonce::from_bytes([2; 16]),
        confirm_code: ConfirmCode::from_bytes([3; 16]),
        card: ben_card.clone(),
    };
    let joiner = PrivateSecret::from_bytes([7; 32]);
    let envelope =
        seal_private_reply(&invite, &body, &joiner, &mut ScriptedRng::seeded(4)).unwrap();
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert!(sealed.is_private());
    assert_eq!(
        open_reply(&sealed, &alice.enc),
        Err(DecodeError::CannotOpen)
    );
    assert_eq!(
        open_private_reply(&sealed, &alice.enc, &PrivateSecret::from_bytes([8; 32])).err(),
        Some(DecodeError::CannotOpen)
    );
    let link = PrivateSecret::from_bytes([9; 32]);
    let (opened, secret) = open_private_reply(&sealed, &alice.enc, &link).unwrap();
    assert_eq!(opened, body);
    assert_eq!(secret, joiner);

    let alice_channel = ChannelKey::channel(&link, &secret, &invite, &opened.card);
    let ben_channel = ChannelKey::channel(&link, &joiner, &invite, &ben_card);
    assert_eq!(alice_channel, ben_channel);
    let confirm = ConfirmBody {
        nonce: n_a.clone(),
        card: alice_card.clone(),
    };
    let envelope = seal_private_confirm(
        &ben_card,
        &confirm,
        &alice.sig,
        &alice_channel,
        &mut ScriptedRng::seeded(5),
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert_eq!(
        open_confirm(&sealed, &ben.enc),
        Err(DecodeError::CannotOpen)
    );
    assert_eq!(
        open_private_confirm(&sealed, &ben.enc, &ben_channel).unwrap(),
        Confirm::Accepted(Box::new(confirm))
    );
    let other = ChannelKey::channel(
        &link,
        &PrivateSecret::from_bytes([6; 32]),
        &invite,
        &ben_card,
    );
    assert_eq!(
        open_private_confirm(&sealed, &ben.enc, &other),
        Err(DecodeError::CannotOpen)
    );
}

#[test]
fn a_base_envelope_never_opens_as_private_nor_a_private_one_as_base() {
    let (alice, ben) = (Side::new(1), Side::new(2));
    let ben_card = ben.card("Ben", NET);
    let content = Content::new(MessageType::AppPayload, vec![1, 2, 3]);
    let channel = ChannelKey::from_bytes([5; 32]);
    let private = seal_psk(
        NET,
        ben_card.enc_key(),
        HintRule::Contact(&ben.hint),
        &content,
        Some(&alice.sig),
        &channel,
        &mut ScriptedRng::seeded(6),
    )
    .unwrap();
    assert_eq!(private[6], SUITE_PSK);
    let sealed = SealedEnvelope::decode(&private, NET).unwrap();
    assert_eq!(sealed.open(&ben.enc), Err(DecodeError::CannotOpen));
    assert_eq!(
        sealed.open_psk(&ben.enc, &channel).unwrap().content,
        content
    );
    let base = seal(
        NET,
        ben_card.enc_key(),
        HintRule::Contact(&ben.hint),
        &content,
        Some(&alice.sig),
        &mut ScriptedRng::seeded(6),
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&base, NET).unwrap();
    assert_eq!(
        sealed.open_psk(&ben.enc, &channel),
        Err(DecodeError::CannotOpen)
    );
}

#[test]
fn the_private_words_check_covers_both_secrets() {
    let (alice, ben) = (Side::new(1), Side::new(2));
    let (a, b) = (alice.card("Alice", NET), ben.card("Ben", NET));
    let (n_a, n_b) = (Nonce::from_bytes([1; 16]), Nonce::from_bytes([2; 16]));
    let secret = |byte| PrivateSecret::from_bytes([byte; 32]);
    let sas = private_sas(NET, &a, &b, &n_a, &n_b, &secret(1), &secret(2));
    assert_eq!(
        sas,
        private_sas(NET, &a, &b, &n_a, &n_b, &secret(1), &secret(2))
    );
    assert_ne!(
        sas,
        private_sas(NET, &a, &b, &n_a, &n_b, &secret(3), &secret(2))
    );
    assert_ne!(
        sas,
        private_sas(NET, &a, &b, &n_a, &n_b, &secret(1), &secret(3))
    );
    assert_ne!(sas, Sas::compute(NET, &a, &b, &n_a, &n_b));
}
