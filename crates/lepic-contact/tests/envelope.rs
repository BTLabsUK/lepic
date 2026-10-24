// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{ScriptedRng, Side};
use ed25519_dalek::Signer;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use lepic_contact::{
    Content, DecodeError, EncPublicKey, EncSecretKey, EncodeError, Hint, HintKey, HintRule,
    MAX_ARMOR_LEN, MAX_ENVELOPE_LEN, Malformed, MessageType, Network, Purpose, Reference,
    SealedEnvelope, armor, dearmor, looks_sealed, seal,
};
use proptest::prelude::*;

const NET: Network = Network::Floonet;

fn full_content(card_owner: &Side) -> Content {
    Content {
        kind: MessageType::Slate,
        body: br#"{"version_info":{"version":3}}"#.to_vec(),
        reply_key: Some(EncSecretKey::from_bytes([42; 32]).public_key()),
        purpose: Some(Purpose::DepositRequest),
        reference: Some(Reference::new("dep-0042").unwrap()),
        expires: Some(1_800_000_000),
        card: Some(card_owner.card("Alice", NET)),
    }
}

fn seal_to(recipient: &Side, content: &Content, signer: Option<&Side>, seed: u8) -> Vec<u8> {
    seal(
        NET,
        &recipient.enc_pk(),
        HintRule::Contact(&recipient.hint),
        content,
        signer.map(|side| &side.sig),
        &mut ScriptedRng::seeded(seed),
    )
    .unwrap()
}

fn open(envelope: &[u8], key: &EncSecretKey) -> Result<lepic_contact::Opened, DecodeError> {
    SealedEnvelope::decode(envelope, NET)?.open(key)
}

#[test]
fn anonymous_envelope_round_trips_every_field() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let content = full_content(&alice);
    let envelope = seal_to(&bob, &content, None, 7);
    let opened = open(&envelope, &bob.enc).unwrap();
    assert_eq!(opened.content, content);
    assert_eq!(opened.sender, None);
}

#[test]
fn signed_envelope_names_the_verified_sender() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let envelope = seal_to(&bob, &full_content(&alice), Some(&alice), 7);
    let opened = open(&envelope, &bob.enc).unwrap();
    assert_eq!(opened.sender, Some(alice.sig.verifying_key()));
}

#[test]
fn another_key_cannot_open() {
    let (alice, bob, carol) = (Side::new(1), Side::new(11), Side::new(21));
    let envelope = seal_to(&bob, &full_content(&alice), Some(&alice), 7);
    assert_eq!(
        open(&envelope, &carol.enc).err(),
        Some(DecodeError::CannotOpen)
    );
}

#[test]
fn a_small_order_enc_cannot_open() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let mut envelope = seal_to(&bob, &full_content(&alice), None, 7);
    envelope[16..48].fill(0);
    assert_eq!(
        open(&envelope, &bob.enc).err(),
        Some(DecodeError::CannotOpen)
    );
}

#[test]
fn hints_follow_the_rule() {
    let bob = Side::new(11);
    let content = Content::new(MessageType::Notice, b"{}".to_vec());
    for (rule, expected) in [
        (HintRule::Contact(&bob.hint), None),
        (
            HintRule::FixedContact(&bob.hint),
            Some(Hint::fixed(&bob.hint)),
        ),
    ] {
        let envelope = seal(
            NET,
            &bob.enc_pk(),
            rule,
            &content,
            None,
            &mut ScriptedRng::seeded(3),
        )
        .unwrap();
        let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
        let expected = expected.unwrap_or_else(|| Hint::contact(&bob.hint, sealed.enc()));
        assert_eq!(sealed.hint(), expected);
    }
    let reply = EncSecretKey::from_bytes([5; 32]);
    let envelope = seal(
        NET,
        &reply.public_key(),
        HintRule::ReplyKey,
        &content,
        None,
        &mut ScriptedRng::seeded(3),
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&envelope, NET).unwrap();
    assert_eq!(
        sealed.hint(),
        Hint::reply(&reply.public_key(), sealed.enc())
    );
    // Two envelopes to the same contact carry unlinkable hints; the fixed hint repeats.
    let other = seal_to(&bob, &content, None, 4);
    let first = seal_to(&bob, &content, None, 3);
    assert_ne!(
        SealedEnvelope::decode(&first, NET).unwrap().hint(),
        SealedEnvelope::decode(&other, NET).unwrap().hint()
    );
}

#[test]
fn seal_refuses_a_card_of_the_other_network_or_signer() {
    let (alice, bob, carol) = (Side::new(1), Side::new(11), Side::new(21));
    let mut content = Content::new(MessageType::Slate, b"{}".to_vec());
    content.card = Some(alice.card("Alice", Network::Mainnet));
    assert_eq!(
        seal(
            NET,
            &bob.enc_pk(),
            HintRule::ReplyKey,
            &content,
            None,
            &mut ScriptedRng::seeded(1)
        ),
        Err(EncodeError::WrongNetwork)
    );
    content.card = Some(alice.card("Alice", NET));
    assert_eq!(
        seal(
            NET,
            &bob.enc_pk(),
            HintRule::ReplyKey,
            &content,
            Some(&carol.sig),
            &mut ScriptedRng::seeded(1)
        ),
        Err(EncodeError::SigningKeyMismatch)
    );
}

#[test]
fn seal_refuses_a_body_longer_than_a_field() {
    let bob = Side::new(11);
    let content = Content::new(MessageType::Slate, vec![b'x'; 65_536]);
    assert_eq!(
        seal(
            NET,
            &bob.enc_pk(),
            HintRule::ReplyKey,
            &content,
            None,
            &mut ScriptedRng::seeded(1)
        ),
        Err(EncodeError::FieldTooLong { tag: 0x02 })
    );
}

// Header rejections.

fn valid_envelope() -> (Side, Vec<u8>) {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let envelope = seal_to(&bob, &full_content(&alice), Some(&alice), 9);
    (bob, envelope)
}

#[test]
fn header_rejections_have_their_own_errors() {
    let (_, envelope) = valid_envelope();
    let with = |index: usize, byte: u8| {
        let mut changed = envelope.clone();
        changed[index] = byte;
        SealedEnvelope::decode(&changed, NET).err()
    };
    assert_eq!(with(0, 0x88), Some(Malformed::Magic.into()));
    assert_eq!(with(4, 2), Some(DecodeError::NewerVersion { found: 2 }));
    assert_eq!(with(4, 0), Some(Malformed::Version { found: 0 }.into()));
    assert_eq!(with(5, 0), Some(DecodeError::WrongNetwork));
    assert_eq!(with(5, 7), Some(Malformed::Network { byte: 7 }.into()));
    assert_eq!(with(6, 2), Some(DecodeError::UnsupportedSuite { suite: 2 }));
    assert_eq!(with(7, 1), Some(Malformed::Flags { flags: 1 }.into()));
    assert_eq!(
        SealedEnvelope::decode(&envelope, Network::Mainnet).err(),
        Some(DecodeError::WrongNetwork)
    );
}

#[test]
fn rejects_truncated_and_oversized_envelopes() {
    let (_, envelope) = valid_envelope();
    for length in [0, 15, 16, 47, 48, 63] {
        assert_eq!(
            SealedEnvelope::decode(&envelope[..length], NET).err(),
            Some(Malformed::Truncated.into()),
            "{length}"
        );
    }
    let huge = vec![0u8; MAX_ENVELOPE_LEN + 1];
    assert_eq!(
        SealedEnvelope::decode(&huge, NET).err(),
        Some(DecodeError::Oversized {
            limit: MAX_ENVELOPE_LEN,
            found: MAX_ENVELOPE_LEN + 1
        })
    );
}

#[test]
fn trailing_bytes_break_the_tag() {
    let (bob, mut envelope) = valid_envelope();
    envelope.push(0);
    assert_eq!(
        open(&envelope, &bob.enc).err(),
        Some(DecodeError::CannotOpen)
    );
}

// Inner content rejections: content sealed as raw bytes, so each rule is reached.

fn header(hint: [u8; 8]) -> [u8; 16] {
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&[0x89, 0x45, 0x53, 0x45]);
    header[4] = 1;
    header[5] = NET.byte();
    header[6] = 1;
    header[8..].copy_from_slice(&hint);
    header
}

fn seal_raw(recipient: &EncPublicKey, header: &[u8; 16], inner: &[u8]) -> Vec<u8> {
    let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient.as_bytes()).unwrap();
    let mut info = b"epic-seal/1".to_vec();
    info.extend_from_slice(&[NET.byte(), 1]);
    let (encapped, ciphertext) =
        hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public,
            &info,
            inner,
            header,
            &mut ScriptedRng::seeded(77),
        )
        .unwrap();
    let mut envelope = header.to_vec();
    envelope.extend_from_slice(&encapped.to_bytes());
    envelope.extend_from_slice(&ciphertext);
    envelope
}

/// Decrypts without checking the content; the test sides' X25519 key is one repeated byte.
fn open_raw(envelope: &[u8], key_byte: u8) -> Vec<u8> {
    let secret = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&[key_byte; 32]).unwrap();
    let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&envelope[16..48]).unwrap();
    let mut info = b"epic-seal/1".to_vec();
    info.extend_from_slice(&[envelope[5], 1]);
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &secret,
        &encapped,
        &info,
        &envelope[48..],
        &envelope[..16],
    )
    .unwrap()
}

fn field(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// `fields`, the sender key, `extensions` (tags from 0x80), then the signature over all of them.
fn signed_with(
    signer: &Side,
    header: &[u8; 16],
    recipient: &EncPublicKey,
    fields: &[u8],
    extensions: &[u8],
) -> Vec<u8> {
    let mut fields = fields.to_vec();
    fields.extend(field(0x08, signer.sig.verifying_key().as_bytes()));
    fields.extend_from_slice(extensions);
    let mut input = b"epic-seal/1 sig".to_vec();
    input.extend_from_slice(header);
    input.extend_from_slice(recipient.as_bytes());
    input.extend_from_slice(&fields);
    fields.extend(field(0xff, &signer.sig.sign(&input).to_bytes()));
    fields
}

fn signed(signer: &Side, header: &[u8; 16], recipient: &EncPublicKey, fields: &[u8]) -> Vec<u8> {
    signed_with(signer, header, recipient, fields, &[])
}

fn open_inner(inner: &[u8]) -> Result<lepic_contact::Opened, DecodeError> {
    let bob = Side::new(11);
    open(&seal_raw(&bob.enc_pk(), &header([0; 8]), inner), &bob.enc)
}

fn minimal() -> Vec<u8> {
    [field(0x01, &[1]), field(0x02, b"{}")].concat()
}

#[test]
fn inner_rejections_have_their_own_errors() {
    let cases: Vec<(Vec<u8>, DecodeError)> = vec![
        (
            field(0x02, b"{}"),
            Malformed::MissingField { tag: 0x01 }.into(),
        ),
        (
            field(0x01, &[1]),
            Malformed::MissingField { tag: 0x02 }.into(),
        ),
        (
            [field(0x01, &[9]), field(0x02, b"{}")].concat(),
            Malformed::FieldValue { tag: 0x01 }.into(),
        ),
        (
            [field(0x01, &[1, 1]), field(0x02, b"{}")].concat(),
            Malformed::FieldLength { tag: 0x01 }.into(),
        ),
        (
            [field(0x02, b"{}"), field(0x01, &[1])].concat(),
            Malformed::FieldOrder { tag: 0x01 }.into(),
        ),
        (
            [minimal(), field(0x09, &[0; 64])].concat(),
            Malformed::UnknownField { tag: 0x09 }.into(),
        ),
        (
            [minimal(), field(0x7f, &[])].concat(),
            Malformed::UnknownField { tag: 0x7f }.into(),
        ),
        (
            [minimal(), field(0x03, &[0; 32])].concat(),
            Malformed::FieldValue { tag: 0x03 }.into(),
        ),
        (
            [minimal(), field(0x04, &[6])].concat(),
            Malformed::FieldValue { tag: 0x04 }.into(),
        ),
        (
            [minimal(), field(0x05, b"a\x07b")].concat(),
            Malformed::FieldValue { tag: 0x05 }.into(),
        ),
        (
            [minimal(), field(0x05, &[0xff])].concat(),
            Malformed::FieldValue { tag: 0x05 }.into(),
        ),
        (
            [minimal(), field(0x06, &[0; 4])].concat(),
            Malformed::FieldLength { tag: 0x06 }.into(),
        ),
        (
            [minimal(), field(0x08, &[0; 32])].concat(),
            Malformed::SenderKeyWithoutSignature.into(),
        ),
        (
            [minimal(), field(0xff, &[0; 64])].concat(),
            Malformed::MissingField { tag: 0x08 }.into(),
        ),
        (
            [minimal(), vec![0x80, 0, 5, 1]].concat(),
            Malformed::Truncated.into(),
        ),
    ];
    for (inner, expected) in cases {
        assert_eq!(open_inner(&inner).err(), Some(expected), "{inner:02x?}");
    }
}

#[test]
fn high_tags_are_skipped_and_signed() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let header = header([0; 8]);
    let extensions = [field(0x90, b"later"), field(0xfe, b"")].concat();
    let inner = signed_with(&alice, &header, &bob.enc_pk(), &minimal(), &extensions);
    let opened = open(&seal_raw(&bob.enc_pk(), &header, &inner), &bob.enc).unwrap();
    assert_eq!(opened.sender, Some(alice.sig.verifying_key()));

    // The extension field is covered: changing it breaks the signature.
    let mut changed = inner.clone();
    let position = changed.windows(5).position(|w| w == b"later").unwrap();
    changed[position] = b'L';
    assert_eq!(
        open(&seal_raw(&bob.enc_pk(), &header, &changed), &bob.enc).err(),
        Some(DecodeError::BadSignature)
    );
}

#[test]
fn a_bad_signature_or_weak_sender_key_is_refused() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let header = header([0; 8]);
    let mut inner = signed(&alice, &header, &bob.enc_pk(), &minimal());
    let last = inner.len() - 1;
    inner[last] ^= 1;
    assert_eq!(
        open(&seal_raw(&bob.enc_pk(), &header, &inner), &bob.enc).err(),
        Some(DecodeError::BadSignature)
    );

    let weak = [minimal(), field(0x08, &[0; 32]), field(0xff, &[0; 64])].concat();
    assert_eq!(
        open_inner(&weak).err(),
        Some(Malformed::FieldValue { tag: 0x08 }.into())
    );
}

#[test]
fn a_signed_card_must_be_the_senders() {
    let (alice, bob, carol) = (Side::new(1), Side::new(11), Side::new(21));
    let header = header([0; 8]);
    let fields = [minimal(), field(0x07, carol.card("Carol", NET).as_bytes())].concat();
    let inner = signed(&alice, &header, &bob.enc_pk(), &fields);
    assert_eq!(
        open(&seal_raw(&bob.enc_pk(), &header, &inner), &bob.enc).err(),
        Some(Malformed::FieldValue { tag: 0x07 }.into())
    );
}

#[test]
fn the_signature_binds_the_recipient() {
    // Bob re-seals Alice's signed content, unchanged, to Carol: Carol must not accept it as
    // Alice's.
    let (alice, bob, carol) = (Side::new(1), Side::new(11), Side::new(21));
    let envelope = seal_to(&bob, &full_content(&alice), Some(&alice), 5);
    let inner = open_raw(&envelope, 11);
    let resealed = seal_raw(&carol.enc_pk(), envelope[..16].try_into().unwrap(), &inner);
    assert_eq!(
        open(&resealed, &carol.enc).err(),
        Some(DecodeError::BadSignature)
    );
}

#[test]
fn the_signature_binds_the_header() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let envelope = seal_to(&bob, &full_content(&alice), Some(&alice), 5);
    let inner = open_raw(&envelope, 11);
    let resealed = seal_raw(&bob.enc_pk(), &header([9; 8]), &inner);
    assert_eq!(
        open(&resealed, &bob.enc).err(),
        Some(DecodeError::BadSignature)
    );
}

// Armor.

#[test]
fn armor_round_trips_and_reads_quoted_text() {
    let (bob, envelope) = valid_envelope();
    let text = armor(&envelope);
    assert!(text.starts_with("BEGINEPICSEALED.\n"));
    assert!(text.ends_with(".\nENDEPICSEALED."));
    assert!(text.lines().all(|line| line.len() <= 76));
    assert!(looks_sealed(&format!("\n  {text}")));
    assert!(!looks_sealed("{\"version_info\":{}}"));
    assert_eq!(dearmor(&text).unwrap(), envelope);

    let quoted: String = text.lines().map(|line| format!("> {line}\r\n")).collect();
    assert_eq!(dearmor(&quoted).unwrap(), envelope);
    let spaced = text.replace('\n', " \t ");
    assert_eq!(
        dearmor(&format!("{spaced} trailing. words")).unwrap(),
        envelope
    );
    let opened = open(&dearmor(&quoted).unwrap(), &bob.enc).unwrap();
    assert_eq!(opened.content.kind, MessageType::Slate);
}

#[test]
fn armor_rejections_have_their_own_errors() {
    let (_, envelope) = valid_envelope();
    let text = armor(&envelope);
    // Swap two payload characters: the base64 stays valid, the checksum does not.
    let mut bytes = text.clone().into_bytes();
    let (a, b) = (20, 21);
    assert_ne!(bytes[a], bytes[b]);
    bytes.swap(a, b);
    assert_eq!(
        dearmor(&String::from_utf8(bytes).unwrap()),
        Err(DecodeError::Damaged)
    );
    assert_eq!(
        dearmor(&text.replace("BEGINEPICSEALED", "BEGINEPICSLATE")),
        Err(Malformed::Framing.into())
    );
    assert_eq!(
        dearmor(&text.replace("ENDEPICSEALED", "END")),
        Err(Malformed::Framing.into())
    );
    assert_eq!(
        dearmor("BEGINEPICSEALED. abc"),
        Err(Malformed::Framing.into())
    );
    assert_eq!(
        dearmor(&format!("{}+{}", &text[..20], &text[21..])),
        Err(Malformed::PayloadText.into())
    );
    let long = "x".repeat(MAX_ARMOR_LEN + 1);
    assert_eq!(
        dearmor(&long),
        Err(DecodeError::Oversized {
            limit: MAX_ARMOR_LEN,
            found: MAX_ARMOR_LEN + 1
        })
    );
}

// Properties.

fn purpose() -> impl Strategy<Value = Option<Purpose>> {
    prop_oneof![
        Just(None),
        Just(Some(Purpose::Payment)),
        Just(Some(Purpose::DepositRequest)),
        Just(Some(Purpose::Withdrawal)),
        Just(Some(Purpose::Refund)),
        Just(Some(Purpose::Request)),
    ]
}

fn kind() -> impl Strategy<Value = MessageType> {
    prop_oneof![
        Just(MessageType::Slate),
        Just(MessageType::Notice),
        Just(MessageType::PairingReply),
        Just(MessageType::PairingConfirm),
        Just(MessageType::ContactUpdate),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn open_inverts_seal(
        kind in kind(),
        body in proptest::collection::vec(any::<u8>(), 0..2048),
        purpose in purpose(),
        expires in proptest::option::of(any::<u64>()),
        reference in proptest::option::of("[a-z0-9-]{1,64}"),
        reply in proptest::option::of(1u8..=255),
        signed in any::<bool>(),
        with_card in any::<bool>(),
        seed in any::<u8>(),
    ) {
        let (alice, bob) = (Side::new(1), Side::new(11));
        let content = Content {
            kind,
            body,
            reply_key: reply.map(|byte| EncSecretKey::from_bytes([byte; 32]).public_key()),
            purpose,
            reference: reference.map(|text| Reference::new(&text).unwrap()),
            expires,
            card: with_card.then(|| alice.card("Alice", NET)),
        };
        let envelope = seal_to(&bob, &content, signed.then_some(&alice), seed);
        let armored = armor(&envelope);
        prop_assert!(armored.len() <= MAX_ARMOR_LEN);
        let opened = open(&dearmor(&armored).unwrap(), &bob.enc).unwrap();
        prop_assert_eq!(opened.content, content);
        prop_assert_eq!(opened.sender, signed.then(|| alice.sig.verifying_key()));
    }

    #[test]
    fn any_single_byte_change_is_refused(
        index in any::<prop::sample::Index>(),
        mask in 1u8..=255,
        signed in any::<bool>(),
    ) {
        let (alice, bob) = (Side::new(1), Side::new(11));
        let mut envelope = seal_to(&bob, &full_content(&alice), signed.then_some(&alice), 1);
        let position = index.index(envelope.len());
        envelope[position] ^= mask;
        prop_assert!(open(&envelope, &bob.enc).is_err());
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let bob = Side::new(11);
        if let Ok(sealed) = SealedEnvelope::decode(&bytes, NET) {
            let _ = sealed.open(&bob.enc);
        }
        let _ = dearmor(&String::from_utf8_lossy(&bytes));
    }
}

#[test]
fn hint_keys_do_not_print() {
    assert_eq!(
        format!("{:?}", HintKey::from_bytes([1; 32])),
        "HintKey(<redacted>)"
    );
}
