//! Replays the RFC 0002 vectors in `testdata/vectors/pairing`, written by the independent pairing
//! kit (RFC 0002 section 14): the HPKE suite against RFC 9180 A.2.1, envelopes of every type sealed
//! with a fixed ephemeral key, cards, invites, replies and confirms, the SAS, pairing words, and
//! every malformed input with the typed error it must give.

// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::HashMap;

use common::{ScriptedRng, hex};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use lepic_contact::{
    ConfirmBody, ConfirmStatus, ContactCard, Content, DecodeError, EncSecretKey, Hint, HintKey,
    HintRule, Invite, InviteId, Malformed, MessageType, Network, Nonce, PairingCode, PairingLink,
    PairingWords, Purpose, ReplyBody, Sas, SealedEnvelope, SigningKey, VerifyingKey, WordsError,
    WordsKey, armor, dearmor, open_confirm, open_contact_update, open_key_check,
    open_key_check_answer, open_reply, pairing_envelope_from_link, pairing_envelope_link, seal,
    seal_confirm, seal_reply,
};
use serde_json::Value;

const KIT_GENERATOR: &str = "epic-pairing-kit";
const KIT_VERSION: &str = "0.2.0";
const KIT_COMMIT: &str = "9e27d32526c68f0e70b225deb3d309fe1d88ce63";

fn vectors(file: &str) -> Vec<Value> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/pairing")
        .join(file);
    let document: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let meta = &document["meta"];
    assert_eq!(meta["generator"], KIT_GENERATOR, "{file}: generator");
    assert_eq!(meta["kit_version"], KIT_VERSION, "{file}: kit version");
    assert_eq!(meta["git_commit"], KIT_COMMIT, "{file}: kit commit");
    assert_eq!(meta["file"], file, "{file}: name");
    let vectors = document["vectors"].as_array().unwrap().clone();
    assert!(!vectors.is_empty(), "{file}: no vectors");
    vectors
}

fn bytes(value: &Value) -> Vec<u8> {
    hex(value.as_str().unwrap_or_else(|| panic!("not hex: {value}")))
}

fn array<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn network(value: &Value) -> Network {
    Network::from_byte(u8::try_from(value.as_u64().unwrap()).unwrap()).unwrap()
}

fn signing_key(value: &Value) -> SigningKey {
    SigningKey::from_bytes(&array(value))
}

fn verifying_key(value: &Value) -> VerifyingKey {
    VerifyingKey::from_bytes(&array(value)).unwrap()
}

fn type_byte(kind: MessageType) -> u8 {
    match kind {
        MessageType::Slate => 1,
        MessageType::Notice => 2,
        MessageType::PairingReply => 3,
        MessageType::PairingConfirm => 4,
        MessageType::ContactUpdate => 5,
        MessageType::KeyCheck => 6,
        MessageType::KeyCheckAnswer => 7,
    }
}

fn purpose_byte(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::Payment => 1,
        Purpose::DepositRequest => 2,
        Purpose::Withdrawal => 3,
        Purpose::Refund => 4,
        Purpose::Request => 5,
    }
}

/// Every Ed25519 seed the kit used, by public key, so cards can be signed again byte for byte.
fn signing_keys() -> HashMap<[u8; 32], SigningKey> {
    let mut keys = HashMap::new();
    for vector in vectors("contact_keys.json") {
        for contact in vector["contacts"].as_array().unwrap() {
            let key = signing_key(&contact["sig_sk"]);
            keys.insert(key.verifying_key().to_bytes(), key);
        }
    }
    keys
}

/// Decodes a card, signs its fields again with the owner's key and checks the bytes and link.
fn check_card(
    card_hex: &Value,
    uri: &Value,
    net: Network,
    keys: &HashMap<[u8; 32], SigningKey>,
) -> ContactCard {
    let card = ContactCard::decode(&bytes(card_hex), net).unwrap();
    let key = keys
        .get(card.sig_key().as_bytes())
        .unwrap_or_else(|| panic!("no signing key for card {card_hex}"));
    let signed = ContactCard::sign(net, card.fields().clone(), key).unwrap();
    assert_eq!(signed.as_bytes(), card.as_bytes(), "card {card_hex}");
    assert_eq!(card.to_link(), text(uri));
    assert_eq!(ContactCard::from_link(text(uri), net).unwrap(), card);
    card
}

#[test]
fn the_suite_matches_rfc9180_a2_1() {
    for vector in vectors("hpke_rfc9180_a2.json") {
        assert_eq!(vector["kem_id"], 32);
        assert_eq!(vector["kdf_id"], 1);
        assert_eq!(vector["aead_id"], 3);
        assert_eq!(vector["mode"], 0);
        let info = bytes(&vector["info"]);

        let (sk_r, pk_r) = X25519HkdfSha256::derive_keypair(&bytes(&vector["ikmR"]));
        assert_eq!(sk_r.to_bytes().to_vec(), bytes(&vector["skRm"]));
        assert_eq!(pk_r.to_bytes().to_vec(), bytes(&vector["pkRm"]));

        // The ephemeral key comes from 32 bytes of the caller's RNG through DeriveKeyPair, so an
        // RNG that yields ikmE reproduces the RFC's encapsulation.
        let mut rng = ScriptedRng::new(&bytes(&vector["ikmE"]));
        let (encapped, mut sender) = hpke::setup_sender_with_rng::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
        >(&OpModeS::Base, &pk_r, &info, &mut rng)
        .unwrap();
        assert_eq!(encapped.to_bytes().to_vec(), bytes(&vector["enc"]));
        let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk_r,
            &encapped,
            &info,
        )
        .unwrap();

        let encryptions = vector["encryptions"].as_array().unwrap();
        let last = encryptions
            .iter()
            .map(|entry| entry["seq"].as_u64().unwrap())
            .max()
            .unwrap();
        let mut checked = 0;
        for sequence in 0..=last {
            let listed = encryptions
                .iter()
                .find(|entry| entry["seq"].as_u64() == Some(sequence));
            let (plaintext, aad) = match listed {
                Some(entry) => (bytes(&entry["pt"]), bytes(&entry["aad"])),
                None => (b"skipped".to_vec(), Vec::new()),
            };
            let ciphertext = sender.seal(&plaintext, &aad).unwrap();
            assert_eq!(receiver.open(&ciphertext, &aad).unwrap(), plaintext);
            if let Some(entry) = listed {
                assert_eq!(ciphertext, bytes(&entry["ct"]), "sequence {sequence}");
                checked += 1;
            }
        }
        assert_eq!(checked, encryptions.len());

        for entry in vector["exports"].as_array().unwrap() {
            let length = usize::try_from(entry["L"].as_u64().unwrap()).unwrap();
            let mut out = vec![0; length];
            sender.export(&bytes(&entry["context"]), &mut out).unwrap();
            assert_eq!(out, bytes(&entry["value"]));
        }

        let first = &encryptions[0];
        let secret =
            <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&bytes(&vector["skRm"])).unwrap();
        let encapped =
            <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&bytes(&vector["enc"])).unwrap();
        let plaintext = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &secret,
            &encapped,
            &info,
            &bytes(&first["ct"]),
            &bytes(&first["aad"]),
        )
        .unwrap();
        assert_eq!(plaintext, bytes(&first["pt"]));
    }
}

fn check_opened(opened: &lepic_contact::Opened, expected: &Value, name: &str) {
    let content = &opened.content;
    assert_eq!(
        expected["type"].as_u64(),
        Some(u64::from(type_byte(content.kind))),
        "{name}"
    );
    assert_eq!(to_hex(&content.body), expected["body"], "{name}");
    assert_eq!(
        content.reply_key.map(|key| to_hex(key.as_bytes())),
        expected["reply_key"].as_str().map(str::to_owned),
        "{name}"
    );
    assert_eq!(
        content
            .purpose
            .map(|purpose| u64::from(purpose_byte(purpose))),
        expected["purpose"].as_u64(),
        "{name}"
    );
    assert_eq!(
        content
            .reference
            .as_ref()
            .map(lepic_contact::Reference::as_str),
        expected["reference"].as_str(),
        "{name}"
    );
    assert_eq!(content.expires, expected["expires"].as_u64(), "{name}");
    assert_eq!(
        content.card.as_ref().map(|card| to_hex(card.as_bytes())),
        expected["card"].as_str().map(str::to_owned),
        "{name}"
    );
    assert_eq!(
        opened.sender.map(|key| to_hex(key.as_bytes())),
        expected["sender_key"].as_str().map(str::to_owned),
        "{name}"
    );
    assert_eq!(
        opened.sender.is_some(),
        expected["signed"].as_bool().unwrap(),
        "{name}"
    );
}

#[test]
fn envelopes_open_and_seal_byte_for_byte() {
    let mut resealed = 0;
    for vector in vectors("envelopes.json") {
        let name = text(&vector["name"]);
        let net = network(&vector["net"]);
        let recipient = EncSecretKey::from_bytes(array(&vector["recipient_enc_sk"]));
        let recipient_pk = recipient.public_key();
        assert_eq!(to_hex(recipient_pk.as_bytes()), vector["recipient_enc_pk"]);
        let (eph_sk, _) = X25519HkdfSha256::derive_keypair(&bytes(&vector["eph_ikm"]));
        assert_eq!(
            eph_sk.to_bytes().to_vec(),
            bytes(&vector["eph_sk"]),
            "{name}"
        );

        let envelope = bytes(&vector["envelope"]);
        let sealed = SealedEnvelope::decode(&envelope, net).unwrap();
        assert_eq!(to_hex(sealed.hint().as_bytes()), vector["hint"], "{name}");
        assert_eq!(to_hex(sealed.enc()), vector["enc"], "{name}");
        assert_eq!(to_hex(&envelope[..16]), vector["header"], "{name}");
        let opened = sealed.open(&recipient).unwrap();
        check_opened(&opened, &vector["opened"], name);

        assert_eq!(
            armor(&envelope),
            text(&vector["armored_wrapped_76"]),
            "{name}"
        );
        for form in ["armored", "armored_wrapped_76", "armored_quoted"] {
            if let Some(armored) = vector[form].as_str() {
                assert_eq!(dearmor(armored).unwrap(), envelope, "{name} {form}");
            }
        }

        let hint_input = bytes(&vector["hint_input"]);
        let hint_key = HintKey::from_bytes(hint_input.clone().try_into().unwrap_or([0; 32]));
        let hint_rule = match text(&vector["hint_kind"]) {
            "contact" => HintRule::Contact(&hint_key),
            "fixed" => HintRule::FixedContact(&hint_key),
            "reply" => {
                assert_eq!(hint_input, recipient_pk.as_bytes());
                HintRule::ReplyKey
            }
            // The same bytes as the pairing reply of `cards_invites.json`, sealed there.
            "invite_id" => continue,
            other => panic!("unknown hint kind {other}"),
        };
        // Fields from 0x80 up are read and ignored; this crate never writes them.
        if !vector["opened"]["ignored_extra"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            continue;
        }
        let signer = vector.get("sender_sig_sk").map(signing_key);
        let content: Content = opened.content.clone();
        let mut rng = ScriptedRng::new(&bytes(&vector["eph_ikm"]));
        let ours = seal(
            net,
            &recipient_pk,
            hint_rule,
            &content,
            signer.as_ref(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(to_hex(&ours), vector["envelope"], "{name}");
        resealed += 1;
    }
    assert!(resealed > 20);
}

#[test]
fn fixed_hints_match_the_kit() {
    for vector in vectors("contact_keys.json") {
        for contact in vector["contacts"].as_array().unwrap() {
            let hint = Hint::fixed(&HintKey::from_bytes(array(&contact["hint_key"])));
            assert_eq!(to_hex(hint.as_bytes()), contact["fixed_hint"]);
        }
    }
}

#[test]
fn cards_sign_and_link_byte_for_byte() {
    let keys = signing_keys();
    let mut cards = 0;
    for vector in vectors("cards_invites.json") {
        if vector["kind"] != "cards" {
            continue;
        }
        let net = network(&vector["net"]);
        for entry in vector["cards"].as_array().unwrap() {
            let card = check_card(&entry["card"], &entry["uri"], net, &keys);
            let fields = card.fields();
            assert_eq!(fields.name.as_str(), entry["fields"]["name"]);
            assert_eq!(u64::from(fields.caps.bits()), entry["fields"]["caps"]);
            assert_eq!(u64::from(fields.seq), entry["fields"]["seq"]);
            cards += 1;
        }
    }
    assert!(cards > 0);
}

#[test]
fn pairings_replay_byte_for_byte() {
    let keys = signing_keys();
    let mut pairings = 0;
    for vector in vectors("cards_invites.json") {
        if vector["kind"] != "pairing" {
            continue;
        }
        let label = text(&vector["label"]);
        let net = network(&vector["net"]);
        let inputs = &vector["inputs"];
        let card_a = check_card(&vector["card_a"], &vector["card_a_uri"], net, &keys);
        let card_b = check_card(&vector["card_b"], &vector["card_b_uri"], net, &keys);
        let inviter_sig = signing_key(&vector["inviter"]["sig_sk"]);
        let inviter_enc = EncSecretKey::from_bytes(array(&vector["inviter"]["enc_sk"]));
        let invitee_enc = EncSecretKey::from_bytes(array(&vector["invitee"]["enc_sk"]));
        assert_eq!(inviter_sig.verifying_key(), *card_a.sig_key(), "{label}");
        assert_eq!(inviter_enc.public_key(), *card_a.enc_key(), "{label}");
        assert_eq!(invitee_enc.public_key(), *card_b.enc_key(), "{label}");

        let code = PairingCode::from_bytes(array(&inputs["code"]));
        let n_a = Nonce::from_bytes(array(&inputs["nA"]));
        let n_b = Nonce::from_bytes(array(&inputs["nB"]));
        let invite = Invite::decode(&bytes(&vector["invite"]), net).unwrap();
        assert_eq!(
            Invite::new(net, invite.fields().clone())
                .unwrap()
                .as_bytes(),
            invite.as_bytes()
        );
        assert_eq!(invite.to_link(), text(&vector["invite_uri"]));
        assert_eq!(
            Invite::from_link(text(&vector["invite_uri"]), net).unwrap(),
            invite
        );
        assert_eq!(invite.fields().code, code);
        assert_eq!(invite.fields().expires, inputs["expires"].as_u64().unwrap());
        assert_eq!(to_hex(invite.fields().commit.as_bytes()), vector["commit"]);
        assert_eq!(
            lepic_contact::Commitment::new(&n_a, &card_a),
            invite.fields().commit
        );
        assert_eq!(invite.fields().enc_key, *card_a.enc_key());
        assert_eq!(
            to_hex(InviteId::from_code(&code).as_bytes()),
            vector["invite_id"]
        );

        let reply_body = ReplyBody {
            code: code.clone(),
            nonce: n_b.clone(),
            confirm_code: lepic_contact::ConfirmCode::from_bytes(array(&inputs["rc"])),
            card: card_b.clone(),
        };
        assert_eq!(
            to_hex(&reply_body.encode()),
            vector["reply_body"],
            "{label}"
        );
        let reply = seal_reply(
            &invite,
            &reply_body,
            &mut ScriptedRng::new(&bytes(&vector["reply_eph_ikm"])),
        )
        .unwrap();
        assert_eq!(to_hex(&reply), vector["reply"], "{label}");
        assert_eq!(dearmor(text(&vector["reply_armored"])).unwrap(), reply);
        assert_eq!(
            pairing_envelope_link(PairingLink::Reply, &reply),
            text(&vector["reply_uri"])
        );
        assert_eq!(
            pairing_envelope_from_link(text(&vector["reply_uri"]), PairingLink::Reply).unwrap(),
            reply
        );
        let sealed = SealedEnvelope::decode(&reply, net).unwrap();
        assert_eq!(
            sealed.hint().as_bytes(),
            InviteId::from_code(&code).as_bytes()
        );
        assert_eq!(open_reply(&sealed, &inviter_enc).unwrap(), reply_body);

        let confirm_body = ConfirmBody {
            nonce: n_a.clone(),
            card: card_a.clone(),
            status: ConfirmStatus::Accepted,
        };
        assert_eq!(
            to_hex(&confirm_body.encode()),
            vector["confirm_body"],
            "{label}"
        );
        let confirm = seal_confirm(
            &card_b,
            &confirm_body,
            &inviter_sig,
            &mut ScriptedRng::new(&bytes(&vector["confirm_eph_ikm"])),
        )
        .unwrap();
        assert_eq!(to_hex(&confirm), vector["confirm"], "{label}");
        assert_eq!(dearmor(text(&vector["confirm_armored"])).unwrap(), confirm);
        assert_eq!(
            pairing_envelope_link(PairingLink::Confirm, &confirm),
            text(&vector["confirm_uri"])
        );
        let opened = open_confirm(
            &SealedEnvelope::decode(&confirm, net).unwrap(),
            &invitee_enc,
        )
        .unwrap();
        assert_eq!(opened, confirm_body);
        assert!(opened.matches_invite(&invite));

        let sas = Sas::compute(net, &card_a, &card_b, &n_a, &n_b);
        assert_eq!(to_hex(sas.as_bytes()), vector["sas"], "{label}");
        pairings += 1;
    }
    assert!(pairings > 0);
}

#[test]
fn sas_matches_the_kit() {
    for vector in vectors("sas.json") {
        let name = text(&vector["name"]);
        let net = network(&vector["net"]);
        let card = |key: &str| ContactCard::decode(&bytes(&vector[key]), net).unwrap();
        let sas = if vector.get("card_1").is_some() {
            let (first, second) = (card("card_1"), card("card_2"));
            let sas = Sas::in_person(net, &first, &second);
            assert_eq!(sas, Sas::in_person(net, &second, &first), "{name}");
            assert_eq!(vector["nA"], "00".repeat(16));
            assert_eq!(vector["nB"], "00".repeat(16));
            sas
        } else {
            Sas::compute(
                net,
                &card("card_a"),
                &card("card_b"),
                &Nonce::from_bytes(array(&vector["nA"])),
                &Nonce::from_bytes(array(&vector["nB"])),
            )
        };
        assert_eq!(to_hex(sas.as_bytes()), vector["sas"], "{name}");
        let symbols = sas.symbols().unwrap();
        for (index, entry) in symbols.iter().enumerate() {
            assert_eq!(entry.emoji, vector["emoji"][index], "{name}");
            assert_eq!(entry.name, vector["names"][index], "{name}");
        }
    }
}

#[test]
fn pairing_words_match_the_kit() {
    for vector in vectors("words.json") {
        let name = text(&vector["name"]);
        let net = network(&vector["net"]);
        let words = PairingWords::from_bytes(array(&vector["words"]));
        let symbols = words.symbols().unwrap();
        for (index, entry) in symbols.iter().enumerate() {
            assert_eq!(entry.emoji, vector["emoji"][index], "{name}");
            assert_eq!(entry.name, vector["names"][index], "{name}");
        }
        let names: Vec<&str> = symbols.iter().map(|entry| entry.name).collect();
        let emoji: Vec<&str> = symbols.iter().map(|entry| entry.emoji).collect();
        assert_eq!(PairingWords::parse(&names).unwrap(), words);
        assert_eq!(PairingWords::parse(&emoji).unwrap(), words);

        let argon2 = &vector["argon2id"];
        assert_eq!(argon2["iterations"], 3);
        assert_eq!(argon2["memory_kib"], 65_536);
        assert_eq!(argon2["lanes"], 1);
        assert_eq!(argon2["version"], 19);
        assert_eq!(argon2["length"], 32);
        assert_eq!(argon2["salt"], vector["aad"]);
        let key = words.stretch(net).unwrap();
        assert_eq!(to_hex(key.expose_bytes()), vector["k"], "{name}");
        assert_eq!(
            to_hex(&*key.mailbox_seed()),
            vector["mailbox_seed"],
            "{name}"
        );

        let invite = Invite::decode(&bytes(&vector["invite"]), net).unwrap();
        assert_eq!(
            key.seal_invite(&invite).unwrap(),
            text(&vector["posted"]),
            "{name}"
        );
        assert_eq!(
            key.open_invite(net, text(&vector["posted"])).unwrap(),
            invite.as_bytes()
        );
    }
}

/// Whether `error` is the typed error LEPIC gives for the kit's error code `code`.
fn decode_error_matches(code: &str, error: &DecodeError) -> bool {
    use DecodeError as D;
    use Malformed as M;
    match code {
        "truncated" | "tlv_truncated" => matches!(error, D::Malformed(M::Truncated)),
        "too_large" | "armor_too_large" | "uri_too_large" => {
            matches!(error, D::Oversized { .. })
        }
        "bad_magic" => matches!(error, D::Malformed(M::Magic)),
        "unknown_version"
        | "card_unknown_format"
        | "invite_unknown_format"
        | "uri_newer_version" => matches!(
            error,
            D::NewerVersion { .. } | D::Malformed(M::Version { .. })
        ),
        "wrong_network" => matches!(error, D::WrongNetwork | D::Malformed(M::Network { .. })),
        "unknown_suite" => matches!(error, D::UnsupportedSuite { .. }),
        "bad_flags" => matches!(error, D::Malformed(M::Flags { .. })),
        "cannot_open" => matches!(error, D::CannotOpen),
        "key_changed" => matches!(error, D::KeyChanged),
        "bad_signature" | "card_bad_signature" => matches!(error, D::BadSignature),
        "missing_sender_key" => matches!(error, D::Malformed(M::MissingField { tag: 0x08 })),
        "tlv_missing_field" | "card_missing_field" | "invite_missing_field" => {
            matches!(error, D::Malformed(M::MissingField { .. }))
        }
        "tlv_order" => matches!(
            error,
            D::Malformed(M::FieldOrder { .. } | M::FieldAfterSignature)
        ),
        "signature_not_last" => matches!(
            error,
            D::Malformed(M::FieldAfterSignature | M::FieldOrder { .. })
        ),
        "tlv_unknown_tag" => matches!(error, D::Malformed(M::UnknownField { .. })),
        "tlv_bad_value" | "card_bad_value" | "invite_bad_value" => matches!(
            error,
            D::Malformed(M::FieldValue { .. } | M::FieldLength { .. })
        ),
        "armor_framing" => matches!(error, D::Malformed(M::Framing)),
        "armor_encoding" | "uri_encoding" => matches!(error, D::Malformed(M::PayloadText)),
        // Fewer than the four checksum bytes is truncation here; the kit folds it into the
        // checksum error.
        "armor_checksum" | "uri_checksum" => {
            matches!(error, D::Damaged | D::Malformed(M::Truncated))
        }
        "uri_prefix" => matches!(error, D::Malformed(M::LinkPrefix)),
        "key_check_bad" => matches!(
            error,
            D::Malformed(M::Unsigned { .. } | M::Body | M::FieldValue { tag: 0x01 })
        ),
        _ => false,
    }
}

fn malformed_input(vector: &Value) -> (Vec<u8>, String) {
    if let Some(hex) = vector["input_hex"].as_str() {
        return (common::hex(hex), String::new());
    }
    if let Some(text) = vector["input_text"].as_str() {
        return (Vec::new(), text.to_owned());
    }
    for (key, generator) in vector.as_object().unwrap() {
        if !key.ends_with("_generate") {
            continue;
        }
        let count = usize::try_from(generator["count"].as_u64().unwrap()).unwrap();
        let prefix = generator["prefix"].as_str().unwrap_or("");
        let suffix = generator["suffix"].as_str().unwrap_or("");
        if let Some(byte) = generator["byte"].as_str() {
            return (common::hex(byte).repeat(count), String::new());
        }
        let fill = generator["fill"].as_str().unwrap();
        if key == "input_text_generate" {
            return (
                Vec::new(),
                format!("{prefix}{}{suffix}", fill.repeat(count)),
            );
        }
        let mut input = common::hex(prefix);
        input.extend(common::hex(fill).repeat(count));
        input.extend(common::hex(suffix));
        return (input, String::new());
    }
    panic!("no input in {vector}");
}

fn open_malformed(vector: &Value, input: &[u8], text: &str) -> DecodeError {
    let net = network(&vector["net"]);
    let key = || EncSecretKey::from_bytes(array(&vector["recipient_enc_sk"]));
    let sealed = || SealedEnvelope::decode(input, net);
    let peer = || verifying_key(&vector["peer_sig_pk"]);
    let outcome: Result<(), DecodeError> = match text_kind(vector) {
        "envelope_header" => sealed().map(drop),
        "envelope_open" => sealed().and_then(|sealed| match vector.get("expected_sender") {
            Some(expected) => sealed.open_from(&key(), &verifying_key(expected)).map(drop),
            None => sealed.open(&key()).map(drop),
        }),
        "armor" => dearmor(text).map(drop),
        "card" => ContactCard::decode(input, net).map(drop),
        "invite" => Invite::decode(input, net).map(drop),
        "uri_contact" => ContactCard::from_link(text, net).map(drop),
        "uri_pair" => Invite::from_link(text, net).map(drop),
        "key_check" => {
            sealed().and_then(|sealed| open_key_check(&sealed, &key(), &peer()).map(drop))
        }
        "key_check_answer" => {
            sealed().and_then(|sealed| open_key_check_answer(&sealed, &key(), &peer()).map(drop))
        }
        "contact_update" => {
            sealed().and_then(|sealed| open_contact_update(&sealed, &key(), &peer()).map(drop))
        }
        other => panic!("unknown malformed kind {other}"),
    };
    outcome
        .err()
        .unwrap_or_else(|| panic!("{} was accepted", vector["name"]))
}

fn text_kind(vector: &Value) -> &str {
    vector["kind"].as_str().unwrap()
}

#[test]
fn every_malformed_input_gives_its_typed_error() {
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for vector in vectors("malformed.json") {
        let name = text(&vector["name"]);
        let code = text(&vector["expected_error"]);
        let (input, input_text) = malformed_input(&vector);
        if text_kind(&vector) == "words_open" {
            assert_eq!(code, "words_cannot_open", "{name}");
            let net = network(&vector["net"]);
            let words = PairingWords::from_bytes(array(&vector["words"]));
            let error = words
                .stretch(net)
                .unwrap()
                .open_invite(net, &input_text)
                .unwrap_err();
            assert_eq!(error, WordsError::CannotOpen, "{name}");
        } else {
            let error = open_malformed(&vector, &input, &input_text);
            if !decode_error_matches(code, &error) {
                mismatches.push(format!("{name}: kit says {code}, LEPIC gave {error:?}"));
            }
        }
        checked += 1;
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert!(checked > 80);
}

#[test]
fn posted_text_over_the_limit_is_not_opened() {
    let key = WordsKey::from_bytes([7; 32]);
    let too_long = "A".repeat(lepic_contact::MAX_POSTED_LEN + 1);
    assert_eq!(
        key.open_invite(Network::Mainnet, &too_long).unwrap_err(),
        WordsError::CannotOpen
    );
}
