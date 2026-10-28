// SPDX-License-Identifier: Apache-2.0
//! Replays the RFC 0002 vectors in `testdata/vectors/pairing`, written by the independent pairing
//! kit (RFC 0002 section 14): the HPKE suite against RFC 9180 A.2.1, envelopes of every type sealed
//! with a fixed ephemeral key, cards, invites, replies, confirms and refusals, the SAS, pairing
//! words, the key check with its proofs, and every malformed input with the typed error it must
//! give.

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
    Confirm, ConfirmBody, ContactCard, Content, DecodeError, EncSecretKey, Hint, HintKey, HintRule,
    Invite, InviteId, KeyCheck, KeyCheckAnswer, Malformed, MessageType, Network, Nonce,
    PairingCode, PairingLink, PairingWords, Purpose, Refusal, ReplyBody, Sas, SealedEnvelope,
    SigningKey, VerifyingKey, WordsError, WordsKey, WordsWindow, accept_found, accept_restored,
    armor, dearmor, key_check_tag, open_confirm, open_contact_update, open_key_check,
    open_key_check_answer, open_reply, pairing_envelope_from_link, pairing_envelope_link, seal,
    seal_confirm, seal_found, seal_key_check, seal_not_found, seal_refusal, seal_reply,
    seal_restored,
};
use serde_json::Value;

const KIT_GENERATOR: &str = "epic-pairing-kit";
const KIT_VERSION: &str = "0.3.0";
const KIT_COMMIT: &str = "8e79dc1262691c95a08ede386ca96efd28b803c4";

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
        MessageType::AppPayload => 0x40,
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
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn pairings_replay_byte_for_byte() {
    let keys = signing_keys();
    let mut pairings = 0;
    let mut refusals = 0;
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
        assert_eq!(opened, Confirm::Accepted(Box::new(confirm_body.clone())));
        assert!(confirm_body.matches_invite(&invite));

        // The refusal of envelopes.json is sealed to the person scenario's invitee.
        if label == "person" {
            let record = envelope_vector("confirm_refusal_used_anonymous", net);
            let refusal = seal_refusal(
                &card_b,
                Refusal::AlreadyUsed,
                &mut ScriptedRng::new(&bytes(&record["eph_ikm"])),
            )
            .unwrap();
            assert_eq!(to_hex(&refusal), record["envelope"], "{label}");
            assert_eq!(
                open_confirm(
                    &SealedEnvelope::decode(&refusal, net).unwrap(),
                    &invitee_enc
                )
                .unwrap(),
                Confirm::Refused(Refusal::AlreadyUsed)
            );
            refusals += 1;
        }

        let sas = Sas::compute(net, &card_a, &card_b, &n_a, &n_b);
        assert_eq!(to_hex(sas.as_bytes()), vector["sas"], "{label}");
        pairings += 1;
    }
    assert!(pairings > 0);
    assert_eq!(refusals, 2, "one refusal per network");
}

fn envelope_vector(name: &str, net: Network) -> Value {
    vectors("envelopes.json")
        .into_iter()
        .find(|vector| vector["name"] == name && network(&vector["net"]) == net)
        .unwrap_or_else(|| panic!("no envelope {name}"))
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
        let window = WordsWindow::from_value(vector["window"].as_u64().unwrap());
        let unix = vector["unix"].as_u64().unwrap();
        assert_eq!(WordsWindow::at(unix), window, "{name}");
        assert_eq!(WordsWindow::to_try(unix).next(), Some(window), "{name}");
        let salt = format!(
            "{}{}",
            text(&vector["aad"]),
            to_hex(&window.value().to_be_bytes())
        );
        assert_eq!(argon2["salt"], salt, "{name}");
        let key = words.stretch(net, window).unwrap();
        assert_eq!(to_hex(key.expose_bytes()), vector["k"], "{name}");
        assert_eq!(
            to_hex(&*key.mailbox_seed()),
            vector["mailbox_seed"],
            "{name}"
        );

        let invite = Invite::decode(&bytes(&vector["invite"]), net).unwrap();
        let nonce = bytes(&vector["nonce"]);
        assert_eq!(nonce.len(), 12);
        let posted = key
            .seal_invite(&invite, &mut ScriptedRng::new(&nonce))
            .unwrap();
        assert_eq!(posted, text(&vector["posted"]), "{name}");
        assert_eq!(
            key.open_invite(net, text(&vector["posted"])).unwrap(),
            invite.as_bytes()
        );
        // The invite opens only with the key of the window it was made in.
        let before = WordsWindow::from_value(window.value() - 1);
        assert_eq!(
            words
                .stretch(net, before)
                .unwrap()
                .open_invite(net, &posted),
            Err(WordsError::CannotOpen)
        );
    }
}

/// The contact root the kit recorded for a raw account key on a network.
fn contact_root(raw: &Value, net: &Value) -> [u8; 32] {
    let vector = vectors("contact_keys.json")
        .into_iter()
        .find(|vector| vector["raw"] == *raw && vector["net"] == *net)
        .unwrap_or_else(|| panic!("no root for {raw} on {net}"));
    array(&vector["root"])
}

/// `HKDF-Expand(prk, info, 32)`: the first block, `HMAC(prk, info || 01)`.
fn expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(prk).unwrap();
    mac.update(info);
    mac.update(&[1]);
    mac.finalize().into_bytes().into()
}

/// The enc secret, signing key and hint key of `slot` under `root` (RFC 0002 2.2).
fn slot_keys(root: &[u8; 32], slot: &Value) -> (EncSecretKey, SigningKey, HintKey) {
    let slot = u32::try_from(slot.as_u64().unwrap()).unwrap().to_be_bytes();
    let derive = |label: &[u8]| expand(root, &[label, &slot].concat());
    (
        EncSecretKey::from_bytes(derive(b"enc")),
        SigningKey::from_bytes(&derive(b"sig")),
        HintKey::from_bytes(derive(b"hint")),
    )
}

/// The ikm the kit draws a named case's ephemeral key from, checked against the recorded key.
fn eph_rng(case: &str, net: &Value, recorded_sk: &Value) -> ScriptedRng {
    use sha2::Digest;
    let net = u8::try_from(net.as_u64().unwrap()).unwrap();
    let ikm: [u8; 32] = sha2::Sha256::new()
        .chain_update(b"epic-vectors/1 eph ")
        .chain_update(case.as_bytes())
        .chain_update([net])
        .finalize()
        .into();
    let (sk, _) = X25519HkdfSha256::derive_keypair(&ikm);
    assert_eq!(sk.to_bytes().to_vec(), bytes(recorded_sk), "{case}");
    ScriptedRng::new(&ikm)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// The kit's key check between X and Y, end to end: every envelope sealed again byte for byte
/// with the kit's ephemeral keys, opened by the other side, and every proof accepted.
#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn key_checks_replay_byte_for_byte() {
    let mut checked = 0;
    for vector in vectors("keycheck.json") {
        let net_value = &vector["net"];
        let net = network(net_value);
        let root_x = contact_root(&vector["x_raw"], net_value);
        let root_y = contact_root(&vector["y_raw"], net_value);
        let (x_new_enc, x_new_sig, _) = slot_keys(&root_x, &vector["x_new_slot"]);
        let (_, x_old_sig, _) = slot_keys(&root_x, &vector["x_old_slot"]);
        let (y_new_enc, y_new_sig, _) = slot_keys(&root_y, &vector["y_new_slot"]);
        let (_, y_old_sig, y_old_hint) = slot_keys(&root_y, &vector["y_old_slot"]);
        let card = |key: &str| ContactCard::decode(&bytes(&vector[key]), net).unwrap();
        let (x_old_card, x_new_card) = (card("x_old_card"), card("x_new_card"));
        let (y_old_card, y_new_card) = (card("y_old_card"), card("y_new_card"));
        let y_refreshed = card("y_refreshed_card");
        assert_eq!(*x_old_card.sig_key(), x_old_sig.verifying_key());
        assert_eq!(*y_old_card.sig_key(), y_old_sig.verifying_key());
        assert_eq!(x_new_card.enc_key(), &x_new_enc.public_key());
        assert_eq!(y_new_card.enc_key(), &y_new_enc.public_key());
        assert_eq!(y_old_card.fields().hint_key, y_old_hint);
        assert_eq!(y_old_card.fields().seq, 3);
        assert_eq!(y_refreshed.fields().seq, 4);

        let (n_x, n_y) = (x_new_sig.verifying_key(), y_new_sig.verifying_key());
        assert_eq!(*x_new_card.sig_key(), n_x);
        assert_eq!(*y_new_card.sig_key(), n_y);
        assert_eq!(to_hex(n_x.as_bytes()), vector["nX"]);
        assert_eq!(to_hex(n_y.as_bytes()), vector["nY"]);
        let tag = key_check_tag(&y_old_hint, &n_y, &n_x);
        assert_eq!(to_hex(&tag), vector["tag"]);
        assert_eq!(vector["found_slot"], vector["y_old_slot"]);

        // 1. X checks.
        let eph = &vector["eph"];
        let check = seal_key_check(
            &y_new_card,
            &y_old_card,
            &x_new_sig,
            &mut eph_rng("keycheck/check", net_value, &eph["check"]),
        )
        .unwrap();
        assert_eq!(to_hex(&check), vector["check"]);
        let opened = open_key_check(
            &SealedEnvelope::decode(&check, net).unwrap(),
            &y_new_enc,
            &n_x,
        )
        .unwrap();
        assert_eq!(opened, KeyCheck { seq: 3, tag });
        assert_eq!(to_hex(&opened.encode()), vector["check_body"]);

        // 3. Y found the slot and proves it with the old slot key.
        let found = seal_found(
            &x_new_card,
            &y_new_sig,
            &check,
            &y_refreshed,
            &y_old_sig,
            &mut eph_rng("keycheck/found", net_value, &eph["found"]),
        )
        .unwrap();
        assert_eq!(to_hex(&found), vector["found"]);
        let answer = open_key_check_answer(
            &SealedEnvelope::decode(&found, net).unwrap(),
            &x_new_enc,
            &n_y,
        )
        .unwrap();
        let KeyCheckAnswer::Found(proof) = &answer else {
            panic!("not a found answer: {answer:?}");
        };
        assert_eq!(proof.card_bytes(), y_refreshed.as_bytes());
        assert_eq!(to_hex(proof.proof()), vector["found_proof"]);
        let found_message = [
            &b"epic-pair/1 keycheck found"[..],
            &sha256(&check),
            n_y.as_bytes(),
            n_x.as_bytes(),
            &sha256(y_refreshed.as_bytes()),
        ]
        .concat();
        assert_eq!(to_hex(&found_message), vector["found_message"]);

        // 4. X accepts it.
        assert_eq!(
            accept_found(&answer, &check, &n_y, &n_x, &y_old_card).unwrap(),
            y_refreshed
        );

        // 5. X answers restored with its old card and a proof by its old key.
        let restored = seal_restored(
            &y_new_card,
            &x_new_sig,
            &found,
            &x_old_card,
            &x_old_sig,
            &mut eph_rng("keycheck/restored", net_value, &eph["restored"]),
        )
        .unwrap();
        assert_eq!(to_hex(&restored), vector["restored"]);
        let answer = open_key_check_answer(
            &SealedEnvelope::decode(&restored, net).unwrap(),
            &y_new_enc,
            &n_x,
        )
        .unwrap();
        let KeyCheckAnswer::Restored(proof) = &answer else {
            panic!("not a restored answer: {answer:?}");
        };
        assert_eq!(to_hex(proof.proof()), vector["restored_proof"]);
        let restored_message = [
            &b"epic-pair/1 keycheck restored"[..],
            &sha256(&found),
            n_x.as_bytes(),
            n_y.as_bytes(),
            &sha256(x_old_card.as_bytes()),
        ]
        .concat();
        assert_eq!(to_hex(&restored_message), vector["restored_message"]);

        // 6. Y accepts it.
        assert_eq!(
            accept_restored(&answer, &found, &n_x, &n_y, net).unwrap(),
            x_old_card
        );

        // Or: Y did not find the slot.
        let not_found = seal_not_found(
            &x_new_card,
            &y_new_sig,
            &mut eph_rng("keycheck/not_found", net_value, &eph["not_found"]),
        )
        .unwrap();
        assert_eq!(to_hex(&not_found), vector["not_found"]);
        assert_eq!(
            open_key_check_answer(
                &SealedEnvelope::decode(&not_found, net).unwrap(),
                &x_new_enc,
                &n_y
            )
            .unwrap(),
            KeyCheckAnswer::NotFound
        );
        checked += 1;
    }
    assert_eq!(checked, 2);
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
            D::KeyCheckNotProven
                | D::Malformed(M::Unsigned { .. } | M::Body | M::FieldValue { tag: 0x01 })
        ),
        "reply_bad" => matches!(
            error,
            D::Malformed(M::Body | M::Signed { .. } | M::Unsigned { .. })
        ),
        "weak_sig_key" => matches!(error, D::WeakSigKey),
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
        "confirm" => sealed().and_then(|sealed| open_confirm(&sealed, &key()).map(drop)),
        other => panic!("unknown malformed kind {other}"),
    };
    outcome
        .err()
        .unwrap_or_else(|| panic!("{} was accepted", vector["name"]))
}

/// The window the kit's malformed words cases use unless they name another.
fn words_vector_window() -> u64 {
    vectors("words.json")[0]["window"].as_u64().unwrap()
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
            let window = vector
                .get("window")
                .map_or(words_vector_window(), |window| window.as_u64().unwrap());
            let error = words
                .stretch(net, WordsWindow::from_value(window))
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
