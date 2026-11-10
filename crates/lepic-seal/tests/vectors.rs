// SPDX-License-Identifier: Apache-2.0
//! Replays the envelope vectors in `testdata/vectors/pairing` that belong to the format alone,
//! written by the independent pairing kit: the HPKE suite against RFC 9180 A.2.1, and the RFC
//! 0003 envelopes of type 0A with their key classes, padding, the reply mailbox, the EPICTX
//! armor, the payment file classifier and every malformed input with the typed error it must
//! give.

// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{ScriptedRng, hex, to_hex};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use lepic_seal::{
    ArmorMarker, ClassifyError, DecodeError, EncSecretKey, EncodeError, HintKey, HintRule,
    KeyClass, MAX_BODY_LEN, Malformed, MessageType, NATIVE_SLATE, Network, PaymentFile,
    ReplyMailbox, SUITE, SealedEnvelope, SigningKey, TxContent, TxKey, TxOpened, armor, armor_tx,
    classify, dearmor, dearmor_marked, pad_target, padme, seal_padded, seal_tx,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const KIT_GENERATOR: &str = "epic-pairing-kit";
const KIT_VERSION: &str = "0.5.0";
const KIT_COMMIT: &str = "c506876dae4fe8ec8efa304c3a9967fb41dc6e90";

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

fn size(value: &Value) -> usize {
    usize::try_from(value.as_u64().unwrap()).unwrap()
}

fn network(value: &Value) -> Network {
    Network::from_byte(u8::try_from(value.as_u64().unwrap()).unwrap()).unwrap()
}

fn key_class(value: &Value) -> KeyClass {
    match text(value) {
        "seal" => KeyClass::Seal,
        "epic1" => KeyClass::Epic1,
        "listener" => KeyClass::Listener,
        "epicbox" => KeyClass::Epicbox,
        other => panic!("unknown key class {other}"),
    }
}

fn sha256(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// A body of `count` bytes `i & 0xFF`, as the kit writes `body_generate`.
fn generated_body(spec: &Value) -> Vec<u8> {
    (0..size(&spec["count"]))
        .map(|at| u8::try_from(at & 0xff).unwrap())
        .collect()
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
            let length = size(&entry["L"]);
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

#[test]
fn padding_targets_match_the_kit() {
    for vector in vectors("epictx_padding.json") {
        let length = size(&vector["length"]);
        assert_eq!(padme(length), size(&vector["padme"]), "padme({length})");
        assert_eq!(pad_target(length), size(&vector["target"]), "{length}");
        assert_eq!(
            pad_target(length) - length,
            size(&vector["padding_length"]),
            "{length}"
        );
    }
}

#[test]
fn reply_mailboxes_match_the_kit() {
    for vector in vectors("epictx_reply_mailbox.json") {
        let name = text(&vector["name"]);
        let value = bytes(&vector["value"]);
        assert_eq!(value.len(), size(&vector["length"]), "{name}");
        let parsed = ReplyMailbox::from_bytes(&value);
        assert_eq!(parsed.is_ok(), vector["valid"].as_bool().unwrap(), "{name}");
        if let Ok(mailbox) = parsed {
            assert_eq!(mailbox.to_bytes(), value, "{name}");
            assert_eq!(
                ReplyMailbox::new(*mailbox.key(), mailbox.relay()).unwrap(),
                mailbox
            );
        } else {
            assert_eq!(
                parsed.err(),
                Some(Malformed::FieldValue { tag: 0x09 }),
                "{name}"
            );
        }
    }
}

fn check_tx_opened(opened: &TxOpened, expected: &Value, name: &str) {
    let content = &opened.content;
    assert_eq!(expected["type"], u64::from(NATIVE_SLATE), "{name}");
    if let Some(body) = expected["body"].as_str() {
        assert_eq!(to_hex(&content.body), body, "{name}");
    }
    assert_eq!(
        content.reply_key.map(|key| to_hex(key.as_bytes())),
        expected["reply_key"].as_str().map(str::to_owned),
        "{name}"
    );
    assert_eq!(
        content
            .reply_mailbox
            .as_ref()
            .map(|mailbox| to_hex(&mailbox.to_bytes())),
        expected["reply_mailbox"].as_str().map(str::to_owned),
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

fn tx_key(class: KeyClass, rule: Option<HintRule<'_>>) -> TxKey<'_> {
    match class {
        KeyClass::Epic1 => TxKey::Epic1,
        KeyClass::Listener => TxKey::Listener,
        KeyClass::Epicbox => TxKey::Epicbox,
        KeyClass::Seal => TxKey::Seal(rule.unwrap()),
    }
}

/// The hint rule of a vector, checked against the input the kit names.
fn hint_rule<'a>(
    vector: &Value,
    hint_key: &'a HintKey,
    recipient_pk: &lepic_seal::EncPublicKey,
) -> Option<HintRule<'a>> {
    let hint_input = bytes(&vector["hint_input"]);
    match text(&vector["hint_kind"]) {
        "contact" => Some(HintRule::Contact(hint_key)),
        "reply" => {
            assert_eq!(hint_input, recipient_pk.as_bytes());
            Some(HintRule::ReplyKey)
        }
        "zero" => {
            assert_eq!(hint_input, [0; 8]);
            None
        }
        other => panic!("unknown hint kind {other}"),
    }
}

/// A type 0A opens only with the tx reader and its key class; a padded slate of RFC 0002 opens
/// with the RFC 0002 reader, which skips tag FE as an extension, and is not a type 0A.
fn check_opens(
    vector: &Value,
    sealed: &SealedEnvelope<'_>,
    recipient: &EncSecretKey,
    class: KeyClass,
    name: &str,
) {
    let expected = &vector["opened"];
    let unpadded = size(&vector["unpadded_length"]);
    if expected["type"].as_u64() == Some(u64::from(NATIVE_SLATE)) {
        let opened = sealed.open_tx(recipient, class).unwrap();
        check_tx_opened(&opened, expected, name);
        assert_eq!(
            opened.padding,
            Some(size(&vector["padding_length"])),
            "{name}"
        );
        assert_eq!(opened.inner_len, pad_target(unpadded), "{name}");
        // The RFC 0002 reader knows no type 0A.
        let refused = if class == KeyClass::Seal {
            Malformed::FieldValue { tag: 0x01 }.into()
        } else {
            DecodeError::CannotOpen
        };
        assert_eq!(sealed.open(recipient).err(), Some(refused), "{name}");
    } else {
        let opened = sealed.open(recipient).unwrap();
        assert_eq!(opened.content.kind, MessageType::Slate, "{name}");
        assert_eq!(to_hex(&opened.content.body), expected["body"], "{name}");
        assert_eq!(
            opened.sender.map(|key| to_hex(key.as_bytes())),
            expected["sender_key"].as_str().map(str::to_owned),
            "{name}"
        );
        assert_eq!(
            sealed.open_tx(recipient, class).err(),
            Some(Malformed::FieldValue { tag: 0x01 }.into()),
            "{name}"
        );
    }
}

/// Every armored form of a vector gives its envelope and marker.
fn check_armor(vector: &Value, envelope: &[u8], name: &str) {
    let Some(wrapped) = vector["armored_wrapped_76"].as_str() else {
        return;
    };
    let marker = match text(&vector["armor_marker"]) {
        "tx" => ArmorMarker::Tx,
        "sealed" => ArmorMarker::Sealed,
        other => panic!("unknown marker {other}"),
    };
    let armored = match marker {
        ArmorMarker::Tx => armor_tx(envelope),
        ArmorMarker::Sealed => armor(envelope),
    };
    assert_eq!(armored, wrapped, "{name}");
    let native = vector["opened"]["type"].as_u64() == Some(u64::from(NATIVE_SLATE));
    assert_eq!(native, marker == ArmorMarker::Tx, "{name}");
    for form in ["armored", "armored_wrapped_76", "armored_quoted"] {
        assert_eq!(
            dearmor_marked(text(&vector[form])).unwrap(),
            (envelope.to_vec(), marker),
            "{name} {form}"
        );
    }
    assert_eq!(
        dearmor(text(&vector["armored_other_marker"])).unwrap(),
        envelope,
        "{name}"
    );
}

/// Seals the opened content again from the vector's ephemeral key.
fn reseal(
    vector: &Value,
    sealed: &SealedEnvelope<'_>,
    recipient: &EncSecretKey,
    class: KeyClass,
    rule: Option<HintRule<'_>>,
) -> Vec<u8> {
    let net = network(&vector["net"]);
    let recipient_pk = recipient.public_key();
    let signer = vector
        .get("sender_sig_sk")
        .map(|seed| SigningKey::from_bytes(&array(seed)));
    let mut rng = ScriptedRng::new(&bytes(&vector["eph_ikm"]));
    if vector["opened"]["type"].as_u64() == Some(u64::from(NATIVE_SLATE)) {
        let content = sealed.open_tx(recipient, class).unwrap().content;
        let key = tx_key(class, rule);
        seal_tx(net, &recipient_pk, key, &content, signer.as_ref(), &mut rng).unwrap()
    } else {
        let content = sealed.open(recipient).unwrap().content;
        // The kit's slates are the padded form of RFC 0003 5.7.
        seal_padded(
            net,
            &recipient_pk,
            rule.unwrap(),
            &content,
            signer.as_ref(),
            &mut rng,
        )
        .unwrap()
    }
}

/// Every envelope opens with its key class, every armored form gives the same bytes, and every
/// one this crate can write is sealed again byte for byte from the same ephemeral key.
#[test]
fn epictx_envelopes_open_and_seal_byte_for_byte() {
    let mut opened_count = 0;
    let mut resealed = 0;
    for vector in vectors("epictx_envelopes.json") {
        let name = text(&vector["name"]);
        let net = network(&vector["net"]);
        let class = key_class(&vector["key_class"]);
        assert_eq!(to_hex(&class.info(net, SUITE)), vector["info"], "{name}");
        let recipient = EncSecretKey::from_bytes(array(&vector["recipient_enc_sk"]));
        let recipient_pk = recipient.public_key();
        assert_eq!(to_hex(recipient_pk.as_bytes()), vector["recipient_enc_pk"]);
        let (eph_sk, _) = X25519HkdfSha256::derive_keypair(&bytes(&vector["eph_ikm"]));
        assert_eq!(
            eph_sk.to_bytes().to_vec(),
            bytes(&vector["eph_sk"]),
            "{name}"
        );
        let unpadded = size(&vector["unpadded_length"]);
        let padding = size(&vector["padding_length"]);
        assert_eq!(unpadded + padding, pad_target(unpadded), "{name}");
        assert_eq!(
            size(&vector["inner_length"]),
            pad_target(unpadded),
            "{name}"
        );
        let expected = &vector["opened"];
        let hint_key =
            HintKey::from_bytes(bytes(&vector["hint_input"]).try_into().unwrap_or([0; 32]));
        let rule = hint_rule(&vector, &hint_key, &recipient_pk);

        // Each envelope opens from its bytes, or from the bytes this crate seals when the kit
        // gives only their digest.
        let envelope = match vector.get("envelope") {
            Some(envelope) => bytes(envelope),
            None => {
                let mut content = TxContent::new(generated_body(&vector["body_generate"]));
                content.reply_key = expected["reply_key"]
                    .as_str()
                    .map(|key| lepic_seal::EncPublicKey::from_bytes(hex(key).try_into().unwrap()))
                    .transpose()
                    .unwrap();
                let key = tx_key(class, rule);
                let mut rng = ScriptedRng::new(&bytes(&vector["eph_ikm"]));
                let ours = seal_tx(net, &recipient_pk, key, &content, None, &mut rng).unwrap();
                assert_eq!(sha256(&ours), vector["envelope_sha256"], "{name}");
                resealed += 1;
                ours
            }
        };
        assert_eq!(envelope.len(), size(&vector["envelope_length"]), "{name}");
        let sealed = SealedEnvelope::decode(&envelope, net).unwrap();
        assert_eq!(to_hex(sealed.hint().as_bytes()), vector["hint"], "{name}");
        assert_eq!(to_hex(sealed.enc()), vector["enc"], "{name}");
        assert_eq!(to_hex(&envelope[..16]), vector["header"], "{name}");
        check_opens(&vector, &sealed, &recipient, class, name);
        opened_count += 1;
        check_armor(&vector, &envelope, name);

        // Fields from 0x80 up that this crate does not know are read and ignored, never
        // written, so a vector with them is not sealed again.
        let writes_all = expected["ignored_extra"].as_array().unwrap().is_empty();
        if let Some(expected_envelope) = vector.get("envelope")
            && writes_all
        {
            let ours = reseal(&vector, &sealed, &recipient, class, rule);
            assert_eq!(to_hex(&ours), text(expected_envelope), "{name}");
            resealed += 1;
        }
    }
    assert_eq!(opened_count, 29);
    assert!(resealed > 20);
}

#[test]
fn payment_files_are_classified_as_the_kit_says() {
    for vector in vectors("epictx_files.json") {
        let name = text(&vector["name"]);
        let expected = match text(&vector["expected"]) {
            "armour" => Ok(PaymentFile::Armour),
            "legacy_json" => Ok(PaymentFile::LegacyJson),
            "stock_saved_tx" => Err(ClassifyError::StockSavedTx),
            "not_payment_file" => Err(ClassifyError::NotPaymentFile),
            other => panic!("unknown class {other}"),
        };
        assert_eq!(classify(&bytes(&vector["input_hex"])), expected, "{name}");
    }
}

fn error_matches(code: &str, error: &DecodeError) -> bool {
    use DecodeError as D;
    use Malformed as M;
    match code {
        "tlv_bad_value" => matches!(
            error,
            D::Malformed(M::FieldValue { .. } | M::FieldLength { .. })
        ),
        "tlv_unknown_tag" => matches!(error, D::Malformed(M::UnknownField { .. })),
        "cannot_open" => matches!(error, D::CannotOpen),
        "armor_framing" => matches!(error, D::Malformed(M::Framing)),
        "armor_checksum" => matches!(error, D::Damaged | D::Malformed(M::Truncated)),
        other => panic!("unknown error code {other}"),
    }
}

#[test]
fn every_malformed_epictx_input_gives_its_typed_error() {
    for vector in vectors("epictx_malformed.json") {
        let name = text(&vector["name"]);
        let code = text(&vector["expected_error"]);
        let net = network(&vector["net"]);
        match text(&vector["kind"]) {
            "epictx_open" => {
                let recipient = EncSecretKey::from_bytes(array(&vector["recipient_enc_sk"]));
                let input = bytes(&vector["input_hex"]);
                let error = SealedEnvelope::decode(&input, net)
                    .and_then(|sealed| sealed.open_tx(&recipient, key_class(&vector["key_class"])))
                    .unwrap_err();
                assert!(error_matches(code, &error), "{name}: {error:?}");
            }
            "epictx_armor" => {
                let error = dearmor_marked(text(&vector["input_text"])).unwrap_err();
                assert!(error_matches(code, &error), "{name}: {error:?}");
            }
            "epictx_seal" => {
                assert_eq!(code, "body_too_large");
                assert_eq!(key_class(&vector["key_class"]), KeyClass::Listener);
                let recipient =
                    lepic_seal::EncPublicKey::from_bytes(array(&vector["recipient_enc_pk"]))
                        .unwrap();
                let mut content = TxContent::new(generated_body(&vector["body_generate"]));
                content.reply_key = Some(
                    lepic_seal::EncPublicKey::from_bytes(array(&vector["reply_key"])).unwrap(),
                );
                let found = content.body.len();
                assert_eq!(
                    seal_tx(
                        net,
                        &recipient,
                        TxKey::Listener,
                        &content,
                        None,
                        &mut ScriptedRng::seeded(1)
                    ),
                    Err(EncodeError::BodyTooLarge {
                        limit: MAX_BODY_LEN,
                        found
                    }),
                    "{name}"
                );
            }
            other => panic!("unknown kind {other}"),
        }
    }
}
