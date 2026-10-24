//! RFC 9180 Appendix A.2.1: the HPKE suite of the envelope, checked byte for byte.

// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{ScriptedRng, hex};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use lepic_contact::{
    Content, EncPublicKey, EncSecretKey, HintRule, MessageType, Network, SealedEnvelope, seal,
};
use serde_json::Value;

const VECTOR: &str = include_str!("../../../testdata/vectors/pairing/hpke_rfc9180_a2.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn field(value: &Value, pointer: &str) -> Vec<u8> {
    hex(value.pointer(pointer).unwrap().as_str().unwrap())
}

#[test]
fn the_suite_matches_rfc9180_a2_1() {
    let vector = vector();
    let inputs = &vector["inputs"];
    assert_eq!(inputs["kem_id"], 32);
    assert_eq!(inputs["kdf_id"], 1);
    assert_eq!(inputs["aead_id"], 3);
    assert_eq!(inputs["mode"], 0);
    let info = field(&vector, "/inputs/info");

    let (sk_r, pk_r) = X25519HkdfSha256::derive_keypair(&field(&vector, "/inputs/ikmR"));
    assert_eq!(
        sk_r.to_bytes().to_vec(),
        field(&vector, "/expected/setup/skRm")
    );
    assert_eq!(
        pk_r.to_bytes().to_vec(),
        field(&vector, "/expected/setup/pkRm")
    );

    // The ephemeral key comes from 32 bytes of the caller's RNG through DeriveKeyPair, so an RNG
    // that yields ikmE reproduces the RFC's encapsulation.
    let mut rng = ScriptedRng::new(&field(&vector, "/inputs/ikmE"));
    let (encapped, mut sender) = hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &pk_r, &info, &mut rng)
    .unwrap();
    assert_eq!(
        encapped.to_bytes().to_vec(),
        field(&vector, "/expected/setup/enc")
    );
    let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk_r,
        &encapped,
        &info,
    )
    .unwrap();

    let encryptions = vector["expected"]["encryptions"].as_array().unwrap();
    let mut checked = 0;
    for sequence in 0..=256u64 {
        let listed = encryptions
            .iter()
            .find(|entry| entry["sequence_number"].as_u64() == Some(sequence));
        let (plaintext, aad) = match listed {
            Some(entry) => (field(entry, "/pt"), field(entry, "/aad")),
            None => (b"skipped".to_vec(), Vec::new()),
        };
        let ciphertext = sender.seal(&plaintext, &aad).unwrap();
        assert_eq!(receiver.open(&ciphertext, &aad).unwrap(), plaintext);
        if let Some(entry) = listed {
            assert_eq!(ciphertext, field(entry, "/ct"), "sequence {sequence}");
            checked += 1;
        }
    }
    assert_eq!(checked, encryptions.len());

    for entry in vector["expected"]["exports"].as_array().unwrap() {
        let length = usize::try_from(entry["length"].as_u64().unwrap()).unwrap();
        let mut out = vec![0; length];
        sender
            .export(&field(entry, "/exporter_context"), &mut out)
            .unwrap();
        assert_eq!(out, field(entry, "/exported_value"));
    }
}

#[test]
fn single_shot_open_reads_the_first_rfc_ciphertext() {
    let vector = vector();
    let secret =
        <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&field(&vector, "/expected/setup/skRm"))
            .unwrap();
    let encapped =
        <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&field(&vector, "/expected/setup/enc"))
            .unwrap();
    let first = &vector["expected"]["encryptions"][0];
    let plaintext = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &secret,
        &encapped,
        &field(&vector, "/inputs/info"),
        &field(first, "/ct"),
        &field(first, "/aad"),
    )
    .unwrap();
    assert_eq!(plaintext, field(first, "/pt"));
}

#[test]
fn an_envelope_sealed_with_ikm_e_carries_the_rfc_enc() {
    let vector = vector();
    let recipient_secret: [u8; 32] = field(&vector, "/expected/setup/skRm").try_into().unwrap();
    let recipient = EncSecretKey::from_bytes(recipient_secret);
    assert_eq!(
        recipient.public_key(),
        EncPublicKey::from_bytes(field(&vector, "/expected/setup/pkRm").try_into().unwrap())
            .unwrap()
    );
    let mut rng = ScriptedRng::new(&field(&vector, "/inputs/ikmE"));
    let envelope = seal(
        Network::Floonet,
        &recipient.public_key(),
        HintRule::ReplyKey,
        &Content::new(MessageType::Slate, b"{}".to_vec()),
        None,
        &mut rng,
    )
    .unwrap();
    let sealed = SealedEnvelope::decode(&envelope, Network::Floonet).unwrap();
    assert_eq!(sealed.enc().to_vec(), field(&vector, "/expected/setup/enc"));
    assert_eq!(sealed.open(&recipient).unwrap().content.body, b"{}");
}
