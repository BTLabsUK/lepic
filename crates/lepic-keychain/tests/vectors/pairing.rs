//! Replays the RFC 0002 key vectors in `testdata/vectors/pairing`, written by the independent
//! pairing kit: contact roots and slot keys, the slot search, one-time reply keys, and the
//! pairing mailbox keys of codes and of pairing words.

use lepic_keychain::{ContactRoot, pairing_mailbox_keys};
use lepic_primitives::params::Network;
use serde_json::Value;
use sha2::{Digest, Sha256};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use super::{bytes, hex};

pub(crate) const KIT_GENERATOR: &str = "epic-pairing-kit";
pub(crate) const KIT_VERSION: &str = "0.2.0";
pub(crate) const KIT_COMMIT: &str = "9e27d32526c68f0e70b225deb3d309fe1d88ce63";

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

fn network(value: &Value) -> Network {
    match value.as_u64() {
        Some(0) => Network::Mainnet,
        Some(1) => Network::Floonet,
        other => panic!("unknown net {other:?}"),
    }
}

fn array<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn root(vector: &Value) -> ContactRoot {
    ContactRoot::from_raw(&array(&vector["raw"]), network(&vector["net"])).unwrap()
}

#[test]
fn pairing_contact_keys_match_the_kit() {
    for vector in vectors("contact_keys.json") {
        let root = root(&vector);
        assert_eq!(hex(root.expose_bytes()), vector["root"], "{vector}");
        for contact in vector["contacts"].as_array().unwrap() {
            let slot = u32::try_from(contact["slot"].as_u64().unwrap()).unwrap();
            let keys = root
                .contact_keys(slot, array(&contact["box_salt"]))
                .unwrap();
            assert_eq!(hex(keys.expose_enc_secret()), contact["enc_sk"]);
            assert_eq!(hex(&keys.enc_public_key()), contact["enc_pk"]);
            assert_eq!(hex(keys.expose_signing_key().as_bytes()), contact["sig_sk"]);
            assert_eq!(hex(&keys.sig_public_key()), contact["sig_pk"]);
            assert_eq!(hex(keys.expose_hint_key()), contact["hint_key"]);
            assert_eq!(hex(&*root.hint_key(slot).unwrap()), contact["hint_key"]);
            assert_eq!(
                hex(keys.expose_box_secret().expose_bytes()),
                contact["box_sk"]
            );
            assert_eq!(
                contact["box_ctr"], 0,
                "only the counter loop test needs ctr 01"
            );
        }
    }
}

#[test]
fn pairing_slot_search_finds_each_vector_slot() {
    for vector in vectors("contact_keys.json") {
        let root = root(&vector);
        for contact in vector["contacts"].as_array().unwrap() {
            let found = root
                .find_slot(
                    &array(&contact["hint_key"]),
                    &array(&contact["enc_pk"]),
                    &array(&contact["sig_pk"]),
                )
                .unwrap();
            assert_eq!(found.map(u64::from), contact["slot"].as_u64());
        }
    }
}

#[test]
fn pairing_reply_keys_match_the_kit() {
    for vector in vectors("reply_keys.json") {
        let reply = root(&vector).reply_key(array(&vector["slate_id"])).unwrap();
        let secret = reply.expose_x25519_secret();
        assert_eq!(hex(secret), vector["reply_sk"], "{vector}");
        let public = x25519(*secret, X25519_BASEPOINT_BYTES);
        assert_eq!(hex(&public), vector["reply_pk"]);
        let hint_key: [u8; 32] = Sha256::new()
            .chain_update(b"epic-seal/1 reply")
            .chain_update(public)
            .finalize()
            .into();
        assert_eq!(hex(&hint_key), vector["reply_hint_key"]);
    }
}

fn check_mailbox(seed: [u8; 16], net: &Value, expected: &Value) {
    let (pbox, pfrom) = pairing_mailbox_keys(seed, network(net)).unwrap();
    assert_eq!(hex(pbox.expose_bytes()), expected["pbox_sk"], "{expected}");
    assert_eq!(
        hex(pfrom.expose_bytes()),
        expected["pfrom_sk"],
        "{expected}"
    );
    assert_eq!(expected["pbox_ctr"], 0);
    assert_eq!(expected["pfrom_ctr"], 0);
}

#[test]
fn pairing_mailbox_keys_match_the_kit() {
    let mut real = 0;
    for vector in vectors("mailbox_keys.json") {
        match vector["kind"].as_str().unwrap() {
            "real" => {
                check_mailbox(array(&vector["seed"]), &vector["net"], &vector);
                real += 1;
            }
            // Replayed by the counter loop's unit test, which can inject the order.
            "synthetic_order" => {}
            other => panic!("unknown mailbox vector kind {other}"),
        }
    }
    assert!(real > 0);
}

#[test]
fn pairing_words_rendezvous_mailboxes_match_the_kit() {
    for vector in vectors("words.json") {
        check_mailbox(
            array(&vector["mailbox_seed"]),
            &vector["net"],
            &vector["rendezvous_mailbox"],
        );
    }
}
