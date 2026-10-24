// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fmt::Write as _;
use std::path::PathBuf;

use lepic_crypto::PublicKey;
use lepic_keychain::{
    ContactKeyError, ContactRoot, Identifier, Keychain, SLOT_COUNT, SwitchCommitment,
    contact_identity_key_id, pairing_mailbox_keys,
};
use lepic_primitives::params::Network;
use serde_json::{Value, json};

const PHRASE: &str = "pipe stock song coast pair always emotion member joy sting dash theory";
const NETWORKS: [(Network, &str); 2] =
    [(Network::Mainnet, "mainnet"), (Network::Floonet, "floonet")];

fn account() -> Identifier {
    Identifier::new(2, [0, 0, 0, 0]).unwrap()
}

fn keychain() -> Keychain {
    Keychain::from_mnemonic(PHRASE, Network::Mainnet).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn pub_hex(key: &lepic_crypto::SecretKey) -> String {
    hex(&PublicKey::from_secret_key(key).unwrap().to_bytes())
}

#[test]
fn root_is_deterministic_and_network_separated() {
    let kc = keychain();
    let a = kc.contact_root(&account(), Network::Mainnet).unwrap();
    let b = kc.contact_root(&account(), Network::Mainnet).unwrap();
    let f = kc.contact_root(&account(), Network::Floonet).unwrap();
    assert_eq!(a.expose_bytes(), b.expose_bytes());
    assert_ne!(a.expose_bytes(), f.expose_bytes());
}

#[test]
fn keychain_root_is_from_raw_of_the_derived_key() {
    let kc = keychain();
    let id = contact_identity_key_id(&account()).unwrap();
    let raw = kc.derive_key(0, &id, SwitchCommitment::None).unwrap();
    for (network, _) in NETWORKS {
        let a = kc.contact_root(&account(), network).unwrap();
        let b = ContactRoot::from_raw(raw.expose_bytes(), network).unwrap();
        assert_eq!(a.expose_bytes(), b.expose_bytes());
    }
}

#[test]
fn root_differs_per_account() {
    let kc = keychain();
    let other = Identifier::new(2, [1, 0, 0, 0]).unwrap();
    let a = kc.contact_root(&account(), Network::Mainnet).unwrap();
    let b = kc.contact_root(&other, Network::Mainnet).unwrap();
    assert_ne!(a.expose_bytes(), b.expose_bytes());
}

#[test]
fn keys_are_deterministic_and_separated() {
    let root = keychain()
        .contact_root(&account(), Network::Mainnet)
        .unwrap();
    let a = root.contact_keys(1, [9; 16]).unwrap();
    let a2 = root.contact_keys(1, [9; 16]).unwrap();
    let b = root.contact_keys(2, [9; 16]).unwrap();
    assert_eq!(a.expose_enc_secret(), a2.expose_enc_secret());
    assert_eq!(a.sig_public_key(), a2.sig_public_key());
    assert_eq!(a.box_public_key(), a2.box_public_key());
    assert_ne!(a.expose_enc_secret(), b.expose_enc_secret());
    assert_ne!(a.expose_hint_key(), b.expose_hint_key());
    assert_ne!(a.expose_enc_secret(), a.expose_hint_key());
    assert_ne!(a.box_public_key(), b.box_public_key());
    let r1 = root.reply_key([7; 16]).unwrap();
    let r2 = root.reply_key([8; 16]).unwrap();
    assert_ne!(r1.expose_x25519_secret(), r2.expose_x25519_secret());
}

#[test]
fn box_salt_changes_only_the_mailbox_key() {
    let root = keychain()
        .contact_root(&account(), Network::Mainnet)
        .unwrap();
    let a = root.contact_keys(5, [1; 16]).unwrap();
    let b = root.contact_keys(5, [2; 16]).unwrap();
    assert_eq!(a.expose_enc_secret(), b.expose_enc_secret());
    assert_eq!(a.sig_public_key(), b.sig_public_key());
    assert_eq!(a.expose_hint_key(), b.expose_hint_key());
    assert_ne!(a.box_public_key(), b.box_public_key());
}

#[test]
fn hint_key_alone_equals_the_slot_keys_hint_key() {
    let root = keychain()
        .contact_root(&account(), Network::Floonet)
        .unwrap();
    for slot in [0, 1, 4097, SLOT_COUNT - 1] {
        let keys = root.contact_keys(slot, [3; 16]).unwrap();
        assert_eq!(*root.hint_key(slot).unwrap(), *keys.expose_hint_key());
    }
}

#[test]
fn rejects_slots_from_65536() {
    let root = keychain()
        .contact_root(&account(), Network::Mainnet)
        .unwrap();
    for slot in [SLOT_COUNT, SLOT_COUNT + 1, u32::MAX] {
        assert_eq!(
            root.contact_keys(slot, [0; 16]).unwrap_err(),
            ContactKeyError::SlotOutOfRange { slot }
        );
        assert_eq!(
            root.hint_key(slot).unwrap_err(),
            ContactKeyError::SlotOutOfRange { slot }
        );
    }
}

#[test]
fn find_slot_recovers_the_slot_of_a_card() {
    let root = keychain()
        .contact_root(&account(), Network::Mainnet)
        .unwrap();
    for slot in [0, 31_337, SLOT_COUNT - 1] {
        let keys = root.contact_keys(slot, [4; 16]).unwrap();
        let found = root
            .find_slot(
                keys.expose_hint_key(),
                &keys.enc_public_key(),
                &keys.sig_public_key(),
            )
            .unwrap();
        assert_eq!(found, Some(slot));
    }
}

#[test]
fn find_slot_refuses_cards_of_another_seed_or_mixed_keys() {
    let root = keychain()
        .contact_root(&account(), Network::Mainnet)
        .unwrap();
    let ours = root.contact_keys(12, [0; 16]).unwrap();
    let other = ContactRoot::from_raw(&[0x33; 32], Network::Mainnet)
        .unwrap()
        .contact_keys(12, [0; 16])
        .unwrap();
    let find =
        |hint: &[u8; 32], enc: &[u8; 32], sig: &[u8; 32]| root.find_slot(hint, enc, sig).unwrap();
    assert_eq!(
        find(
            other.expose_hint_key(),
            &other.enc_public_key(),
            &other.sig_public_key()
        ),
        None
    );
    assert_eq!(
        find(
            ours.expose_hint_key(),
            &other.enc_public_key(),
            &ours.sig_public_key()
        ),
        None
    );
    assert_eq!(
        find(
            ours.expose_hint_key(),
            &ours.enc_public_key(),
            &other.sig_public_key()
        ),
        None
    );
    let floonet = keychain()
        .contact_root(&account(), Network::Floonet)
        .unwrap()
        .contact_keys(12, [0; 16])
        .unwrap();
    assert_eq!(
        find(
            floonet.expose_hint_key(),
            &floonet.enc_public_key(),
            &floonet.sig_public_key()
        ),
        None
    );
}

#[test]
fn debug_output_is_redacted() {
    let root = keychain()
        .contact_root(&account(), Network::Mainnet)
        .unwrap();
    let keys = root.contact_keys(1, [1; 16]).unwrap();
    let reply = root.reply_key([1; 16]).unwrap();
    let shown = format!("{root:?} {keys:?} {reply:?}");
    assert!(shown.contains("redacted"));
    assert!(!shown.contains(&hex(root.expose_bytes())));
    assert!(!shown.contains(&hex(keys.expose_enc_secret())));
}

#[test]
fn mailbox_keys_depend_on_seed_and_network() {
    let (b1, f1) = pairing_mailbox_keys([1; 16], Network::Mainnet).unwrap();
    let (b2, _) = pairing_mailbox_keys([1; 16], Network::Mainnet).unwrap();
    let (b3, _) = pairing_mailbox_keys([2; 16], Network::Mainnet).unwrap();
    let (b4, _) = pairing_mailbox_keys([1; 16], Network::Floonet).unwrap();
    assert_eq!(b1.expose_bytes(), b2.expose_bytes());
    assert_ne!(b1.expose_bytes(), b3.expose_bytes());
    assert_ne!(b1.expose_bytes(), b4.expose_bytes());
    assert_ne!(b1.expose_bytes(), f1.expose_bytes());
}

const SLOTS: [(u32, [u8; 16]); 3] = [(0, [0; 16]), (1, [0x5a; 16]), (SLOT_COUNT - 1, [0xff; 16])];
const SLATE_IDS: [[u8; 16]; 2] = [
    [0; 16],
    [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ],
];
const CODES: [[u8; 16]; 2] = [[0; 16], [0xa5; 16]];

fn network_block(raw: &[u8; 32]) -> Value {
    let mut networks = serde_json::Map::new();
    for (network, name) in NETWORKS {
        let root = ContactRoot::from_raw(raw, network).unwrap();
        let contacts: Vec<Value> = SLOTS
            .iter()
            .map(|(slot, box_salt)| {
                let k = root.contact_keys(*slot, *box_salt).unwrap();
                json!({
                    "slot": slot,
                    "box_salt": hex(box_salt),
                    "enc_secret": hex(k.expose_enc_secret()),
                    "enc_public": hex(&k.enc_public_key()),
                    "sig_public": hex(&k.sig_public_key()),
                    "hint_key": hex(k.expose_hint_key()),
                    "box_secret": hex(k.expose_box_secret().expose_bytes()),
                    "box_public": hex(&k.box_public_key().to_bytes()),
                })
            })
            .collect();
        let replies: Vec<Value> = SLATE_IDS
            .iter()
            .map(|sid| {
                json!({
                    "slate_id": hex(sid),
                    "reply_secret": hex(root.reply_key(*sid).unwrap().expose_x25519_secret()),
                })
            })
            .collect();
        let mailboxes: Vec<Value> = CODES
            .iter()
            .map(|seed| {
                let (b, f) = pairing_mailbox_keys(*seed, network).unwrap();
                json!({
                    "seed": hex(seed),
                    "box_secret": hex(b.expose_bytes()),
                    "box_public": pub_hex(&b),
                    "from_secret": hex(f.expose_bytes()),
                    "from_public": pub_hex(&f),
                })
            })
            .collect();
        networks.insert(
            name.to_owned(),
            json!({
                "root": hex(root.expose_bytes()),
                "contacts": contacts,
                "replies": replies,
                "mailboxes": mailboxes,
            }),
        );
    }
    Value::Object(networks)
}

fn build_fixture() -> Value {
    let kc = keychain();
    let id = contact_identity_key_id(&account()).unwrap();
    let raw = kc.derive_key(0, &id, SwitchCommitment::None).unwrap();
    let from_raw: Vec<Value> = [0x11u8, 0x22]
        .iter()
        .map(|byte| json!({ "raw": hex(&[*byte; 32]), "networks": network_block(&[*byte; 32]) }))
        .collect();
    json!({
        "comment": "LEPIC's own output, not independent vectors. The independent Python kit cross-checks it as golden vectors under testdata/vectors/pairing. RFC 0002 2.1-2.3 and 8.1.",
        "mnemonic": PHRASE,
        "path": id.to_bip32_path(),
        "raw_key": hex(raw.expose_bytes()),
        "mnemonic_networks": network_block(raw.expose_bytes()),
        "from_raw": from_raw,
    })
}

#[test]
fn fixture_matches_lepic_output() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contact_keys_lepic.json");
    let current = build_fixture();
    if std::env::var_os("LEPIC_UPDATE_FIXTURES").is_some() {
        let mut text = serde_json::to_string_pretty(&current).unwrap();
        text.push('\n');
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored, current);
}
