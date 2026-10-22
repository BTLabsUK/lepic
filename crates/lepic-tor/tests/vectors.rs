//! Onion v3 vectors.
//!
//! - `testdata/vectors/keys/address_keys_seed{16,32}.json` (generated from `epic-wallet` by
//!   `conformance/`): the address secret key is the payment-proof key's seed, and
//!   `payment_proof_onion_v3` is the onion `epic-wallet` derives from its public key.
//! - A throwaway wallet's onion key file written by `epic-wallet` `v4.1.0` and the onion its
//!   `address` command printed; tor published that onion only once the seed was expanded.
//! - Onion addresses published by the Tor Project, checked for their version and checksum.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use lepic_tor::{OnionAddress, OnionError, expanded_secret, onion_address, public_key_of_seed};
use serde_json::Value;

const WALLET_REPO: &str = "https://github.com/EpicCash/epic-wallet";
const WALLET_COMMIT: &str = "465d499f01aad7e570b6cc220d52c6bfcf6a9a44";

const KEY_FILE_SEED: &str = "37c50a0cfaf343cbc594fde3cb29a88427d40891de34791f1d97f9d99e1e35d9";
const KEY_FILE_PUBLIC_KEY: &str =
    "62be2076374085e7cbfee9869da228517248f8a51e92fc490f6b5f39afe9c372";
const KEY_FILE_ONION: &str = "mk7ca5rxicc6ps765gdj3irikfzer6ffd2jpysipnnpttl7jynzaluyd";

const TOR_PROJECT_ONIONS: [&str; 4] = [
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    "sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion",
    "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion",
    "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
];

fn hex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "{text}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, found {value}"))
}

fn address_key_cases(name: &str) -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/keys")
        .join(format!("{name}.json"));
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let vector: Value = serde_json::from_str(&source).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "keys", "{name}: area");
    assert_eq!(vector["name"], name, "{name}: name");
    assert_eq!(vector["upstream"]["repo"], WALLET_REPO, "{name}: repo");
    assert_eq!(vector["upstream"]["commit"], WALLET_COMMIT, "{name}: pin");
    vector["expected"]["cases"].as_array().unwrap().clone()
}

/// The public key tor derives from the expanded key it is given.
fn public_key_tor_derives(expanded: &[u8; 64]) -> [u8; 32] {
    VerifyingKey::from(&ExpandedSecretKey::from_bytes(expanded)).to_bytes()
}

fn assert_onion_of_seed(seed: &[u8; 32], public_key: &[u8; 32], onion: &str, case: &str) {
    assert_eq!(&public_key_of_seed(seed), public_key, "{case}: public key");
    assert_eq!(
        onion_address(public_key),
        format!("{onion}.onion"),
        "{case}: onion"
    );
    assert_eq!(
        &public_key_tor_derives(&expanded_secret(seed)),
        public_key,
        "{case}: tor's key"
    );
    let parsed = OnionAddress::parse(onion).unwrap();
    assert_eq!(parsed.public_key(), public_key, "{case}: parsed key");
    assert_eq!(parsed.service_id(), onion, "{case}: service id");
}

#[test]
fn payment_proof_onions_match_epic_wallet() {
    let mut checked = 0;
    for name in ["address_keys_seed16", "address_keys_seed32"] {
        for (i, case) in address_key_cases(name).iter().enumerate() {
            let label = format!("{name}[{i}]");
            assert_onion_of_seed(
                &hex32(text(&case["address_secret_key"])),
                &hex32(text(&case["payment_proof_public_key"])),
                text(&case["payment_proof_onion_v3"]),
                &label,
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 12);
}

#[test]
fn epic_wallet_key_file_seed_publishes_its_address() {
    assert_onion_of_seed(
        &hex32(KEY_FILE_SEED),
        &hex32(KEY_FILE_PUBLIC_KEY),
        KEY_FILE_ONION,
        "key file",
    );
}

#[test]
fn seed_and_public_key_as_tor_key_publishes_another_onion() {
    let seed = hex32(KEY_FILE_SEED);
    let mut unexpanded = [0u8; 64];
    unexpanded[..32].copy_from_slice(&seed);
    unexpanded[32..].copy_from_slice(&hex32(KEY_FILE_PUBLIC_KEY));
    assert_ne!(
        public_key_tor_derives(&unexpanded),
        hex32(KEY_FILE_PUBLIC_KEY)
    );
}

#[test]
fn tor_project_onions_parse() {
    for onion in TOR_PROJECT_ONIONS {
        let parsed = OnionAddress::parse(onion).unwrap();
        assert_eq!(parsed.to_string(), onion);
        assert_eq!(onion_address(parsed.public_key()), onion);
    }
}

#[test]
fn tor_project_onion_with_one_changed_character_is_a_typo() {
    let typo = TOR_PROJECT_ONIONS[0].replacen("pg6", "pg7", 1);
    assert_eq!(OnionAddress::parse(&typo), Err(OnionError::Checksum));
}
