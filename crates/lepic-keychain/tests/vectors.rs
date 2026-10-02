//! Replays the G-01 golden vectors in `testdata/vectors/keys` that cover mnemonics, BIP32
//! derivation, identifiers, keychain commitments and Epicbox address keys. Commitments over raw
//! blinding factors and bulletproofs are checked by `lepic-crypto`, proof builders by K-02 and the
//! seed file by K-03.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_crypto::{Commitment, PublicKey, SecretKey};
use lepic_keychain::{
    ExtKeyVersion, Identifier, Keychain, MnemonicError, Seed, SwitchCommitment, address_key_id,
};
use serde_json::Value;

const NODE_REPO: &str = "https://github.com/EpicCash/epic";
const NODE_COMMIT: &str = "9d022b1d521d3f705532e12ab77e0a429f6fde1f";
const WALLET_REPO: &str = "https://github.com/EpicCash/epic-wallet";
const WALLET_COMMIT: &str = "465d499f01aad7e570b6cc220d52c6bfcf6a9a44";

const SEEDS: [&str; 2] = ["seed16", "seed32"];

fn load(name: &str, repo: &str, commit: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/keys")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let vector: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "keys", "{name}: area");
    assert_eq!(vector["name"], name, "{name}: name");
    assert_eq!(vector["upstream"]["repo"], repo, "{name}: repo");
    assert_eq!(vector["upstream"]["commit"], commit, "{name}: pin");
    vector
}

fn node_vector(name: &str) -> Value {
    load(name, NODE_REPO, NODE_COMMIT)
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, found {value}"))
}

fn bytes(value: &Value) -> Vec<u8> {
    let hex = text(value);
    assert!(hex.len().is_multiple_of(2), "odd hex {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cases(value: &Value) -> &[Value] {
    let cases = value.as_array().unwrap();
    assert!(!cases.is_empty());
    cases
}

fn path(value: &Value) -> Identifier {
    let depth = u8::try_from(value["depth"].as_u64().unwrap()).unwrap();
    let components: Vec<u32> = value["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| u32::try_from(component.as_u64().unwrap()).unwrap())
        .collect();
    Identifier::new(depth, components.try_into().unwrap()).unwrap()
}

fn version(network: &str) -> ExtKeyVersion {
    match network {
        "mainnet" => ExtKeyVersion::MAINNET,
        "floonet" => ExtKeyVersion::FLOONET,
        other => panic!("unknown network {other}"),
    }
}

fn keychain(seed: &Value, network: &str) -> Keychain {
    let seed = Seed::from_entropy(&bytes(seed)).unwrap();
    Keychain::from_seed(&seed, version(network)).unwrap()
}

fn switch(name: &str) -> SwitchCommitment {
    match name {
        "none" => SwitchCommitment::None,
        "regular" => SwitchCommitment::Regular,
        other => panic!("unknown switch type {other}"),
    }
}

#[test]
fn entropy_encodes_to_upstream_mnemonic_and_back() {
    for name in [
        "mnemonic_12_words_zero",
        "mnemonic_12_words_seed16",
        "mnemonic_15_words",
        "mnemonic_18_words",
        "mnemonic_21_words",
        "mnemonic_24_words_seed32",
    ] {
        let vector = node_vector(name);
        let entropy = bytes(&vector["inputs"]["entropy"]);
        let expected = text(&vector["expected"]["mnemonic"]);
        let word_count = vector["expected"]["word_count"].as_u64().unwrap();

        let seed = Seed::from_entropy(&entropy).unwrap();
        assert_eq!(seed.to_mnemonic().unwrap().as_str(), expected, "{name}");
        assert_eq!(seed.word_count() as u64, word_count, "{name}");

        let parsed = Seed::from_mnemonic(expected).unwrap();
        assert_eq!(parsed.expose_bytes(), entropy.as_slice(), "{name}");
    }
}

#[test]
fn parses_phrases_as_upstream_does() {
    let rejected = [
        ("mnemonic_parse_bad_checksum", MnemonicError::Checksum),
        (
            "mnemonic_parse_unknown_word",
            MnemonicError::UnknownWord { position: 0 },
        ),
        (
            "mnemonic_parse_uppercase_word",
            MnemonicError::UnknownWord { position: 0 },
        ),
        (
            "mnemonic_parse_11_words",
            MnemonicError::WordCount { actual: 11 },
        ),
        (
            "mnemonic_parse_13_words",
            MnemonicError::WordCount { actual: 13 },
        ),
        (
            "mnemonic_parse_empty",
            MnemonicError::WordCount { actual: 0 },
        ),
    ];
    for (name, error) in rejected {
        let vector = node_vector(name);
        assert!(vector["expected"]["entropy"].is_null(), "{name}");
        assert!(vector["expected"]["error"].is_string(), "{name}");
        let phrase = text(&vector["inputs"]["mnemonic"]);
        assert_eq!(Seed::from_mnemonic(phrase).err(), Some(error), "{name}");
    }

    let vector = node_vector("mnemonic_parse_extra_whitespace");
    assert!(vector["expected"]["error"].is_null());
    let seed = Seed::from_mnemonic(text(&vector["inputs"]["mnemonic"])).unwrap();
    assert_eq!(seed.expose_bytes(), bytes(&vector["expected"]["entropy"]));
}

#[test]
fn derives_master_and_child_keys_as_upstream() {
    for seed_name in SEEDS {
        for network in ["mainnet", "floonet"] {
            let name = format!("derivation_{seed_name}_{network}");
            let vector = node_vector(&name);
            assert_eq!(text(&vector["inputs"]["network"]), network);
            let keychain = keychain(&vector["inputs"]["seed"], network);

            let master = &vector["expected"]["master"];
            assert_eq!(
                hex(keychain.master().secret_key().expose_bytes()),
                text(&master["secret_key"]),
                "{name}"
            );
            assert_eq!(
                hex(keychain.master().chain_code().expose_bytes()),
                text(&master["chain_code"]),
                "{name}"
            );
            assert_eq!(
                keychain.master_public_key().unwrap().to_hex(),
                text(&master["public_key"]),
                "{name}"
            );
            assert_eq!(
                hex(&keychain.version().private),
                text(&master["ext_priv_version"])
            );
            assert_eq!(
                hex(&keychain.version().public),
                text(&master["ext_pub_version"])
            );

            let inputs = cases(&vector["inputs"]["paths"]);
            let keys = cases(&vector["expected"]["keys"]);
            assert_eq!(inputs.len(), keys.len(), "{name}");
            for (input, key) in inputs.iter().zip(keys) {
                let id = path(input);
                assert_eq!(path(&key["path"]), id, "{name}");
                let label = format!("{name} {}", id.to_hex());
                assert_eq!(id.to_hex(), text(&key["identifier"]), "{label}");
                assert_eq!(id.to_bip32_path(), text(&key["bip32_path"]), "{label}");
                assert_eq!(
                    id.parent().to_hex(),
                    text(&key["parent_identifier"]),
                    "{label}"
                );
                assert_eq!(Identifier::from_hex(&id.to_hex()), Ok(id), "{label}");

                let ext = keychain.derive_ext_key(&id).unwrap();
                assert_eq!(ext.depth(), id.depth(), "{label}");
                assert_eq!(
                    hex(ext.secret_key().expose_bytes()),
                    text(&key["secret_key"]),
                    "{label}"
                );
                assert_eq!(
                    ext.public_key().unwrap().to_hex(),
                    text(&key["public_key"]),
                    "{label}"
                );
                assert_eq!(
                    hex(ext.chain_code().expose_bytes()),
                    text(&key["chain_code"]),
                    "{label}"
                );
                assert_eq!(
                    hex(&ext.parent_fingerprint().0),
                    text(&key["parent_fingerprint"]),
                    "{label}"
                );

                let plain = keychain.derive_key(0, &id, SwitchCommitment::None).unwrap();
                assert_eq!(hex(plain.expose_bytes()), text(&key["secret_key"]));
            }
        }
    }
}

#[test]
fn derives_output_blinds_and_commitments_on_both_networks() {
    for seed_name in SEEDS {
        let name = format!("commitments_{seed_name}");
        let vector = node_vector(&name);
        let seed = &vector["inputs"]["seed"];
        let keychains = [keychain(seed, "mainnet"), keychain(seed, "floonet")];
        for case in cases(&vector["expected"]["cases"]) {
            let id = path(&case["path"]);
            assert_eq!(id.to_hex(), text(&case["identifier"]));
            let amount: u64 = text(&case["amount"]).parse().unwrap();
            let switch = switch(text(&case["switch"]));
            let blind = SecretKey::from_hex(text(&case["blind"])).unwrap();
            let commit = Commitment::from_hex(text(&case["commit"])).unwrap();
            for keychain in &keychains {
                let label = format!("{name} {id} {amount} {switch:?}");
                let derived = keychain.derive_key(amount, &id, switch).unwrap();
                assert_eq!(derived.expose_bytes(), blind.expose_bytes(), "{label}");
                assert_eq!(keychain.commit(amount, &id, switch), Ok(commit), "{label}");
            }
        }
    }
}

#[test]
fn derives_epicbox_address_keys_on_both_networks() {
    for seed_name in SEEDS {
        let name = format!("address_keys_{seed_name}");
        let vector = load(&name, WALLET_REPO, WALLET_COMMIT);
        let seed = &vector["inputs"]["seed"];
        let keychains = [keychain(seed, "mainnet"), keychain(seed, "floonet")];
        let parents = cases(&vector["inputs"]["parents"]);
        let indexes = cases(&vector["inputs"]["indexes"]);
        let expected = cases(&vector["expected"]["cases"]);
        assert_eq!(expected.len(), parents.len() * indexes.len(), "{name}");

        for case in expected {
            let parent = Identifier::from_hex(text(&case["parent_identifier"])).unwrap();
            assert!(parents.iter().any(|candidate| path(candidate) == parent));
            let index = u32::try_from(case["index"].as_u64().unwrap()).unwrap();
            let label = format!("{name} {parent} {index}");

            let id = address_key_id(&parent, index).unwrap();
            assert_eq!(id.to_hex(), text(&case["key_identifier"]), "{label}");
            assert_eq!(id.to_bip32_path(), text(&case["key_bip32_path"]), "{label}");

            for keychain in &keychains {
                let raw = keychain.derive_key(0, &id, SwitchCommitment::None).unwrap();
                assert_eq!(
                    hex(raw.expose_bytes()),
                    text(&case["raw_secret_key"]),
                    "{label}"
                );
                let address_key = keychain.address_key(&parent, index).unwrap();
                assert_eq!(
                    hex(address_key.expose_bytes()),
                    text(&case["address_secret_key"]),
                    "{label}"
                );
                assert_eq!(
                    PublicKey::from_secret_key(&address_key).unwrap().to_hex(),
                    text(&case["address_public_key"]),
                    "{label}"
                );
            }
        }
    }
}
