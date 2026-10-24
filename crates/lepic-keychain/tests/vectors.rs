//! Replays the G-01 golden vectors in `testdata/vectors/keys` that cover mnemonics, BIP32
//! derivation, identifiers, keychain commitments, Epicbox address keys and payment-proof keys.
//! It also replays the proof builder vectors, the `wallet.seed` vectors of the read-only seed
//! file import, the app data vectors and the RFC 0002 contact key vectors of the pairing kit.
//! Commitments over raw blinding factors and bulletproofs are checked by `lepic-crypto`. The onion v3 form of the payment-proof key is Tor-only and not ported.

// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

#[path = "vectors/app_data.rs"]
mod app_data;
#[path = "vectors/pairing.rs"]
mod pairing;

use std::path::PathBuf;

use lepic_crypto::{Commitment, PublicKey, RangeProof, SecretKey};
use lepic_keychain::proof::{create_output, create_proof, rewind};
use lepic_keychain::{
    Identifier, Keychain, LegacyProofBuilder, MnemonicError, OutputRewinder, ProofBuild,
    ProofBuilder, RewoundOutput, Seed, SwitchCommitment, WalletSeedError, WalletSeedFile,
    address_key_id,
};
use lepic_primitives::params::Network;
use serde_json::Value;

const NODE_REPO: &str = "https://github.com/EpicCash/epic";
const NODE_COMMIT: &str = "82fa7e813dc3b9bf137b9dd523d847f4210f5ba4";
const WALLET_REPO: &str = "https://github.com/EpicCash/epic-wallet";
const WALLET_COMMIT: &str = "845b3fcf4df12ed0139929c62157015447a9d063";

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

fn network(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "floonet" => Network::Floonet,
        other => panic!("unknown network {other}"),
    }
}

fn keychain(seed: &Value, name: &str) -> Keychain {
    let seed = Seed::from_entropy(&bytes(seed)).unwrap();
    Keychain::from_seed(&seed, network(name)).unwrap()
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
                let proof_key = keychain.payment_proof_key(&parent, index).unwrap();
                assert_eq!(
                    hex(&proof_key.public_key()),
                    text(&case["payment_proof_public_key"]),
                    "{label}"
                );
            }
        }
    }
}

fn rewound(value: &Value) -> Option<RewoundOutput> {
    if value.is_null() {
        return None;
    }
    Some(RewoundOutput {
        amount: text(&value["amount"]).parse().unwrap(),
        identifier: Identifier::from_hex(text(&value["identifier"])).unwrap(),
        switch: switch(text(&value["switch"])),
    })
}

/// Replays one proof builder vector. `own` and `other` are the builder under test and the other
/// scheme of the same wallet; `stranger` is the same scheme for `other_seed`.
fn replay_proofs<B: ProofBuild, O: ProofBuild>(
    vector: &Value,
    keychain: &Keychain,
    own: &B,
    other: &O,
    stranger: &B,
) {
    let name = text(&vector["name"]);
    let paths = cases(&vector["inputs"]["paths"]);
    let amounts = cases(&vector["inputs"]["amounts"]);
    let switches = cases(&vector["inputs"]["switches"]);
    let expected = cases(&vector["expected"]["cases"]);
    assert_eq!(
        expected.len(),
        paths.len() * amounts.len() * switches.len(),
        "{name}"
    );
    let rewinder = OutputRewinder::new(keychain).unwrap();

    for case in expected {
        let id = path(&case["path"]);
        assert_eq!(id.to_hex(), text(&case["identifier"]));
        let amount: u64 = text(&case["amount"]).parse().unwrap();
        let switch = switch(text(&case["switch"]));
        let label = format!("{name} {id} {amount} {switch:?}");
        let commit = Commitment::from_hex(text(&case["commit"])).unwrap();
        let proof = RangeProof::from_hex(text(&case["proof"])).unwrap();

        assert_eq!(keychain.commit(amount, &id, switch), Ok(commit), "{label}");
        let rewind_nonce = own.rewind_nonce(&commit).unwrap();
        assert_eq!(
            hex(rewind_nonce.expose_bytes()),
            text(&case["rewind_nonce"]),
            "{label}"
        );
        let private_nonce = own.private_nonce(&commit).unwrap();
        assert_eq!(
            hex(private_nonce.expose_bytes()),
            text(&case["private_nonce"]),
            "{label}"
        );
        assert_eq!(
            hex(own.proof_message(&id, switch).as_bytes()),
            text(&case["message"]),
            "{label}"
        );
        assert_eq!(
            create_proof(keychain, own, amount, &id, switch),
            Ok(proof.clone()),
            "{label}"
        );
        let output = create_output(keychain, own, amount, &id, switch).unwrap();
        assert_eq!(output.commitment, commit, "{label}");
        assert_eq!(output.proof, proof, "{label}");

        let expected_rewind = rewound(&case["rewind"]);
        assert!(expected_rewind.is_some(), "{label}");
        assert_eq!(rewind(own, &commit, &proof), Ok(expected_rewind), "{label}");
        assert_eq!(
            rewind(other, &commit, &proof),
            Ok(rewound(&case["rewind_with_other_builder"])),
            "{label}"
        );
        assert_eq!(
            rewind(stranger, &commit, &proof),
            Ok(rewound(&case["rewind_by_other_wallet"])),
            "{label}"
        );
        assert_eq!(
            rewinder.rewind(&commit, &proof),
            Ok(expected_rewind),
            "{label}"
        );
    }
}

#[test]
fn builds_and_rewinds_proofs_as_upstream_proof_builder() {
    let vector = node_vector("proofs_builder_seed32");
    assert_eq!(vector["inputs"]["builder"], "ProofBuilder");
    let network = text(&vector["inputs"]["network"]);
    let stranger = keychain(&vector["inputs"]["other_seed"], network);
    let keychain = keychain(&vector["inputs"]["seed"], network);
    replay_proofs(
        &vector,
        &keychain,
        &ProofBuilder::new(&keychain).unwrap(),
        &LegacyProofBuilder::new(&keychain).unwrap(),
        &ProofBuilder::new(&stranger).unwrap(),
    );
}

#[test]
fn builds_and_rewinds_proofs_as_upstream_legacy_proof_builder() {
    let vector = node_vector("proofs_legacy_builder_seed32");
    assert_eq!(vector["inputs"]["builder"], "LegacyProofBuilder");
    let network = text(&vector["inputs"]["network"]);
    let stranger = keychain(&vector["inputs"]["other_seed"], network);
    let keychain = keychain(&vector["inputs"]["seed"], network);
    replay_proofs(
        &vector,
        &keychain,
        &LegacyProofBuilder::new(&keychain).unwrap(),
        &ProofBuilder::new(&keychain).unwrap(),
        &LegacyProofBuilder::new(&stranger).unwrap(),
    );
}

#[test]
fn decrypts_upstream_wallet_seed_files() {
    for name in ["wallet_seed_seed32", "wallet_seed_seed16_empty_password"] {
        let vector = load(name, WALLET_REPO, WALLET_COMMIT);
        let inputs = &vector["inputs"];
        let expected = &vector["expected"];
        let file_text = text(&expected["file"]);
        for field in ["encrypted_seed", "salt", "nonce"] {
            assert!(
                file_text.contains(&format!("\"{field}\": {}", expected[field])),
                "{name}"
            );
        }

        let file = WalletSeedFile::parse(file_text).unwrap();
        let password = text_bytes(&inputs["password"]);
        let seed = file.decrypt(password).unwrap();
        assert_eq!(seed.expose_bytes(), bytes(&inputs["entropy"]), "{name}");
        assert_eq!(
            seed.to_mnemonic().unwrap().as_str(),
            text(&inputs["mnemonic"]),
            "{name}"
        );

        let wrong = text_bytes(&inputs["wrong_password"]);
        assert!(
            matches!(file.decrypt(wrong), Err(WalletSeedError::Decryption)),
            "{name}"
        );

        // Changing any hex digit of the sealed seed must fail authentication, not decrypt.
        let sealed = text(&expected["encrypted_seed"]);
        for index in 0..sealed.len() {
            let mut digits = sealed.as_bytes().to_vec();
            digits[index] = if digits[index] == b'0' { b'1' } else { b'0' };
            let tampered = file_text.replace(sealed, std::str::from_utf8(&digits).unwrap());
            let file = WalletSeedFile::parse(&tampered).unwrap();
            assert!(
                matches!(file.decrypt(password), Err(WalletSeedError::Decryption)),
                "{name} digit {index}"
            );
        }
    }
}

fn text_bytes(value: &Value) -> &[u8] {
    text(value).as_bytes()
}
