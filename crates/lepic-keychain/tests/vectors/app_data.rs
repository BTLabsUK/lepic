//! Replays the app data vectors in `testdata/vectors/app_data`: the wallet root secret, checked
//! through its hash, and `WFEH` version 1 files sealed by an independent implementation.

use blake2::Blake2b256;
use blake2::digest::Digest;
use lepic_keychain::app_data::{self, HEADER_LEN};
use lepic_keychain::{AppDataError, Identifier, Keychain, SwitchCommitment};
use lepic_primitives::params::Network;
use serde_json::Value;

use super::{NODE_COMMIT, NODE_REPO, bytes, hex, text};

const CASES: [&str; 3] = ["wfeh_seed_a", "wfeh_seed_b", "wfeh_seed_a_empty_payload"];

fn vector(name: &str) -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/app_data")
        .join(format!("{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(vector["schema"], 1, "{name}: schema");
    assert_eq!(vector["area"], "app_data", "{name}: area");
    assert_eq!(vector["name"], name, "{name}: name");
    assert_eq!(vector["upstream"]["repo"], NODE_REPO, "{name}: repo");
    assert_eq!(vector["upstream"]["commit"], NODE_COMMIT, "{name}: pin");
    vector
}

fn keychain(vector: &Value, network: Network) -> Keychain {
    let from_phrase =
        Keychain::from_mnemonic(text(&vector["inputs"]["mnemonic"]), network).unwrap();
    let seed = lepic_keychain::Seed::from_entropy(&bytes(&vector["inputs"]["entropy"])).unwrap();
    let from_entropy = Keychain::from_seed(&seed, network).unwrap();
    assert_eq!(
        from_phrase.master().secret_key().expose_bytes(),
        from_entropy.master().secret_key().expose_bytes()
    );
    from_phrase
}

#[test]
fn derives_the_root_secret_upstream_hashes() {
    for name in CASES {
        let vector = vector(name);
        for network in [Network::Mainnet, Network::Floonet] {
            let root = keychain(&vector, network)
                .derive_key(0, &Identifier::ROOT, SwitchCommitment::Regular)
                .unwrap();
            assert_eq!(
                hex(&Blake2b256::digest(root.expose_bytes())),
                text(&vector["expected"]["root_secret_blake2b"]),
                "{name} {network:?}"
            );
        }
    }
}

#[test]
fn seals_the_golden_files_byte_for_byte_and_opens_them() {
    for name in CASES {
        let vector = vector(name);
        let inputs = &vector["inputs"];
        let file = bytes(&vector["expected"]["file"]);
        let payload = text(&inputs["payload"]).as_bytes();
        for network in [Network::Mainnet, Network::Floonet] {
            let keychain = keychain(&vector, network);
            let salt = bytes(&inputs["salt"]).try_into().unwrap();
            let nonce = bytes(&inputs["nonce"]).try_into().unwrap();
            let sealed = app_data::seal(&keychain, salt, nonce, payload).unwrap();
            assert_eq!(hex(&sealed), hex(&file), "{name} {network:?}");
            assert_eq!(&app_data::open(&keychain, &file).unwrap()[..], payload);
        }
        assert_eq!(
            hex(&file[22..38]),
            text(&vector["expected"]["check"]),
            "{name}"
        );
        assert_eq!(file.len(), HEADER_LEN + payload.len() + 16, "{name}");
    }
}

#[test]
fn refuses_the_golden_file_of_another_seed_as_foreign() {
    let own = keychain(&vector("wfeh_seed_a"), Network::Mainnet);
    let foreign = bytes(&vector("wfeh_seed_b")["expected"]["file"]);
    assert_eq!(
        app_data::open(&own, &foreign).unwrap_err(),
        AppDataError::ForeignWallet
    );
}

#[test]
fn refuses_every_flipped_byte_of_a_golden_file() {
    let vector = vector("wfeh_seed_a");
    let keychain = keychain(&vector, Network::Mainnet);
    let file = bytes(&vector["expected"]["file"]);
    for index in 0..file.len() {
        let mut flipped = file.clone();
        flipped[index] ^= 0x80;
        let expected = match index {
            0..4 => AppDataError::NotAppData,
            4 => AppDataError::UnsupportedVersion {
                version: file[4] ^ 0x80,
                kdf: file[5],
            },
            5 => AppDataError::UnsupportedVersion {
                version: file[4],
                kdf: file[5] ^ 0x80,
            },
            // A changed salt or check gives another check value than the header holds.
            6..38 => AppDataError::ForeignWallet,
            _ => AppDataError::Damaged,
        };
        assert_eq!(
            app_data::open(&keychain, &flipped).unwrap_err(),
            expected,
            "byte {index}"
        );
    }
    for length in 0..file.len() {
        let expected = if length < HEADER_LEN {
            AppDataError::NotAppData
        } else {
            AppDataError::Damaged
        };
        assert_eq!(
            app_data::open(&keychain, &file[..length]).unwrap_err(),
            expected,
            "length {length}"
        );
    }
}
