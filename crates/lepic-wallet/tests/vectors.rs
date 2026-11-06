// SPDX-License-Identifier: Apache-2.0
//! Golden vector replays of the engine (docs/rules.md): `cargo xtask vectors verify` runs exactly
//! this target.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

#[path = "finalize/vectors.rs"]
mod finalize_vectors;
#[path = "invoice/harness.rs"]
mod invoice_harness;
#[path = "invoice/vectors.rs"]
mod invoice_vectors;
#[path = "receive/harness.rs"]
mod receive_harness;
#[path = "receive/vectors.rs"]
mod receive_vectors;
mod refresh_support;
mod scan_support;
mod selection_vectors;
mod send_vectors;
mod support;

use lepic_primitives::amount::Height;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use serde_json::Value;

/// The outcome LEPIC's refresh reports for a recorded session. Where the node's tip is below the
/// last refresh's height, upstream applies no output state and LEPIC changes nothing.
fn expected_refresh(vector: &Value) -> Option<RefreshOutcome> {
    let last_confirmed =
        refresh_support::number(&vector["inputs"]["before"]["last_confirmed_height"]);
    let tip = vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| exchange["method"] == "get_tip")
        .map(|exchange| refresh_support::number(&exchange["response"]["result"]["Ok"]["height"]))
        .unwrap();
    (tip < last_confirmed).then(|| RefreshOutcome::NodeBehind {
        tip: Height::new(tip),
        last_confirmed: Height::new(last_confirmed),
    })
}

/// Upstream's update stopped before its scan because it could not reach the node.
fn upstream_update_stopped(vector: &Value) -> bool {
    vector["expected"]["node_unreachable"] == true
}

#[test]
fn restore_vectors_find_exactly_the_outputs_upstream_found() {
    restore_every_vector();
}

/// The restore of [`restore_vectors_find_exactly_the_outputs_upstream_found`] on the plain
/// SQLite store; `cargo xtask budget` times it beside the encrypted one.
#[test]
fn restore_vectors_on_the_plain_sqlite_store() {
    support::with_store_kind(support::StoreKind::Sqlite, restore_every_vector);
}

/// The restore of [`restore_vectors_find_exactly_the_outputs_upstream_found`] on the SQLite
/// store encrypted at rest.
#[test]
fn restore_vectors_on_the_encrypted_sqlite_store() {
    support::with_store_kind(support::StoreKind::EncryptedSqlite, restore_every_vector);
}

fn restore_every_vector() {
    for (name, vector) in scan_support::restore_vectors() {
        let harness = scan_support::harness(&vector);
        let wallet = harness.wallet();
        scan_support::restore(&harness, &wallet, &vector);

        let summary = harness
            .block_on(wallet.scan(scan_support::options(&vector), &ScanCancel::new()))
            .unwrap();

        let expected = vector["expected"]["after"]["outputs"].as_array().unwrap();
        assert_eq!(summary.restored, expected.len() as u64, "{name}");
        assert!(!summary.resumed, "{name}");
        // The comparison reads the database as another program would, with no seed to derive
        // the encrypted store's key from; the plain runs cover it.
        if harness.stores.kind() != support::StoreKind::EncryptedSqlite {
            scan_support::assert_matches_upstream(&harness, &wallet, &vector, &name);
        }
    }
}

#[test]
fn refresh_vectors_end_in_the_states_upstream_reached() {
    for (name, vector) in refresh_support::refresh_vectors() {
        let harness = scan_support::harness(&vector);
        let wallet = harness.wallet();
        scan_support::restore(&harness, &wallet, &vector);
        let ids = refresh_support::seed_before(&harness, &vector);

        let outcome = harness.block_on(wallet.refresh()).unwrap();

        match expected_refresh(&vector) {
            Some(behind) => assert_eq!(outcome, behind, "{name}"),
            None => assert!(
                matches!(outcome, RefreshOutcome::Refreshed(_)),
                "{name}: {outcome:?}"
            ),
        }
        refresh_support::assert_matches_upstream(&harness, &wallet, &vector, &ids, &name);
    }
}

#[test]
fn refresh_then_update_scan_ends_where_upstream_update_ended() {
    for (name, vector) in refresh_support::refresh_vectors() {
        let harness = scan_support::harness(&vector);
        let wallet = harness.wallet();
        scan_support::restore(&harness, &wallet, &vector);
        let ids = refresh_support::seed_before(&harness, &vector);

        harness.block_on(wallet.refresh()).unwrap();
        if upstream_update_stopped(&vector) {
            refresh_support::assert_matches_upstream(&harness, &wallet, &vector, &ids, &name);
            refresh_support::assert_scanned_like_upstream(&wallet, &vector, &name);
            continue;
        }
        let options = ScanOptions {
            start: lepic_wallet::scan::ScanStart::LastScanned,
            ..scan_support::options(&vector)
        };
        let summary = harness
            .block_on(wallet.scan(options, &ScanCancel::new()))
            .unwrap();

        assert_eq!(summary.restored, 0, "{name}");
        refresh_support::assert_matches_upstream(&harness, &wallet, &vector, &ids, &name);
        refresh_support::assert_scanned_like_upstream(&wallet, &vector, &name);
    }
}

/// `testdata/vectors/keys/address_keys_seed32.json`: the previous onion key of a wallet
/// restored from the vector's seed is the address secret key of `m/0/0`, index 0, and its
/// public key is the payment-proof key `epic-wallet` derives.
#[test]
fn the_previous_onion_key_is_the_payment_proof_key_of_the_default_account() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/keys/address_keys_seed32.json");
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let case = vector["expected"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["parent_identifier"] == "0200000000000000000000000000000000" && case["index"] == 0
        })
        .unwrap();
    let seed_hex = vector["inputs"]["seed"].as_str().unwrap();
    let entropy = hex_bytes(seed_hex);
    let phrase = lepic_keychain::Seed::from_entropy(&entropy)
        .unwrap()
        .to_mnemonic()
        .unwrap();
    let harness = support::Harness::new();
    let wallet = harness.wallet();
    assert!(matches!(
        wallet.previous_onion_key(),
        Err(lepic_wallet::WalletError::Locked)
    ));

    harness
        .block_on(wallet.restore(support::password("vector password"), &phrase))
        .unwrap();
    let key = wallet.previous_onion_key().unwrap();

    assert_eq!(
        key.expose_seed().as_slice(),
        hex_bytes(case["address_secret_key"].as_str().unwrap())
    );
    assert_eq!(
        key.public_key().as_slice(),
        hex_bytes(case["payment_proof_public_key"].as_str().unwrap())
    );
    assert_eq!(format!("{key:?}"), "OnionKey([redacted])");
    wallet.lock();
    assert!(matches!(
        wallet.previous_onion_key(),
        Err(lepic_wallet::WalletError::Locked)
    ));
}

/// `testdata/vectors/keys/onion_key_*.json`: the onion key of a wallet restored from the
/// vector's seed is the generator's LEPIC-namespace key, not the payment-proof key.
#[test]
fn the_onion_key_is_the_namespace_key_of_the_vectors() {
    for name in ["onion_key_seed32", "onion_key_seed16"] {
        let vector = keys_vector(name);
        let harness = support::Harness::new();
        let wallet = restored(&harness, vector["inputs"]["seed"].as_str().unwrap());
        let expected = &vector["expected"];

        let key = wallet.onion_key().unwrap();

        assert_eq!(
            key.expose_seed().as_slice(),
            hex_bytes(expected["ed25519_seed"].as_str().unwrap()),
            "{name}"
        );
        assert_eq!(
            key.public_key().as_slice(),
            hex_bytes(expected["public_key"].as_str().unwrap()),
            "{name}"
        );
        let previous = wallet.previous_onion_key().unwrap();
        assert_ne!(key.public_key(), previous.public_key(), "{name}");
    }
}

/// `testdata/vectors/store_key/*.json`: the store key derived from the vector's phrase is the
/// key the vector's database key opens with, and its check file is accepted for that key and
/// refused for another seed's.
#[test]
fn store_key_vectors_open_their_database_and_check_file() {
    use lepic_store::{
        AtRest, STORE_KEY_LEN, SqliteStore, StoreError, StoreKey, StoreKeys, WalletStore,
    };
    use lepic_wallet::{ENCRYPTED_DATABASE_FILE, EncryptedSqliteStores, StoreOpener};

    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/store_key");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let name = vector["name"].as_str().unwrap();
        let seed =
            lepic_keychain::Seed::from_mnemonic(vector["inputs"]["mnemonic"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            seed.expose_bytes(),
            hex_bytes(vector["inputs"]["entropy"].as_str().unwrap()).as_slice(),
            "{name}"
        );
        let expected: [u8; STORE_KEY_LEN] =
            hex_bytes(vector["expected"]["store_key"].as_str().unwrap())
                .try_into()
                .unwrap();
        let derived = lepic_wallet::store_key(&seed).unwrap();
        let other =
            lepic_wallet::store_key(&lepic_keychain::Seed::from_entropy(&[0x77; 32]).unwrap())
                .unwrap();

        // A database made under the vector's key bytes opens with the derived key.
        let folder = tempfile::tempdir().unwrap();
        let database = folder.path().join(ENCRYPTED_DATABASE_FILE);
        let made = SqliteStore::open(
            &database,
            StoreKeys::from_bytes([0; 32], [0; 32]),
            AtRest::Encrypted(&StoreKey::from_bytes(expected)),
        )
        .unwrap();
        made.write(|repos| repos.put_setting("vector", name))
            .unwrap();
        drop(made);
        let mut check = database.as_os_str().to_owned();
        check.push(".check");
        std::fs::write(
            &check,
            hex_bytes(vector["expected"]["check_file"].as_str().unwrap()),
        )
        .unwrap();
        let opened = EncryptedSqliteStores
            .open(
                folder.path(),
                StoreKeys::from_bytes([0; 32], [0; 32]),
                &derived,
            )
            .unwrap();
        assert_eq!(
            opened
                .read(|repos| repos.setting("vector"))
                .unwrap()
                .as_deref(),
            Some(name)
        );
        drop(opened);
        assert_eq!(
            std::fs::read(&check).unwrap(),
            hex_bytes(vector["expected"]["check_file"].as_str().unwrap()),
            "{name}: an accepted check is kept"
        );
        let refused = EncryptedSqliteStores.open(
            folder.path(),
            StoreKeys::from_bytes([0; 32], [0; 32]),
            &other,
        );
        assert!(matches!(refused, Err(StoreError::WrongKey)), "{name}");
        seen += 1;
    }
    assert_eq!(seen, 3);
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn keys_vector(name: &str) -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../testdata/vectors/keys/{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(vector["area"], "keys");
    assert_eq!(vector["name"], name);
    vector
}

/// A wallet restored from the vector's seed, unlocked.
fn restored(harness: &support::Harness, seed_hex: &str) -> support::TestWallet {
    let phrase = lepic_keychain::Seed::from_entropy(&hex_bytes(seed_hex))
        .unwrap()
        .to_mnemonic()
        .unwrap();
    let wallet = harness.wallet();
    harness
        .block_on(wallet.restore(support::password("vector password"), &phrase))
        .unwrap();
    wallet
}

fn listing_of(case: &Value) -> lepic_wallet::namespace::Listing {
    lepic_wallet::namespace::Listing::from_hex(
        case["service_key"].as_str().unwrap(),
        u32::try_from(case["generation"].as_u64().unwrap()).unwrap(),
    )
    .unwrap()
}

/// `testdata/vectors/keys/listing_keys_*.json`: every listing key of a wallet restored from the
/// vector's seed is the keyed BLAKE2b the generator computed, for each directory and generation.
#[test]
fn listing_keys_are_the_vectors() {
    for name in ["listing_keys_seed32", "listing_keys_seed16"] {
        let vector = keys_vector(name);
        let harness = support::Harness::new();
        let wallet = restored(&harness, vector["inputs"]["seed"].as_str().unwrap());
        let cases = vector["expected"]["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6, "{name}");
        for case in cases {
            let key = wallet.address_key_at(&listing_of(case)).unwrap();
            assert_eq!(
                key.to_bytes().as_slice(),
                hex_bytes(case["public_key"].as_str().unwrap()),
                "{name}"
            );
        }
    }
}

/// `testdata/vectors/keys/listing_signatures.json`: one listing key signs the same message
/// under each app domain of the registry as the generator did, and each verifies only for its
/// own domain.
#[test]
fn listing_signatures_are_the_vectors() {
    let vector = keys_vector("listing_signatures");
    let harness = support::Harness::new();
    let wallet = restored(&harness, vector["inputs"]["seed"].as_str().unwrap());
    let listing = listing_of(&vector["inputs"]);
    let message = hex_bytes(vector["inputs"]["message"].as_str().unwrap());
    let key = wallet.address_key_at(&listing).unwrap();
    assert_eq!(
        key.to_bytes().as_slice(),
        hex_bytes(vector["expected"]["public_key"].as_str().unwrap())
    );
    let cases = vector["expected"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let domain = lepic_epicbox::ServiceDomain::parse(case["domain"].as_str().unwrap()).unwrap();
        let signature = wallet
            .sign_with_address_key_at(&listing, &domain, &message)
            .unwrap();
        assert_eq!(
            signature.to_der_hex(),
            case["signature_der"].as_str().unwrap(),
            "{}",
            domain.as_str()
        );
        for other in cases {
            let other_domain =
                lepic_epicbox::ServiceDomain::parse(other["domain"].as_str().unwrap()).unwrap();
            assert_eq!(
                lepic_epicbox::listing_message_verifies(&key, &other_domain, &message, &signature),
                other_domain == domain
            );
        }
    }
}

/// `testdata/vectors/keys/device_link_key_*.json`: the device-link signatures of a wallet
/// restored from the vector's seed are the generator's, and verify on that wallet.
#[test]
fn device_link_signatures_are_the_vectors() {
    for name in ["device_link_key_seed32", "device_link_key_seed16"] {
        let vector = keys_vector(name);
        let harness = support::Harness::new();
        let wallet = restored(&harness, vector["inputs"]["seed"].as_str().unwrap());
        for case in vector["expected"]["cases"].as_array().unwrap() {
            let transcript = hex_bytes(case["transcript"].as_str().unwrap());
            let signature = wallet.device_link_sign(&transcript).unwrap();
            assert_eq!(
                signature.as_slice(),
                hex_bytes(case["signature"].as_str().unwrap()),
                "{name}"
            );
            assert!(wallet.device_link_verify(&transcript, &signature).unwrap());
        }
    }
}
