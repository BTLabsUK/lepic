//! The log test runs in its own binary: `tracing` caches per call site whether anyone listens,
//! and tests on other threads that run without a subscriber can reset that cache while this
//! test captures, which drops its records.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_primitives::params::Network;
use lepic_telemetry::{assert_no_secrets, capture};
use lepic_wallet::WordCount;
use support::{Harness, password};

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn sealing_and_opening_app_data_log_and_return_no_root_secret() {
    let harness = Harness::new();
    let ((phrase, file, opened, foreign), captured) = capture(|| {
        let wallet = harness.wallet();
        let phrase = harness
            .block_on(wallet.create(password(PASSWORD), WordCount::default()))
            .unwrap();
        let file = wallet.seal_app_data(b"payload").unwrap();
        let opened = wallet.open_app_data(&file).unwrap().to_vec();
        let mut other = file.clone();
        other[30] ^= 1;
        let foreign = wallet.open_app_data(&other).unwrap_err().to_string();
        (phrase, file, opened, foreign)
    });

    let seed = Seed::from_mnemonic(phrase.expose()).unwrap();
    let root = Keychain::from_seed(&seed, Network::Mainnet)
        .unwrap()
        .derive_key(0, &Identifier::ROOT, SwitchCommitment::Regular)
        .unwrap();
    let root = root.expose_bytes();

    let records = &captured.records;
    let messages: Vec<&str> = records.iter().map(|r| r.message.as_str()).collect();
    assert!(messages.contains(&"app data sealed"), "{messages:?}");
    assert!(messages.contains(&"app data opened"), "{messages:?}");
    assert_no_secrets(records, &[root, seed.expose_bytes()]).unwrap();

    assert_eq!(opened, b"payload");
    assert!(!file.windows(root.len()).any(|window| window == root));
    let root_hex: String = root.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!foreign.contains(&root_hex));
}
