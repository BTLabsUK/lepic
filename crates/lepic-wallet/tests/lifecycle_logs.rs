//! The log test runs in its own binary: `tracing` caches per call site whether anyone listens,
//! and tests on other threads that run without a subscriber can reset that cache while this
//! test captures, which drops its records.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use std::path::PathBuf;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_primitives::params::Network;
use lepic_telemetry::{assert_no_secrets, capture};
use lepic_wallet::WordCount;
use support::{Harness, TestVault, WALLET_SEED_VECTOR, password, vector_text};

const PASSWORD: &str = "correct horse battery staple";
const WRONG_PASSWORD: &str = "incorrect horse";

/// Key material derived from a seed that must never be logged: the database context key (as
/// `lifecycle::context_key` derives it), the master key and chain code, and the first output key
/// of the default account.
fn derived_secrets(seed: &Seed) -> Vec<Vec<u8>> {
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).unwrap();
    mac.update(b"lepic-wallet private context key v1");
    let context_key: [u8; 32] = mac.finalize_fixed().into();
    let keychain = Keychain::from_seed(seed, Network::Mainnet).unwrap();
    let output_key = keychain
        .derive_key(
            0,
            &Identifier::new(3, [0, 0, 0, 0]).unwrap(),
            SwitchCommitment::None,
        )
        .unwrap();
    vec![
        context_key.to_vec(),
        keychain.master().secret_key().expose_bytes().to_vec(),
        keychain.master().chain_code().expose_bytes().to_vec(),
        output_key.expose_bytes().to_vec(),
    ]
}

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn lifecycle_operations_run_in_named_spans_and_never_log_secrets() {
    let vector: serde_json::Value = serde_json::from_str(WALLET_SEED_VECTOR).unwrap();
    let phrase_text = vector_text(&vector, "/inputs/mnemonic");
    let file_password = vector_text(&vector, "/inputs/password");
    let entropy = vector_text(&vector, "/inputs/entropy");
    let harness = Harness::new();

    let (phrase, captured) = capture(|| {
        let wallet = harness.wallet();
        let phrase = harness
            .block_on(wallet.create(password(PASSWORD), WordCount::default()))
            .unwrap();
        wallet.create_account("savings").unwrap();
        wallet.lock();
        harness
            .block_on(wallet.open(password(WRONG_PASSWORD)))
            .unwrap_err();
        harness.block_on(wallet.open(password(PASSWORD))).unwrap();
        wallet.close();

        let importer = harness.wallet_with(
            {
                let mut config = harness.config(Network::Mainnet);
                config.data_dir = PathBuf::from("/imported");
                config
            },
            TestVault::default(),
        );
        harness
            .block_on(importer.import_wallet_seed(
                password(PASSWORD),
                &vector_text(&vector, "/expected/file"),
                password(&file_password),
            ))
            .unwrap();
        importer.close();

        let restorer = harness.wallet_with(
            {
                let mut config = harness.config(Network::Mainnet);
                config.data_dir = PathBuf::from("/restored");
                config
            },
            TestVault::default(),
        );
        harness
            .block_on(restorer.restore(password(PASSWORD), &phrase_text))
            .unwrap();
        restorer.close();
        phrase
    });

    let created_seed = Seed::from_mnemonic(phrase.expose()).unwrap();
    let vector_seed = Seed::from_mnemonic(&phrase_text).unwrap();
    let mut secrets: Vec<&[u8]> = vec![
        PASSWORD.as_bytes(),
        WRONG_PASSWORD.as_bytes(),
        file_password.as_bytes(),
        entropy.as_bytes(),
        created_seed.expose_bytes(),
        vector_seed.expose_bytes(),
    ];
    let derived: Vec<Vec<u8>> = [&created_seed, &vector_seed]
        .into_iter()
        .flat_map(derived_secrets)
        .collect();
    secrets.extend(derived.iter().map(Vec::as_slice));
    let created_words: Vec<&str> = phrase.expose().split(' ').collect();
    let vector_words = phrase_text.clone();
    let vector_words: Vec<&str> = vector_words.split(' ').collect();
    // Two consecutive words are specific enough not to match ordinary log text by chance.
    let created_pairs: Vec<String> = created_words
        .windows(2)
        .map(|pair| pair.join(" "))
        .collect();
    let vector_pairs: Vec<String> = vector_words.windows(2).map(|pair| pair.join(" ")).collect();
    secrets.extend(created_pairs.iter().map(String::as_bytes));
    secrets.extend(vector_pairs.iter().map(String::as_bytes));
    assert_no_secrets(&captured.records, &secrets).unwrap();

    let messages: Vec<(&str, &[&str])> = captured
        .records
        .iter()
        .map(|record| (record.message.as_str(), record.spans.as_slice()))
        .collect();
    for (message, span) in [
        ("wallet created", "create"),
        ("account created", "create_account"),
        ("wallet locked", "lock"),
        ("wallet opened", "open"),
        ("wallet closed", "close"),
        ("wallet imported", "import_wallet_seed"),
        ("wallet restored", "restore"),
        // Logged on the blocking pool, which must keep the operation's span and subscriber.
        ("secret storage created", "create"),
        ("wallet database prepared", "create"),
        ("secret storage unlocked", "open"),
        ("wallet database prepared", "open"),
        ("wallet.seed decrypted", "import_wallet_seed"),
        ("wallet database prepared", "import_wallet_seed"),
        ("wallet database prepared", "restore"),
    ] {
        assert!(
            messages
                .iter()
                .any(|(logged, spans)| *logged == message && spans.contains(&span)),
            "no {message:?} in span {span:?}: {messages:?}"
        );
    }
    for record in &captured.records {
        assert_eq!(record.field("wallet"), Some("test"), "{record}");
    }
}
