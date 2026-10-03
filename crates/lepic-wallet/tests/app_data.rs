// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

use lepic_keychain::AppDataError;
use lepic_keychain::app_data::{HEADER_LEN, MAX_PAYLOAD_LEN};
use lepic_wallet::{WalletError, WordCount};
use support::{Harness, TestWallet, password, vector_text};

const PASSWORD: &str = "correct horse battery staple";
const PAYLOAD: &[u8] = br#"{"format":"wfe-history","version":1,"txs":[]}"#;

const GOLDEN: &str = include_str!("../../../testdata/vectors/app_data/wfeh_seed_a.json");

fn created(harness: &Harness) -> (TestWallet, String) {
    let wallet = harness.wallet();
    let phrase = harness
        .block_on(wallet.create(password(PASSWORD), WordCount::default()))
        .unwrap();
    (wallet, phrase.expose().to_owned())
}

fn restored(harness: &Harness, phrase: &str) -> TestWallet {
    let wallet = harness.wallet();
    harness
        .block_on(wallet.restore(password(PASSWORD), phrase))
        .unwrap();
    wallet
}

fn app_data_error(result: Result<impl std::fmt::Debug, WalletError>) -> AppDataError {
    match result {
        Err(WalletError::AppData(error)) => error,
        other => panic!("expected an app data error, got {other:?}"),
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_sealed_file_opens_to_its_payload_and_differs_on_every_seal() {
    let harness = Harness::new();
    let (wallet, _) = created(&harness);

    let first = wallet.seal_app_data(PAYLOAD).unwrap();
    let second = wallet.seal_app_data(PAYLOAD).unwrap();

    assert_eq!(&first[..6], b"WFEH\x01\x01");
    assert_eq!(first.len(), HEADER_LEN + PAYLOAD.len() + 16);
    assert_eq!(&wallet.open_app_data(&first).unwrap()[..], PAYLOAD);
    assert_eq!(&wallet.open_app_data(&second).unwrap()[..], PAYLOAD);
    // Salt at 6..22, nonce at 38..50: both fresh for each file.
    assert_ne!(first[6..22], second[6..22]);
    assert_ne!(first[38..50], second[38..50]);
    assert_ne!(first[HEADER_LEN..], second[HEADER_LEN..]);
}

#[test]
fn a_wallet_restored_from_the_phrase_opens_the_file() {
    let original = Harness::new();
    let (wallet, phrase) = created(&original);
    let file = wallet.seal_app_data(PAYLOAD).unwrap();

    let elsewhere = Harness::new();
    let restored = restored(&elsewhere, &phrase);
    assert_eq!(&restored.open_app_data(&file).unwrap()[..], PAYLOAD);
}

#[test]
fn the_golden_file_opens_to_its_payload_in_the_wallet_of_its_phrase() {
    let vector: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    let harness = Harness::new();
    let wallet = restored(&harness, &vector_text(&vector, "/inputs/mnemonic"));
    let file = unhex(&vector_text(&vector, "/expected/file"));
    let payload = vector_text(&vector, "/inputs/payload");
    assert_eq!(
        &wallet.open_app_data(&file).unwrap()[..],
        payload.as_bytes()
    );
}

#[test]
fn another_wallets_file_is_told_apart_from_a_damaged_one() {
    let harness = Harness::new();
    let (wallet, _) = created(&harness);
    let other = Harness::new();
    let other_wallet = restored(
        &other,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about",
    );
    let file = other_wallet.seal_app_data(PAYLOAD).unwrap();

    assert_eq!(
        app_data_error(wallet.open_app_data(&file)),
        AppDataError::ForeignWallet
    );

    let own = wallet.seal_app_data(PAYLOAD).unwrap();
    for index in [HEADER_LEN - 1, HEADER_LEN, own.len() - 1] {
        let mut flipped = own.clone();
        flipped[index] ^= 0x01;
        assert_eq!(
            app_data_error(wallet.open_app_data(&flipped)),
            AppDataError::Damaged,
            "byte {index}"
        );
    }
    assert_eq!(
        app_data_error(wallet.open_app_data(&own[..own.len() - 1])),
        AppDataError::Damaged
    );
}

#[test]
fn unknown_formats_and_versions_have_their_own_errors() {
    let harness = Harness::new();
    let (wallet, _) = created(&harness);
    let file = wallet.seal_app_data(PAYLOAD).unwrap();

    assert_eq!(
        app_data_error(wallet.open_app_data(b"not a file")),
        AppDataError::NotAppData
    );
    assert_eq!(
        app_data_error(wallet.open_app_data(&file[..HEADER_LEN - 1])),
        AppDataError::NotAppData
    );
    let mut newer = file.clone();
    newer[4] = 2;
    assert_eq!(
        app_data_error(wallet.open_app_data(&newer)),
        AppDataError::UnsupportedVersion { version: 2, kdf: 1 }
    );
    let mut other_kdf = file;
    other_kdf[5] = 9;
    assert_eq!(
        app_data_error(wallet.open_app_data(&other_kdf)),
        AppDataError::UnsupportedVersion { version: 1, kdf: 9 }
    );
}

#[test]
fn oversized_payloads_and_files_are_refused() {
    let harness = Harness::new();
    let (wallet, _) = created(&harness);
    let too_big = vec![0u8; MAX_PAYLOAD_LEN + 1];
    assert!(matches!(
        app_data_error(wallet.seal_app_data(&too_big)),
        AppDataError::TooLong { .. }
    ));
    let too_big = vec![0u8; MAX_PAYLOAD_LEN + HEADER_LEN + 17];
    assert!(matches!(
        app_data_error(wallet.open_app_data(&too_big)),
        AppDataError::TooLong { .. }
    ));
}

#[test]
fn a_locked_wallet_neither_seals_nor_opens() {
    let harness = Harness::new();
    let (wallet, _) = created(&harness);
    let file = wallet.seal_app_data(PAYLOAD).unwrap();
    wallet.lock();
    assert!(matches!(
        wallet.seal_app_data(PAYLOAD),
        Err(WalletError::Locked)
    ));
    assert!(matches!(
        wallet.open_app_data(&file),
        Err(WalletError::Locked)
    ));
}
