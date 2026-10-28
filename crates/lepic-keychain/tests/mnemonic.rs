// SPDX-License-Identifier: Apache-2.0
use lepic_keychain::{MnemonicError, Seed};
use proptest::prelude::*;

const SEED16_PHRASE: &str =
    "pipe stock song coast pair always emotion member joy sting dash theory";

#[test]
fn rejects_phrase_with_wrong_word_count() {
    for count in [1, 11, 13, 14, 25] {
        let phrase = vec!["abandon"; count].join(" ");
        assert_eq!(
            Seed::from_mnemonic(&phrase).err(),
            Some(MnemonicError::WordCount { actual: count })
        );
    }
}

#[test]
fn rejects_whitespace_only_phrase() {
    assert_eq!(
        Seed::from_mnemonic(" \t\n ").err(),
        Some(MnemonicError::WordCount { actual: 0 })
    );
}

#[test]
fn reports_position_of_unknown_word() {
    let phrase = SEED16_PHRASE.replace("joy", "joyful");
    assert_eq!(
        Seed::from_mnemonic(&phrase).err(),
        Some(MnemonicError::UnknownWord { position: 8 })
    );
}

#[test]
fn rejects_capitalised_and_accented_words() {
    for phrase in [
        SEED16_PHRASE.replace("pipe", "Pipe"),
        SEED16_PHRASE.replace("theory", "théory"),
    ] {
        assert!(matches!(
            Seed::from_mnemonic(&phrase),
            Err(MnemonicError::UnknownWord { .. })
        ));
    }
}

#[test]
fn rejects_swapped_words_by_checksum() {
    let phrase = SEED16_PHRASE.replace("pipe stock", "stock pipe");
    assert_eq!(
        Seed::from_mnemonic(&phrase).err(),
        Some(MnemonicError::Checksum)
    );
}

#[test]
fn error_text_does_not_repeat_the_words() {
    let phrase = SEED16_PHRASE.replace("joy", "secretword");
    let error = Seed::from_mnemonic(&phrase).err().unwrap();
    assert!(!error.to_string().contains("secretword"));
    assert!(!format!("{error:?}").contains("secretword"));
}

proptest! {
    #[test]
    fn entropy_round_trips_through_mnemonic(
        len in prop::sample::select(vec![16usize, 20, 24, 28, 32]),
        bytes in prop::collection::vec(any::<u8>(), 32),
    ) {
        let entropy = &bytes[..len];
        let seed = Seed::from_entropy(entropy).unwrap();
        let phrase = seed.to_mnemonic().unwrap();
        prop_assert_eq!(phrase.split(' ').count(), seed.word_count());
        let parsed = Seed::from_mnemonic(&phrase).unwrap();
        prop_assert_eq!(parsed.expose_bytes(), entropy);
    }
}
