// SPDX-License-Identifier: Apache-2.0
//! Mnemonic to entropy and back, with the node keychain's `mnemonic` module, which the wallet calls
//! for `WalletSeed::from_mnemonic` and `to_mnemonic`. The entropy is the wallet seed.

use epic_keychain::mnemonic;
use serde::Serialize;

use super::{AREA, Inconsistent, KeysPins, SEED_16, SEED_32, ensure};
use crate::{Error, Rendered, hex, render};

const VALID: [(&str, &[u8]); 6] = [
    ("mnemonic_12_words_zero", &[0x00; 16]),
    ("mnemonic_12_words_seed16", &SEED_16),
    ("mnemonic_15_words", &[0x7f; 20]),
    ("mnemonic_18_words", &[0x80; 24]),
    ("mnemonic_21_words", &[0xff; 28]),
    ("mnemonic_24_words_seed32", &SEED_32),
];

#[derive(Serialize)]
struct ValidInputs {
    entropy: String,
}

#[derive(Serialize)]
struct ValidExpected {
    word_count: usize,
    mnemonic: String,
}

#[derive(Serialize)]
struct ParseInputs<'a> {
    mnemonic: &'a str,
}

/// Exactly one of `entropy` and `error` is set. `error` is upstream's message, recorded so a
/// reader can see which check rejected the phrase.
#[derive(Serialize)]
struct ParseExpected {
    entropy: Option<String>,
    error: Option<String>,
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for (name, entropy) in VALID {
        let phrase = mnemonic::from_entropy(&entropy.to_vec())
            .map_err(|_| Error::reference("mnemonic from entropy")(Inconsistent(name)))?;
        let round_trip = mnemonic::to_entropy(&phrase)
            .map_err(|_| Error::reference("entropy from mnemonic")(Inconsistent(name)))?;
        ensure(round_trip == entropy, "mnemonic round trip")?;
        let expected = ValidExpected {
            word_count: phrase.split(' ').count(),
            mnemonic: phrase,
        };
        let inputs = ValidInputs {
            entropy: hex(entropy),
        };
        vectors.push(render(AREA, name, pins.node, inputs, expected)?);
    }
    for (name, phrase) in parse_cases()? {
        let expected = match mnemonic::to_entropy(&phrase) {
            Ok(entropy) => ParseExpected {
                entropy: Some(hex(entropy)),
                error: None,
            },
            Err(error) => ParseExpected {
                entropy: None,
                error: Some(error.to_string()),
            },
        };
        let inputs = ParseInputs { mnemonic: &phrase };
        vectors.push(render(AREA, name, pins.node, inputs, expected)?);
    }
    Ok(vectors)
}

/// Phrases derived from valid ones so that each case breaks exactly one rule, plus whitespace
/// variants that upstream accepts because it splits on any run of whitespace.
fn parse_cases() -> Result<Vec<(&'static str, String)>, Error> {
    let zero = mnemonic::from_entropy(&vec![0x00; 16])
        .map_err(|_| Error::reference("mnemonic from entropy")(Inconsistent("zero")))?;
    let seed16 = mnemonic::from_entropy(&SEED_16.to_vec())
        .map_err(|_| Error::reference("mnemonic from entropy")(Inconsistent("seed16")))?;
    let words: Vec<&str> = seed16.split(' ').collect();
    let (first, rest) = words
        .split_first()
        .ok_or(Error::reference("mnemonic words")(Inconsistent("empty")))?;
    let (_, all_but_last) = words
        .split_last()
        .ok_or(Error::reference("mnemonic words")(Inconsistent("empty")))?;

    let extra_whitespace = format!("  {}\n", words.join(" \t "));
    let uppercase_first = format!("{} {}", first.to_uppercase(), rest.join(" "));
    let unknown_first = format!("lepic {}", rest.join(" "));
    let eleven_words = all_but_last.join(" ");
    let thirteen_words = format!("{seed16} {first}");
    // Twelve copies of the first word of the zero phrase form a valid word sequence with a wrong
    // checksum.
    let bad_checksum = zero
        .split(' ')
        .next()
        .map(|word| [word; 12].join(" "))
        .ok_or(Error::reference("mnemonic words")(Inconsistent("empty")))?;

    Ok(vec![
        ("mnemonic_parse_extra_whitespace", extra_whitespace),
        ("mnemonic_parse_bad_checksum", bad_checksum),
        ("mnemonic_parse_unknown_word", unknown_first),
        ("mnemonic_parse_uppercase_word", uppercase_first),
        ("mnemonic_parse_11_words", eleven_words),
        ("mnemonic_parse_13_words", thirteen_words),
        ("mnemonic_parse_empty", String::new()),
    ])
}
