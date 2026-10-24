// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::HashSet;

use common::Side;
use lepic_contact::{Network, Nonce, Sas, symbol};

const TABLE: &str = include_str!("../../../testdata/sas/emoji-v1.txt");

#[test]
fn the_table_has_256_distinct_single_codepoint_emoji_with_plain_names() {
    let lines: Vec<&str> = TABLE.lines().collect();
    assert_eq!(lines.len(), 256);
    assert!(TABLE.ends_with('\n'));
    let mut emoji = HashSet::new();
    let mut names = HashSet::new();
    for (index, line) in lines.iter().enumerate() {
        let (glyph, name) = line.split_once('\t').expect("emoji, tab, name");
        assert_eq!(glyph.chars().count(), 1, "line {index}: one code point");
        assert!(
            !name.is_empty() && name.len() <= 12 && name.bytes().all(|b| b.is_ascii_lowercase()),
            "line {index}: {name:?}"
        );
        assert!(emoji.insert(glyph), "line {index}: emoji repeats");
        assert!(names.insert(name), "line {index}: name repeats");
        let entry = symbol(u8::try_from(index).unwrap()).unwrap();
        assert_eq!((entry.emoji, entry.name), (glyph, name));
    }
}

#[test]
fn no_name_is_a_bip39_word() {
    let words: HashSet<&str> = bip39::Language::English
        .word_list()
        .iter()
        .copied()
        .collect();
    let clashes: Vec<&str> = TABLE
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(_, name)| name)
        .filter(|name| words.contains(name))
        .collect();
    assert!(clashes.is_empty(), "{clashes:?}");
}

#[test]
fn no_emoji_needs_a_variation_selector_or_skin_tone() {
    for line in TABLE.lines() {
        let glyph = line.split_once('\t').unwrap().0;
        for c in glyph.chars() {
            assert!(!matches!(c, '\u{FE0E}' | '\u{FE0F}' | '\u{200D}'), "{line}");
            assert!(!('\u{1F3FB}'..='\u{1F3FF}').contains(&c), "{line}");
            assert!(!('\u{1F1E6}'..='\u{1F1FF}').contains(&c), "{line}");
        }
    }
}

#[test]
fn both_sides_compute_the_same_sas_and_any_change_moves_it() {
    let (alice, bob, mallory) = (Side::new(1), Side::new(11), Side::new(31));
    let net = Network::Floonet;
    let (card_a, card_b) = (alice.card("Alice", net), bob.card("Bob", net));
    let (na, nb) = (Nonce::from_bytes([1; 16]), Nonce::from_bytes([2; 16]));
    let sas = Sas::compute(net, &card_a, &card_b, &na, &nb);
    assert_eq!(sas, Sas::compute(net, &card_a, &card_b, &na, &nb));
    assert_ne!(sas, Sas::compute(net, &card_b, &card_a, &na, &nb));
    assert_ne!(
        sas,
        Sas::compute(net, &mallory.card("Alice", net), &card_b, &na, &nb)
    );
    assert_ne!(
        sas,
        Sas::compute(net, &card_a, &card_b, &Nonce::from_bytes([3; 16]), &nb)
    );
    assert_ne!(
        sas,
        Sas::compute(net, &card_a, &card_b, &na, &Nonce::from_bytes([3; 16]))
    );
    let mainnet = Sas::compute(
        Network::Mainnet,
        &alice.card("Alice", Network::Mainnet),
        &bob.card("Bob", Network::Mainnet),
        &na,
        &nb,
    );
    assert_ne!(sas, mainnet);
    let symbols = sas.symbols().unwrap();
    for (symbol, byte) in symbols.iter().zip(sas.as_bytes()) {
        assert_eq!(*symbol, lepic_contact::symbol(*byte).unwrap());
    }
}

#[test]
fn in_person_sas_does_not_depend_on_who_scanned_first() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let net = Network::Floonet;
    let (card_a, card_b) = (alice.card("Alice", net), bob.card("Bob", net));
    assert_eq!(
        Sas::in_person(net, &card_a, &card_b),
        Sas::in_person(net, &card_b, &card_a)
    );
    let (low, high) = if card_a.sig_key().as_bytes() < card_b.sig_key().as_bytes() {
        (&card_a, &card_b)
    } else {
        (&card_b, &card_a)
    };
    assert_eq!(
        Sas::in_person(net, &card_a, &card_b),
        Sas::compute(net, low, high, &Nonce::zero(), &Nonce::zero())
    );
}

#[test]
fn every_byte_has_a_symbol() {
    for index in 0..=255u8 {
        assert!(symbol(index).is_ok());
    }
}
