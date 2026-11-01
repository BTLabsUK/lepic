// SPDX-License-Identifier: Apache-2.0
//! Store area: what LEPIC keeps per peer Epicbox key, a sealed row under a keyed hash of the key
//! (ADR 0016, schema version 12 amendment). No upstream wallet has it; the row is written here
//! from its description by code independent of LEPIC's:
//!
//! - the two seed subkeys and the key tag are keyed BLAKE2b-256 by `blake2-rfc`, the
//!   implementation the node hashes with;
//! - the seal is XChaCha20-Poly1305 built from HChaCha20, written here from
//!   draft-irtf-cfrg-xchacha section 2.2 and checked against its test vector, and `ring`'s
//!   ChaCha20-Poly1305, so LEPIC's RustCrypto code is checked against it byte for byte.
//!
//! The nonce is a fixed input here; the store draws it.

use blake2_rfc::blake2b::blake2b;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde::Serialize;

use crate::{Error, Pins, Rendered, hex, render};

const AREA: &str = "store";

const CONTEXT_KEY_DOMAIN: &[u8] = b"lepic-wallet private context key v1";
const PEER_TAG_KEY_DOMAIN: &[u8] = b"lepic-wallet peer tag v1";
const TAG_DOMAIN: &[u8] = b"lepic-store peer tag v1";
const ASSOCIATED_DATA_DOMAIN: &[u8] = b"lepic-store peer compat v1";
const SEALED_FORMAT: u8 = 1;
const RECORD_VERSION: u8 = 1;

/// Fixed test-only seed entropy, peer keys and nonces. Never real wallet material.
struct Case {
    name: &'static str,
    entropy: [u8; 32],
    /// An Epicbox key as the store is given it, the base58 key text.
    peer_key: &'static str,
    nonce: [u8; 24],
    record: Record,
}

#[derive(Clone, Copy, Serialize)]
struct Record {
    /// Unix nanoseconds; `None` when absent.
    last_marked_at: Option<i64>,
    last_unmarked_at: Option<i64>,
    claimed: u32,
    works: u32,
    features_at: Option<i64>,
}

const CASES: [Case; 2] = [
    Case {
        name: "peer_compat",
        entropy: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        peer_key: "esWjXDfZ3w1Rv8FA9rB2U5A8NFmDCXiWkzhVZZP3zXpH5NL8bQq9",
        nonce: [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ],
        record: Record {
            last_marked_at: Some(1_790_000_000_123_456_789),
            last_unmarked_at: Some(1_790_000_100_000_000_000),
            claimed: 0b1011,
            works: 0b0001,
            features_at: Some(1_790_000_000_123_456_789),
        },
    },
    Case {
        name: "peer_compat_migrated",
        entropy: [
            0xa5, 0x5a, 0xc3, 0x3c, 0x96, 0x69, 0xf0, 0x0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xf0, 0x0f, 0x69, 0x96,
            0x3c, 0xc3, 0x5a, 0xa5,
        ],
        peer_key: "esZ7Ntn3V4FkxXqJ1sK6PZ9yCRMrBgQhW2u8oDcVmLAiTe5bF3Hp",
        nonce: [0; 24],
        // A row as the migration from schema version 11 writes a `lepic` one.
        record: Record {
            last_marked_at: Some(1_780_000_000_000_000_000),
            last_unmarked_at: None,
            claimed: 1,
            works: 1,
            features_at: None,
        },
    },
];

#[derive(Serialize)]
struct Inputs {
    entropy: String,
    peer_key: String,
    nonce: String,
    record: Record,
}

/// `context_key` and `peer_tag_key` are the seed subkeys, `key_tag` the row id, `record` the
/// plaintext and `sealed` the stored column: format byte, nonce, ciphertext and tag.
#[derive(Serialize)]
struct Expected {
    context_key: String,
    peer_tag_key: String,
    key_tag: String,
    associated_data: String,
    record: String,
    sealed: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Inconsistent(&'static str);

fn inconsistent(what: &'static str) -> Error {
    Error::reference("self-consistency check")(Inconsistent(what))
}

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    check_hchacha20()?;
    CASES.iter().map(|case| render_case(pins, case)).collect()
}

fn keyed(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let data: Vec<u8> = parts.concat();
    let mut out = [0; 32];
    out.copy_from_slice(blake2b(32, key, &data).as_bytes());
    out
}

fn record_bytes(record: &Record) -> Vec<u8> {
    let mut presence = 0_u8;
    for (time, bit) in [
        (record.last_marked_at, 1_u8),
        (record.last_unmarked_at, 2),
        (record.features_at, 4),
    ] {
        if time.is_some() {
            presence |= bit;
        }
    }
    let mut bytes = vec![RECORD_VERSION, presence];
    for time in [
        record.last_marked_at,
        record.last_unmarked_at,
        record.features_at,
    ] {
        bytes.extend_from_slice(&time.unwrap_or(0).to_be_bytes());
    }
    bytes.extend_from_slice(&record.claimed.to_be_bytes());
    bytes.extend_from_slice(&record.works.to_be_bytes());
    bytes
}

fn render_case(pins: &Pins, case: &Case) -> Result<Rendered, Error> {
    let context_key = keyed(&case.entropy, &[CONTEXT_KEY_DOMAIN]);
    let peer_tag_key = keyed(&case.entropy, &[PEER_TAG_KEY_DOMAIN]);
    let key_tag = keyed(&peer_tag_key, &[TAG_DOMAIN, case.peer_key.as_bytes()]);
    let associated_data = [ASSOCIATED_DATA_DOMAIN, &key_tag].concat();
    let record = record_bytes(&case.record);
    let sealed = seal(&context_key, &case.nonce, &associated_data, &record)?;
    if open(&context_key, &associated_data, &sealed)? != record {
        return Err(inconsistent("sealed row opens to its record"));
    }
    let inputs = Inputs {
        entropy: hex(case.entropy),
        peer_key: case.peer_key.to_owned(),
        nonce: hex(case.nonce),
        record: case.record,
    };
    let expected = Expected {
        context_key: hex(context_key),
        peer_tag_key: hex(peer_tag_key),
        key_tag: hex(key_tag),
        associated_data: hex(&associated_data),
        record: hex(&record),
        sealed: hex(&sealed),
    };
    render(AREA, case.name, &pins.node, inputs, expected)
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let get = |i: usize| state.get(i).copied().unwrap_or(0);
    let (mut va, mut vb, mut vc, mut vd) = (get(a), get(b), get(c), get(d));
    va = va.wrapping_add(vb);
    vd = (vd ^ va).rotate_left(16);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_left(12);
    va = va.wrapping_add(vb);
    vd = (vd ^ va).rotate_left(8);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_left(7);
    for (i, value) in [(a, va), (b, vb), (c, vc), (d, vd)] {
        if let Some(slot) = state.get_mut(i) {
            *slot = value;
        }
    }
}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0; N];
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        let mut le = [0; 4];
        le.copy_from_slice(chunk);
        *word = u32::from_le_bytes(le);
    }
    out
}

/// HChaCha20 of `key` and the first 16 bytes of the nonce: the ChaCha20 state after its 20
/// rounds, without the final addition, words 0..4 and 12..16.
fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let constants: [u32; 4] = words(b"expand 32-byte k");
    let key_words: [u32; 8] = words(key);
    let nonce_words: [u32; 4] = words(nonce);
    let mut state = [0_u32; 16];
    for (slot, value) in state
        .iter_mut()
        .zip(constants.iter().chain(&key_words).chain(&nonce_words))
    {
        *slot = *value;
    }
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0; 32];
    for (chunk, word) in out
        .chunks_exact_mut(4)
        .zip(state.iter().take(4).chain(state.iter().skip(12)))
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// draft-irtf-cfrg-xchacha-03 section 2.2.1.
fn check_hchacha20() -> Result<(), Error> {
    let mut key = [0_u8; 32];
    for (byte, value) in key.iter_mut().zip(0_u8..) {
        *byte = value;
    }
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];
    let expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";
    if hex(hchacha20(&key, &nonce)) != expected {
        return Err(inconsistent("hchacha20 test vector"));
    }
    Ok(())
}

fn ietf_key(key: &[u8; 32], nonce: &[u8; 24]) -> Result<(LessSafeKey, [u8; 12]), Error> {
    let mut head = [0; 16];
    head.copy_from_slice(nonce.get(..16).ok_or_else(|| inconsistent("nonce"))?);
    let subkey = hchacha20(key, &head);
    let mut ietf_nonce = [0; 12];
    if let Some(tail) = ietf_nonce.get_mut(4..) {
        tail.copy_from_slice(nonce.get(16..).ok_or_else(|| inconsistent("nonce"))?);
    }
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &subkey)
        .map_err(|_| inconsistent("ring refused the key"))?;
    Ok((LessSafeKey::new(unbound), ietf_nonce))
}

fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    let (aead, ietf_nonce) = ietf_key(key, nonce)?;
    let mut body = plain.to_vec();
    aead.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(ietf_nonce),
        Aad::from(aad),
        &mut body,
    )
    .map_err(|_| inconsistent("ring refused to seal"))?;
    let mut sealed = vec![SEALED_FORMAT];
    sealed.extend_from_slice(nonce);
    sealed.extend_from_slice(&body);
    Ok(sealed)
}

fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce: [u8; 24] = sealed
        .get(1..25)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| inconsistent("sealed nonce"))?;
    let (aead, ietf_nonce) = ietf_key(key, &nonce)?;
    let mut body = sealed
        .get(25..)
        .ok_or_else(|| inconsistent("sealed body"))?
        .to_vec();
    let plain = aead
        .open_in_place(
            Nonce::assume_unique_for_key(ietf_nonce),
            Aad::from(aad),
            &mut body,
        )
        .map_err(|_| inconsistent("ring refused to open"))?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{DEFAULT_OUT, LOCKFILE};

    #[test]
    fn regenerated_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        for vector in generate(&pins)? {
            let path = Path::new(DEFAULT_OUT)
                .join(AREA)
                .join(format!("{}.json", vector.name));
            assert_eq!(std::fs::read(&path)?, vector.bytes, "{}", path.display());
        }
        Ok(())
    }
}
