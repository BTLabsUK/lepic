// SPDX-License-Identifier: Apache-2.0
//! Store key area: the key LEPIC encrypts a wallet database under and the key check file
//! beside it (ADR 0032). LEPIC's own derivation, with no upstream counterpart: the seed is the
//! BIP39 entropy `epic_keychain::mnemonic` reads from the phrase, and the BLAKE2b is
//! `blake2_rfc`'s, so LEPIC's RustCrypto code is checked against an independent implementation
//! of the description below. The check's salt is a fixed input here; LEPIC draws it.
//!
//! - `store_key = BLAKE2b-256(key = seed, "lepic-wallet store key v1")`
//! - check file = `0x01 ‖ salt(16) ‖ BLAKE2b-128(key = store_key, "lepic-wallet store check v1" ‖ salt)`

use blake2_rfc::blake2b::blake2b;
use epic_keychain::mnemonic;
use serde::Serialize;

use crate::{Error, Pins, Rendered, hex, render};

const AREA: &str = "store_key";

const STORE_KEY_DOMAIN: &[u8] = b"lepic-wallet store key v1";
const CHECK_DOMAIN: &[u8] = b"lepic-wallet store check v1";
const CHECK_FORMAT: u8 = 1;

/// Fixed test-only seeds and salts. Never real wallet material.
struct Case {
    name: &'static str,
    entropy: &'static [u8],
    salt: [u8; 16],
}

const CASES: [Case; 3] = [
    Case {
        name: "store_key_seed_a",
        entropy: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        salt: [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ],
    },
    Case {
        name: "store_key_seed_a_other_salt",
        entropy: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        salt: [0; 16],
    },
    Case {
        name: "store_key_seed_12_words",
        entropy: &[
            0xa5, 0x5a, 0xc3, 0x3c, 0x96, 0x69, 0xf0, 0x0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ],
        salt: [0xff; 16],
    },
];

#[derive(Serialize)]
struct Inputs {
    mnemonic: String,
    entropy: String,
    salt: String,
}

#[derive(Serialize)]
struct Expected {
    store_key: String,
    check_file: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Inconsistent(&'static str);

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    CASES.iter().map(|case| render_case(pins, case)).collect()
}

fn render_case(pins: &Pins, case: &Case) -> Result<Rendered, Error> {
    let phrase = mnemonic::from_entropy(&case.entropy.to_vec())
        .map_err(|_| Error::reference("mnemonic from entropy")(Inconsistent("entropy")))?;
    let seed = mnemonic::to_entropy(&phrase)
        .map_err(|_| Error::reference("entropy from mnemonic")(Inconsistent("phrase")))?;
    if seed != case.entropy {
        return Err(Error::reference("self-consistency check")(Inconsistent(
            "the phrase gives back its entropy",
        )));
    }
    let store_key = blake2b(32, &seed, STORE_KEY_DOMAIN);
    let mut message = CHECK_DOMAIN.to_vec();
    message.extend_from_slice(&case.salt);
    let tag = blake2b(16, store_key.as_bytes(), &message);
    let mut check_file = vec![CHECK_FORMAT];
    check_file.extend_from_slice(&case.salt);
    check_file.extend_from_slice(tag.as_bytes());
    let inputs = Inputs {
        mnemonic: phrase,
        entropy: hex(case.entropy),
        salt: hex(case.salt),
    };
    let expected = Expected {
        store_key: hex(store_key.as_bytes()),
        check_file: hex(&check_file),
    };
    render(AREA, case.name, &pins.node, inputs, expected)
}
