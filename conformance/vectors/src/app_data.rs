// SPDX-License-Identifier: Apache-2.0
//! App data area: the wallet root secret `epic-wallet` derives at `m` with
//! `derive_key(0, root_key_id, Regular)`, recorded only as the BLAKE2b-256 hash its
//! `set_keychain` stores as the master checksum, and a `WFEH` version 1 file sealed under it.
//!
//! The file is sealed by an independent implementation of the format in `docs/compat/wfeh.md`
//! over `ring`, the library the host app seals these files with, so LEPIC's RustCrypto code is
//! checked against it byte for byte. Salt and nonce are fixed inputs here; the app draws them.

use blake2_rfc::blake2b::blake2b;
use epic_keychain::{ExtKeychain, Keychain, SwitchCommitmentType, mnemonic};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use serde::Serialize;

use crate::{Error, Pins, Rendered, hex, render};

const AREA: &str = "app_data";

const MAGIC: &[u8; 4] = b"WFEH";
const VERSION: u8 = 1;
const KDF_ROOT_SECRET: u8 = 1;
const SALT_LEN: usize = 16;
const CHECK_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SALT_START: usize = MAGIC.len() + 2;
const NONCE_START: usize = SALT_START + SALT_LEN + CHECK_LEN;
const HEADER_LEN: usize = NONCE_START + NONCE_LEN;
const INFO_KEY: &[u8] = b"wfe-history-export-v1/key";
const INFO_CHECK: &[u8] = b"wfe-history-export-v1/check";

/// A payload of the shape the app's history backup carries. Test data only.
const PAYLOAD: &str = concat!(
    r#"{"format":"wfe-history","version":1,"chain":"Mainnet","#,
    r#""wallet_fp":"00112233445566778899aabbccddeeff","exported_at_unix":1790000000,"#,
    r#""app_version":"1.0.0","last_confirmed_height":123456,"#,
    r#""txs":[{"slate_id":"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0","kind":"Sent","#,
    r#""status":"Confirmed","note":"rent"}],"contacts":[]}"#
);

/// Fixed test-only seeds, salts and nonces. Never real wallet material.
struct Case {
    name: &'static str,
    entropy: [u8; 32],
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    payload: &'static [u8],
}

const CASES: [Case; 3] = [
    Case {
        name: "wfeh_seed_a",
        entropy: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        salt: [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ],
        nonce: [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
        ],
        payload: PAYLOAD.as_bytes(),
    },
    Case {
        name: "wfeh_seed_b",
        entropy: [
            0xa5, 0x5a, 0xc3, 0x3c, 0x96, 0x69, 0xf0, 0x0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xf0, 0x0f, 0x69, 0x96,
            0x3c, 0xc3, 0x5a, 0xa5,
        ],
        salt: [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
            0x23, 0x01,
        ],
        nonce: [
            0x5e, 0x5e, 0x5e, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ],
        payload: PAYLOAD.as_bytes(),
    },
    Case {
        name: "wfeh_seed_a_empty_payload",
        entropy: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        salt: [0; 16],
        nonce: [0xff; 12],
        payload: b"",
    },
];

#[derive(Serialize)]
struct Inputs {
    mnemonic: String,
    entropy: String,
    salt: String,
    nonce: String,
    payload: String,
}

/// `root_secret_blake2b` is the unkeyed BLAKE2b-256 of the root secret, never the secret.
/// `check` is the header's check value; `file` is the whole sealed file. The root secret is the
/// same on every network, since the network changes only the extended key's version bytes.
#[derive(Serialize)]
struct Expected {
    root_secret_blake2b: String,
    check: String,
    file: String,
}

/// Raised when the reference code disagrees with itself. A vector is never written from such a
/// run.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Inconsistent(&'static str);

fn inconsistent(what: &'static str) -> Error {
    Error::reference("self-consistency check")(Inconsistent(what))
}

/// `ring` reports failures as a unit error without `std::error::Error`.
fn ring_failed(step: &'static str) -> impl FnOnce(ring::error::Unspecified) -> Error {
    move |_| Error::reference(step)(Inconsistent("ring refused the operation"))
}

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    CASES.iter().map(|case| render_case(pins, case)).collect()
}

fn render_case(pins: &Pins, case: &Case) -> Result<Rendered, Error> {
    let phrase = mnemonic::from_entropy(&case.entropy.to_vec())
        .map_err(|_| inconsistent("mnemonic from entropy"))?;
    let root = root_secret(&case.entropy)?;
    let (file, check) = seal(&root, case)?;
    if open(&root, &file)? != case.payload {
        return Err(inconsistent("sealed file opens to its payload"));
    }
    let payload = std::str::from_utf8(case.payload)
        .map_err(|_| inconsistent("payload is text"))?
        .to_owned();
    let inputs = Inputs {
        mnemonic: phrase,
        entropy: hex(case.entropy),
        salt: hex(case.salt),
        nonce: hex(case.nonce),
        payload,
    };
    let expected = Expected {
        root_secret_blake2b: hex(blake2b(32, &[], &root).as_bytes()),
        check: hex(check),
        file: hex(&file),
    };
    render(AREA, case.name, &pins.node, inputs, expected)
}

fn root_secret(entropy: &[u8]) -> Result<[u8; 32], Error> {
    let mut roots = [false, true].into_iter().map(|is_floonet| {
        let keychain = ExtKeychain::from_seed(entropy, is_floonet)
            .map_err(Error::reference("keychain from seed"))?;
        let root = keychain
            .derive_key(
                0,
                &ExtKeychain::root_key_id(),
                &SwitchCommitmentType::Regular,
            )
            .map_err(Error::reference("root secret"))?;
        Ok::<_, Error>(root.0)
    });
    let mainnet = roots.next().ok_or_else(|| inconsistent("mainnet root"))??;
    let floonet = roots.next().ok_or_else(|| inconsistent("floonet root"))??;
    if mainnet != floonet {
        return Err(inconsistent("root secret is the same on every network"));
    }
    Ok(mainnet)
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn keys(root: &[u8], salt: &[u8]) -> Result<(LessSafeKey, [u8; CHECK_LEN]), Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(root);
    let okm = prk
        .expand(&[INFO_KEY], &CHACHA20_POLY1305)
        .map_err(ring_failed("hkdf key"))?;
    let key = LessSafeKey::new(UnboundKey::from(okm));
    let mut check = [0u8; CHECK_LEN];
    prk.expand(&[INFO_CHECK], Len(CHECK_LEN))
        .and_then(|okm| okm.fill(&mut check))
        .map_err(ring_failed("hkdf check"))?;
    Ok((key, check))
}

fn seal(root: &[u8], case: &Case) -> Result<(Vec<u8>, [u8; CHECK_LEN]), Error> {
    let (key, check) = keys(root, &case.salt)?;
    let mut file = Vec::new();
    file.extend_from_slice(MAGIC);
    file.push(VERSION);
    file.push(KDF_ROOT_SECRET);
    file.extend_from_slice(&case.salt);
    file.extend_from_slice(&check);
    file.extend_from_slice(&case.nonce);
    let mut body = case.payload.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(case.nonce),
        Aad::from(file.as_slice()),
        &mut body,
    )
    .map_err(ring_failed("seal"))?;
    file.extend_from_slice(&body);
    Ok((file, check))
}

fn open(root: &[u8], file: &[u8]) -> Result<Vec<u8>, Error> {
    let header = file
        .get(..HEADER_LEN)
        .ok_or_else(|| inconsistent("header"))?;
    let salt = header
        .get(SALT_START..SALT_START + SALT_LEN)
        .ok_or_else(|| inconsistent("salt"))?;
    let nonce: [u8; NONCE_LEN] = header
        .get(NONCE_START..)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| inconsistent("nonce"))?;
    let (key, _) = keys(root, salt)?;
    let mut body = file
        .get(HEADER_LEN..)
        .ok_or_else(|| inconsistent("body"))?
        .to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut body,
        )
        .map_err(ring_failed("open"))?;
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
