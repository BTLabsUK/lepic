// SPDX-License-Identifier: Apache-2.0
//! App data files: the host app's encrypted backups, in the `WFEH` version 1 format that its
//! history export already writes, so files made before the app moved to LEPIC still open.
//!
//! ```text
//! magic    4  "WFEH"
//! version  1  1
//! kdf      1  1 = HKDF-SHA256 over the wallet's root secret
//! salt    16  fresh for every file
//! check   16  HKDF output with info `wfe-history-export-v1/check`
//! nonce   12  ChaCha20-Poly1305 nonce, fresh for every file
//! sealed   *  ciphertext of the payload, then the 16-byte tag
//! ```
//!
//! The 50-byte header is the associated data. The key is the HKDF output with info
//! `wfe-history-export-v1/key`. Both HKDF outputs use the per-file salt and the root secret,
//! which is the key `epic-wallet` derives with `derive_key(0, root_key_id, Regular)`. A wallet
//! restored from the same phrase opens its own files; `check` tells another wallet's file apart
//! from a damaged one and reveals nothing about the key. `docs/compat/wfeh.md` has the details.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::identifier::Identifier;
use crate::keychain::{Keychain, KeychainError, SwitchCommitment};

pub const MAGIC: [u8; 4] = *b"WFEH";
pub const FORMAT_VERSION: u8 = 1;
const KDF_ROOT_SECRET_HKDF_SHA256: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const CHECK_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + SALT_LEN + CHECK_LEN + NONCE_LEN;

/// The largest payload sealed or opened. The app refuses larger backup files before reading
/// them, so no file it wrote is larger.
pub const MAX_PAYLOAD_LEN: usize = 32 * 1024 * 1024;
const OVERHEAD: usize = HEADER_LEN + TAG_LEN;
pub const MAX_FILE_LEN: usize = MAX_PAYLOAD_LEN + OVERHEAD;

const INFO_KEY: &[u8] = b"wfe-history-export-v1/key";
const INFO_CHECK: &[u8] = b"wfe-history-export-v1/check";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AppDataError {
    #[error("not an app data file")]
    NotAppData,
    #[error("app data format version {version} with key derivation {kdf} is not supported")]
    UnsupportedVersion { version: u8, kdf: u8 },
    /// The file is intact but was sealed under another wallet's root secret.
    #[error("app data file belongs to another wallet")]
    ForeignWallet,
    /// The file is this wallet's, but a byte was changed or the file was cut short.
    #[error("app data file is damaged")]
    Damaged,
    #[error("app data of {actual} bytes exceeds the limit of {max} bytes")]
    TooLong { actual: usize, max: usize },
    #[error("app data key derivation failed")]
    Keychain(#[from] KeychainError),
    #[error("app data encryption failed")]
    Encryption,
}

/// Seals `payload` for the wallet of `keychain`. The caller draws `salt` and `nonce` fresh for
/// every file; a repeated nonce under one salt reveals the payloads.
pub fn seal(
    keychain: &Keychain,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, AppDataError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(AppDataError::TooLong {
            actual: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }
    let keys = FileKeys::derive(keychain, &salt)?;
    let mut file = Vec::with_capacity(payload.len().saturating_add(OVERHEAD));
    file.extend_from_slice(&MAGIC);
    file.push(FORMAT_VERSION);
    file.push(KDF_ROOT_SECRET_HKDF_SHA256);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&keys.check);
    file.extend_from_slice(&nonce);
    let mut sealed = Zeroizing::new(payload.to_vec());
    let tag = keys
        .cipher()
        .encrypt_inout_detached(&nonce.into(), &file, sealed.as_mut_slice().into())
        .map_err(|_| AppDataError::Encryption)?;
    file.extend_from_slice(&sealed);
    file.extend_from_slice(&tag);
    Ok(file)
}

/// Opens a file [`seal`] made for the wallet of `keychain`. Work and allocation are bounded by
/// [`MAX_FILE_LEN`]; the checks run in the order of the error variants.
pub fn open(keychain: &Keychain, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppDataError> {
    if file.len() > MAX_FILE_LEN {
        return Err(AppDataError::TooLong {
            actual: file.len(),
            max: MAX_FILE_LEN,
        });
    }
    let header = Header::parse(file)?;
    let keys = FileKeys::derive(keychain, &header.salt)?;
    if !equal_in_constant_time(&keys.check, &header.check) {
        return Err(AppDataError::ForeignWallet);
    }
    let body = file.get(HEADER_LEN..).ok_or(AppDataError::NotAppData)?;
    let body_len = body
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(AppDataError::Damaged)?;
    let (ciphertext, tag) = body.split_at(body_len);
    let tag = Tag::try_from(tag).map_err(|_| AppDataError::Damaged)?;
    let aad = file.get(..HEADER_LEN).ok_or(AppDataError::NotAppData)?;
    let mut payload = Zeroizing::new(ciphertext.to_vec());
    keys.cipher()
        .decrypt_inout_detached(
            &header.nonce.into(),
            aad,
            payload.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| AppDataError::Damaged)?;
    Ok(payload)
}

struct Header {
    salt: [u8; SALT_LEN],
    check: [u8; CHECK_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn parse(file: &[u8]) -> Result<Self, AppDataError> {
        let header: &[u8; HEADER_LEN] = file
            .get(..HEADER_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(AppDataError::NotAppData)?;
        let (magic, rest) = header.split_at(MAGIC.len());
        if magic != MAGIC {
            return Err(AppDataError::NotAppData);
        }
        let [version, kdf, rest @ ..] = rest else {
            return Err(AppDataError::NotAppData);
        };
        if *version != FORMAT_VERSION || *kdf != KDF_ROOT_SECRET_HKDF_SHA256 {
            return Err(AppDataError::UnsupportedVersion {
                version: *version,
                kdf: *kdf,
            });
        }
        let (salt, rest) = rest.split_at(SALT_LEN);
        let (check, nonce) = rest.split_at(CHECK_LEN);
        Ok(Self {
            salt: array(salt)?,
            check: array(check)?,
            nonce: array(nonce)?,
        })
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AppDataError> {
    bytes.try_into().map_err(|_| AppDataError::NotAppData)
}

/// Compares derived values without stopping at the first difference.
fn equal_in_constant_time(ours: &[u8; CHECK_LEN], theirs: &[u8; CHECK_LEN]) -> bool {
    ours.iter()
        .zip(theirs)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// The cipher key and check value of one file. The key is wiped on drop.
struct FileKeys {
    key: Zeroizing<[u8; 32]>,
    check: [u8; CHECK_LEN],
}

impl FileKeys {
    fn derive(keychain: &Keychain, salt: &[u8; SALT_LEN]) -> Result<Self, AppDataError> {
        // epic-wallet's root secret: the master key, switched for amount zero.
        let root = keychain.derive_key(0, &Identifier::ROOT, SwitchCommitment::Regular)?;
        let hkdf = Hkdf::<Sha256>::new(Some(salt), root.expose_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(INFO_KEY, key.as_mut_slice())
            .map_err(|_| AppDataError::Encryption)?;
        let mut check = [0u8; CHECK_LEN];
        hkdf.expand(INFO_CHECK, &mut check)
            .map_err(|_| AppDataError::Encryption)?;
        Ok(Self { key, check })
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new((&*self.key).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn constant_time_comparison_sees_a_difference_in_any_position() {
        let ours = [7u8; CHECK_LEN];
        assert!(equal_in_constant_time(&ours, &ours));
        for index in 0..CHECK_LEN {
            let mut theirs = ours;
            theirs[index] ^= 0x80;
            assert!(!equal_in_constant_time(&ours, &theirs));
        }
    }

    /// RFC 5869 appendix A, test cases 1 to 3: HKDF-SHA256 as `FileKeys` calls it, with a salt
    /// (an empty one in case 3) and outputs longer than one block.
    #[test]
    fn hkdf_sha256_matches_rfc_5869() {
        let cases = [
            (
                vec![0x0bu8; 22],
                hex("000102030405060708090a0b0c"),
                hex("f0f1f2f3f4f5f6f7f8f9"),
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                (0x00u8..=0x4f).collect(),
                (0x60u8..=0xaf).collect(),
                (0xb0u8..=0xff).collect(),
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                vec![0x0bu8; 22],
                Vec::new(),
                Vec::new(),
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, okm) in cases {
            let okm = hex(okm);
            let mut output = vec![0u8; okm.len()];
            Hkdf::<Sha256>::new(Some(&salt), &ikm)
                .expand(&info, &mut output)
                .unwrap();
            assert_eq!(output, okm);
        }
    }
}
