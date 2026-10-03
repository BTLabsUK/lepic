//! The vault file format, version 1.
//!
//! ```text
//! magic        8  "LEPICVLT"
//! version      1  1
//! kdf          1  1 = Argon2id v0x13
//! memory_kib   4  u32 big-endian
//! iterations   4  u32 big-endian
//! parallelism  4  u32 big-endian
//! salt        16
//! nonce       24  XChaCha20-Poly1305 nonce, fresh for every write
//! sealed       *  ciphertext of the payload, then the 16-byte tag
//! ```
//!
//! The header is the associated data, so changing any header byte fails decryption. The payload
//! is a u16 big-endian count, then per secret a u8 name length, the name, a u32 big-endian value
//! length and the value, with names in strictly increasing byte order.

use std::collections::BTreeMap;

use chacha20poly1305::Tag;
use chacha20poly1305::aead::AeadInOut;
use zeroize::Zeroizing;

use super::VaultError;
use super::kdf::{KdfParams, SALT_LEN, VaultKey};
use super::store::{MAX_SECRET_NAME_LEN, SecretBytes, SecretName};

pub const MAGIC: [u8; 8] = *b"LEPICVLT";
pub const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID_V13: u8 = 1;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + 3 * 4 + SALT_LEN + NONCE_LEN;

pub const MAX_SECRETS: usize = 64;
pub const MAX_SECRET_LEN: usize = 4096;
const MAX_ENTRY_LEN: usize = 1 + MAX_SECRET_NAME_LEN + 4 + MAX_SECRET_LEN;
pub const MAX_PAYLOAD_LEN: usize = 2 + MAX_SECRETS * MAX_ENTRY_LEN;
pub const MIN_VAULT_LEN: usize = HEADER_LEN + 2 + TAG_LEN;
pub const MAX_VAULT_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN + TAG_LEN;

pub(crate) type Secrets = BTreeMap<SecretName, SecretBytes>;

/// The public part of a vault file: everything needed to derive the key and decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultHeader {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl VaultHeader {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(KDF_ARGON2ID_V13);
        bytes.extend_from_slice(&self.params.memory_kib().to_be_bytes());
        bytes.extend_from_slice(&self.params.iterations().to_be_bytes());
        bytes.extend_from_slice(&self.params.parallelism().to_be_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, VaultError> {
        if reader.array::<8>()? != MAGIC {
            return Err(VaultError::NotAVault);
        }
        let version = reader.u8()?;
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion { version });
        }
        let kdf = reader.u8()?;
        if kdf != KDF_ARGON2ID_V13 {
            return Err(VaultError::UnsupportedKdf { kdf });
        }
        let memory_kib = reader.u32()?;
        let iterations = reader.u32()?;
        let parallelism = reader.u32()?;
        let params = KdfParams::new(memory_kib, iterations, parallelism)?;
        Ok(Self {
            params,
            salt: reader.array()?,
            nonce: reader.array()?,
        })
    }
}

/// A vault file as stored: the header and the sealed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    header: VaultHeader,
    sealed: Vec<u8>,
}

impl VaultFile {
    /// Parses the bytes of a vault file without decrypting it. Does work bounded by
    /// [`MAX_VAULT_LEN`] and never allocates more than the input.
    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_VAULT_LEN {
            return Err(VaultError::TooLong {
                actual: bytes.len(),
                max: MAX_VAULT_LEN,
            });
        }
        if bytes.len() < MIN_VAULT_LEN {
            return Err(VaultError::Truncated {
                actual: bytes.len(),
                min: MIN_VAULT_LEN,
            });
        }
        let mut reader = Reader(bytes);
        let header = VaultHeader::decode(&mut reader)?;
        Ok(Self {
            header,
            sealed: reader.0.to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.header.encode();
        bytes.extend_from_slice(&self.sealed);
        bytes
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub(crate) fn seal(
        header: VaultHeader,
        key: &VaultKey,
        secrets: &Secrets,
    ) -> Result<Self, VaultError> {
        let mut sealed = encode_payload(secrets)?;
        let tag = key
            .cipher()
            .encrypt_inout_detached(
                &header.nonce.into(),
                &header.encode(),
                sealed.as_mut_slice().into(),
            )
            .map_err(|_| VaultError::Encryption)?;
        sealed.extend_from_slice(&tag);
        Ok(Self {
            header,
            sealed: std::mem::take(&mut *sealed),
        })
    }

    pub(crate) fn open(&self, key: &VaultKey) -> Result<Secrets, VaultError> {
        let body_len = self
            .sealed
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(VaultError::Decryption)?;
        let (body, tag) = self.sealed.split_at(body_len);
        let tag = Tag::try_from(tag).map_err(|_| VaultError::Decryption)?;
        let mut payload = Zeroizing::new(body.to_vec());
        key.cipher()
            .decrypt_inout_detached(
                &self.header.nonce.into(),
                &self.header.encode(),
                payload.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| VaultError::Decryption)?;
        decode_payload(&payload)
    }
}

fn encode_payload(secrets: &Secrets) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let count = u16::try_from(secrets.len())
        .ok()
        .filter(|count| usize::from(*count) <= MAX_SECRETS)
        .ok_or(VaultError::TooManySecrets { max: MAX_SECRETS })?;
    let capacity = secrets.values().fold(2usize, |total, value| {
        total
            .saturating_add(1 + MAX_SECRET_NAME_LEN + 4)
            .saturating_add(value.len())
    });
    let mut payload = Zeroizing::new(Vec::with_capacity(capacity.saturating_add(TAG_LEN)));
    payload.extend_from_slice(&count.to_be_bytes());
    for (name, value) in secrets {
        let name_len = u8::try_from(name.as_str().len()).map_err(|_| VaultError::CorruptPayload)?;
        let value_len = u32::try_from(value.len())
            .ok()
            .filter(|len| usize::try_from(*len).is_ok_and(|len| len <= MAX_SECRET_LEN))
            .ok_or(VaultError::SecretTooLarge {
                actual: value.len(),
                max: MAX_SECRET_LEN,
            })?;
        payload.push(name_len);
        payload.extend_from_slice(name.as_str().as_bytes());
        payload.extend_from_slice(&value_len.to_be_bytes());
        payload.extend_from_slice(value.expose_bytes());
    }
    Ok(payload)
}

fn decode_payload(payload: &[u8]) -> Result<Secrets, VaultError> {
    let mut reader = Reader(payload);
    let corrupt = |_| VaultError::CorruptPayload;
    let count = usize::from(reader.u16().map_err(corrupt)?);
    if count > MAX_SECRETS {
        return Err(VaultError::CorruptPayload);
    }
    let mut secrets = Secrets::new();
    for _ in 0..count {
        let name_len = usize::from(reader.u8().map_err(corrupt)?);
        let name = reader.bytes(name_len).map_err(corrupt)?;
        let name = std::str::from_utf8(name)
            .ok()
            .and_then(|name| SecretName::new(name).ok())
            .ok_or(VaultError::CorruptPayload)?;
        let value_len = usize::try_from(reader.u32().map_err(corrupt)?)
            .ok()
            .filter(|len| *len <= MAX_SECRET_LEN)
            .ok_or(VaultError::CorruptPayload)?;
        let value = SecretBytes::from_slice(reader.bytes(value_len).map_err(corrupt)?);
        if secrets
            .last_key_value()
            .is_some_and(|(last, _)| *last >= name)
        {
            return Err(VaultError::CorruptPayload);
        }
        secrets.insert(name, value);
    }
    if !reader.0.is_empty() {
        return Err(VaultError::CorruptPayload);
    }
    Ok(secrets)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(self.truncated())?;
        self.0 = rest;
        Ok(*head)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], VaultError> {
        let (head, rest) = self.0.split_at_checked(len).ok_or(self.truncated())?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, VaultError> {
        self.array::<1>().map(u8::from_be_bytes)
    }

    fn u16(&mut self) -> Result<u16, VaultError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, VaultError> {
        self.array().map(u32::from_be_bytes)
    }

    fn truncated(&self) -> VaultError {
        VaultError::Truncated {
            actual: self.0.len(),
            min: MIN_VAULT_LEN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exposed(secrets: &Secrets) -> Vec<(&str, &[u8])> {
        secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose_bytes()))
            .collect()
    }

    fn secrets(entries: &[(&str, &[u8])]) -> Secrets {
        entries
            .iter()
            .map(|(name, value)| {
                (
                    SecretName::new(name).unwrap(),
                    SecretBytes::from_slice(value),
                )
            })
            .collect()
    }

    #[test]
    fn header_has_the_documented_length() {
        let header = VaultHeader {
            params: KdfParams::new(8, 1, 1).unwrap(),
            salt: [0; SALT_LEN],
            nonce: [0; NONCE_LEN],
        };
        assert_eq!(header.encode().len(), HEADER_LEN);
        assert_eq!(HEADER_LEN, 62);
    }

    #[test]
    fn refuses_a_header_asking_for_more_than_lepic_writes() {
        let header = |memory_kib: u32, iterations: u32| {
            let mut bytes = VaultHeader {
                params: KdfParams::DEFAULT,
                salt: [0; SALT_LEN],
                nonce: [0; NONCE_LEN],
            }
            .encode();
            bytes[10..14].copy_from_slice(&memory_kib.to_be_bytes());
            bytes[14..18].copy_from_slice(&iterations.to_be_bytes());
            bytes.extend_from_slice(&[0; 2 + TAG_LEN]);
            bytes
        };
        for (memory_kib, iterations) in [(1024 * 1024, 1), (64 * 1024, 16), (256 * 1024, 3)] {
            assert!(
                matches!(
                    VaultFile::decode(&header(memory_kib, iterations)),
                    Err(VaultError::KdfParams(_))
                ),
                "m={memory_kib} t={iterations}"
            );
        }
        let default = KdfParams::DEFAULT;
        let file = VaultFile::decode(&header(default.memory_kib(), default.iterations())).unwrap();
        assert_eq!(file.header().params, default);
    }

    #[test]
    fn payload_round_trips() {
        let secrets = secrets(&[
            ("a", b""),
            ("b/seed", &[7; 32]),
            ("z", &[1; MAX_SECRET_LEN]),
        ]);
        let payload = encode_payload(&secrets).unwrap();
        assert_eq!(
            exposed(&decode_payload(&payload).unwrap()),
            exposed(&secrets)
        );
        assert_eq!(
            decode_payload(&encode_payload(&Secrets::new()).unwrap())
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn rejects_payload_with_unsorted_or_duplicate_names() {
        let mut payload = vec![0, 2];
        for name in [b"b", b"a"] {
            payload.extend_from_slice(&[1, name[0], 0, 0, 0, 0]);
        }
        assert!(matches!(
            decode_payload(&payload),
            Err(VaultError::CorruptPayload)
        ));
        payload[8] = b'b';
        assert!(matches!(
            decode_payload(&payload),
            Err(VaultError::CorruptPayload)
        ));
    }

    #[test]
    fn rejects_payload_with_bad_lengths_names_or_trailing_bytes() {
        let cases: [&[u8]; 6] = [
            &[],
            &[0, 1, 1, b'a', 0, 0, 0],
            &[0, 1, 1, b'A', 0, 0, 0, 0],
            &[0, 1, 1, b'a', 0, 0, 0x10, 0x01],
            &[0, 0, 0],
            &[0, 65],
        ];
        for payload in cases {
            assert!(
                matches!(decode_payload(payload), Err(VaultError::CorruptPayload)),
                "{payload:?}"
            );
        }
    }

    #[test]
    fn refuses_to_encode_oversized_secrets() {
        let secrets = secrets(&[("a", &[0; MAX_SECRET_LEN + 1])]);
        assert!(matches!(
            encode_payload(&secrets),
            Err(VaultError::SecretTooLarge {
                actual,
                max: MAX_SECRET_LEN
            }) if actual == MAX_SECRET_LEN + 1
        ));
    }
}
