//! Private transaction contexts (blinding factors and nonces) and their encryption at rest.
//!
//! A context is sealed with XChaCha20-Poly1305 under a key the engine derives from the wallet's
//! root key. The slate id and participant are authenticated as associated data, so a sealed
//! context copied to another row does not open.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Record, StoreError};

pub const CONTEXT_KEY_LEN: usize = 32;

const SEALED_FORMAT_V1: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const ASSOCIATED_DATA_DOMAIN: &[u8] = b"lepic-store private context v1";
const ASSOCIATED_DATA_LEN: usize = ASSOCIATED_DATA_DOMAIN.len() + 16 + 1;
const SEALED_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// The key private contexts are sealed under.
pub struct ContextKey(Zeroizing<[u8; CONTEXT_KEY_LEN]>);

impl ContextKey {
    pub fn from_bytes(bytes: [u8; CONTEXT_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for ContextKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContextKey([redacted])")
    }
}

/// A participant's private data for one slate, in the engine's own encoding.
pub struct PrivateContext(Zeroizing<Vec<u8>>);

impl PrivateContext {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PrivateContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateContext([redacted])")
    }
}

/// The slate participant id the context belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId(pub u8);

pub trait ContextRepository {
    /// Seals and stores the context, replacing one stored for the same slate and participant.
    fn put_context(
        &mut self,
        slate_id: Uuid,
        participant: ParticipantId,
        context: &PrivateContext,
    ) -> Result<(), StoreError>;

    /// Opens the stored context. Fails with [`StoreError::ContextUndecryptable`] when the store
    /// was opened with a different key or the sealed bytes were altered.
    fn context(
        &self,
        slate_id: Uuid,
        participant: ParticipantId,
    ) -> Result<Option<PrivateContext>, StoreError>;

    /// Removes the context if it is stored.
    fn delete_context(
        &mut self,
        slate_id: Uuid,
        participant: ParticipantId,
    ) -> Result<(), StoreError>;
}

fn associated_data(slate_id: Uuid, participant: ParticipantId) -> Vec<u8> {
    let mut data = Vec::with_capacity(ASSOCIATED_DATA_LEN);
    data.extend_from_slice(ASSOCIATED_DATA_DOMAIN);
    data.extend_from_slice(slate_id.as_bytes());
    data.push(participant.0);
    data
}

/// Why sealing or opening failed, for the caller to turn into the error of its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealFailure {
    Randomness(getrandom::Error),
    Unsealable,
    Malformed,
    Undecryptable,
}

fn cipher(key: &ContextKey) -> Result<XChaCha20Poly1305, SealFailure> {
    XChaCha20Poly1305::new_from_slice(key.0.as_slice()).map_err(|_| SealFailure::Unsealable)
}

/// Sealed layout: format byte, nonce, ciphertext with tag.
pub(crate) fn seal_bytes(
    key: &ContextKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealFailure> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(SealFailure::Randomness)?;
    let ciphertext = cipher(key)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealFailure::Unsealable)?;
    let mut sealed = Vec::with_capacity(SEALED_OVERHEAD.saturating_add(plaintext.len()));
    sealed.push(SEALED_FORMAT_V1);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

pub(crate) fn open_bytes(
    key: &ContextKey,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, SealFailure> {
    let Some((&SEALED_FORMAT_V1, rest)) = sealed.split_first() else {
        return Err(SealFailure::Malformed);
    };
    let Some((nonce, ciphertext)) = rest.split_first_chunk::<NONCE_LEN>() else {
        return Err(SealFailure::Malformed);
    };
    if ciphertext.len() < TAG_LEN {
        return Err(SealFailure::Malformed);
    }
    cipher(key)?
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SealFailure::Undecryptable)
}

pub(crate) fn seal(
    key: &ContextKey,
    slate_id: Uuid,
    participant: ParticipantId,
    context: &PrivateContext,
) -> Result<Vec<u8>, StoreError> {
    seal_bytes(
        key,
        &associated_data(slate_id, participant),
        context.expose(),
    )
    .map_err(|failure| match failure {
        SealFailure::Randomness(error) => StoreError::Randomness(error),
        _ => StoreError::ContextUnsealable,
    })
}

pub(crate) fn open(
    key: &ContextKey,
    slate_id: Uuid,
    participant: ParticipantId,
    sealed: &[u8],
) -> Result<PrivateContext, StoreError> {
    open_bytes(key, &associated_data(slate_id, participant), sealed)
        .map(PrivateContext::new)
        .map_err(|failure| match failure {
            SealFailure::Malformed => StoreError::Corrupt {
                record: Record::Context,
                field: "sealed bytes",
            },
            SealFailure::Undecryptable => StoreError::ContextUndecryptable,
            SealFailure::Randomness(error) => StoreError::Randomness(error),
            SealFailure::Unsealable => StoreError::ContextUnsealable,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLATE: Uuid = Uuid::from_bytes([7; 16]);

    fn key(byte: u8) -> ContextKey {
        ContextKey::from_bytes([byte; CONTEXT_KEY_LEN])
    }

    #[test]
    fn sealed_context_opens_with_the_same_key_and_row() {
        let sealed = seal(
            &key(1),
            SLATE,
            ParticipantId(0),
            &PrivateContext::new(b"secret".to_vec()),
        )
        .unwrap();
        let opened = open(&key(1), SLATE, ParticipantId(0), &sealed).unwrap();
        assert_eq!(opened.expose(), b"secret");
    }

    #[test]
    fn sealed_context_does_not_contain_the_plaintext() {
        let plaintext = b"blinding factor and nonce".to_vec();
        let sealed = seal(
            &key(1),
            SLATE,
            ParticipantId(0),
            &PrivateContext::new(plaintext.clone()),
        )
        .unwrap();
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }

    #[test]
    fn rejects_opening_under_another_key_slate_or_participant() {
        let sealed = seal(
            &key(1),
            SLATE,
            ParticipantId(0),
            &PrivateContext::new(b"secret".to_vec()),
        )
        .unwrap();
        for (k, slate, participant) in [
            (key(2), SLATE, ParticipantId(0)),
            (key(1), Uuid::from_bytes([8; 16]), ParticipantId(0)),
            (key(1), SLATE, ParticipantId(1)),
        ] {
            assert!(matches!(
                open(&k, slate, participant, &sealed),
                Err(StoreError::ContextUndecryptable)
            ));
        }
    }

    #[test]
    fn rejects_truncated_or_unknown_sealed_format() {
        let sealed = seal(
            &key(1),
            SLATE,
            ParticipantId(0),
            &PrivateContext::new(Vec::new()),
        )
        .unwrap();
        let mut unknown_format = sealed.clone();
        unknown_format[0] = 2;
        for bytes in [
            &[][..],
            &sealed[..NONCE_LEN],
            &sealed[..sealed.len() - 1],
            &unknown_format,
        ] {
            assert!(matches!(
                open(&key(1), SLATE, ParticipantId(0), bytes),
                Err(StoreError::Corrupt {
                    record: Record::Context,
                    ..
                } | StoreError::ContextUndecryptable)
            ));
        }
    }

    #[test]
    fn debug_output_redacts_key_and_context() {
        assert_eq!(format!("{:?}", key(9)), "ContextKey([redacted])");
        assert_eq!(
            format!("{:?}", PrivateContext::new(b"x".to_vec())),
            "PrivateContext([redacted])"
        );
    }
}
