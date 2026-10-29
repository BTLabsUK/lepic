// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The vault713 Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic-wallet libwallet/src/crypto.rs, libwallet/src/message.rs (Apache-2.0);
// see NOTICE and upstream.toml.

use std::fmt;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag};
use lepic_crypto::{CryptoError, EcdsaSignature, Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::address::{AddressError, EpicboxAddress};
use crate::json::JsonProblem;

pub const SALT_LEN: usize = 8;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// Longer `str` text is rejected before it is parsed. It bounds the ciphertext as well.
pub const MAX_MESSAGE_LEN: usize = 4 * 1024 * 1024;

const PBKDF2_ROUNDS: u32 = 100;

/// Signs SHA-256 of the UTF-8 text, as the relay and `epic-wallet` expect for challenges, `str`
/// and message ids.
pub fn sign_text(text: &str, key: &SecretKey) -> Result<EcdsaSignature, CryptoError> {
    EcdsaSignature::sign(&text_digest(text), key)
}

pub fn verify_text(
    text: &str,
    signature: &EcdsaSignature,
    key: &PublicKey,
) -> Result<(), CryptoError> {
    signature.verify(&text_digest(text), key)
}

fn text_digest(text: &str) -> Message {
    Message::from(<[u8; 32]>::from(Sha256::digest(text.as_bytes())))
}

/// The PBKDF2 salt of one message. Public, and drawn fresh for every message by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

impl From<[u8; SALT_LEN]> for Salt {
    fn from(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }
}

/// The ChaCha20-Poly1305 nonce of one message. Public, and drawn fresh for every message by the
/// caller; reusing one with the same key breaks the cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl From<[u8; NONCE_LEN]> for Nonce {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

/// The symmetric key of one message, shared by sender and receiver. Wiped on drop, never printed.
pub struct MessageKey(Zeroizing<[u8; KEY_LEN]>);

impl MessageKey {
    /// PBKDF2-HMAC-SHA512 over the ECDH X coordinate of `peer * own`.
    pub fn derive(peer: &PublicKey, own: &SecretKey, salt: &Salt) -> Result<Self, CryptoError> {
        let shared = peer.shared_secret(own)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha512>(
            shared.expose_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            key.as_mut_slice(),
        );
        Ok(Self(key))
    }

    /// The raw key. Callers must not log it or copy it into memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Builds the cipher from the key in place, so the only other copy is inside the cipher,
    /// which wipes it on drop.
    fn cipher(&self) -> Option<ChaCha20Poly1305> {
        ChaCha20Poly1305::new_from_slice(self.0.as_slice()).ok()
    }
}

impl fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessageKey([redacted])")
    }
}

/// Decrypted message text, never printed. Not wiped on drop: both parties can read what an
/// Epicbox message carries, and callers copy it into the slates they handle.
pub struct Plaintext(String);

impl Plaintext {
    pub fn expose_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Plaintext([redacted])")
    }
}

/// A part of the `str` JSON that a [`MessageError`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageField {
    EncryptedMessage,
    Salt,
    Nonce,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MessageError {
    #[error("message has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("message is not the expected json")]
    Json(#[source] JsonProblem),
    #[error("message field {field:?} is not hex")]
    InvalidHex { field: MessageField },
    #[error("message field {field:?} has {actual} bytes, expected {expected}")]
    WrongLength {
        field: MessageField,
        expected: usize,
        actual: usize,
    },
    #[error("ciphertext has {actual} bytes, shorter than the {TAG_LEN}-byte tag")]
    CiphertextTooShort { actual: usize },
    #[error("message key could not be derived")]
    Key(#[source] CryptoError),
    #[error("message could not be encrypted")]
    Encryption,
    #[error("message did not decrypt with this key")]
    Decryption,
    #[error("decrypted message is not utf-8")]
    NotUtf8,
    #[error("sender address is invalid")]
    Sender(#[source] AddressError),
    #[error("message signature is invalid")]
    Signature(#[source] CryptoError),
    #[error("message is addressed to another key")]
    NotAddressedToUs,
}

/// The destination as the sender wrote it. Only the key is checked on receipt, as `epic-wallet`
/// does, so the domain and port are carried as received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    public_key: String,
    domain: String,
    port: Option<u16>,
}

impl Destination {
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl From<&EpicboxAddress> for Destination {
    fn from(address: &EpicboxAddress) -> Self {
        Self {
            public_key: address.key_text(),
            domain: address.domain().as_str().to_owned(),
            port: address.port(),
        }
    }
}

/// `EncryptedMessage` from `epic-wallet`: the slate encrypted for one receiver, and its JSON
/// form, which travels as the `str` of `PostSlate` and `Slate` frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    destination: Destination,
    ciphertext: Vec<u8>,
    salt: Salt,
    nonce: Nonce,
}

/// Field order is the wire order; signatures cover these exact bytes.
#[derive(Serialize, Deserialize)]
struct MessageJson<'a> {
    destination: Destination,
    #[serde(borrow)]
    encrypted_message: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    salt: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    nonce: std::borrow::Cow<'a, str>,
}

impl EncryptedMessage {
    /// Encrypts `plaintext` from `sender` to `destination`'s key. The caller draws `salt` and
    /// `nonce` from a secure RNG for every message.
    pub fn seal(
        plaintext: &str,
        destination: &EpicboxAddress,
        sender: &SecretKey,
        salt: Salt,
        nonce: Nonce,
    ) -> Result<Self, MessageError> {
        let key = MessageKey::derive(destination.public_key(), sender, &salt)
            .map_err(MessageError::Key)?;
        let mut ciphertext = plaintext.as_bytes().to_vec();
        let tag = key
            .cipher()
            .ok_or(MessageError::Encryption)?
            .encrypt_inout_detached(&nonce.0.into(), &[], ciphertext.as_mut_slice().into())
            .map_err(|_| MessageError::Encryption)?;
        ciphertext.extend_from_slice(&tag);
        Ok(Self {
            destination: Destination::from(destination),
            ciphertext,
            salt,
            nonce,
        })
    }

    /// Parses the `str` JSON. Unknown keys are ignored, as `epic-wallet` ignores them.
    pub fn from_json(text: &str) -> Result<Self, MessageError> {
        if text.len() > MAX_MESSAGE_LEN {
            return Err(MessageError::TooLong {
                actual: text.len(),
                max: MAX_MESSAGE_LEN,
            });
        }
        let json: MessageJson<'_> =
            serde_json::from_str(text).map_err(|error| MessageError::Json(error.into()))?;
        let ciphertext = hex_decode(&json.encrypted_message, MessageField::EncryptedMessage)?;
        if ciphertext.len() < TAG_LEN {
            return Err(MessageError::CiphertextTooShort {
                actual: ciphertext.len(),
            });
        }
        Ok(Self {
            destination: json.destination,
            ciphertext,
            salt: Salt(hex_decode_array(&json.salt, MessageField::Salt)?),
            nonce: Nonce(hex_decode_array(&json.nonce, MessageField::Nonce)?),
        })
    }

    /// The `str` text, byte for byte as `epic-wallet` writes it.
    pub fn to_json(&self) -> Result<String, MessageError> {
        serde_json::to_string(&MessageJson {
            destination: self.destination.clone(),
            encrypted_message: hex_encode(&self.ciphertext).into(),
            salt: hex_encode(&self.salt.0).into(),
            nonce: hex_encode(&self.nonce.0).into(),
        })
        .map_err(|error| MessageError::Json(error.into()))
    }

    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    pub fn is_addressed_to(&self, own: &EpicboxAddress) -> bool {
        self.destination.public_key == own.key_text()
    }

    /// Ciphertext followed by the 16-byte tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// The message key from the other party's public key and our secret key. Sender and receiver
    /// derive the same key.
    pub fn key(&self, peer: &PublicKey, own: &SecretKey) -> Result<MessageKey, MessageError> {
        MessageKey::derive(peer, own, &self.salt).map_err(MessageError::Key)
    }

    pub fn decrypt_with_key(&self, key: &MessageKey) -> Result<Plaintext, MessageError> {
        let body_len =
            self.ciphertext
                .len()
                .checked_sub(TAG_LEN)
                .ok_or(MessageError::CiphertextTooShort {
                    actual: self.ciphertext.len(),
                })?;
        let (body, tag) = self.ciphertext.split_at(body_len);
        let tag = Tag::try_from(tag).map_err(|_| MessageError::Decryption)?;
        let mut buffer = body.to_vec();
        key.cipher()
            .ok_or(MessageError::Decryption)?
            .decrypt_inout_detached(
                &self.nonce.0.into(),
                &[],
                buffer.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| MessageError::Decryption)?;
        String::from_utf8(buffer)
            .map(Plaintext)
            .map_err(|_| MessageError::NotUtf8)
    }

    pub fn open(&self, sender: &PublicKey, own: &SecretKey) -> Result<Plaintext, MessageError> {
        self.decrypt_with_key(&self.key(sender, own)?)
    }
}

/// A message ready for `PostSlate`: the `str` text and the sender's signature over exactly it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    pub str: String,
    pub signature: EcdsaSignature,
}

impl SignedMessage {
    pub fn seal(
        plaintext: &str,
        destination: &EpicboxAddress,
        sender: &SecretKey,
        salt: Salt,
        nonce: Nonce,
    ) -> Result<Self, MessageError> {
        let str = EncryptedMessage::seal(plaintext, destination, sender, salt, nonce)?.to_json()?;
        let signature = sign_text(&str, sender).map_err(MessageError::Signature)?;
        Ok(Self { str, signature })
    }
}

/// A message from a `Slate` frame that was signed by its sender, addressed to us, and decrypted.
#[derive(Debug)]
pub struct ReceivedMessage {
    pub sender: EpicboxAddress,
    pub plaintext: Plaintext,
}

impl ReceivedMessage {
    /// Checks and opens the `from`, `str` and `signature` of a `Slate` frame. The signature is
    /// verified over `str` as received, before anything in it is parsed.
    pub fn open(
        from: &str,
        str: &str,
        signature_hex: &str,
        own: &EpicboxAddress,
        own_secret: &SecretKey,
    ) -> Result<Self, MessageError> {
        let sender = EpicboxAddress::parse(from, own.network()).map_err(MessageError::Sender)?;
        let signature =
            EcdsaSignature::from_der_hex(signature_hex).map_err(MessageError::Signature)?;
        verify_text(str, &signature, sender.public_key()).map_err(MessageError::Signature)?;
        let message = EncryptedMessage::from_json(str)?;
        if !message.is_addressed_to(own) {
            return Err(MessageError::NotAddressedToUs);
        }
        let plaintext = message.open(sender.public_key(), own_secret)?;
        Ok(Self { sender, plaintext })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            text.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    text
}

fn hex_decode(text: &str, field: MessageField) -> Result<Vec<u8>, MessageError> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(MessageError::InvalidHex { field });
    }
    pairs
        .iter()
        .map(|[high, low]| Ok(nibble(*high, field)?.wrapping_shl(4) | nibble(*low, field)?))
        .collect()
}

fn hex_decode_array<const N: usize>(
    text: &str,
    field: MessageField,
) -> Result<[u8; N], MessageError> {
    let bytes = hex_decode(text, field)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| MessageError::WrongLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

fn nibble(digit: u8, field: MessageField) -> Result<u8, MessageError> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(MessageError::InvalidHex { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn address_of(key: &SecretKey) -> EpicboxAddress {
        EpicboxAddress::new(
            PublicKey::from_secret_key(key).unwrap(),
            Network::Mainnet,
            crate::address::Domain::parse("relay.example.org").unwrap(),
            None,
        )
    }

    fn sealed(plaintext: &str) -> EncryptedMessage {
        EncryptedMessage::seal(
            plaintext,
            &address_of(&secret(2)),
            &secret(1),
            Salt::from([7; SALT_LEN]),
            Nonce::from([9; NONCE_LEN]),
        )
        .unwrap()
    }

    #[test]
    fn hex_round_trips_every_byte() {
        let bytes: Vec<u8> = (0..=255).collect();
        let text = hex_encode(&bytes);
        assert_eq!(hex_decode(&text, MessageField::Salt).unwrap(), bytes);
        assert_eq!(
            hex_decode(&text.to_uppercase(), MessageField::Salt).unwrap(),
            bytes
        );
    }

    #[test]
    fn rejects_odd_and_non_hex_digits() {
        for text in ["abc", "zz", "0x00", " 00"] {
            assert!(matches!(
                hex_decode(text, MessageField::Nonce),
                Err(MessageError::InvalidHex {
                    field: MessageField::Nonce
                })
            ));
        }
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let mut message = sealed("slate");
        message.ciphertext[0] ^= 1;
        assert!(matches!(
            message.open(&PublicKey::from_secret_key(&secret(1)).unwrap(), &secret(2)),
            Err(MessageError::Decryption)
        ));
    }

    #[test]
    fn rejects_wrong_receiver_key() {
        let message = sealed("slate");
        assert!(matches!(
            message.open(&PublicKey::from_secret_key(&secret(1)).unwrap(), &secret(3)),
            Err(MessageError::Decryption)
        ));
    }

    #[test]
    fn rejects_plaintext_that_is_not_utf8() {
        let destination = address_of(&secret(2));
        let key = MessageKey::derive(destination.public_key(), &secret(1), &Salt([7; 8])).unwrap();
        let mut ciphertext = vec![0xff, 0xfe];
        let tag = key
            .cipher()
            .unwrap()
            .encrypt_inout_detached(&[9u8; 12].into(), &[], ciphertext.as_mut_slice().into())
            .unwrap();
        ciphertext.extend_from_slice(&tag);
        let message = EncryptedMessage {
            destination: Destination::from(&destination),
            ciphertext,
            salt: Salt([7; 8]),
            nonce: Nonce([9; 12]),
        };
        assert!(matches!(
            message.open(&PublicKey::from_secret_key(&secret(1)).unwrap(), &secret(2)),
            Err(MessageError::NotUtf8)
        ));
    }

    #[test]
    fn redacts_key_and_plaintext_in_debug() {
        let message = sealed("secret slate");
        let sender = PublicKey::from_secret_key(&secret(1)).unwrap();
        let key = message.key(&sender, &secret(2)).unwrap();
        let plaintext = message.decrypt_with_key(&key).unwrap();
        assert_eq!(format!("{key:?}"), "MessageKey([redacted])");
        assert_eq!(format!("{plaintext:?}"), "Plaintext([redacted])");
    }
}
