// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The vault713 Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic-wallet libwallet/src/crypto.rs, libwallet/src/message.rs (Apache-2.0);
// see NOTICE and upstream.toml.

//! Epicbox message crypto: ECDH and PBKDF2 for the key, ChaCha20-Poly1305 for the slate, and
//! ECDSA over SHA-256 for the sender's signature.

use std::fmt;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag};
use lepic_crypto::{CryptoError, EcdsaSignature, Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::address::{AddressError, EpicboxAddress};
use crate::json::JsonProblem;

/// Bytes in a message's PBKDF2 salt.
pub const SALT_LEN: usize = 8;
/// Bytes in a message's ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;
/// Bytes in the Poly1305 tag at the end of a ciphertext.
pub const TAG_LEN: usize = 16;
/// Bytes in a message key.
pub const KEY_LEN: usize = 32;
/// Longer `str` text is rejected before it is parsed. It bounds the ciphertext as well.
pub const MAX_MESSAGE_LEN: usize = 4 * 1024 * 1024;

const PBKDF2_ROUNDS: u32 = 100;

/// Signs SHA-256 of the UTF-8 text, as the relay and `epic-wallet` expect for challenges, `str`
/// and message ids.
pub fn sign_text(text: &str, key: &SecretKey) -> Result<EcdsaSignature, CryptoError> {
    EcdsaSignature::sign(&text_digest(text), key)
}

/// Checks a [`sign_text`] signature over `text` against `key`.
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
    /// The salt's bytes.
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
    /// The nonce's bytes.
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
    /// The text. Callers must not log it.
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
    /// The hex ciphertext.
    EncryptedMessage,
    /// The hex salt.
    Salt,
    /// The hex nonce.
    Nonce,
}

/// Why a message could not be sealed, parsed or opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MessageError {
    /// The `str` text is longer than [`MAX_MESSAGE_LEN`].
    #[error("message has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    /// The `str` text is not the message JSON.
    #[error("message is not the expected json")]
    Json(#[source] JsonProblem),
    /// A field is not hex.
    #[error("message field {field:?} is not hex")]
    InvalidHex { field: MessageField },
    /// A field decoded to the wrong number of bytes.
    #[error("message field {field:?} has {actual} bytes, expected {expected}")]
    WrongLength {
        field: MessageField,
        expected: usize,
        actual: usize,
    },
    /// The ciphertext is too short to hold the tag.
    #[error("ciphertext has {actual} bytes, shorter than the {TAG_LEN}-byte tag")]
    CiphertextTooShort { actual: usize },
    /// The message key could not be derived from the two keys.
    #[error("message key could not be derived")]
    Key(#[source] CryptoError),
    /// The cipher refused to encrypt.
    #[error("message could not be encrypted")]
    Encryption,
    /// The tag did not match: wrong key or altered ciphertext.
    #[error("message did not decrypt with this key")]
    Decryption,
    /// The decrypted bytes are not UTF-8.
    #[error("decrypted message is not utf-8")]
    NotUtf8,
    /// The sender's address does not parse.
    #[error("sender address is invalid")]
    Sender(#[source] AddressError),
    /// The sender's signature is malformed or does not verify.
    #[error("message signature is invalid")]
    Signature(#[source] CryptoError),
    /// The message names another key as its destination.
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
    /// The destination key as base58check text.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// The destination relay's domain as the sender wrote it.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The destination port as the sender wrote it.
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
            encrypted_message: lepic_crypto::hex::encode(&self.ciphertext).into(),
            salt: lepic_crypto::hex::encode(&self.salt.0).into(),
            nonce: lepic_crypto::hex::encode(&self.nonce.0).into(),
        })
        .map_err(|error| MessageError::Json(error.into()))
    }

    /// Where the sender addressed the message.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Whether the destination key is `own`'s key. Domain and port are not compared.
    pub fn is_addressed_to(&self, own: &EpicboxAddress) -> bool {
        self.destination.public_key == own.key_text()
    }

    /// Ciphertext followed by the 16-byte tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The message's salt.
    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    /// The message's nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// The message key from the other party's public key and our secret key. Sender and receiver
    /// derive the same key.
    pub fn key(&self, peer: &PublicKey, own: &SecretKey) -> Result<MessageKey, MessageError> {
        MessageKey::derive(peer, own, &self.salt).map_err(MessageError::Key)
    }

    /// Decrypts with a key already derived and checks the tag.
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

    /// Derives the key from `sender` and `own`, then decrypts.
    pub fn open(&self, sender: &PublicKey, own: &SecretKey) -> Result<Plaintext, MessageError> {
        self.decrypt_with_key(&self.key(sender, own)?)
    }
}

/// A message ready for `PostSlate`: the `str` text and the sender's signature over exactly it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    /// The message JSON, sent as the frame's `str`.
    pub str: String,
    /// The sender's signature over `str`.
    pub signature: EcdsaSignature,
}

impl SignedMessage {
    /// Encrypts `plaintext` to `destination` and signs the result. The caller draws `salt` and
    /// `nonce` from a secure RNG for every message.
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
    /// The address that signed the message.
    pub sender: EpicboxAddress,
    /// The decrypted text.
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

fn hex_decode(text: &str, field: MessageField) -> Result<Vec<u8>, MessageError> {
    lepic_crypto::hex::decode_bounded(text, 0, usize::MAX)
        .map_err(|_| MessageError::InvalidHex { field })
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
        let text = lepic_crypto::hex::encode(&bytes);
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
