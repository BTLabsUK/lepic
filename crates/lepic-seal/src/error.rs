// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// Why received bytes or text were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("the text was damaged on the way")]
    Damaged,
    #[error("made by a newer wallet: version {found}")]
    NewerVersion { found: u8 },
    #[error("made for the other network")]
    WrongNetwork,
    #[error("{found} bytes is over the limit of {limit}")]
    Oversized { limit: usize, found: usize },
    #[error("unsupported envelope suite {suite}")]
    UnsupportedSuite { suite: u8 },
    #[error("malformed input: {0}")]
    Malformed(#[from] Malformed),
    #[error("the signature does not verify")]
    BadSignature,
    #[error("the envelope cannot be opened with this key")]
    CannotOpen,
    #[error("signed by another key than the contact's")]
    KeyChanged,
    #[error("a sig key is not a canonical point or is of small order")]
    WeakSigKey,
    #[error("the key check answer does not prove the old key")]
    KeyCheckNotProven,
}

/// What exactly was wrong with malformed input, for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Malformed {
    #[error("input ends early")]
    Truncated,
    #[error("bytes after the end")]
    TrailingBytes,
    #[error("wrong magic bytes")]
    Magic,
    #[error("unknown network byte {byte}")]
    Network { byte: u8 },
    #[error("unknown format version {found}")]
    Version { found: u8 },
    #[error("unknown envelope flags {flags}")]
    Flags { flags: u8 },
    #[error("armor framing is not BEGIN marker. payload. matching END marker.")]
    Framing,
    #[error("link does not start with the expected epiccash prefix")]
    LinkPrefix,
    #[error("payload is not unpadded base64url")]
    PayloadText,
    #[error("field {tag} is out of order or repeated")]
    FieldOrder { tag: u8 },
    #[error("unknown field {tag}")]
    UnknownField { tag: u8 },
    #[error("field after the signature")]
    FieldAfterSignature,
    #[error("required field {tag} is missing")]
    MissingField { tag: u8 },
    #[error("field {tag} has the wrong length")]
    FieldLength { tag: u8 },
    #[error("field {tag} has an invalid value")]
    FieldValue { tag: u8 },
    #[error("pairing body has an invalid value")]
    Body,
    #[error("message type {kind} must be signed")]
    Unsigned { kind: u8 },
    #[error("message type {kind} must be anonymous")]
    Signed { kind: u8 },
}

/// Why something could not be built or sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("field {tag} is longer than a field can hold")]
    FieldTooLong { tag: u8 },
    /// A body over 65,535 bytes, the most a field holds: the binding size of a sealed slate.
    #[error("body of {found} bytes is over the limit of {limit}")]
    BodyTooLarge { limit: usize, found: usize },
    /// A reply mailbox goes only beside a reply key, in an anonymous envelope.
    #[error("a reply mailbox needs a reply key and an anonymous envelope")]
    ReplyMailbox,
    #[error("encoded size {found} is over the limit of {limit}")]
    Oversized { limit: usize, found: usize },
    #[error("the card is for the other network")]
    WrongNetwork,
    #[error("the signing key does not match the card's sig key")]
    SigningKeyMismatch,
    #[error("hpke encapsulation failed")]
    Encapsulation,
    #[error("hpke encryption failed")]
    Encryption,
    /// A private pairing's message for an invite of another class, or the other way round.
    #[error("the invite is of another pairing class")]
    WrongClass,
}

/// Why key bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyError {
    #[error("x25519 public key is of small order")]
    SmallOrder,
    #[error("ed25519 public key is not a canonical point or is of small order")]
    InvalidVerifyingKey,
}

/// Why text was refused as a name, reference or address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TextError {
    #[error("text length {found} is outside 1 to {max} bytes")]
    Length { found: usize, max: usize },
    #[error("character {position} is a control or hidden formatting character")]
    HiddenCharacter { position: usize },
    #[error("character {position} is not allowed in an address")]
    AddressCharacter { position: usize },
    #[error("address has no single key@domain form")]
    AddressShape,
}
