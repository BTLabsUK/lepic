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
    #[error("armor framing is not BEGINEPICSEALED. payload. ENDEPICSEALED.")]
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
}

/// Why key bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyError {
    #[error("x25519 public key is of small order")]
    SmallOrder,
    #[error("ed25519 public key is not a valid point or is weak")]
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

/// Why the SAS table could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SasTableError {
    #[error("sas table has no line {index}")]
    MissingLine { index: u8 },
    #[error("sas table line {index} is not emoji, tab, name")]
    BadLine { index: u8 },
}

/// Why pairing words could not be read or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WordsError {
    #[error("the words are not five entries of the table")]
    Unknown,
    #[error("no invite opens with these words")]
    CannotOpen,
    #[error("stretching the words failed")]
    Derivation,
    #[error("sealing the invite failed")]
    Encryption,
}
