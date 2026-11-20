// SPDX-License-Identifier: Apache-2.0
//! `ur:epic-slate`: slate text as a sequence of QR codes, for two phones side by side
//! (ADR 0025, `docs/compat/ur-epic-slate.md`).
//!
//! The slate JSON is deflated and wrapped in a small CBOR map, then split into BC-UR multipart
//! parts with fountain codes, so a receiver that misses frames of the looping animation still
//! recovers the message. Decoding is stateless: the caller passes every distinct part it has
//! scanned so far and gets the progress, and the slate text once enough parts arrived. Neither
//! direction parses the slate; the text goes on to the codecs like slate text from a file.
//!
//! Payload version 2 (RFC 0003 §5.18) carries a native `lepic.v1` slate or an envelope as bytes,
//! nothing compressed: [`encode_ur_binary`] writes it and [`decode_ur_parts`] reads either
//! version. [`encode_ur_slate`] and [`decode_ur_slate`] handle version 1 only.
//!
//! Whether a payload is one code or an animated sequence is the caller's display policy: the
//! `_split` encoders take the longest payload that stays one code, and the others apply the
//! defaults below. The reader takes one part or many either way.

use minicbor::data::Type;
use thiserror::Error;
use ur::bytewords::{self, Style};
use ur::fountain;

/// The UR type of an Epic slate.
pub const UR_TYPE: &str = "epic-slate";
/// The payload version [`encode_ur_slate`] writes and [`decode_ur_slate`] reads: deflated JSON.
pub const PAYLOAD_VERSION: u64 = 1;
/// The payload version of [`encode_ur_binary`]: native slate or envelope bytes.
pub const BINARY_PAYLOAD_VERSION: u64 = 2;
/// Magic of a native `lepic.v1` slate; the bytes of a version 2 payload start with it or with
/// [`ENVELOPE_MAGIC`].
pub const NATIVE_SLATE_MAGIC: [u8; 4] = [0x89, 0x45, 0x53, 0x4c];
/// Magic of an envelope.
pub const ENVELOPE_MAGIC: [u8; 4] = [0x89, 0x45, 0x53, 0x45];
/// Longest version 2 byte string written or read: the largest slate envelope (RFC 0003 §5.17).
/// A code of this size needs fragments longer than 200 bytes, because a code holds at most
/// [`MAX_SEQUENCE_LEN`] fragments (51,200 bytes at 200).
pub const MAX_BINARY_LEN: usize = 67_648;
/// A version 2 payload of at most this many bytes is one single-part code, unless the caller
/// passes its own limit to [`encode_ur_binary_split`].
pub const SINGLE_CODE_MAX_LEN: usize = 360;
/// Recommended fragment length of a version 2 multipart code.
pub const BINARY_FRAGMENT_LEN: usize = 200;

/// Longest slate text that is encoded, and the most a payload may inflate to. A QR sequence for
/// a slate this long would already be far longer than a person waits for.
pub const MAX_SLATE_TEXT_LEN: usize = 64 * 1024;
/// Shortest fragment the encoder accepts.
pub const MIN_FRAGMENT_LEN: usize = 16;
/// Longest fragment the encoder writes and the decoder accepts.
pub const MAX_FRAGMENT_LEN: usize = 1024;
/// Most fragments a message may be split into.
pub const MAX_SEQUENCE_LEN: usize = 256;
/// Longest part text the decoder reads: a [`MAX_FRAGMENT_LEN`] fragment with its part header,
/// CBOR framing and checksum in minimal bytewords, rounded up.
pub const MAX_PART_TEXT_LEN: usize = 2400;
/// Most parts one decode call reads.
pub const MAX_PARTS: usize = 1024;
/// Most part text one decode call reads, over all parts.
pub const MAX_TOTAL_TEXT_LEN: usize = 1024 * 1024;
/// Fountain parts the encoder adds after the pure ones, at least.
pub const MIN_FOUNTAIN_PARTS: usize = 10;

const JSON_PAYLOAD_VERSION_BYTE: u8 = 1;
const BINARY_PAYLOAD_VERSION_BYTE: u8 = 2;
const PAYLOAD_KEY_VERSION: u64 = 1;
const PAYLOAD_KEY_DEFLATE: u64 = 2;
const DEFLATE_LEVEL: u8 = 10;
/// Long enough for every registered UR type name; longer names are not UR syntax here.
const MAX_TYPE_LEN: usize = 64;
/// Digits of the largest sequence number a fountain part carries (`u32::MAX`).
const MAX_INDEX_DIGITS: usize = 10;

/// Why slate text could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UrEncodeError {
    #[error("slate text is empty")]
    Empty,
    #[error("slate text of {len} bytes exceeds {max} bytes")]
    TextTooLong { len: usize, max: usize },
    #[error("slate text is not json")]
    NotJson,
    #[error("fragment length {len} is outside {min} to {max}")]
    FragmentLength { len: usize, min: usize, max: usize },
    #[error("single-code limit {len} exceeds {max}")]
    SingleCodeLength { len: usize, max: usize },
    #[error("the slate needs {count} fragments, more than {max}")]
    TooManyFragments { count: usize, max: usize },
    #[error("multipart framing failed")]
    Framing,
}

/// Why scanned parts could not be decoded. The first failing part decides; the variants say
/// whether the caller should drop that part, start over, or give up on the code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UrDecodeError {
    #[error("{count} parts exceed {max} per call")]
    TooManyParts { count: usize, max: usize },
    #[error("parts of {len} characters in total exceed {max}")]
    TooMuchText { len: usize, max: usize },
    #[error("part of {len} characters exceeds {max}")]
    PartTooLong { len: usize, max: usize },
    #[error("text is not a uniform resource")]
    NotUr,
    #[error("uniform resource of type {ur_type} is not an epic slate")]
    OtherType { ur_type: String },
    #[error("parts belong to different codes")]
    MixedCodes,
    #[error("sequence of {len} fragments exceeds {max}")]
    SequenceTooLong { len: usize, max: usize },
    #[error("part is malformed: {0}")]
    InvalidPart(PartFault),
    #[error("payload is malformed: {0}")]
    MalformedPayload(PayloadFault),
    #[error("payload version {version} is not supported")]
    UnsupportedVersion { version: u64 },
    #[error("compressed slate is not valid deflate data")]
    InvalidDeflate,
    #[error("slate text inflates past {max} bytes")]
    InflatesTooLarge { max: usize },
    #[error("slate text is not utf-8")]
    NotUtf8,
    #[error("slate text is not json")]
    NotJson,
}

/// What is wrong inside one part of an `epic-slate` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PartFault {
    #[error("sequence index is not `<n>-<count>` with 1 <= n")]
    Index,
    #[error("body is not minimal bytewords with a valid checksum")]
    Bytewords,
    #[error("fountain part is not valid cbor")]
    Cbor,
    #[error("fountain part disagrees with its sequence index")]
    IndexMismatch,
    #[error("fragment of {len} bytes is empty or exceeds the limit")]
    FragmentLength { len: usize },
    #[error("message length does not fit the fragments")]
    MessageLength,
    #[error("fragments do not reassemble to the checksummed message")]
    Reassembly,
}

/// What is wrong in the CBOR payload of a complete code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PayloadFault {
    #[error("not a definite cbor map")]
    NotAMap,
    #[error("key {key} is missing")]
    MissingKey { key: u64 },
    #[error("unexpected key")]
    UnexpectedKey,
    #[error("a value has the wrong type")]
    WrongType,
    #[error("bytes follow the map")]
    TrailingBytes,
}

/// How far a set of scanned parts got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrProgress {
    /// Fragments recovered so far, directly or from fountain parts.
    pub resolved_fragments: usize,
    /// Fragments of the message; 0 when no part was given.
    pub fragment_count: usize,
    /// The slate text, once every fragment is recovered.
    pub json: Option<String>,
}

impl UrProgress {
    pub fn is_complete(&self) -> bool {
        self.json.is_some()
    }
}

/// The QR texts of `slate_json`, uppercase for the QR alphanumeric mode. A payload that fits
/// one fragment of `max_fragment_len` bytes is one single-part code. Otherwise the list holds
/// every pure fragment in order, then fountain parts, as many as [`fountain_part_count`] says;
/// showing the list in a loop lets a receiver recover from missed frames.
pub fn encode_ur_slate(
    slate_json: impl AsRef<str>,
    max_fragment_len: usize,
) -> Result<Vec<String>, UrEncodeError> {
    encode_ur_slate_split(slate_json, max_fragment_len, max_fragment_len)
}

/// [`encode_ur_slate`] with the caller's single-code limit: a payload of at most
/// `single_code_max_len` bytes, 0 to [`MAX_FRAGMENT_LEN`], is one single-part code; a longer one
/// is split into fragments of at most `max_fragment_len` bytes. 0 always splits.
pub fn encode_ur_slate_split(
    slate_json: impl AsRef<str>,
    single_code_max_len: usize,
    max_fragment_len: usize,
) -> Result<Vec<String>, UrEncodeError> {
    let slate_json = slate_json.as_ref();
    if !(MIN_FRAGMENT_LEN..=MAX_FRAGMENT_LEN).contains(&max_fragment_len) {
        return Err(UrEncodeError::FragmentLength {
            len: max_fragment_len,
            min: MIN_FRAGMENT_LEN,
            max: MAX_FRAGMENT_LEN,
        });
    }
    if single_code_max_len > MAX_FRAGMENT_LEN {
        return Err(UrEncodeError::SingleCodeLength {
            len: single_code_max_len,
            max: MAX_FRAGMENT_LEN,
        });
    }
    check_slate_text(slate_json).map_err(|error| match error {
        SlateTextError::Empty => UrEncodeError::Empty,
        SlateTextError::NotJson => UrEncodeError::NotJson,
        SlateTextError::TooLong(len) => UrEncodeError::TextTooLong {
            len,
            max: MAX_SLATE_TEXT_LEN,
        },
    })?;
    let payload = encode_payload(slate_json.as_bytes());
    encode_parts(&payload, single_code_max_len, max_fragment_len).map_err(|error| match error {
        FramingError::TooManyFragments(count) => UrEncodeError::TooManyFragments {
            count,
            max: MAX_SEQUENCE_LEN,
        },
        FramingError::Framing => UrEncodeError::Framing,
    })
}

/// The QR texts of a version 2 payload: `bytes` is a native slate or an envelope, told by its
/// magic. A payload of at most [`SINGLE_CODE_MAX_LEN`] bytes is one single-part code; a longer
/// one is split into fragments of at most `max_fragment_len` bytes
/// ([`BINARY_FRAGMENT_LEN`] recommended), written as [`encode_ur_slate`] writes them.
pub fn encode_ur_binary(
    bytes: &[u8],
    max_fragment_len: usize,
) -> Result<Vec<String>, UrBinaryEncodeError> {
    encode_ur_binary_split(bytes, SINGLE_CODE_MAX_LEN, max_fragment_len)
}

/// [`encode_ur_binary`] with the caller's single-code limit in place of
/// [`SINGLE_CODE_MAX_LEN`]: a payload of at most `single_code_max_len` bytes, 0 to
/// [`MAX_FRAGMENT_LEN`], is one single-part code; a longer one is split into fragments of at
/// most `max_fragment_len` bytes. 0 always splits.
pub fn encode_ur_binary_split(
    bytes: &[u8],
    single_code_max_len: usize,
    max_fragment_len: usize,
) -> Result<Vec<String>, UrBinaryEncodeError> {
    if !(MIN_FRAGMENT_LEN..=MAX_FRAGMENT_LEN).contains(&max_fragment_len) {
        return Err(UrBinaryEncodeError::FragmentLength {
            len: max_fragment_len,
            min: MIN_FRAGMENT_LEN,
            max: MAX_FRAGMENT_LEN,
        });
    }
    if single_code_max_len > MAX_FRAGMENT_LEN {
        return Err(UrBinaryEncodeError::SingleCodeLength {
            len: single_code_max_len,
            max: MAX_FRAGMENT_LEN,
        });
    }
    if bytes.len() > MAX_BINARY_LEN {
        return Err(UrBinaryEncodeError::TooLong {
            len: bytes.len(),
            max: MAX_BINARY_LEN,
        });
    }
    classify_binary(bytes).ok_or(UrBinaryEncodeError::UnknownMagic)?;
    let payload = frame_payload(BINARY_PAYLOAD_VERSION_BYTE, bytes);
    encode_parts(&payload, single_code_max_len, max_fragment_len).map_err(|error| match error {
        FramingError::TooManyFragments(count) => UrBinaryEncodeError::TooManyFragments {
            count,
            max: MAX_SEQUENCE_LEN,
        },
        FramingError::Framing => UrBinaryEncodeError::Framing,
    })
}

enum FramingError {
    TooManyFragments(usize),
    Framing,
}

/// One single-part code when `payload` is at most `single_max` bytes, else every pure fragment
/// of at most `fragment_len` bytes and the fountain parts, uppercase.
fn encode_parts(
    payload: &[u8],
    single_max: usize,
    fragment_len: usize,
) -> Result<Vec<String>, FramingError> {
    if payload.len() <= single_max {
        let part = ur::try_encode(payload, &ur::Type::Custom(UR_TYPE))
            .map_err(|_| FramingError::Framing)?;
        return Ok(vec![part.to_ascii_uppercase()]);
    }
    let mut encoder =
        ur::Encoder::new(payload, fragment_len, UR_TYPE).map_err(|_| FramingError::Framing)?;
    let fragments = encoder.fragment_count();
    if fragments > MAX_SEQUENCE_LEN {
        return Err(FramingError::TooManyFragments(fragments));
    }
    let total = fragments.saturating_add(fountain_part_count(fragments));
    (0..total)
        .map(|_| {
            encoder
                .next_part()
                .map(|part| part.to_ascii_uppercase())
                .map_err(|_| FramingError::Framing)
        })
        .collect()
}

/// Fountain parts [`encode_ur_slate`] adds after `fragments` pure parts: twice as many, and at
/// least [`MIN_FOUNTAIN_PARTS`], so a loop of the list survives several missed frames.
pub fn fountain_part_count(fragments: usize) -> usize {
    fragments.saturating_mul(2).max(MIN_FOUNTAIN_PARTS)
}

/// Decodes the distinct QR texts scanned so far, in any order and case. Duplicates are
/// harmless. No parts yields empty progress. The text returned is UTF-8 JSON, not yet checked
/// as a slate. Reads payload version 1 only; [`decode_ur_parts`] reads both versions.
pub fn decode_ur_slate<S: AsRef<str>>(parts: &[S]) -> Result<UrProgress, UrDecodeError> {
    let assembled = assemble(parts)?;
    let json = match &assembled.payload {
        Some(payload) => Some(decode_payload(payload)?),
        None => None,
    };
    Ok(UrProgress {
        resolved_fragments: assembled.resolved_fragments,
        fragment_count: assembled.fragment_count,
        json,
    })
}

/// What a complete code carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrContent {
    /// Payload version 1: the slate JSON text.
    Json(String),
    /// Payload version 2.
    Binary(UrBinary),
}

/// The bytes of a version 2 payload, told apart by their magic and returned whole, magic
/// included. Neither is parsed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrBinary {
    NativeSlate(Vec<u8>),
    Envelope(Vec<u8>),
}

/// How far a set of scanned parts got, for either payload version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrContentProgress {
    pub resolved_fragments: usize,
    pub fragment_count: usize,
    /// Set once every fragment is recovered.
    pub content: Option<UrContent>,
}

impl UrContentProgress {
    pub fn is_complete(&self) -> bool {
        self.content.is_some()
    }
}

/// Why a version 2 payload could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UrBinaryEncodeError {
    #[error("bytes start with neither the native slate nor the envelope magic")]
    UnknownMagic,
    #[error("{len} bytes exceed {max} bytes")]
    TooLong { len: usize, max: usize },
    #[error("fragment length {len} is outside {min} to {max}")]
    FragmentLength { len: usize, min: usize, max: usize },
    #[error("single-code limit {len} exceeds {max}")]
    SingleCodeLength { len: usize, max: usize },
    #[error("the payload needs {count} fragments, more than {max}")]
    TooManyFragments { count: usize, max: usize },
    #[error("multipart framing failed")]
    Framing,
}

/// Why scanned parts could not be read as either payload version.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UrContentError {
    #[error(transparent)]
    Decode(#[from] UrDecodeError),
    #[error("payload bytes start with neither the native slate nor the envelope magic")]
    UnknownMagic,
    #[error("payload of {len} bytes exceeds {max} bytes")]
    TooLong { len: usize, max: usize },
}

/// Like [`decode_ur_slate`], for codes of payload version 1 or 2. Version 2 bytes are checked
/// for their magic and length only.
pub fn decode_ur_parts<S: AsRef<str>>(parts: &[S]) -> Result<UrContentProgress, UrContentError> {
    let assembled = assemble(parts)?;
    let content = match &assembled.payload {
        Some(payload) => Some(decode_content(payload)?),
        None => None,
    };
    Ok(UrContentProgress {
        resolved_fragments: assembled.resolved_fragments,
        fragment_count: assembled.fragment_count,
        content,
    })
}

/// Fragments gathered from parts, and the CBOR payload once all are there.
struct Assembled {
    resolved_fragments: usize,
    fragment_count: usize,
    payload: Option<Vec<u8>>,
}

fn assemble<S: AsRef<str>>(parts: &[S]) -> Result<Assembled, UrDecodeError> {
    check_bounds(parts)?;
    let mut parsed = Vec::with_capacity(parts.len());
    for part in parts {
        parsed.push(parse_part(part.as_ref())?);
    }
    let Some(first) = parsed.first() else {
        return Ok(Assembled {
            resolved_fragments: 0,
            fragment_count: 0,
            payload: None,
        });
    };
    match first {
        ParsedPart::Single(payload) => {
            if parsed
                .iter()
                .any(|other| !matches!(other, ParsedPart::Single(body) if body == payload))
            {
                return Err(UrDecodeError::MixedCodes);
            }
            Ok(Assembled {
                resolved_fragments: 1,
                fragment_count: 1,
                payload: Some(payload.clone()),
            })
        }
        ParsedPart::Multi(_) => assemble_multipart(parsed),
    }
}

fn check_bounds<S: AsRef<str>>(parts: &[S]) -> Result<(), UrDecodeError> {
    if parts.len() > MAX_PARTS {
        return Err(UrDecodeError::TooManyParts {
            count: parts.len(),
            max: MAX_PARTS,
        });
    }
    let mut total: usize = 0;
    for part in parts {
        let len = part.as_ref().len();
        if len > MAX_PART_TEXT_LEN {
            return Err(UrDecodeError::PartTooLong {
                len,
                max: MAX_PART_TEXT_LEN,
            });
        }
        total = total.saturating_add(len);
    }
    if total > MAX_TOTAL_TEXT_LEN {
        return Err(UrDecodeError::TooMuchText {
            len: total,
            max: MAX_TOTAL_TEXT_LEN,
        });
    }
    Ok(())
}

enum ParsedPart {
    /// The CBOR payload of a single-part code.
    Single(Vec<u8>),
    Multi(MultiPart),
}

/// A fountain part with its header fields checked against its sequence index.
struct MultiPart {
    sequence_count: usize,
    message_length: usize,
    checksum: u32,
    fragment_len: usize,
    part: fountain::Part,
}

impl MultiPart {
    fn same_code(&self, other: &Self) -> bool {
        self.sequence_count == other.sequence_count
            && self.message_length == other.message_length
            && self.checksum == other.checksum
            && self.fragment_len == other.fragment_len
    }
}

fn parse_part(text: &str) -> Result<ParsedPart, UrDecodeError> {
    if !text.is_ascii() {
        return Err(UrDecodeError::NotUr);
    }
    let text = text.to_ascii_lowercase();
    let rest = text.strip_prefix("ur:").ok_or(UrDecodeError::NotUr)?;
    let (ur_type, body) = rest.split_once('/').ok_or(UrDecodeError::NotUr)?;
    if ur_type.is_empty()
        || ur_type.len() > MAX_TYPE_LEN
        || !ur_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(UrDecodeError::NotUr);
    }
    if ur_type != UR_TYPE {
        return Err(UrDecodeError::OtherType {
            ur_type: ur_type.to_owned(),
        });
    }
    match body.split_once('/') {
        None => Ok(ParsedPart::Single(decode_bytewords(body)?)),
        Some((index, words)) => parse_multipart(index, words).map(ParsedPart::Multi),
    }
}

fn decode_bytewords(words: &str) -> Result<Vec<u8>, UrDecodeError> {
    bytewords::decode(words, Style::Minimal)
        .map_err(|_| UrDecodeError::InvalidPart(PartFault::Bytewords))
}

fn parse_multipart(index: &str, words: &str) -> Result<MultiPart, UrDecodeError> {
    let (sequence, sequence_count) = parse_index(index)?;
    if sequence_count > MAX_SEQUENCE_LEN {
        return Err(UrDecodeError::SequenceTooLong {
            len: sequence_count,
            max: MAX_SEQUENCE_LEN,
        });
    }
    let cbor = decode_bytewords(words)?;
    let header = read_part_header(&cbor)?;
    if header.sequence != sequence || header.sequence_count != sequence_count {
        return Err(UrDecodeError::InvalidPart(PartFault::IndexMismatch));
    }
    if header.fragment_len == 0 || header.fragment_len > MAX_FRAGMENT_LEN {
        return Err(UrDecodeError::InvalidPart(PartFault::FragmentLength {
            len: header.fragment_len,
        }));
    }
    check_message_length(
        header.message_length,
        header.fragment_len,
        header.sequence_count,
    )?;
    let part = minicbor::decode::<fountain::Part>(&cbor)
        .map_err(|_| UrDecodeError::InvalidPart(PartFault::Cbor))?;
    Ok(MultiPart {
        sequence_count,
        message_length: header.message_length,
        checksum: header.checksum,
        fragment_len: header.fragment_len,
        part,
    })
}

/// `<sequence>-<count>`, both decimal without sign or leading `+`, sequence at least 1 and
/// count between 1 and what a `u32` holds.
fn parse_index(index: &str) -> Result<(usize, usize), UrDecodeError> {
    let invalid = || UrDecodeError::InvalidPart(PartFault::Index);
    let (sequence, count) = index.split_once('-').ok_or_else(invalid)?;
    let sequence = parse_decimal(sequence).ok_or_else(invalid)?;
    let count = parse_decimal(count).ok_or_else(invalid)?;
    if sequence == 0 || count == 0 {
        return Err(invalid());
    }
    Ok((sequence, count))
}

fn parse_decimal(digits: &str) -> Option<usize> {
    if digits.is_empty()
        || digits.len() > MAX_INDEX_DIGITS
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let value = digits.parse::<u32>().ok()?;
    usize::try_from(value).ok()
}

struct PartHeader {
    sequence: usize,
    sequence_count: usize,
    message_length: usize,
    checksum: u32,
    fragment_len: usize,
}

/// The fields of a fountain part, `[sequence, count, message length, checksum, fragment]`,
/// with nothing after the array.
fn read_part_header(cbor: &[u8]) -> Result<PartHeader, UrDecodeError> {
    let fault = || UrDecodeError::InvalidPart(PartFault::Cbor);
    let mut decoder = minicbor::Decoder::new(cbor);
    if decoder.array().map_err(|_| fault())? != Some(5) {
        return Err(fault());
    }
    let mut field = || -> Result<usize, UrDecodeError> {
        let value = decoder.u32().map_err(|_| fault())?;
        usize::try_from(value).map_err(|_| fault())
    };
    let sequence = field()?;
    let sequence_count = field()?;
    let message_length = field()?;
    let checksum = decoder.u32().map_err(|_| fault())?;
    if decoder.datatype().map_err(|_| fault())? != Type::Bytes {
        return Err(fault());
    }
    let fragment_len = decoder.bytes().map_err(|_| fault())?.len();
    if decoder.position() != cbor.len() {
        return Err(fault());
    }
    Ok(PartHeader {
        sequence,
        sequence_count,
        message_length,
        checksum,
        fragment_len,
    })
}

/// The message must need exactly `count` fragments of `fragment_len` bytes.
fn check_message_length(
    message_length: usize,
    fragment_len: usize,
    count: usize,
) -> Result<(), UrDecodeError> {
    let fault = || UrDecodeError::InvalidPart(PartFault::MessageLength);
    let capacity = fragment_len.checked_mul(count).ok_or_else(fault)?;
    let below = capacity.checked_sub(fragment_len).ok_or_else(fault)?;
    if message_length <= below || message_length > capacity {
        return Err(fault());
    }
    Ok(())
}

fn assemble_multipart(parsed: Vec<ParsedPart>) -> Result<Assembled, UrDecodeError> {
    let mut parts = Vec::with_capacity(parsed.len());
    for part in parsed {
        match part {
            ParsedPart::Multi(part) => parts.push(part),
            ParsedPart::Single(_) => return Err(UrDecodeError::MixedCodes),
        }
    }
    let Some(first) = parts.first() else {
        return Err(UrDecodeError::MixedCodes);
    };
    if parts.iter().any(|part| !part.same_code(first)) {
        return Err(UrDecodeError::MixedCodes);
    }
    let fragment_count = first.sequence_count;
    let mut decoder = fountain::Decoder::default();
    for part in parts {
        decoder
            .receive(part.part)
            .map_err(|_| UrDecodeError::InvalidPart(PartFault::Reassembly))?;
    }
    let resolved_fragments = decoder.resolved_fragment_count().unwrap_or(0);
    let payload = decoder
        .message()
        .map_err(|_| UrDecodeError::InvalidPart(PartFault::Reassembly))?;
    Ok(Assembled {
        resolved_fragments,
        fragment_count,
        payload,
    })
}

/// `{1: 1, 2: deflated slate text}`.
fn encode_payload(slate_text: &[u8]) -> Vec<u8> {
    let deflated = miniz_oxide::deflate::compress_to_vec(slate_text, DEFLATE_LEVEL);
    frame_payload(JSON_PAYLOAD_VERSION_BYTE, &deflated)
}

/// `{1: version, 2: body}`, a definite map with its keys in ascending order. `version` is a
/// CBOR unsigned integer below 24.
fn frame_payload(version: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len().saturating_add(8));
    payload.extend_from_slice(&[0xa2, 0x01, version, 0x02]);
    // A byte string header in its shortest form. A body of at most MAX_SLATE_TEXT_LEN or
    // MAX_BINARY_LEN bytes stays far below the four-byte length form.
    match (u8::try_from(body.len()), u16::try_from(body.len())) {
        (Ok(len), _) if len < 24 => payload.push(0x40 | len),
        (Ok(len), _) => payload.extend_from_slice(&[0x58, len]),
        (Err(_), Ok(len)) => {
            payload.push(0x59);
            payload.extend_from_slice(&len.to_be_bytes());
        }
        (Err(_), Err(_)) => {
            payload.push(0x5a);
            let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
            payload.extend_from_slice(&len.to_be_bytes());
        }
    }
    payload.extend_from_slice(body);
    payload
}

fn decode_content(payload: &[u8]) -> Result<UrContent, UrContentError> {
    let (version, body) = read_payload(payload, &[PAYLOAD_VERSION, BINARY_PAYLOAD_VERSION])?;
    if version == PAYLOAD_VERSION {
        return Ok(UrContent::Json(inflate_slate(body)?));
    }
    if body.len() > MAX_BINARY_LEN {
        return Err(UrContentError::TooLong {
            len: body.len(),
            max: MAX_BINARY_LEN,
        });
    }
    match classify_binary(body).ok_or(UrContentError::UnknownMagic)? {
        BinaryKind::NativeSlate => Ok(UrContent::Binary(UrBinary::NativeSlate(body.to_vec()))),
        BinaryKind::Envelope => Ok(UrContent::Binary(UrBinary::Envelope(body.to_vec()))),
    }
}

enum BinaryKind {
    NativeSlate,
    Envelope,
}

fn classify_binary(bytes: &[u8]) -> Option<BinaryKind> {
    match bytes.get(..4)? {
        magic if magic == NATIVE_SLATE_MAGIC => Some(BinaryKind::NativeSlate),
        magic if magic == ENVELOPE_MAGIC => Some(BinaryKind::Envelope),
        _ => None,
    }
}

fn decode_payload(payload: &[u8]) -> Result<String, UrDecodeError> {
    let (_, deflated) = read_payload(payload, &[PAYLOAD_VERSION])?;
    inflate_slate(deflated)
}

fn inflate_slate(deflated: &[u8]) -> Result<String, UrDecodeError> {
    let text = miniz_oxide::inflate::decompress_to_vec_with_limit(deflated, MAX_SLATE_TEXT_LEN)
        .map_err(|error| match error.status {
            miniz_oxide::inflate::TINFLStatus::HasMoreOutput => UrDecodeError::InflatesTooLarge {
                max: MAX_SLATE_TEXT_LEN,
            },
            _ => UrDecodeError::InvalidDeflate,
        })?;
    let text = String::from_utf8(text).map_err(|_| UrDecodeError::NotUtf8)?;
    match check_slate_text(&text) {
        Ok(()) => Ok(text),
        // The inflate limit already bounds the length.
        Err(_) => Err(UrDecodeError::NotJson),
    }
}

/// The version and the byte string of `{1: version, 2: bytes}`, for a version in `accepted`.
fn read_payload<'a>(payload: &'a [u8], accepted: &[u64]) -> Result<(u64, &'a [u8]), UrDecodeError> {
    let malformed = UrDecodeError::MalformedPayload;
    let mut decoder = minicbor::Decoder::new(payload);
    let Ok(Some(entries)) = decoder.map() else {
        return Err(malformed(PayloadFault::NotAMap));
    };
    if entries == 0 {
        return Err(malformed(PayloadFault::MissingKey {
            key: PAYLOAD_KEY_VERSION,
        }));
    }
    read_key(&mut decoder, PAYLOAD_KEY_VERSION)?;
    let version = decoder
        .u64()
        .map_err(|_| malformed(PayloadFault::WrongType))?;
    if !accepted.contains(&version) {
        return Err(UrDecodeError::UnsupportedVersion { version });
    }
    match entries {
        1 => {
            return Err(malformed(PayloadFault::MissingKey {
                key: PAYLOAD_KEY_DEFLATE,
            }));
        }
        2 => {}
        _ => return Err(malformed(PayloadFault::UnexpectedKey)),
    }
    read_key(&mut decoder, PAYLOAD_KEY_DEFLATE)?;
    if decoder.datatype().ok() != Some(Type::Bytes) {
        return Err(malformed(PayloadFault::WrongType));
    }
    let body = decoder
        .bytes()
        .map_err(|_| malformed(PayloadFault::WrongType))?;
    if decoder.position() != payload.len() {
        return Err(malformed(PayloadFault::TrailingBytes));
    }
    Ok((version, body))
}

fn read_key(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), UrDecodeError> {
    match decoder.u64() {
        Ok(key) if key == expected => Ok(()),
        Ok(_) => Err(UrDecodeError::MalformedPayload(PayloadFault::UnexpectedKey)),
        Err(_) => Err(UrDecodeError::MalformedPayload(PayloadFault::WrongType)),
    }
}

enum SlateTextError {
    Empty,
    TooLong(usize),
    NotJson,
}

fn check_slate_text(text: &str) -> Result<(), SlateTextError> {
    if text.is_empty() {
        return Err(SlateTextError::Empty);
    }
    if text.len() > MAX_SLATE_TEXT_LEN {
        return Err(SlateTextError::TooLong(text.len()));
    }
    serde_json::from_str::<serde::de::IgnoredAny>(text)
        .map(|_| ())
        .map_err(|_| SlateTextError::NotJson)
}
