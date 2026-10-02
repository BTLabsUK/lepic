//! The codec framework: one [`Codec`] per wire format, mapping between [`WireSlate`] and the
//! domain [`Slate`]. Codecs own their wire structs and never convert into each other.

use crate::error::{DecodeError, EncodeError};
use crate::model::Slate;

/// Largest wire slate any codec is given. A legacy JSON slate whose body is at the transaction
/// weight limit, compact or pretty-printed, stays below it, so only input no wallet produces is
/// refused.
pub const MAX_WIRE_SLATE_LEN: usize = 8 * 1024 * 1024;

/// Stable name of a codec, stored with slates and named by transport policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CodecId(&'static str);

impl CodecId {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for CodecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The media type of a wire slate, so transports can label and route it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MediaType(&'static str);

impl MediaType {
    pub const JSON: Self = Self("application/json");
    pub const OCTET_STREAM: Self = Self("application/octet-stream");

    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The payload of a wire slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireContent {
    Text(String),
    Binary(Vec<u8>),
}

/// A slate as it travels: text or bytes, labelled with a media type. Transports that only see
/// bytes, such as a file import, wrap them with [`WireSlate::binary`]; text codecs read the
/// bytes as UTF-8 either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireSlate {
    media_type: MediaType,
    content: WireContent,
}

impl WireSlate {
    pub const fn text(media_type: MediaType, text: String) -> Self {
        Self {
            media_type,
            content: WireContent::Text(text),
        }
    }

    pub const fn binary(media_type: MediaType, bytes: Vec<u8>) -> Self {
        Self {
            media_type,
            content: WireContent::Binary(bytes),
        }
    }

    pub const fn media_type(&self) -> MediaType {
        self.media_type
    }

    pub const fn content(&self) -> &WireContent {
        &self.content
    }

    pub fn into_content(self) -> WireContent {
        self.content
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.content {
            WireContent::Text(text) => text.as_bytes(),
            WireContent::Binary(bytes) => bytes,
        }
    }

    /// The payload as text, or `None` when it is not UTF-8.
    pub fn as_text(&self) -> Option<&str> {
        match &self.content {
            WireContent::Text(text) => Some(text),
            WireContent::Binary(bytes) => std::str::from_utf8(bytes).ok(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

/// Chain facts a codec may need to write a slate that carries no [`crate::origin::WireOrigin`]
/// to copy them from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncodeContext {
    /// Block header version at the slate's height on the wallet's network.
    pub block_header_version: u16,
}

/// One wire format.
///
/// `decode` is a pure function of its input and must reject, never panic, on any bytes; it is
/// the entry point the fuzz targets call, so it starts with [`crate::validate::check_size`].
/// `encode` is lossless: if the format cannot carry something the slate holds, it fails with
/// [`EncodeError::Unrepresentable`].
pub trait Codec: Send + Sync {
    fn id(&self) -> CodecId;

    /// A cheap structural check whether the input is in this format. It does not validate;
    /// [`Codec::decode`] may still reject input that `detect` accepts.
    fn detect(&self, wire: &WireSlate) -> bool;

    /// Decodes and validates the input. The slate carries a [`crate::origin::WireOrigin`]
    /// naming this codec.
    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError>;

    fn encode(&self, slate: &Slate, context: &EncodeContext) -> Result<WireSlate, EncodeError>;
}
