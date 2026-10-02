//! Where a decoded slate came from, so a reply can echo what the peer sent.

use crate::codec::CodecId;

/// The `version_info` triple of a legacy JSON slate, exactly as received. It can disagree with
/// the slate's JSON shape, and upstream peers expect it carried through unchanged on replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LegacyHeader {
    pub version: u16,
    pub orig_version: u16,
    pub block_header_version: u16,
}

/// The codec a slate was decoded with and, for legacy codecs, its header. Only codecs and
/// transport policies read it; the engine stores and passes it on without interpreting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireOrigin {
    codec: CodecId,
    legacy_header: Option<LegacyHeader>,
}

impl WireOrigin {
    pub const fn new(codec: CodecId) -> Self {
        Self {
            codec,
            legacy_header: None,
        }
    }

    pub const fn legacy(codec: CodecId, header: LegacyHeader) -> Self {
        Self {
            codec,
            legacy_header: Some(header),
        }
    }

    pub const fn codec(&self) -> CodecId {
        self.codec
    }

    pub const fn legacy_header(&self) -> Option<LegacyHeader> {
        self.legacy_header
    }
}
