//! How a transport picks the wire format of a slate (ADR 0003). The engine never names a
//! codec; it asks the transport's [`FormatPolicy`] to decode and encode.

use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::origin::{LegacyHeader, WireOrigin};
use lepic_slate::registry::CodecRegistry;

use crate::error::FormatError;

/// The codec to encode with and, for a legacy codec, the `version_info` header to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Encoding {
    pub codec: CodecId,
    /// `None` lets the codec write the header of a slate it creates.
    pub legacy_header: Option<LegacyHeader>,
}

/// The formats one transport speaks.
pub trait FormatPolicy: Send + Sync {
    /// Codecs this transport decodes. Input in any other format is refused.
    fn accepted(&self) -> &[CodecId];

    /// The encoding of a slate this wallet starts: S1 or I1.
    fn for_new_slate(&self, slate: &Slate, context: &EncodeContext) -> Encoding;

    /// The encoding of a slate answering one the peer sent. A slate decoded from the peer keeps
    /// its [`WireOrigin`] through the stage transitions, so the policy can echo what it received.
    fn for_reply(&self, slate: &Slate, context: &EncodeContext) -> Encoding;

    /// Detects the format among the accepted codecs and decodes.
    fn decode(&self, codecs: &CodecRegistry, wire: &WireSlate) -> Result<Slate, DecodeError> {
        codecs.decode_accepted(wire, self.accepted())
    }

    fn encode_new_slate(
        &self,
        codecs: &CodecRegistry,
        slate: &Slate,
        context: &EncodeContext,
    ) -> Result<WireSlate, FormatError> {
        encode_with(codecs, self.for_new_slate(slate, context), slate, context)
    }

    fn encode_reply(
        &self,
        codecs: &CodecRegistry,
        slate: &Slate,
        context: &EncodeContext,
    ) -> Result<WireSlate, FormatError> {
        encode_with(codecs, self.for_reply(slate, context), slate, context)
    }
}

/// Encodes `slate` as `encoding` says. The codec sees the chosen header as the slate's origin,
/// which is how a policy controls the header a legacy codec writes.
pub fn encode_with(
    codecs: &CodecRegistry,
    encoding: Encoding,
    slate: &Slate,
    context: &EncodeContext,
) -> Result<WireSlate, FormatError> {
    let codec = codecs
        .get(encoding.codec)
        .ok_or(FormatError::CodecNotRegistered {
            codec: encoding.codec,
        })?;
    let origin = encoding
        .legacy_header
        .map(|header| WireOrigin::legacy(encoding.codec, header));
    let slate = slate.clone().with_origin(origin);
    Ok(codec.encode(&slate, context)?)
}
