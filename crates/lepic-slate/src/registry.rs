// SPDX-License-Identifier: Apache-2.0
//! The set of codecs a wallet speaks, and detection of the codec of an unknown wire slate.

use crate::codec::{Codec, CodecId, EncodeContext, WireSlate};
use crate::error::{DecodeError, EncodeError, RegistryError};
use crate::model::Slate;
use crate::validate::check_size;

/// Codecs in registration order. Detection asks them in that order and the first that
/// recognises the input decodes it, so register more specific formats before more general ones.
#[derive(Default)]
pub struct CodecRegistry {
    codecs: Vec<Box<dyn Codec>>,
}

impl CodecRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, codec: Box<dyn Codec>) -> Result<(), RegistryError> {
        let id = codec.id();
        if self.get(id).is_some() {
            return Err(RegistryError::DuplicateCodec { codec: id });
        }
        self.codecs.push(codec);
        Ok(())
    }

    pub fn get(&self, id: CodecId) -> Option<&dyn Codec> {
        self.codecs
            .iter()
            .map(Box::as_ref)
            .find(|codec| codec.id() == id)
    }

    pub fn ids(&self) -> impl Iterator<Item = CodecId> + '_ {
        self.codecs.iter().map(|codec| codec.id())
    }

    /// The first registered codec that recognises the input.
    pub fn detect(&self, wire: &WireSlate) -> Result<&dyn Codec, DecodeError> {
        self.detect_among(wire, None)
    }

    /// The first registered codec in `accepted` that recognises the input. Codecs outside
    /// `accepted` are not asked, so a transport only ever decodes the formats it speaks.
    pub fn detect_accepted(
        &self,
        wire: &WireSlate,
        accepted: &[CodecId],
    ) -> Result<&dyn Codec, DecodeError> {
        self.detect_among(wire, Some(accepted))
    }

    /// Detects the codec and decodes with it.
    pub fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.detect(wire)?.decode(wire)
    }

    pub fn decode_accepted(
        &self,
        wire: &WireSlate,
        accepted: &[CodecId],
    ) -> Result<Slate, DecodeError> {
        self.detect_accepted(wire, accepted)?.decode(wire)
    }

    /// Encodes with the named codec, or returns `None` when it is not registered.
    pub fn encode(
        &self,
        id: CodecId,
        slate: &Slate,
        context: &EncodeContext,
    ) -> Option<Result<WireSlate, EncodeError>> {
        self.get(id).map(|codec| codec.encode(slate, context))
    }

    fn detect_among(
        &self,
        wire: &WireSlate,
        accepted: Option<&[CodecId]>,
    ) -> Result<&dyn Codec, DecodeError> {
        check_size(wire)?;
        self.codecs
            .iter()
            .map(Box::as_ref)
            .filter(|codec| accepted.is_none_or(|ids| ids.contains(&codec.id())))
            .find(|codec| codec.detect(wire))
            .ok_or(DecodeError::UnknownFormat)
    }
}

impl std::fmt::Debug for CodecRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.ids()).finish()
    }
}
