//! The V2 JSON slate with the LEPIC marker, for ordinary sends between LEPIC wallets over
//! Epicbox (`docs/compat/epicbox.md`).
//!
//! It writes exactly what [`V2JsonCodec`] writes, plus `"lepic":{"version":1}` as the last
//! top-level key, and reads what [`V2JsonCodec`] reads. Stock `epic-wallet` ignores the key and
//! drops it when it rewrites the slate, so a reply that still carries it came from LEPIC, and
//! [`carries_lepic_marker`](super::marked_v3::carries_lepic_marker) finds it in either shape. No
//! slate signature covers the key: it proves a capability, never anything about the slate. It
//! shares the id `legacy-v2`, because on the wire it is a V2 slate; a registry holds either it
//! or [`V2JsonCodec`].

use crate::codec::legacy::v2_json::V2JsonCodec;
use crate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use crate::error::{DecodeError, EncodeError};
use crate::model::Slate;

/// What follows the last key of the V2 object.
const MARKER: &str = ",\"lepic\":{\"version\":1}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkedV2JsonCodec {
    v2: V2JsonCodec,
}

impl MarkedV2JsonCodec {
    pub const fn new(v2: V2JsonCodec) -> Self {
        Self { v2 }
    }
}

impl Codec for MarkedV2JsonCodec {
    fn id(&self) -> CodecId {
        self.v2.id()
    }

    fn detect(&self, wire: &WireSlate) -> bool {
        self.v2.detect(wire)
    }

    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.v2.decode(wire)
    }

    fn encode(&self, slate: &Slate, context: &EncodeContext) -> Result<WireSlate, EncodeError> {
        let plain = self.v2.encode(slate, context)?;
        // The V2 writer always ends its object with `}`; anything else goes out unmarked,
        // which only costs the capability proof.
        let marked = plain
            .as_text()
            .and_then(|text| text.strip_suffix('}'))
            .map(|body| format!("{body}{MARKER}}}"));
        Ok(marked.map_or(plain, |text| WireSlate::text(MediaType::JSON, text)))
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use lepic_primitives::params::Network;
    use serde_json::Value;

    use super::*;
    use crate::codec::legacy::v3_json::V3JsonCodec;
    use crate::codec::marked_v3::carries_lepic_marker;

    const VECTORS: [&str; 3] = [
        include_str!("../../../../testdata/vectors/slates/send_epicbox_plain_s1_v2.json"),
        include_str!("../../../../testdata/vectors/slates/send_epicbox_message_s2_v2.json"),
        include_str!("../../../../testdata/vectors/slates/send_epicbox_header_7_s1_v2.json"),
    ];

    const CONTEXT: EncodeContext = EncodeContext {
        block_header_version: 6,
    };

    fn v2() -> V2JsonCodec {
        V2JsonCodec::new(Network::Floonet.params().default_base_fee())
    }

    fn vector_wire(vector: &str) -> WireSlate {
        let vector: Value = serde_json::from_str(vector).unwrap();
        let json = vector["expected"]["json"].as_str().unwrap().to_owned();
        WireSlate::text(MediaType::JSON, json)
    }

    fn text(wire: &WireSlate) -> &str {
        wire.as_text().unwrap()
    }

    #[test]
    fn marked_output_is_the_v2_output_with_the_marker_last() {
        for vector in VECTORS {
            let slate = v2().decode(&vector_wire(vector)).unwrap();
            let plain = v2().encode(&slate, &CONTEXT).unwrap();
            let marked = MarkedV2JsonCodec::new(v2())
                .encode(&slate, &CONTEXT)
                .unwrap();
            let body = text(&plain).strip_suffix('}').unwrap();
            assert_eq!(
                text(&marked),
                format!("{body},\"lepic\":{{\"version\":1}}}}")
            );
        }
    }

    #[test]
    fn a_marked_slate_decodes_to_the_slate_it_was_written_from() {
        let codec = MarkedV2JsonCodec::new(v2());
        for vector in VECTORS {
            let slate = v2().decode(&vector_wire(vector)).unwrap();
            let marked = codec.encode(&slate, &CONTEXT).unwrap();
            assert!(codec.detect(&marked));
            assert_eq!(codec.decode(&marked).unwrap(), slate);
            assert_eq!(v2().decode(&marked).unwrap(), slate);
        }
    }

    #[test]
    fn a_marked_v2_slate_is_still_read_as_v2_and_not_v3() {
        let base_fee = Network::Floonet.params().default_base_fee();
        let slate = v2().decode(&vector_wire(VECTORS[0])).unwrap();
        let marked = MarkedV2JsonCodec::new(v2())
            .encode(&slate, &CONTEXT)
            .unwrap();
        assert!(v2().detect(&marked));
        assert!(!V3JsonCodec::new(base_fee).detect(&marked));
    }

    #[test]
    fn only_marked_output_carries_the_marker() {
        let slate = v2().decode(&vector_wire(VECTORS[0])).unwrap();
        assert!(!carries_lepic_marker(
            &v2().encode(&slate, &CONTEXT).unwrap()
        ));
        let marked = MarkedV2JsonCodec::new(v2())
            .encode(&slate, &CONTEXT)
            .unwrap();
        assert!(carries_lepic_marker(&marked));
    }
}
