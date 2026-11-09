// SPDX-License-Identifier: Apache-2.0
//! The V2 JSON slate with the LEPIC marker, for ordinary sends between LEPIC wallets over
//! Epicbox (`docs/compat/epicbox.md`).
//!
//! It writes exactly what [`V2JsonCodec`] writes, plus `"lepic":{"version":1}` as the last
//! top-level key, and reads what [`V2JsonCodec`] reads. Stock `epic-wallet` ignores the key and
//! drops it when it rewrites the slate, so a reply that still carries it came from LEPIC, and
//! [`carries_lepic_marker`](super::v3::carries_lepic_marker) finds it in either shape. No
//! slate signature covers the key: it proves a capability, never anything about the slate. It
//! shares the id `legacy-v2`, because on the wire it is a V2 slate; a registry holds either it
//! or [`V2JsonCodec`].

use crate::v2_json::V2JsonCodec;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError};
use lepic_slate::model::Slate;

use super::{MarkerExtra, marker_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkedV2JsonCodec {
    v2: V2JsonCodec,
    extra: MarkerExtra,
}

impl MarkedV2JsonCodec {
    pub const fn new(v2: V2JsonCodec) -> Self {
        Self {
            v2,
            extra: MarkerExtra::None,
        }
    }

    /// The codec writing `features` as the marker's `f`, for a slate sent over Epicbox only.
    pub const fn with_features(mut self, features: u32) -> Self {
        self.extra = MarkerExtra::Features(features);
        self
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
            .map(|body| format!("{body}{}}}", marker_text(&self.extra)));
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
    use crate::marker::v3::carries_lepic_marker;
    use crate::v3_json::V3JsonCodec;

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

    #[test]
    fn features_are_written_as_f_after_the_version() {
        use crate::marker::v3::lepic_marker_features;
        for vector in VECTORS {
            let slate = v2().decode(&vector_wire(vector)).unwrap();
            let plain = v2().encode(&slate, &CONTEXT).unwrap();
            let marked = MarkedV2JsonCodec::new(v2())
                .with_features(1)
                .encode(&slate, &CONTEXT)
                .unwrap();
            let body = text(&plain).strip_suffix('}').unwrap();
            assert_eq!(
                text(&marked),
                format!("{body},\"lepic\":{{\"version\":1,\"f\":1}}}}")
            );
            assert_eq!(lepic_marker_features(&marked), Some(1));
            assert_eq!(v2().decode(&marked).unwrap(), slate);
        }
    }
}
