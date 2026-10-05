//! The V3 JSON slate with the LEPIC marker, for invoice stages between LEPIC wallets over
//! Epicbox (`docs/compat/epicbox.md`).
//!
//! It writes exactly what [`V3JsonCodec`] writes, plus `"lepic":{"version":1}` as the last
//! top-level key, and reads what [`V3JsonCodec`] reads. Stock `epic-wallet` ignores the key and
//! drops it when it rewrites the slate, so a slate that still carries it came from LEPIC. No
//! slate signature covers the key: it proves a capability, never anything about the slate. It
//! shares the id `legacy-v3`, because on the wire it is a V3 slate; a registry holds either it
//! or [`V3JsonCodec`].

use serde::Deserialize;

use crate::codec::legacy::v3_json::V3JsonCodec;
use crate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use crate::error::{DecodeError, EncodeError};
use crate::model::Slate;
use crate::validate::check_size;

/// What follows the last key of the V3 object.
const MARKER: &str = ",\"lepic\":{\"version\":1}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkedV3JsonCodec {
    v3: V3JsonCodec,
}

impl MarkedV3JsonCodec {
    pub const fn new(v3: V3JsonCodec) -> Self {
        Self { v3 }
    }
}

impl Codec for MarkedV3JsonCodec {
    fn id(&self) -> CodecId {
        self.v3.id()
    }

    fn detect(&self, wire: &WireSlate) -> bool {
        self.v3.detect(wire)
    }

    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.v3.decode(wire)
    }

    fn encode(&self, slate: &Slate, context: &EncodeContext) -> Result<WireSlate, EncodeError> {
        let plain = self.v3.encode(slate, context)?;
        // The V3 writer always ends its object with `}`; anything else goes out unmarked,
        // which only costs the capability proof.
        let marked = plain
            .as_text()
            .and_then(|text| text.strip_suffix('}'))
            .map(|body| format!("{body}{MARKER}}}"));
        Ok(marked.map_or(plain, |text| WireSlate::text(MediaType::JSON, text)))
    }
}

/// Whether `wire` is a JSON object whose top-level `lepic` key is an object with an integer
/// `version` of at least 1, as [`MarkedV3JsonCodec`] writes it. Reads nothing else, and is
/// false for anything over the slate size bound.
pub fn carries_lepic_marker(wire: &WireSlate) -> bool {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        lepic: Option<Marker>,
    }
    #[derive(Deserialize)]
    struct Marker {
        version: u64,
    }
    if check_size(wire).is_err() {
        return false;
    }
    let Some(text) = wire.as_text() else {
        return false;
    };
    text.trim_start().starts_with('{')
        && serde_json::from_str::<Probe>(text)
            .is_ok_and(|probe| probe.lepic.is_some_and(|marker| marker.version >= 1))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use lepic_primitives::params::Network;
    use serde_json::{Value, json};

    use super::*;

    const VECTORS: [&str; 3] = [
        include_str!("../../../../testdata/vectors/slates/invoice_file_messages_i1_v3.json"),
        include_str!("../../../../testdata/vectors/slates/invoice_file_messages_i2_v3.json"),
        include_str!(
            "../../../../testdata/vectors/slates/send_file_ttl_payment_proof_messages_s1_v3.json"
        ),
    ];

    const CONTEXT: EncodeContext = EncodeContext {
        block_header_version: 6,
    };

    fn v3() -> V3JsonCodec {
        V3JsonCodec::new(Network::Floonet.params().default_base_fee())
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
    fn marked_output_is_the_v3_output_with_the_marker_last() {
        for vector in VECTORS {
            let slate = v3().decode(&vector_wire(vector)).unwrap();
            let plain = v3().encode(&slate, &CONTEXT).unwrap();
            let marked = MarkedV3JsonCodec::new(v3())
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
        let codec = MarkedV3JsonCodec::new(v3());
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        let marked = codec.encode(&slate, &CONTEXT).unwrap();
        assert!(codec.detect(&marked));
        assert_eq!(codec.decode(&marked).unwrap(), slate);
        assert_eq!(v3().decode(&marked).unwrap(), slate);
    }

    #[test]
    fn only_marked_output_carries_the_marker() {
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        assert!(!carries_lepic_marker(
            &v3().encode(&slate, &CONTEXT).unwrap()
        ));
        let marked = MarkedV3JsonCodec::new(v3())
            .encode(&slate, &CONTEXT)
            .unwrap();
        assert!(carries_lepic_marker(&marked));
    }

    #[test]
    fn only_a_marker_object_with_a_positive_integer_version_counts() {
        let with = |marker: Value| {
            let mut value: Value = serde_json::from_str(text(&vector_wire(VECTORS[0]))).unwrap();
            value["lepic"] = marker;
            let wire = WireSlate::text(MediaType::JSON, serde_json::to_string(&value).unwrap());
            carries_lepic_marker(&wire)
        };
        assert!(with(json!({"version": 1})));
        assert!(with(json!({"version": 2, "other": true})));
        assert!(!with(json!({"version": 0})));
        assert!(!with(json!({"version": "1"})));
        assert!(!with(json!({"version": -1})));
        assert!(!with(json!({})));
        assert!(!with(json!("lepic")));
        assert!(!with(Value::Null));
        assert!(!carries_lepic_marker(&WireSlate::text(
            MediaType::JSON,
            "[1]".to_owned()
        )));
        assert!(!carries_lepic_marker(&WireSlate::binary(
            MediaType::JSON,
            vec![0xff]
        )));
    }
}
