// SPDX-License-Identifier: Apache-2.0
//! The V3 JSON slate with the LEPIC marker, for invoice stages between LEPIC wallets over
//! Epicbox (`docs/compat/epicbox.md`).
//!
//! It writes exactly what [`V3JsonCodec`] writes, plus `"lepic":{"version":1}` as the last
//! top-level key, and reads what [`V3JsonCodec`] reads. Stock `epic-wallet` ignores the key and
//! drops it when it rewrites the slate, so a slate that still carries it came from LEPIC. No
//! slate signature covers the key: it proves a capability, never anything about the slate. It
//! shares the id `legacy-v3`, because on the wire it is a V3 slate; a registry holds either it
//! or [`V3JsonCodec`].
//!
//! Given a 32-byte X25519 reply public key it writes `"lepic":{"version":1,"reply":"<hex>"}`
//! instead (RFC 0002 section 5); [`lepic_marker_reply_key`] reads it back. The key
//! authenticates nothing.

use lepic_crypto::hex;
use serde::Deserialize;

use crate::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError};
use lepic_slate::model::Slate;
use lepic_slate::validate::check_size;

use super::{MarkerExtra, marker_text};

/// The X25519 u-coordinates of small order, as libsodium's blacklist lists them (little-endian):
/// 0, 1, the two points of order 8, and the three encodings of p-1, p and p+1. [`is_small_order`]
/// compares after clearing bit 255, which X25519 ignores, so the non-canonical variants of the
/// same points are covered too.
const SMALL_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    p_plus(0xec),
    p_plus(0xed),
    p_plus(0xee),
];

/// The 32 bytes `ec ff .. ff 7f` with the first byte `first`.
const fn p_plus(first: u8) -> [u8; 32] {
    let mut bytes = [0xff; 32];
    bytes[0] = first;
    bytes[31] = 0x7f;
    bytes
}

fn is_small_order(key: &[u8; 32]) -> bool {
    let mut masked = *key;
    if let Some(last) = masked.last_mut() {
        *last &= 0x7f;
    }
    SMALL_ORDER.contains(&masked)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkedV3JsonCodec {
    v3: V3JsonCodec,
    extra: MarkerExtra,
}

impl MarkedV3JsonCodec {
    pub const fn new(v3: V3JsonCodec) -> Self {
        Self {
            v3,
            extra: MarkerExtra::None,
        }
    }

    /// The codec writing `reply_key`, an X25519 public key, into the marker, for a file or
    /// paste slate. Such a marker never carries `f`.
    pub const fn with_reply_key(mut self, reply_key: [u8; 32]) -> Self {
        self.extra = MarkerExtra::Reply(reply_key);
        self
    }

    /// The codec writing `features` as the marker's `f`, for a slate sent over Epicbox only.
    /// Such a marker never carries a reply key.
    pub const fn with_features(mut self, features: u32) -> Self {
        self.extra = MarkerExtra::Features(features);
        self
    }

    /// The codec writing `features` as `f` and `key`, the X25519 key of the sender's payments
    /// address, as `reply`, for a slate sent over Epicbox only by a wallet that takes native
    /// slates there (RFC 0003 5.15).
    pub const fn with_native_claim(mut self, features: u32, key: [u8; 32]) -> Self {
        self.extra = MarkerExtra::NativeClaim { features, key };
        self
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
            .map(|body| format!("{body}{}}}", marker_text(&self.extra)));
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

/// The feature bits in the LEPIC marker of `wire`: its `f` when the marker counts for
/// [`carries_lepic_marker`] and `f` is an integer that fits a `u32`, unknown bits kept. `None`
/// for a marker without `f` (an older LEPIC, which claims only `MARKER` of
/// `lepic_transport::marker::features`), a malformed `f`, or no marker.
pub fn lepic_marker_features(wire: &WireSlate) -> Option<u32> {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        lepic: Option<Marker>,
    }
    #[derive(Deserialize)]
    struct Marker {
        version: u64,
        #[serde(default)]
        f: Option<u32>,
    }
    if check_size(wire).is_err() {
        return None;
    }
    let text = wire.as_text()?;
    if !text.trim_start().starts_with('{') {
        return None;
    }
    let marker = serde_json::from_str::<Probe>(text).ok()?.lepic?;
    if marker.version < 1 {
        return None;
    }
    marker.f
}

/// The reply public key in the LEPIC marker of `wire`, if the marker has a `reply` of exactly 64
/// lowercase hex digits that is neither all zero nor of small order. Anything else gives `None`,
/// so the answer goes plain.
pub fn lepic_marker_reply_key(wire: &WireSlate) -> Option<[u8; 32]> {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        lepic: Option<Marker>,
    }
    #[derive(Deserialize)]
    struct Marker {
        version: u64,
        #[serde(default)]
        reply: Option<String>,
    }
    if check_size(wire).is_err() {
        return None;
    }
    let text = wire.as_text()?;
    if !text.trim_start().starts_with('{') {
        return None;
    }
    let marker = serde_json::from_str::<Probe>(text).ok()?.lepic?;
    if marker.version < 1 {
        return None;
    }
    let key = decode_reply_hex(marker.reply.as_deref()?)?;
    (!is_small_order(&key)).then_some(key)
}

/// The reply key is written in lowercase only, which is stricter than the shared decoder.
fn decode_reply_hex(text: &str) -> Option<[u8; 32]> {
    let lowercase = text
        .bytes()
        .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'));
    if !lowercase {
        return None;
    }
    hex::decode_array(text).ok()
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

    fn reply_wire(reply: &Value) -> WireSlate {
        let mut value: Value = serde_json::from_str(text(&vector_wire(VECTORS[0]))).unwrap();
        value["lepic"] = json!({"version": 1, "reply": reply});
        WireSlate::text(MediaType::JSON, serde_json::to_string(&value).unwrap())
    }

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn reply_key_is_written_last_and_read_back() {
        let codec = MarkedV3JsonCodec::new(v3()).with_reply_key(KEY);
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        let wire = codec.encode(&slate, &CONTEXT).unwrap();
        let plain = v3().encode(&slate, &CONTEXT).unwrap();
        let body = text(&plain).strip_suffix('}').unwrap();
        assert_eq!(
            text(&wire),
            format!(
                "{body},\"lepic\":{{\"version\":1,\"reply\":\"{}\"}}}}",
                "42".repeat(32)
            )
        );
        assert!(carries_lepic_marker(&wire));
        assert_eq!(lepic_marker_reply_key(&wire), Some(KEY));
        assert_eq!(codec.decode(&wire).unwrap(), slate);
    }

    #[test]
    fn marker_without_a_reply_key_reads_none() {
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        let marked = MarkedV3JsonCodec::new(v3())
            .encode(&slate, &CONTEXT)
            .unwrap();
        assert_eq!(lepic_marker_reply_key(&marked), None);
        assert_eq!(lepic_marker_reply_key(&vector_wire(VECTORS[0])), None);
    }

    #[test]
    fn malformed_reply_hex_reads_none() {
        let good = "42".repeat(32);
        assert_eq!(lepic_marker_reply_key(&reply_wire(&json!(good))), Some(KEY));
        for bad in [
            json!("zz".repeat(32)),
            json!("4G".repeat(32)),
            json!("AB".repeat(32)),
            json!(format!("{good}0")),
            json!(format!(" {good}")),
            json!("42"),
            json!(""),
            json!(42),
            Value::Null,
        ] {
            assert_eq!(lepic_marker_reply_key(&reply_wire(&bad)), None, "{bad}");
        }
    }

    #[test]
    fn wrong_length_reply_reads_none() {
        for len in [62, 66, 128] {
            assert_eq!(
                lepic_marker_reply_key(&reply_wire(&json!("4a".repeat(len / 2)))),
                None
            );
        }
    }

    #[test]
    fn all_zero_reply_reads_none() {
        assert_eq!(
            lepic_marker_reply_key(&reply_wire(&json!("00".repeat(32)))),
            None
        );
    }

    #[test]
    fn small_order_replies_read_none() {
        for point in SMALL_ORDER {
            let hex: String = point.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                lepic_marker_reply_key(&reply_wire(&json!(hex))),
                None,
                "{hex}"
            );
            // The same point with the bit X25519 ignores set.
            let mut high = point;
            high[31] |= 0x80;
            let hex: String = high.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                lepic_marker_reply_key(&reply_wire(&json!(hex))),
                None,
                "{hex}"
            );
        }
    }

    #[test]
    fn reply_in_a_marker_of_version_zero_or_a_non_object_reads_none() {
        let mut value: Value = serde_json::from_str(text(&vector_wire(VECTORS[0]))).unwrap();
        value["lepic"] = json!({"version": 0, "reply": "42".repeat(32)});
        let wire = WireSlate::text(MediaType::JSON, serde_json::to_string(&value).unwrap());
        assert_eq!(lepic_marker_reply_key(&wire), None);
        assert_eq!(
            lepic_marker_reply_key(&WireSlate::binary(MediaType::JSON, vec![0xff])),
            None
        );
        assert_eq!(
            lepic_marker_reply_key(&WireSlate::text(MediaType::JSON, "[1]".to_owned())),
            None
        );
    }

    #[test]
    fn features_are_written_as_f_and_read_back() {
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        let plain = v3().encode(&slate, &CONTEXT).unwrap();
        let body = text(&plain).strip_suffix('}').unwrap();
        let wire = MarkedV3JsonCodec::new(v3())
            .with_features(0x21)
            .encode(&slate, &CONTEXT)
            .unwrap();
        assert_eq!(
            text(&wire),
            format!("{body},\"lepic\":{{\"version\":1,\"f\":33}}}}")
        );
        assert!(carries_lepic_marker(&wire));
        assert_eq!(lepic_marker_features(&wire), Some(0x21));
        assert_eq!(lepic_marker_reply_key(&wire), None);
        assert_eq!(v3().decode(&wire).unwrap(), slate);
    }

    #[test]
    fn a_reply_key_marker_never_carries_f() {
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        for codec in [
            MarkedV3JsonCodec::new(v3()).with_reply_key(KEY),
            MarkedV3JsonCodec::new(v3())
                .with_features(7)
                .with_reply_key(KEY),
        ] {
            let wire = codec.encode(&slate, &CONTEXT).unwrap();
            assert_eq!(lepic_marker_features(&wire), None);
            assert!(!text(&wire).contains("\"f\""));
            assert_eq!(lepic_marker_reply_key(&wire), Some(KEY));
        }
    }

    #[test]
    fn a_native_claim_writes_f_and_reply_and_both_readers_read_it() {
        let slate = v3().decode(&vector_wire(VECTORS[0])).unwrap();
        let plain = v3().encode(&slate, &CONTEXT).unwrap();
        let body = text(&plain).strip_suffix('}').unwrap();
        let wire = MarkedV3JsonCodec::new(v3())
            .with_native_claim(0xb5, KEY)
            .encode(&slate, &CONTEXT)
            .unwrap();
        let hex: String = KEY.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            text(&wire),
            format!("{body},\"lepic\":{{\"version\":1,\"f\":181,\"reply\":\"{hex}\"}}}}")
        );
        assert!(carries_lepic_marker(&wire));
        assert_eq!(lepic_marker_features(&wire), Some(0xb5));
        assert_eq!(lepic_marker_reply_key(&wire), Some(KEY));
        assert_eq!(v3().decode(&wire).unwrap(), slate);
    }

    #[test]
    fn only_a_u32_f_in_a_counted_marker_reads_as_features() {
        let with = |marker: Value| {
            let mut value: Value = serde_json::from_str(text(&vector_wire(VECTORS[0]))).unwrap();
            value["lepic"] = marker;
            let wire = WireSlate::text(MediaType::JSON, serde_json::to_string(&value).unwrap());
            (carries_lepic_marker(&wire), lepic_marker_features(&wire))
        };
        assert_eq!(with(json!({"version": 1, "f": 0})), (true, Some(0)));
        assert_eq!(
            with(json!({"version": 1, "f": u32::MAX})),
            (true, Some(u32::MAX))
        );
        assert_eq!(with(json!({"version": 2, "f": 5, "x": 1})), (true, Some(5)));
        assert_eq!(with(json!({"version": 1})), (true, None));
        assert_eq!(
            with(json!({"version": 1, "f": u64::from(u32::MAX) + 1})),
            (true, None)
        );
        assert_eq!(with(json!({"version": 1, "f": -1})), (true, None));
        assert_eq!(with(json!({"version": 1, "f": "3"})), (true, None));
        assert_eq!(with(json!({"version": 1, "f": 1.5})), (true, None));
        assert_eq!(with(json!({"version": 0, "f": 3})), (false, None));
        assert_eq!(lepic_marker_features(&vector_wire(VECTORS[0])), None);
    }
}
