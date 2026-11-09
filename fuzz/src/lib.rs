// SPDX-License-Identifier: Apache-2.0
//! Helpers the fuzz targets share. A target panics only to report a defect: a decoder that
//! panicked itself, or a decoded value that breaks a property the decoder promises.

use lepic_crypto::Commitment;
use lepic_legacy_slate::v2_json::V2JsonCodec;
use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_primitives::amount::Fee;
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;

/// The fee rule is part of what the codecs check, so they get the real floonet base fee.
pub const BASE_FEE: Fee = Network::Floonet.params().default_base_fee();

pub const ENCODE_CONTEXT: EncodeContext = EncodeContext {
    block_header_version: 6,
};

/// Both legacy codecs, more specific first, as a wallet registers them.
pub fn legacy_codecs() -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    for codec in [
        Box::new(V3JsonCodec::new(BASE_FEE)) as Box<dyn Codec>,
        Box::new(V2JsonCodec::new(BASE_FEE)),
    ] {
        if codecs.register(codec).is_err() {
            panic!("the legacy codecs have distinct ids");
        }
    }
    codecs
}

/// A slate `codec` accepted must encode with the same codec and decode back to itself, and its
/// encoding must be stable. Only the wire origin may change on the way: the codecs write the
/// header version that follows the slate's shape (ADR 0020), whatever header it was read with.
pub fn assert_round_trips(codec: &dyn Codec, slate: &Slate) {
    let encoded = match codec.encode(slate, &ENCODE_CONTEXT) {
        Ok(encoded) => encoded,
        Err(error) => panic!("{} decoded a slate it cannot encode: {error}", codec.id()),
    };
    let decoded = match codec.decode(&encoded) {
        Ok(decoded) => decoded,
        Err(error) => panic!("{} rejected its own encoding: {error}", codec.id()),
    };
    assert_eq!(
        decoded.origin().map(|origin| origin.codec()),
        Some(codec.id()),
        "{} decoded its own encoding as another codec",
        codec.id()
    );
    assert_eq!(
        decoded.clone().with_origin(None),
        slate.clone().with_origin(None),
        "{} round trip changed the slate",
        codec.id()
    );
    match codec.encode(&decoded, &ENCODE_CONTEXT) {
        Ok(again) => assert_eq!(again, encoded, "{} encoding is not stable", codec.id()),
        Err(error) => panic!("{} cannot encode what it decoded: {error}", codec.id()),
    }
}

/// Every run of exactly 66 hex digits in `bytes` that parses as a commitment, in order. Lets a
/// target answer "was this commitment requested?" the way a client that asked for it would.
pub fn commitments_in(bytes: &[u8]) -> Vec<Commitment> {
    const HEX_LEN: usize = 66;
    bytes
        .split(|byte| !byte.is_ascii_hexdigit())
        .filter(|run| run.len() == HEX_LEN)
        .filter_map(|run| std::str::from_utf8(run).ok())
        .filter_map(|hex| Commitment::from_hex(hex).ok())
        .collect()
}

/// A deterministic RNG (SplitMix64) for targets that build slates, so a crash input rebuilds the
/// same slates when it is replayed.
pub struct CountingRng(u64);

impl CountingRng {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl rand_core::TryRng for CountingRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.try_next_u64().map(|value| (value >> 32) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for CountingRng {}

/// The most edits [`mutate_slate`] makes to one slate.
pub const MAX_EDITS: usize = 8;

/// `slate` changed as a hostile peer could change it while it still decodes: valid in form,
/// adversarial in content. It is encoded as V3 JSON and `edits`, three bytes each, change that
/// JSON: a number set to an edge value, a string replaced by one from `donors` (keys,
/// signatures, commitments and proofs of other slates, so they still parse), a field nulled, a
/// hex digit flipped, an array element duplicated, dropped or swapped. `None` when the result
/// no longer decodes.
pub fn mutate_slate(slate: &Slate, edits: &[u8], donors: &[String]) -> Option<Slate> {
    let codec = V3JsonCodec::new(BASE_FEE);
    let encoded = codec.encode(slate, &ENCODE_CONTEXT).ok()?;
    let mut json: serde_json::Value = serde_json::from_slice(encoded.as_bytes()).ok()?;
    for edit in edits.chunks_exact(3).take(MAX_EDITS) {
        let &[kind, at, with] = edit else {
            continue;
        };
        apply_edit(&mut json, kind, at, with, donors);
    }
    let bytes = serde_json::to_vec(&json).ok()?;
    codec
        .decode(&WireSlate::binary(MediaType::JSON, bytes))
        .ok()
}

fn apply_edit(json: &mut serde_json::Value, kind: u8, at: u8, with: u8, donors: &[String]) {
    use serde_json::Value;
    let mut leaves = Vec::new();
    let mut arrays = Vec::new();
    collect_pointers(json, String::new(), &mut leaves, &mut arrays);
    let pick = |list: &[String]| list.get(usize::from(at) % list.len().max(1)).cloned();
    match kind % 7 {
        0..=3 => {
            let Some(pointer) = pick(&leaves) else {
                return;
            };
            let Some(leaf) = json.pointer_mut(&pointer) else {
                return;
            };
            match (kind % 7, &*leaf) {
                (0, Value::Number(number)) => {
                    let value = number.as_u64().unwrap_or(0);
                    let edge = [
                        0,
                        1,
                        u64::MAX,
                        u64::MAX / 2,
                        value.wrapping_add(1),
                        value.wrapping_sub(1),
                        value.wrapping_mul(2),
                        u64::from(with),
                    ];
                    *leaf = Value::from(edge[usize::from(with) % edge.len()]);
                }
                (0, Value::String(text)) if text.bytes().all(|b| b.is_ascii_digit()) => {
                    let value: u64 = text.parse().unwrap_or(0);
                    let edge = [0, 1, u64::MAX, value.wrapping_add(1), value.wrapping_sub(1)];
                    *leaf = Value::from(edge[usize::from(with) % edge.len()].to_string());
                }
                (1, Value::String(_)) if !donors.is_empty() => {
                    *leaf = Value::from(donors[usize::from(with) % donors.len()].clone());
                }
                (2, _) => *leaf = Value::Null,
                (3, Value::String(text)) if !text.is_empty() => {
                    let mut bytes = text.clone().into_bytes();
                    let index = usize::from(with) % bytes.len();
                    bytes[index] = match bytes[index] {
                        b'0' => b'1',
                        b'f' => b'e',
                        b'F' => b'E',
                        other if other.is_ascii_hexdigit() => b'0',
                        other => other,
                    };
                    *leaf = Value::from(String::from_utf8(bytes).unwrap_or_default());
                }
                _ => {}
            }
        }
        kind => {
            let Some(pointer) = pick(&arrays) else {
                return;
            };
            let Some(Value::Array(items)) = json.pointer_mut(&pointer) else {
                return;
            };
            if items.is_empty() {
                return;
            }
            let index = usize::from(with) % items.len();
            match kind {
                4 => {
                    let copy = items[index].clone();
                    items.insert(index, copy);
                }
                5 => {
                    items.remove(index);
                }
                _ => items.swap(0, index),
            }
        }
    }
}

/// JSON pointers to every scalar and every array in `value`.
fn collect_pointers(
    value: &serde_json::Value,
    path: String,
    leaves: &mut Vec<String>,
    arrays: &mut Vec<String>,
) {
    use serde_json::Value;
    match value {
        Value::Object(fields) => {
            for (name, field) in fields {
                let name = name.replace('~', "~0").replace('/', "~1");
                collect_pointers(field, format!("{path}/{name}"), leaves, arrays);
            }
        }
        Value::Array(items) => {
            arrays.push(path.clone());
            for (index, item) in items.iter().enumerate() {
                collect_pointers(item, format!("{path}/{index}"), leaves, arrays);
            }
        }
        _ => leaves.push(path),
    }
}

/// Every string in the V3 JSON of `slates`, the donors [`mutate_slate`] swaps in.
pub fn donor_strings(slates: &[&Slate]) -> Vec<String> {
    let codec = V3JsonCodec::new(BASE_FEE);
    let mut donors = Vec::new();
    for slate in slates {
        let Ok(encoded) = codec.encode(slate, &ENCODE_CONTEXT) else {
            continue;
        };
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(encoded.as_bytes()) else {
            continue;
        };
        let (mut leaves, mut arrays) = (Vec::new(), Vec::new());
        collect_pointers(&json, String::new(), &mut leaves, &mut arrays);
        for pointer in leaves {
            if let Some(serde_json::Value::String(text)) = json.pointer(&pointer) {
                donors.push(text.clone());
            }
        }
    }
    donors.sort();
    donors.dedup();
    donors
}
