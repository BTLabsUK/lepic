//! Unkeyed BLAKE2b-256 as the node's `Hashed` trait computes it: over raw bytes, and over the
//! serialization of typed values.

use epic_core::core::hash::{Hash, Hashed, ZERO_HASH};
use epic_core::ser::{self, ProtocolVersion, Writeable};
use serde::Serialize;

use super::AREA;
use crate::{Error, Pins, Rendered, hex, render};

#[derive(Serialize)]
struct NoInputs {}

#[derive(Serialize)]
struct Cases<T> {
    cases: Vec<T>,
}

#[derive(Serialize)]
struct BytesHash {
    data: String,
    hash: String,
}

/// `preimage` is the value's binary serialization, which is exactly what the hasher consumes for
/// these types.
#[derive(Serialize)]
struct ValueHash {
    r#type: &'static str,
    value: String,
    preimage: String,
    hash: String,
}

fn pattern(len: usize) -> Vec<u8> {
    (0..=u8::MAX).cycle().take(len).collect()
}

fn bytes_hashes() -> Vec<BytesHash> {
    let mut inputs: Vec<Vec<u8>> = [0usize, 1, 32, 33, 64, 127, 128, 129, 256, 1000]
        .into_iter()
        .map(pattern)
        .collect();
    inputs.push(b"abc".to_vec());
    inputs
        .into_iter()
        .map(|data| BytesHash {
            hash: hex(data.hash()),
            data: hex(data),
        })
        .collect()
}

fn value_hash<T: Writeable + Hashed>(
    r#type: &'static str,
    value: String,
    thing: &T,
) -> Result<ValueHash, Error> {
    let preimage = ser::ser_vec(thing, ProtocolVersion(2)).map_err(Error::reference(r#type))?;
    Ok(ValueHash {
        r#type,
        value,
        preimage: hex(preimage),
        hash: hex(thing.hash()),
    })
}

fn value_hashes() -> Result<Vec<ValueHash>, Error> {
    let abc = b"abc".to_vec().hash();
    Ok(vec![
        value_hash("u8", "0".to_owned(), &0u8)?,
        value_hash("u8", "255".to_owned(), &255u8)?,
        value_hash("u64", "0".to_owned(), &0u64)?,
        value_hash("u64", u64::MAX.to_string(), &u64::MAX)?,
        value_hash("(u8,u64)", "(0,7000000)".to_owned(), &(0u8, 7_000_000u64))?,
        value_hash(
            "(u8,u64,u64)",
            "(2,7000000,1000000)".to_owned(),
            &(2u8, 7_000_000u64, 1_000_000u64),
        )?,
        value_hash("hash", hex(ZERO_HASH), &ZERO_HASH)?,
        value_hash(
            "(hash,hash)",
            format!("({},{})", hex(ZERO_HASH), hex(abc)),
            &(ZERO_HASH, abc),
        )?,
    ])
}

#[derive(Serialize)]
struct HashOps {
    zero_hash: String,
    /// `Hash + Hash` hashes the two 32-byte values concatenated.
    zero_plus_abc: String,
    /// `Hash::to_u64` reads the first eight bytes big-endian.
    abc_to_u64: String,
}

fn hash_ops() -> HashOps {
    let abc: Hash = b"abc".to_vec().hash();
    HashOps {
        zero_hash: hex(ZERO_HASH),
        // Upstream spells hash combination as `Add`; it hashes, it does not add.
        zero_plus_abc: hex(<Hash as std::ops::Add>::add(ZERO_HASH, abc)),
        abc_to_u64: abc.to_u64().to_string(),
    }
}

pub(super) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    Ok(vec![
        render(
            AREA,
            "hash_bytes",
            &pins.node,
            NoInputs {},
            Cases {
                cases: bytes_hashes(),
            },
        )?,
        render(
            AREA,
            "hash_values",
            &pins.node,
            NoInputs {},
            Cases {
                cases: value_hashes()?,
            },
        )?,
        render(AREA, "hash_operations", &pins.node, NoInputs {}, hash_ops())?,
    ])
}
