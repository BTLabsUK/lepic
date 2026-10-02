//! Golden vectors for serialization and hashing, written by the G-02 generator from the Epic
//! node at the commit each file records.

use std::path::PathBuf;

use lepic_primitives::hash::{Hash, Hashed, ZERO_HASH, blake2b_256, blake2b_256_keyed};
use lepic_primitives::ser::{
    MAX_READ_LEN, ProtocolVersion, Reader, SerError, VecWriter, Writer, deserialize, ser_vec,
};
use serde_json::Value;

const V2: ProtocolVersion = ProtocolVersion::V2;
const UPSTREAM_REPO: &str = "https://github.com/EpicCash/epic";
const UPSTREAM_COMMIT: &str = "9d022b1d521d3f705532e12ab77e0a429f6fde1f";

// Helpers carry `cfg(test)` so the clippy test allowances (clippy.toml) cover them as they cover
// the `#[test]` functions that call them.

#[cfg(test)]
fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/primitives")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap();
    let vector: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(vector["schema"], 1, "{name}");
    assert_eq!(vector["area"], "primitives", "{name}");
    assert_eq!(vector["name"], name);
    assert_eq!(vector["upstream"]["repo"], UPSTREAM_REPO, "{name}");
    assert_eq!(vector["upstream"]["commit"], UPSTREAM_COMMIT, "{name}");
    vector
}

#[cfg(test)]
fn cases(vector: &Value) -> &[Value] {
    let cases = vector["expected"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    cases
}

#[cfg(test)]
fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {case}"))
}

#[cfg(test)]
fn bytes(case: &Value, key: &str) -> Vec<u8> {
    let hex = text(case, key);
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty(), "odd hex length for {key} in {case}");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(test)]
fn hash(case: &Value, key: &str) -> Hash {
    Hash::from_hex(text(case, key)).unwrap()
}

/// Splits a tuple value such as `(2,7000000,1000000)` into its fields.
#[cfg(test)]
fn fields(value: &str) -> Vec<&str> {
    value
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not a tuple: {value}"))
        .split(',')
        .collect()
}

/// Encodes a value of the vector's named type, then decodes the expected bytes back to it.
#[cfg(test)]
fn check_value(type_name: &str, value: &str, encoded: &[u8]) {
    macro_rules! check {
        ($value:expr) => {{
            let value = $value;
            assert_eq!(ser_vec(&value, V2), encoded, "{type_name} {value:?}");
            assert_eq!(deserialize(encoded, V2), Ok(value), "{type_name}");
        }};
    }
    match type_name {
        "u8" => check!(value.parse::<u8>().unwrap()),
        "u16" => check!(value.parse::<u16>().unwrap()),
        "u32" => check!(value.parse::<u32>().unwrap()),
        "i32" => check!(value.parse::<i32>().unwrap()),
        "u64" => check!(value.parse::<u64>().unwrap()),
        "i64" => check!(value.parse::<i64>().unwrap()),
        "protocol_version" => check!(ProtocolVersion::new(value.parse().unwrap())),
        "(u8,u64)" => match fields(value).as_slice() {
            [a, b] => check!((a.parse::<u8>().unwrap(), b.parse::<u64>().unwrap())),
            other => panic!("{type_name} with {other:?}"),
        },
        "(u8,u64,u64)" => match fields(value).as_slice() {
            [a, b, c] => check!((
                a.parse::<u8>().unwrap(),
                b.parse::<u64>().unwrap(),
                c.parse::<u64>().unwrap()
            )),
            other => panic!("{type_name} with {other:?}"),
        },
        "(u64,u64,u64)" => match fields(value).as_slice() {
            [a, b, c] => check!((
                a.parse::<u64>().unwrap(),
                b.parse::<u64>().unwrap(),
                c.parse::<u64>().unwrap()
            )),
            other => panic!("{type_name} with {other:?}"),
        },
        other => panic!("unhandled type {other}"),
    }
}

#[test]
fn ser_integers_match_upstream() {
    let vector = load("ser_integers");
    for case in cases(&vector) {
        check_value(
            text(case, "type"),
            text(case, "value"),
            &bytes(case, "encoded"),
        );
    }
}

#[test]
fn ser_composites_match_upstream() {
    let vector = load("ser_composites");
    for case in cases(&vector) {
        check_value(
            text(case, "type"),
            text(case, "value"),
            &bytes(case, "encoded"),
        );
    }
}

#[test]
fn ser_length_prefixed_bytes_match_upstream() {
    let vector = load("ser_length_prefixed_bytes");
    for case in cases(&vector) {
        assert_eq!(text(case, "type"), "bytes");
        let value = bytes(case, "value");
        let encoded = bytes(case, "encoded");

        let mut writer = VecWriter::new(V2);
        writer.write_bytes(&value);
        assert_eq!(writer.into_bytes(), encoded);

        let mut reader = Reader::new(&encoded, V2);
        assert_eq!(
            reader.read_bytes_len_prefix(MAX_READ_LEN),
            Ok(value.as_slice())
        );
        assert_eq!(reader.finish(), Ok(()));
    }
}

// Upstream reports a short read as `IOErr(UnexpectedEof)`; LEPIC reports `Truncated`.
#[test]
fn ser_truncated_reads_match_upstream() {
    let vector = load("ser_truncated_reads");
    for case in cases(&vector) {
        let input = bytes(case, "bytes");
        let outcome = match text(case, "type") {
            "u8" => deserialize::<u8>(&input, V2).map(drop),
            "u16" => deserialize::<u16>(&input, V2).map(drop),
            "u32" => deserialize::<u32>(&input, V2).map(drop),
            "u64" => deserialize::<u64>(&input, V2).map(drop),
            "(u8,u64)" => deserialize::<(u8, u64)>(&input, V2).map(drop),
            other => panic!("unhandled type {other}"),
        };
        match text(case, "outcome") {
            "ok" => assert_eq!(outcome, Ok(()), "{case}"),
            "IOErr(UnexpectedEof)" => assert!(
                matches!(outcome, Err(SerError::Truncated { .. })),
                "{case} gave {outcome:?}"
            ),
            other => panic!("unhandled outcome {other}"),
        }
    }
}

#[test]
fn hash_bytes_match_upstream() {
    let vector = load("hash_bytes");
    for case in cases(&vector) {
        assert_eq!(
            blake2b_256(&bytes(case, "data")),
            hash(case, "hash"),
            "{case}"
        );
    }
}

#[test]
fn keyed_hash_bytes_match_blake2_rfc() {
    let vector = load("hash_bytes_keyed");
    let mut key_lengths: Vec<usize> = Vec::new();
    for case in cases(&vector) {
        let key = bytes(case, "key");
        let result = blake2b_256_keyed(&key, &bytes(case, "data"));
        assert_eq!(result, Ok(hash(case, "hash")), "{case}");
        key_lengths.push(key.len());
    }
    key_lengths.sort_unstable();
    key_lengths.dedup();
    assert_eq!(key_lengths, [0, 1, 32, 33, 64]);
}

#[test]
fn hash_values_match_upstream() {
    let vector = load("hash_values");
    for case in cases(&vector) {
        let value = text(case, "value");
        let preimage = bytes(case, "preimage");
        let (encoded, hashed) = match text(case, "type") {
            "u8" => {
                let v: u8 = value.parse().unwrap();
                (ser_vec(&v, V2), v.hash())
            }
            "u64" => {
                let v: u64 = value.parse().unwrap();
                (ser_vec(&v, V2), v.hash())
            }
            "(u8,u64)" => {
                let [a, b] = fields(value)[..] else {
                    panic!("{value}")
                };
                let v = (a.parse::<u8>().unwrap(), b.parse::<u64>().unwrap());
                (ser_vec(&v, V2), v.hash())
            }
            "(u8,u64,u64)" => {
                let [a, b, c] = fields(value)[..] else {
                    panic!("{value}")
                };
                let v = (
                    a.parse::<u8>().unwrap(),
                    b.parse::<u64>().unwrap(),
                    c.parse::<u64>().unwrap(),
                );
                (ser_vec(&v, V2), v.hash())
            }
            "hash" => {
                let v = Hash::from_hex(value).unwrap();
                (ser_vec(&v, V2), v.hash())
            }
            "(hash,hash)" => {
                let [a, b] = fields(value)[..] else {
                    panic!("{value}")
                };
                let v = (Hash::from_hex(a).unwrap(), Hash::from_hex(b).unwrap());
                (ser_vec(&v, V2), v.hash())
            }
            other => panic!("unhandled type {other}"),
        };
        assert_eq!(encoded, preimage, "{case}");
        assert_eq!(hashed, hash(case, "hash"), "{case}");
    }
}

// Upstream `Hash + Hash` is the hash of the pair; LEPIC exposes it as `(a, b).hash()`.
#[test]
fn hash_operations_match_upstream() {
    let vector = load("hash_operations");
    let expected = &vector["expected"];
    let abc = blake2b_256(b"abc");
    assert_eq!(ZERO_HASH, hash(expected, "zero_hash"));
    assert_eq!((ZERO_HASH, abc).hash(), hash(expected, "zero_plus_abc"));
    assert_eq!(
        abc.to_u64(),
        text(expected, "abc_to_u64").parse::<u64>().unwrap()
    );
}
