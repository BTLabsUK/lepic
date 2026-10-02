//! Binary serialization of the building blocks: integers, length-prefixed bytes, tuples and the
//! protocol version, plus how the reader treats truncated input.

use epic_core::ser::{self, ProtocolVersion, Readable, Writeable, Writer};
use serde::Serialize;

use super::AREA;
use super::fixtures::ser_error_name;
use crate::{Error, Pins, Rendered, hex, render};

/// Writes its bytes with the u64 length prefix of `Writer::write_bytes`.
struct LengthPrefixed(Vec<u8>);

impl Writeable for LengthPrefixed {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        writer.write_bytes(&self.0)
    }
}

#[derive(Serialize)]
struct Encoded {
    r#type: &'static str,
    value: String,
    encoded: String,
}

#[derive(Serialize)]
struct Decoded {
    r#type: &'static str,
    bytes: String,
    outcome: String,
}

#[derive(Serialize)]
struct NoInputs {}

#[derive(Serialize)]
struct Cases<T> {
    cases: Vec<T>,
}

fn encode<T: Writeable>(r#type: &'static str, value: String, thing: &T) -> Result<Encoded, Error> {
    let bytes = ser::ser_vec(thing, ProtocolVersion(2)).map_err(Error::reference(r#type))?;
    Ok(Encoded {
        r#type,
        value,
        encoded: hex(bytes),
    })
}

fn integers() -> Result<Vec<Encoded>, Error> {
    let mut cases = Vec::new();
    for value in [0u8, 1, 0x7f, 0x80, u8::MAX] {
        cases.push(encode("u8", value.to_string(), &value)?);
    }
    for value in [0u16, 1, 0x1234, u16::MAX] {
        cases.push(encode("u16", value.to_string(), &value)?);
    }
    for value in [0u32, 1, 0x1234_5678, u32::MAX] {
        cases.push(encode("u32", value.to_string(), &value)?);
    }
    for value in [0i32, 1, -1, i32::MIN, i32::MAX] {
        cases.push(encode("i32", value.to_string(), &value)?);
    }
    for value in [0u64, 1, 0x0102_0304_0506_0708, (1 << 53) | 1, u64::MAX] {
        cases.push(encode("u64", value.to_string(), &value)?);
    }
    for value in [0i64, 1, -1, i64::MIN, i64::MAX] {
        cases.push(encode("i64", value.to_string(), &value)?);
    }
    Ok(cases)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..=u8::MAX).cycle().take(len).collect()
}

fn length_prefixed() -> Result<Vec<Encoded>, Error> {
    [0usize, 1, 3, 32, 33, 255, 256]
        .into_iter()
        .map(|len| {
            let bytes = pattern(len);
            encode("bytes", hex(&bytes), &LengthPrefixed(bytes))
        })
        .collect()
}

fn composites() -> Result<Vec<Encoded>, Error> {
    Ok(vec![
        encode("(u8,u64)", "(0,7000000)".to_owned(), &(0u8, 7_000_000u64))?,
        encode(
            "(u8,u64,u64)",
            "(2,7000000,1000000)".to_owned(),
            &(2u8, 7_000_000u64, 1_000_000u64),
        )?,
        encode("(u64,u64,u64)", "(1,2,1)".to_owned(), &(1u64, 2u64, 1u64))?,
        encode("protocol_version", "1".to_owned(), &ProtocolVersion(1))?,
        encode("protocol_version", "2".to_owned(), &ProtocolVersion(2))?,
    ])
}

fn decode<T: Readable>(r#type: &'static str, bytes: &[u8]) -> Decoded {
    let outcome = match ser::deserialize::<T>(&mut &bytes[..], ProtocolVersion(2)) {
        Ok(_) => "ok".to_owned(),
        Err(error) => ser_error_name(&error),
    };
    Decoded {
        r#type,
        bytes: hex(bytes),
        outcome,
    }
}

fn truncated_reads() -> Vec<Decoded> {
    vec![
        decode::<u8>("u8", &[]),
        decode::<u16>("u16", &[0x12]),
        decode::<u32>("u32", &[0x12, 0x34, 0x56]),
        decode::<u64>("u64", &[1, 2, 3, 4, 5, 6, 7]),
        decode::<u64>("u64", &[1, 2, 3, 4, 5, 6, 7, 8]),
        decode::<(u8, u64)>("(u8,u64)", &[0, 0, 0, 0, 0, 0, 0, 0]),
    ]
}

pub(super) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    Ok(vec![
        render(
            AREA,
            "ser_integers",
            &pins.node,
            NoInputs {},
            Cases { cases: integers()? },
        )?,
        render(
            AREA,
            "ser_length_prefixed_bytes",
            &pins.node,
            NoInputs {},
            Cases {
                cases: length_prefixed()?,
            },
        )?,
        render(
            AREA,
            "ser_composites",
            &pins.node,
            NoInputs {},
            Cases {
                cases: composites()?,
            },
        )?,
        render(
            AREA,
            "ser_truncated_reads",
            &pins.node,
            NoInputs {},
            Cases {
                cases: truncated_reads(),
            },
        )?,
    ])
}
