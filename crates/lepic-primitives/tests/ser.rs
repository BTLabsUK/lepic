// SPDX-License-Identifier: Apache-2.0
use lepic_primitives::ser::{
    MAX_MULTI_COUNT, MAX_READ_LEN, ProtocolVersion, Readable, Reader, SerError, SerializationMode,
    VecWriter, Writeable, Writer, deserialize, ser_vec,
};
use proptest::prelude::*;

const V2: ProtocolVersion = ProtocolVersion::V2;

fn round_trip<T: Readable + Writeable + PartialEq + std::fmt::Debug>(value: &T) {
    let bytes = ser_vec(value, V2);
    assert_eq!(deserialize::<T>(&bytes, V2).as_ref(), Ok(value));
}

/// Every strict prefix of a valid encoding must fail as truncated.
fn assert_prefixes_truncated<T: Readable + std::fmt::Debug>(bytes: &[u8]) {
    let mut prefix = bytes;
    while let Some((_, shorter)) = prefix.split_last() {
        prefix = shorter;
        let result = deserialize::<T>(prefix, V2);
        assert!(
            matches!(result, Err(SerError::Truncated { .. })),
            "prefix of {} bytes gave {result:?}",
            prefix.len()
        );
    }
}

#[test]
fn integers_are_big_endian() {
    assert_eq!(ser_vec(&0x0102_u16, V2), [1, 2]);
    assert_eq!(ser_vec(&0x0102_0304_u32, V2), [1, 2, 3, 4]);
    assert_eq!(ser_vec(&-2_i32, V2), [0xff, 0xff, 0xff, 0xfe]);
    assert_eq!(
        ser_vec(&0x0102_0304_0506_0708_u64, V2),
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(ser_vec(&-1_i64, V2), [0xff; 8]);
}

#[test]
fn write_bytes_prefixes_a_u64_length() {
    let mut writer = VecWriter::new(V2);
    writer.write_bytes(b"abc");
    assert_eq!(
        writer.into_bytes(),
        [0, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']
    );
}

#[test]
fn sequences_write_items_without_a_count() {
    assert_eq!(ser_vec(&vec![1_u8, 2, 3], V2), [1, 2, 3]);
    assert_eq!(ser_vec(&(1_u8, 2_u16), V2), [1, 0, 2]);
}

#[test]
fn vec_writer_reports_full_mode_and_its_version() {
    let writer = VecWriter::new(ProtocolVersion::V1);
    assert_eq!(writer.serialization_mode(), SerializationMode::Full);
    assert_eq!(writer.protocol_version(), ProtocolVersion::V1);
}

#[test]
fn reader_carries_its_protocol_version() {
    let reader = Reader::new(&[], ProtocolVersion::new(7));
    assert_eq!(reader.protocol_version().value(), 7);
}

#[test]
fn rejects_truncated_integers() {
    assert_prefixes_truncated::<u16>(&ser_vec(&u16::MAX, V2));
    assert_prefixes_truncated::<u32>(&ser_vec(&u32::MAX, V2));
    assert_prefixes_truncated::<i32>(&ser_vec(&i32::MIN, V2));
    assert_prefixes_truncated::<u64>(&ser_vec(&u64::MAX, V2));
    assert_prefixes_truncated::<i64>(&ser_vec(&i64::MIN, V2));
    assert_eq!(
        deserialize::<u8>(&[], V2),
        Err(SerError::Truncated {
            needed: 1,
            available: 0
        })
    );
}

#[test]
fn rejects_trailing_bytes() {
    assert_eq!(
        deserialize::<u16>(&[0, 1, 2], V2),
        Err(SerError::TrailingBytes { remaining: 1 })
    );
    assert_eq!(
        deserialize::<(u8, u8)>(&[0, 1, 2, 3], V2),
        Err(SerError::TrailingBytes { remaining: 2 })
    );
}

#[test]
fn rejects_length_prefix_over_the_caller_maximum() {
    let mut writer = VecWriter::new(V2);
    writer.write_bytes(&[7; 5]);
    let bytes = writer.into_bytes();
    let mut reader = Reader::new(&bytes, V2);
    assert_eq!(
        reader.read_bytes_len_prefix(4),
        Err(SerError::TooLarge { len: 5, max: 4 })
    );
}

#[test]
fn rejects_length_prefix_over_the_node_read_limit() {
    let len = u64::try_from(MAX_READ_LEN).unwrap().checked_add(1).unwrap();
    let bytes = ser_vec(&len, V2);
    let mut reader = Reader::new(&bytes, V2);
    assert_eq!(
        reader.read_bytes_len_prefix(usize::MAX),
        Err(SerError::TooLarge {
            len,
            max: MAX_READ_LEN
        })
    );
}

#[test]
fn rejects_huge_length_prefix_without_allocating() {
    let bytes = ser_vec(&u64::MAX, V2);
    let mut reader = Reader::new(&bytes, V2);
    assert_eq!(
        reader.read_bytes_len_prefix(64),
        Err(SerError::TooLarge {
            len: u64::MAX,
            max: 64
        })
    );
}

#[test]
fn rejects_length_prefix_beyond_the_input() {
    let mut bytes = ser_vec(&10_u64, V2);
    bytes.extend_from_slice(&[1, 2, 3]);
    let mut reader = Reader::new(&bytes, V2);
    assert_eq!(
        reader.read_bytes_len_prefix(64),
        Err(SerError::Truncated {
            needed: 10,
            available: 3
        })
    );
}

#[test]
fn reads_length_prefixed_bytes_at_the_maximum() {
    let mut writer = VecWriter::new(V2);
    writer.write_bytes(&[9; 4]);
    let bytes = writer.into_bytes();
    let mut reader = Reader::new(&bytes, V2);
    assert_eq!(reader.read_bytes_len_prefix(4), Ok(&[9_u8; 4][..]));
    assert_eq!(reader.finish(), Ok(()));
}

#[test]
fn rejects_fixed_read_over_the_node_read_limit() {
    let mut reader = Reader::new(&[], V2);
    assert!(matches!(
        reader.read_fixed_bytes(MAX_READ_LEN.checked_add(1).unwrap()),
        Err(SerError::TooLarge { .. })
    ));
}

#[test]
fn rejects_unexpected_byte() {
    let mut reader = Reader::new(&[3], V2);
    assert_eq!(
        reader.expect_u8(4),
        Err(SerError::UnexpectedByte {
            expected: 4,
            found: 3
        })
    );
    let mut reader = Reader::new(&[4], V2);
    assert_eq!(reader.expect_u8(4), Ok(()));
}

#[test]
fn rejects_multi_count_over_the_caller_maximum() {
    let bytes = [0_u8; 16];
    let mut reader = Reader::new(&bytes, V2);
    assert_eq!(
        reader.read_multi::<u8>(3, 2),
        Err(SerError::TooLarge { len: 3, max: 2 })
    );
}

#[test]
fn rejects_multi_count_over_the_node_limit() {
    let mut reader = Reader::new(&[], V2);
    let count = u64::try_from(MAX_MULTI_COUNT)
        .unwrap()
        .checked_add(1)
        .unwrap();
    assert_eq!(
        reader.read_multi::<u8>(count, usize::MAX),
        Err(SerError::TooLarge {
            len: count,
            max: MAX_MULTI_COUNT
        })
    );
}

#[test]
fn rejects_multi_count_beyond_the_input_before_allocating() {
    let mut reader = Reader::new(&[1, 2], V2);
    assert_eq!(
        reader.read_multi::<u64>(3, 1000),
        Err(SerError::Truncated {
            needed: 3,
            available: 2
        })
    );
}

#[test]
fn rejects_multi_with_truncated_item() {
    let bytes = [0_u8; 15];
    let mut reader = Reader::new(&bytes, V2);
    assert!(matches!(
        reader.read_multi::<u64>(2, 10),
        Err(SerError::Truncated { .. })
    ));
}

#[test]
fn ser_error_display_is_lowercase_without_period() {
    let message = SerError::TrailingBytes { remaining: 2 }.to_string();
    assert_eq!(message, "2 trailing bytes after the value");
}

proptest! {
    #[test]
    fn integers_round_trip(a: u8, b: u16, c: u32, d: i32, e: u64, f: i64) {
        round_trip(&a);
        round_trip(&b);
        round_trip(&c);
        round_trip(&d);
        round_trip(&e);
        round_trip(&f);
    }

    #[test]
    fn tuples_round_trip(a: u8, b: u64, c: i32, d: u16) {
        round_trip(&(a, b));
        round_trip(&(a, b, c));
        round_trip(&(a, b, c, d));
    }

    #[test]
    fn tuples_reject_every_truncation(a: u8, b: u64, c: i32, d: u16) {
        assert_prefixes_truncated::<(u8, u64, i32, u16)>(&ser_vec(&(a, b, c, d), V2));
    }

    #[test]
    fn protocol_version_round_trips(value: u32) {
        let version = ProtocolVersion::new(value);
        round_trip(&version);
        prop_assert_eq!(ser_vec(&version, V2), value.to_be_bytes());
    }

    #[test]
    fn length_prefixed_bytes_round_trip(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut writer = VecWriter::new(V2);
        writer.write_bytes(&data);
        let bytes = writer.into_bytes();
        let mut reader = Reader::new(&bytes, V2);
        prop_assert_eq!(reader.read_bytes_len_prefix(512), Ok(data.as_slice()));
        prop_assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn multi_round_trips(items in proptest::collection::vec(any::<u64>(), 0..64)) {
        let bytes = ser_vec(&items, V2);
        let mut reader = Reader::new(&bytes, V2);
        let count = u64::try_from(items.len()).unwrap();
        prop_assert_eq!(reader.read_multi::<u64>(count, 64), Ok(items));
        prop_assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn arbitrary_input_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = deserialize::<(u64, i32, u16, u8)>(&data, V2);
        let mut reader = Reader::new(&data, V2);
        let _ = reader.read_bytes_len_prefix(usize::MAX);
        let mut reader = Reader::new(&data, V2);
        if let Ok(count) = reader.read_u64() {
            let _ = reader.read_multi::<u32>(count, usize::MAX);
        }
    }
}
