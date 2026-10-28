use lepic_primitives::hash::{
    Hash, HashError, HashWriter, Hashed, MAX_KEY_LEN, ZERO_HASH, blake2b_256, blake2b_256_keyed,
};
use lepic_primitives::ser::{
    ProtocolVersion, SerError, SerializationMode, Writeable, Writer, deserialize, ser_vec,
};
use proptest::prelude::*;

const V2: ProtocolVersion = ProtocolVersion::V2;

// Published BLAKE2b-256 digests of "" and "abc", also produced by coreutils `b2sum -l 256`.
const EMPTY_DIGEST: &str = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
const ABC_DIGEST: &str = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";

#[test]
fn unkeyed_blake2b_256_matches_known_answers() {
    assert_eq!(blake2b_256(b"").to_hex(), EMPTY_DIGEST);
    assert_eq!(blake2b_256(b"abc").to_hex(), ABC_DIGEST);
}

#[test]
fn empty_key_gives_the_unkeyed_hash() {
    assert_eq!(blake2b_256_keyed(&[], b"abc"), Ok(blake2b_256(b"abc")));
}

#[test]
fn key_changes_the_hash() {
    let keyed = blake2b_256_keyed(&[1; 33], b"abc").unwrap();
    assert_ne!(keyed, blake2b_256(b"abc"));
    assert_ne!(keyed, blake2b_256_keyed(&[2; 33], b"abc").unwrap());
}

#[test]
fn accepts_key_of_maximum_length() {
    assert!(blake2b_256_keyed(&[5; MAX_KEY_LEN], b"abc").is_ok());
}

#[test]
fn rejects_key_longer_than_64_bytes() {
    assert_eq!(
        blake2b_256_keyed(&[0; 65], b"abc"),
        Err(HashError::KeyTooLong { len: 65 })
    );
}

#[test]
fn hash_of_a_value_is_blake2b_of_its_encoding() {
    let value = (7_u64, 9_u8);
    assert_eq!(value.hash(), blake2b_256(&ser_vec(&value, V2)));
    assert_eq!(vec![1_u8, 2, 3].hash(), blake2b_256(&[1, 2, 3]));
}

#[test]
fn hash_writer_uses_hash_mode_and_the_node_local_version() {
    let writer = HashWriter::new();
    assert_eq!(writer.serialization_mode(), SerializationMode::Hash);
    assert_eq!(writer.protocol_version(), ProtocolVersion::V2);
}

#[test]
fn hash_writer_of_nothing_is_the_empty_digest() {
    assert_eq!(HashWriter::new().into_hash().to_hex(), EMPTY_DIGEST);
}

#[test]
fn zero_hash_is_the_default_and_all_zero() {
    assert_eq!(Hash::default(), ZERO_HASH);
    assert_eq!(ZERO_HASH.as_bytes(), &[0; 32]);
}

#[test]
fn to_u64_reads_the_first_eight_bytes_big_endian() {
    let mut bytes = [0xff; 32];
    bytes[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Hash::from_bytes(bytes).to_u64(), 0x0102_0304_0506_0708);
}

#[test]
fn display_is_full_hex_and_debug_is_short() {
    let hash = blake2b_256(b"abc");
    assert_eq!(hash.to_string(), ABC_DIGEST);
    assert_eq!(format!("{hash:?}"), ABC_DIGEST[..12]);
}

#[test]
fn from_hex_accepts_uppercase() {
    let hash = Hash::from_hex(&ABC_DIGEST.to_uppercase()).unwrap();
    assert_eq!(hash.to_hex(), ABC_DIGEST);
}

#[test]
fn rejects_hex_of_wrong_length() {
    assert_eq!(
        Hash::from_hex(&ABC_DIGEST[..62]),
        Err(HashError::InvalidHexLength { len: 62 })
    );
    assert_eq!(
        Hash::from_hex(&format!("{ABC_DIGEST}00")),
        Err(HashError::InvalidHexLength { len: 66 })
    );
}

#[test]
fn rejects_non_hex_digits() {
    let mut hex = ABC_DIGEST.to_owned();
    hex.replace_range(10..11, "g");
    assert_eq!(
        Hash::from_hex(&hex),
        Err(HashError::InvalidHexDigit { byte: 5 })
    );
}

#[test]
fn rejects_multibyte_characters_in_hex() {
    let hex = format!("é{}", &ABC_DIGEST[2..]);
    assert_eq!(
        Hash::from_hex(&hex),
        Err(HashError::InvalidHexDigit { byte: 0 })
    );
}

#[test]
fn rejects_slice_of_wrong_length() {
    assert_eq!(
        Hash::from_slice(&[0; 31]),
        Err(HashError::InvalidLength { len: 31 })
    );
    assert_eq!(
        Hash::from_slice(&[0; 33]),
        Err(HashError::InvalidLength { len: 33 })
    );
}

#[test]
fn rejects_truncated_and_trailing_hash_encoding() {
    let bytes = ser_vec(&blake2b_256(b"abc"), V2);
    for len in 0..bytes.len() {
        assert!(matches!(
            deserialize::<Hash>(&bytes[..len], V2),
            Err(SerError::Truncated { .. })
        ));
    }
    let mut long = bytes;
    long.push(0);
    assert_eq!(
        deserialize::<Hash>(&long, V2),
        Err(SerError::TrailingBytes { remaining: 1 })
    );
}

proptest! {
    #[test]
    fn hash_round_trips_through_bytes_and_hex(bytes: [u8; 32]) {
        let hash = Hash::from_bytes(bytes);
        let encoded = ser_vec(&hash, V2);
        prop_assert_eq!(&encoded, &bytes);
        prop_assert_eq!(deserialize::<Hash>(&encoded, V2), Ok(hash));
        prop_assert_eq!(Hash::from_hex(&hash.to_hex()), Ok(hash));
        prop_assert_eq!(Hash::from_slice(&bytes), Ok(hash));
    }

    #[test]
    fn hash_of_a_hash_is_blake2b_of_its_bytes(bytes: [u8; 32]) {
        let hash = Hash::from_bytes(bytes);
        prop_assert_eq!(hash.hash(), blake2b_256(&bytes));
    }

    #[test]
    fn hash_writer_equals_one_shot_hash(chunks in proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 0..200), 0..8)
    ) {
        let mut writer = HashWriter::new();
        let mut all = Vec::new();
        for chunk in &chunks {
            writer.write_fixed_bytes(chunk);
            all.extend_from_slice(chunk);
        }
        prop_assert_eq!(writer.into_hash(), blake2b_256(&all));
    }

    #[test]
    fn from_hex_never_panics(text in ".{0,80}") {
        let _ = Hash::from_hex(&text);
    }

    #[test]
    fn written_value_hashes_equal_whatever_the_wrapping(a: u64, b: u8) {
        let mut writer = HashWriter::new();
        (&a, &b).write(&mut writer);
        prop_assert_eq!(writer.into_hash(), (a, b).hash());
    }
}
