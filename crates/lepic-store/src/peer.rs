// SPDX-License-Identifier: Apache-2.0
//! What each peer's own messages showed about the software behind its Epicbox public key, keyed by
//! the key alone, because the relay authenticates the key of a message and never its domain.
//!
//! A row holds only dates and feature bits. It is sealed under the private context key and found
//! by a keyed hash of the key, so the table names no peer: the hash key is its own subkey of the
//! seed, and the hash is authenticated with the sealed bytes, so a row copied under another
//! peer's hash does not open.

use std::fmt;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use jiff::Timestamp;
use zeroize::Zeroizing;

use crate::context::{self, ContextKey, SealFailure};
use crate::encoding::timestamp_to_column;
use crate::error::{Record, StoreError};

pub const PEER_TAG_KEY_LEN: usize = 32;
pub const PEER_TAG_LEN: usize = 32;

/// Domain of the keyed hash that turns a key into the tag its row is stored under.
const TAG_DOMAIN: &[u8] = b"lepic-store peer tag v1";
/// Domain of the associated data a row is sealed with.
const ASSOCIATED_DATA_DOMAIN: &[u8] = b"lepic-store peer compat v1";

/// Version of the record inside the sealed bytes. Later fields go into a new version, so the
/// table needs no migration for them.
const RECORD_V1: u8 = 1;
/// The version 1 record followed by the peer's native seal key. A row without that key is
/// still written as version 1.
const RECORD_V2: u8 = 2;
const HAS_LAST_MARKED: u8 = 1;
const HAS_LAST_UNMARKED: u8 = 1 << 1;
const HAS_FEATURES_AT: u8 = 1 << 2;
const KNOWN_PRESENCE: u8 = HAS_LAST_MARKED | HAS_LAST_UNMARKED | HAS_FEATURES_AT;
/// Version, presence bits, three timestamps, two bit sets.
pub(crate) const RECORD_V1_LEN: usize = 1 + 1 + 3 * 8 + 2 * 4;
/// Version 1 and a 32-byte key.
pub(crate) const RECORD_V2_LEN: usize = RECORD_V1_LEN + 32;

/// The key that peer tags are keyed hashes under.
pub struct PeerTagKey(Zeroizing<[u8; PEER_TAG_KEY_LEN]>);

impl PeerTagKey {
    pub fn from_bytes(bytes: [u8; PEER_TAG_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A key that `fill` writes straight into its own wiped buffer. Fails with the error of
    /// `fill`.
    pub fn filled_by<E>(
        fill: impl FnOnce(&mut [u8; PEER_TAG_KEY_LEN]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut key = Self(Zeroizing::new([0; PEER_TAG_KEY_LEN]));
        fill(&mut key.0)?;
        Ok(key)
    }

    /// The tag the row of the Epicbox key `key` (its key text) is stored under.
    ///
    /// Fails with [`StoreError::Unsealable`] only if the hash refused the key, which a key of
    /// this length never is.
    pub fn tag(&self, key: &str) -> Result<PeerTag, StoreError> {
        let mut mac =
            <Blake2bMac<U32> as KeyInit>::new_from_slice(self.0.as_slice()).map_err(|_| {
                StoreError::Unsealable {
                    record: Record::PeerCompat,
                }
            })?;
        mac.update(TAG_DOMAIN);
        mac.update(key.as_bytes());
        Ok(PeerTag(mac.finalize_fixed().into()))
    }
}

impl fmt::Debug for PeerTagKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerTagKey([redacted])")
    }
}

/// The keyed hash of a peer's Epicbox key that its row is stored under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerTag(pub [u8; PEER_TAG_LEN]);

/// What a peer's own messages over Epicbox showed. Nothing else is kept about a peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerCompat {
    /// The last authenticated message from the key that carried the LEPIC marker, or the last
    /// notice from it this wallet accepted.
    pub last_marked_at: Option<Timestamp>,
    /// The last slate from the key without the marker, or an invoice it sent back unchanged.
    pub last_unmarked_at: Option<Timestamp>,
    /// The feature bits of the latest marked message.
    pub claimed: u32,
    /// The feature bits that actually worked with the key.
    pub works: u32,
    /// When `claimed` was last written from a message that carried feature bits; `None` for a
    /// peer that never sent any.
    pub features_at: Option<Timestamp>,
    /// The X25519 key the latest marked message sealed native slates to, when it claimed them
    /// (RFC 0003 5.15); `None` when that message claimed none or carried no valid key.
    pub native_key: Option<[u8; 32]>,
}

impl PeerCompat {
    /// The newest date of the row, which pruning goes by.
    pub fn last_seen(&self) -> Option<Timestamp> {
        [self.last_marked_at, self.last_unmarked_at, self.features_at]
            .into_iter()
            .flatten()
            .max()
    }
}

pub trait PeerRepository {
    /// Stores what is known of the peer with the Epicbox key `key`, replacing what was stored.
    fn put_peer_compat(&mut self, key: &str, compat: &PeerCompat) -> Result<(), StoreError>;

    fn peer_compat(&self, key: &str) -> Result<Option<PeerCompat>, StoreError>;

    /// Deletes every row whose newest date is before `before`, and returns how many went.
    fn forget_peers(&mut self, before: Timestamp) -> Result<usize, StoreError>;
}

fn put_time(record: &mut Vec<u8>, time: Option<Timestamp>) -> Result<(), StoreError> {
    let nanos = time.map(timestamp_to_column).transpose()?.unwrap_or(0);
    record.extend_from_slice(&nanos.to_be_bytes());
    Ok(())
}

/// The record as it is sealed: version, presence bits, the three dates as big-endian
/// nanoseconds (zero when absent), then `claimed` and `works` big-endian, then in version 2 the
/// native seal key.
pub(crate) fn encode_record(compat: &PeerCompat) -> Result<Vec<u8>, StoreError> {
    let mut presence = 0;
    for (time, bit) in [
        (compat.last_marked_at, HAS_LAST_MARKED),
        (compat.last_unmarked_at, HAS_LAST_UNMARKED),
        (compat.features_at, HAS_FEATURES_AT),
    ] {
        if time.is_some() {
            presence |= bit;
        }
    }
    let mut record = Vec::with_capacity(RECORD_V2_LEN);
    record.push(if compat.native_key.is_some() {
        RECORD_V2
    } else {
        RECORD_V1
    });
    record.push(presence);
    put_time(&mut record, compat.last_marked_at)?;
    put_time(&mut record, compat.last_unmarked_at)?;
    put_time(&mut record, compat.features_at)?;
    record.extend_from_slice(&compat.claimed.to_be_bytes());
    record.extend_from_slice(&compat.works.to_be_bytes());
    if let Some(key) = &compat.native_key {
        record.extend_from_slice(key);
    }
    Ok(record)
}

fn corrupt(field: &'static str) -> StoreError {
    StoreError::Corrupt {
        record: Record::PeerCompat,
        field,
    }
}

fn take<const N: usize>(rest: &mut &[u8], field: &'static str) -> Result<[u8; N], StoreError> {
    let (head, tail) = rest.split_first_chunk::<N>().ok_or(corrupt(field))?;
    *rest = tail;
    Ok(*head)
}

fn take_time(
    rest: &mut &[u8],
    present: bool,
    field: &'static str,
) -> Result<Option<Timestamp>, StoreError> {
    let nanos = i64::from_be_bytes(take::<8>(rest, field)?);
    if !present {
        return if nanos == 0 {
            Ok(None)
        } else {
            Err(corrupt(field))
        };
    }
    Timestamp::from_nanosecond(i128::from(nanos))
        .map(Some)
        .map_err(|_| corrupt(field))
}

pub(crate) fn decode_record(record: &[u8]) -> Result<PeerCompat, StoreError> {
    let mut rest = record;
    let [version] = take::<1>(&mut rest, "record version")?;
    if version != RECORD_V1 && version != RECORD_V2 {
        return Err(corrupt("record version"));
    }
    let [presence] = take::<1>(&mut rest, "presence")?;
    if presence & !KNOWN_PRESENCE != 0 {
        return Err(corrupt("presence"));
    }
    let compat = PeerCompat {
        last_marked_at: take_time(&mut rest, presence & HAS_LAST_MARKED != 0, "last marked at")?,
        last_unmarked_at: take_time(
            &mut rest,
            presence & HAS_LAST_UNMARKED != 0,
            "last unmarked at",
        )?,
        features_at: take_time(&mut rest, presence & HAS_FEATURES_AT != 0, "features at")?,
        claimed: u32::from_be_bytes(take::<4>(&mut rest, "claimed")?),
        works: u32::from_be_bytes(take::<4>(&mut rest, "works")?),
        native_key: if version == RECORD_V2 {
            Some(take::<32>(&mut rest, "native key")?)
        } else {
            None
        },
    };
    if !rest.is_empty() {
        return Err(corrupt("record length"));
    }
    Ok(compat)
}

fn associated_data(tag: &PeerTag) -> Vec<u8> {
    let mut data = Vec::with_capacity(ASSOCIATED_DATA_DOMAIN.len().saturating_add(PEER_TAG_LEN));
    data.extend_from_slice(ASSOCIATED_DATA_DOMAIN);
    data.extend_from_slice(&tag.0);
    data
}

fn sealing_error(failure: SealFailure) -> StoreError {
    let record = Record::PeerCompat;
    match failure {
        SealFailure::Randomness(error) => StoreError::Randomness(error),
        SealFailure::Unsealable => StoreError::Unsealable { record },
        SealFailure::Malformed => corrupt("sealed bytes"),
        SealFailure::Undecryptable => StoreError::Undecryptable { record },
    }
}

pub(crate) fn seal(
    key: &ContextKey,
    tag: &PeerTag,
    compat: &PeerCompat,
) -> Result<Vec<u8>, StoreError> {
    context::seal_bytes(key, &associated_data(tag), &encode_record(compat)?).map_err(sealing_error)
}

pub(crate) fn open(
    key: &ContextKey,
    tag: &PeerTag,
    sealed: &[u8],
) -> Result<PeerCompat, StoreError> {
    let record = context::open_bytes(key, &associated_data(tag), sealed).map_err(sealing_error)?;
    decode_record(&record)
}

/// The pure steps of a row, for the golden vectors: the record bytes, a seal with a given nonce,
/// and opening sealed bytes.
#[doc(hidden)]
pub mod vectors {
    use super::{ContextKey, PeerCompat, PeerTag, StoreError, associated_data, sealing_error};

    pub fn record(compat: &PeerCompat) -> Result<Vec<u8>, StoreError> {
        super::encode_record(compat)
    }

    pub fn seal_with_nonce(
        key: &ContextKey,
        tag: &PeerTag,
        compat: &PeerCompat,
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, StoreError> {
        crate::context::seal_bytes_with_nonce(
            key,
            &associated_data(tag),
            &super::encode_record(compat)?,
            nonce,
        )
        .map_err(sealing_error)
    }

    pub fn open(key: &ContextKey, tag: &PeerTag, sealed: &[u8]) -> Result<PeerCompat, StoreError> {
        super::open(key, tag, sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(second).unwrap()
    }

    fn full() -> PeerCompat {
        PeerCompat {
            last_marked_at: Some(at(1_790_000_000)),
            last_unmarked_at: Some(at(1_790_000_100)),
            claimed: 0b111,
            works: 0b1,
            features_at: Some(at(1_790_000_000)),
            native_key: None,
        }
    }

    fn native() -> PeerCompat {
        PeerCompat {
            native_key: Some([9; 32]),
            ..full()
        }
    }

    #[test]
    fn records_round_trip_with_and_without_dates() {
        for compat in [PeerCompat::default(), full()] {
            let record = encode_record(&compat).unwrap();
            assert_eq!(record.len(), RECORD_V1_LEN);
            assert_eq!(decode_record(&record).unwrap(), compat);
        }
        let record = encode_record(&native()).unwrap();
        assert_eq!((record[0], record.len()), (RECORD_V2, RECORD_V2_LEN));
        assert_eq!(
            record[..RECORD_V1_LEN][1..],
            encode_record(&full()).unwrap()[1..]
        );
        assert_eq!(decode_record(&record).unwrap(), native());
    }

    #[test]
    fn rejects_records_of_another_version_length_or_presence() {
        let record = encode_record(&full()).unwrap();
        let mut other_version = record.clone();
        other_version[0] = 3;
        let mut short_key = encode_record(&native()).unwrap();
        short_key.pop();
        let mut no_key = record.clone();
        no_key[0] = RECORD_V2;
        let mut unknown_presence = record.clone();
        unknown_presence[1] |= 1 << 3;
        let mut absent_but_set = encode_record(&PeerCompat::default()).unwrap();
        absent_but_set[9] = 1;
        let mut longer = record.clone();
        longer.push(0);
        for bad in [
            other_version,
            unknown_presence,
            absent_but_set,
            longer,
            short_key,
            no_key,
            record[..record.len() - 1].to_vec(),
            Vec::new(),
        ] {
            assert!(
                matches!(
                    decode_record(&bad),
                    Err(StoreError::Corrupt {
                        record: Record::PeerCompat,
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_row_opens_only_under_its_own_tag_and_key() {
        let key = ContextKey::from_bytes([1; 32]);
        let tags = PeerTagKey::from_bytes([2; 32]);
        let tag = tags.tag("alice").unwrap();
        let sealed = seal(&key, &tag, &full()).unwrap();
        assert_eq!(open(&key, &tag, &sealed).unwrap(), full());
        assert!(matches!(
            open(&key, &tags.tag("bob").unwrap(), &sealed),
            Err(StoreError::Undecryptable { .. })
        ));
        assert!(matches!(
            open(&ContextKey::from_bytes([3; 32]), &tag, &sealed),
            Err(StoreError::Undecryptable { .. })
        ));
    }

    #[test]
    fn tags_depend_on_the_key_and_the_tag_key() {
        let tags = PeerTagKey::from_bytes([2; 32]);
        let tag = |tags: &PeerTagKey, key| tags.tag(key).unwrap();
        assert_eq!(tag(&tags, "alice"), tag(&tags, "alice"));
        assert_ne!(tag(&tags, "alice"), tag(&tags, "bob"));
        assert_ne!(
            tag(&tags, "alice"),
            tag(&PeerTagKey::from_bytes([3; 32]), "alice")
        );
    }

    #[test]
    fn last_seen_is_the_newest_date() {
        assert_eq!(PeerCompat::default().last_seen(), None);
        assert_eq!(full().last_seen(), Some(at(1_790_000_100)));
    }
}
