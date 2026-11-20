// SPDX-License-Identifier: Apache-2.0
//! Hex decoding that reports failures as [`CryptoError`] for the item being decoded.

use zeroize::Zeroize;

use crate::error::{CryptoError, Item};
use crate::hex::{self, HexError};

/// Decodes hex of exactly `N` bytes. Upper and lower case digits are accepted.
pub(crate) fn decode_array<const N: usize>(hex: &str, item: Item) -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    if let Err(error) = decode_into(hex, &mut out, item) {
        out.zeroize();
        return Err(error);
    }
    Ok(out)
}

/// Decodes hex of `min` to `max` bytes, checking the length before allocating.
pub(crate) fn decode_bounded(
    hex: &str,
    min: usize,
    max: usize,
    item: Item,
) -> Result<Vec<u8>, CryptoError> {
    hex::decode_bounded(hex, min, max).map_err(|error| match error {
        HexError::LengthOutOfRange { actual, .. } if (min..=max).contains(&actual.div_ceil(2)) => {
            CryptoError::InvalidHex { item }
        }
        HexError::LengthOutOfRange { actual, .. } => CryptoError::LengthOutOfRange {
            item,
            min,
            max,
            actual: actual.div_ceil(2),
        },
        other => item_error(other, item),
    })
}

/// Decodes hex of exactly `out.len()` bytes into `out`, so a secret can be decoded straight into
/// memory that is wiped. On error `out` may hold part of the input.
pub(crate) fn decode_into(hex: &str, out: &mut [u8], item: Item) -> Result<(), CryptoError> {
    hex::decode_into(hex, out).map_err(|error| item_error(error, item))
}

fn item_error(error: HexError, item: Item) -> CryptoError {
    match error {
        HexError::WrongLength { expected, actual } if actual.is_multiple_of(2) => {
            CryptoError::WrongLength {
                item,
                expected: expected / 2,
                actual: actual / 2,
            }
        }
        HexError::WrongLength { .. } | HexError::OddLength | HexError::InvalidDigit { .. } => {
            CryptoError::InvalidHex { item }
        }
        HexError::LengthOutOfRange { min, max, actual } => CryptoError::LengthOutOfRange {
            item,
            min: min / 2,
            max: max / 2,
            actual: actual.div_ceil(2),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_either_case() {
        assert_eq!(decode_array::<2>("0aFF", Item::Message), Ok([0x0a, 0xff]));
    }

    #[test]
    fn rejects_odd_length_hex() {
        assert_eq!(
            decode_array::<2>("abc", Item::Message),
            Err(CryptoError::InvalidHex {
                item: Item::Message
            })
        );
    }

    #[test]
    fn rejects_non_hex_digits() {
        assert_eq!(
            decode_array::<2>("zz00", Item::Message),
            Err(CryptoError::InvalidHex {
                item: Item::Message
            })
        );
        assert_eq!(
            decode_array::<1>("0x", Item::Message),
            Err(CryptoError::InvalidHex {
                item: Item::Message
            })
        );
    }

    #[test]
    fn rejects_hex_of_the_wrong_length() {
        assert_eq!(
            decode_array::<2>("00", Item::Message),
            Err(CryptoError::WrongLength {
                item: Item::Message,
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn rejects_bounded_hex_over_the_limit_before_decoding() {
        assert_eq!(
            decode_bounded(&"0".repeat(10), 1, 4, Item::RangeProof),
            Err(CryptoError::LengthOutOfRange {
                item: Item::RangeProof,
                min: 1,
                max: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn rejects_odd_bounded_hex_just_under_the_minimum_as_invalid_hex() {
        assert_eq!(
            decode_bounded("abc", 2, 4, Item::RangeProof),
            Err(CryptoError::InvalidHex {
                item: Item::RangeProof
            })
        );
    }
}
