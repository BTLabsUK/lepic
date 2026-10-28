//! Hex text to bytes and back, shared by every core crate so they all apply the same rules.
//!
//! Decoding accepts upper and lower case digits and no prefix. Lengths in [`HexError`] count hex
//! digits, not bytes.

use thiserror::Error;

/// Hex text that does not decode to the expected bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HexError {
    #[error("expected {expected} hex digits, found {actual}")]
    WrongLength { expected: usize, actual: usize },
    #[error("expected between {min} and {max} hex digits, found {actual}")]
    LengthOutOfRange {
        min: usize,
        max: usize,
        actual: usize,
    },
    #[error("hex text has an odd number of digits")]
    OddLength,
    #[error("hex text contains a character that is not a hex digit (byte {byte})")]
    InvalidDigit {
        /// Index of the byte the offending digit belongs to.
        byte: usize,
    },
}

/// Lowercase hex, as upstream writes it.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for value in [byte.wrapping_shr(4), byte & 0x0f] {
            if let Some(digit) = DIGITS.get(usize::from(value)) {
                out.push(char::from(*digit));
            }
        }
    }
    out
}

/// Decodes exactly `2 * out.len()` digits into `out`, so a secret can be decoded straight into
/// memory that is wiped. On error `out` may hold part of the input.
pub fn decode_into(hex: &str, out: &mut [u8]) -> Result<(), HexError> {
    let digits = hex.as_bytes();
    let expected = out.len().saturating_mul(2);
    if digits.len() != expected {
        return Err(HexError::WrongLength {
            expected,
            actual: digits.len(),
        });
    }
    decode_pairs(digits, out)
}

/// Decodes exactly `2 * N` digits.
pub fn decode_array<const N: usize>(hex: &str) -> Result<[u8; N], HexError> {
    let mut out = [0u8; N];
    decode_into(hex, &mut out)?;
    Ok(out)
}

/// Decodes `min_bytes` to `max_bytes` bytes of hex, checking the length before allocating.
pub fn decode_bounded(hex: &str, min_bytes: usize, max_bytes: usize) -> Result<Vec<u8>, HexError> {
    let digits = hex.as_bytes();
    let (min, max) = (min_bytes.saturating_mul(2), max_bytes.saturating_mul(2));
    if digits.len() < min || digits.len() > max {
        return Err(HexError::LengthOutOfRange {
            min,
            max,
            actual: digits.len(),
        });
    }
    if !digits.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = vec![0u8; digits.len() / 2];
    decode_pairs(digits, &mut out)?;
    Ok(out)
}

fn decode_pairs(digits: &[u8], out: &mut [u8]) -> Result<(), HexError> {
    let (pairs, _) = digits.as_chunks::<2>();
    for (index, (byte, [high, low])) in out.iter_mut().zip(pairs).enumerate() {
        let invalid = HexError::InvalidDigit { byte: index };
        let high = nibble(*high).ok_or(invalid)?;
        let low = nibble(*low).ok_or(invalid)?;
        *byte = high.wrapping_shl(4) | low;
    }
    Ok(())
}

fn nibble(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bytes_through_hex() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(decode_array::<4>("000fa5ff"), Ok(bytes));
        assert_eq!(decode_array::<4>("000FA5FF"), Ok(bytes));
    }

    #[test]
    fn rejects_wrong_length_including_odd_length() {
        assert_eq!(
            decode_array::<2>("abc"),
            Err(HexError::WrongLength {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            decode_array::<2>("00"),
            Err(HexError::WrongLength {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn reports_the_byte_holding_the_first_bad_digit() {
        assert_eq!(
            decode_array::<2>("00zz"),
            Err(HexError::InvalidDigit { byte: 1 })
        );
        assert_eq!(
            decode_array::<1>("0x"),
            Err(HexError::InvalidDigit { byte: 0 })
        );
    }

    #[test]
    fn rejects_bounded_hex_outside_the_limits_before_decoding() {
        assert_eq!(
            decode_bounded(&"0".repeat(10), 1, 4),
            Err(HexError::LengthOutOfRange {
                min: 2,
                max: 8,
                actual: 10
            })
        );
        assert_eq!(
            decode_bounded("", 1, 4),
            Err(HexError::LengthOutOfRange {
                min: 2,
                max: 8,
                actual: 0
            })
        );
    }

    #[test]
    fn rejects_odd_bounded_hex_inside_the_limits() {
        assert_eq!(decode_bounded("abc", 1, 4), Err(HexError::OddLength));
    }

    #[test]
    fn decodes_bounded_hex() {
        assert_eq!(decode_bounded("0aFF", 1, 4), Ok(vec![0x0a, 0xff]));
    }
}
