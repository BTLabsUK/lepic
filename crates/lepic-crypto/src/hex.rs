use zeroize::Zeroize;

use crate::error::{CryptoError, Item};

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
    let actual = hex.len().div_ceil(2);
    if actual < min || actual > max {
        return Err(CryptoError::LengthOutOfRange {
            item,
            min,
            max,
            actual,
        });
    }
    let mut out = vec![0u8; actual];
    decode_into(hex, &mut out, item)?;
    Ok(out)
}

fn decode_into(hex: &str, out: &mut [u8], item: Item) -> Result<(), CryptoError> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return Err(CryptoError::InvalidHex { item });
    }
    let actual = digits.len() / 2;
    if actual != out.len() {
        return Err(CryptoError::WrongLength {
            item,
            expected: out.len(),
            actual,
        });
    }
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = nibble(*high, item)?.wrapping_shl(4) | nibble(*low, item)?;
    }
    Ok(())
}

fn nibble(digit: u8, item: Item) -> Result<u8, CryptoError> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(CryptoError::InvalidHex { item })
}

/// Lowercase hex, as upstream writes it.
pub(crate) fn encode(bytes: &[u8]) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bytes_through_hex() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        let hex = encode(&bytes);
        assert_eq!(hex, "000fa5ff");
        assert_eq!(decode_array::<4>(&hex, Item::Message), Ok(bytes));
        assert_eq!(decode_array::<4>("000FA5FF", Item::Message), Ok(bytes));
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
}
