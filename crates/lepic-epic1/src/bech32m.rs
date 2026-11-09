// SPDX-License-Identifier: Apache-2.0
//! bech32m (BIP 350), written for this crate: lower case only, no 90-character cap.
//!
//! The segwit cap of BIP 173 does not apply to an epic1 (115 or 116 characters); this module
//! bounds the whole string by [`MAX_LEN`] instead.

use thiserror::Error;

/// The checksum constant of bech32m.
const CHECKSUM_CONSTANT: u32 = 0x2bc8_30a3;
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
const CHECKSUM_LEN: usize = 6;
const SEPARATOR: u8 = b'1';

/// Longest text this crate encodes or decodes. An epic1 is 116 characters at most.
pub const MAX_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Bech32Error {
    #[error("text has {len} characters, the limit is {max}")]
    TooLong { len: usize, max: usize },
    #[error("text has a character outside the printable ASCII range")]
    InvalidCharacter,
    #[error("text mixes upper and lower case")]
    MixedCase,
    #[error("text is in upper case; only lower case is read")]
    UpperCase,
    #[error("text has no separator, or an empty human-readable part")]
    MissingSeparator,
    #[error("data part is shorter than the checksum")]
    TooShort,
    #[error("data part has a character outside the bech32 alphabet")]
    InvalidDataCharacter,
    #[error("checksum does not match")]
    Checksum,
    #[error("data padding is longer than four bits or not zero")]
    Padding,
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut checksum: u32 = 1;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn checksum_input<'a>(hrp: &'a [u8], data: &'a [u8]) -> impl Iterator<Item = u8> + 'a {
    hrp.iter()
        .map(|byte| byte >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.iter().map(|byte| byte & 0x1f))
        .chain(data.iter().copied())
}

/// Regroups `data` from `from`-bit to `to`-bit values. `pad` adds the final partial group
/// (encoding); without it, leftover bits must be fewer than `from` and zero (decoding).
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, Bech32Error> {
    let max_value: u32 = 1u32.wrapping_shl(to).wrapping_sub(1);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(
        data.len()
            .saturating_mul(8)
            .checked_div(to as usize)
            .unwrap_or(0)
            .saturating_add(1),
    );
    for &value in data {
        accumulator = ((accumulator << from) | u32::from(value)) & 0x0fff_ffff;
        bits = bits.saturating_add(from);
        while bits >= to {
            bits = bits.saturating_sub(to);
            out.push(
                u8::try_from((accumulator >> bits) & max_value)
                    .map_err(|_| Bech32Error::Padding)?,
            );
        }
    }
    if pad {
        if bits > 0 {
            let last = (accumulator << to.saturating_sub(bits)) & max_value;
            out.push(u8::try_from(last).map_err(|_| Bech32Error::Padding)?);
        }
    } else if bits >= from || (accumulator << to.saturating_sub(bits)) & max_value != 0 {
        return Err(Bech32Error::Padding);
    }
    Ok(out)
}

/// `hrp`, `1`, `data` and the checksum, in lower case. `hrp` must be lower-case printable
/// ASCII; the caller passes constants.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    if hrp.is_empty()
        || !hrp
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && !byte.is_ascii_uppercase())
    {
        return Err(Bech32Error::InvalidCharacter);
    }
    let groups = convert_bits(data, 8, 5, true)?;
    let mut values = groups.clone();
    values.extend_from_slice(&[0; CHECKSUM_LEN]);
    let polymod = polymod(checksum_input(hrp.as_bytes(), &values)) ^ CHECKSUM_CONSTANT;
    let mut out = String::with_capacity(
        hrp.len()
            .saturating_add(1)
            .saturating_add(groups.len())
            .saturating_add(CHECKSUM_LEN),
    );
    out.push_str(hrp);
    out.push(char::from(SEPARATOR));
    for group in &groups {
        out.push(symbol(*group));
    }
    for index in 0..CHECKSUM_LEN {
        let shift = 5u32.saturating_mul(
            u32::try_from(CHECKSUM_LEN.saturating_sub(1).saturating_sub(index)).unwrap_or(0),
        );
        out.push(symbol(u8::try_from((polymod >> shift) & 0x1f).unwrap_or(0)));
    }
    if out.len() > MAX_LEN {
        return Err(Bech32Error::TooLong {
            len: out.len(),
            max: MAX_LEN,
        });
    }
    Ok(out)
}

fn symbol(group: u8) -> char {
    CHARSET
        .get(usize::from(group))
        .copied()
        .map_or('q', char::from)
}

/// The human-readable part and the data bytes of a lower-case bech32m string whose checksum
/// holds. Mixed case, upper case and a bad checksum are refused.
pub fn decode(text: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    if text.len() > MAX_LEN {
        return Err(Bech32Error::TooLong {
            len: text.len(),
            max: MAX_LEN,
        });
    }
    let bytes = text.as_bytes();
    if !bytes.iter().all(|byte| (33..=126).contains(byte)) {
        return Err(Bech32Error::InvalidCharacter);
    }
    let has_upper = bytes.iter().any(u8::is_ascii_uppercase);
    let has_lower = bytes.iter().any(u8::is_ascii_lowercase);
    if has_upper && has_lower {
        return Err(Bech32Error::MixedCase);
    }
    if has_upper {
        return Err(Bech32Error::UpperCase);
    }
    let separator = bytes
        .iter()
        .rposition(|byte| *byte == SEPARATOR)
        .filter(|position| *position > 0)
        .ok_or(Bech32Error::MissingSeparator)?;
    let (hrp, rest) = bytes.split_at(separator);
    let data_part = rest.get(1..).unwrap_or_default();
    if data_part.len() < CHECKSUM_LEN {
        return Err(Bech32Error::TooShort);
    }
    let mut values = Vec::with_capacity(data_part.len());
    for byte in data_part {
        let position = CHARSET
            .iter()
            .position(|symbol| symbol == byte)
            .ok_or(Bech32Error::InvalidDataCharacter)?;
        values.push(u8::try_from(position).map_err(|_| Bech32Error::InvalidDataCharacter)?);
    }
    if polymod(checksum_input(hrp, &values)) != CHECKSUM_CONSTANT {
        return Err(Bech32Error::Checksum);
    }
    let payload_len = values.len().saturating_sub(CHECKSUM_LEN);
    let payload = values.get(..payload_len).unwrap_or_default();
    let data = convert_bits(payload, 5, 8, false)?;
    // The human-readable part is printable ASCII: checked above.
    Ok((String::from_utf8_lossy(hrp).into_owned(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP 350, valid bech32m strings (lower case ones; the upper-case forms are refused by
    /// design).
    const VALID: [&str; 5] = [
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];

    /// BIP 350, strings that must be refused (the one that only breaks the human-readable
    /// part's length limit is left out: this crate has no such limit).
    const INVALID: [&str; 13] = [
        "\u{20}1xj0phk",
        "\u{7f}1g6xzxy",
        "\u{80}1vctc34",
        "qyrz8wqd2c9m",
        "1qyrz8wqd2c9m",
        "y1b0jsk6g",
        "lt1igcx5c0",
        "in1muywd",
        "mm1crxm3i",
        "au1s5cgom",
        "M1VUXWEZ",
        "16plkw9",
        "1p2gdwpf",
    ];

    #[test]
    fn reads_the_bip_350_valid_strings() {
        for text in VALID {
            let (hrp, data) = decode(text).unwrap_or_else(|error| panic!("{text}: {error}"));
            assert_eq!(encode(&hrp, &data).as_deref(), Ok(text), "{text}");
        }
    }

    #[test]
    fn refuses_the_bip_350_invalid_strings() {
        for text in INVALID {
            assert!(decode(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn refuses_a_bech32_checksum() {
        // BIP 173's `A12UEL5L` in lower case: a valid bech32 string, not a bech32m one.
        assert_eq!(decode("a12uel5l"), Err(Bech32Error::Checksum));
    }

    #[test]
    fn refuses_mixed_and_upper_case() {
        assert_eq!(decode("A1lqfn3a"), Err(Bech32Error::MixedCase));
        assert_eq!(decode("A1LQFN3A"), Err(Bech32Error::UpperCase));
    }

    #[test]
    fn refuses_a_changed_character() {
        assert_eq!(decode("a1lqfn3q"), Err(Bech32Error::Checksum));
    }

    #[test]
    fn refuses_text_over_the_limit() {
        let long = format!("a1{}", "q".repeat(MAX_LEN));
        assert!(matches!(decode(&long), Err(Bech32Error::TooLong { .. })));
    }

    #[test]
    fn round_trips_65_bytes_without_padding() {
        let data: Vec<u8> = (0..65).collect();
        let text = encode("epic", &data).unwrap();
        assert_eq!(text.len(), 115);
        assert_eq!(decode(&text), Ok(("epic".to_owned(), data)));
    }
}
