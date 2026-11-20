// SPDX-License-Identifier: Apache-2.0
//! The owner's profile (ADR 0041): 16 bits the wallet tells its paired contacts about the host.
//! The library carries the number and keeps no meaning for it; the names live here.

/// The bits the CLI names, lowest first. Other bits are legal and pass through unnamed.
pub const NAMES: [(&str, u16); 2] = [("no-payments", 0x1), ("automated", 0x2)];

/// A number, decimal or `0x` hex, of at most 16 bits.
pub fn parse_bits(text: &str) -> Option<u16> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Bit names, comma-separated. Unknown names refuse the whole value; empty names none.
pub fn parse_names(text: &str) -> Option<u16> {
    let mut bits = 0;
    for name in text
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        bits |= NAMES
            .iter()
            .find_map(|(known, bit)| (*known == name).then_some(*bit))?;
    }
    Some(bits)
}

/// A setting's text: a number when it starts with a digit, else names.
pub fn parse_setting(text: &str) -> Option<u16> {
    if text.trim().starts_with(|c: char| c.is_ascii_digit()) {
        parse_bits(text)
    } else {
        parse_names(text)
    }
}

/// The names of the bits set, and the bits that have none.
pub fn describe(profile: u32) -> (Vec<&'static str>, u32) {
    let mut unknown = profile;
    let names = NAMES
        .iter()
        .filter(|(_, bit)| profile & u32::from(*bit) != 0)
        .map(|(name, bit)| {
            unknown &= !u32::from(*bit);
            *name
        })
        .collect();
    (names, unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers_agree() {
        assert_eq!(parse_names("no-payments,automated"), Some(3));
        assert_eq!(parse_names(" automated , "), Some(2));
        assert_eq!(parse_names(""), Some(0));
        assert_eq!(parse_names("everything"), None);
        assert_eq!(parse_bits("3"), Some(3));
        assert_eq!(parse_bits("0x8001"), Some(0x8001));
        assert_eq!(parse_bits("0xFFFF"), Some(0xFFFF));
        for bad in ["65536", "0x10000", "-1", "", "0x", "no-payments"] {
            assert_eq!(parse_bits(bad), None, "{bad}");
        }
        assert_eq!(parse_setting("automated"), Some(2));
        assert_eq!(parse_setting("0x3"), Some(3));
    }

    #[test]
    fn describe_names_known_bits_and_leaves_the_rest() {
        assert_eq!(describe(0), (vec![], 0));
        assert_eq!(describe(3), (vec!["no-payments", "automated"], 0));
        assert_eq!(describe(0x8001), (vec!["no-payments"], 0x8000));
    }
}
