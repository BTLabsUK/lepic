// SPDX-License-Identifier: Apache-2.0
//! Amounts as people type and read them: EPIC with up to eight decimals.

use lepic_primitives::amount::{Amount, EPIC_BASE, Fee};
use thiserror::Error;

/// Decimal places of one base unit.
const DECIMALS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AmountError {
    #[error("amount is not a decimal number of epic")]
    Syntax,
    #[error("amount has more than {DECIMALS} decimals")]
    TooPrecise,
    #[error("amount is too large")]
    TooLarge,
    #[error("amount is zero")]
    Zero,
}

/// Parses `1`, `1.5` or `.25` into base units. Signs, exponents, separators and spaces are
/// refused, so what was typed is exactly what is sent.
pub fn parse_amount(text: &str) -> Result<Amount, AmountError> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && fraction.is_empty() {
        return Err(AmountError::Syntax);
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|b| b.is_ascii_digit())
    {
        return Err(AmountError::Syntax);
    }
    if fraction.len() > DECIMALS {
        return Err(AmountError::TooPrecise);
    }
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<u64>().map_err(|_| AmountError::TooLarge)?
    };
    let fraction_units = format!("{fraction:0<DECIMALS$}")
        .parse::<u64>()
        .map_err(|_| AmountError::Syntax)?;
    let units = whole
        .checked_mul(EPIC_BASE)
        .and_then(|units| units.checked_add(fraction_units))
        .ok_or(AmountError::TooLarge)?;
    if units == 0 {
        return Err(AmountError::Zero);
    }
    Ok(Amount::new(units))
}

/// `150000000` base units read `1.50000000`. Every amount the CLI prints has all eight decimals,
/// so JSON consumers can compare strings.
pub fn format_units(units: u64) -> String {
    let whole = units.checked_div(EPIC_BASE).unwrap_or(0);
    let fraction = units.checked_rem(EPIC_BASE).unwrap_or(0);
    format!("{whole}.{fraction:0DECIMALS$}")
}

pub fn format_amount(amount: Amount) -> String {
    format_units(amount.value())
}

pub fn format_fee(fee: Fee) -> String {
    format_units(fee.value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_and_fractional_epic() {
        for (text, units) in [
            ("1", 100_000_000),
            ("1.5", 150_000_000),
            ("0.00000001", 1),
            (".25", 25_000_000),
            ("2.", 200_000_000),
            ("184467440737.09551615", u64::MAX),
        ] {
            assert_eq!(parse_amount(text), Ok(Amount::new(units)), "{text}");
        }
    }

    #[test]
    fn rejects_amounts_that_are_not_plain_decimals() {
        for text in [
            "", ".", "-1", "+1", "1e3", "1,5", " 1", "1 ", "1.2.3", "0x10", "١",
        ] {
            assert_eq!(parse_amount(text), Err(AmountError::Syntax), "{text}");
        }
    }

    #[test]
    fn rejects_zero_too_precise_and_too_large_amounts() {
        assert_eq!(parse_amount("0"), Err(AmountError::Zero));
        assert_eq!(parse_amount("0.000"), Err(AmountError::Zero));
        assert_eq!(parse_amount("1.000000001"), Err(AmountError::TooPrecise));
        assert_eq!(
            parse_amount("184467440737.09551616"),
            Err(AmountError::TooLarge)
        );
        assert_eq!(
            parse_amount("99999999999999999999"),
            Err(AmountError::TooLarge)
        );
    }

    #[test]
    fn formats_with_all_eight_decimals() {
        assert_eq!(format_units(0), "0.00000000");
        assert_eq!(format_units(1), "0.00000001");
        assert_eq!(format_units(150_000_000), "1.50000000");
        assert_eq!(format_units(u64::MAX), "184467440737.09551615");
    }

    #[test]
    fn formatted_amounts_parse_back() {
        for units in [1, 7, 99_999_999, 100_000_000, 123_456_789_012, u64::MAX] {
            assert_eq!(parse_amount(&format_units(units)), Ok(Amount::new(units)));
        }
    }
}
