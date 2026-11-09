// SPDX-License-Identifier: Apache-2.0
//! Decimal EPIC amounts in links, read by the rules of the LEPIC CLI: EPIC with up to eight
//! decimals; signs, exponents, separators and spaces are refused, and so is zero.

use lepic_primitives::amount::{Amount, EPIC_BASE};
use thiserror::Error;

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

/// Parses `1`, `1.5` or `.25` into base units.
pub fn parse_amount(text: &str) -> Result<Amount, AmountError> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && fraction.is_empty() {
        return Err(AmountError::Syntax);
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|byte| byte.is_ascii_digit())
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

/// The shortest text [`parse_amount`] reads back to `amount`: `5`, `1.5`, `0.00000001`.
pub fn format_amount(amount: Amount) -> String {
    let units = amount.value();
    let whole = units.checked_div(EPIC_BASE).unwrap_or(0);
    let fraction = units.checked_rem(EPIC_BASE).unwrap_or(0);
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:0DECIMALS$}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats() {
        for (text, units) in [
            ("1", 100_000_000),
            ("1.5", 150_000_000),
            (".25", 25_000_000),
            ("0.00000001", 1),
            ("184467440737.09551615", u64::MAX),
        ] {
            let amount = parse_amount(text).unwrap();
            assert_eq!(amount.value(), units, "{text}");
        }
        for text in ["5", "1.5", "0.25", "0.00000001", "12.34567891"] {
            assert_eq!(format_amount(parse_amount(text).unwrap()), text);
        }
    }

    #[test]
    fn refuses_bad_values() {
        for (text, error) in [
            ("", AmountError::Syntax),
            (".", AmountError::Syntax),
            ("-1", AmountError::Syntax),
            ("+1", AmountError::Syntax),
            ("1e3", AmountError::Syntax),
            ("1,5", AmountError::Syntax),
            (" 1", AmountError::Syntax),
            ("1.2.3", AmountError::Syntax),
            ("0.000000001", AmountError::TooPrecise),
            ("184467440738", AmountError::TooLarge),
            ("0", AmountError::Zero),
            ("0.0", AmountError::Zero),
        ] {
            assert_eq!(parse_amount(text), Err(error), "{text:?}");
        }
    }
}
