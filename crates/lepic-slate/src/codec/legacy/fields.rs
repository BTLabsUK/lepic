//! Field codecs shared by the legacy JSON formats: reading every value form upstream accepts into
//! typed field errors, and writing values in exactly the form upstream writes.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::error::{DecodeError, FieldProblem};
use crate::validate::encode_hex;

/// A JSON value where a legacy format expects a scalar. Reading accepts any JSON value, so a value
/// of the wrong type becomes a typed field error rather than a syntax error, and an absent key is
/// told apart from `null`.
#[derive(Debug, Default)]
pub(crate) enum Scalar {
    #[default]
    Absent,
    Null,
    Bool,
    Unsigned(u64),
    /// A negative integer, a fraction, or an integer above `u64::MAX`.
    OtherNumber,
    Text(String),
    /// An array or an object, skipped without being kept.
    Compound,
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ScalarVisitor)
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any json value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Scalar, E> {
        Ok(Scalar::Bool)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Scalar, E> {
        Ok(Scalar::Unsigned(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Scalar, E> {
        Ok(u64::try_from(value).map_or(Scalar::OtherNumber, Scalar::Unsigned))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::OtherNumber)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Scalar, E> {
        Ok(Scalar::Text(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Scalar, E> {
        Ok(Scalar::Text(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Scalar, E> {
        Ok(Scalar::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Scalar, E> {
        Ok(Scalar::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Scalar, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scalar, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Scalar::Compound)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Scalar, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Scalar::Compound)
    }
}

pub(crate) const fn field_error(field: &'static str, problem: FieldProblem) -> DecodeError {
    DecodeError::Field { field, problem }
}

pub(crate) const fn missing(field: &'static str) -> DecodeError {
    field_error(field, FieldProblem::Missing)
}

/// A `u64` written as a JSON number or as a string of decimal digits, as upstream's
/// `string_or_u64` reads it.
pub(crate) fn integer(field: &'static str, value: &Scalar) -> Result<u64, DecodeError> {
    match value {
        Scalar::Unsigned(number) => Ok(*number),
        Scalar::Text(text) => {
            parse_decimal(text).ok_or(field_error(field, FieldProblem::IntegerOutOfRange))
        }
        Scalar::OtherNumber => Err(field_error(field, FieldProblem::IntegerOutOfRange)),
        Scalar::Absent => Err(missing(field)),
        Scalar::Null | Scalar::Bool | Scalar::Compound => {
            Err(field_error(field, FieldProblem::WrongType))
        }
    }
}

/// [`integer`], or `None` for `null`.
pub(crate) fn optional_integer(
    field: &'static str,
    value: &Scalar,
) -> Result<Option<u64>, DecodeError> {
    match value {
        Scalar::Null => Ok(None),
        other => integer(field, other).map(Some),
    }
}

/// An integer that must be a JSON number, not a string.
pub(crate) fn number<T: TryFrom<u64>>(
    field: &'static str,
    value: &Scalar,
) -> Result<T, DecodeError> {
    match value {
        Scalar::Unsigned(number) => {
            T::try_from(*number).map_err(|_| field_error(field, FieldProblem::IntegerOutOfRange))
        }
        Scalar::OtherNumber => Err(field_error(field, FieldProblem::IntegerOutOfRange)),
        Scalar::Absent => Err(missing(field)),
        Scalar::Null | Scalar::Bool | Scalar::Text(_) | Scalar::Compound => {
            Err(field_error(field, FieldProblem::WrongType))
        }
    }
}

pub(crate) fn text<'a>(field: &'static str, value: &'a Scalar) -> Result<&'a str, DecodeError> {
    match value {
        Scalar::Text(text) => Ok(text),
        Scalar::Absent => Err(missing(field)),
        Scalar::Null
        | Scalar::Bool
        | Scalar::Unsigned(_)
        | Scalar::OtherNumber
        | Scalar::Compound => Err(field_error(field, FieldProblem::WrongType)),
    }
}

/// [`text`], or `None` for `null`. An absent key is still missing.
pub(crate) fn optional_text<'a>(
    field: &'static str,
    value: &'a Scalar,
) -> Result<Option<&'a str>, DecodeError> {
    match value {
        Scalar::Null => Ok(None),
        other => text(field, other).map(Some),
    }
}

/// A text field turned into a domain value by `parse`.
pub(crate) fn parsed<T>(
    field: &'static str,
    value: &Scalar,
    parse: impl FnOnce(&str) -> Result<T, FieldProblem>,
) -> Result<T, DecodeError> {
    parse(text(field, value)?).map_err(|problem| field_error(field, problem))
}

/// [`parsed`], or `None` for `null`.
pub(crate) fn optional_parsed<T>(
    field: &'static str,
    value: &Scalar,
    parse: impl FnOnce(&str) -> Result<T, FieldProblem>,
) -> Result<Option<T>, DecodeError> {
    optional_text(field, value)?
        .map(|text| parse(text).map_err(|problem| field_error(field, problem)))
        .transpose()
}

/// Decimal digits only. Upstream writes nothing else, so signs and spaces are refused.
fn parse_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Writes one JSON object field by field, compact, in the order the fields are given.
pub(crate) struct ObjectWriter<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> ObjectWriter<'a> {
    pub(crate) fn open(out: &'a mut String) -> Self {
        out.push('{');
        Self { out, empty: true }
    }

    /// Writes the key and returns the output for its value.
    pub(crate) fn key(&mut self, key: &str) -> &mut String {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        write_string(self.out, key);
        self.out.push(':');
        self.out
    }

    pub(crate) fn close(self) {
        self.out.push('}');
    }
}

pub(crate) fn write_array<T>(
    out: &mut String,
    items: impl IntoIterator<Item = T>,
    mut write_item: impl FnMut(&mut String, T),
) {
    out.push('[');
    for (position, item) in items.into_iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        write_item(out, item);
    }
    out.push(']');
}

pub(crate) fn write_null(out: &mut String) {
    out.push_str("null");
}

pub(crate) fn write_number(out: &mut String, value: u64) {
    out.push_str(&value.to_string());
}

/// A `u64` as a string of decimal digits, as upstream's `string_or_u64` writes it.
pub(crate) fn write_integer_string(out: &mut String, value: u64) {
    out.push('"');
    write_number(out, value);
    out.push('"');
}

pub(crate) fn write_hex(out: &mut String, bytes: &[u8]) {
    out.push('"');
    out.push_str(&encode_hex(bytes));
    out.push('"');
}

/// A JSON string escaped as `serde_json` escapes it, which is what upstream writes: quote,
/// backslash and control characters only, with the short forms where JSON has them and
/// lowercase `\u00xx` otherwise. Everything else, including non-ASCII, is written as is.
pub(crate) fn write_string(out: &mut String, text: &str) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if u32::from(control) < 0x20 => {
                out.push_str("\\u00");
                let code = u32::from(control);
                for nibble in [code >> 4, code & 0x0f] {
                    if let Some(&digit) = usize::try_from(nibble).ok().and_then(|n| DIGITS.get(n)) {
                        out.push(char::from(digit));
                    }
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(json: &str) -> Scalar {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn integers_are_read_from_numbers_and_digit_strings() {
        assert_eq!(integer("f", &scalar("7")), Ok(7));
        assert_eq!(integer("f", &scalar("\"007\"")), Ok(7));
        assert_eq!(
            integer("f", &scalar("\"18446744073709551615\"")),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn rejects_integers_out_of_range_or_not_decimal() {
        for json in [
            "-1",
            "1.5",
            "18446744073709551616",
            "\"18446744073709551616\"",
            "\"-1\"",
            "\"+1\"",
            "\" 1\"",
            "\"\"",
            "\"0x10\"",
        ] {
            assert_eq!(
                integer("f", &scalar(json)),
                Err(field_error("f", FieldProblem::IntegerOutOfRange)),
                "{json}"
            );
        }
    }

    #[test]
    fn rejects_values_of_the_wrong_type() {
        for json in ["null", "true", "[1]", "{\"a\":1}"] {
            assert_eq!(
                integer("f", &scalar(json)),
                Err(field_error("f", FieldProblem::WrongType)),
                "{json}"
            );
        }
        assert_eq!(
            number::<u64>("f", &scalar("\"2\"")),
            Err(field_error("f", FieldProblem::WrongType))
        );
        assert_eq!(
            number::<u16>("f", &scalar("65536")),
            Err(field_error("f", FieldProblem::IntegerOutOfRange))
        );
        assert_eq!(
            text("f", &scalar("1")),
            Err(field_error("f", FieldProblem::WrongType))
        );
    }

    #[test]
    fn null_is_none_but_absent_is_missing() {
        assert_eq!(optional_integer("f", &scalar("null")), Ok(None));
        assert_eq!(optional_text("f", &scalar("null")), Ok(None));
        assert_eq!(optional_integer("f", &Scalar::Absent), Err(missing("f")));
        assert_eq!(optional_text("f", &Scalar::Absent), Err(missing("f")));
    }

    #[test]
    fn strings_are_escaped_as_serde_json_escapes_them() {
        let samples = [
            "plain",
            "quote \" and backslash \\",
            "\n\r\t\u{08}\u{0c}\u{00}\u{1f}\u{7f}",
            "é ✓ 🙂 \u{2028}",
            "</script>",
        ];
        for sample in samples {
            let mut out = String::new();
            write_string(&mut out, sample);
            assert_eq!(out, serde_json::to_string(sample).unwrap(), "{sample:?}");
        }
    }

    #[test]
    fn objects_and_arrays_are_written_compact_in_order() {
        let mut out = String::new();
        let mut object = ObjectWriter::open(&mut out);
        write_integer_string(object.key("b"), 3);
        write_array(object.key("a"), [1u64, 2], write_number);
        write_null(object.key("c"));
        write_hex(object.key("d"), &[0xab, 0x01]);
        object.close();
        assert_eq!(out, r#"{"b":"3","a":[1,2],"c":null,"d":"ab01"}"#);
    }
}
