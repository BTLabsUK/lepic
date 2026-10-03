//! What the file policy dispatches on, read without building a JSON document tree. Everything
//! else in the file is skipped while it is parsed, so the memory used does not grow with it.

use std::fmt;
use std::marker::PhantomData;

use lepic_slate::error::{DecodeError, FieldProblem};
use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

/// The keys V3 has and V2 lacks.
const V3_ONLY_KEYS: [&str; 2] = ["ttl_cutoff_height", "payment_proof"];

pub(super) struct FileHeader {
    /// `version_info.version`, as upstream's version probe reads it.
    pub(super) version: u64,
    /// Whether any key in [`V3_ONLY_KEYS`] is present at the top level, whatever its value.
    pub(super) has_v3_only_keys: bool,
}

/// Reads the header of a slate file. A file that is not a JSON object is an unknown format; a
/// slate with only a top-level `version` key is version 1, and one with neither that nor
/// `version_info` is refused for the missing `version_info`. A key that appears twice counts
/// as its last value, as in a JSON document tree.
pub(super) fn read_header(text: &str) -> Result<FileHeader, DecodeError> {
    let Document::Object(top) =
        serde_json::from_str::<Document>(text).map_err(|_| DecodeError::UnknownFormat)?
    else {
        return Err(DecodeError::UnknownFormat);
    };
    Ok(FileHeader {
        version: top.version()?,
        has_v3_only_keys: top.has_v3_only_keys,
    })
}

/// The slate file with every top-level V3-only key removed and every other value kept as
/// written, so the V2 codec reads it as upstream's V2 parse does, ignoring those keys.
pub(super) fn without_v3_only_keys(text: &str) -> Result<String, DecodeError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let stripped = deserializer
        .deserialize_map(StripV3OnlyKeys {
            capacity: text.len(),
        })
        .and_then(|stripped| deserializer.end().map(|()| stripped))
        .map_err(|_| DecodeError::UnknownFormat)?;
    Ok(stripped)
}

struct StripV3OnlyKeys {
    capacity: usize,
}

impl<'de> Visitor<'de> for StripV3OnlyKeys {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<String, A::Error> {
        let mut stripped = String::with_capacity(self.capacity);
        stripped.push('{');
        while let Some(key) = map.next_key::<String>()? {
            if V3_ONLY_KEYS.contains(&key.as_str()) {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let value: &'de RawValue = map.next_value()?;
            if stripped.len() > 1 {
                stripped.push(',');
            }
            stripped.push_str(&serde_json::to_string(&key).map_err(de::Error::custom)?);
            stripped.push(':');
            stripped.push_str(value.get());
        }
        stripped.push('}');
        Ok(stripped)
    }
}

/// The parts of a top-level JSON object the header is made of.
#[derive(Default)]
struct TopLevel {
    version_info: Option<VersionInfo>,
    has_version: bool,
    has_v3_only_keys: bool,
}

impl TopLevel {
    fn version(&self) -> Result<u64, DecodeError> {
        let version_field = |problem| DecodeError::Field {
            field: "version_info.version",
            problem,
        };
        match &self.version_info {
            Some(VersionInfo(Some(VersionNumber::Unsigned(version)))) => Ok(*version),
            Some(VersionInfo(Some(VersionNumber::Other))) => {
                Err(version_field(FieldProblem::WrongType))
            }
            Some(VersionInfo(None)) => Err(version_field(FieldProblem::Missing)),
            None if self.has_version => Ok(1),
            None => Err(DecodeError::Field {
                field: "version_info",
                problem: FieldProblem::Missing,
            }),
        }
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum TopLevelKey {
    VersionInfo,
    Version,
    TtlCutoffHeight,
    PaymentProof,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum VersionInfoKey {
    Version,
    #[serde(other)]
    Other,
}

/// The whole file: an object, or any other JSON value.
enum Document {
    Object(TopLevel),
    Other,
}

/// `version_info`: its `version` if it is an object holding one, `None` otherwise.
struct VersionInfo(Option<VersionNumber>);

/// `version_info.version`: an unsigned integer, or any other JSON value.
enum VersionNumber {
    Unsigned(u64),
    Other,
}

/// A JSON value of any type of which only some shapes matter. Every other value is skipped
/// without being kept and becomes [`Shape::other`].
trait Shape: Sized {
    fn other() -> Self;

    fn unsigned(_: u64) -> Self {
        Self::other()
    }

    fn object<'de, A: MapAccess<'de>>(mut map: A) -> Result<Self, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Self::other())
    }
}

impl Shape for Document {
    fn other() -> Self {
        Self::Other
    }

    fn object<'de, A: MapAccess<'de>>(mut map: A) -> Result<Self, A::Error> {
        let mut top = TopLevel::default();
        while let Some(key) = map.next_key::<TopLevelKey>()? {
            match key {
                TopLevelKey::VersionInfo => top.version_info = Some(map.next_value()?),
                TopLevelKey::Version => {
                    map.next_value::<IgnoredAny>()?;
                    top.has_version = true;
                }
                TopLevelKey::TtlCutoffHeight | TopLevelKey::PaymentProof => {
                    map.next_value::<IgnoredAny>()?;
                    top.has_v3_only_keys = true;
                }
                TopLevelKey::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Self::Object(top))
    }
}

impl Shape for VersionInfo {
    fn other() -> Self {
        Self(None)
    }

    fn object<'de, A: MapAccess<'de>>(mut map: A) -> Result<Self, A::Error> {
        let mut version = None;
        while let Some(key) = map.next_key::<VersionInfoKey>()? {
            match key {
                VersionInfoKey::Version => version = Some(map.next_value()?),
                VersionInfoKey::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Self(version))
    }
}

impl Shape for VersionNumber {
    fn other() -> Self {
        Self::Other
    }

    fn unsigned(version: u64) -> Self {
        Self::Unsigned(version)
    }
}

macro_rules! deserialize_as_shape {
    ($($shape:ty),*) => {$(
        impl<'de> Deserialize<'de> for $shape {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_any(ShapeVisitor(PhantomData))
            }
        }
    )*};
}

deserialize_as_shape!(Document, VersionInfo, VersionNumber);

struct ShapeVisitor<T>(PhantomData<T>);

impl<'de, T: Shape> Visitor<'de> for ShapeVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<T, E> {
        Ok(T::other())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<T, E> {
        Ok(T::other())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<T, E> {
        Ok(T::unsigned(value))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<T, E> {
        Ok(T::other())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<T, E> {
        Ok(T::other())
    }

    fn visit_unit<E: de::Error>(self) -> Result<T, E> {
        Ok(T::other())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(T::other())
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
        T::object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Result<u64, DecodeError> {
        read_header(text).map(|header| header.version)
    }

    fn field_problem(text: &str) -> Option<(&'static str, FieldProblem)> {
        match version(text) {
            Err(DecodeError::Field { field, problem }) => Some((field, problem)),
            _ => None,
        }
    }

    #[test]
    fn reads_version_info_version_and_ignores_everything_else() {
        let text = r#"{"x":[{"version_info":{"version":9}}],"version_info":{"a":[1],"version":3}}"#;
        assert_eq!(version(text).unwrap(), 3);
    }

    #[test]
    fn a_repeated_key_counts_as_its_last_value() {
        let text = r#"{"version_info":{"version":2},"version_info":{"version":3,"version":2}}"#;
        assert_eq!(version(text).unwrap(), 2);
    }

    #[test]
    fn reads_escaped_key_names() {
        assert_eq!(
            version(r#"{"version\u005finfo":{"versio\u006e":3}}"#).unwrap(),
            3
        );
    }

    #[test]
    fn a_top_level_version_without_version_info_is_version_one() {
        assert_eq!(version(r#"{"version":null}"#).unwrap(), 1);
    }

    #[test]
    fn refuses_a_slate_without_version_info() {
        assert_eq!(
            field_problem(r#"{"x":3}"#),
            Some(("version_info", FieldProblem::Missing))
        );
    }

    #[test]
    fn refuses_version_info_without_a_version() {
        for text in [
            r#"{"version_info":{}}"#,
            r#"{"version_info":null}"#,
            r#"{"version_info":[3]}"#,
            r#"{"version_info":3}"#,
        ] {
            assert_eq!(
                field_problem(text),
                Some(("version_info.version", FieldProblem::Missing)),
                "{text}"
            );
        }
    }

    #[test]
    fn refuses_a_version_that_is_not_an_unsigned_integer() {
        for value in ["-2", "3.0", "\"3\"", "null", "true", "[3]", "{}"] {
            let text = format!(r#"{{"version_info":{{"version":{value}}}}}"#);
            assert_eq!(
                field_problem(&text),
                Some(("version_info.version", FieldProblem::WrongType)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_one_json_object_is_an_unknown_format() {
        for text in [
            "",
            "[]",
            "3",
            "\"x\"",
            "null",
            r#"{"version_info":{"version":3}"#,
            r#"{"version_info":{"version":3}} {}"#,
        ] {
            assert!(
                matches!(version(text), Err(DecodeError::UnknownFormat)),
                "{text}"
            );
        }
    }

    #[test]
    fn notices_v3_only_keys_whatever_their_value() {
        for text in [
            r#"{"version_info":{"version":2},"ttl_cutoff_height":null}"#,
            r#"{"version_info":{"version":2},"payment_proof":[{}]}"#,
        ] {
            assert!(read_header(text).unwrap().has_v3_only_keys, "{text}");
        }
        let nested =
            r#"{"version_info":{"version":2,"payment_proof":1},"x":{"ttl_cutoff_height":1}}"#;
        assert!(!read_header(nested).unwrap().has_v3_only_keys);
    }

    #[test]
    fn stripping_removes_only_top_level_v3_only_keys_and_keeps_values_as_written() {
        let text = r#"{ "a" : 1.50, "ttl_cutoff_height":7,"b":{"payment_proof": "x"},"payment_proof":{"y":[1]},"payment_proof":null, "c\u0041":"\u00e9" }"#;
        assert_eq!(
            without_v3_only_keys(text).unwrap(),
            r#"{"a":1.50,"b":{"payment_proof": "x"},"cA":"\u00e9"}"#
        );
    }

    #[test]
    fn stripping_a_slate_of_only_v3_only_keys_leaves_an_empty_object() {
        assert_eq!(
            without_v3_only_keys(r#"{"ttl_cutoff_height":1,"payment_proof":null}"#).unwrap(),
            "{}"
        );
    }
}
