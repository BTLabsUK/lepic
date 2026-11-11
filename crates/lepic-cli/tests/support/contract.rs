// SPDX-License-Identifier: Apache-2.0
//! The contract `docs/api/openapi.json` sets, checked on every answer a test reads from
//! `/api/v1`: the status is one the operation documents, the media type is the one documented
//! for it, and the body has exactly the documented fields, types, enums and formats.
//!
//! Only the schema keywords the document uses are known; any other fails loudly, so a new
//! keyword gets checked here before the document relies on it.

use std::sync::LazyLock;

use serde_json::{Map, Value};

use super::Reply;

static SPEC: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../../docs/api/openapi.json")).unwrap()
});

/// The keywords a schema may use. Annotations are listed with the ones checked.
const KNOWN: &[&str] = &[
    "$ref",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "maxProperties",
    "items",
    "enum",
    "oneOf",
    "format",
    "maxLength",
    "pattern",
    "description",
    "default",
    "example",
    "examples",
    "title",
    "deprecated",
];

/// Panics with every way `reply`, the answer to `method` on `path` (below `/api/v1`, query
/// included), breaks the contract.
pub fn check(method: &str, path: &str, reply: &Reply) {
    let errors = errors(method, path, reply);
    assert!(
        errors.is_empty(),
        "{method} /api/v1{path} breaks the contract:\n  {}\n{reply:?}",
        errors.join("\n  ")
    );
}

/// Every way `reply` breaks the contract; empty when it keeps it.
pub fn errors(method: &str, path: &str, reply: &Reply) -> Vec<String> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let Some(operation) = operation(method, path) else {
        // No operation: the router's own 404 or 405, as a problem.
        if ![404, 405].contains(&reply.status) {
            return vec![format!(
                "{} for a path and method the document does not have",
                reply.status
            )];
        }
        return body(&problem_content(), reply);
    };
    let responses = &operation["responses"];
    let status = reply.status.to_string();
    let Some(response) = responses.get(&status).or_else(|| responses.get("default")) else {
        let documented: Vec<&String> = responses.as_object().unwrap().keys().collect();
        return vec![format!(
            "status {status} is not documented for {} (documented: {documented:?})",
            operation["operationId"]
        )];
    };
    let response = resolve(response);
    match response.get("content") {
        Some(content) => body(content, reply),
        None if reply.body.is_empty() => Vec::new(),
        None => vec![format!("a {status} has no body, got {:?}", reply.body)],
    }
}

/// The operation `method` on `path` maps to: the template that matches with the most literal
/// segments, as the router picks it.
fn operation(method: &str, path: &str) -> Option<&'static Value> {
    let segments: Vec<&str> = path.split('/').collect();
    SPEC["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(template, item)| {
            let parts: Vec<&str> = template.split('/').collect();
            if parts.len() != segments.len() {
                return None;
            }
            let mut literal = 0;
            for (part, segment) in parts.iter().zip(&segments) {
                if part.starts_with('{') {
                    if segment.is_empty() {
                        return None;
                    }
                } else if part == segment {
                    literal += 1;
                } else {
                    return None;
                }
            }
            Some((literal, item))
        })
        .max_by_key(|(literal, _)| *literal)
        .and_then(|(_, item)| item.get(method.to_ascii_lowercase()))
}

fn problem_content() -> Value {
    resolve(&SPEC["components"]["responses"]["NotFound"])["content"].clone()
}

/// The body against the documented media types and their schemas.
fn body(content: &Value, reply: &Reply) -> Vec<String> {
    let media = reply
        .header("content-type")
        .map(|value| value.split(';').next().unwrap().trim().to_owned());
    let Some(media) = media else {
        return vec!["no content-type".to_owned()];
    };
    let Some(documented) = content.get(&media) else {
        let types: Vec<&String> = content.as_object().unwrap().keys().collect();
        return vec![format!("content-type {media} is not documented ({types:?})")];
    };
    if !media.ends_with("json") {
        return Vec::new();
    }
    let value: Value = match serde_json::from_str(&reply.body) {
        Ok(value) => value,
        Err(error) => return vec![format!("not JSON: {error}")],
    };
    let mut errors = Vec::new();
    if let Some(schema) = documented.get("schema") {
        validate(schema, &value, "", &mut errors);
    }
    errors
}

fn resolve(value: &Value) -> &Value {
    match value.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let pointer = reference.strip_prefix('#').unwrap();
            resolve(
                SPEC.pointer(pointer)
                    .unwrap_or_else(|| panic!("{reference} is not in the document")),
            )
        }
        None => value,
    }
}

/// Checks `value`, found at `at`, against `schema`, adding each failure to `errors`.
#[allow(clippy::too_many_lines)] // One block per keyword.
pub fn validate(schema: &Value, value: &Value, at: &str, errors: &mut Vec<String>) {
    let schema = resolve(schema);
    let Some(keywords) = schema.as_object() else {
        errors.push(format!("{at}: the schema is not an object"));
        return;
    };
    for keyword in keywords.keys() {
        assert!(
            KNOWN.contains(&keyword.as_str()) || keyword.starts_with("x-"),
            "the contract check does not know the schema keyword {keyword} (at {at})"
        );
    }
    let at_or_root = if at.is_empty() { "/" } else { at };
    if let Some(choices) = schema.get("oneOf").and_then(Value::as_array) {
        let mut matched = 0;
        let mut why = Vec::new();
        for choice in choices {
            let mut choice_errors = Vec::new();
            validate(choice, value, at, &mut choice_errors);
            if choice_errors.is_empty() {
                matched += 1;
            } else {
                why.push(choice_errors.join("; "));
            }
        }
        if matched != 1 {
            errors.push(format!(
                "{at_or_root}: matches {matched} of the oneOf choices, not one ({why:?})"
            ));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            errors.push(format!("{at_or_root}: {value} is not one of {allowed:?}"));
        }
    }
    let Some(kind) = schema.get("type").and_then(Value::as_str) else {
        return;
    };
    let fits = match kind {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        other => panic!("unknown type {other} at {at}"),
    };
    if !fits {
        errors.push(format!("{at_or_root}: {value} is not {kind}"));
        return;
    }
    match value {
        Value::String(text) => string(schema, text, at_or_root, errors),
        Value::Array(items) => {
            if let Some(item) = schema.get("items") {
                for (index, element) in items.iter().enumerate() {
                    validate(item, element, &format!("{at}/{index}"), errors);
                }
            }
        }
        Value::Object(fields) => object(schema, fields, at, errors),
        _ => {}
    }
}

fn object(schema: &Value, fields: &Map<String, Value>, at: &str, errors: &mut Vec<String>) {
    let at_or_root = if at.is_empty() { "/" } else { at };
    let properties = schema.get("properties").and_then(Value::as_object);
    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = required.as_str().unwrap();
        if !fields.contains_key(name) {
            errors.push(format!("{at_or_root}: the required field {name} is missing"));
        }
    }
    if let Some(most) = schema.get("maxProperties").and_then(Value::as_u64) {
        if fields.len() as u64 > most {
            errors.push(format!("{at_or_root}: more than {most} fields"));
        }
    }
    let extra = schema.get("additionalProperties");
    for (name, field) in fields {
        let field_at = format!("{at}/{name}");
        match (properties.and_then(|known| known.get(name)), extra) {
            (Some(property), _) => validate(property, field, &field_at, errors),
            (None, Some(Value::Bool(false))) => {
                errors.push(format!("{field_at}: not a documented field"));
            }
            (None, Some(Value::Bool(true))) => {}
            (None, Some(other)) => validate(other, field, &field_at, errors),
            // A free-form object documents no fields; any field is its own.
            (None, None) if properties.is_none() => {}
            // The API's objects are closed: a field the schema does not name is drift.
            (None, None) => errors.push(format!("{field_at}: not a documented field")),
        }
    }
}

fn string(schema: &Value, text: &str, at: &str, errors: &mut Vec<String>) {
    if let Some(most) = schema.get("maxLength").and_then(Value::as_u64) {
        if text.chars().count() as u64 > most {
            errors.push(format!("{at}: longer than {most} characters"));
        }
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str) {
        let fits = match format {
            "date-time" => is_date_time(text),
            "uuid" => is_uuid(text),
            "byte" => is_base64(text),
            // Annotations only.
            "password" | "uri" | "email" => true,
            other => panic!("the contract check does not know the format {other} (at {at})"),
        };
        if !fits {
            errors.push(format!("{at}: {text:?} is not a {format}"));
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let fits = match pattern {
            r"^-?[0-9]+(\.[0-9]{1,8})?$" => is_decimal(text),
            "^[0-9a-f]+$" => !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            other => panic!("the contract check does not know the pattern {other} (at {at})"),
        };
        if !fits {
            errors.push(format!("{at}: {text:?} does not match {pattern}"));
        }
    }
}

pub fn is_decimal(text: &str) -> bool {
    let text = text.strip_prefix('-').unwrap_or(text);
    let (whole, fraction) = text.split_once('.').map_or((text, None), |(w, f)| (w, Some(f)));
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    digits(whole) && fraction.is_none_or(|fraction| digits(fraction) && fraction.len() <= 8)
}

/// RFC 3339 in UTC as serve writes it: `YYYY-MM-DDTHH:MM:SS[.fraction]Z` or with an offset.
pub fn is_date_time(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    let shape = b"dddd-dd-ddTdd:dd:dd";
    let head = shape.iter().zip(bytes).all(|(want, got)| match want {
        b'd' => got.is_ascii_digit(),
        other => other == got,
    });
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return false;
        }
        rest = &fraction[digits..];
    }
    let zone = rest == "Z"
        || (rest.len() == 6
            && (rest.starts_with('+') || rest.starts_with('-'))
            && rest.as_bytes()[3] == b':');
    head && zone
}

pub fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn is_base64(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}
