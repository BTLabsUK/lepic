// SPDX-License-Identifier: Apache-2.0
//! JSON parse errors that carry no text of the document.

use serde_json::error::Category;

/// Why a JSON document did not parse, without any of its text: a parser's message can quote the
/// document, and relay frames and peer messages are untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{} at line {line} column {column}", category_name(*.category))]
pub struct JsonProblem {
    /// What kind of problem the parser found.
    pub category: Category,
    /// The line it found it on, from 1.
    pub line: usize,
    /// The column it found it at, from 1.
    pub column: usize,
}

impl From<serde_json::Error> for JsonProblem {
    fn from(error: serde_json::Error) -> Self {
        Self {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }
}

fn category_name(category: Category) -> &'static str {
    match category {
        Category::Io => "read error",
        Category::Syntax => "syntax error",
        Category::Data => "unexpected value",
        Category::Eof => "unexpected end",
    }
}
