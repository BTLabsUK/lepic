// SPDX-License-Identifier: Apache-2.0
//! Error text as a host may display it. An error's message, and the messages of the errors
//! under it, can quote text from a node, a peer or a file, so every entry is cleaned and bounded
//! before a terminal or an app shows it.

use std::error::Error;

use crate::epicbox_invoice::HIDDEN_FORMATTING;

/// Entries longer than this many characters are cut and end in an ellipsis.
pub const MAX_ERROR_ENTRY_CHARS: usize = 256;

/// The most entries of one error chain that are shown; deeper sources are left out.
pub const MAX_ERROR_ENTRIES: usize = 16;

/// Whole messages longer than this many characters are cut: room for a full chain of
/// [`MAX_ERROR_ENTRIES`] entries and the separators between them.
pub const MAX_ERROR_MESSAGE_CHARS: usize = MAX_ERROR_ENTRIES * (MAX_ERROR_ENTRY_CHARS + 2);

const ELLIPSIS: char = '…';

/// One entry of an error chain with each run of line breaks and tabs made one space, other
/// control characters, bidirectional formatting and zero-width characters removed, and cut to
/// [`MAX_ERROR_ENTRY_CHARS`] characters.
pub fn display_error_text(text: &str) -> String {
    cleaned(text, MAX_ERROR_ENTRY_CHARS)
}

/// A whole error message, such as a chain already joined, cleaned as [`display_error_text`]
/// cleans an entry and cut to [`MAX_ERROR_MESSAGE_CHARS`] characters.
pub fn display_error_message(text: &str) -> String {
    cleaned(text, MAX_ERROR_MESSAGE_CHARS)
}

fn cleaned(text: &str, max_chars: usize) -> String {
    let mut kept = shown_chars(text);
    let mut shown = String::new();
    for c in kept.by_ref().take(max_chars) {
        shown.push(c);
    }
    if kept.next().is_some() {
        shown.pop();
        shown.push(ELLIPSIS);
    }
    shown
}

/// The characters of `text` that are shown. A run of line breaks and tabs becomes one space, so
/// the words around it stay apart; other hidden characters are dropped.
fn shown_chars(text: &str) -> impl Iterator<Item = char> + '_ {
    let mut after_break = false;
    text.chars().filter_map(move |c| {
        if matches!(c, '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}') {
            let first = !after_break;
            after_break = true;
            return first.then_some(' ');
        }
        if c.is_control() || HIDDEN_FORMATTING.contains(&c) {
            return None;
        }
        after_break = false;
        Some(c)
    })
}

/// The message of `error` and of each source under it, outermost first, each through
/// [`display_error_text`] and at most [`MAX_ERROR_ENTRIES`] of them. An entry equal to the one
/// before it, as when a wrapper prints its source, appears once.
pub fn display_error_chain(error: &(dyn Error + 'static)) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let errors = std::iter::successors(Some(error), |&error| error.source());
    for error in errors {
        if entries.len() >= MAX_ERROR_ENTRIES {
            break;
        }
        let text = display_error_text(&error.to_string());
        if entries.last() != Some(&text) {
            entries.push(text);
        }
    }
    entries
}

/// The most characters of a node's or a relay's text the API passes on. The store keeps up to
/// 1024 bytes of the push's error with the node's message; a node's message is one line, and
/// this keeps each event and webhook that carries it small.
pub const NODE_TEXT_MAX_CHARS: usize = 256;

/// `text`, which came from a node or a relay, as plain text: each control character escaped, so it
/// cannot forge lines in a log or move a terminal's cursor, and each character that reorders or
/// hides text escaped as well, so it cannot turn round what a console, a terminal or a log shows;
/// then cut to [`NODE_TEXT_MAX_CHARS`], escapes counted, with `…` at the end when it was cut.
pub fn node_text(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            plain.extend(c.escape_default());
        } else if reorders_or_hides(c) {
            plain.extend(c.escape_unicode());
        } else {
            plain.push(c);
        }
    }
    if plain.chars().count() <= NODE_TEXT_MAX_CHARS {
        return plain;
    }
    let mut cut: String = plain
        .chars()
        .take(NODE_TEXT_MAX_CHARS.saturating_sub(1))
        .collect();
    cut.push('…');
    cut
}

/// Zero-width characters and marks, bidirectional embeddings, overrides and isolates, the word
/// joiner and invisible operators, the byte order mark and the line and paragraph separators.
const fn reorders_or_hides(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("{text}")]
    struct Layer {
        text: String,
        #[source]
        source: Option<Box<Layer>>,
    }

    fn layered(texts: &[&str]) -> Layer {
        texts
            .iter()
            .rev()
            .fold(None, |source, text| {
                Some(Layer {
                    text: (*text).to_owned(),
                    source: source.map(Box::new),
                })
            })
            .unwrap()
    }

    #[test]
    fn removes_control_and_hidden_formatting_characters() {
        let shown = display_error_text("a\u{1b}[2J\u{202E}b\u{2066}c\u{200B}d\u{2060}e\u{2028}f\n");
        assert!(
            shown
                .chars()
                .all(|c| !c.is_control() && !HIDDEN_FORMATTING.contains(&c))
        );
        assert!(shown.starts_with('a') && shown.ends_with("f "));
    }

    #[test]
    fn line_breaks_and_tabs_become_one_space() {
        assert_eq!(display_error_text("a\nb"), "a b");
        assert_eq!(
            display_error_text("a\r\n\u{202E}\tb\u{2028}c\u{2029}d"),
            "a b c d"
        );
    }

    #[test]
    fn cuts_long_entries_with_an_ellipsis() {
        let shown = display_error_text(&"x".repeat(10_000));
        assert_eq!(shown.chars().count(), MAX_ERROR_ENTRY_CHARS);
        assert!(shown.ends_with(ELLIPSIS));
        let exact = "y".repeat(MAX_ERROR_ENTRY_CHARS);
        assert_eq!(display_error_text(&exact), exact);
    }

    #[test]
    fn whole_messages_have_a_larger_bound() {
        let shown = display_error_message(&"\u{202E}m".repeat(10_000));
        assert_eq!(shown.chars().count(), MAX_ERROR_MESSAGE_CHARS);
        assert!(!shown.contains('\u{202E}'));
    }

    #[test]
    fn node_text_escapes_control_and_reordering_characters_and_cuts() {
        assert_eq!(
            node_text("a\u{1b}[2J\u{202E}b\u{200B}c\nd"),
            "a\\u{1b}[2J\\u{202e}b\\u{200b}c\\nd"
        );
        let short = "x".repeat(NODE_TEXT_MAX_CHARS);
        assert_eq!(node_text(&short), short);
        let cut = node_text(&format!("\u{2066}{}", "x".repeat(400)));
        assert_eq!(cut.chars().count(), NODE_TEXT_MAX_CHARS);
        assert!(
            cut.starts_with("\\u{2066}x") && cut.ends_with(ELLIPSIS),
            "{cut}"
        );
    }

    #[test]
    fn chain_is_cleaned_bounded_and_without_repeats() {
        let long = "\u{202E}".repeat(5) + &"z".repeat(5_000);
        let mut texts = vec!["outer", "outer", long.as_str()];
        texts.extend(std::iter::repeat_n("deep", 40));
        let entries = display_error_chain(&layered(&texts));
        assert!(entries.len() <= MAX_ERROR_ENTRIES);
        assert_eq!(entries.first().map(String::as_str), Some("outer"));
        assert_ne!(entries.get(1).map(String::as_str), Some("outer"));
        for entry in &entries {
            assert!(entry.chars().count() <= MAX_ERROR_ENTRY_CHARS);
            assert!(!entry.contains('\u{202E}'));
        }
    }
}
