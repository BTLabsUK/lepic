//! Error text as a host may display it. An error's message, and the messages of the errors
//! under it, can quote text from a node, a peer or a file, so every entry is cleaned and bounded
//! before a terminal or an app shows it.

use std::error::Error;

use crate::epicbox_invoice::HIDDEN_FORMATTING;

/// Entries longer than this many characters are cut and end in [`ELLIPSIS`].
pub const MAX_ERROR_ENTRY_CHARS: usize = 256;

/// The most entries of one error chain that are shown; deeper sources are left out.
pub const MAX_ERROR_ENTRIES: usize = 16;

/// Whole messages longer than this many characters are cut: room for a full chain of
/// [`MAX_ERROR_ENTRIES`] entries and the separators between them.
pub const MAX_ERROR_MESSAGE_CHARS: usize = MAX_ERROR_ENTRIES * (MAX_ERROR_ENTRY_CHARS + 2);

const ELLIPSIS: char = '…';

/// One entry of an error chain with control characters, bidirectional formatting, line and
/// paragraph separators and zero-width characters removed, cut to [`MAX_ERROR_ENTRY_CHARS`]
/// characters.
pub fn display_error_text(text: &str) -> String {
    cleaned(text, MAX_ERROR_ENTRY_CHARS)
}

/// A whole error message, such as a chain already joined, cleaned as [`display_error_text`]
/// cleans an entry and cut to [`MAX_ERROR_MESSAGE_CHARS`] characters.
pub fn display_error_message(text: &str) -> String {
    cleaned(text, MAX_ERROR_MESSAGE_CHARS)
}

fn cleaned(text: &str, max_chars: usize) -> String {
    let mut kept = text
        .chars()
        .filter(|c| !c.is_control() && !HIDDEN_FORMATTING.contains(c));
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
        assert!(shown.starts_with('a') && shown.ends_with('f'));
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
