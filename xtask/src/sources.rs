// SPDX-License-Identifier: Apache-2.0
//! Reading the repository's own files for the text-level gates in `repo_lint`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// A file the gates read, with its path relative to the repository root and `/` separators.
pub(crate) struct SourceFile {
    pub(crate) path: String,
    pub(crate) text: String,
}

/// Every file under `pathspecs` that git tracks or would track, so build output, ignored work
/// directories and local data never reach a gate.
pub(crate) fn repository_files(root: &Path, pathspecs: &[&str]) -> Result<Vec<SourceFile>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
        ])
        .args(pathspecs)
        .output()
        .context("could not start `git ls-files`")?;
    if !output.status.success() {
        bail!(
            "`git ls-files` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let listing = String::from_utf8(output.stdout).context("`git ls-files` printed non-utf-8")?;
    let mut paths: Vec<&str> = listing
        .split('\0')
        .filter(|path| !path.is_empty())
        .collect();
    paths.sort_unstable();
    paths.dedup();
    let mut files = Vec::new();
    for path in paths {
        let full: PathBuf = root.join(path);
        // A tracked file deleted in the working tree is not part of what is being checked.
        if !full.is_file() {
            continue;
        }
        let text =
            fs::read_to_string(&full).with_context(|| format!("reading {}", full.display()))?;
        files.push(SourceFile {
            path: path.to_owned(),
            text,
        });
    }
    Ok(files)
}

pub(crate) fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Rust source with comments and the contents of string and character literals replaced by
/// spaces. Newlines are kept, so byte offsets map to the same lines as in the original.
pub(crate) fn code_only(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let at = |index: usize| chars.get(index).copied();
    let blank = |out: &mut String, c: char| out.push(if c == '\n' { '\n' } else { ' ' });
    let mut i = 0;
    while let Some(c) = at(i) {
        let next = at(i.saturating_add(1));
        let starts_token = i == 0 || at(i.saturating_sub(1)).is_none_or(|p| !is_ident_char(p));
        if c == '/' && next == Some('/') {
            while let Some(c) = at(i).filter(|c| *c != '\n') {
                blank(&mut out, c);
                i = i.saturating_add(1);
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while let Some(c) = at(i) {
                let next = at(i.saturating_add(1));
                if c == '/' && next == Some('*') {
                    depth = depth.saturating_add(1);
                    out.push_str("  ");
                    i = i.saturating_add(2);
                } else if c == '*' && next == Some('/') {
                    depth = depth.saturating_sub(1);
                    out.push_str("  ");
                    i = i.saturating_add(2);
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, c);
                    i = i.saturating_add(1);
                }
            }
        } else if let Some(hashes) = starts_token.then(|| raw_string_start(&chars, i)).flatten() {
            // Keep the prefix up to and including the opening quote, blank the rest.
            while let Some(c) = at(i).filter(|c| *c != '"') {
                out.push(c);
                i = i.saturating_add(1);
            }
            out.push('"');
            i = i.saturating_add(1);
            while let Some(c) = at(i) {
                let closes = c == '"'
                    && (1..=hashes).all(|offset| at(i.saturating_add(offset)) == Some('#'));
                if closes {
                    out.push('"');
                    out.extend(std::iter::repeat_n('#', hashes));
                    i = i.saturating_add(hashes).saturating_add(1);
                    break;
                }
                blank(&mut out, c);
                i = i.saturating_add(1);
            }
        } else if c == '"' {
            out.push('"');
            i = i.saturating_add(1);
            while let Some(c) = at(i) {
                i = i.saturating_add(1);
                if c == '\\' {
                    out.push(' ');
                    if let Some(escaped) = at(i) {
                        blank(&mut out, escaped);
                        i = i.saturating_add(1);
                    }
                } else if c == '"' {
                    out.push('"');
                    break;
                } else {
                    blank(&mut out, c);
                }
            }
        } else if c == '\'' && (next == Some('\\') || at(i.saturating_add(2)) == Some('\'')) {
            // A character literal; a quote not closed two characters on is a lifetime.
            out.push('\'');
            i = i.saturating_add(1);
            while let Some(c) = at(i) {
                i = i.saturating_add(1);
                if c == '\\' {
                    out.push(' ');
                    if let Some(escaped) = at(i) {
                        blank(&mut out, escaped);
                        i = i.saturating_add(1);
                    }
                } else if c == '\'' {
                    out.push('\'');
                    break;
                } else {
                    blank(&mut out, c);
                }
            }
        } else {
            out.push(c);
            i = i.saturating_add(1);
        }
    }
    out
}

/// The number of `#` of a raw string literal (`r"`, `r#"`, `br"`, `cr#"`) starting at `i`.
fn raw_string_start(chars: &[char], i: usize) -> Option<usize> {
    let rest = chars.get(i..)?;
    let (['b' | 'c', 'r', rest @ ..] | ['r', rest @ ..]) = rest else {
        return None;
    };
    let hashes = rest.iter().take_while(|c| **c == '#').count();
    (rest.get(hashes) == Some(&'"')).then_some(hashes)
}

/// The 1-based line of a byte offset into `text`.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(0, |before| before.matches('\n').count())
        .saturating_add(1)
}

/// Byte offsets of `needle` in `haystack` where it is not part of a longer identifier.
pub(crate) fn word_offsets<'a>(
    haystack: &'a str,
    needle: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    haystack
        .match_indices(needle)
        .filter_map(move |(start, _)| {
            let before = haystack.get(..start)?.chars().next_back();
            let after = haystack
                .get(start.checked_add(needle.len())?..)?
                .chars()
                .next();
            let bounded =
                before.is_none_or(|c| !is_ident_char(c)) && after.is_none_or(|c| !is_ident_char(c));
            bounded.then_some(start)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blanks_comments_strings_and_chars_but_keeps_code_and_lines() {
        let source = "let a = \"std::fs\"; // std::fs\n/* outer /* std::net */ still */ let b = 'x';\nlet c = r#\"tokio \"# ; let d: &'static str = br\"x\";\nlet e = '\\'';\nuse std::fs;\n";
        let code = code_only(source);
        assert_eq!(code.lines().count(), source.lines().count());
        assert_eq!(word_offsets(&code, "std").count(), 1);
        assert!(code.contains("'static"));
        assert!(!code.contains("tokio"));
        assert!(code.contains("use std::fs;"));
        let fs = word_offsets(&code, "fs").next().unwrap();
        assert_eq!(line_of(&code, fs), 5);
    }

    #[test]
    fn word_offsets_respect_identifier_boundaries() {
        let text = "Instant Instantly my_Instant (Instant)";
        assert_eq!(word_offsets(text, "Instant").collect::<Vec<_>>(), [0, 30]);
    }
}
