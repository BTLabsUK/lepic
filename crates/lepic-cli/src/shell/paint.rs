// SPDX-License-Identifier: Apache-2.0
//! The shell's colours: the sixteen basic ANSI colours with bold and dim, which every terminal
//! the shell runs in draws, Windows conhost and Windows Terminal included. With colour off
//! nothing here writes an escape sequence, so `NO_COLOR` and a terminal without colour get the
//! same text, unstyled. Text is measured and cut before it is styled: a row is as wide with
//! colour as without.

/// How a piece of text is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Plain,
    Bold,
    Dim,
    Yellow,
    YellowBold,
    Green,
    Red,
    RedBold,
    Cyan,
    CyanBold,
}

pub(crate) const RESET: &str = "\x1b[0m";

impl Tone {
    const fn sgr(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Bold => "\x1b[1m",
            Self::Dim => "\x1b[2m",
            Self::Yellow => "\x1b[33m",
            Self::YellowBold => "\x1b[1;33m",
            Self::Green => "\x1b[32m",
            Self::Red => "\x1b[31m",
            Self::RedBold => "\x1b[1;31m",
            Self::Cyan => "\x1b[36m",
            Self::CyanBold => "\x1b[1;36m",
        }
    }
}

/// `text` in `tone`, or as it is with colour off.
pub(crate) fn tint(text: &str, tone: Tone, on: bool) -> String {
    if !on || tone == Tone::Plain || text.is_empty() {
        return text.to_owned();
    }
    format!("{}{text}{RESET}", tone.sgr())
}

/// A row as pieces of text, each with its tone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Spans(Vec<(String, Tone)>);

impl Spans {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn of(text: impl Into<String>, tone: Tone) -> Self {
        let mut spans = Self::new();
        spans.push(text, tone);
        spans
    }

    pub(crate) fn push(&mut self, text: impl Into<String>, tone: Tone) {
        let text = text.into();
        if !text.is_empty() {
            self.0.push((text, tone));
        }
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// The pieces joined by `sep`.
    pub(crate) fn join(parts: Vec<Self>, sep: &Self) -> Self {
        let mut out = Self::new();
        for (index, part) in parts.into_iter().enumerate() {
            if index > 0 {
                out.extend(sep.clone());
            }
            out.extend(part);
        }
        out
    }

    pub(crate) fn width(&self) -> usize {
        self.0.iter().map(|(text, _)| cells(text)).sum()
    }

    /// The row cut to `columns - 1` cells.
    pub(crate) fn cut(self, columns: u16) -> Self {
        let mut left = usize::from(columns.saturating_sub(1));
        let mut out = Self::new();
        for (text, tone) in self.0 {
            if left == 0 {
                break;
            }
            let taken = take_cells(&text, left);
            left = left.saturating_sub(cells(&taken));
            out.push(taken, tone);
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn plain(&self) -> String {
        self.0.iter().map(|(text, _)| text.as_str()).collect()
    }

    pub(crate) fn render(&self, on: bool) -> String {
        self.0
            .iter()
            .map(|(text, tone)| tint(text, *tone, on))
            .collect()
    }
}

/// Whether `word` reads as an amount: `1.50000000`, `10.992`.
fn is_amount(word: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == ',');
    match word.split_once('.') {
        Some((whole, fraction)) => {
            digits(whole) && !fraction.is_empty() && fraction.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// A table header: two or more words, all upper case.
fn is_header(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words.len() >= 2
        && line.chars().any(|c| c.is_ascii_uppercase())
        && !line.chars().any(char::is_lowercase)
}

/// Amounts in bold, the rest in `base`. In a line of `base` colour only an amount followed by
/// `EPIC` counts.
fn amounts(line: &str, base: Tone, on: bool) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while !rest.is_empty() {
        let start = rest
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(rest.len());
        let (space, word_on) = rest.split_at(start);
        out.push_str(&tint(space, base, on));
        if word_on.is_empty() {
            break;
        }
        let end = word_on.find(char::is_whitespace).unwrap_or(word_on.len());
        let (word, after) = word_on.split_at(end);
        let bare = word.trim_start_matches(['+', '-', '(']);
        let lead = word.len().saturating_sub(bare.len());
        let (prefix, number) = word.split_at(lead);
        let followed_by_epic = after.trim_start().starts_with("EPIC");
        if is_amount(number.trim_end_matches([',', ')', '.']))
            && (followed_by_epic || base == Tone::Plain)
        {
            let trimmed = number.trim_end_matches([',', ')', '.']);
            let tail = number.get(trimmed.len()..).unwrap_or("");
            out.push_str(&tint(prefix, base, on));
            out.push_str(&tint(trimmed, Tone::Bold, on));
            out.push_str(&tint(tail, base, on));
        } else {
            out.push_str(&tint(word, base, on));
        }
        rest = after;
    }
    out
}

/// The text a command printed, coloured as the shell shows it: `error:` red, `hint:` cyan,
/// `warning:` yellow, table headers dim, amounts bold, and the first line of `success` green.
pub(crate) fn output(text: &str, success: bool, on: bool) -> String {
    if !on {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len().saturating_add(64));
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        out.push_str(&output_line(body, success && index == 0, on));
        out.push_str(newline);
    }
    out
}

fn output_line(line: &str, first_of_success: bool, on: bool) -> String {
    for (label, tone) in [
        ("error:", Tone::RedBold),
        ("hint:", Tone::CyanBold),
        ("warning:", Tone::YellowBold),
    ] {
        if let Some(rest) = line.strip_prefix(label) {
            return format!("{}{}", tint(label, tone, on), hint_rest(rest, label, on));
        }
    }
    if is_header(line) {
        return tint(line, Tone::Dim, on);
    }
    if first_of_success {
        return amounts(line, Tone::Green, on);
    }
    amounts(line, Tone::Plain, on)
}

/// After `hint:`, a suggested command (`did you mean tx list?`) in bold.
fn hint_rest(rest: &str, label: &str, on: bool) -> String {
    if label == "hint:"
        && let Some(command) = rest
            .strip_prefix(" did you mean ")
            .and_then(|c| c.strip_suffix('?'))
    {
        return format!(" did you mean {}?", tint(command, Tone::Bold, on));
    }
    rest.to_owned()
}

/// The shell's help: section titles bold, command names cyan, the closing note dim.
pub(crate) fn help(lines: &[String], on: bool) -> Vec<String> {
    let last = lines.len().saturating_sub(1);
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if !on || line.is_empty() {
                line.clone()
            } else if index == last {
                tint(line, Tone::Dim, on)
            } else if let Some(row) = line.strip_prefix("  ") {
                let end = row.find("  ").unwrap_or(row.len());
                let (name, what) = row.split_at(end);
                format!("  {}{what}", tint(name, Tone::CyanBold, on))
            } else {
                tint(line, Tone::Bold, on)
            }
        })
        .collect()
}

/// Clap's help and errors: `error:` and `hint:` as in [`output`], section titles (`Usage:`,
/// `Options:`) bold, and the names in each entry cyan.
pub(crate) fn clap_text(text: &str, on: bool) -> String {
    if !on {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len().saturating_add(64));
    for line in text.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let painted = if let Some(rest) = body.strip_prefix("Usage:") {
            format!("{}{rest}", tint("Usage:", Tone::Bold, on))
        } else if !body.starts_with(' ') && body.ends_with(':') && !body.contains(' ') {
            tint(body, Tone::Bold, on)
        } else if let Some(row) = body.strip_prefix("  ")
            && row.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-')
        {
            let end = row.find("  ").unwrap_or(row.len());
            let (name, what) = row.split_at(end);
            format!("  {}{what}", tint(name, Tone::Cyan, on))
        } else {
            output_line(body, false, on)
        };
        out.push_str(&painted);
        out.push_str(newline);
    }
    out
}

/// The send review: labels dim, the total bold, the warning yellow.
pub(crate) fn review(lines: &[String], on: bool) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            if !on {
                return line.clone();
            }
            let Some(row) = line.strip_prefix("  ") else {
                return tint(line, Tone::YellowBold, on);
            };
            let end = row.find("  ").unwrap_or(row.len());
            let (label, value) = row.split_at(end);
            let value = if label == "Total" {
                tint(value, Tone::Bold, on)
            } else {
                value.to_owned()
            };
            format!("  {}{value}", tint(label, Tone::Dim, on))
        })
        .collect()
}

/// `text` without its SGR sequences.
#[cfg(test)]
pub(crate) fn strip(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Rows of `Label    value`: the labels dim.
pub(crate) fn labels(lines: &[String], on: bool) -> Vec<String> {
    lines
        .iter()
        .map(|line| match line.find("  ") {
            Some(end) if on && end > 0 => {
                let (label, value) = line.split_at(end);
                format!("{}{value}", tint(label, Tone::Dim, on))
            }
            _ => line.clone(),
        })
        .collect()
}

/// The cells `text` takes on a terminal: wide characters take two, combining marks none.
pub(crate) fn cells(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

/// The start of `text` that fits in `max` cells; a wide character that would cross the edge is
/// left out.
pub(crate) fn take_cells(text: &str, max: usize) -> String {
    let mut used: usize = 0;
    let mut out = String::new();
    for character in text.chars() {
        let width = unicode_width::UnicodeWidthChar::width(character).unwrap_or(0);
        match used.checked_add(width) {
            Some(next) if next <= max => used = next,
            _ => break,
        }
        out.push(character);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wide characters count two cells, and a cut never splits one at the edge.
    #[test]
    fn widths_count_terminal_cells() {
        assert_eq!(cells("wallet"), 6);
        assert_eq!(cells("財布"), 4);
        assert_eq!(cells("e\u{301}"), 1);
        assert_eq!(take_cells("財布です", 5), "財布");
        assert_eq!(take_cells("ab", 0), "");
    }

    #[test]
    fn colour_off_writes_no_escape() {
        let text = "Transaction 3 sent 1.50000000 EPIC (fee 0.00800000) by epicbox.\n\
                    ID  DIR  STATE\nerror: unknown command: tx lsit\nhint: did you mean tx list?\n";
        assert_eq!(output(text, true, false), text);
        assert_eq!(tint("x", Tone::Red, false), "x");
        let spans = Spans::of("a", Tone::Bold);
        assert_eq!(spans.render(false), "a");
        let lines = vec!["Shell".to_owned(), "  exit  leaves".to_owned()];
        assert_eq!(help(&lines, false), lines);
        assert_eq!(review(&lines, false), lines);
    }

    #[test]
    fn output_is_coloured_by_kind() {
        let painted = output(
            "Transaction 3 sent 1.50000000 EPIC (fee 0.00800000) by epicbox.\nSlate x.\n",
            true,
            true,
        );
        assert!(painted.starts_with("\u{1b}[32mTransaction"), "{painted:?}");
        assert!(
            painted.contains("\u{1b}[1m1.50000000\u{1b}[0m"),
            "{painted:?}"
        );
        assert!(painted.ends_with("Slate x.\n"), "{painted:?}");
        let error = output(
            "error: unknown command: tx lsit\nhint: did you mean tx list?\n",
            false,
            true,
        );
        assert!(
            error.starts_with("\u{1b}[1;31merror:\u{1b}[0m unknown"),
            "{error:?}"
        );
        assert!(
            error.contains("\u{1b}[1;36mhint:\u{1b}[0m did you mean \u{1b}[1mtx list\u{1b}[0m?")
        );
        let table = output("ID  DIR  AMOUNT\n3   send 1.50000000\n", false, true);
        assert!(
            table.starts_with("\u{1b}[2mID  DIR  AMOUNT\u{1b}[0m\n"),
            "{table:?}"
        );
        assert!(table.contains("\u{1b}[1m1.50000000\u{1b}[0m"), "{table:?}");
    }

    #[test]
    fn cut_counts_text_only() {
        let mut spans = Spans::of("abc", Tone::Dim);
        spans.push("def", Tone::Bold);
        let cut = spans.cut(5);
        assert_eq!(cut.plain(), "abcd");
        assert_eq!(cut.render(true), "\u{1b}[2mabc\u{1b}[0m\u{1b}[1md\u{1b}[0m");
    }
}
