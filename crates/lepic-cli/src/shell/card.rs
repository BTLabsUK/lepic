// SPDX-License-Identifier: Apache-2.0
//! The welcome card the interactive shell prints at start, and the epic1 mark shown beside epic1
//! addresses. The card carries the LEPIC banner only; the epic1 mark never appears in it.

#![allow(dead_code)]

/// Which character set the terminal can draw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Glyphs {
    Unicode,
    Ascii,
}

/// What the card says about the running session.
pub(crate) struct CardInfo<'a> {
    pub version: &'a str,
    pub wallet: &'a str,
    pub network: &'a str,
}

const BANNER: [&str; 5] = [
    "██       ███████  ██████   ██   ██████",
    "██       ██       ██   ██  ██  ██",
    "██       █████    ██████   ██  ██",
    "██       ██       ██       ██  ██",
    "███████  ███████  ██       ██   ██████",
];

const SIDE_BY_SIDE_MIN: u16 = 80;
const BANNER_MIN: u16 = 44;
const BOX_MIN: u16 = 24;
const BANNER_GAP: usize = 2;

const ACCENT: &str = "\x1b[38;2;246;212;113m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Plain,
    Bold,
    Dim,
    Accent,
}

impl Style {
    fn open(self) -> &'static str {
        match self {
            Style::Plain => "",
            Style::Bold => BOLD,
            Style::Dim => DIM,
            Style::Accent => ACCENT,
        }
    }
}

struct Span {
    text: String,
    style: Style,
}

type Line = Vec<Span>;

fn span(text: impl Into<String>, style: Style) -> Span {
    Span {
        text: text.into(),
        style,
    }
}

fn width(line: &Line) -> usize {
    line.iter().map(|s| s.text.chars().count()).sum()
}

fn render(line: &Line, color: bool) -> String {
    let mut out = String::new();
    for s in line {
        if color && s.style != Style::Plain && !s.text.is_empty() {
            out.push_str(s.style.open());
            out.push_str(&s.text);
            out.push_str(RESET);
        } else {
            out.push_str(&s.text);
        }
    }
    out
}

fn localize(line: Line, glyphs: Glyphs) -> Line {
    if glyphs == Glyphs::Unicode {
        return line;
    }
    line.into_iter()
        .map(|s| span(s.text.replace('·', "-").replace('→', "->"), s.style))
        .collect()
}

/// Cuts the line to `max` cells, ending in an ellipsis when something was removed.
fn fit(line: Line, max: usize, glyphs: Glyphs) -> Line {
    if width(&line) <= max {
        return line;
    }
    let ellipsis = match glyphs {
        Glyphs::Unicode => "…",
        Glyphs::Ascii => "...",
    };
    let keep = max.saturating_sub(ellipsis.chars().count());
    let mut left = keep;
    let mut out = Line::new();
    for s in line {
        if left == 0 {
            break;
        }
        let taken: String = s.text.chars().take(left).collect();
        left = left.saturating_sub(taken.chars().count());
        out.push(span(taken, s.style));
    }
    if keep == 0 {
        out.clear();
        let cut: String = ellipsis.chars().take(max).collect();
        out.push(span(cut, Style::Dim));
    } else {
        out.push(span(ellipsis, Style::Dim));
    }
    out
}

fn banner_width() -> usize {
    BANNER.iter().map(|r| r.chars().count()).max().unwrap_or(0)
}

fn banner_line(index: usize, glyphs: Glyphs) -> Line {
    let row = BANNER.get(index).copied().unwrap_or("");
    let text = match glyphs {
        Glyphs::Unicode => row.to_owned(),
        Glyphs::Ascii => row.replace('█', "#"),
    };
    vec![span(text, Style::Bold)]
}

fn title(info: &CardInfo<'_>) -> Line {
    vec![span(format!("LEPIC {}", info.version), Style::Bold)]
}

fn wallet_line(info: &CardInfo<'_>) -> Line {
    vec![
        span("wallet ", Style::Dim),
        span(info.wallet, Style::Plain),
        span(" · ", Style::Dim),
        span(info.network, Style::Plain),
    ]
}

fn hint(label: &str, rest: &str) -> Line {
    let mut line = Line::new();
    if !label.is_empty() {
        line.push(span(label, Style::Dim));
    }
    line.push(span(rest, Style::Plain));
    line
}

/// The text of the card in five rows, to sit beside the five-row banner.
fn text_wide(info: &CardInfo<'_>) -> Vec<Line> {
    vec![
        title(info),
        wallet_line(info),
        hint("Start with: ", "help or ?"),
        hint("", "Tab completes   exit leaves"),
        hint("", "→ accepts a suggestion"),
    ]
}

/// The text of the card with one hint per line.
fn text_narrow(info: &CardInfo<'_>) -> Vec<Line> {
    vec![
        title(info),
        wallet_line(info),
        Line::new(),
        hint("Start with: ", "help or ?"),
        hint("", "Tab completes"),
        hint("", "→ accepts a suggestion"),
        hint("", "exit leaves"),
    ]
}

/// The welcome card, one string per line without a trailing newline. No line is wider than
/// `columns - 1` cells, so the last column stays free.
pub(crate) fn welcome(
    info: &CardInfo<'_>,
    columns: u16,
    glyphs: Glyphs,
    color: bool,
) -> Vec<String> {
    let max = usize::from(columns.saturating_sub(1));
    let body: Vec<Line> = if columns < BOX_MIN {
        let mut lines = text_narrow(info);
        lines.retain(|l| !l.is_empty());
        return lines
            .into_iter()
            .map(|l| render(&fit(localize(l, glyphs), max, glyphs), color))
            .collect();
    } else if columns < BANNER_MIN {
        text_narrow(info)
    } else if columns < SIDE_BY_SIDE_MIN {
        let mut lines: Vec<Line> = (0..BANNER.len()).map(|i| banner_line(i, glyphs)).collect();
        lines.push(Line::new());
        lines.extend(text_narrow(info));
        lines
    } else {
        let text = text_wide(info);
        let pad = banner_width().saturating_add(BANNER_GAP);
        (0..BANNER.len())
            .map(|i| {
                let mut line = banner_line(i, glyphs);
                let used = width(&line);
                line.push(span(" ".repeat(pad.saturating_sub(used)), Style::Plain));
                line.extend(text.get(i).map(clone_line).unwrap_or_default());
                line
            })
            .collect()
    };
    boxed(body, max, glyphs, color)
}

fn clone_line(line: &Line) -> Line {
    line.iter().map(|s| span(s.text.clone(), s.style)).collect()
}

fn boxed(body: Vec<Line>, max: usize, glyphs: Glyphs, color: bool) -> Vec<String> {
    let inner_max = max.saturating_sub(4);
    let body: Vec<Line> = body
        .into_iter()
        .map(|l| fit(localize(l, glyphs), inner_max, glyphs))
        .collect();
    let inner = body.iter().map(width).max().unwrap_or(0);
    let (tl, tr, bl, br, h, v) = match glyphs {
        Glyphs::Unicode => ('╭', '╮', '╰', '╯', '─', '│'),
        Glyphs::Ascii => ('+', '+', '+', '+', '-', '|'),
    };
    let rule = h.to_string().repeat(inner.saturating_add(2));
    let mut out = vec![format!("{tl}{rule}{tr}")];
    for line in &body {
        let fill = " ".repeat(inner.saturating_sub(width(line)));
        out.push(format!("{v} {}{fill} {v}", render(line, color)));
    }
    out.push(format!("{bl}{rule}{br}"));
    out
}

const MARK: [&str; 5] = [".#..#..", "##....#", ".#.#...", ".#...#.", "###.#.."];
const MARK_DIGIT_COLUMNS: usize = 3;

/// The epic1 mark: a "1" in the accent colour among dim noise cells, with clear space of two
/// cells on every side. Without colour the noise is drawn lighter so the "1" still reads.
pub(crate) fn epic1_mark(glyphs: Glyphs, color: bool) -> Vec<String> {
    let (solid, noise) = match glyphs {
        Glyphs::Unicode => ("██", "▒▒"),
        Glyphs::Ascii => ("##", "++"),
    };
    let mut out = vec![String::new()];
    for row in MARK {
        let mut line = String::from("  ");
        for (column, cell) in row.chars().enumerate() {
            if cell != '#' {
                line.push_str("  ");
            } else if column < MARK_DIGIT_COLUMNS {
                if color {
                    line.push_str(&format!("{ACCENT}{solid}{RESET}"));
                } else {
                    line.push_str(solid);
                }
            } else if color {
                line.push_str(&format!("{DIM}{solid}{RESET}"));
            } else {
                line.push_str(noise);
            }
        }
        line.push_str("  ");
        out.push(line);
    }
    out.push(String::new());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTHS: [u16; 6] = [24, 40, 60, 80, 112, 200];

    fn info() -> CardInfo<'static> {
        CardInfo {
            version: "0.5.0",
            wallet: "main",
            network: "mainnet",
        }
    }

    fn visible_width(line: &str) -> usize {
        let mut n: usize = 0;
        let mut in_escape = false;
        for c in line.chars() {
            match (in_escape, c) {
                (false, '\x1b') => in_escape = true,
                (true, 'm') => in_escape = false,
                (true, _) => {}
                (false, _) => n = n.saturating_add(1),
            }
        }
        n
    }

    fn all_cases() -> Vec<(u16, Glyphs, bool, Vec<String>)> {
        let mut cases = Vec::new();
        for columns in WIDTHS.into_iter().chain([0, 10, 23, 43, 79]) {
            for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
                for color in [false, true] {
                    cases.push((
                        columns,
                        glyphs,
                        color,
                        welcome(&info(), columns, glyphs, color),
                    ));
                }
            }
        }
        cases
    }

    #[test]
    fn no_line_is_wider_than_the_terminal_minus_one() {
        for (columns, _, _, lines) in all_cases() {
            for line in lines {
                assert!(
                    visible_width(&line) < usize::from(columns).max(1),
                    "{columns}: {line:?}"
                );
            }
        }
    }

    #[test]
    fn ascii_output_is_ascii() {
        for (columns, glyphs, color, lines) in all_cases() {
            if glyphs == Glyphs::Ascii {
                assert!(lines.iter().all(|l| l.is_ascii()), "{columns} {color}");
            }
        }
        for color in [false, true] {
            assert!(
                epic1_mark(Glyphs::Ascii, color)
                    .iter()
                    .all(|l| l.is_ascii())
            );
        }
    }

    #[test]
    fn colour_off_has_no_escape_codes() {
        for (columns, _, color, lines) in all_cases() {
            if !color {
                assert!(lines.iter().all(|l| !l.contains('\x1b')), "{columns}");
            }
        }
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            assert!(
                epic1_mark(glyphs, false)
                    .iter()
                    .all(|l| !l.contains('\x1b'))
            );
        }
    }

    #[test]
    fn version_and_wallet_appear_when_there_is_room() {
        for (columns, _, _, lines) in all_cases() {
            if columns >= 40 {
                let text = lines.join("\n");
                assert!(text.contains("LEPIC 0.5.0"), "{columns}");
                assert!(text.contains("main"), "{columns}");
            }
        }
    }

    #[test]
    fn layout_follows_the_width() {
        let rows = |columns| welcome(&info(), columns, Glyphs::Unicode, false).len();
        assert_eq!(rows(112), 7);
        assert!(rows(60) > rows(112));
        assert!(rows(40) < rows(60));
        assert!(
            welcome(&info(), 20, Glyphs::Unicode, false)
                .iter()
                .all(|l| !l.contains('╭'))
        );
        assert!(
            welcome(&info(), 40, Glyphs::Unicode, false)
                .iter()
                .all(|l| !l.contains('█'))
        );
    }

    #[test]
    fn eighty_columns_cut_nothing() {
        let text = welcome(&info(), 80, Glyphs::Unicode, false).join("\n");
        assert!(!text.contains('…'));
        assert!(text.contains("→ accepts a suggestion"));
    }

    #[test]
    fn long_text_is_cut_with_an_ellipsis() {
        let long = CardInfo {
            version: "0.5.0",
            wallet: "a-wallet-with-a-very-long-name-indeed",
            network: "mainnet",
        };
        let unicode = welcome(&long, 40, Glyphs::Unicode, false).join("\n");
        assert!(unicode.contains('…'));
        let ascii = welcome(&long, 40, Glyphs::Ascii, false).join("\n");
        assert!(ascii.contains("..."));
    }

    #[test]
    fn card_never_holds_the_epic1_mark() {
        for (_, _, _, lines) in all_cases() {
            let text = lines.join("\n");
            assert!(!text.contains('▒'));
            assert!(!text.contains("++"));
            assert!(!text.contains("\x1b[38;2;246;212;113m"));
        }
    }

    #[test]
    fn mark_has_clear_space_and_a_readable_one() {
        let plain = epic1_mark(Glyphs::Unicode, false);
        assert_eq!(plain.len(), 7);
        assert!(plain[0].is_empty() && plain[6].is_empty());
        assert!(
            plain[1..6]
                .iter()
                .all(|l| l.starts_with("  ") && l.ends_with("  "))
        );
        assert!(
            plain
                .iter()
                .all(|l| visible_width(l) == 0 || visible_width(l) == 18)
        );
        assert_eq!(plain[1], "    ██    ▒▒      ");
        assert_eq!(plain[2], "  ████        ▒▒  ");
        let coloured = epic1_mark(Glyphs::Unicode, true).join("\n");
        assert!(coloured.contains(ACCENT) && coloured.contains(DIM));
        assert!(!coloured.contains('▒'));
    }
}
