// SPDX-License-Identifier: Apache-2.0
//! The welcome card the interactive shell prints at start, and the epic1 mark shown beside epic1
//! addresses. The card carries the lepic wordmark only; the epic1 mark never appears in it, as
//! both branding packs keep the marks apart and never lock them up.
//!
//! The wordmark follows the LEPIC branding pack: the word `lepic` with its l drawn as a bar in
//! Phosphor green and the letters `epic` in the terminal's own text colour. Never a green word.
//! On 16-colour terminals Phosphor is the basic green (`32`), which every console draws.

use super::paint::{Paint, Tone, cells, take_cells, tint};

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

/// The bar of the wordmark, in the rows it fills. It is wider than a letter stem, two and a half
/// cells against a five-cell letter, as in the pack's geometry (24 of 58 units).
const BAR: &str = "██▌";
const BAR_ROWS: usize = 4;
/// Cells between the bar and the e.
const BAR_GAP: &str = "  ";
/// `epic` in Red Hat Mono's lowercase shapes, two pixels a row: an ascender row with the dot of
/// the i, three rows of x-height ending on the baseline, where the bar ends too, and a
/// descender row for the p.
const LETTERS: [&str; 5] = [
    "              ▀",
    "▄▀▀▀▄ █▀▀▀▄ ▀▀█   ▄▀▀▀▀",
    "█▀▀▀▀ █   █   █   █",
    "▀▄▄▄▀ █▄▄▄▀   █▄▄ ▀▄▄▄▄",
    "      █",
];
/// The cells a letter of the wordmark takes with the space after it.
const LETTER_PITCH: usize = 6;
/// The inline mark for cards too narrow for the wordmark: U+258C, then the letters.
const MARK_BAR: &str = "▌";
const MARK_LETTERS: &str = "epic";

/// The frames of the sweep, the pack's start animation: the bar starts where the c stands and
/// moves one letter left a frame, the letters appear behind it, and it parks as the l.
pub(crate) const SWEEP_STEPS: usize = 4;

const SIDE_BY_SIDE_MIN: u16 = 80;
const BANNER_MIN: u16 = 44;
const BOX_MIN: u16 = 24;
const BANNER_GAP: usize = 2;

#[cfg_attr(not(test), allow(dead_code))]
const ACCENT: &str = "\x1b[38;2;246;212;113m";
#[cfg_attr(not(test), allow(dead_code))]
const DIM: &str = "\x1b[2m";
#[cfg_attr(not(test), allow(dead_code))]
const RESET: &str = "\x1b[0m";

struct Span {
    text: String,
    tone: Tone,
}

type Line = Vec<Span>;

fn span(text: impl Into<String>, tone: Tone) -> Span {
    Span {
        text: text.into(),
        tone,
    }
}

fn width(line: &Line) -> usize {
    line.iter().map(|s| cells(&s.text)).sum()
}

fn render(line: &Line, paint: Paint) -> String {
    line.iter().map(|s| tint(&s.text, s.tone, paint)).collect()
}

fn localize(line: Line, glyphs: Glyphs) -> Line {
    if glyphs == Glyphs::Unicode {
        return line;
    }
    line.into_iter()
        .map(|s| span(s.text.replace('·', "-").replace('→', "->"), s.tone))
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
    let keep = max.saturating_sub(cells(ellipsis));
    let mut left = keep;
    let mut out = Line::new();
    for s in line {
        if left == 0 {
            break;
        }
        let taken = take_cells(&s.text, left);
        left = left.saturating_sub(cells(&taken));
        out.push(span(taken, s.tone));
    }
    if keep == 0 {
        out.clear();
        let cut = take_cells(ellipsis, max);
        out.push(span(cut, Tone::Dim));
    } else {
        out.push(span(ellipsis, Tone::Dim));
    }
    out
}

const BANNER_ROWS: usize = LETTERS.len();

/// Half blocks drawn in ASCII: a full cell, the top half and the bottom half.
fn ascii(text: &str) -> String {
    text.replace(['█', '▌'], "#")
        .replace('▀', "\"")
        .replace('▄', "_")
}

fn drawn(text: &str, glyphs: Glyphs) -> String {
    match glyphs {
        Glyphs::Unicode => text.to_owned(),
        Glyphs::Ascii => ascii(text),
    }
}

fn banner_width() -> usize {
    let letters = LETTERS.iter().map(|r| cells(r)).max().unwrap_or(0);
    cells(BAR)
        .saturating_add(cells(BAR_GAP))
        .saturating_add(letters)
}

/// Row `index` of the wordmark at `step` of the sweep: the bar `step` letters to the right of
/// its place, and only the letters behind it. Step 0 is the wordmark at rest.
fn banner_line(index: usize, glyphs: Glyphs, step: usize) -> Line {
    let shift = step.saturating_mul(LETTER_PITCH);
    let bar = if index < BAR_ROWS {
        span(drawn(BAR, glyphs), Tone::Green)
    } else {
        span(" ".repeat(cells(BAR)), Tone::Plain)
    };
    let letters: String = LETTERS
        .get(index)
        .copied()
        .unwrap_or("")
        .chars()
        .skip(shift)
        .collect();
    vec![
        span(" ".repeat(shift), Tone::Plain),
        bar,
        span(BAR_GAP, Tone::Plain),
        span(drawn(&letters, glyphs), Tone::Plain),
    ]
}

/// The one-line mark, `▌epic`, with the pack's tagline once the sweep has ended.
fn mark_line(glyphs: Glyphs, step: usize) -> Line {
    let letters: String = MARK_LETTERS.chars().skip(step).collect();
    let mut line = vec![
        span(" ".repeat(step), Tone::Plain),
        span(drawn(MARK_BAR, glyphs), Tone::Green),
        span(letters, Tone::Bold),
    ];
    if step == 0 {
        line.push(span("  light Epic", Tone::Dim));
    }
    line
}

fn title(info: &CardInfo<'_>, tagline: bool) -> Line {
    let mut line = vec![
        span("LEPIC", Tone::Bold),
        span(format!(" {}", info.version), Tone::Dim),
    ];
    if tagline {
        line.push(span(" · light Epic wallet core", Tone::Dim));
    }
    line
}

fn wallet_line(info: &CardInfo<'_>) -> Line {
    vec![
        span("wallet ", Tone::Dim),
        span(info.wallet, Tone::Bold),
        span(" · ", Tone::Rule),
        span(info.network, Tone::Plain),
    ]
}

/// `key what it does` pieces with a dot between them: each key plain, the rest dim.
fn keys(pairs: &[(&str, &str)]) -> Line {
    let mut line = Line::new();
    for (index, (key, what)) in pairs.iter().enumerate() {
        if index > 0 {
            line.push(span(" · ", Tone::Rule));
        }
        line.push(span(*key, Tone::Plain));
        line.push(span(format!(" {what}"), Tone::Dim));
    }
    line
}

/// The text of the card in five rows, to sit beside the five-row wordmark.
fn text_wide(info: &CardInfo<'_>) -> Vec<Line> {
    vec![
        title(info, true),
        wallet_line(info),
        Line::new(),
        keys(&[
            ("?", "help"),
            ("Tab", "complete"),
            ("→", "accept suggestion"),
        ]),
        keys(&[("exit", "leaves"), ("Ctrl+C", "cancel")]),
    ]
}

/// The text of the card with one hint per line.
fn text_narrow(info: &CardInfo<'_>) -> Vec<Line> {
    vec![
        title(info, false),
        wallet_line(info),
        Line::new(),
        keys(&[("?", "help")]),
        keys(&[("Tab", "complete")]),
        keys(&[("→", "accept suggestion")]),
        keys(&[("exit", "leaves")]),
    ]
}

/// The welcome card, one string per line without a trailing newline. No line is wider than
/// `columns - 1` cells, so the last column stays free.
pub(crate) fn welcome(
    info: &CardInfo<'_>,
    columns: u16,
    glyphs: Glyphs,
    paint: Paint,
) -> Vec<String> {
    frame(info, columns, glyphs, paint, 0)
}

/// The card at each step of the sweep, the last of them the card at rest. Every frame has the
/// same rows, so one is drawn over the other.
pub(crate) fn sweep(
    info: &CardInfo<'_>,
    columns: u16,
    glyphs: Glyphs,
    paint: Paint,
) -> Vec<Vec<String>> {
    (0..=SWEEP_STEPS)
        .rev()
        .map(|step| frame(info, columns, glyphs, paint, step))
        .collect()
}

fn frame(
    info: &CardInfo<'_>,
    columns: u16,
    glyphs: Glyphs,
    paint: Paint,
    step: usize,
) -> Vec<String> {
    let max = usize::from(columns.saturating_sub(1));
    let body: Vec<Line> = if columns < BOX_MIN {
        let mut lines = vec![mark_line(glyphs, step)];
        lines.extend(text_narrow(info));
        lines.retain(|l| !l.is_empty());
        return lines
            .into_iter()
            .map(|l| render(&fit(localize(l, glyphs), max, glyphs), paint))
            .collect();
    } else if columns < BANNER_MIN {
        let mut lines = vec![mark_line(glyphs, step), Line::new()];
        lines.extend(text_narrow(info));
        lines
    } else if columns < SIDE_BY_SIDE_MIN {
        let mut lines: Vec<Line> = (0..BANNER_ROWS)
            .map(|i| banner_line(i, glyphs, step))
            .collect();
        lines.push(Line::new());
        lines.extend(text_narrow(info));
        lines
    } else {
        let text = text_wide(info);
        let pad = banner_width().saturating_add(BANNER_GAP);
        (0..BANNER_ROWS)
            .map(|i| {
                let mut line = banner_line(i, glyphs, step);
                let used = width(&line);
                line.push(span(" ".repeat(pad.saturating_sub(used)), Tone::Plain));
                line.extend(text.get(i).map(clone_line).unwrap_or_default());
                line
            })
            .collect()
    };
    boxed(body, max, glyphs, paint)
}

fn clone_line(line: &Line) -> Line {
    line.iter().map(|s| span(s.text.clone(), s.tone)).collect()
}

fn boxed(body: Vec<Line>, max: usize, glyphs: Glyphs, paint: Paint) -> Vec<String> {
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
    let edge = |text: String| tint(&text, Tone::Rule, paint);
    let side = edge(v.to_string());
    let mut out = vec![edge(format!("{tl}{rule}{tr}"))];
    for line in &body {
        let fill = " ".repeat(inner.saturating_sub(width(line)));
        out.push(format!("{side} {}{fill} {side}", render(line, paint)));
    }
    out.push(edge(format!("{bl}{rule}{br}")));
    out
}

// The mark waits for the shell to print epic1 addresses beside it.
#[cfg_attr(not(test), allow(dead_code))]
const MARK: [&str; 5] = [".#..#..", "##....#", ".#.#...", ".#...#.", "###.#.."];
#[cfg_attr(not(test), allow(dead_code))]
const MARK_DIGIT_COLUMNS: usize = 3;

/// The epic1 mark: a "1" in the accent colour among dim noise cells, with clear space of two
/// cells on every side. Without colour the noise is drawn lighter so the "1" still reads.
#[cfg_attr(not(test), allow(dead_code))]
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
    use crate::shell::paint::strip;

    const WIDTHS: [u16; 6] = [24, 40, 60, 80, 112, 200];
    const PAINTS: [Paint; 4] = [Paint::Off, Paint::Ansi, Paint::Night, Paint::Paper];
    const GREEN: &str = "\x1b[32m";

    fn info() -> CardInfo<'static> {
        CardInfo {
            version: "0.5.0",
            wallet: "main",
            network: "mainnet",
        }
    }

    fn visible_width(line: &str) -> usize {
        cells(&strip(line))
    }

    fn all_cases() -> Vec<(u16, Glyphs, Paint, Vec<String>)> {
        let mut cases = Vec::new();
        for columns in WIDTHS.into_iter().chain([0, 10, 23, 43, 79]) {
            for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
                for paint in PAINTS {
                    for frame in sweep(&info(), columns, glyphs, paint) {
                        cases.push((columns, glyphs, paint, frame));
                    }
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
        for (columns, glyphs, paint, lines) in all_cases() {
            if glyphs == Glyphs::Ascii {
                assert!(lines.iter().all(|l| l.is_ascii()), "{columns} {paint:?}");
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
        for (columns, _, paint, lines) in all_cases() {
            if !paint.on() {
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
    fn the_text_is_the_same_in_every_palette() {
        for columns in WIDTHS {
            let plain = welcome(&info(), columns, Glyphs::Unicode, Paint::Off);
            for paint in PAINTS {
                let painted = welcome(&info(), columns, Glyphs::Unicode, paint);
                let shown: Vec<String> = painted.iter().map(|line| strip(line)).collect();
                assert_eq!(shown, plain, "{columns} {paint:?}");
            }
        }
    }

    #[test]
    fn version_and_wallet_appear_when_there_is_room() {
        for (columns, _, _, lines) in all_cases() {
            if columns >= 40 {
                let text = strip(&lines.join("\n"));
                assert!(text.contains("LEPIC 0.5.0"), "{columns}");
                assert!(text.contains("main"), "{columns}");
            }
        }
    }

    #[test]
    fn layout_follows_the_width() {
        let rows = |columns| welcome(&info(), columns, Glyphs::Unicode, Paint::Off).len();
        assert_eq!(rows(112), 7);
        assert!(rows(60) > rows(112));
        assert!(rows(40) < rows(60));
        assert!(
            welcome(&info(), 20, Glyphs::Unicode, Paint::Off)
                .iter()
                .all(|l| !l.contains('╭'))
        );
        assert!(
            welcome(&info(), 40, Glyphs::Unicode, Paint::Off)
                .iter()
                .all(|l| !l.contains('█'))
        );
    }

    #[test]
    fn eighty_columns_cut_nothing() {
        let text = welcome(&info(), 80, Glyphs::Unicode, Paint::Off).join("\n");
        assert!(!text.contains('…'));
        assert!(text.contains("? help · Tab complete · → accept suggestion"));
        assert!(text.contains("exit leaves · Ctrl+C cancel"));
    }

    #[test]
    fn long_text_is_cut_with_an_ellipsis() {
        let long = CardInfo {
            wallet: "a-wallet-with-a-very-long-name-indeed",
            ..info()
        };
        let unicode = welcome(&long, 40, Glyphs::Unicode, Paint::Off).join("\n");
        assert!(unicode.contains('…'));
        let ascii = welcome(&long, 40, Glyphs::Ascii, Paint::Off).join("\n");
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
    fn only_the_bar_is_green() {
        for columns in [24, 40, 60, 112] {
            for lines in sweep(&info(), columns, Glyphs::Unicode, Paint::Ansi) {
                let text = lines.join("\n");
                let greens: Vec<&str> = text.split(GREEN).skip(1).collect();
                assert!(!greens.is_empty(), "{columns}");
                for after in greens {
                    let painted = after.split(RESET).next().unwrap_or("");
                    assert!(
                        painted == BAR || painted == MARK_BAR,
                        "{columns}: {painted:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn wordmark_reads_lepic_with_the_bar_down_to_the_baseline() {
        let plain = welcome(&info(), 112, Glyphs::Unicode, Paint::Off);
        let rows: Vec<&str> = plain[1..6]
            .iter()
            .map(|l| &l[l.find(' ').unwrap_or(0)..])
            .collect();
        assert!(
            rows[..4].iter().all(|r| r.starts_with(" ██▌  ")),
            "{rows:?}"
        );
        assert!(rows[4].starts_with("       "), "{rows:?}");
        assert!(rows[4].contains("█"), "the p has a descender: {rows:?}");
        let ascii = welcome(&info(), 112, Glyphs::Ascii, Paint::Off).join("\n");
        assert!(ascii.contains("###  _\"\"\"_"), "{ascii}");
        let narrow = strip(&welcome(&info(), 40, Glyphs::Unicode, Paint::Ansi).join("\n"));
        assert!(narrow.contains("▌epic  light Epic"), "{narrow}");
    }

    /// The bar starts where the c stands, the letters appear behind it one a frame, and the
    /// last frame is the card at rest. Every frame has the card's rows and its text.
    #[test]
    fn the_sweep_moves_the_bar_left_until_it_is_the_l() {
        let frames = sweep(&info(), 112, Glyphs::Unicode, Paint::Off);
        assert_eq!(frames.len(), SWEEP_STEPS + 1);
        let rest = welcome(&info(), 112, Glyphs::Unicode, Paint::Off);
        assert_eq!(frames.last(), Some(&rest));
        let baseline = |frame: &Vec<String>| frame[4].clone();
        assert!(baseline(&frames[0]).starts_with("│ ") && !baseline(&frames[0]).contains('▀'));
        let bar_at = |frame: &Vec<String>| frame[2].find(BAR).unwrap();
        for pair in frames.windows(2) {
            assert!(bar_at(&pair[0]) > bar_at(&pair[1]));
            assert_eq!(pair[0].len(), pair[1].len());
        }
        for frame in &frames {
            assert!(frame.join("\n").contains("wallet main · mainnet"));
        }
        // The c appears first, then the i, the p and the e.
        let letters = |frame: &Vec<String>| frame[3].matches('█').count();
        assert!(letters(&frames[1]) < letters(&frames[2]));
        assert!(letters(&frames[2]) < letters(&frames[4]));

        let narrow = sweep(&info(), 40, Glyphs::Unicode, Paint::Off);
        let marks: Vec<&str> = narrow.iter().map(|frame| frame[1].trim_end()).collect();
        assert_eq!(marks[0].trim_end_matches('│').trim_end(), "│     ▌");
        assert_eq!(marks[1].trim_end_matches('│').trim_end(), "│    ▌c");
        assert_eq!(marks[3].trim_end_matches('│').trim_end(), "│  ▌pic");
        assert!(marks[4].starts_with("│ ▌epic  light Epic"));
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
