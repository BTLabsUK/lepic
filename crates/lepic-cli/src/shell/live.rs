// SPDX-License-Identifier: Apache-2.0
//! The live area under the console: a blank row, the input line, the status rule and the hint
//! or progress row. Each row is built as styled pieces and cut to the terminal width minus one
//! column before it is styled, so the terminal never wraps it and colour never changes a width. Nothing but the blank row sits above the input: a
//! terminal that rewraps rows above the cursor when it narrows leaves them behind, while the
//! rows under the cursor are cleared on every paint.

use crate::settings::Env;
use crate::shell::card::Glyphs;
use crate::shell::paint::{Paint, Spans, Tone};

/// The characters the live area draws with.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Marks {
    pub glyphs: Glyphs,
    pub rule: char,
    pub sep: &'static str,
    pub on: &'static str,
    pub off: &'static str,
    pub synced: &'static str,
    pub syncing: &'static str,
    pub up: &'static str,
    pub down: &'static str,
    pub right: &'static str,
    /// The prompt mark: the bar of the lepic wordmark, which is its cursor too.
    pub prompt: &'static str,
    /// What a hidden prompt shows for each character typed.
    pub mask: &'static str,
    pub ellipsis: &'static str,
    spinner: &'static [&'static str],
}

impl Marks {
    pub(crate) const fn new(glyphs: Glyphs) -> Self {
        match glyphs {
            Glyphs::Unicode => Self {
                glyphs,
                rule: '─',
                sep: "·",
                on: "●",
                off: "○",
                synced: "✓",
                syncing: "…",
                up: "↑",
                down: "↓",
                right: "→",
                prompt: "▌",
                mask: "•",
                ellipsis: "…",
                // The bar as a scan beam, half a cell a frame, in glyphs every console font holds.
                spinner: &[
                    "▌  ", "▐  ", " ▌ ", " ▐ ", "  ▌", "  ▐", "  ▌", " ▐ ", " ▌ ", "▐  ",
                ],
            },
            Glyphs::Ascii => Self {
                glyphs,
                rule: '-',
                sep: "|",
                on: "*",
                off: "o",
                synced: "+",
                syncing: "~",
                up: "Up",
                down: "Down",
                right: "Right",
                prompt: ">",
                mask: "*",
                ellipsis: "...",
                spinner: &["|", "/", "-", "\\"],
            },
        }
    }

    /// The spinner frame for tick `n`.
    pub(crate) fn spinner(&self, n: usize) -> &'static str {
        let frames = self.spinner;
        n.checked_rem(frames.len())
            .and_then(|frame| frames.get(frame))
            .copied()
            .unwrap_or("")
    }
}

/// How the shell draws at this terminal: its characters, its colours, and whether it animates.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Look {
    pub marks: Marks,
    pub paint: Paint,
    pub motion: bool,
}

impl Look {
    /// The look for the terminal `env` describes; `ansi` says whether escape sequences reach it.
    pub(crate) fn of(env: &Env, ansi: bool) -> Self {
        let paint = paint(env, true, ansi);
        Self {
            marks: Marks::new(glyphs(env)),
            paint,
            motion: motion(env, paint),
        }
    }

    /// `text` in `tone`.
    pub(crate) fn tint(&self, text: &str, tone: Tone) -> String {
        super::paint::tint(text, tone, self.paint)
    }
}

/// Unicode, unless `LEPIC_ASCII=1`, a dumb terminal, or a Windows console that names no terminal
/// program: Windows Terminal and the editors' terminals draw Unicode, classic conhost may not.
/// `LEPIC_ASCII=0` asks for Unicode wherever the shell runs.
pub(crate) fn glyphs(env: &Env) -> Glyphs {
    match env.get("LEPIC_ASCII") {
        Some("1") => return Glyphs::Ascii,
        Some("0") => return Glyphs::Unicode,
        _ => {}
    }
    if env.get("TERM").is_some_and(|term| term == "dumb") {
        return Glyphs::Ascii;
    }
    let named = env.get("WT_SESSION").is_some() || env.get("TERM_PROGRAM").is_some();
    if cfg!(windows) && !named {
        return Glyphs::Ascii;
    }
    Glyphs::Unicode
}

/// Colour in the shell: on at a terminal unless `NO_COLOR` is set or `TERM` is `dumb`.
pub(crate) fn colour(env: &Env, terminal: bool) -> bool {
    terminal
        && env.get("NO_COLOR").is_none_or(str::is_empty)
        && env.get("TERM").is_none_or(|term| term != "dumb")
}

/// The colours the shell draws with at this terminal. `LEPIC_THEME` picks them: `ansi`, `night`
/// or `paper`. Otherwise a terminal that says it draws 24-bit colour gets the LEPIC palette, for
/// a light background when `COLORFGBG` names one, and every other terminal the ANSI colours.
/// `ansi` says whether escape sequences reach the console at all.
pub(crate) fn paint(env: &Env, terminal: bool, ansi: bool) -> Paint {
    if !ansi || !colour(env, terminal) {
        return Paint::Off;
    }
    match env.get("LEPIC_THEME") {
        Some("ansi") => return Paint::Ansi,
        Some("night") => return Paint::Night,
        Some("paper") => return Paint::Paper,
        _ => {}
    }
    if !true_colour(env) {
        return Paint::Ansi;
    }
    if light_background(env) {
        Paint::Paper
    } else {
        Paint::Night
    }
}

/// Whether the terminal says it draws 24-bit colour: `COLORTERM`, Windows Terminal, or a
/// terminal program or `TERM` known for it.
fn true_colour(env: &Env) -> bool {
    env.get("COLORTERM")
        .is_some_and(|value| matches!(value, "truecolor" | "24bit"))
        || env.get("WT_SESSION").is_some()
        || env.get("TERM_PROGRAM").is_some_and(|program| {
            matches!(
                program,
                "iTerm.app" | "WezTerm" | "vscode" | "ghostty" | "Hyper"
            )
        })
        || env.get("TERM").is_some_and(|term| {
            ["kitty", "alacritty", "ghostty", "wezterm", "foot", "direct"]
                .iter()
                .any(|name| term.contains(name))
        })
}

/// Whether `COLORFGBG`, `foreground;background` in ANSI colour numbers, names a light
/// background.
fn light_background(env: &Env) -> bool {
    env.get("COLORFGBG")
        .and_then(|value| value.rsplit(';').next())
        .and_then(|background| background.parse::<u8>().ok())
        .is_some_and(|background| background == 7 || background >= 9)
}

/// Whether the shell animates: in colour, unless `LEPIC_MOTION=0`.
pub(crate) fn motion(env: &Env, paint: Paint) -> bool {
    paint.on() && env.get("LEPIC_MOTION").is_none_or(|value| value != "0")
}

/// Whether escape sequences reach the console as colour. A Windows console needs virtual
/// terminal processing on, which crossterm switches on when it can; classic conhost starts
/// with it off, so this runs before anything coloured is printed.
pub(crate) fn ansi_works() -> bool {
    #[cfg(windows)]
    {
        crossterm::ansi_support::supports_ansi()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Whether the wallet has caught up with the chain, as the session last heard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SyncMark {
    #[default]
    Unknown,
    Syncing,
    Synced,
}

/// Whether the node answered, as the session last heard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NodeMark {
    #[default]
    Unknown,
    Reached,
    Unreached,
}

/// What the status rule shows.
#[derive(Clone, Debug, Default)]
pub(crate) struct Status {
    pub wallet: String,
    pub network: String,
    pub locked: bool,
    /// Formatted amounts, `None` before the first read.
    pub balance: Option<String>,
    pub spendable: Option<String>,
    pub height: Option<u64>,
    pub sync: SyncMark,
    pub node: NodeMark,
    pub tor: bool,
    pub api: bool,
}

/// The order segments go in as the terminal narrows: first the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Segment {
    Api,
    Tor,
    Network,
    Height,
    Spendable,
    Balance,
    Wallet,
}

const DROP_ORDER: [Segment; 6] = [
    Segment::Api,
    Segment::Tor,
    Segment::Network,
    Segment::Height,
    Segment::Spendable,
    Segment::Balance,
];

/// Visible width of `text` in cells.
#[cfg(test)]
pub(crate) fn width(text: &str) -> usize {
    super::paint::cells(text)
}

/// `text` with control characters replaced, so a name cannot move the cursor or set a colour.
pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// An amount in EPIC as the status shows it: without trailing zeros, `10.992 EPIC`.
pub(crate) fn short_amount(formatted: &str) -> String {
    let trimmed = if formatted.contains('.') {
        formatted.trim_end_matches('0').trim_end_matches('.')
    } else {
        formatted
    };
    format!("{trimmed} EPIC")
}

/// `2411005` as `2,411,005`.
pub(crate) fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len().saturating_mul(2));
    for (i, c) in digits.chars().enumerate() {
        let left = digits.len().saturating_sub(i);
        if i > 0 && left.is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

impl Status {
    fn left(&self, keep: &[Segment]) -> Vec<Spans> {
        let mut out = vec![Spans::of(printable(&self.wallet), Tone::Bold)];
        if self.locked {
            out.push(Spans::of("locked", Tone::Dim));
            return out;
        }
        if keep.contains(&Segment::Balance)
            && let Some(balance) = &self.balance
        {
            out.push(Spans::of(balance.clone(), Tone::Amount));
        }
        if keep.contains(&Segment::Spendable)
            && let Some(spendable) = &self.spendable
            && self.balance.as_ref() != Some(spendable)
        {
            let mut spans = Spans::of(spendable.clone(), Tone::Plain);
            spans.push(" spendable", Tone::Dim);
            out.push(spans);
        }
        out
    }

    fn right(&self, keep: &[Segment], marks: &Marks) -> Vec<Spans> {
        let mut out = Vec::new();
        let flag = |name: &str, on: bool| {
            let mut spans = Spans::of(format!("{name} "), Tone::Dim);
            if on {
                spans.push(marks.on, Tone::Green);
            } else {
                spans.push(marks.off, Tone::Dim);
            }
            spans
        };
        if keep.contains(&Segment::Height) && self.node == NodeMark::Unreached {
            let mut spans = Spans::of("node ", Tone::Dim);
            spans.push("unreached", Tone::Red);
            out.push(spans);
        } else if keep.contains(&Segment::Height)
            && let Some(height) = self.height
        {
            let mut spans = Spans::of("h ", Tone::Dim);
            spans.push(grouped(height), Tone::Plain);
            match self.sync {
                SyncMark::Unknown => {}
                SyncMark::Syncing => spans.push(format!(" {}", marks.syncing), Tone::Yellow),
                SyncMark::Synced => spans.push(format!(" {}", marks.synced), Tone::Green),
            }
            out.push(spans);
        }
        if keep.contains(&Segment::Network) {
            out.push(Spans::of(self.network.clone(), Tone::Plain));
        }
        if keep.contains(&Segment::Tor) {
            out.push(flag("tor", self.tor));
        }
        if keep.contains(&Segment::Api) {
            out.push(flag("api", self.api));
        }
        out
    }

    /// The status rule: `── main · 10.992 EPIC ───── h 2,411,005 ✓ · mainnet · tor ● · api ○ ──`,
    /// never wider than `columns - 1`. Segments drop in [`DROP_ORDER`] until it fits.
    #[cfg(test)]
    pub(crate) fn rule(&self, columns: u16, marks: &Marks) -> String {
        self.rule_spans(columns, marks).plain()
    }

    /// The status rule in its colours.
    pub(crate) fn rule_spans(&self, columns: u16, marks: &Marks) -> Spans {
        let max = usize::from(columns.saturating_sub(1));
        let rule = marks.rule.to_string();
        let sep = Spans::of(format!(" {} ", marks.sep), Tone::Rule);
        let mut keep: Vec<Segment> = DROP_ORDER.to_vec();
        keep.push(Segment::Wallet);
        loop {
            let left = Spans::join(self.left(&keep), &sep);
            let right = Spans::join(self.right(&keep, marks), &sep);
            let mut head = Spans::of(format!("{rule}{rule} "), Tone::Rule);
            head.extend(left);
            head.push(" ", Tone::Plain);
            let mut tail = Spans::new();
            if right.width() > 0 {
                tail.push(" ", Tone::Plain);
                tail.extend(right);
                tail.push(" ", Tone::Plain);
            }
            tail.push(format!("{rule}{rule}"), Tone::Rule);
            let used = head.width().saturating_add(tail.width());
            // At least three rule characters between the two halves.
            if used.saturating_add(3) <= max || keep.len() == 1 {
                let fill = max.saturating_sub(used);
                head.push(rule.repeat(fill), Tone::Rule);
                head.extend(tail);
                return head.cut(columns);
            }
            if let Some(next) = DROP_ORDER.iter().find(|segment| keep.contains(segment)) {
                keep.retain(|segment| segment != next);
            }
        }
    }
}

/// The row under the status rule while the user edits `line`: the usage of the command being
/// typed when `usage` knows it, else what the keys do.
#[cfg(test)]
pub(crate) fn hint_row(
    line: &str,
    locked: bool,
    usage: Option<&str>,
    columns: u16,
    marks: &Marks,
) -> String {
    hint_spans(line, locked, usage, columns, marks).plain()
}

/// The hint row in its colours: the keys plain, what they do dim.
pub(crate) fn hint_spans(
    line: &str,
    locked: bool,
    usage: Option<&str>,
    columns: u16,
    marks: &Marks,
) -> Spans {
    if let Some(usage) = usage {
        return Spans::of(printable(usage), Tone::Dim).cut(columns);
    }
    let history = format!("{} history", marks.up);
    let accept = format!("{} accept suggestion", marks.right);
    let keys: &[&str] = if line.trim().is_empty() && locked {
        &["unlock opens the wallet", "exit leaves"]
    } else if line.trim().is_empty() {
        &["? help", "Tab complete", &history, "Ctrl+C cancel"]
    } else {
        &["Enter run", "Tab complete", &accept, "Ctrl+C clear"]
    };
    key_spans(keys, marks).cut(columns)
}

/// `key what it does` pieces joined by the separator: each key plain, the rest dim.
pub(crate) fn key_spans(keys: &[&str], marks: &Marks) -> Spans {
    let sep = Spans::of(format!(" {} ", marks.sep), Tone::Rule);
    let parts = keys
        .iter()
        .map(|key| {
            let (name, what) = key.split_once(' ').unwrap_or((key, ""));
            let mut spans = Spans::of(name, Tone::Plain);
            if !what.is_empty() {
                spans.push(format!(" {what}"), Tone::Dim);
            }
            spans
        })
        .collect();
    Spans::join(parts, &sep)
}

/// The row under the status rule while a command runs: `⠋ scan 2,410,800/2,411,006 · 5s ·
/// Ctrl+C cancel`.
#[cfg(test)]
pub(crate) fn progress_row(
    tick: usize,
    what: &str,
    seconds: u64,
    columns: u16,
    marks: &Marks,
) -> String {
    progress_spans(tick, what, seconds, columns, marks).plain()
}

/// The progress row in its colours: the spinner green, the keys dim.
pub(crate) fn progress_spans(
    tick: usize,
    what: &str,
    seconds: u64,
    columns: u16,
    marks: &Marks,
) -> Spans {
    let sep = format!(" {} ", marks.sep);
    let mut spans = Spans::of(marks.spinner(tick), Tone::Green);
    spans.push(format!(" {}", printable(what)), Tone::Plain);
    spans.push(sep.clone(), Tone::Rule);
    spans.push(format!("{seconds}s"), Tone::Plain);
    spans.push(sep, Tone::Rule);
    spans.push("Ctrl+C cancel", Tone::Dim);
    spans.cut(columns)
}

/// The rows of the footer drawn while a command runs, the same rows the editor draws: blank,
/// the prompt mark, the status rule, progress.
pub(crate) fn footer(
    status: &Status,
    progress: &Spans,
    columns: u16,
    marks: &Marks,
    paint: Paint,
) -> [String; 4] {
    [
        String::new(),
        prompt_mark(status.locked, marks).cut(columns).render(paint),
        status.rule_spans(columns, marks).render(paint),
        progress.clone().cut(columns).render(paint),
    ]
}

/// The prompt mark: green while the wallet is open, dim while it is locked.
pub(crate) fn prompt_mark(locked: bool, marks: &Marks) -> Spans {
    Spans::of(marks.prompt, if locked { Tone::Dim } else { Tone::Green })
}

/// The colour codes in the SGR sequences of `text`: any foreground or background other than the
/// default (39, 49). Bold, dim and reverse are not colour.
#[cfg(test)]
pub(crate) fn colour_codes(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("\u{1b}[") {
        let after = rest.get(start.saturating_add(2)..).unwrap_or("");
        let end = after
            .find(|c: char| ('\u{40}'..='\u{7e}').contains(&c))
            .unwrap_or(after.len());
        if after[end..].starts_with('m') {
            for param in after[..end].split(';') {
                let code: u16 = param.parse().unwrap_or(0);
                match code {
                    30..=37 | 40..=47 | 90..=97 | 100..=107 => found.push(param.to_owned()),
                    38 | 48 => {
                        found.push(after[..end].to_owned());
                        break;
                    }
                    _ => {}
                }
            }
        }
        rest = after.get(end.saturating_add(1)..).unwrap_or("");
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> Status {
        Status {
            wallet: "main".to_owned(),
            network: "mainnet".to_owned(),
            locked: false,
            balance: Some("10.992 EPIC".to_owned()),
            spendable: Some("8.492".to_owned()),
            height: Some(2_411_005),
            sync: SyncMark::Synced,
            node: NodeMark::Reached,
            tor: true,
            api: false,
        }
    }

    fn env(vars: &[(&str, &str)]) -> Env {
        Env::new(vars.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())))
    }

    const WIDTHS: [u16; 4] = [40, 80, 112, 200];
    const PAINTS: [Paint; 4] = [Paint::Off, Paint::Ansi, Paint::Night, Paint::Paper];

    #[test]
    fn the_rule_is_never_wider_than_the_terminal_minus_one() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            let marks = Marks::new(glyphs);
            for columns in WIDTHS.into_iter().chain([1, 2, 10, 20]) {
                let rule = status().rule(columns, &marks);
                assert!(
                    width(&rule) < usize::from(columns).max(1),
                    "{columns}: {rule}"
                );
            }
        }
    }

    #[test]
    fn the_rule_fills_the_line_when_it_fits() {
        let marks = Marks::new(Glyphs::Unicode);
        for columns in [80, 112, 200] {
            assert_eq!(
                width(&status().rule(columns, &marks)),
                usize::from(columns) - 1
            );
        }
        assert_eq!(
            status().rule(112, &marks),
            format!(
                "── main · 10.992 EPIC · 8.492 spendable {} h 2,411,005 ✓ · mainnet · tor ● · api ○ ──",
                "─".repeat(28)
            )
        );
    }

    #[test]
    fn segments_drop_in_order_as_the_terminal_narrows() {
        let marks = Marks::new(Glyphs::Unicode);
        let at = |columns| status().rule(columns, &marks);
        assert!(at(200).contains("api ○"));
        let mut previous = 7;
        for columns in (10..=200).rev() {
            let rule = at(columns);
            let present = [
                rule.contains("api"),
                rule.contains("tor"),
                rule.contains("mainnet"),
                rule.contains("h 2,411,005"),
                rule.contains("spendable"),
                rule.contains("10.992 EPIC"),
            ];
            // Once a segment is gone, every segment before it in the drop order is gone too.
            let first_kept = present.iter().position(|kept| *kept).unwrap_or(6);
            assert!(
                present[first_kept..].iter().all(|kept| *kept),
                "{columns}: {rule}"
            );
            assert!(
                first_kept <= 6 && 6 - first_kept <= previous,
                "{columns}: {rule}"
            );
            previous = 6 - first_kept;
        }
        let narrow = at(40);
        assert!(narrow.contains("main · 10.992 EPIC"), "{narrow}");
        assert!(!narrow.contains("api"), "{narrow}");
        assert!(at(20).starts_with("── main"), "{}", at(20));
    }

    #[test]
    fn a_locked_wallet_shows_locked_and_no_balance() {
        let marks = Marks::new(Glyphs::Unicode);
        let locked = Status {
            locked: true,
            ..status()
        };
        let rule = locked.rule(80, &marks);
        assert!(rule.starts_with("── main · locked "), "{rule}");
        assert!(!rule.contains("EPIC"), "{rule}");
    }

    /// A node that does not answer takes the place of the height, which is then out of date,
    /// and a wallet that never heard a height shows none.
    #[test]
    fn the_rule_says_when_the_node_is_not_reached() {
        let marks = Marks::new(Glyphs::Unicode);
        let unreached = Status {
            node: NodeMark::Unreached,
            ..status()
        };
        let rule = unreached.rule(112, &marks);
        assert!(rule.contains(" node unreached · mainnet "), "{rule}");
        assert!(!rule.contains("h 2,411,005"), "{rule}");
        let painted = unreached.rule_spans(112, &marks).render(Paint::Ansi);
        assert!(
            painted.contains("\u{1b}[31munreached\u{1b}[0m"),
            "{painted:?}"
        );
        let new = Status {
            height: None,
            sync: SyncMark::Unknown,
            node: NodeMark::Unknown,
            ..status()
        };
        let rule = new.rule(112, &marks);
        assert!(!rule.contains(" h "), "{rule}");
        assert!(rule.contains("── mainnet · tor"), "{rule}");
    }

    #[test]
    fn ascii_rules_are_ascii() {
        let marks = Marks::new(Glyphs::Ascii);
        for columns in WIDTHS {
            let rule = status().rule(columns, &marks);
            assert!(rule.is_ascii(), "{rule}");
            assert!(hint_row("", false, None, columns, &marks).is_ascii());
            assert!(progress_row(3, "scan", 5, columns, &marks).is_ascii());
        }
        assert!(status().rule(112, &marks).contains("tor * | api o --"));
    }

    #[test]
    fn a_wallet_name_cannot_move_the_cursor() {
        let marks = Marks::new(Glyphs::Unicode);
        let odd = Status {
            wallet: "a\x1b[2Jb\n".to_owned(),
            ..status()
        };
        assert!(!odd.rule(80, &marks).chars().any(char::is_control));
    }

    #[test]
    fn hint_rows() {
        let marks = Marks::new(Glyphs::Unicode);
        assert_eq!(
            hint_row("", false, None, 112, &marks),
            "? help · Tab complete · ↑ history · Ctrl+C cancel"
        );
        assert_eq!(
            hint_row("tx l", false, None, 112, &marks),
            "Enter run · Tab complete · → accept suggestion · Ctrl+C clear"
        );
        assert_eq!(
            hint_row("", true, None, 112, &marks),
            "unlock opens the wallet · exit leaves"
        );
        assert_eq!(
            hint_row(
                "tx send",
                false,
                Some("tx send <AMOUNT> --to <TO>"),
                112,
                &marks
            ),
            "tx send <AMOUNT> --to <TO>"
        );
        for columns in WIDTHS {
            assert!(width(&hint_row("x", false, None, columns, &marks)) < usize::from(columns));
        }
        assert_eq!(hint_row("", false, None, 20, &marks), "? help · Tab comple");
        // The keys stand out from what they do.
        let painted = hint_spans("", false, None, 112, &marks).render(Paint::Ansi);
        assert!(
            painted.starts_with("?\u{1b}[2m help\u{1b}[0m\u{1b}[2m · \u{1b}[0mTab"),
            "{painted:?}"
        );
    }

    #[test]
    fn progress_and_footer_rows_fit() {
        let marks = Marks::new(Glyphs::Unicode);
        assert_eq!(
            progress_row(0, "scan 2,410,800/2,411,006", 5, 112, &marks),
            "▌   scan 2,410,800/2,411,006 · 5s · Ctrl+C cancel"
        );
        for columns in WIDTHS {
            let progress = progress_spans(1, "scan", 5, columns, &marks);
            for paint in PAINTS {
                for row in footer(&status(), &progress, columns, &marks, paint) {
                    let shown = crate::shell::paint::strip(&row);
                    assert!(width(&shown) < usize::from(columns), "{row}");
                }
            }
        }
    }

    /// The beam is three cells wide in every frame, so the text beside it does not move.
    #[test]
    fn the_spinner_keeps_its_width() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            let marks = Marks::new(glyphs);
            let first = width(marks.spinner(0));
            for tick in 0..40 {
                assert_eq!(width(marks.spinner(tick)), first, "{glyphs:?} {tick}");
            }
        }
        assert_eq!(Marks::new(Glyphs::Unicode).spinner(4), "  ▌");
    }

    #[test]
    fn amounts_and_heights() {
        assert_eq!(short_amount("10.99200000"), "10.992 EPIC");
        assert_eq!(short_amount("0.00000000"), "0 EPIC");
        assert_eq!(short_amount("12.00000000"), "12 EPIC");
        assert_eq!(grouped(2_411_005), "2,411,005");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(0), "0");
    }

    #[test]
    fn glyphs_and_colour_follow_the_environment() {
        assert_eq!(glyphs(&env(&[("LEPIC_ASCII", "1")])), Glyphs::Ascii);
        assert_eq!(glyphs(&env(&[("LEPIC_ASCII", "0")])), Glyphs::Unicode);
        assert_eq!(
            glyphs(&env(&[("TERM", "dumb"), ("WT_SESSION", "x")])),
            Glyphs::Ascii
        );
        if cfg!(windows) {
            assert_eq!(glyphs(&env(&[])), Glyphs::Ascii);
            assert_eq!(glyphs(&env(&[("WT_SESSION", "x")])), Glyphs::Unicode);
            assert_eq!(glyphs(&env(&[("TERM_PROGRAM", "vscode")])), Glyphs::Unicode);
        } else {
            assert_eq!(glyphs(&env(&[])), Glyphs::Unicode);
        }
        assert!(colour(&env(&[]), true));
        assert!(!colour(&env(&[("NO_COLOR", "1")]), true));
        assert!(colour(&env(&[("NO_COLOR", "")]), true));
        assert!(!colour(&env(&[]), false));
    }

    #[test]
    fn the_palette_follows_what_the_terminal_says_it_draws() {
        let of = |vars: &[(&str, &str)]| paint(&env(vars), true, true);
        assert_eq!(of(&[]), Paint::Ansi);
        assert_eq!(of(&[("TERM", "xterm-256color")]), Paint::Ansi);
        assert_eq!(of(&[("COLORTERM", "truecolor")]), Paint::Night);
        assert_eq!(of(&[("COLORTERM", "24bit")]), Paint::Night);
        assert_eq!(of(&[("WT_SESSION", "x")]), Paint::Night);
        assert_eq!(of(&[("TERM_PROGRAM", "vscode")]), Paint::Night);
        assert_eq!(of(&[("TERM", "xterm-kitty")]), Paint::Night);
        assert_eq!(
            of(&[("COLORTERM", "truecolor"), ("COLORFGBG", "0;15")]),
            Paint::Paper
        );
        assert_eq!(
            of(&[("COLORTERM", "truecolor"), ("COLORFGBG", "15;0")]),
            Paint::Night
        );
        // A light background is nothing to a terminal that draws the ANSI colours only.
        assert_eq!(of(&[("COLORFGBG", "0;15")]), Paint::Ansi);
        assert_eq!(
            of(&[("WT_SESSION", "x"), ("LEPIC_THEME", "ansi")]),
            Paint::Ansi
        );
        assert_eq!(of(&[("LEPIC_THEME", "paper")]), Paint::Paper);
        assert_eq!(of(&[("LEPIC_THEME", "night")]), Paint::Night);
        for off in [
            &[("NO_COLOR", "1"), ("COLORTERM", "truecolor")][..],
            &[("TERM", "dumb"), ("LEPIC_THEME", "night")][..],
        ] {
            assert_eq!(of(off), Paint::Off, "{off:?}");
        }
        assert_eq!(paint(&env(&[("WT_SESSION", "x")]), false, true), Paint::Off);
        assert_eq!(paint(&env(&[("WT_SESSION", "x")]), true, false), Paint::Off);
    }

    #[test]
    fn motion_needs_colour_and_can_be_turned_off() {
        assert!(motion(&env(&[]), Paint::Ansi));
        assert!(motion(&env(&[("LEPIC_MOTION", "1")]), Paint::Night));
        assert!(!motion(&env(&[("LEPIC_MOTION", "0")]), Paint::Night));
        assert!(!motion(&env(&[]), Paint::Off));
        let look = Look::of(&env(&[("NO_COLOR", "1"), ("LEPIC_ASCII", "1")]), true);
        assert_eq!(look.paint, Paint::Off);
        assert_eq!(look.marks.glyphs, Glyphs::Ascii);
        assert!(!look.motion);
        assert_eq!(look.tint("x", Tone::Red), "x");
    }

    #[test]
    fn live_rows_are_coloured_only_with_colour_on() {
        assert_eq!(
            colour_codes("\u{1b}[1;2m\u{1b}[39mx\u{1b}[0m"),
            Vec::<String>::new()
        );
        assert_eq!(colour_codes("\u{1b}[1;31mx"), ["31"]);
        assert_eq!(colour_codes("\u{1b}[38;5;8mx"), ["38;5;8"]);
        assert_eq!(colour_codes("\u{1b}[92mx"), ["92"]);
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            let marks = Marks::new(glyphs);
            for columns in WIDTHS {
                let progress = progress_spans(3, "scan", 5, columns, &marks);
                let rows = |paint: Paint| -> Vec<String> {
                    let mut rows: Vec<String> =
                        footer(&status(), &progress, columns, &marks, paint).into();
                    rows.push(hint_spans("", false, None, columns, &marks).render(paint));
                    rows.push(
                        hint_spans("tx", true, Some("tx <COMMAND>"), columns, &marks).render(paint),
                    );
                    rows
                };
                let plain = rows(Paint::Off);
                for row in &plain {
                    assert!(!row.contains('\u{1b}'), "{row:?}");
                }
                for paint in [Paint::Ansi, Paint::Night, Paint::Paper] {
                    for (row, bare) in rows(paint).iter().zip(&plain) {
                        assert_eq!(&crate::shell::paint::strip(row), bare);
                    }
                }
            }
        }
        let marks = Marks::new(Glyphs::Unicode);
        let rule = status().rule_spans(112, &marks).render(Paint::Ansi);
        assert!(rule.contains("\u{1b}[1mmain\u{1b}[0m"), "{rule:?}");
        assert!(rule.contains("\u{1b}[32m ✓\u{1b}[0m"), "{rule:?}");
        assert!(
            rule.contains("\u{1b}[2mtor \u{1b}[0m\u{1b}[32m●"),
            "{rule:?}"
        );
        let mark = footer(&status(), &Spans::new(), 80, &marks, Paint::Ansi)[1].clone();
        assert_eq!(mark, "\u{1b}[32m▌\u{1b}[0m");
        // The 24-bit palettes draw the same pieces in the pack's colours.
        let night = status().rule_spans(112, &marks).render(Paint::Night);
        assert!(
            night.contains("\u{1b}[38;2;60;235;151m ✓\u{1b}[0m"),
            "{night:?}"
        );
        assert!(
            night.contains("\u{1b}[1;38;2;246;212;113m10.992 EPIC\u{1b}[0m"),
            "{night:?}"
        );
    }
}
