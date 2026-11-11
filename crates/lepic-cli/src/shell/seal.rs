// SPDX-License-Identifier: Apache-2.0
//! The epic1 seal: a short animation in the live area while a sealed payment goes out, with
//! `epic1 pay` and `tx send --to-contact`. The epic1 mark builds its "1" from the foot up, a wave
//! seals the amount into blocks as the calm seal of the epic1 brand does, and the box around it
//! closes from the corners. It runs beside the send and never holds it up: once the send ends
//! the rest plays fast, a key or Ctrl+C skips to the still last frame, and a send that takes
//! longer waits on that frame. Then the area is cleared and one line says the payment was
//! sealed. Without colour, at a narrow or short terminal and with JSON output there is no
//! animation; the first two get the line in plain text, JSON gets nothing.
//!
//! Every frame is a pure function of the time on the seal's clock, built as styled pieces and
//! cut to the terminal width minus one before it is styled, like the rest of the live area.

use std::io::IsTerminal as _;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::Instant;

use crate::cli::{Command, Epic1Command, TxCommand};
use crate::exit::CliError;
use crate::output::Report;
use crate::settings::OutputFormat;
use crate::shell::card::Glyphs;
use crate::shell::editor::columns;
use crate::shell::paint::{Spans, Tone};
use crate::shell::reader::Reply;
use crate::shell::screen::Screen;

/// How often a frame is drawn while something moves.
pub(crate) const FRAME: Duration = Duration::from_millis(40);

/// Narrower than this, or shorter than [`MIN_ROWS`], the seal is a line, not an animation.
pub(crate) const MIN_COLUMNS: u16 = 44;
pub(crate) const MIN_ROWS: u16 = 12;

/// The epic1 mark, 7 by 5 cells: columns 0 to 2 are the "1", the rest is noise.
const MARK: [&str; 5] = [".#..#..", "##....#", ".#.#...", ".#...#.", "###.#.."];
const DIGIT_COLUMNS: usize = 3;
/// Each row of the "1" appears this long after the one under it.
const BUILD_ROW_MS: u64 = 60;
const BUILD_MS: u64 = BUILD_ROW_MS * 5;
/// A cell of the amount flickers this long before it settles, changing every `GLYPH_MS`.
const FLICKER_MS: u64 = 280;
const GLYPH_MS: u64 = 90;
const FLICKER_GLYPHS: &[u8] = b"0123456789abcdef#%&*+=/<>$@";
/// The whole wave takes about this long, whatever the length of the amount.
const WAVE_MS: u64 = 600;
const CLOSE_MS: u64 = 300;
/// How much faster the rest plays once the send has ended.
const FAST: u64 = 4;
/// The amount is cut to this many characters.
const LABEL_MAX: usize = 24;
/// The share of sealed noise cells left empty, in 1/100.
const GAP_PERCENT: u64 = 28;

const INDENT: &str = "  ";
const GAP: &str = "   ";
const MARK_WIDTH: usize = 7;
/// The indent, the mark, the gap and the box's two sides with their spaces.
const FIXED_WIDTH: usize = 2 + MARK_WIDTH + 3 + 4;
const STATUS_GAP: &str = "  ";
const SEALING: &str = "sealing";
const SENDING: &str = "sending";

/// What the seal shows at this terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Show {
    /// The animation, then the line.
    Animated,
    /// Only the line.
    Line,
    /// Nothing: JSON output stays JSON.
    Nothing,
}

/// Whether the seal animates: only with human output, in colour, at a terminal at least
/// [`MIN_COLUMNS`] wide and [`MIN_ROWS`] high. `colour` is the shell's, which is off for
/// `NO_COLOR` and `TERM=dumb`.
pub(crate) const fn show(
    output: OutputFormat,
    colour: bool,
    terminal: bool,
    columns: u16,
    rows: u16,
) -> Show {
    if matches!(output, OutputFormat::Json) {
        return Show::Nothing;
    }
    if !colour || !terminal || columns < MIN_COLUMNS || rows < MIN_ROWS {
        return Show::Line;
    }
    Show::Animated
}

/// Who the payment is sealed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Payee {
    /// The holder of an epic1 link.
    Link,
    /// A paired contact.
    Contact,
}

/// The seal of one sealed send.
pub(crate) struct Seal {
    payee: Payee,
    label: Vec<char>,
    seed: u64,
    show: Show,
    glyphs: Glyphs,
    colour: bool,
    /// Milliseconds on the seal's clock, which runs `FAST` times faster once the send ended.
    clock: u64,
    last: Instant,
    fast: bool,
}

impl Seal {
    /// The seal for `command`, when it sends a sealed payment; `None` for every other command.
    /// What it shows follows `output`, the shell's `colour` and the terminal as it is now.
    pub(crate) fn of(
        command: &Command,
        output: OutputFormat,
        colour: bool,
        glyphs: Glyphs,
    ) -> Option<Self> {
        let (payee, amount) = match command {
            Command::Epic1(epic1) => match &epic1.command {
                Epic1Command::Pay(pay) => (Payee::Link, pay.amount.as_deref()),
                _ => return None,
            },
            Command::Tx(TxCommand::Send(send)) if send.destination.to_contact.is_some() => {
                (Payee::Contact, Some(send.amount.as_str()))
            }
            _ => return None,
        };
        let (columns, rows) = crossterm::terminal::size().unwrap_or((0, 0));
        let terminal = std::io::stdout().is_terminal();
        let show = show(output, colour, terminal, columns, rows);
        Some(Self::new(payee, amount, show, glyphs, colour))
    }

    fn new(payee: Payee, amount: Option<&str>, show: Show, glyphs: Glyphs, colour: bool) -> Self {
        let text = amount.map_or_else(|| "payment".to_owned(), |amount| format!("{amount} EPIC"));
        let label = label(&text, glyphs);
        let seed = label.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, c| {
            (hash ^ u64::from(*c)).wrapping_mul(0x0100_0000_01b3)
        });
        Self {
            payee,
            label,
            seed,
            show,
            glyphs,
            colour,
            clock: 0,
            last: Instant::now(),
            fast: false,
        }
    }

    pub(crate) const fn animated(&self) -> bool {
        matches!(self.show, Show::Animated)
    }

    /// Whether a frame from now differs from the last one.
    pub(crate) fn moving(&self) -> bool {
        self.animated() && self.clock < total(self.label.len())
    }

    /// Moves the clock to now.
    fn advance(&mut self) {
        let now = Instant::now();
        let real = u64::try_from(now.duration_since(self.last).as_millis()).unwrap_or(u64::MAX);
        self.last = now;
        let speed = if self.fast { FAST } else { 1 };
        self.clock = self
            .clock
            .saturating_add(real.saturating_mul(speed))
            .min(total(self.label.len()));
    }

    /// Goes straight to the still last frame.
    pub(crate) fn skip(&mut self) {
        self.clock = total(self.label.len());
    }

    /// The rows to draw above the footer now, at `columns`; none when there is no animation.
    pub(crate) fn rows(&mut self, columns: u16) -> Vec<String> {
        if !self.animated() {
            return Vec::new();
        }
        self.advance();
        frame(self.clock, &self.label, self.seed, self.glyphs, columns)
            .into_iter()
            .map(|row| row.render(self.colour))
            .collect()
    }

    /// Plays the rest fast once the send has ended, until the last frame; a key skips it.
    pub(crate) async fn finish(&mut self, screen: &Screen, replies: &mut UnboundedReceiver<Reply>) {
        if !self.animated() {
            return;
        }
        self.advance();
        self.fast = true;
        let mut frames = tokio::time::interval(FRAME);
        while self.moving() {
            tokio::select! {
                _ = frames.tick() => {}
                reply = replies.recv() => match reply {
                    Some(Reply::Interrupt | Reply::Key) | None => self.skip(),
                    Some(_) => {}
                },
            }
            screen.art(self.rows(columns()));
        }
    }

    /// The line printed once the area is cleared, when `result` sent the payment sealed: none
    /// for an error, a repeat that sent nothing and a payment no relay took.
    pub(crate) fn last_line(&self, result: &Result<Report, CliError>) -> Option<String> {
        let sealed = match result {
            Ok(Report::Epic1Paid(paid)) => paid.posted_ok && !paid.repeated,
            Ok(Report::Send(sent)) => sent.delivered && !sent.repeated,
            _ => false,
        };
        if !sealed || self.show == Show::Nothing {
            return None;
        }
        Some(last_line(self.payee, self.glyphs, self.animated()).render(self.colour))
    }
}

/// `text` cut to [`LABEL_MAX`] characters, with an ellipsis when it was longer.
fn label(text: &str, glyphs: Glyphs) -> Vec<char> {
    let chars: Vec<char> = text.chars().filter(|c| !c.is_control()).collect();
    if chars.len() <= LABEL_MAX {
        return chars;
    }
    let ellipsis: &[char] = match glyphs {
        Glyphs::Unicode => &['…'],
        Glyphs::Ascii => &['.', '.', '.'],
    };
    let keep = LABEL_MAX.saturating_sub(ellipsis.len());
    chars
        .into_iter()
        .take(keep)
        .chain(ellipsis.iter().copied())
        .collect()
}

/// The time between two cells of the wave, for an amount of `len` characters.
fn step(len: usize) -> u64 {
    let len = u64::try_from(len.max(1)).unwrap_or(u64::MAX);
    WAVE_MS.checked_div(len).unwrap_or(0).clamp(12, 42)
}

/// When the wave has settled the last cell.
fn wave_end(len: usize) -> u64 {
    let cells = u64::try_from(len.saturating_sub(1)).unwrap_or(u64::MAX);
    BUILD_MS
        .saturating_add(cells.saturating_mul(step(len)))
        .saturating_add(FLICKER_MS)
}

/// When the last frame is reached.
fn total(len: usize) -> u64 {
    wave_end(len).saturating_add(CLOSE_MS)
}

/// A number from `seed` and `n`, the same each time.
const fn mix(seed: u64, n: u64) -> u64 {
    let mut z = seed.wrapping_add(n.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The three rows of the mark at `t`, two cells of the grid in each character. The noise is
/// there from the start and never changes; the "1" builds from its foot up.
fn mark(t: u64, glyphs: Glyphs) -> [Spans; 3] {
    let shown = |row: usize, column: usize| -> bool {
        let Some(cell) = MARK.get(row).and_then(|line| line.as_bytes().get(column)) else {
            return false;
        };
        if *cell != b'#' {
            return false;
        }
        if column >= DIGIT_COLUMNS {
            return true;
        }
        let from_foot = u64::try_from(MARK.len().saturating_sub(row)).unwrap_or(0);
        t >= from_foot.saturating_mul(BUILD_ROW_MS)
    };
    let mut out: [Spans; 3] = Default::default();
    for (pair, spans) in out.iter_mut().enumerate() {
        let top = pair.saturating_mul(2);
        for column in 0..MARK_WIDTH {
            let cell = match (
                glyphs,
                shown(top, column),
                shown(top.saturating_add(1), column),
            ) {
                (_, false, false) => " ",
                (Glyphs::Ascii, _, _) => "#",
                (Glyphs::Unicode, true, true) => "█",
                (Glyphs::Unicode, true, false) => "▀",
                (Glyphs::Unicode, false, true) => "▄",
            };
            // The noise fades to the right: its first column plain, the others dim.
            let tone = match column {
                _ if cell == " " => Tone::Plain,
                0..DIGIT_COLUMNS => Tone::Yellow,
                DIGIT_COLUMNS => Tone::Plain,
                _ => Tone::Dim,
            };
            spans.push(cell, tone);
        }
    }
    out
}

/// The amount at `t`: as written until the wave reaches a cell, then a flicker, then a block.
/// The first three cells settle in the accent, the rest as noise with gaps; spaces stay.
fn sealed_label(t: u64, label: &[char], seed: u64, glyphs: Glyphs) -> Spans {
    let step = step(label.len());
    let solid = match glyphs {
        Glyphs::Unicode => "█",
        Glyphs::Ascii => "#",
    };
    let flicker_count = u64::try_from(FLICKER_GLYPHS.len()).unwrap_or(1);
    let mut spans = Spans::new();
    let mut accent_left = DIGIT_COLUMNS;
    for (index, c) in label.iter().enumerate() {
        let n = u64::try_from(index).unwrap_or(u64::MAX);
        if *c == ' ' {
            spans.push(" ", Tone::Plain);
            continue;
        }
        let accent = accent_left > 0;
        accent_left = accent_left.saturating_sub(1);
        let start = BUILD_MS.saturating_add(n.saturating_mul(step));
        if t < start {
            spans.push(c.to_string(), Tone::Plain);
        } else if t < start.saturating_add(FLICKER_MS) {
            let turn = t.saturating_sub(start) / GLYPH_MS;
            let pick = mix(seed, n)
                .wrapping_add(turn)
                .checked_rem(flicker_count)
                .unwrap_or(0);
            let glyph = usize::try_from(pick)
                .ok()
                .and_then(|pick| FLICKER_GLYPHS.get(pick))
                .copied()
                .unwrap_or(b'#');
            spans.push(char::from(glyph).to_string(), Tone::Dim);
        } else if accent {
            spans.push(solid, Tone::Yellow);
        } else {
            let roll = mix(seed ^ 0x5ea1, n);
            if roll % 100 < GAP_PERCENT {
                spans.push(" ", Tone::Plain);
            } else if (roll >> 8).is_multiple_of(4) {
                spans.push(solid, Tone::Plain);
            } else {
                spans.push(solid, Tone::Dim);
            }
        }
    }
    spans
}

/// One edge of the box, `width` cells, filled from both ends as `filled` of [`CLOSE_MS`] passes.
fn edge(width: usize, filled: u64, cell: &str) -> String {
    let half = width.div_ceil(2);
    let reach = u64::try_from(half)
        .unwrap_or(0)
        .saturating_mul(filled.min(CLOSE_MS))
        .div_ceil(CLOSE_MS);
    let reach = usize::try_from(reach).unwrap_or(half).min(half);
    (0..width)
        .map(|index| {
            if index < reach || index >= width.saturating_sub(reach) {
                cell
            } else {
                " "
            }
        })
        .collect()
}

/// The frame at `t`: a blank row, then the mark beside the box with the amount in it, cut to
/// `columns - 1`. No rows below [`MIN_COLUMNS`]; the status is left out when the row is short.
fn frame(t: u64, label: &[char], seed: u64, glyphs: Glyphs, columns: u16) -> Vec<Spans> {
    if columns < MIN_COLUMNS {
        return Vec::new();
    }
    let (corners, sides, edges) = match glyphs {
        Glyphs::Unicode => (["▗", "▖", "▝", "▘"], ["▐", "▌"], ["▄", "▀"]),
        Glyphs::Ascii => (["+", "+", "+", "+"], ["|", "|"], ["-", "-"]),
    };
    let inner = label.len().saturating_add(2);
    let closing = t.saturating_sub(wave_end(label.len()));
    let status = if t < total(label.len()) {
        SEALING
    } else {
        SENDING
    };
    let room = usize::from(columns.saturating_sub(1));
    let with_status = FIXED_WIDTH
        .saturating_add(label.len())
        .saturating_add(STATUS_GAP.len())
        .saturating_add(status.len())
        <= room;

    let mut rows = vec![Spans::new()];
    for (index, mark_row) in mark(t, glyphs).into_iter().enumerate() {
        let mut row = Spans::of(INDENT, Tone::Plain);
        row.extend(mark_row);
        row.push(GAP, Tone::Plain);
        match index {
            0 => {
                row.push(corners[0], Tone::Dim);
                row.push(edge(inner, closing, edges[0]), Tone::Dim);
                row.push(corners[1], Tone::Dim);
            }
            1 => {
                row.push(sides[0], Tone::Dim);
                row.push(" ", Tone::Plain);
                row.extend(sealed_label(t, label, seed, glyphs));
                row.push(" ", Tone::Plain);
                row.push(sides[1], Tone::Dim);
                if with_status {
                    row.push(STATUS_GAP, Tone::Plain);
                    row.push(status, Tone::Dim);
                }
            }
            _ => {
                row.push(corners[2], Tone::Dim);
                row.push(edge(inner, closing, edges[1]), Tone::Dim);
                row.push(corners[3], Tone::Dim);
            }
        }
        rows.push(row.cut(columns));
    }
    rows
}

/// The line after a sealed payment, within what the epic1 messaging allows: sealed between
/// paired contacts and to an epic1 link, never how. The blocks only follow the animation.
fn last_line(payee: Payee, glyphs: Glyphs, blocks: bool) -> Spans {
    let (solid, sep) = match glyphs {
        Glyphs::Unicode => ("███", "·"),
        Glyphs::Ascii => ("###", "|"),
    };
    let (said, rest) = match payee {
        Payee::Link => ("Sealed with epic1", "only the other wallet can read it"),
        Payee::Contact => (
            "Sealed for your paired contact",
            "only their wallet can read it",
        ),
    };
    let mut line = Spans::new();
    if blocks {
        line.push(solid, Tone::Yellow);
        line.push(" ", Tone::Plain);
    }
    line.push(said, Tone::Bold);
    line.push(format!(" {sep} {rest}"), Tone::Dim);
    line
}

/// Skips the animation of `seal`, if there is one: a key or Ctrl+C was pressed.
pub(crate) fn skip(seal: &mut Option<Seal>) {
    if let Some(seal) = seal {
        seal.skip();
    }
}

/// For trying the shell by hand: in a debug build `LEPIC_SEAL_FAKE_MS=<ms>` makes a sealed send
/// wait that long and report a payment posted, without sending anything.
#[cfg(debug_assertions)]
pub(crate) fn fake_send(
    env: &crate::settings::Env,
    seal: Option<&Seal>,
) -> Option<futures_util::future::LocalBoxFuture<'static, Result<Report, CliError>>> {
    use futures_util::FutureExt as _;

    use crate::output::{Epic1AttemptReport, Epic1PaidReport};

    seal?;
    let millis: u64 = env.get("LEPIC_SEAL_FAKE_MS")?.parse().ok()?;
    Some(
        async move {
            tokio::time::sleep(Duration::from_millis(millis)).await;
            Ok(Report::Epic1Paid(Epic1PaidReport {
                tx_id: 0,
                slate_id: "00000000-0000-0000-0000-000000000000".to_owned(),
                address: "fake send, nothing was sent".to_owned(),
                attempts: vec![Epic1AttemptReport {
                    host: "relay.invalid (fake send)".to_owned(),
                    error: None,
                    uncertain: false,
                }],
                posted: Some(0),
                posted_ok: true,
                repeated: false,
                uncertain: None,
            }))
        }
        .boxed_local(),
    )
}

#[cfg(not(debug_assertions))]
pub(crate) const fn fake_send(
    _env: &crate::settings::Env,
    _seal: Option<&Seal>,
) -> Option<futures_util::future::LocalBoxFuture<'static, Result<Report, CliError>>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Epic1PaidReport;
    use crate::settings::Env;
    use crate::shell::live::colour;

    fn label_of(text: &str, glyphs: Glyphs) -> (Vec<char>, u64) {
        let seal = Seal::new(Payee::Link, Some(text), Show::Animated, glyphs, true);
        (seal.label, seal.seed)
    }

    fn plain(rows: &[Spans]) -> Vec<String> {
        rows.iter().map(Spans::plain).collect()
    }

    #[test]
    fn frames_stay_narrower_than_the_terminal() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for text in [
                "1.5",
                "123456.12345678",
                "0.00000001 and a long message here",
            ] {
                let (label, seed) = label_of(text, glyphs);
                for columns in [0, 1, 20, 43, 44, 45, 48, 49, 50, 52, 60, 80, 200] {
                    for t in (0..=total(label.len()) + 100).step_by(10) {
                        for row in frame(t, &label, seed, glyphs, columns) {
                            assert!(
                                row.width() < usize::from(columns),
                                "{columns} columns, t {t}: {:?}",
                                row.plain()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_last_frame_stands_still() {
        let (label, seed) = label_of("1.5", Glyphs::Unicode);
        let end = total(label.len());
        let last = frame(end, &label, seed, Glyphs::Unicode, 80);
        for later in [end + 1, end + 500, end + 60_000] {
            assert_eq!(frame(later, &label, seed, Glyphs::Unicode, 80), last);
        }
        let text = plain(&last);
        assert_eq!(text[0], "");
        assert_eq!(text[1], format!("  ▄█  ▀ ▄   ▗{}▖", "▄".repeat(10)));
        assert!(text[2].starts_with("   █ ▀ ▄    ▐ ███ "), "{}", text[2]);
        assert!(text[2].ends_with(" ▌  sending"), "{}", text[2]);
        assert_eq!(text[3], format!("  ▀▀▀ ▀     ▝{}▘", "▀".repeat(10)));
    }

    #[test]
    fn the_noise_never_moves_and_the_one_builds_from_its_foot() {
        let (label, seed) = label_of("1.5", Glyphs::Unicode);
        let at = |t| plain(&frame(t, &label, seed, Glyphs::Unicode, 80));
        let columns = |t, skip, take| -> String {
            at(t)
                .iter()
                .skip(1)
                .map(|row| row.chars().skip(skip).take(take).collect::<String>())
                .collect()
        };
        let noise = columns(0, 5, 4);
        assert_eq!(noise, " ▀ ▄▀ ▄  ▀  ");
        for t in (0..total(label.len()) + 100).step_by(20) {
            assert_eq!(columns(t, 5, 4), noise, "t {t}");
        }
        assert_eq!(columns(0, 2, 3).trim(), "");
        assert_eq!(columns(BUILD_ROW_MS, 2, 3), "      ▀▀▀");
        assert_eq!(columns(BUILD_MS, 2, 3), "▄█  █ ▀▀▀");
    }

    #[test]
    fn the_amount_is_sealed_from_the_left() {
        let (label, seed) = label_of("1.5", Glyphs::Unicode);
        let inside = |t| sealed_label(t, &label, seed, Glyphs::Unicode).plain();
        assert_eq!(inside(0), "1.5 EPIC");
        assert_eq!(inside(BUILD_MS - 1), "1.5 EPIC");
        let settled = inside(wave_end(label.len()));
        assert!(settled.starts_with("███ "), "{settled}");
        assert!(settled.chars().all(|c| c == '█' || c == ' '), "{settled}");
        let midway = inside(BUILD_MS + FLICKER_MS);
        assert!(midway.starts_with('█'), "{midway}");
        assert!(midway.ends_with('C'), "{midway}");
    }

    #[test]
    fn the_box_closes_from_the_corners() {
        assert_eq!(edge(10, 0, "-"), "          ");
        assert_eq!(edge(10, CLOSE_MS / 2, "-"), "---    ---");
        assert_eq!(edge(10, CLOSE_MS, "-"), "----------");
        assert_eq!(edge(9, CLOSE_MS, "-"), "---------");
        assert_eq!(edge(10, CLOSE_MS * 9, "-"), "----------");
    }

    #[test]
    fn ascii_frames_hold_only_ascii() {
        let (label, seed) = label_of("9.99", Glyphs::Ascii);
        for t in (0..=total(label.len())).step_by(5) {
            for row in frame(t, &label, seed, Glyphs::Ascii, 80) {
                assert!(row.plain().is_ascii(), "{}", row.plain());
            }
        }
        for payee in [Payee::Link, Payee::Contact] {
            let line = last_line(payee, Glyphs::Ascii, true).plain();
            assert!(line.is_ascii(), "{line}");
        }
    }

    #[test]
    fn the_last_line_is_one_clean_line() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for payee in [Payee::Link, Payee::Contact] {
                for blocks in [true, false] {
                    let spans = last_line(payee, glyphs, blocks);
                    let text = spans.plain();
                    assert!(!text.contains(['\n', '\r', '\x1b']), "{text:?}");
                    assert_eq!(text.trim(), text);
                    let lower = text.to_lowercase();
                    for word in ["hpke", "envelope", "key", "shield", "encrypt"] {
                        assert!(!lower.contains(word), "{text}");
                    }
                    let rendered = spans.render(true);
                    assert!(
                        rendered.ends_with(crate::shell::paint::RESET),
                        "{rendered:?}"
                    );
                    assert_eq!(spans.render(false), text);
                }
            }
        }
        assert_eq!(
            last_line(Payee::Link, Glyphs::Unicode, true).plain(),
            "███ Sealed with epic1 · only the other wallet can read it"
        );
        assert_eq!(
            last_line(Payee::Contact, Glyphs::Ascii, false).plain(),
            "Sealed for your paired contact | only their wallet can read it"
        );
    }

    #[test]
    fn the_line_follows_the_result() {
        let paid = |posted_ok: bool, repeated: bool| {
            Ok(Report::Epic1Paid(Epic1PaidReport {
                tx_id: 1,
                slate_id: String::new(),
                address: String::new(),
                attempts: Vec::new(),
                posted: posted_ok.then_some(0),
                posted_ok,
                repeated,
                uncertain: None,
            }))
        };
        let seal = Seal::new(Payee::Link, Some("1"), Show::Line, Glyphs::Unicode, false);
        assert_eq!(
            seal.last_line(&paid(true, false)).as_deref(),
            Some("Sealed with epic1 · only the other wallet can read it")
        );
        assert_eq!(seal.last_line(&paid(false, false)), None);
        assert_eq!(seal.last_line(&paid(true, true)), None);
        assert_eq!(
            seal.last_line(&Err(CliError::Arguments("no".to_owned()))),
            None
        );
        let json = Seal::new(
            Payee::Link,
            Some("1"),
            Show::Nothing,
            Glyphs::Unicode,
            false,
        );
        assert_eq!(json.last_line(&paid(true, false)), None);
    }

    #[test]
    fn the_plain_line_is_chosen_for_each_off_case() {
        let human = OutputFormat::Human;
        assert_eq!(show(human, true, true, 80, 24), Show::Animated);
        assert_eq!(show(OutputFormat::Json, true, true, 80, 24), Show::Nothing);
        assert_eq!(show(human, false, true, 80, 24), Show::Line, "no colour");
        assert_eq!(show(human, true, false, 80, 24), Show::Line, "no terminal");
        assert_eq!(show(human, true, true, MIN_COLUMNS - 1, 24), Show::Line);
        assert_eq!(show(human, true, true, 80, MIN_ROWS - 1), Show::Line);
        assert_eq!(
            show(human, true, true, MIN_COLUMNS, MIN_ROWS),
            Show::Animated
        );

        let env = |pairs: &[(&str, &str)]| {
            Env::new(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
            )
        };
        for pairs in [&[("NO_COLOR", "1")][..], &[("TERM", "dumb")][..]] {
            let colour = colour(&env(pairs), true);
            assert_eq!(show(human, colour, true, 80, 24), Show::Line, "{pairs:?}");
        }
        let colour = colour(&env(&[("TERM", "xterm-256color")]), true);
        assert_eq!(show(human, colour, true, 80, 24), Show::Animated);
    }

    #[test]
    fn a_skip_goes_to_the_last_frame() {
        let mut seal = Seal::new(
            Payee::Link,
            Some("1.5"),
            Show::Animated,
            Glyphs::Unicode,
            true,
        );
        assert!(seal.moving());
        assert_eq!(seal.rows(80).len(), 4);
        seal.skip();
        assert!(!seal.moving());
        let mut line = Seal::new(Payee::Link, Some("1.5"), Show::Line, Glyphs::Unicode, true);
        assert!(!line.moving());
        assert!(line.rows(80).is_empty());
    }

    #[test]
    fn long_amounts_are_cut() {
        let (label, _) = label_of("1234567890.12345678 and more", Glyphs::Unicode);
        assert_eq!(label.len(), LABEL_MAX);
        assert_eq!(label.last(), Some(&'…'));
        let (label, _) = label_of("1234567890.12345678 and more", Glyphs::Ascii);
        assert_eq!(label.len(), LABEL_MAX);
        assert!(label.ends_with(&['.', '.', '.']));
        assert_eq!(
            Seal::new(Payee::Link, None, Show::Line, Glyphs::Ascii, false).label,
            "payment".chars().collect::<Vec<_>>()
        );
    }
}
