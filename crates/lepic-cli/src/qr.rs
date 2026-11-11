// SPDX-License-Identifier: Apache-2.0
//! QR codes of addresses and links, drawn in the terminal under the command's text: by default
//! in the shell, with `--qr` elsewhere. Never in JSON output and never when standard output is
//! not a terminal.
//!
//! A code is dark modules on a light field. With colour the light field, quiet zone included, is
//! painted bright white behind black modules, so the code scans on dark and light themes alike.
//! Without colour (`NO_COLOR`) the glyphs are the terminal's own ink: the light modules are
//! inked and the dark ones left blank, so the quiet zone stays visible. That is the right way
//! round on a dark theme; on a light theme the code comes out inverted, which some readers do
//! not take.

use std::io::Write as _;

use qrcode::{Color, EcLevel, QrCode};

use crate::Console;
use crate::cli::{Command, ContactCommand, Epic1Command, TorCommand, WalletCommand};
use crate::output::Report;
use crate::settings::OutputFormat;
use crate::shell::card::Glyphs;

/// Black ink on a bright white background: the light field.
const FIELD: &str = "\x1b[30;107m";
/// A black background: a dark module in the ASCII drawing.
const DARK_FIELD: &str = "\x1b[40m";
const RESET: &str = "\x1b[0m";

/// The quiet zone the standard asks for, and the narrower one used when that does not fit.
const QUIET: usize = 4;
const NARROW_QUIET: usize = 2;

/// What the terminal offers a code.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Canvas {
    pub columns: usize,
    pub glyphs: Glyphs,
    pub colour: bool,
}

/// A code ready to print.
#[derive(Debug)]
pub(crate) struct Drawn {
    pub rows: Vec<String>,
    /// Columns every row takes on screen. The size and level are kept for the tests only.
    #[cfg(test)]
    pub width: usize,
    /// Modules of quiet zone round the code.
    #[cfg(test)]
    pub quiet: usize,
    #[cfg(test)]
    pub level: EcLevel,
}

impl Drawn {
    pub(crate) fn text(&self) -> String {
        let mut text = self.rows.join("\n");
        text.push('\n');
        text
    }
}

/// Why no code was drawn.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    TooLong,
    TooNarrow { needed: usize, columns: usize },
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => write!(f, "No QR code: the text is too long for one."),
            Self::TooNarrow { needed, columns } => write!(
                f,
                "No QR code: it needs a window {needed} columns wide and this one has {columns}."
            ),
        }
    }
}

/// Draws `text` as a QR code that fits `canvas`, one column short of its width so the terminal
/// never wraps a row.
///
/// Level M (a code still reads with 15% of it lost) is the usual choice for a code on a screen:
/// it survives glare, moiré and a camera that sees the window at an angle, and an epic1 link
/// still fits in 80 columns at M. A long link that would not fit at M drops to L (7%), which a
/// sharp screen still reads, before the quiet zone shrinks from 4 modules to 2.
pub(crate) fn draw(text: &str, canvas: Canvas) -> Result<Drawn, Refused> {
    let usable = canvas.columns.saturating_sub(1);
    let mut needed: Option<usize> = None;
    for (level, quiet) in [
        (EcLevel::M, QUIET),
        (EcLevel::L, QUIET),
        (EcLevel::L, NARROW_QUIET),
    ] {
        let Ok(code) = QrCode::with_error_correction_level(text, level) else {
            continue;
        };
        let field = Field::new(&code, quiet);
        let width = field.side.saturating_mul(module_columns(canvas.glyphs));
        if width <= usable {
            return Ok(Drawn {
                rows: field.rows(canvas.glyphs, canvas.colour),
                #[cfg(test)]
                width,
                #[cfg(test)]
                quiet,
                #[cfg(test)]
                level,
            });
        }
        needed = Some(needed.map_or(width, |was| was.min(width)));
    }
    Err(
        needed.map_or(Refused::TooLong, |needed| Refused::TooNarrow {
            needed: needed.saturating_add(1),
            columns: canvas.columns,
        }),
    )
}

/// Columns one module takes: a half-block cell is one column wide and two modules tall, about
/// square; ASCII draws a module as two characters on its own row.
const fn module_columns(glyphs: Glyphs) -> usize {
    match glyphs {
        Glyphs::Unicode => 1,
        Glyphs::Ascii => 2,
    }
}

/// The code's modules inside their quiet zone.
struct Field {
    side: usize,
    quiet: usize,
    code_width: usize,
    modules: Vec<Color>,
}

impl Field {
    fn new(code: &QrCode, quiet: usize) -> Self {
        let code_width = code.width();
        Self {
            side: code_width.saturating_add(quiet.saturating_mul(2)),
            quiet,
            code_width,
            modules: code.to_colors(),
        }
    }

    /// Whether the module at column `x`, row `y` of the field is dark; `None` past its edge.
    fn dark(&self, x: usize, y: usize) -> Option<bool> {
        if x >= self.side || y >= self.side {
            return None;
        }
        let inside = |at: usize| {
            at.checked_sub(self.quiet)
                .filter(|at| *at < self.code_width)
        };
        let dark = match (inside(x), inside(y)) {
            (Some(x), Some(y)) => y
                .checked_mul(self.code_width)
                .and_then(|row| row.checked_add(x))
                .and_then(|at| self.modules.get(at))
                .is_some_and(|color| *color == Color::Dark),
            _ => false,
        };
        Some(dark)
    }

    fn rows(&self, glyphs: Glyphs, colour: bool) -> Vec<String> {
        match glyphs {
            Glyphs::Unicode => self.half_block_rows(colour),
            Glyphs::Ascii => self.ascii_rows(colour),
        }
    }

    /// Two field rows per text row. With colour a glyph's ink is a dark module on the white
    /// field; without, a light one. The half row under an odd last row is white with colour and
    /// blank without, outside the code either way.
    fn half_block_rows(&self, colour: bool) -> Vec<String> {
        (0..self.side)
            .step_by(2)
            .map(|y| {
                let mut row = String::new();
                if colour {
                    row.push_str(FIELD);
                }
                for x in 0..self.side {
                    let top = self.dark(x, y);
                    let bottom = self.dark(x, y.saturating_add(1));
                    let inked = if colour {
                        (top == Some(true), bottom == Some(true))
                    } else {
                        (top == Some(false), bottom == Some(false))
                    };
                    row.push(half_block(inked));
                }
                if colour {
                    row.push_str(RESET);
                }
                row
            })
            .collect()
    }

    /// One field row per text row, two characters a module: with colour as black and white
    /// cells, without as `##` for a light module and two blanks for a dark one.
    fn ascii_rows(&self, colour: bool) -> Vec<String> {
        (0..self.side)
            .map(|y| {
                let mut row = String::new();
                let mut painted = None;
                for x in 0..self.side {
                    let dark = self.dark(x, y) == Some(true);
                    if colour {
                        if painted != Some(dark) {
                            row.push_str(if dark { DARK_FIELD } else { FIELD });
                            painted = Some(dark);
                        }
                        row.push_str("  ");
                    } else {
                        row.push_str(if dark { "  " } else { "##" });
                    }
                }
                if colour {
                    row.push_str(RESET);
                }
                row
            })
            .collect()
    }
}

/// The half block inked at the top, the bottom, both or neither.
const fn half_block((top, bottom): (bool, bool)) -> char {
    match (top, bottom) {
        (true, true) => '█',
        (true, false) => '▀',
        (false, true) => '▄',
        (false, false) => ' ',
    }
}

/// What a report shows as a code: an address or a link to hand someone else.
pub(crate) fn payload(report: &Report) -> Option<&str> {
    match report {
        Report::Address(r) => Some(&r.address),
        Report::Epic1Address(r) => Some(&r.address),
        Report::Epic1Link(r) => Some(&r.link),
        Report::TorAddress(r) => Some(&r.onion),
        Report::ContactInvite(r) => Some(&r.link),
        Report::ContactAccept(r) if !r.posted => Some(&r.reply_link),
        Report::ContactLink(r) if r.outcome == "confirm" => r.link.as_deref(),
        _ => None,
    }
}

/// Whether the command line asks for a code with `--qr`.
pub(crate) fn requested(command: &Command) -> bool {
    match command {
        Command::Wallet(WalletCommand::Address(arg)) => arg.qr,
        Command::Tor(TorCommand::Address(args)) => args.qr.qr,
        Command::Epic1(args) => match &args.command {
            Epic1Command::Address(args) => args.qr.qr,
            Epic1Command::NewAddress(args) => args.qr.qr,
            Epic1Command::Link(args) => args.qr.qr,
            _ => false,
        },
        Command::Contact(args) => match &args.command {
            ContactCommand::Invite(args) => args.qr.qr,
            ContactCommand::Accept(args) => args.qr.qr,
            ContactCommand::Enter(args) => args.qr.qr,
            _ => false,
        },
        _ => false,
    }
}

/// The report of a command that may draw a code, from the JSON serve answered, so the CLI
/// prints the text it would have printed and draws the code from the same report.
#[cfg(unix)]
pub(crate) fn report_from_json(command: &Command, json: &str) -> serde_json::Result<Report> {
    use serde::de::Error as _;
    let other = || serde_json::Error::custom("the command draws no QR code");
    match command {
        Command::Wallet(WalletCommand::Address(_)) => owned(json).map(Report::Address),
        Command::Tor(TorCommand::Address(_)) => owned(json).map(Report::TorAddress),
        Command::Epic1(args) => match &args.command {
            Epic1Command::Address(_) | Epic1Command::NewAddress(_) => {
                owned(json).map(Report::Epic1Address)
            }
            Epic1Command::Link(_) => owned(json).map(Report::Epic1Link),
            _ => Err(other()),
        },
        Command::Contact(args) => match &args.command {
            ContactCommand::Invite(_) => owned(json).map(Report::ContactInvite),
            ContactCommand::Accept(_) => owned(json).map(Report::ContactAccept),
            ContactCommand::Enter(_) => owned(json).map(Report::ContactLink),
            _ => Err(other()),
        },
        _ => Err(other()),
    }
}

/// Reads `json` into a report through an owned value: a report's word fields are `&'static
/// str`, which serde would otherwise borrow from the text.
#[cfg(unix)]
fn owned<T: serde::Deserialize<'static>>(json: &str) -> serde_json::Result<T> {
    T::deserialize(serde_json::from_str::<serde_json::Value>(json)?)
}

/// Prints the code of `payload` on standard output after a command's text, for `--qr`. Off a
/// terminal, or in a window too narrow, it says on standard error why there is none.
pub(crate) fn print_after(console: &mut Console, format: OutputFormat, payload: &str) {
    if format != OutputFormat::Human {
        return;
    }
    if !console.stdout_terminal {
        let _ = writeln!(
            console.stderr,
            "No QR code: standard output is not a terminal."
        );
        return;
    }
    let canvas = Canvas {
        columns: terminal_columns(),
        glyphs: crate::shell::live::glyphs(&console.env),
        colour: crate::shell::live::colour(&console.env, true) && ansi_works(),
    };
    match draw(payload, canvas) {
        Ok(drawn) => {
            let _ = console
                .stdout
                .write_all(format!("\n{}", drawn.text()).as_bytes())
                .and_then(|()| console.stdout.flush());
        }
        Err(refused) => {
            let _ = writeln!(console.stderr, "{refused}");
        }
    }
}

/// What the shell prints under a report that has a code: the code when the window is wide
/// enough, else a dim line that says why there is none.
pub(crate) fn for_shell(
    report: &Report,
    format: OutputFormat,
    columns: u16,
    glyphs: Glyphs,
    colour: bool,
) -> Option<String> {
    if format != OutputFormat::Human {
        return None;
    }
    let canvas = Canvas {
        columns: usize::from(columns),
        glyphs,
        colour,
    };
    Some(match draw(payload(report)?, canvas) {
        Ok(drawn) => format!("\n{}", drawn.text()),
        Err(refused) => {
            let mut note = crate::shell::paint::tint(
                &refused.to_string(),
                crate::shell::paint::Tone::Dim,
                colour,
            );
            note.push('\n');
            note
        }
    })
}

fn terminal_columns() -> usize {
    crossterm::terminal::size().map_or(80, |(columns, _)| usize::from(columns))
}

/// Whether escape sequences reach the console as colour. A Windows console needs virtual
/// terminal processing on, which crossterm switches on when it can.
fn ansi_works() -> bool {
    #[cfg(windows)]
    {
        crossterm::ansi_support::supports_ansi()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, index and count freely (docs/rules.md).
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// The length of an epic1 link with an amount, a message and one relay.
    const LINK: &str = "epic:epic1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsq8x9kz2\
                        ?amount=12.5&message=coffee&epicbox=epicbox.epiccash.com";

    fn canvas(columns: usize, glyphs: Glyphs, colour: bool) -> Canvas {
        Canvas {
            columns,
            glyphs,
            colour,
        }
    }

    fn strip_ansi(row: &str) -> String {
        let mut out = String::new();
        let mut chars = row.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
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

    /// Reads drawn rows back to modules, `true` for dark, quiet zone included: the inverse of
    /// each drawing, to show it loses nothing.
    fn read_back(drawn: &Drawn, glyphs: Glyphs, colour: bool) -> Vec<Vec<bool>> {
        let mut matrix = Vec::new();
        for row in &drawn.rows {
            match glyphs {
                Glyphs::Unicode => {
                    let cells: Vec<(bool, bool)> = strip_ansi(row)
                        .chars()
                        .map(|c| {
                            let (top, bottom) = match c {
                                '█' => (true, true),
                                '▀' => (true, false),
                                '▄' => (false, true),
                                ' ' => (false, false),
                                other => panic!("unexpected glyph {other:?}"),
                            };
                            if colour {
                                (top, bottom)
                            } else {
                                (!top, !bottom)
                            }
                        })
                        .collect();
                    matrix.push(cells.iter().map(|cell| cell.0).collect());
                    matrix.push(cells.iter().map(|cell| cell.1).collect());
                }
                Glyphs::Ascii if colour => {
                    // Each module is two blanks on a background that gives its colour.
                    let mut dark = false;
                    let mut modules = Vec::new();
                    let mut rest = row.as_str();
                    while !rest.is_empty() {
                        if let Some(after) = rest.strip_prefix(DARK_FIELD) {
                            dark = true;
                            rest = after;
                        } else if let Some(after) = rest.strip_prefix(FIELD) {
                            dark = false;
                            rest = after;
                        } else if let Some(after) = rest.strip_prefix(RESET) {
                            rest = after;
                        } else if let Some(after) = rest.strip_prefix("  ") {
                            modules.push(dark);
                            rest = after;
                        } else {
                            panic!("unexpected text {rest:?}");
                        }
                    }
                    matrix.push(modules);
                }
                Glyphs::Ascii => {
                    let chars: Vec<char> = row.chars().collect();
                    matrix.push(
                        chars
                            .chunks(2)
                            .map(|pair| match pair {
                                ['#', '#'] => false,
                                [' ', ' '] => true,
                                other => panic!("unexpected cell {other:?}"),
                            })
                            .collect(),
                    );
                }
            }
        }
        matrix
    }

    /// The modules the code should have: qrcode's matrix in a light quiet zone.
    fn expected(text: &str, level: EcLevel, quiet: usize) -> Vec<Vec<bool>> {
        let code = QrCode::with_error_correction_level(text, level).unwrap();
        let width = code.width();
        let side = width + 2 * quiet;
        (0..side)
            .map(|y| {
                (0..side)
                    .map(|x| {
                        (quiet..quiet + width).contains(&x)
                            && (quiet..quiet + width).contains(&y)
                            && code[(x - quiet, y - quiet)] == Color::Dark
                    })
                    .collect()
            })
            .collect()
    }

    fn side(text: &str, level: EcLevel, quiet: usize) -> usize {
        QrCode::with_error_correction_level(text, level)
            .unwrap()
            .width()
            + 2 * quiet
    }

    #[test]
    fn every_drawing_reads_back_to_the_codes_modules() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for colour in [true, false] {
                let drawn = draw(LINK, canvas(400, glyphs, colour)).unwrap();
                let want = expected(LINK, drawn.level, drawn.quiet);
                let mut read = read_back(&drawn, glyphs, colour);
                if matches!(glyphs, Glyphs::Unicode) && want.len() % 2 == 1 {
                    // The half row under an odd last row is outside the field: blank.
                    let outside = read.pop().unwrap();
                    assert!(outside.iter().all(|dark| *dark != colour));
                }
                assert_eq!(read, want, "{glyphs:?}, colour {colour}");
            }
        }
    }

    #[test]
    fn each_row_takes_the_width_it_reports() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            for colour in [true, false] {
                let drawn = draw(LINK, canvas(400, glyphs, colour)).unwrap();
                let side = side(LINK, drawn.level, drawn.quiet);
                assert_eq!(drawn.width, side * module_columns(glyphs));
                for row in &drawn.rows {
                    assert_eq!(strip_ansi(row).chars().count(), drawn.width);
                }
                let rows = match glyphs {
                    Glyphs::Unicode => side.div_ceil(2),
                    Glyphs::Ascii => side,
                };
                assert_eq!(drawn.rows.len(), rows);
            }
        }
    }

    #[test]
    fn an_epic1_link_fits_80_columns_at_level_m_with_four_quiet_modules() {
        let drawn = draw(LINK, canvas(80, Glyphs::Unicode, true)).unwrap();
        assert_eq!((drawn.level, drawn.quiet), (EcLevel::M, QUIET));
        let read = read_back(&drawn, Glyphs::Unicode, true);
        let side = drawn.width;
        for (y, row) in read.iter().take(side).enumerate() {
            for (x, dark) in row.iter().enumerate() {
                let zone = x < QUIET || y < QUIET || x >= side - QUIET || y >= side - QUIET;
                assert!(
                    !(zone && *dark),
                    "a dark module in the quiet zone at {x},{y}"
                );
            }
        }
    }

    #[test]
    fn a_long_link_drops_to_level_l_then_to_a_two_module_quiet_zone() {
        let long = format!("epiccash://pair?{}", "a".repeat(180));
        let m = side(&long, EcLevel::M, QUIET);
        let l = side(&long, EcLevel::L, QUIET);
        let l_narrow = side(&long, EcLevel::L, NARROW_QUIET);
        assert!(l < m && l_narrow < l);
        let at = |columns| {
            let drawn = draw(&long, canvas(columns, Glyphs::Unicode, true)).unwrap();
            (drawn.level, drawn.quiet)
        };
        assert_eq!(at(m + 1), (EcLevel::M, QUIET));
        assert_eq!(at(m), (EcLevel::L, QUIET));
        assert_eq!(at(l), (EcLevel::L, NARROW_QUIET));
    }

    #[test]
    fn a_window_too_narrow_gets_no_code() {
        let smallest = side(LINK, EcLevel::L, NARROW_QUIET);
        assert_eq!(
            draw(LINK, canvas(smallest, Glyphs::Unicode, true)).unwrap_err(),
            Refused::TooNarrow {
                needed: smallest + 1,
                columns: smallest,
            }
        );
        assert!(draw(LINK, canvas(smallest + 1, Glyphs::Unicode, true)).is_ok());
        assert_eq!(
            draw(LINK, canvas(80, Glyphs::Ascii, false)).unwrap_err(),
            Refused::TooNarrow {
                needed: smallest * 2 + 1,
                columns: 80,
            }
        );
    }

    #[test]
    fn text_past_the_largest_code_is_refused() {
        let huge = "x".repeat(3000);
        assert_eq!(
            draw(&huge, canvas(1000, Glyphs::Unicode, true)).unwrap_err(),
            Refused::TooLong
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_report_serve_answered_gives_the_code_the_cli_would_draw() {
        use crate::cli::Cli;
        use crate::output::{ContactLinkReport, Epic1LinkReport};
        use clap::Parser as _;

        let link = Report::Epic1Link(Epic1LinkReport {
            link: LINK.to_owned(),
            address: "epic1example".to_owned(),
            index: 2,
            kind: "printed",
            n: 7,
        });
        let confirm = Report::ContactLink(ContactLinkReport {
            outcome: "confirm",
            contact_id: Some("00".to_owned()),
            link: Some("epiccash://pair/1/confirm".to_owned()),
        });
        for (line, report) in [
            (&["lepic", "epic1", "link", "--qr"][..], &link),
            (
                &["lepic", "contact", "enter", "epiccash://pair/1/x", "--qr"],
                &confirm,
            ),
        ] {
            let command = Cli::try_parse_from(line).unwrap().command;
            assert!(requested(&command));
            let json = serde_json::to_string(report).unwrap();
            let back = report_from_json(&command, &json).unwrap();
            assert_eq!(payload(&back), payload(report));
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        let command = Cli::try_parse_from(["lepic", "epic1", "link"])
            .unwrap()
            .command;
        assert!(!requested(&command));
        let odd = r#"{"link":"x","address":"y","index":0,"kind":"framed","n":0}"#;
        assert!(report_from_json(&command, odd).is_err());
    }

    #[test]
    fn plain_ascii_rows_are_plain_ascii() {
        let drawn = draw(LINK, canvas(400, Glyphs::Ascii, false)).unwrap();
        assert!(
            drawn
                .rows
                .iter()
                .all(|row| row.is_ascii() && !row.contains('\x1b'))
        );
    }

    #[test]
    fn colour_rows_end_in_a_reset() {
        for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
            let drawn = draw(LINK, canvas(400, glyphs, true)).unwrap();
            assert!(drawn.rows.iter().all(|row| row.ends_with(RESET)));
        }
    }
}
