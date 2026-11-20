// SPDX-License-Identifier: Apache-2.0
//! Where the shell's output goes. While the user edits a line the editor owns the terminal, so
//! lines wait in a queue it prints above the prompt. While a command runs the shell draws its
//! own footer under the output and repaints it in one write per change. Otherwise lines go
//! straight to the terminal.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crossterm::cursor::{Hide, MoveUp, Show};
use crossterm::queue;
use crossterm::style::Print;
use crossterm::terminal::{
    BeginSynchronizedUpdate, Clear, ClearType, DisableLineWrap, EnableLineWrap,
    EndSynchronizedUpdate,
};
use lepic_telemetry::{LogLevel, LogRecord, LogSink};
use reedline::{ExternalOutput, RepaintSignal};
use zeroize::Zeroizing;

use crate::shell::editor::columns;
use crate::shell::live::{Look, printable};
use crate::shell::paint::{Spans, Tone};

/// How long a log line that was shown is not shown again.
const SAME_LOG_LINE_EVERY: Duration = Duration::from_secs(600);
/// How many different log lines are remembered as shown.
const LOG_LINES_REMEMBERED: usize = 32;
/// How often the spinner of [`Screen::busy`] moves.
const SPIN: Duration = Duration::from_millis(100);

/// Who draws the bottom of the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Nobody: lines are written as they come.
    Direct,
    /// The line editor: lines wait in the queue it drains.
    Editing,
    /// The shell, with its footer under the output.
    Running,
}

struct Inner {
    mode: Mode,
    queue: VecDeque<String>,
    footer: Option<[String; 4]>,
    /// Rows drawn above the footer while a command runs, such as the epic1 seal.
    art: Vec<String>,
    out: Box<dyn Write + Send>,
    repaint: Option<RepaintSignal>,
}

/// The terminal as the session and its commands share it.
#[derive(Clone)]
pub(crate) struct Screen(Arc<Mutex<Inner>>);

impl Screen {
    pub(crate) fn new(out: Box<dyn Write + Send>) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            mode: Mode::Direct,
            queue: VecDeque::new(),
            footer: None,
            art: Vec::new(),
            out,
            repaint: None,
        })))
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The signal that makes the editor draw its prompt again, for status changes.
    pub(crate) fn set_repaint(&self, signal: RepaintSignal) {
        self.inner().repaint = Some(signal);
    }

    /// Asks the editor to draw the prompt again; nothing outside editing.
    pub(crate) fn repaint(&self) {
        let inner = self.inner();
        if inner.mode == Mode::Editing
            && let Some(signal) = &inner.repaint
        {
            signal.request_repaint();
        }
    }

    /// Prints `text`, one line per line of it.
    pub(crate) fn print(&self, text: &str) {
        let text = text.strip_suffix('\n').unwrap_or(text);
        let mut inner = self.inner();
        match inner.mode {
            Mode::Editing => inner.queue.extend(
                text.split('\n')
                    .map(|line| line.trim_end_matches('\r').to_owned()),
            ),
            Mode::Running => {
                let _ = inner.paint(Some(text));
            }
            Mode::Direct => {
                let _ = inner.write_lines(text);
            }
        }
    }

    /// The editor is about to read a line.
    pub(crate) fn editing(&self) {
        let mut inner = self.inner();
        let _ = inner.leave();
        inner.mode = Mode::Editing;
    }

    /// The editor gave the terminal back: what waits in the queue is printed.
    pub(crate) fn direct(&self) {
        let mut inner = self.inner();
        let _ = inner.leave();
        inner.mode = Mode::Direct;
    }

    /// A command runs: `footer` goes under its output.
    pub(crate) fn running(&self, footer: [String; 4]) {
        let mut inner = self.inner();
        inner.run();
        inner.footer = Some(footer);
        let _ = inner.paint(None);
    }

    /// Draws `art` above the footer while a command runs, from before the footer shows.
    pub(crate) fn art(&self, art: Vec<String>) {
        let mut inner = self.inner();
        if inner.art.is_empty() && art.is_empty() {
            return;
        }
        inner.run();
        inner.art = art;
        let _ = inner.paint(None);
    }

    /// Draws `lines` over the `over` rows printed last, outside editing and running: for the
    /// frames of the welcome card.
    pub(crate) fn redraw(&self, lines: &[String], over: usize) {
        let mut inner = self.inner();
        if inner.mode == Mode::Direct {
            let _ = inner.write_over(lines, over);
        }
    }

    /// Shows `label` beside the spinner on a row of its own while `work` runs, then clears the
    /// row. Without motion the label is printed once and stays.
    pub(crate) async fn busy<T>(
        &self,
        look: Look,
        label: &str,
        work: impl Future<Output = T>,
    ) -> T {
        if !look.motion {
            self.print(&look.tint(&format!("{label}{}", look.marks.ellipsis), Tone::Dim));
            return work.await;
        }
        let mut work = std::pin::pin!(work);
        let mut ticker = tokio::time::interval(SPIN);
        let mut tick = 0_usize;
        let done = loop {
            tokio::select! {
                done = &mut work => break done,
                _ = ticker.tick() => {
                    let mut row = Spans::of(look.marks.spinner(tick), Tone::Green);
                    row.push(format!(" {label}"), Tone::Dim);
                    self.art(vec![row.cut(columns()).render(look.paint)]);
                    tick = tick.wrapping_add(1);
                }
            }
        };
        self.direct();
        done
    }

    /// Draws `footer` in place of the one shown, while a command runs.
    pub(crate) fn footer(&self, footer: [String; 4]) {
        let mut inner = self.inner();
        if inner.mode == Mode::Running {
            inner.footer = Some(footer);
            let _ = inner.paint(None);
        }
    }
}

impl Inner {
    /// Enters running, unless it runs already.
    fn run(&mut self) {
        if self.mode != Mode::Running {
            let _ = self.leave();
            self.mode = Mode::Running;
            let _ = queue!(self.out, Hide);
        }
    }

    /// Ends the current mode: the queue is printed, the footer cleared.
    fn leave(&mut self) -> io::Result<()> {
        match self.mode {
            Mode::Editing => {
                let lines: Vec<String> = self.queue.drain(..).collect();
                for line in lines {
                    self.write_lines(&line)?;
                }
            }
            Mode::Running => {
                self.footer = None;
                self.art.clear();
                queue!(
                    self.out,
                    Print("\r"),
                    Clear(ClearType::FromCursorDown),
                    Show
                )?;
                self.out.flush()?;
            }
            Mode::Direct => {}
        }
        Ok(())
    }

    fn write_lines(&mut self, text: &str) -> io::Result<()> {
        let mut buffer = Zeroizing::new(Vec::new());
        for line in text.split('\n') {
            buffer.extend_from_slice(line.trim_end_matches('\r').as_bytes());
            buffer.extend_from_slice(b"\r\n");
        }
        self.out.write_all(&buffer)?;
        self.out.flush()
    }

    /// Writes `lines` over the `over` rows above the cursor, in one synchronized write.
    fn write_over(&mut self, lines: &[String], over: usize) -> io::Result<()> {
        let mut buffer = Vec::new();
        queue!(buffer, BeginSynchronizedUpdate, Hide, Print("\r"))?;
        if let Ok(up) = u16::try_from(over)
            && up > 0
        {
            queue!(buffer, MoveUp(up))?;
        }
        queue!(buffer, Clear(ClearType::FromCursorDown))?;
        for line in lines {
            buffer.extend_from_slice(line.as_bytes());
            buffer.extend_from_slice(b"\r\n");
        }
        queue!(buffer, Show, EndSynchronizedUpdate)?;
        self.out.write_all(&buffer)?;
        self.out.flush()
    }

    /// Clears the footer, prints `text` where it was and draws the art and the footer under it,
    /// in one synchronized write. The cursor rests on their first row, a blank one, so a resize
    /// that rewraps the rows below it is cleared by the next paint. The art and the footer are
    /// drawn with autowrap off: rows cut for a width the terminal has just left are clipped
    /// instead of wrapped, so the move back up lands on the first row.
    fn paint(&mut self, text: Option<&str>) -> io::Result<()> {
        let mut buffer = Zeroizing::new(Vec::new());
        queue!(
            buffer,
            BeginSynchronizedUpdate,
            Print("\r"),
            Clear(ClearType::FromCursorDown)
        )?;
        if let Some(text) = text {
            for line in text.split('\n') {
                buffer.extend_from_slice(line.trim_end_matches('\r').as_bytes());
                buffer.extend_from_slice(b"\r\n");
            }
        }
        let rows: Vec<&str> = self
            .art
            .iter()
            .chain(self.footer.iter().flatten())
            .map(String::as_str)
            .collect();
        if !rows.is_empty() {
            queue!(buffer, DisableLineWrap)?;
            buffer.extend_from_slice(rows.join("\r\n").as_bytes());
            let up = u16::try_from(rows.len().saturating_sub(1)).unwrap_or(0);
            if up > 0 {
                queue!(buffer, MoveUp(up))?;
            }
            queue!(buffer, Print("\r"), EnableLineWrap)?;
        }
        queue!(buffer, EndSynchronizedUpdate)?;
        self.out.write_all(&buffer)?;
        self.out.flush()
    }
}

/// What the editor prints above the prompt: the lines queued while it reads.
pub(crate) struct Queue(pub Screen);

impl ExternalOutput for Queue {
    fn drain(&mut self) -> io::Result<Vec<String>> {
        let mut inner = self.0.inner();
        if inner.mode != Mode::Editing {
            return Ok(Vec::new());
        }
        Ok(inner.queue.drain(..).collect())
    }
}

/// A command's standard output or error in the shell: whole lines go to the screen as they end.
pub(crate) struct ScreenWriter {
    screen: Screen,
    partial: Zeroizing<Vec<u8>>,
}

impl ScreenWriter {
    pub(crate) fn new(screen: Screen) -> Self {
        Self {
            screen,
            partial: Zeroizing::new(Vec::new()),
        }
    }
}

impl Write for ScreenWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.partial.extend_from_slice(bytes);
        if let Some(end) = self.partial.iter().rposition(|byte| *byte == b'\n') {
            let whole = Zeroizing::new(
                String::from_utf8_lossy(self.partial.get(..end).unwrap_or(&[])).into_owned(),
            );
            self.screen.print(&whole);
            self.partial.drain(..=end);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ScreenWriter {
    fn drop(&mut self) {
        if !self.partial.is_empty() {
            let rest = Zeroizing::new(String::from_utf8_lossy(&self.partial).into_owned());
            self.screen.print(&rest);
        }
    }
}

/// The session's log lines, on the screen, one row each: `warn  target: message key=value`,
/// the level in its colour and the rest dim, cut at the terminal's edge so a long line does
/// not push the session's own output away. A line with the level, target and message of one
/// shown in the last ten minutes is held back, and counted on the next one shown: a node that
/// does not answer is retried every minute, and says so once.
pub(crate) struct ShellLog {
    screen: Screen,
    look: Look,
    shown: Mutex<Vec<Shown>>,
}

/// A log line that was shown: when, and how many like it were held back since.
struct Shown {
    line: String,
    at: Instant,
    held: u32,
}

impl ShellLog {
    pub(crate) const fn new(screen: Screen, look: Look) -> Self {
        Self {
            screen,
            look,
            shown: Mutex::new(Vec::new()),
        }
    }

    /// Whether `line`, seen at `now`, is shown: `Some` with how many like it were held back
    /// since it was last shown, `None` when it is held back too.
    fn admit(&self, line: String, now: Instant) -> Option<u32> {
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(before) = shown.iter_mut().find(|before| before.line == line) {
            if now.saturating_duration_since(before.at) < SAME_LOG_LINE_EVERY {
                before.held = before.held.saturating_add(1);
                return None;
            }
            before.at = now;
            return Some(std::mem::take(&mut before.held));
        }
        if shown.len() >= LOG_LINES_REMEMBERED {
            shown.remove(0);
        }
        shown.push(Shown {
            line,
            at: now,
            held: 0,
        });
        Some(0)
    }
}

impl LogSink for ShellLog {
    fn record(&self, record: LogRecord) {
        let (level, _) = level_name(record.level);
        let same = format!("{level} {}: {}", record.target, record.message);
        let Some(held) = self.admit(same, Instant::now()) else {
            return;
        };
        let line = log_spans(&record, held, columns(), self.look);
        self.screen.print(&line.render(self.look.paint));
    }
}

const fn level_name(level: LogLevel) -> (&'static str, Tone) {
    match level {
        LogLevel::Error => ("error", Tone::Red),
        LogLevel::Warn => ("warn ", Tone::Yellow),
        LogLevel::Info => ("info ", Tone::Cyan),
        LogLevel::Debug => ("debug", Tone::Dim),
        LogLevel::Trace => ("trace", Tone::Dim),
    }
}

/// The row of `record`; `held` like it were not shown since the last one.
fn log_spans(record: &LogRecord, held: u32, columns: u16, look: Look) -> Spans {
    let (name, tone) = level_name(record.level);
    let mut rest = format!(" {}: {}", record.target, record.message);
    if held > 0 {
        rest.push_str(&format!(" ({held} more like it)"));
    }
    for (key, value) in &record.fields {
        rest.push_str(&format!(" {key}={value}"));
    }
    let mut line = Spans::of(name, tone);
    line.push(printable(&rest), Tone::Dim);
    line.fit(columns, look.marks.ellipsis)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::shell::card::Glyphs;
    use crate::shell::live::Marks;
    use crate::shell::paint::Paint;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn take(&self) -> String {
            String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap()
        }
    }

    fn footer() -> [String; 4] {
        [
            String::new(),
            ">".to_owned(),
            "-- status --".to_owned(),
            "| scan".to_owned(),
        ]
    }

    #[test]
    fn lines_wait_for_the_editor_while_it_reads() {
        let out = Captured::default();
        let screen = Screen::new(Box::new(out.clone()));
        screen.editing();
        screen.print("one\ntwo\n");
        assert_eq!(out.take(), "");
        assert_eq!(Queue(screen.clone()).drain().unwrap(), ["one", "two"]);
        screen.print("three");
        screen.direct();
        assert_eq!(out.take(), "three\r\n");
    }

    #[test]
    fn output_goes_above_the_footer_in_one_synchronized_write() {
        let out = Captured::default();
        let screen = Screen::new(Box::new(out.clone()));
        screen.running(footer());
        let first = out.take();
        assert!(first.contains(">\r\n-- status --\r\n"), "{first:?}");
        screen.print("scanned to height 10");
        let painted = out.take();
        assert!(
            painted.starts_with("\u{1b}[?2026h\r\u{1b}[J"),
            "{painted:?}"
        );
        assert!(
            painted.ends_with("\u{1b}[3A\r\u{1b}[?7h\u{1b}[?2026l"),
            "{painted:?}"
        );
        assert!(
            painted.contains("scanned to height 10\r\n\u{1b}[?7l\r\n>"),
            "the footer is drawn with autowrap off, the output above it is not: {painted:?}"
        );
        assert!(painted.contains("\r\n>\r\n-- status --"));
        assert_eq!(painted.matches("scanned").count(), 1);
        screen.direct();
        let cleared = out.take();
        assert!(cleared.starts_with("\r\u{1b}[J"), "{cleared:?}");
        screen.print("done");
        assert_eq!(out.take(), "done\r\n");
    }

    #[test]
    fn art_goes_above_the_footer_and_leaves_with_it() {
        let out = Captured::default();
        let screen = Screen::new(Box::new(out.clone()));
        screen.art(vec![String::new(), "seal".to_owned()]);
        let alone = out.take();
        assert!(alone.contains("\r\nseal\u{1b}[1A\r\u{1b}[?7h"), "{alone:?}");
        screen.running(footer());
        let both = out.take();
        assert!(!both.contains("\r\u{1b}[J\u{1b}[?25h"), "{both:?}");
        assert!(both.contains("seal\r\n\r\n>\r\n"), "{both:?}");
        assert!(
            both.ends_with("\u{1b}[5A\r\u{1b}[?7h\u{1b}[?2026l"),
            "{both:?}"
        );
        screen.print("posted");
        assert!(out.take().contains("posted\r\n\u{1b}[?7l\r\nseal\r\n"));
        screen.direct();
        assert!(out.take().starts_with("\r\u{1b}[J"));
        screen.running(footer());
        assert!(!out.take().contains("seal"));
    }

    #[test]
    fn the_writer_prints_whole_lines() {
        let out = Captured::default();
        let screen = Screen::new(Box::new(out.clone()));
        let mut writer = ScreenWriter::new(screen);
        writer.write_all(b"half").unwrap();
        assert_eq!(out.take(), "");
        writer.write_all(b" a line\nnext\n").unwrap();
        assert_eq!(out.take(), "half a line\r\nnext\r\n");
        writer.write_all(b"tail").unwrap();
        drop(writer);
        assert_eq!(out.take(), "tail\r\n");
    }

    #[test]
    fn a_frame_is_drawn_over_the_one_before() {
        let out = Captured::default();
        let screen = Screen::new(Box::new(out.clone()));
        screen.redraw(&["one".to_owned(), "two".to_owned()], 0);
        assert_eq!(
            out.take(),
            "\u{1b}[?2026h\u{1b}[?25l\r\u{1b}[Jone\r\ntwo\r\n\u{1b}[?25h\u{1b}[?2026l"
        );
        screen.redraw(&["ONE".to_owned(), "TWO".to_owned()], 2);
        assert!(out.take().contains("\r\u{1b}[2A\u{1b}[JONE\r\nTWO\r\n"));
        screen.editing();
        screen.redraw(&["three".to_owned()], 2);
        assert_eq!(out.take(), "");
    }

    #[test]
    fn a_log_line_takes_one_row() {
        let record = LogRecord {
            level: LogLevel::Warn,
            target: "lepic_node::client".to_owned(),
            message: "node call failed, retrying".to_owned(),
            spans: Vec::new(),
            fields: vec![
                ("attempt", "1".to_owned()),
                ("error", "x\u{1b}[2J".repeat(40)),
            ],
        };
        let look = |glyphs, paint| Look {
            marks: Marks::new(glyphs),
            paint,
            motion: false,
        };
        let plain = log_spans(&record, 0, 80, look(Glyphs::Unicode, Paint::Off)).render(Paint::Off);
        assert!(
            plain.starts_with("warn  lepic_node::client: node call failed, retrying attempt=1"),
            "{plain}"
        );
        assert_eq!(plain.chars().count(), 79);
        assert!(plain.ends_with('…'));
        assert!(!plain.chars().any(char::is_control));
        let ascii = log_spans(&record, 0, 60, look(Glyphs::Ascii, Paint::Ansi)).render(Paint::Ansi);
        assert!(
            ascii.starts_with("\u{1b}[33mwarn \u{1b}[0m\u{1b}[2m lepic_node"),
            "{ascii:?}"
        );
        assert!(ascii.ends_with("...\u{1b}[0m"), "{ascii:?}");
        let counted =
            log_spans(&record, 5, 80, look(Glyphs::Unicode, Paint::Off)).render(Paint::Off);
        assert!(
            counted.contains("retrying (5 more like it) attempt="),
            "{counted}"
        );
    }

    #[test]
    fn a_log_line_shown_lately_is_held_back_and_counted() {
        let look = Look {
            marks: Marks::new(Glyphs::Ascii),
            paint: Paint::Off,
            motion: false,
        };
        let log = ShellLog::new(Screen::new(Box::new(Captured::default())), look);
        let start = Instant::now();
        let after = |seconds| start + Duration::from_secs(seconds);
        let retry = || "warn  node: retrying".to_owned();
        assert_eq!(log.admit(retry(), start), Some(0));
        assert_eq!(log.admit(retry(), after(60)), None);
        assert_eq!(log.admit(retry(), after(120)), None);
        // Another line is not held back by it.
        assert_eq!(
            log.admit("warn  relay: closed".to_owned(), after(121)),
            Some(0)
        );
        assert_eq!(log.admit(retry(), after(601)), Some(2));
        assert_eq!(log.admit(retry(), after(660)), None);
    }
}
