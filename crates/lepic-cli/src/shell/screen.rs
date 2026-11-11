// SPDX-License-Identifier: Apache-2.0
//! Where the shell's output goes. While the user edits a line the editor owns the terminal, so
//! lines wait in a queue it prints above the prompt. While a command runs the shell draws its
//! own footer under the output and repaints it in one write per change. Otherwise lines go
//! straight to the terminal.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crossterm::cursor::{Hide, MoveUp, Show};
use crossterm::queue;
use crossterm::style::Print;
use crossterm::terminal::{BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate};
use lepic_telemetry::{LogRecord, LogSink};
use reedline::{ExternalOutput, RepaintSignal};
use zeroize::Zeroizing;

use crate::shell::live::printable;

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

    /// Clears the footer, prints `text` where it was and draws the art and the footer under it,
    /// in one synchronized write. The cursor rests on their first row, a blank one, so a resize
    /// that rewraps the rows below it is cleared by the next paint.
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
            buffer.extend_from_slice(rows.join("\r\n").as_bytes());
            let up = u16::try_from(rows.len().saturating_sub(1)).unwrap_or(0);
            if up > 0 {
                queue!(buffer, MoveUp(up))?;
            }
            queue!(buffer, Print("\r"))?;
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

/// The session's log lines, on the screen: `WARN target: message key=value`.
pub(crate) struct ShellLog(pub Screen);

impl LogSink for ShellLog {
    fn record(&self, record: LogRecord) {
        self.0.print(&log_line(&record));
    }
}

fn log_line(record: &LogRecord) -> String {
    let mut line = format!(
        "{} {}: {}",
        record.level.to_string().to_ascii_uppercase(),
        record.target,
        record.message
    );
    for (key, value) in &record.fields {
        line.push_str(&format!(" {key}={value}"));
    }
    printable(&line)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

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
        assert!(painted.ends_with("\u{1b}[3A\r\u{1b}[?2026l"), "{painted:?}");
        assert!(painted.contains("scanned to height 10\r\n\r\n>\r\n-- status --"));
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
        assert!(alone.contains("\r\nseal\u{1b}[1A\r"), "{alone:?}");
        screen.running(footer());
        let both = out.take();
        assert!(!both.contains("\r\u{1b}[J\u{1b}[?25h"), "{both:?}");
        assert!(both.contains("seal\r\n\r\n>\r\n"), "{both:?}");
        assert!(both.ends_with("\u{1b}[5A\r\u{1b}[?2026l"), "{both:?}");
        screen.print("posted");
        assert!(out.take().contains("posted\r\n\r\nseal\r\n"));
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
}
