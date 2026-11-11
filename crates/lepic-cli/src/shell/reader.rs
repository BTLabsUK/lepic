// SPDX-License-Identifier: Apache-2.0
//! The thread that owns the line editor. The session asks it for a line, or to watch the keys
//! for Ctrl+C while a command runs, and gets the answers on a channel it can await.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use reedline::{Reedline, Signal};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::shell::editor::LivePrompt;
use crate::shell::history;

/// How often the watch looks at its stop flag.
const WATCH_POLL: Duration = Duration::from_millis(50);

/// What the session asks of the reader.
pub(crate) enum Ask {
    /// Read one line.
    ReadLine,
    /// Watch the keys for Ctrl+C and the terminal for resizes until the flag turns true.
    Watch(Arc<AtomicBool>),
    /// The lines the history holds.
    History,
    /// Clear the screen.
    Clear,
}

/// What the reader answers.
pub(crate) enum Reply {
    Line(Read),
    /// Ctrl+C while watching.
    Interrupt,
    /// The terminal changed size while watching.
    Resize,
    /// The watch ended and the terminal is out of raw mode.
    Watched,
    History(Vec<String>),
}

/// How a read ended.
pub(crate) enum Read {
    Line(String),
    /// Ctrl+C at the prompt: the line is dropped.
    CtrlC,
    /// Ctrl+D on an empty line.
    CtrlD,
    /// The session ended the read through the break flag.
    Break,
    Failed(String),
}

pub(crate) struct Reader {
    asks: Option<mpsc::Sender<Ask>>,
    /// Set to end a read in progress; the editor was built with it as its break signal.
    stop_read: Arc<AtomicBool>,
    pub replies: UnboundedReceiver<Reply>,
    thread: Option<JoinHandle<()>>,
}

impl Reader {
    /// Starts the thread. `stop_read` is the break signal `editor` was built with.
    pub(crate) fn start(
        editor: Reedline,
        prompt: LivePrompt,
        stop_read: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let (asks, asked) = mpsc::channel();
        let (reply, replies) = unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("lepic-shell-reader".to_owned())
            .spawn(move || serve(editor, &prompt, &asked, &reply))?;
        Ok(Self {
            asks: Some(asks),
            stop_read,
            replies,
            thread: Some(thread),
        })
    }

    pub(crate) fn ask(&self, ask: Ask) {
        if let Some(asks) = &self.asks {
            let _ = asks.send(ask);
        }
    }

    /// Ends the read in progress, which answers [`Read::Break`].
    pub(crate) fn break_read(&self) {
        self.stop_read.store(true, Ordering::SeqCst);
    }
}

impl Drop for Reader {
    /// Ends the thread once it has answered what it was asked; it saves the history on the way.
    fn drop(&mut self) {
        self.break_read();
        drop(self.asks.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(
    mut editor: Reedline,
    prompt: &LivePrompt,
    asked: &mpsc::Receiver<Ask>,
    reply: &UnboundedSender<Reply>,
) {
    while let Ok(ask) = asked.recv() {
        let answer = match ask {
            Ask::ReadLine => Some(Reply::Line(match editor.read_line(prompt) {
                Ok(Signal::Success(line)) => Read::Line(line),
                Ok(Signal::CtrlD) => Read::CtrlD,
                Ok(Signal::ExternalBreak(_)) => Read::Break,
                Ok(_) => Read::CtrlC,
                Err(error) => Read::Failed(error.to_string()),
            })),
            Ask::Watch(stop) => {
                watch(&stop, reply);
                Some(Reply::Watched)
            }
            Ask::History => Some(Reply::History(history::lines(editor.history()))),
            Ask::Clear => {
                let _ = editor.clear_screen();
                None
            }
        };
        if let Some(answer) = answer
            && reply.send(answer).is_err()
        {
            break;
        }
    }
    let _ = editor.sync_history();
}

/// Reads the keys in raw mode, so Ctrl+C arrives as a key rather than a signal, until `stop`.
fn watch(stop: &AtomicBool, reply: &UnboundedSender<Reply>) {
    if enable_raw_mode().is_err() {
        return;
    }
    while !stop.load(Ordering::SeqCst) {
        match event::poll(WATCH_POLL) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key))
                    if key.kind == KeyEventKind::Press
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c' | 'C')) =>
                {
                    let _ = reply.send(Reply::Interrupt);
                }
                Ok(Event::Resize(_, _)) => {
                    let _ = reply.send(Reply::Resize);
                }
                Ok(_) => {}
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }
    }
    let _ = disable_raw_mode();
}
