// SPDX-License-Identifier: Apache-2.0
//! What the shell asks outside its line editor: a hidden line, a yes or no, a choice from a
//! short list, and a page shown once. Each reads the keys itself in raw mode on a thread of its
//! own, so the session keeps running beside it and can end it.

use std::io::{self, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crossterm::cursor::{Hide, MoveTo, MoveUp, Show};
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::queue;
use crossterm::style::Print;
use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use zeroize::Zeroizing;

use crate::secret::{RawMode, SecretError, Shown, read_hidden_line};
use crate::shell::editor::columns;
use crate::shell::live::{Look, key_spans};
use crate::shell::paint::{Spans, Tone};

/// How often a prompt on its own thread looks whether it is still waited for.
const PROMPT_POLL: Duration = Duration::from_millis(100);
/// A cancelled step waits for its prompt's thread to give the terminal back in steps of
/// `PROMPT_RELEASE`, at most `PROMPT_RELEASE_TRIES` of them (one second).
const PROMPT_RELEASE: Duration = Duration::from_millis(10);
const PROMPT_RELEASE_TRIES: u32 = 100;

/// The prompt threads still running. Each holds the terminal, in raw mode or with echo off,
/// until it ends.
static PROMPTS_RUNNING: AtomicUsize = AtomicUsize::new(0);

/// Counts one prompt thread for as long as it lives.
struct PromptRunning;

impl PromptRunning {
    fn start() -> Self {
        PROMPTS_RUNNING.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for PromptRunning {
    fn drop(&mut self) {
        PROMPTS_RUNNING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Waits until every prompt thread has ended and given the terminal back, so the line editor
/// does not read under a terminal mode a dropped prompt restores late. A prompt checks its stop
/// flag every `PROMPT_POLL`; after one second this stops waiting.
pub(crate) async fn prompts_ended() {
    for _ in 0..PROMPT_RELEASE_TRIES {
        if PROMPTS_RUNNING.load(Ordering::SeqCst) == 0 {
            return;
        }
        tokio::time::sleep(PROMPT_RELEASE).await;
    }
}

/// Turns true when dropped: a prompt's thread watches it, so a prompt nobody waits for any
/// more ends and leaves raw mode.
struct StopOnDrop(Arc<AtomicBool>);

impl StopOnDrop {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Runs `ask` on a thread of its own, with the flag that turns true once nobody waits for the
/// answer. `None` when the thread failed.
async fn on_thread<T: Send + 'static>(
    ask: impl FnOnce(&AtomicBool) -> T + Send + 'static,
) -> Option<T> {
    let stop = StopOnDrop::new();
    let flag = stop.flag();
    let running = PromptRunning::start();
    let answer = tokio::task::spawn_blocking(move || {
        let _running = running;
        ask(&flag)
    })
    .await
    .ok();
    drop(stop);
    answer
}

/// Asks for a secret at the terminal: `prompt`, then what is typed drawn as `shown` says.
pub(crate) async fn secret(
    what: &'static str,
    prompt: String,
    shown: Shown,
) -> Result<Zeroizing<String>, SecretError> {
    on_thread(move |stop| read_hidden_line(what, &prompt, shown, &|| stop.load(Ordering::SeqCst)))
        .await
        .unwrap_or(Err(SecretError::Cancelled { what }))
}

/// Asks `question` and reads the answer: only `y` answers yes.
pub(crate) async fn yes(question: String) -> bool {
    on_thread(move |stop| confirm(&question, stop))
        .await
        .unwrap_or(false)
}

/// Keys typed before a question do not answer it.
fn forget_typed_keys() {
    while matches!(event::poll(Duration::ZERO), Ok(true)) {
        if event::read().is_err() {
            break;
        }
    }
}

/// The next key pressed, as its code and whether Ctrl was held. `None` once `stop` turns true or
/// the terminal cannot be read.
fn next_key(stop: &AtomicBool) -> Option<(KeyCode, bool)> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        match event::poll(PROMPT_POLL) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => return None,
        }
        match event::read() {
            Ok(TermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                // AltGr arrives as Ctrl and Alt together and types a character.
                let control = key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT);
                return Some((key.code, control));
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

/// Asks `question` and reads an answer up to Enter: only `y` answers yes. Esc or Ctrl+C
/// answers no at once. Once `stop` turns true it ends with no answer.
fn confirm(question: &str, stop: &AtomicBool) -> bool {
    let mut out = io::stdout();
    let Ok(raw) = RawMode::enable() else {
        let _ = out.write_all(question.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
        return false;
    };
    forget_typed_keys();
    let _ = out.write_all(question.as_bytes());
    let _ = out.flush();
    let mut answer = Answer::default();
    let yes = loop {
        let Some((code, control)) = next_key(stop) else {
            break if stop.load(Ordering::SeqCst) {
                None
            } else {
                Some(false)
            };
        };
        match answer.key(code, control) {
            Step::Echo(text) => {
                let _ = out.write_all(text.as_bytes());
                let _ = out.flush();
            }
            Step::Done(yes) => break Some(yes),
            Step::Nothing => {}
        }
    };
    drop(raw);
    let _ = out.write_all(answer.ending(yes).as_bytes());
    let _ = out.flush();
    yes == Some(true)
}

/// The answer typed so far at a `[y/N]` question: one character, shown after the question.
#[derive(Default)]
struct Answer {
    typed: Option<char>,
}

/// What a key does to an [`Answer`].
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Write this after the question.
    Echo(&'static str),
    /// The question is answered.
    Done(bool),
    Nothing,
}

impl Answer {
    fn key(&mut self, code: KeyCode, control: bool) -> Step {
        match code {
            KeyCode::Char('c' | 'd') if control => Step::Done(false),
            KeyCode::Char(character) if !control && !character.is_control() => {
                let again = self.typed.replace(character).is_some();
                // A y shows as typed; anything else reads as a no and shows as n.
                let yes = matches!(character, 'y' | 'Y');
                Step::Echo(match (again, yes) {
                    (false, true) => "y",
                    (false, false) => "n",
                    (true, true) => "\u{8}y",
                    (true, false) => "\u{8}n",
                })
            }
            KeyCode::Backspace if self.typed.take().is_some() => Step::Echo("\u{8} \u{8}"),
            KeyCode::Enter => Step::Done(matches!(self.typed, Some('y' | 'Y'))),
            KeyCode::Esc => Step::Done(false),
            _ => Step::Nothing,
        }
    }

    /// What ends the question's line: the answer when it was not typed, then a new line.
    fn ending(&self, yes: Option<bool>) -> &'static str {
        match (yes, self.typed) {
            (None | Some(true), _) => "\n",
            (Some(false), Some(typed)) if !matches!(typed, 'y' | 'Y') => "\n",
            // Esc or Ctrl+C after a typed y: the y is replaced.
            (Some(false), Some(_)) => "\u{8}N\n",
            (Some(false), None) => "N\n",
        }
    }
}

/// One line of a list to choose from: what it is, and a few words about it.
#[derive(Clone, Debug)]
pub(crate) struct Choice {
    pub label: String,
    pub about: String,
}

/// Shows `choices` as a list, the first one marked, and returns the one Enter picks. The arrows
/// and `j`/`k` move the mark, a digit picks at once; Esc, Ctrl+C and `q` pick none.
pub(crate) async fn choose(choices: Vec<Choice>, look: Look) -> Option<usize> {
    on_thread(move |stop| choose_at_terminal(&choices, look, stop))
        .await
        .flatten()
}

/// What a key does at a list of `count` choices with the mark on `marked`.
#[derive(Debug, PartialEq, Eq)]
enum Pick {
    Mark(usize),
    Take(usize),
    Leave,
    Nothing,
}

fn menu_key(code: KeyCode, control: bool, marked: usize, count: usize) -> Pick {
    let last = count.saturating_sub(1);
    match code {
        KeyCode::Char('c' | 'd') if control => Pick::Leave,
        KeyCode::Esc | KeyCode::Char('q') => Pick::Leave,
        KeyCode::Enter => Pick::Take(marked),
        KeyCode::Up | KeyCode::Char('k') => Pick::Mark(marked.checked_sub(1).unwrap_or(last)),
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => Pick::Mark(if marked >= last {
            0
        } else {
            marked.saturating_add(1)
        }),
        KeyCode::Char(digit @ '1'..='9') => digit
            .to_digit(10)
            .and_then(|number| usize::try_from(number).ok())
            .and_then(|number| number.checked_sub(1))
            .filter(|index| *index < count)
            .map_or(Pick::Nothing, Pick::Take),
        _ => Pick::Nothing,
    }
}

/// The rows of the list: one per choice, a blank one, and what the keys do.
fn menu_rows(choices: &[Choice], marked: usize, columns: u16, look: Look) -> Vec<String> {
    let widest = choices
        .iter()
        .map(|choice| crate::shell::paint::cells(&choice.label))
        .max()
        .unwrap_or(0);
    let mut rows: Vec<String> = choices
        .iter()
        .enumerate()
        .map(|(index, choice)| choice_spans(choice, index == marked, widest, look))
        .map(|spans| spans.cut(columns).render(look.paint))
        .collect();
    rows.push(String::new());
    let moves = format!("{}{} move", look.marks.up, look.marks.down);
    let mut keys = Spans::of("  ", Tone::Plain);
    keys.extend(key_spans(
        &[&moves, "Enter choose", "Esc leave"],
        &look.marks,
    ));
    rows.push(keys.cut(columns).render(look.paint));
    rows
}

fn choice_spans(choice: &Choice, marked: bool, widest: usize, look: Look) -> Spans {
    let mut spans = Spans::of("  ", Tone::Plain);
    if marked {
        spans.push(look.marks.prompt, Tone::Green);
        spans.push(format!(" {:<widest$}", choice.label), Tone::Bold);
    } else {
        spans.push(format!("  {:<widest$}", choice.label), Tone::Plain);
    }
    if !choice.about.is_empty() {
        spans.push(format!("   {}", choice.about), Tone::Dim);
    }
    spans
}

fn choose_at_terminal(choices: &[Choice], look: Look, stop: &AtomicBool) -> Option<usize> {
    let mut out = io::stdout();
    let raw = RawMode::enable().ok()?;
    forget_typed_keys();
    let mut marked = 0_usize;
    let mut drawn = 0_usize;
    let picked = loop {
        let rows = menu_rows(choices, marked, columns(), look);
        let _ = draw_over(&mut out, &rows, drawn);
        drawn = rows.len();
        let Some((code, control)) = next_key(stop) else {
            break None;
        };
        match menu_key(code, control, marked, choices.len()) {
            Pick::Mark(index) => marked = index,
            Pick::Take(index) => break Some(index),
            Pick::Leave => break None,
            Pick::Nothing => {}
        }
    };
    // The list gives way to the one line that was picked.
    let kept: Vec<String> = picked
        .and_then(|index| choices.get(index))
        .map(|choice| {
            let only = Choice {
                label: choice.label.clone(),
                about: String::new(),
            };
            choice_spans(&only, true, 0, look)
                .cut(columns())
                .render(look.paint)
        })
        .into_iter()
        .collect();
    let _ = draw_over(&mut out, &kept, drawn);
    let _ = queue!(out, Print("\r\n"), Show);
    let _ = out.flush();
    drop(raw);
    picked
}

/// Draws `rows` in place of the `before` rows drawn last, whose last row holds the cursor.
fn draw_over(out: &mut impl io::Write, rows: &[String], before: usize) -> io::Result<()> {
    queue!(out, Hide, Print("\r"))?;
    if let Some(up) = before.checked_sub(1).and_then(|up| u16::try_from(up).ok())
        && up > 0
    {
        queue!(out, MoveUp(up))?;
    }
    queue!(out, Clear(ClearType::FromCursorDown))?;
    queue!(out, Print(rows.join("\r\n")))?;
    out.flush()
}

/// Shows `text` on the terminal's alternate screen until Enter, then takes it away: nothing of
/// it stays in the scrollback. For the recovery phrase, which is shown once.
pub(crate) async fn page(text: Zeroizing<String>) {
    on_thread(move |stop| page_at_terminal(&text, stop)).await;
}

fn page_at_terminal(text: &str, stop: &AtomicBool) {
    let mut out = io::stdout();
    let Ok(raw) = RawMode::enable() else {
        return;
    };
    forget_typed_keys();
    let draw = |out: &mut io::Stdout| {
        let _ = queue!(out, MoveTo(0, 0), Clear(ClearType::All));
        let _ = out.write_all(Zeroizing::new(text.replace('\n', "\r\n")).as_bytes());
        let _ = out.flush();
    };
    let _ = queue!(out, EnterAlternateScreen, Hide);
    draw(&mut out);
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match event::poll(PROMPT_POLL) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => break,
        }
        match event::read() {
            Ok(TermEvent::Key(key))
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Enter =>
            {
                break;
            }
            Ok(TermEvent::Resize(_, _)) => draw(&mut out),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = queue!(out, Clear(ClearType::All), Show, LeaveAlternateScreen);
    let _ = out.flush();
    drop(raw);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::card::Glyphs;
    use crate::shell::live::Marks;
    use crate::shell::paint::{Paint, strip};

    fn look(glyphs: Glyphs, paint: Paint) -> Look {
        Look {
            marks: Marks::new(glyphs),
            paint,
            motion: false,
        }
    }

    fn choices() -> Vec<Choice> {
        vec![
            Choice {
                label: "Create a wallet".to_owned(),
                about: "a new recovery phrase of 24 words".to_owned(),
            },
            Choice {
                label: "Restore a wallet".to_owned(),
                about: "from its recovery phrase".to_owned(),
            },
            Choice {
                label: "Leave".to_owned(),
                about: String::new(),
            },
        ]
    }

    /// `n` then Enter answers no and the Enter ends the question, so no empty line follows.
    #[test]
    fn a_yes_no_answer_ends_at_enter() {
        let mut answer = Answer::default();
        assert_eq!(answer.key(KeyCode::Char('n'), false), Step::Echo("n"));
        assert_eq!(answer.key(KeyCode::Enter, false), Step::Done(false));
        assert_eq!(answer.ending(Some(false)), "\n");

        let mut answer = Answer::default();
        assert_eq!(answer.key(KeyCode::Char('y'), false), Step::Echo("y"));
        assert_eq!(answer.key(KeyCode::Enter, false), Step::Done(true));
        assert_eq!(answer.ending(Some(true)), "\n");

        // A changed mind: y, Backspace, x reads as no; n then y reads as yes.
        let mut answer = Answer::default();
        answer.key(KeyCode::Char('y'), false);
        assert_eq!(
            answer.key(KeyCode::Backspace, false),
            Step::Echo("\u{8} \u{8}")
        );
        assert_eq!(answer.key(KeyCode::Char('x'), false), Step::Echo("n"));
        assert_eq!(answer.key(KeyCode::Enter, false), Step::Done(false));
        let mut answer = Answer::default();
        answer.key(KeyCode::Char('n'), false);
        assert_eq!(answer.key(KeyCode::Char('Y'), false), Step::Echo("\u{8}y"));
        assert_eq!(answer.key(KeyCode::Enter, false), Step::Done(true));

        // Enter alone, Esc and Ctrl+C answer no; after a y the shown y becomes N.
        let mut answer = Answer::default();
        assert_eq!(answer.key(KeyCode::Enter, false), Step::Done(false));
        assert_eq!(answer.ending(Some(false)), "N\n");
        let mut answer = Answer::default();
        answer.key(KeyCode::Char('y'), false);
        assert_eq!(answer.key(KeyCode::Char('c'), true), Step::Done(false));
        assert_eq!(answer.ending(Some(false)), "\u{8}N\n");
        let mut answer = Answer::default();
        assert_eq!(answer.key(KeyCode::Esc, false), Step::Done(false));
        assert_eq!(answer.key(KeyCode::Backspace, false), Step::Nothing);
    }

    #[test]
    fn the_keys_move_the_mark_around_the_list_and_pick() {
        assert_eq!(menu_key(KeyCode::Down, false, 0, 3), Pick::Mark(1));
        assert_eq!(menu_key(KeyCode::Down, false, 2, 3), Pick::Mark(0));
        assert_eq!(menu_key(KeyCode::Up, false, 0, 3), Pick::Mark(2));
        assert_eq!(menu_key(KeyCode::Char('k'), false, 2, 3), Pick::Mark(1));
        assert_eq!(menu_key(KeyCode::Enter, false, 1, 3), Pick::Take(1));
        assert_eq!(menu_key(KeyCode::Char('3'), false, 0, 3), Pick::Take(2));
        assert_eq!(menu_key(KeyCode::Char('4'), false, 0, 3), Pick::Nothing);
        assert_eq!(menu_key(KeyCode::Esc, false, 1, 3), Pick::Leave);
        assert_eq!(menu_key(KeyCode::Char('c'), true, 1, 3), Pick::Leave);
        assert_eq!(menu_key(KeyCode::Char('c'), false, 1, 3), Pick::Nothing);
    }

    #[test]
    fn the_list_marks_one_row_and_fits_the_terminal() {
        let rows = menu_rows(&choices(), 1, 112, look(Glyphs::Unicode, Paint::Off));
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows[0],
            "    Create a wallet    a new recovery phrase of 24 words"
        );
        assert_eq!(rows[1], "  ▌ Restore a wallet   from its recovery phrase");
        assert_eq!(rows[2], "    Leave           ");
        assert_eq!(rows[4], "  ↑↓ move · Enter choose · Esc leave");
        for columns in [20, 40, 80] {
            for paint in [Paint::Off, Paint::Ansi, Paint::Night] {
                for row in menu_rows(&choices(), 0, columns, look(Glyphs::Ascii, paint)) {
                    let shown = strip(&row);
                    assert!(shown.is_ascii(), "{shown}");
                    assert!(shown.chars().count() < usize::from(columns), "{shown}");
                    assert!(paint.on() || !row.contains('\u{1b}'), "{row:?}");
                }
            }
        }
    }

    #[test]
    fn a_list_is_drawn_over_the_one_before() {
        let mut out = Vec::new();
        draw_over(&mut out, &["a".to_owned(), "b".to_owned()], 0).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\u{1b}[?25l\r\u{1b}[Ja\r\nb"
        );
        let mut out = Vec::new();
        draw_over(&mut out, &["c".to_owned()], 3).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\u{1b}[?25l\r\u{1b}[2A\u{1b}[Jc"
        );
    }
}
