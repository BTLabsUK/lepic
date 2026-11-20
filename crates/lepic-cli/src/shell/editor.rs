// SPDX-License-Identifier: Apache-2.0
//! The line editor's parts: the prompt, a blank row above the input, the status rule and hint
//! row under it, completion from the command tree, the keys, and the colours of the input. With
//! colour off nothing here writes more than the dim and reverse the menu and hint have always had.

use std::borrow::Cow;
use std::ffi::OsString;
use std::sync::{Arc, Mutex, PoisonError};

use clap::CommandFactory as _;
use reedline::{
    Color, Completer, CompletionResult, DefaultHinter, DescriptionMode, Emacs, Highlighter,
    IdeMenu, KeyCode, KeyModifiers, MenuBuilder as _, Prompt, PromptEditMode, PromptHistorySearch,
    Reedline, ReedlineEvent, ReedlineMenu, Span, StatusLine, StyledText, Suggestion,
    default_emacs_keybindings,
};

use crate::cli::Cli;
use crate::shell::live::{Look, Status, hint_spans, prompt_mark};
use crate::shell::paint::{Paint, Tone};
use crate::shell::words::{SHELL_WORDS, parse, shell_words_of, tokenize, usage};

/// The menu Tab opens.
const MENU: &str = "completion_menu";

/// What the live area shows, shared by the session, which changes it, and the editor, which
/// draws it on each repaint.
#[derive(Clone)]
pub(crate) struct Shared(Arc<Mutex<Status>>);

impl Shared {
    pub(crate) fn new(status: Status) -> Self {
        Self(Arc::new(Mutex::new(status)))
    }

    pub(crate) fn get(&self) -> Status {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn update(&self, change: impl FnOnce(&mut Status)) {
        change(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner));
    }
}

/// Columns of the terminal now; 80 when it cannot be read.
pub(crate) fn columns() -> u16 {
    crossterm::terminal::size().map_or(80, |(columns, _)| columns)
}

/// The prompt while editing: a blank line, then the bar, green while the wallet is open and dim
/// while it is locked. The status goes under the input, where a terminal that rewraps rows as it
/// narrows cannot leave a copy of it behind.
pub(crate) struct LivePrompt {
    pub status: Shared,
    pub look: Look,
}

impl Prompt for LivePrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed("\n")
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        let locked = self.status.get().locked;
        let mark = prompt_mark(locked, &self.look.marks);
        Cow::Owned(format!("{} ", mark.render(self.look.paint)))
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("  ")
    }

    fn render_prompt_history_search_indicator(&self, search: PromptHistorySearch) -> Cow<'_, str> {
        Cow::Owned(format!("(search: {}) ", search.term))
    }

    fn get_prompt_color(&self) -> Color {
        Color::Default
    }

    fn get_prompt_multiline_color(&self) -> Color {
        Color::Default
    }

    fn get_indicator_color(&self) -> Color {
        Color::Default
    }

    fn get_prompt_right_color(&self) -> Color {
        Color::Default
    }
}

/// What stays in the console once a line is submitted: a blank line and the bar, dim, with the
/// line.
pub(crate) struct TransientPrompt {
    pub look: Look,
}

impl Prompt for TransientPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed("\n")
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Owned(format!(
            "{} ",
            self.look.tint(self.look.marks.prompt, Tone::Dim)
        ))
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("  ")
    }

    fn render_prompt_history_search_indicator(&self, _search: PromptHistorySearch) -> Cow<'_, str> {
        self.render_prompt_indicator(PromptEditMode::Default)
    }

    fn get_prompt_color(&self) -> Color {
        Color::Default
    }

    fn get_prompt_multiline_color(&self) -> Color {
        Color::Default
    }

    fn get_indicator_color(&self) -> Color {
        Color::Default
    }

    fn get_prompt_right_color(&self) -> Color {
        Color::Default
    }
}

/// The rows under the input: the status rule, then the usage of the command being typed or what
/// the keys do.
pub(crate) struct LiveStatusLine {
    status: Shared,
    look: Look,
    root: clap::Command,
    /// The last line asked about and its usage, since usage is asked for on every repaint.
    cached: Option<(String, Option<String>)>,
}

impl LiveStatusLine {
    pub(crate) fn new(status: Shared, look: Look) -> Self {
        Self {
            status,
            look,
            root: Cli::command(),
            cached: None,
        }
    }

    fn usage(&mut self, line: &str) -> Option<String> {
        if let Some((cached, usage)) = &self.cached
            && cached == line
        {
            return usage.clone();
        }
        let found = command_usage(&mut self.root, line);
        self.cached = Some((line.to_owned(), found.clone()));
        found
    }
}

/// The usage of the `lepic` command `line` names, when its first word is a command rather than
/// one of the shell's words.
pub(crate) fn command_usage(root: &mut clap::Command, line: &str) -> Option<String> {
    let words = tokenize(line).words;
    let first = words.first()?;
    if !matches!(parse(line), Ok(crate::shell::words::Line::Command { .. }))
        || root.find_subcommand(first).is_none()
    {
        return None;
    }
    usage(root, &words)
}

impl StatusLine for LiveStatusLine {
    fn status(&mut self, line: &str, _pos: usize, columns: u16, ansi: bool) -> String {
        let usage = self.usage(line);
        let status = self.status.get();
        let paint = if ansi { self.look.paint } else { Paint::Off };
        let marks = &self.look.marks;
        format!(
            "{}\n{}",
            status.rule_spans(columns, marks).render(paint),
            hint_spans(line, status.locked, usage.as_deref(), columns, marks).render(paint)
        )
    }
}

/// The input in colour: a command word cyan, a flag cyan, a word that names no command red. A
/// word still being typed toward a command stays plain. With colour off, the line as typed.
struct Words {
    root: clap::Command,
    paint: Paint,
}

/// The colours of the input and the menu as the editor's own styles, which take a colour by its
/// ANSI name or by its 24-bit value.
const fn editor_colour(tone: Tone, paint: Paint) -> Color {
    match (tone, paint) {
        (Tone::Cyan | Tone::CyanBold, Paint::Night) => Color::Rgb(125, 207, 255),
        (Tone::Cyan | Tone::CyanBold, Paint::Paper) => Color::Rgb(11, 98, 184),
        (Tone::Cyan | Tone::CyanBold, _) => Color::Cyan,
        (Tone::Red | Tone::RedBold, Paint::Night) => Color::Rgb(255, 107, 129),
        (Tone::Red | Tone::RedBold, Paint::Paper) => Color::Rgb(196, 38, 58),
        (Tone::Red | Tone::RedBold, _) => Color::Red,
        (Tone::Dim, Paint::Night) => Color::Rgb(128, 138, 153),
        (Tone::Dim, Paint::Paper) => Color::Rgb(107, 114, 128),
        _ => Color::Default,
    }
}

impl Words {
    /// The words the first word may be.
    fn first_words(&self) -> Vec<String> {
        let shell = SHELL_WORDS
            .iter()
            .map(|(word, _)| word.split(' ').next().unwrap_or(word).to_owned());
        let commands = self
            .root
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .map(|sub| sub.get_name().to_owned());
        shell.chain(commands).chain(["quit".to_owned()]).collect()
    }

    /// How the word at `index` is drawn, after the words before it.
    fn tone(&self, before: &[&str], word: &str, last: bool) -> Tone {
        if word.starts_with('-') {
            return Tone::Cyan;
        }
        let known = |names: Vec<String>| {
            if names.iter().any(|name| name == word) {
                Tone::CyanBold
            } else if last && names.iter().any(|name| name.starts_with(word)) {
                Tone::Plain
            } else {
                Tone::Red
            }
        };
        match before {
            [] => known(self.first_words()),
            [first] if *first == "serve" => known(vec!["start".to_owned(), "stop".to_owned()]),
            [first] => match self.root.find_subcommand(first) {
                Some(group) if group.has_subcommands() => known(
                    group
                        .get_subcommands()
                        .filter(|sub| !sub.is_hide_set())
                        .map(|sub| sub.get_name().to_owned())
                        .chain(shell_words_of(first).map(|(name, _)| name.to_owned()))
                        .collect(),
                ),
                _ => Tone::Plain,
            },
            _ => Tone::Plain,
        }
    }
}

impl Highlighter for Words {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        let mut plain = Color::Default.normal();
        plain.foreground = None;
        let mut text = StyledText::new();
        if !self.paint.on() {
            text.push((plain, line.to_owned()));
            return text;
        }
        let mut before: Vec<&str> = Vec::new();
        let mut rest = line;
        while !rest.is_empty() {
            let start = rest
                .find(|c: char| !c.is_whitespace())
                .unwrap_or(rest.len());
            let (space, from) = rest.split_at(start);
            if !space.is_empty() {
                text.push((plain, space.to_owned()));
            }
            if from.is_empty() {
                break;
            }
            let end = from.find(char::is_whitespace).unwrap_or(from.len());
            let (word, after) = from.split_at(end);
            // Only the command words are judged; a quoted value or what follows a flag is not.
            let judged = before.len() < 2 && !word.starts_with(['"', '\'']);
            let tone = if judged || word.starts_with('-') {
                self.tone(&before, word, after.is_empty())
            } else {
                Tone::Plain
            };
            let style = match tone {
                Tone::CyanBold => editor_colour(tone, self.paint).bold(),
                Tone::Cyan | Tone::Red => editor_colour(tone, self.paint).normal(),
                _ => plain,
            };
            text.push((style, word.to_owned()));
            before.push(word);
            rest = after;
        }
        text
    }
}

/// Completes the first word from the shell's words and the commands, and the rest from the
/// command tree.
struct ClapCompleter {
    root: clap::Command,
}

impl ClapCompleter {
    fn first_words(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for (word, what) in SHELL_WORDS {
            let first = word.split(' ').next().unwrap_or(word);
            // A group of commands that has a shell word too, `node`, is listed as the group.
            let listed_below = first != "serve" && self.root.find_subcommand(first).is_some();
            if first == "?" || listed_below || out.iter().any(|(seen, _)| seen == first) {
                continue;
            }
            let what = if first == "serve" {
                "Serve the wallet API while the shell runs: serve start, serve stop"
            } else {
                what
            };
            out.push((first.to_owned(), what.to_owned()));
        }
        for sub in self.root.get_subcommands() {
            let name = sub.get_name();
            if sub.is_hide_set() || matches!(name, "serve" | "shell" | "help") {
                continue;
            }
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            out.push((name.to_owned(), about));
        }
        out
    }

    fn candidates(&mut self, words: &[String]) -> Vec<(String, Option<String>)> {
        let current = words.last().cloned().unwrap_or_default();
        let named = |list: Vec<(String, String)>| -> Vec<(String, Option<String>)> {
            list.into_iter()
                .filter(|(name, _)| name.starts_with(&current))
                .map(|(name, what)| (name, Some(what)))
                .collect()
        };
        match words {
            [_] => named(self.first_words()),
            [first, _] if first == "serve" => named(vec![
                ("start".to_owned(), "Serve the wallet API".to_owned()),
                ("stop".to_owned(), "Stop serving".to_owned()),
            ]),
            [first, _] if first == "help" || first == "?" => named(
                self.first_words()
                    .into_iter()
                    .filter(|(name, _)| self.root.find_subcommand(name).is_some())
                    .collect(),
            ),
            [first, second, rest @ ..] if first == "serve" && second == "start" => {
                let mut args: Vec<OsString> = vec!["lepic".into(), "serve".into()];
                args.extend(rest.iter().map(OsString::from));
                self.clap(args)
            }
            _ => {
                let mut args: Vec<OsString> = vec!["lepic".into()];
                args.extend(words.iter().map(OsString::from));
                let mut found = self.clap(args);
                if let [group, _] = words {
                    // The group's shell words follow its commands, before its options.
                    let at = found
                        .iter()
                        .position(|(name, _)| name.starts_with('-'))
                        .unwrap_or(found.len());
                    let own = named(
                        shell_words_of(group)
                            .map(|(name, what)| (name.to_owned(), what.to_owned()))
                            .collect(),
                    );
                    found.splice(at..at, own);
                }
                found
            }
        }
    }

    fn clap(&mut self, args: Vec<OsString>) -> Vec<(String, Option<String>)> {
        let index = args.len().saturating_sub(1);
        clap_complete::engine::complete(&mut self.root, args, index, None)
            .map(|found| {
                found
                    .into_iter()
                    .filter(|candidate| !candidate.is_hide_set())
                    .map(|candidate| {
                        (
                            candidate.get_value().to_string_lossy().into_owned(),
                            candidate.get_help().map(ToString::to_string),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Completer for ClapCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> CompletionResult {
        let head = line.get(..pos).unwrap_or(line);
        let typed = tokenize(head);
        let mut words = typed.words;
        if typed.fresh {
            words.push(String::new());
        }
        let start = if typed.fresh {
            pos
        } else {
            head.char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace())
                .map_or(0, |(at, c)| at.saturating_add(c.len_utf8()))
        };
        let suggestions: Vec<Suggestion> = self
            .candidates(&words)
            .into_iter()
            .map(|(value, description)| Suggestion {
                value,
                description,
                span: Span::new(start, pos),
                append_whitespace: true,
                display_override: None,
                style: None,
                extra: None,
                match_indices: None,
            })
            .collect();
        CompletionResult::fresh(suggestions)
    }
}

/// The line editor, its prompt and history set up for the shell.
pub(crate) fn line_editor(
    status: &Shared,
    look: Look,
    history: Box<dyn reedline::History>,
) -> Reedline {
    let paint = look.paint;
    let mut plain = Color::Default.normal();
    plain.foreground = None;
    let dim = match paint {
        Paint::Night | Paint::Paper => editor_colour(Tone::Dim, paint).normal(),
        Paint::Off | Paint::Ansi => Color::Default.dimmed(),
    };
    let selected = Color::Default.reverse();
    let name = if paint.on() {
        editor_colour(Tone::Cyan, paint).normal()
    } else {
        plain
    };
    let marker = format!("{} ", look.marks.prompt);
    let menu = IdeMenu::default()
        .with_name(MENU)
        .with_marker(&marker)
        .with_text_style(name)
        .with_selected_text_style(selected)
        .with_description_text_style(dim)
        .with_match_text_style(name.underline())
        .with_selected_match_text_style(selected.underline())
        .with_default_border()
        .with_description_mode(DescriptionMode::PreferRight)
        .with_min_completion_width(12)
        .with_max_completion_height(8);
    let mut keys = default_emacs_keybindings();
    keys.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu(MENU.to_owned()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keys.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );
    Reedline::create()
        .with_history(history)
        .with_completer(Box::new(ClapCompleter {
            root: Cli::command(),
        }))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(menu)))
        .with_edit_mode(Box::new(Emacs::new(keys)))
        .with_hinter(Box::new(DefaultHinter::default().with_style(dim)))
        .with_highlighter(Box::new(Words {
            root: Cli::command(),
            paint,
        }))
        .with_status_line(Box::new(LiveStatusLine::new(status.clone(), look)))
        .with_transient_prompt(Box::new(TransientPrompt { look }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::card::Glyphs;
    use crate::shell::live::{Marks, colour_codes};

    fn look(glyphs: Glyphs, paint: Paint) -> Look {
        Look {
            marks: Marks::new(glyphs),
            paint,
            motion: false,
        }
    }

    fn status() -> Status {
        Status {
            wallet: "main".to_owned(),
            network: "mainnet".to_owned(),
            balance: Some("10.992 EPIC".to_owned()),
            spendable: Some("8.492".to_owned()),
            height: Some(2_411_005),
            ..Status::default()
        }
    }

    #[test]
    fn the_editor_rows_are_coloured_only_with_colour_on() {
        for paint in [Paint::Off, Paint::Ansi, Paint::Night, Paint::Paper] {
            let colour = paint.on();
            let look = look(Glyphs::Unicode, paint);
            let shared = Shared::new(status());
            let mut line = LiveStatusLine::new(shared.clone(), look);
            let prompt = LivePrompt {
                status: shared,
                look,
            };
            for columns in [40, 80, 112, 200] {
                let rows = [
                    line.status("tx send 1 --to x", 16, columns, true),
                    line.status("", 0, columns, true),
                    prompt
                        .render_prompt_indicator(PromptEditMode::Default)
                        .into_owned(),
                ];
                for row in rows {
                    assert_eq!(row.contains('\x1b'), colour, "{row:?}");
                    for shown in crate::shell::paint::strip(&row).lines() {
                        assert!(shown.chars().count() < usize::from(columns), "{row:?}");
                    }
                }
            }
        }
        let words = |colour| Words {
            root: Cli::command(),
            paint: if colour { Paint::Ansi } else { Paint::Off },
        };
        let plain = words(false)
            .highlight("tx list --limit 5", 0)
            .render_simple();
        assert!(!plain.contains('\u{1b}'), "{plain:?}");
        let painted = words(true)
            .highlight("tx list --limit 5", 0)
            .render_simple();
        assert_eq!(colour_codes(&painted), ["36", "36", "36"], "{painted:?}");
        let typo = words(true).highlight("tx lsit", 0).render_simple();
        assert!(colour_codes(&typo).contains(&"31".to_owned()), "{typo:?}");
        let typing = words(true).highlight("tx li", 0).render_simple();
        assert_eq!(colour_codes(&typing), ["36"], "{typing:?}");
    }

    #[test]
    fn the_status_line_shows_the_usage_of_a_command_only() {
        let mut line = LiveStatusLine::new(Shared::new(status()), look(Glyphs::Ascii, Paint::Off));
        let send = line.status("tx send ", 8, 200, false);
        let rows: Vec<&str> = send.lines().collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].starts_with("-- main | 10.992 EPIC"), "{send}");
        assert!(rows[1].starts_with("tx send"), "{send}");
        let help = line.status("help", 4, 200, false);
        assert!(
            help.lines()
                .nth(1)
                .is_some_and(|row| row.starts_with("Enter run"))
        );
        let typo = line.status("tx lsit", 7, 200, false);
        assert!(
            typo.lines()
                .nth(1)
                .is_some_and(|row| row.starts_with("tx "))
        );
    }

    #[test]
    fn completion_offers_shell_words_commands_and_flags() {
        let mut completer = ClapCompleter {
            root: Cli::command(),
        };
        let values = |result: CompletionResult| -> Vec<String> {
            result
                .suggestions()
                .iter()
                .map(|suggestion| suggestion.value.clone())
                .collect()
        };
        let first = values(completer.complete("", 0));
        assert!(first.contains(&"unlock".to_owned()));
        assert!(first.contains(&"tx".to_owned()));
        assert!(first.contains(&"serve".to_owned()));
        assert!(!first.contains(&"shell".to_owned()));
        assert!(!first.contains(&"?".to_owned()));
        assert_eq!(values(completer.complete("serve s", 7)), ["start", "stop"]);
        let node = values(completer.complete("node ", 5));
        assert_eq!(
            node.get(..2),
            Some(["status".to_owned(), "use".to_owned()].as_slice())
        );
        assert_eq!(values(completer.complete("node u", 6)), ["use"]);
        assert_eq!(
            first.iter().filter(|word| word.as_str() == "node").count(),
            1
        );
        let tx = values(completer.complete("tx l", 4));
        assert!(tx.contains(&"list".to_owned()), "{tx:?}");
        let flags = values(completer.complete("serve start --so", 16));
        assert!(flags.iter().any(|flag| flag == "--socket"), "{flags:?}");
    }
}
