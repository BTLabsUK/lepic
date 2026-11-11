// SPDX-License-Identifier: Apache-2.0
//! What a line typed in the shell means: the shell's own words, read before clap, and the
//! checks a command line passes before it runs. No terminal and no wallet here.

use crate::cli::{Command, EpicboxCommand, HttpCommand, TorCommand, WalletCommand};

/// A line split into words: blanks separate them, quotes keep blanks inside one, and a backslash
/// outside single quotes takes the next character as it is.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Words {
    pub words: Vec<String>,
    /// The line ends in a blank, so a new, empty word starts at the cursor.
    pub fresh: bool,
    /// A quote opened and never closed.
    pub open_quote: bool,
}

pub(crate) fn tokenize(line: &str) -> Words {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some('"') | None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
                started = true;
            }
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => {
                current.push(c);
                started = true;
            }
        }
    }
    let fresh = !started && quote.is_none();
    if started || quote.is_some() {
        words.push(current);
    }
    Words {
        words,
        fresh,
        open_quote: quote.is_some(),
    }
}

/// What a line asks the shell to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    Empty,
    /// `help` or `?`, with the command to show the usage of.
    Help(Vec<String>),
    Lock,
    Unlock,
    Clear,
    History,
    Status,
    Exit,
    /// `serve start` and the flags of `lepic serve`.
    ServeStart(Vec<String>),
    ServeStop,
    /// A `lepic` command line without `lepic`; `yes` when `--yes` asked to skip the send review.
    Command {
        args: Vec<String>,
        yes: bool,
    },
}

/// The shell words, with what each does, in the order help lists them.
pub(crate) const SHELL_WORDS: [(&str, &str); 10] = [
    ("help", "List the commands; help <command> shows its usage"),
    (
        "status",
        "Show the wallet, the node and what runs in this session",
    ),
    ("lock", "Lock the wallet; serve stops first"),
    ("unlock", "Open the wallet again"),
    (
        "serve start",
        "Answer the wallet API on a local socket while the shell runs",
    ),
    ("serve stop", "Stop serving the wallet API"),
    ("history", "List the lines typed in this data directory"),
    ("clear", "Clear the screen"),
    ("exit", "Lock the wallet and leave; quit and Ctrl+D too"),
    ("?", "Same as help"),
];

pub(crate) fn parse(line: &str) -> Result<Line, String> {
    let Words {
        words, open_quote, ..
    } = tokenize(line);
    if open_quote {
        return Err("a quote is not closed".to_owned());
    }
    let Some(first) = words.first() else {
        return Ok(Line::Empty);
    };
    let rest = words.get(1..).unwrap_or_default();
    let bare = |line: Line| {
        if rest.is_empty() {
            Ok(line)
        } else {
            Err(format!("{first} takes no arguments"))
        }
    };
    match first.as_str() {
        "help" | "?" => Ok(Line::Help(rest.to_vec())),
        "lock" => bare(Line::Lock),
        "unlock" => bare(Line::Unlock),
        "clear" => bare(Line::Clear),
        "history" => bare(Line::History),
        "status" => bare(Line::Status),
        "exit" | "quit" => bare(Line::Exit),
        "serve" => match rest.first().map(String::as_str) {
            Some("start") => Ok(Line::ServeStart(rest.get(1..).unwrap_or_default().to_vec())),
            Some("stop") if rest.len() == 1 => Ok(Line::ServeStop),
            Some("stop") => Err("serve stop takes no arguments".to_owned()),
            _ => Err("in the shell, serve start runs serve and serve stop stops it".to_owned()),
        },
        "lepic" => Err("type the command without lepic".to_owned()),
        _ => {
            let (args, yes) = strip_yes(words);
            Ok(Line::Command { args, yes })
        }
    }
}

/// Takes the shell's `--yes` out of a `tx send` line, so clap never sees it. Arguments after a
/// bare `--` are left alone.
pub(crate) fn strip_yes(words: Vec<String>) -> (Vec<String>, bool) {
    let is_send = command_path(&words).starts_with(&["tx".to_owned(), "send".to_owned()]);
    if !is_send {
        return (words, false);
    }
    let mut yes = false;
    let mut after_dashes = false;
    let kept = words
        .into_iter()
        .filter(|word| {
            if after_dashes {
                return true;
            }
            if word == "--" {
                after_dashes = true;
                return true;
            }
            if word == "--yes" {
                yes = true;
                return false;
            }
            true
        })
        .collect();
    (kept, yes)
}

/// The leading words of a line that are not options: `tx send` of `tx send 1 --to x`.
fn command_path(words: &[String]) -> Vec<String> {
    words
        .iter()
        .take_while(|word| !word.starts_with('-'))
        .cloned()
        .collect()
}

/// Whether the history file may keep `line`. Lines that may hold secret material are left out:
/// contact invite links, payload hex, anything naming a password, seed imports, and answers
/// given to `in-person take` other than by `--file`.
pub(crate) fn keep_in_history(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.contains("password") || lower.contains("secret") {
        return false;
    }
    let Words { words, .. } = tokenize(line);
    let path = command_path(&words);
    if path.starts_with(&["wallet".to_owned(), "import-seed".to_owned()]) {
        return false;
    }
    if path.starts_with(&["in-person".to_owned(), "take".to_owned()])
        && !words
            .iter()
            .any(|word| word == "--file" || word.starts_with("--file="))
    {
        return false;
    }
    !words.iter().any(|word| {
        let word = word.to_ascii_lowercase();
        word.starts_with("epiccash:") || word == "--hex" || word.starts_with("--hex=")
    })
}

/// Why the shell will not run `command`, if it will not. `serving` says whether serve runs in
/// this session.
pub(crate) fn refusal(command: &Command, args: &[String], serving: bool) -> Option<String> {
    let outside = |what: &str| {
        Some(format!(
            "{what} runs outside the shell: exit, then run lepic {what}"
        ))
    };
    match command {
        Command::Wallet(WalletCommand::Init(_)) => return outside("wallet init"),
        Command::Wallet(WalletCommand::Restore(_)) => return outside("wallet restore"),
        Command::Wallet(WalletCommand::ImportSeed(_)) => return outside("wallet import-seed"),
        Command::Wallet(WalletCommand::Password) => return outside("wallet password"),
        Command::Shell => return Some("the shell is open already".to_owned()),
        Command::Serve(_) => {
            return Some("in the shell, serve start runs serve and serve stop stops it".to_owned());
        }
        Command::Epicbox(EpicboxCommand::Listen)
        | Command::Http(HttpCommand::Listen(_))
        | Command::Tor(TorCommand::Listen(_))
            if serving =>
        {
            return Some(
                "serve runs in this session and listens already; serve stop first".to_owned(),
            );
        }
        _ => {}
    }
    if args.iter().any(|arg| arg == "-") {
        return Some(
            "standard input belongs to the shell here; give a file instead of -".to_owned(),
        );
    }
    None
}

/// The edit distance between `a` and `b`, in characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut row = Vec::with_capacity(previous.len());
        row.push(i.saturating_add(1));
        for (cb, pair) in b.iter().zip(previous.windows(2)) {
            let (&diagonal, &above) = (pair.first().unwrap_or(&0), pair.get(1).unwrap_or(&0));
            let left = row.last().copied().unwrap_or(0);
            let substitute = diagonal.saturating_add(usize::from(ca != cb));
            let delete = above.saturating_add(1);
            let insert = left.saturating_add(1);
            row.push(substitute.min(delete).min(insert));
        }
        previous = row;
    }
    previous.last().copied().unwrap_or(0)
}

/// The words a command group accepts next: its visible subcommands, and the shell words at the
/// top.
fn choices(command: &clap::Command, top: bool) -> Vec<String> {
    let mut names: Vec<String> = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().to_owned())
        .filter(|name| !(top && (name == "serve" || name == "shell")))
        .collect();
    if top {
        names.extend(
            [
                "help", "status", "lock", "unlock", "history", "clear", "exit", "quit", "serve",
            ]
            .map(str::to_owned),
        );
    }
    names
}

/// For a line whose command words name no command: the words as typed, and the nearest command,
/// as `("tx lsit", Some("tx list"))`. `None` when the words do name a command.
pub(crate) fn unknown_command(
    root: &clap::Command,
    words: &[String],
) -> Option<(String, Option<String>)> {
    let path = command_path(words);
    let mut command = root;
    let mut known: Vec<&str> = Vec::new();
    for (i, word) in path.iter().enumerate() {
        command.get_subcommands().next()?;
        if let Some(sub) = command.find_subcommand(word) {
            known.push(sub.get_name());
            command = sub;
            continue;
        }
        let typed = path.get(..=i).unwrap_or_default().join(" ");
        let nearest = choices(command, i == 0)
            .into_iter()
            .map(|name| (edit_distance(word, &name), name))
            .filter(|(distance, name)| *distance <= 2 && *distance < name.chars().count())
            .min()
            .map(|(_, name)| {
                let mut found = known.clone();
                found.push(&name);
                found.join(" ")
            });
        return Some((typed, nearest));
    }
    None
}

/// The usage of the command the words name, `tx send [OPTIONS] <AMOUNT> <--to …>`, once the
/// words name one. `root` is the `lepic` command; it is built here if it is not yet.
pub(crate) fn usage(root: &mut clap::Command, words: &[String]) -> Option<String> {
    let path = command_path(words);
    if path.is_empty() {
        return None;
    }
    // Subcommands know their full name, `lepic tx send`, only once the tree is built; building
    // a built tree does nothing.
    root.build();
    let mut command = root;
    for word in &path {
        if command.find_subcommand(word).is_none() {
            break;
        }
        command = command.find_subcommand_mut(word)?;
    }
    let rendered = command.render_usage().to_string();
    let line = rendered.lines().next()?.trim();
    let line = line.strip_prefix("Usage: ").unwrap_or(line);
    let line = line.strip_prefix("lepic ")?;
    Some(line.to_owned())
}

/// The lines of `help`: the shell words, then the commands in two groups, each with what it does.
pub(crate) fn help_lines(root: &clap::Command) -> Vec<String> {
    const WALLET: [&str; 8] = [
        "wallet",
        "tx",
        "invoice",
        "contact",
        "epic1",
        "in-person",
        "epictx",
        "profile",
    ];
    const NETWORK: [&str; 6] = ["node", "epicbox", "http", "tor", "peer", "api"];
    let about = |name: &str| {
        root.find_subcommand(name)
            .and_then(clap::Command::get_about)
            .map(ToString::to_string)
            .unwrap_or_default()
    };
    let width = SHELL_WORDS
        .iter()
        .map(|(word, _)| word.len())
        .chain(WALLET.iter().chain(NETWORK.iter()).map(|name| name.len()))
        .max()
        .unwrap_or(0);
    let row = |name: &str, what: &str| format!("  {name:<width$}  {what}");
    let mut lines = vec!["Shell".to_owned()];
    lines.extend(
        SHELL_WORDS
            .iter()
            .filter(|(word, _)| *word != "?")
            .map(|(word, what)| row(word, what)),
    );
    lines.push(String::new());
    lines.push("Wallet".to_owned());
    lines.extend(WALLET.iter().map(|name| row(name, &about(name))));
    lines.push(String::new());
    lines.push("Network".to_owned());
    lines.extend(NETWORK.iter().map(|name| row(name, &about(name))));
    lines.push(String::new());
    lines.push(
        "help <command> shows its usage. Outside the session every command runs as \
         lepic <command>."
            .to_owned(),
    );
    lines
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use clap::{CommandFactory as _, Parser as _};

    use super::*;
    use crate::cli::Cli;

    fn words(line: &str) -> Vec<String> {
        tokenize(line).words
    }

    #[test]
    fn lines_split_on_blanks_and_keep_quoted_text() {
        assert_eq!(words("tx  send 1 --to x"), ["tx", "send", "1", "--to", "x"]);
        assert_eq!(
            words(r#"tx send 1 --message "for the bike""#)[4],
            "for the bike"
        );
        assert_eq!(words("a 'b \"c' d"), ["a", "b \"c", "d"]);
        assert_eq!(words(r"a b\ c"), ["a", "b c"]);
        assert_eq!(words(r#"a "" b"#), ["a", "", "b"]);
        assert!(tokenize("tx ").fresh);
        assert!(!tokenize("tx").fresh);
        assert!(tokenize("").fresh);
        assert!(tokenize("a \"b").open_quote);
        assert_eq!(parse("a \"b"), Err("a quote is not closed".to_owned()));
    }

    #[test]
    fn shell_words_come_before_commands() {
        assert_eq!(parse("  "), Ok(Line::Empty));
        assert_eq!(parse("help"), Ok(Line::Help(vec![])));
        assert_eq!(parse("? tx send"), Ok(Line::Help(words("tx send"))));
        assert_eq!(parse("lock"), Ok(Line::Lock));
        assert_eq!(parse("unlock"), Ok(Line::Unlock));
        assert_eq!(parse("clear"), Ok(Line::Clear));
        assert_eq!(parse("history"), Ok(Line::History));
        assert_eq!(parse("status"), Ok(Line::Status));
        assert_eq!(parse("exit"), Ok(Line::Exit));
        assert_eq!(parse("quit"), Ok(Line::Exit));
        assert_eq!(parse("serve start"), Ok(Line::ServeStart(vec![])));
        assert_eq!(
            parse("serve start --http"),
            Ok(Line::ServeStart(vec!["--http".to_owned()]))
        );
        assert_eq!(parse("serve stop"), Ok(Line::ServeStop));
        assert!(parse("serve").is_err());
        assert!(parse("serve stop now").is_err());
        assert_eq!(parse("lock now"), Err("lock takes no arguments".to_owned()));
        assert!(parse("lepic tx list").is_err());
        assert_eq!(
            parse("tx list"),
            Ok(Line::Command {
                args: words("tx list"),
                yes: false
            })
        );
    }

    #[test]
    fn yes_is_taken_out_of_sends_only() {
        assert_eq!(
            strip_yes(words("tx send 1 --to x --yes")),
            (words("tx send 1 --to x"), true)
        );
        assert_eq!(
            strip_yes(words("tx send --yes 1 --to x")),
            (words("tx send 1 --to x"), true)
        );
        assert_eq!(
            strip_yes(words("tx send 1 --to x -- --yes")),
            (words("tx send 1 --to x -- --yes"), false)
        );
        assert_eq!(
            strip_yes(words("tx list --yes")),
            (words("tx list --yes"), false)
        );
        assert_eq!(
            parse("tx send 1 --to x --yes"),
            Ok(Line::Command {
                args: words("tx send 1 --to x"),
                yes: true
            })
        );
    }

    #[test]
    fn history_leaves_out_secret_lines() {
        assert!(keep_in_history("tx list"));
        assert!(keep_in_history("tx send 1 --to epic1qqq"));
        assert!(keep_in_history("epic1 pay epic:epic1abc"));
        assert!(!keep_in_history("contact enter epiccash://pair?x=y"));
        assert!(!keep_in_history("contact enter EPICCASH://pair?x=y"));
        assert!(!keep_in_history("in-person pay --hex 00ff"));
        assert!(!keep_in_history("in-person pay --hex=00ff"));
        assert!(!keep_in_history("wallet import-seed wallet.seed"));
        assert!(!keep_in_history("--password-file p tx list"));
        assert!(!keep_in_history("node status --node-api-secret-file s"));
        assert!(!keep_in_history("in-person take 0a1b2c3d"));
        assert!(!keep_in_history(
            "in-person take ur:epic/1-2/abc ur:epic/2-2/def"
        ));
        assert!(keep_in_history("in-person take --file answer.bin"));
    }

    #[test]
    fn the_shell_refuses_what_runs_outside_it() {
        let refused = |line: &str, serving: bool| {
            let args = words(line);
            let cli = Cli::try_parse_from(std::iter::once("lepic".to_owned()).chain(args.clone()))
                .expect("the line parses");
            refusal(&cli.command, &args, serving)
        };
        for line in [
            "wallet init",
            "wallet restore",
            "wallet import-seed seed.txt",
            "wallet password",
            "shell",
            "serve",
        ] {
            assert!(refused(line, false).is_some(), "{line} is refused");
        }
        for line in ["epicbox listen", "http listen", "tor listen"] {
            assert!(
                refused(line, true).is_some(),
                "{line} is refused while serving"
            );
            assert!(
                refused(line, false).is_none(),
                "{line} runs while not serving"
            );
        }
        assert!(refused("tx send 1 --to-file -", false).is_some());
        assert!(refused("tx list", false).is_none());
        assert!(refused("tx list", true).is_none());
    }

    #[test]
    fn typos_name_the_nearest_command() {
        let root = Cli::command();
        let unknown = |line: &str| unknown_command(&root, &words(line));
        assert_eq!(
            unknown("tx lsit"),
            Some(("tx lsit".to_owned(), Some("tx list".to_owned())))
        );
        assert_eq!(
            unknown("wallt info"),
            Some(("wallt".to_owned(), Some("wallet".to_owned())))
        );
        assert_eq!(
            unknown("stauts"),
            Some(("stauts".to_owned(), Some("status".to_owned())))
        );
        assert_eq!(unknown("zzzzzz"), Some(("zzzzzz".to_owned(), None)));
        assert_eq!(unknown("tx list"), None);
        assert_eq!(unknown("tx send 1 --to x"), None);
    }

    #[test]
    fn usage_names_the_command_being_typed() {
        let mut root = Cli::command();
        root.build();
        let send = usage(&mut root, &words("tx send 1")).unwrap();
        assert!(send.starts_with("tx send "), "{send}");
        assert!(usage(&mut root, &words("tx")).unwrap().starts_with("tx "));
        assert_eq!(usage(&mut root, &[]), None);
        assert_eq!(usage(&mut root, &words("--output json")), None);
    }

    #[test]
    fn some_commands_run_outside_the_shell() {
        let refused = |line: &str, serving: bool| {
            let args = words(line);
            let mut argv = vec!["lepic".to_owned()];
            argv.extend(args.iter().cloned());
            let cli = Cli::try_parse_from(argv).unwrap();
            refusal(&cli.command, &args, serving)
        };
        assert!(refused("wallet init", false).is_some());
        assert!(refused("wallet password", false).is_some());
        assert!(refused("serve", false).is_some());
        assert!(refused("tx list", false).is_none());
        assert!(refused("epicbox listen", false).is_none());
        assert!(refused("epicbox listen", true).is_some());
        assert!(refused("epictx open -", false).is_some());
    }

    #[test]
    fn help_lists_the_shell_words_and_every_command() {
        let root = Cli::command();
        let lines = help_lines(&root);
        assert_eq!(lines[0], "Shell");
        for sub in root.get_subcommands() {
            let name = sub.get_name();
            if name == "serve" || name == "shell" || sub.is_hide_set() {
                continue;
            }
            assert!(
                lines
                    .iter()
                    .any(|line| line.starts_with(&format!("  {name} "))),
                "{name} missing"
            );
        }
        assert!(lines.last().unwrap().starts_with("help <command>"));
    }

    #[test]
    fn edit_distances() {
        assert_eq!(edit_distance("lsit", "list"), 2);
        assert_eq!(edit_distance("", "ab"), 2);
        assert_eq!(edit_distance("same", "same"), 0);
    }
}
