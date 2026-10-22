//! The command tree: every option keeps one meaning, every help page renders, and no option
//! takes a secret.

// Tests may unwrap and panic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use clap::{Arg, Command, CommandFactory as _, Parser as _};
use lepic_cli::cli::Cli;

/// Every command, with the path of names that reaches it.
fn walk(command: &Command, path: &[String], out: &mut Vec<(Vec<String>, Command)>) {
    out.push((path.to_vec(), command.clone()));
    for sub in command.get_subcommands() {
        let mut next = path.to_vec();
        next.push(sub.get_name().to_owned());
        walk(sub, &next, out);
    }
}

fn all_commands() -> Vec<(Vec<String>, Command)> {
    let mut root = Cli::command();
    root.build();
    let mut out = Vec::new();
    walk(&root, &[], &mut out);
    out
}

/// What an option means: its id and help text. Two uses of one flag must agree on both. clap
/// adds a pointer to `--help` on pages that have a long form; it does not change the meaning.
fn meaning(arg: &Arg) -> String {
    let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
    let help = help
        .split_once(" (see more with '--help')")
        .map_or(help.as_str(), |(text, _)| text)
        .to_owned();
    format!("{} | {help}", arg.get_id())
}

#[test]
fn the_tree_passes_clap_debug_asserts() {
    Cli::command().debug_assert();
}

#[test]
fn the_tree_has_every_planned_command() {
    let paths: Vec<String> = all_commands()
        .into_iter()
        .map(|(path, _)| path.join(" "))
        .collect();
    for expected in [
        "wallet init",
        "wallet restore",
        "wallet import-seed",
        "wallet info",
        "wallet address",
        "wallet scan",
        "tx send",
        "tx receive",
        "tx finalize",
        "tx resend",
        "tx post",
        "tx cancel",
        "tx release",
        "tx list",
        "tx show",
        "invoice issue",
        "invoice pay",
        "invoice list",
        "invoice decline",
        "epicbox listen",
        "epicbox drain",
        "epicbox status",
        "epicbox allow add",
        "epicbox allow remove",
        "epicbox allow list",
        "epicbox invoice-address",
        "http listen",
        "node status",
    ] {
        assert!(
            paths.iter().any(|path| path == expected),
            "missing {expected}"
        );
    }
}

#[test]
fn a_send_takes_an_http_address_with_its_options() {
    let cli = Cli::try_parse_from([
        "lepic",
        "tx",
        "send",
        "1",
        "--to",
        "http://203.0.113.7:3415",
        "--allow-plain-http",
        "--fluff",
    ])
    .unwrap();
    let lepic_cli::cli::Command::Tx(lepic_cli::cli::TxCommand::Send(args)) = cli.command else {
        panic!("not a send");
    };
    assert_eq!(
        args.destination.to.as_deref(),
        Some("http://203.0.113.7:3415")
    );
    assert!(args.plain_http.allow_plain_http && args.fluff.fluff);

    let cli = Cli::try_parse_from(["lepic", "http", "listen"]).unwrap();
    let lepic_cli::cli::Command::Http(lepic_cli::cli::HttpCommand::Listen(args)) = cli.command
    else {
        panic!("not an http listen");
    };
    assert_eq!((args.port, args.internet), (3415, false));
    let cli =
        Cli::try_parse_from(["lepic", "http", "listen", "--port", "0", "--internet"]).unwrap();
    let lepic_cli::cli::Command::Http(lepic_cli::cli::HttpCommand::Listen(args)) = cli.command
    else {
        panic!("not an http listen");
    };
    assert_eq!((args.port, args.internet), (0, true));
}

#[test]
fn no_short_or_long_flag_has_two_meanings() {
    let mut longs: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut shorts: BTreeMap<char, (String, String)> = BTreeMap::new();
    let mut conflicts = Vec::new();
    for (path, command) in all_commands() {
        let at = path.join(" ");
        for arg in command.get_arguments() {
            let meaning = meaning(arg);
            if let Some(long) = arg.get_long() {
                match longs.get(long) {
                    Some((first, seen)) if *seen != meaning => {
                        conflicts.push(format!(
                            "--{long}: `{seen}` in [{first}], `{meaning}` in [{at}]"
                        ));
                    }
                    Some(_) => {}
                    None => {
                        longs.insert(long.to_owned(), (at.clone(), meaning.clone()));
                    }
                }
            }
            if let Some(short) = arg.get_short() {
                match shorts.get(&short) {
                    Some((first, seen)) if *seen != meaning => {
                        conflicts.push(format!(
                            "-{short}: `{seen}` in [{first}], `{meaning}` in [{at}]"
                        ));
                    }
                    Some(_) => {}
                    None => {
                        shorts.insert(short, (at.clone(), meaning));
                    }
                }
            }
        }
    }
    assert!(conflicts.is_empty(), "{conflicts:#?}");
    // The walk saw the shared flags, so the check had something to compare.
    assert!(longs.contains_key("account") && shorts.contains_key(&'a'));
}

#[test]
fn global_options_are_exactly_the_planned_six() {
    let root = Cli::command();
    let mut globals: Vec<&str> = root
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .filter_map(Arg::get_long)
        .collect();
    globals.sort_unstable();
    assert_eq!(
        globals,
        [
            "config",
            "data-dir",
            "log-format",
            "log-level",
            "network",
            "output"
        ]
    );
}

#[test]
fn help_renders_for_every_command() {
    for (path, _) in all_commands() {
        for flag in ["-h", "--help"] {
            let mut args = vec!["lepic".to_owned()];
            args.extend(path.iter().cloned());
            args.push(flag.to_owned());
            let error = Cli::try_parse_from(&args).map(|_| ()).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp,
                "{args:?}: {error}"
            );
            let text = error.render().to_string();
            assert!(text.contains("Usage: lepic"), "{args:?}: {text}");
        }
    }
}

#[test]
fn help_starts_with_what_the_command_does() {
    for (path, command) in all_commands() {
        let Some(about) = command.get_about().map(ToString::to_string) else {
            continue;
        };
        for flag in ["-h", "--help"] {
            let mut args = vec!["lepic".to_owned()];
            args.extend(path.iter().cloned());
            args.push(flag.to_owned());
            let text = Cli::try_parse_from(&args)
                .map(|_| ())
                .unwrap_err()
                .render()
                .to_string();
            assert!(text.starts_with(&about), "{args:?}: {text}");
        }
    }
}

#[test]
fn no_option_or_argument_takes_a_secret() {
    for (path, command) in all_commands() {
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str().to_ascii_lowercase();
            for secret in ["password", "phrase", "mnemonic", "seed_words", "secret"] {
                assert!(!id.contains(secret), "{} takes {id}", path.join(" "));
            }
        }
    }
}

#[test]
fn help_that_names_the_password_variable_says_it_stays_in_the_environment() {
    let mut pages = 0;
    for (path, _) in all_commands() {
        for flag in ["-h", "--help"] {
            let mut args = vec!["lepic".to_owned()];
            args.extend(path.iter().cloned());
            args.push(flag.to_owned());
            let text = Cli::try_parse_from(&args)
                .map(|_| ())
                .unwrap_err()
                .render()
                .to_string();
            let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if words.contains("LEPIC_PASSWORD") {
                pages += 1;
                assert!(
                    words.contains("LEPIC_PASSWORD stays in the process environment"),
                    "{args:?}: {text}"
                );
            }
        }
    }
    assert!(pages >= 4, "only {pages} help pages name LEPIC_PASSWORD");
}
