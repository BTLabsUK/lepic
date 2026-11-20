// SPDX-License-Identifier: Apache-2.0
//! The `lepic` binary: runs one command of [`lepic_cli`] on the real process and exits with its
//! code. `docs/cli.md` lists the commands.

use std::io::{self, IsTerminal as _};
use std::process::ExitCode;

use lepic_cli::secret::SecretInput;
use lepic_cli::settings::Env;
use lepic_cli::{Console, ProcessHost, run_with};

fn main() -> ExitCode {
    let stdin = io::stdin();
    let terminal = stdin.is_terminal();
    let mut console = Console {
        env: Env::from_process(),
        secrets: SecretInput::new(
            Box::new(io::BufReader::new(stdin)),
            terminal,
            Box::new(io::stderr()),
        ),
        stdout: Box::new(io::stdout()),
        stderr: Box::new(io::stderr()),
        ansi: io::stderr().is_terminal(),
        stdout_terminal: io::stdout().is_terminal(),
    };
    // Without a command, `lepic` opens the shell when it talks to a person.
    let interactive = terminal && io::stdout().is_terminal();
    ExitCode::from(run_with(
        &ProcessHost::default(),
        std::env::args_os(),
        &mut console,
        interactive,
    ))
}
