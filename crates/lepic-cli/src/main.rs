// SPDX-License-Identifier: Apache-2.0
//! The lepic command-line wallet.

use std::io::{self, IsTerminal as _};
use std::process::ExitCode;

use lepic_cli::secret::SecretInput;
use lepic_cli::settings::Env;
use lepic_cli::{Console, ProcessHost, run};

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
    };
    ExitCode::from(run(
        &ProcessHost::default(),
        std::env::args_os(),
        &mut console,
    ))
}
