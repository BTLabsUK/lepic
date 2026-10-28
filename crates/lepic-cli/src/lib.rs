// SPDX-License-Identifier: Apache-2.0
//! The `lepic` command-line wallet, as a library so tests drive it in-process with a mock node
//! and a mock relay.
//!
//! [`run`] parses the arguments, resolves the settings once, installs logging for the command's
//! duration only, runs the command on its own Tokio runtime and prints its report. Everything
//! the process would take from the outside (environment, standard streams, node, relay, signal)
//! comes in through [`Host`] and [`Console`], so the CLI keeps no global state.

pub mod amount;
pub mod cli;
mod commands;
pub mod exit;
pub mod hint;
pub mod host;
pub mod output;
pub mod progress;
pub mod secret;
pub mod settings;
pub mod stores;
pub mod vault;

use std::ffi::OsString;
use std::io::Write;

use clap::Parser as _;
use clap::error::ErrorKind as ClapErrorKind;
use lepic_telemetry::{CliConfig, CliTelemetry, LogFilter};
use rand::SeedableRng as _;
use rand::rngs::{StdRng, SysRng};
use zeroize::Zeroizing;

pub use crate::host::{Host, ProcessHost};

use crate::cli::Cli;
use crate::exit::{CliError, ErrorKind};
use crate::output::{render, render_error};
use crate::secret::SecretInput;
use crate::settings::{Env, OutputFormat, Settings, output_format};

/// The process's standard streams and environment, as one command sees them.
pub struct Console {
    pub env: Env,
    pub secrets: SecretInput,
    pub stdout: Box<dyn Write + Send>,
    pub stderr: Box<dyn Write + Send>,
    /// Colour in log lines on stderr.
    pub ansi: bool,
}

/// Runs one command and returns its exit code (see [`exit::ErrorKind`]).
pub fn run<H: Host>(
    host: &H,
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
    console: &mut Console,
) -> u8 {
    randomize_crypto_context();
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            );
            let text = error.render().to_string();
            let (stream, code) = if informational {
                (&mut console.stdout, 0)
            } else {
                (&mut console.stderr, ErrorKind::Usage.exit_code())
            };
            let _ = stream.write_all(text.as_bytes());
            return code;
        }
    };
    let format = output_format(&cli.global, &console.env);
    let settings = match Settings::resolve(&cli.global, &console.env) {
        Ok(settings) => settings,
        Err(error) => return report_error(console, format, &error.into(), None),
    };
    let text = match execute(host, cli, &settings, console) {
        Ok(text) => text,
        Err(error) => return report_error(console, settings.output, &error, Some(&settings)),
    };
    let written = console
        .stdout
        .write_all(text.as_bytes())
        .and_then(|()| console.stdout.flush());
    match written {
        Ok(()) => 0,
        Err(source) => report_error(
            console,
            settings.output,
            &CliError::Io {
                what: "write the command output",
                source,
            },
            Some(&settings),
        ),
    }
}

/// Blinds the secp256k1 context before anything uses it. Nothing in the process does crypto
/// before the first `run`, so later calls, which only tests make, find it already created.
/// Without OS randomness it stays unblinded, which changes no result; a command that needs
/// randomness then fails on its own.
fn randomize_crypto_context() {
    if let Ok(mut rng) = StdRng::try_from_rng(&mut SysRng) {
        lepic_wallet::randomize_crypto_context(&mut rng);
    }
}

fn report_error(
    console: &mut Console,
    format: OutputFormat,
    error: &CliError,
    settings: Option<&Settings>,
) -> u8 {
    let hint = match format {
        OutputFormat::Human => hint::hint(error, settings),
        OutputFormat::Json => None,
    };
    let text = render_error(error, format, hint.as_deref());
    let stream = match format {
        OutputFormat::Json => &mut console.stdout,
        OutputFormat::Human => &mut console.stderr,
    };
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.flush();
    error.kind().exit_code()
}

fn execute<H: Host>(
    host: &H,
    cli: Cli,
    settings: &Settings,
    console: &mut Console,
) -> Result<Zeroizing<String>, CliError> {
    let telemetry = CliTelemetry::new(CliConfig {
        filter: LogFilter::parse(&settings.log_filter)?,
        console: settings.log_format,
        ansi: console.ansi,
        file: None,
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::io("start the async runtime"))?;
    let report = tracing::dispatcher::with_default(telemetry.dispatch(), || {
        runtime.block_on(commands::execute(host, cli.command, settings, console))
    })?;
    Ok(render(&report, settings.output))
}
