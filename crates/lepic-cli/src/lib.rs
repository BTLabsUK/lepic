// SPDX-License-Identifier: Apache-2.0
//! The `lepic` command-line wallet, as a library so tests drive it in-process with a mock node
//! and a mock relay.
//!
//! [`run`] parses the arguments, resolves the settings once, installs logging for the command's
//! duration only, runs the command on its own Tokio runtime and prints its report. Everything
//! the process would take from the outside (environment, standard streams, node, relay, signal)
//! comes in through [`Host`] and [`Console`], so the CLI keeps no global state.

pub mod amount;
#[cfg(unix)]
mod api;
mod api_clients;
pub mod app_config;
pub mod cli;
mod commands;
pub mod exit;
pub mod hint;
pub mod host;
pub mod output;
pub mod profile;
pub mod progress;
pub mod secret;
mod service;
pub mod settings;
pub mod settings_file;
pub mod stores;
#[cfg(unix)]
mod through_serve;
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
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) if json_requested(&args, &console.env) && !is_informational(&error) => {
            let message = usage_message(&error);
            return report_error(
                console,
                OutputFormat::Json,
                &CliError::Arguments(message),
                None,
            );
        }
        Err(error) => {
            let (text, code) = usage_text(&error);
            let stream = if code == 0 {
                &mut console.stdout
            } else {
                &mut console.stderr
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

/// Whether the command line, or failing that the environment, asks for JSON output. It reads
/// the raw arguments, since it runs when they did not parse: the last `--output` before a bare
/// `--` counts.
fn json_requested(args: &[OsString], env: &Env) -> bool {
    let mut value: Option<String> = None;
    let mut iter = args.iter().skip(1).map(|arg| arg.to_string_lossy());
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        if let Some(given) = arg.strip_prefix("--output=") {
            value = Some(given.to_owned());
        } else if arg == "--output" {
            value = iter.next().map(std::borrow::Cow::into_owned);
        }
    }
    let value = value.or_else(|| env.get("LEPIC_OUTPUT").map(str::to_owned));
    value.is_some_and(|value| {
        <crate::cli::OutputArg as clap::ValueEnum>::from_str(&value, false)
            .is_ok_and(|parsed| matches!(parsed, crate::cli::OutputArg::Json))
    })
}

fn is_informational(error: &clap::Error) -> bool {
    matches!(
        error.kind(),
        ClapErrorKind::DisplayHelp
            | ClapErrorKind::DisplayVersion
            | ClapErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    )
}

/// The first paragraph of clap's message, without its `error: ` prefix: the usage lines and
/// the pointer to `--help` that follow are for a terminal.
fn usage_message(error: &clap::Error) -> String {
    let plain = error.render().to_string();
    let first = plain.split("\n\n").next().unwrap_or_default();
    let first = first.trim();
    first.strip_prefix("error: ").unwrap_or(first).to_owned()
}

/// What a command line that does not parse prints, and the exit code: help and version on
/// standard output with 0, anything else on standard error with the usage code.
fn usage_text(error: &clap::Error) -> (String, u8) {
    let informational = matches!(
        error.kind(),
        ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
    );
    let code = if informational {
        0
    } else {
        ErrorKind::Usage.exit_code()
    };
    (error.render().to_string(), code)
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

pub(crate) fn report_error(
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
    tracing::dispatcher::with_default(telemetry.dispatch(), || {
        runtime.block_on(async {
            // While `lepic serve` holds the wallet, a command with a route runs there.
            #[cfg(unix)]
            if let Some(text) = through_serve::run(&cli.command, settings).await? {
                return Ok(text);
            }
            let report = commands::execute(host, cli.command, settings, console).await?;
            Ok(render(&report, settings.output))
        })
    })
}
