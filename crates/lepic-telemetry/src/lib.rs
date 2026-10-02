//! Tracing subscribers and redaction helpers for the CLI and mobile hosts.
//!
//! Library crates only emit `tracing` spans and events. The binaries install
//! one of the subscribers built here:
//!
//! - [`CliTelemetry`] for the CLI: pretty, compact or JSON lines on stderr,
//!   and optionally a rotating log file.
//! - [`HostLayer`] for the mobile binding: every record is handed to a
//!   [`LogSink`] that the host app implements.
//!
//! [`capture`] and [`assert_no_secrets`] let tests in any crate check what
//! their code logs.
//!
//! JSON lines carry `timestamp`, `level`, `target`, `message`, every event
//! field under its own name, and `spans`: the enclosing spans from the
//! outermost inward, each with its `name` and fields. Field names follow the
//! vocabulary in `docs/logging.md`.

mod capture;
mod cli;
mod error;
mod filter;
mod host;
mod record;

pub use capture::{Captured, Encoding, LeakCheckError, assert_no_secrets, capture};
pub use cli::{CliConfig, CliTelemetry, FileLog, LogFormat, Rotation};
pub use error::TelemetryError;
pub use filter::{LOG_FILTER_ENV, LogFilter};
pub use host::{HostLayer, LogSink, host_dispatch};
pub use record::{ErrorChain, LogLevel, LogRecord};
