// SPDX-License-Identifier: Apache-2.0
use std::io;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use tracing::{Dispatch, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{self, RollingFileAppender};
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::layer::{Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Registry};

use crate::{LogFilter, TelemetryError};

type Base = tracing_subscriber::layer::Layered<EnvFilter, Registry>;
type BoxedLayer = Box<dyn Layer<Base> + Send + Sync>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Multi-line, for a person reading a terminal.
    #[default]
    Pretty,
    /// One line per event.
    Compact,
    /// One JSON object per line; the shape is described in the crate docs.
    Json,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rotation {
    Hourly,
    #[default]
    Daily,
    Never,
}

/// A log file in `directory`, named `<file_name_prefix>.<date>` unless
/// rotation is [`Rotation::Never`].
#[derive(Clone, Debug)]
pub struct FileLog {
    pub directory: PathBuf,
    pub file_name_prefix: String,
    pub rotation: Rotation,
    /// Older files beyond this count are deleted on rotation; `None` keeps
    /// them all.
    pub max_files: Option<NonZeroUsize>,
    pub format: LogFormat,
}

#[derive(Debug, Default)]
pub struct CliConfig {
    pub filter: LogFilter,
    pub console: LogFormat,
    /// Colour escapes on the console. Files never get them.
    pub ansi: bool,
    pub file: Option<FileLog>,
}

/// A subscriber for the CLI. Install [`CliTelemetry::dispatch`] with
/// `tracing::dispatcher::set_global_default` and keep this value alive until
/// exit: dropping it flushes and closes the log file.
pub struct CliTelemetry {
    dispatch: Dispatch,
    _file_guard: Option<WorkerGuard>,
}

impl CliTelemetry {
    /// Logs to stderr, which keeps stdout free for command output.
    ///
    /// # Errors
    ///
    /// [`TelemetryError::LogFile`] when the log file cannot be created.
    pub fn new(config: CliConfig) -> Result<Self, TelemetryError> {
        Self::with_console_writer(config, io::stderr)
    }

    /// Like [`CliTelemetry::new`], with console output going to `writer`.
    ///
    /// # Errors
    ///
    /// [`TelemetryError::LogFile`] when the log file cannot be created.
    pub fn with_console_writer<W>(config: CliConfig, writer: W) -> Result<Self, TelemetryError>
    where
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        let mut layers: Vec<BoxedLayer> = vec![format_layer(config.console, config.ansi, writer)];
        let file_guard = match config.file {
            Some(file) => {
                let appender = file_appender(&file)?;
                let (writer, guard) = tracing_appender::non_blocking(appender);
                layers.push(format_layer(file.format, false, writer));
                Some(guard)
            }
            None => None,
        };
        let subscriber = Registry::default()
            .with(config.filter.into_env_filter())
            .with(layers);
        Ok(Self {
            dispatch: Dispatch::new(subscriber),
            _file_guard: file_guard,
        })
    }

    #[must_use]
    pub fn dispatch(&self) -> &Dispatch {
        &self.dispatch
    }
}

fn file_appender(file: &FileLog) -> Result<RollingFileAppender, TelemetryError> {
    let rotation = match file.rotation {
        Rotation::Hourly => rolling::Rotation::HOURLY,
        Rotation::Daily => rolling::Rotation::DAILY,
        Rotation::Never => rolling::Rotation::NEVER,
    };
    let mut builder = RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(&file.file_name_prefix);
    if let Some(max_files) = file.max_files {
        builder = builder.max_log_files(max_files.get());
    }
    builder
        .build(&file.directory)
        .map_err(|source| TelemetryError::LogFile {
            directory: file.directory.clone(),
            source,
        })
}

fn format_layer<S, W>(format: LogFormat, ansi: bool, writer: W) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer = fmt::layer().with_writer(writer).with_ansi(ansi);
    match format {
        LogFormat::Pretty => layer.pretty().boxed(),
        LogFormat::Compact => layer.compact().boxed(),
        LogFormat::Json => layer
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(true)
            .boxed(),
    }
}
