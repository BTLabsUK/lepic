//! Log records for the app: the stream the runtime forwards them to, and lines the app adds.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub(crate) const fn directive(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl From<lepic_telemetry::LogLevel> for LogLevel {
    fn from(level: lepic_telemetry::LogLevel) -> Self {
        match level {
            lepic_telemetry::LogLevel::Error => Self::Error,
            lepic_telemetry::LogLevel::Warn => Self::Warn,
            lepic_telemetry::LogLevel::Info => Self::Info,
            lepic_telemetry::LogLevel::Debug => Self::Debug,
            lepic_telemetry::LogLevel::Trace => Self::Trace,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogField {
    pub name: String,
    pub value: String,
}

/// One log record. Messages and fields follow the LEPIC log vocabulary; none carries a secret.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    /// The Rust module, or `dart.<tag>` for lines from `LepicRuntime::log_message`.
    pub target: String,
    pub message: String,
    /// Operation spans from the outermost inward, such as `send`.
    pub spans: Vec<String>,
    pub fields: Vec<LogField>,
}

impl From<lepic_telemetry::LogRecord> for LogEntry {
    fn from(record: lepic_telemetry::LogRecord) -> Self {
        Self {
            level: record.level.into(),
            target: record.target,
            message: record.message,
            spans: record.spans.into_iter().map(str::to_owned).collect(),
            fields: record
                .fields
                .into_iter()
                .map(|(name, value)| LogField {
                    name: name.to_owned(),
                    value,
                })
                .collect(),
        }
    }
}
