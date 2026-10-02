use std::error::Error;
use std::fmt;

use tracing::field::{Field, Visit};
use tracing::{Level, Metadata};

/// Longest source chain rendered for an error field, so a cyclic or very
/// deep chain cannot make one record unbounded.
const MAX_ERROR_SOURCES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn of(metadata: &Metadata<'_>) -> Self {
        match *metadata.level() {
            Level::ERROR => Self::Error,
            Level::WARN => Self::Warn,
            Level::INFO => Self::Info,
            Level::DEBUG => Self::Debug,
            _ => Self::Trace,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        })
    }
}

/// One event with the fields of every span it happened in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    pub level: LogLevel,
    pub target: String,
    pub message: String,
    /// Span names from the outermost span inward.
    pub spans: Vec<&'static str>,
    /// Span fields from the outermost span inward, then the event's own
    /// fields, in the order they were recorded.
    pub fields: Vec<(&'static str, String)>,
}

impl LogRecord {
    pub(crate) fn new(
        metadata: &Metadata<'_>,
        spans: Vec<&'static str>,
        mut fields: Vec<(&'static str, String)>,
        event: FieldValues,
    ) -> Self {
        fields.extend(event.fields);
        Self {
            level: LogLevel::of(metadata),
            target: metadata.target().to_owned(),
            message: event.message.unwrap_or_default(),
            spans,
            fields,
        }
    }

    /// The field value under `name`, the innermost one if several spans
    /// recorded it.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .rev()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value.as_str())
    }
}

impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.level, self.target)?;
        for span in &self.spans {
            write!(f, ":{span}")?;
        }
        write!(f, ": {}", self.message)?;
        for (name, value) in &self.fields {
            write!(f, " {name}={value}")?;
        }
        Ok(())
    }
}

/// Displays an error followed by its sources, separated by `": "`.
///
/// Log errors as `error = %ErrorChain(&error)`: the JSON and text formatters
/// otherwise print only the outermost error.
#[derive(Clone, Copy)]
pub struct ErrorChain<'a>(pub &'a (dyn Error + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let sources = std::iter::successors(self.0.source(), |&error| error.source());
        for source in sources.take(MAX_ERROR_SOURCES) {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Collects the fields of one span or event as rendered strings.
#[derive(Debug, Default)]
pub(crate) struct FieldValues {
    pub(crate) message: Option<String>,
    pub(crate) fields: Vec<(&'static str, String)>,
}

impl FieldValues {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((field.name(), value));
        }
    }
}

impl Visit for FieldValues {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_owned());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, value.to_string());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.push(field, value.to_string());
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.push(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        self.push(field, ErrorChain(value).to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }
}
