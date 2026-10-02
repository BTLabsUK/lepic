use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex, PoisonError};

use thiserror::Error;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{HostLayer, LogRecord, LogSink};

/// Records produced by the closure passed to [`capture`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub records: Vec<LogRecord>,
}

#[derive(Default)]
struct CaptureSink(Mutex<Vec<LogRecord>>);

impl CaptureSink {
    fn take(&self) -> Vec<LogRecord> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl LogSink for CaptureSink {
    fn record(&self, record: LogRecord) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record);
    }
}

/// Runs `f` with a subscriber that records every span and event at every
/// level on the current thread, and returns its result with the records.
/// Events emitted on other threads are not captured.
pub fn capture<T>(f: impl FnOnce() -> T) -> (T, Captured) {
    let sink = Arc::new(CaptureSink::default());
    let subscriber = Registry::default().with(HostLayer::new(sink.clone()));
    let output = tracing::subscriber::with_default(subscriber, f);
    let records = sink.take();
    (output, Captured { records })
}

/// How a secret appeared in a rendered record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Raw,
    LowerHex,
    UpperHex,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raw => "raw bytes",
            Self::LowerHex => "lowercase hex",
            Self::UpperHex => "uppercase hex",
        })
    }
}

/// Never carries the secret itself, so a failing test does not print it.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeakCheckError {
    #[error("secret {secret} appeared in record {record} as {encoding}")]
    Leaked {
        secret: usize,
        record: usize,
        encoding: Encoding,
    },
    #[error("secret {secret} is empty and would match every record")]
    EmptySecret { secret: usize },
}

/// Fails if any secret appears in any record rendered with its `Display`
/// form, either as its raw bytes or hex encoded. Indices in the error count
/// from zero.
///
/// # Errors
///
/// [`LeakCheckError::Leaked`] for the first secret found, or
/// [`LeakCheckError::EmptySecret`] when a secret has no bytes.
pub fn assert_no_secrets(records: &[LogRecord], secrets: &[&[u8]]) -> Result<(), LeakCheckError> {
    let needles = secrets
        .iter()
        .enumerate()
        .map(|(secret, bytes)| {
            if bytes.is_empty() {
                return Err(LeakCheckError::EmptySecret { secret });
            }
            Ok([
                (Encoding::Raw, bytes.to_vec()),
                (Encoding::LowerHex, hex(bytes, false).into_bytes()),
                (Encoding::UpperHex, hex(bytes, true).into_bytes()),
            ])
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (record, rendered) in records.iter().map(ToString::to_string).enumerate() {
        for (secret, encodings) in needles.iter().enumerate() {
            for (encoding, needle) in encodings {
                if contains(rendered.as_bytes(), needle) {
                    return Err(LeakCheckError::Leaked {
                        secret,
                        record,
                        encoding: *encoding,
                    });
                }
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8], upper: bool) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = if upper {
            write!(out, "{byte:02X}")
        } else {
            write!(out, "{byte:02x}")
        };
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
