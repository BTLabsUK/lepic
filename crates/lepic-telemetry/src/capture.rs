use std::fmt;
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
#[non_exhaustive]
pub enum Encoding {
    /// The secret's own bytes; only a valid UTF-8 secret can match.
    Raw,
    /// `8c01fe42`
    LowerHex,
    /// `8C01FE42`
    UpperHex,
    /// `8c 01 fe 42`, how tracing records a `&[u8]` field value.
    SpacedHex,
    /// `[140, 1, 254, 66]`, the `Debug` form of a byte array, slice or
    /// `Vec`, including inside a derived `Debug`.
    DebugDecimal,
}

impl Encoding {
    const ALL: [Self; 5] = [
        Self::Raw,
        Self::LowerHex,
        Self::UpperHex,
        Self::SpacedHex,
        Self::DebugDecimal,
    ];

    fn render(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Raw => bytes.to_vec(),
            Self::LowerHex => join(bytes, "", |byte| format!("{byte:02x}")),
            Self::UpperHex => join(bytes, "", |byte| format!("{byte:02X}")),
            Self::SpacedHex => join(bytes, " ", |byte| format!("{byte:02x}")),
            Self::DebugDecimal => format!("{bytes:?}").into_bytes(),
        }
    }
}

fn join(bytes: &[u8], separator: &str, byte_text: impl Fn(u8) -> String) -> Vec<u8> {
    bytes
        .iter()
        .map(|&byte| byte_text(byte))
        .collect::<Vec<_>>()
        .join(separator)
        .into_bytes()
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raw => "raw bytes",
            Self::LowerHex => "lowercase hex",
            Self::UpperHex => "uppercase hex",
            Self::SpacedHex => "space-separated hex",
            Self::DebugDecimal => "debug-formatted decimal bytes",
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
/// form, in any [`Encoding`]. Indices in the error count from zero.
///
/// Records are rendered as UTF-8 text, so a secret that is not valid UTF-8
/// is found only through its encoded forms, never as [`Encoding::Raw`].
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
            Ok(Encoding::ALL.map(|encoding| (encoding, encoding.render(bytes))))
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
