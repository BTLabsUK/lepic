//! Logs kept on the device for support: a size-bounded ring of redacted records in a directory
//! the app owns, and the support bundle exported from it.
//!
//! Records are redacted before they reach the disk, so neither the ring nor a bundle ever holds
//! a value the redaction drops. Field values are kept only for the fields in [`KEPT_FIELDS`];
//! every other field, including amounts and addresses, is written as `[redacted]`, and quoted
//! input inside an `error` value is redacted the same way. Messages,
//! targets and span names are kept, which is why messages must never interpolate values.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use jiff::Timestamp;
use thiserror::Error;

use crate::{LogRecord, LogSink};

/// Fields from the log vocabulary whose values say nothing about keys, amounts or addresses.
const KEPT_FIELDS: [&str; 15] = [
    "wallet",
    "account",
    "tx_id",
    "slate_id",
    "stage",
    "codec",
    "transport",
    "relay",
    "node",
    "msg_id",
    "height",
    "attempt",
    "elapsed_ms",
    "error",
    "tag",
];

const REDACTED: &str = "[redacted]";

/// The ring rotates through this many segment files, so at most one segment of the newest
/// records is lost when the oldest segment is dropped.
const SEGMENTS: u64 = 4;
const MIN_LIMIT_BYTES: u64 = 4 * 1024;
const MAX_LINE_BYTES: u64 = 4 * 1024;
const BUNDLE_FORMAT: u32 = 1;

/// The most bytes the ring keeps on disk, across all its files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRingLimit {
    segment_bytes: u64,
}

impl LogRingLimit {
    /// One MiB.
    pub const DEFAULT: Self = Self {
        segment_bytes: 256 * 1024,
    };

    /// # Errors
    ///
    /// [`LogRingError::LimitTooSmall`] below 4 KiB.
    pub fn new(max_bytes: u64) -> Result<Self, LogRingError> {
        if max_bytes < MIN_LIMIT_BYTES {
            return Err(LogRingError::LimitTooSmall {
                max_bytes,
                min_bytes: MIN_LIMIT_BYTES,
            });
        }
        Ok(Self {
            segment_bytes: max_bytes / SEGMENTS,
        })
    }

    /// The limit actually enforced, which may round [`LogRingLimit::new`]'s argument down.
    #[must_use]
    pub fn max_bytes(self) -> u64 {
        self.segment_bytes.saturating_mul(SEGMENTS)
    }

    fn max_line_bytes(self) -> usize {
        usize::try_from(self.segment_bytes.min(MAX_LINE_BYTES)).unwrap_or(usize::MAX)
    }
}

impl Default for LogRingLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LogRingError {
    #[error("log ring limit of {max_bytes} bytes is below the minimum of {min_bytes} bytes")]
    LimitTooSmall { max_bytes: u64, min_bytes: u64 },
    #[error("log ring directory {directory} could not be prepared")]
    Directory {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("support bundle could not be written to {path}")]
    Export {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// A [`LogSink`] that appends each record, redacted, to a ring of files in one directory and
/// never lets them grow past their [`LogRingLimit`]. When the newest file is full the oldest is
/// deleted. A record longer than 4 KiB, or than a quarter of the limit, is cut short.
///
/// The directory should hold nothing else: files named like ring segments are deleted when they
/// do not fit the limit.
pub struct LogRing {
    dir: PathBuf,
    limit: LogRingLimit,
    clock: fn() -> Timestamp,
    active: Mutex<Active>,
}

/// The newest segment, open for appending, and its length.
#[derive(Default)]
struct Active {
    file: Option<File>,
    len: u64,
}

impl LogRing {
    /// Opens the ring in `dir`, creating the directory when needed, and keeps appending to the
    /// records already there.
    ///
    /// # Errors
    ///
    /// [`LogRingError::Directory`] when the directory or its files cannot be created, read or
    /// trimmed to the limit.
    pub fn open(dir: impl Into<PathBuf>, limit: LogRingLimit) -> Result<Self, LogRingError> {
        Self::open_with_clock(dir.into(), limit, Timestamp::now)
    }

    fn open_with_clock(
        dir: PathBuf,
        limit: LogRingLimit,
        clock: fn() -> Timestamp,
    ) -> Result<Self, LogRingError> {
        let prepared = fs::create_dir_all(&dir)
            .and_then(|()| remove_segments_outside(&dir, limit))
            .and_then(|()| Active::open(&dir));
        match prepared {
            Ok(active) => Ok(Self {
                dir,
                limit,
                clock,
                active: Mutex::new(active),
            }),
            Err(source) => Err(LogRingError::Directory {
                directory: dir,
                source,
            }),
        }
    }

    #[must_use]
    pub fn limit(&self) -> LogRingLimit {
        self.limit
    }

    /// Writes the support bundle to `path`, replacing any file there: a short header, then every
    /// record in the ring, oldest first. Records logged while the export runs wait for it.
    ///
    /// # Errors
    ///
    /// [`LogRingError::Export`] when the bundle cannot be written or a segment cannot be read.
    pub fn export_support_bundle(&self, path: &Path) -> Result<(), LogRingError> {
        let _paused = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        self.write_bundle(path)
            .map_err(|source| LogRingError::Export {
                path: path.to_owned(),
                source,
            })
    }

    fn write_bundle(&self, path: &Path) -> io::Result<()> {
        let mut out = BufWriter::new(File::create(path)?);
        writeln!(out, "lepic support bundle")?;
        writeln!(out, "format: {BUNDLE_FORMAT}")?;
        writeln!(out, "version: {}", env!("CARGO_PKG_VERSION"))?;
        writeln!(out, "exported_at: {:.3}", (self.clock)())?;
        writeln!(out, "ring_limit_bytes: {}", self.limit.max_bytes())?;
        writeln!(
            out,
            "redacted: values of fields other than {}",
            KEPT_FIELDS.join(", ")
        )?;
        writeln!(out, "---")?;
        for index in (0..SEGMENTS).rev() {
            match File::open(segment_path(&self.dir, index)) {
                Ok(segment) => {
                    io::copy(&mut segment.take(self.limit.segment_bytes), &mut out)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        out.into_inner()
            .map_err(io::IntoInnerError::into_error)?
            .sync_all()
    }

    fn append(&self, active: &mut Active, line: &[u8]) -> io::Result<()> {
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if active.file.is_none() {
            *active = Active::open(&self.dir)?;
        }
        if active.len.saturating_add(len) > self.limit.segment_bytes {
            *active = Active::default();
            self.rotate()?;
            *active = Active::open(&self.dir)?;
        }
        // Holds even when a rotation went wrong half way and left a full segment in place.
        if active.len.saturating_add(len) > self.limit.segment_bytes {
            return Ok(());
        }
        let Some(file) = active.file.as_mut() else {
            return Ok(());
        };
        if let Err(error) = file.write_all(line) {
            // The length on disk is unknown now; reopening reads it back.
            *active = Active::default();
            return Err(error);
        }
        active.len = active.len.saturating_add(len);
        Ok(())
    }

    fn rotate(&self) -> io::Result<()> {
        remove_if_present(&segment_path(&self.dir, SEGMENTS.saturating_sub(1)))?;
        let moves: Vec<(u64, u64)> = (0..SEGMENTS).zip(1..SEGMENTS).collect();
        for (from, to) in moves.into_iter().rev() {
            match fs::rename(segment_path(&self.dir, from), segment_path(&self.dir, to)) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        Ok(())
    }
}

impl LogSink for LogRing {
    fn record(&self, record: LogRecord) {
        let line = ring_line(&record, (self.clock)(), self.limit.max_line_bytes());
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        // A record that cannot be stored is dropped; logging the failure would come back here.
        let _ = self.append(&mut active, line.as_bytes());
    }
}

impl Active {
    fn open(dir: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(segment_path(dir, 0))?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Some(file),
            len,
        })
    }
}

fn segment_path(dir: &Path, index: u64) -> PathBuf {
    dir.join(format!("lepic.{index}.log"))
}

fn segment_index(file_name: &str) -> Option<u64> {
    file_name
        .strip_prefix("lepic.")?
        .strip_suffix(".log")?
        .parse()
        .ok()
}

/// Deletes segments a larger or differently split limit left behind.
fn remove_segments_outside(dir: &Path, limit: LogRingLimit) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(index) = entry.file_name().to_str().and_then(segment_index) else {
            continue;
        };
        if index >= SEGMENTS || entry.metadata()?.len() > limit.segment_bytes {
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// One record as one line of at most `max_bytes`, with every field outside [`KEPT_FIELDS`]
/// redacted and control characters escaped.
fn ring_line(record: &LogRecord, at: Timestamp, max_bytes: usize) -> String {
    let mut line = String::new();
    // Writing to a String cannot fail.
    let _ = write!(line, "{at:.3} {} ", record.level);
    push_escaped(&mut line, &record.target);
    for span in &record.spans {
        line.push(':');
        push_escaped(&mut line, span);
    }
    line.push_str(": ");
    push_escaped(&mut line, &record.message);
    for (name, value) in &record.fields {
        line.push(' ');
        push_escaped(&mut line, name);
        line.push('=');
        if *name == "error" {
            push_escaped(&mut line, &redact_quoted(value));
        } else if KEPT_FIELDS.contains(name) {
            push_escaped(&mut line, value);
        } else {
            line.push_str(REDACTED);
        }
    }
    let body_bytes = max_bytes.saturating_sub(1);
    if line.len() > body_bytes {
        line.truncate(line.floor_char_boundary(body_bytes));
    }
    line.push('\n');
    line
}

/// Replaces every span quoted with `"` or `` ` `` by `[redacted]`. LEPIC's own errors carry no
/// values, but the decoder errors they keep as sources quote the input they rejected, and that
/// input may be an address or an amount. An unclosed quote redacts the rest of the text.
fn redact_quoted(error: &str) -> String {
    let mut redacted = String::with_capacity(error.len());
    let mut chars = error.chars();
    while let Some(c) = chars.next() {
        redacted.push(c);
        if c != '"' && c != '`' {
            continue;
        }
        redacted.push_str(REDACTED);
        let mut escaped = false;
        for inner in chars.by_ref() {
            if inner == c && !escaped {
                redacted.push(c);
                break;
            }
            escaped = c == '"' && inner == '\\' && !escaped;
        }
    }
    redacted
}

fn push_escaped(line: &mut String, text: &str) {
    for c in text.chars() {
        if c.is_control() {
            line.extend(c.escape_default());
        } else {
            line.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tracing::dispatcher;

    use super::*;
    use crate::{LogFilter, LogLevel, assert_no_secrets, host_dispatch};

    const MNEMONIC: &str = "abandon ability able about above absent absorb abstract absurd";
    const PASSWORD: &str = "correct horse battery staple";
    const ADDRESS: &str = "esWWbPq4mFMqGXZ2nN1P9P2uGFZnTtM4axHwHrrcmVdTbixBK3oa@epicbox.example";
    const SEED: [u8; 8] = [0x8c, 0x01, 0xfe, 0x42, 0x17, 0x99, 0x00, 0xab];

    fn fixed_clock() -> Timestamp {
        Timestamp::UNIX_EPOCH
    }

    fn open(dir: &Path, max_bytes: u64) -> LogRing {
        let limit = LogRingLimit::new(max_bytes).unwrap();
        LogRing::open_with_clock(dir.to_owned(), limit, fixed_clock).unwrap()
    }

    fn segment_sizes(dir: &Path) -> Vec<u64> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .collect()
    }

    fn record(message: &str, fields: Vec<(&'static str, String)>) -> LogRecord {
        LogRecord {
            level: LogLevel::Info,
            target: "lepic_wallet::send".to_owned(),
            message: message.to_owned(),
            spans: vec!["send"],
            fields,
        }
    }

    fn export(ring: &LogRing, dir: &Path) -> String {
        let path = dir.join("bundle.txt");
        ring.export_support_bundle(&path).unwrap();
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn ring_never_exceeds_its_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 8 * 1024);
        let max = ring.limit().max_bytes();

        for index in 0_usize..3_000 {
            let message = match index % 7 {
                0 => "é".repeat(index),
                1 => "x".repeat(100_000),
                _ => format!("record {index}"),
            };
            ring.record(record(&message, vec![("height", index.to_string())]));

            let sizes = segment_sizes(dir.path());
            assert!(sizes.len() <= 4, "{} segments", sizes.len());
            assert!(sizes.iter().all(|&size| size <= max / 4));
            assert!(sizes.iter().sum::<u64>() <= max, "record {index}");
        }

        let bundle = export(&ring, tempfile::tempdir().unwrap().path());
        assert!(bundle.ends_with("height=2999\n"));
    }

    #[test]
    fn reopening_with_a_smaller_limit_trims_the_ring() {
        let dir = tempfile::tempdir().unwrap();
        let large = open(dir.path(), 64 * 1024);
        for index in 0..2_000 {
            large.record(record(&format!("record {index}"), vec![]));
        }
        drop(large);
        fs::write(dir.path().join("lepic.9.log"), "stale").unwrap();

        let small = open(dir.path(), 4 * 1024);
        assert!(segment_sizes(dir.path()).iter().sum::<u64>() <= 4 * 1024);
        small.record(record("record after reopen", vec![]));
        assert!(segment_sizes(dir.path()).iter().sum::<u64>() <= 4 * 1024);
    }

    #[test]
    fn rejects_limit_below_minimum() {
        assert!(matches!(
            LogRingLimit::new(4 * 1024 - 1),
            Err(LogRingError::LimitTooSmall { .. })
        ));
    }

    #[test]
    fn bundle_lists_records_oldest_first_across_segments() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 4 * 1024);
        for index in 0..60 {
            ring.record(record(&format!("record {index:02}"), vec![]));
        }

        let bundle = export(&ring, tempfile::tempdir().unwrap().path());
        let (header, body) = bundle.split_once("---\n").unwrap();
        assert!(header.starts_with("lepic support bundle\nformat: 1\n"));
        let numbers: Vec<u32> = body
            .lines()
            .map(|line| line.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert!(numbers.len() > 4);
        assert!(numbers.windows(2).all(|pair| pair[0] + 1 == pair[1]));
        assert_eq!(numbers.last(), Some(&59));
    }

    #[test]
    fn stored_record_is_one_line_with_unknown_fields_redacted() {
        let line = ring_line(
            &record(
                "slate\nreceived",
                vec![
                    ("slate_id", "0436430c".to_owned()),
                    ("amount", "1000000".to_owned()),
                ],
            ),
            fixed_clock(),
            4096,
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00.000Z info lepic_wallet::send:send: slate\\nreceived \
             slate_id=0436430c amount=[redacted]\n"
        );
    }

    /// Hands every record to the ring and keeps a copy of what the live stream would get.
    struct Tee {
        ring: Arc<LogRing>,
        live: Mutex<Vec<LogRecord>>,
    }

    impl LogSink for Tee {
        fn record(&self, record: LogRecord) {
            self.live.lock().unwrap().push(record.clone());
            self.ring.record(record);
        }
    }

    #[test]
    fn export_of_a_session_passes_assert_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let tee = Arc::new(Tee {
            ring: Arc::clone(&ring),
            live: Mutex::default(),
        });
        let dispatch = host_dispatch(tee.clone(), LogFilter::parse("trace").unwrap());

        dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!("send", wallet = "w1", seed = ?SEED);
            let _entered = span.enter();
            tracing::debug!(mnemonic = MNEMONIC, password = PASSWORD, "wallet opened");
            tracing::debug!(address = ADDRESS, amount = 1_000_000_u64, "slate created");
            tracing::trace!(key = %hex(&SEED), raw = &SEED[..], "key derived");
            tracing::info!(slate_id = "0436430c", stage = "S1", "slate sent");
        });

        let secrets: [&[u8]; 4] = [
            MNEMONIC.as_bytes(),
            PASSWORD.as_bytes(),
            ADDRESS.as_bytes(),
            &SEED,
        ];
        let live = tee.live.lock().unwrap().clone();
        assert!(
            assert_no_secrets(&live, &secrets).is_err(),
            "the session must log secrets for this test to show anything"
        );

        let bundle = export(&ring, tempfile::tempdir().unwrap().path());
        assert!(
            bundle.contains(": slate sent wallet=w1 seed=[redacted] slate_id=0436430c stage=S1\n")
        );
        assert!(bundle.contains("wallet=w1"));
        let exported = LogRecord {
            level: LogLevel::Info,
            target: String::new(),
            message: bundle,
            spans: Vec::new(),
            fields: Vec::new(),
        };
        assert_eq!(assert_no_secrets(&[exported], &secrets), Ok(()));
    }

    #[test]
    fn oversized_record_is_cut_to_one_line_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 64 * 1024);
        ring.record(record(&"x".repeat(100_000), vec![]));
        ring.record(record("record after", vec![]));

        let bundle = export(&ring, tempfile::tempdir().unwrap().path());
        let (_, body) = bundle.split_once("---\n").unwrap();
        let lines: Vec<&str> = body.split_inclusive('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("xxxx"));
        assert!(lines[0].len() <= 4 * 1024, "{} bytes", lines[0].len());
        assert!(lines[0].ends_with('\n'));
        assert!(lines[1].ends_with(": record after\n"));
    }

    #[derive(Debug, Error)]
    #[error("relay frame could not be decoded")]
    struct FrameError(#[source] serde_json::Error);

    #[test]
    fn quoted_input_in_error_text_is_redacted() {
        let invalid_type = serde_json::from_str::<u64>(&format!("\"{ADDRESS}\"")).unwrap_err();
        let out_of_range = serde_json::from_str::<u8>("300431").unwrap_err();
        let escaped = serde_json::from_str::<u64>(r#""say \"hi\" esWWbPq4""#).unwrap_err();
        for source in [&invalid_type, &escaped] {
            assert!(
                source.to_string().contains("esWWbPq4"),
                "serde_json must quote its input for this test to show anything: {source}"
            );
        }

        assert!(out_of_range.to_string().contains("`300431`"));

        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let dispatch = host_dispatch(ring.clone(), LogFilter::parse("trace").unwrap());
        for source in [invalid_type, out_of_range, escaped] {
            let error = FrameError(source);
            dispatcher::with_default(&dispatch, || {
                tracing::warn!(error = %crate::ErrorChain(&error), "relay frame rejected");
            });
        }

        let bundle = export(&ring, tempfile::tempdir().unwrap().path());
        assert!(bundle.contains(
            "error=relay frame could not be decoded: invalid type: string \"[redacted]\", expected u64"
        ));
        assert!(bundle.contains("invalid value: integer `[redacted]`, expected u8"));
        assert!(!bundle.contains("esWWbPq4"));
        assert!(!bundle.contains("300431"));
        let exported = LogRecord {
            level: LogLevel::Info,
            target: String::new(),
            message: bundle,
            spans: Vec::new(),
            fields: Vec::new(),
        };
        assert_eq!(
            assert_no_secrets(&[exported], &[ADDRESS.as_bytes()]),
            Ok(())
        );
    }

    #[test]
    fn unclosed_quote_redacts_the_rest() {
        assert_eq!(redact_quoted("bad `esWW at line 1"), "bad `[redacted]");
        assert_eq!(redact_quoted("no quotes here"), "no quotes here");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
