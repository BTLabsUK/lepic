// The clippy.toml test allowance covers #[test] functions only, not the
// helpers of an integration test crate.
#![allow(clippy::unwrap_used)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use lepic_telemetry::{
    CliConfig, CliTelemetry, ErrorChain, FileLog, LogFilter, LogFormat, Rotation, TelemetryError,
};
use serde_json::Value;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    fn json_lines(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = Buffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn console(format: LogFormat, filter: LogFilter) -> (CliTelemetry, Buffer) {
    let buffer = Buffer::default();
    let config = CliConfig {
        filter,
        console: format,
        ansi: false,
        file: None,
    };
    let telemetry = CliTelemetry::with_console_writer(config, buffer.clone()).unwrap();
    (telemetry, buffer)
}

#[derive(Debug)]
struct Refused(io::Error);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("relay refused")
    }
}

impl Error for Refused {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Field names listed in the vocabulary table of docs/logging.md.
fn documented_field_names() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/logging.md");
    let doc = fs::read_to_string(path).unwrap();
    let table = doc
        .split("## One vocabulary")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .unwrap();
    table
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|line| line.split('`').next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn json_lines_carry_documented_field_names() {
    let (telemetry, buffer) = console(LogFormat::Json, LogFilter::parse("trace").unwrap());
    let error = Refused(io::Error::new(io::ErrorKind::ConnectionRefused, "closed"));

    tracing::dispatcher::with_default(telemetry.dispatch(), || {
        let span = tracing::info_span!("send", wallet = "w1", account = "default", tx_id = 7);
        let _entered = span.enter();
        tracing::info!(
            slate_id = "0436430c-2b02-624c-2032-570501212b00",
            stage = "S1",
            codec = "legacy-v3",
            transport = "epicbox",
            relay = "relay.example",
            peer_relay = "peer.example",
            node = "node.example",
            msg_id = "m-1",
            height = 1_000_u64,
            attempt = 1_u32,
            elapsed_ms = 12_u64,
            error = %ErrorChain(&error),
            tag = "t",
            status = "imported",
            count = 3_u32,
            "slate sent"
        );
    });

    let lines = buffer.json_lines();
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    for envelope in ["timestamp", "level", "target", "message", "spans"] {
        assert!(line.get(envelope).is_some(), "missing {envelope} in {line}");
    }
    assert_eq!(line["level"], "INFO");
    assert_eq!(line["message"], "slate sent");
    assert_eq!(line["error"], "relay refused: closed");
    assert_eq!(line["height"], 1000);

    let span = &line["spans"][0];
    assert_eq!(span["name"], "send");

    let mut emitted: Vec<String> = ["wallet", "account", "tx_id"]
        .into_iter()
        .filter(|name| span.get(name).is_some())
        .map(str::to_owned)
        .collect();
    emitted.extend(
        line.as_object()
            .unwrap()
            .keys()
            .filter(|key| {
                !["timestamp", "level", "target", "message", "spans"].contains(&key.as_str())
            })
            .cloned(),
    );
    let mut documented = documented_field_names();
    documented.sort();
    emitted.sort();
    assert_eq!(emitted, documented);
}

#[test]
fn filter_directives_select_targets_and_levels() {
    let filter = LogFilter::parse("warn,lepic_wallet=debug").unwrap();
    let (telemetry, buffer) = console(LogFormat::Json, filter);

    tracing::dispatcher::with_default(telemetry.dispatch(), || {
        tracing::info!(target: "lepic_node", "node info dropped");
        tracing::warn!(target: "lepic_node", "node warn kept");
        tracing::debug!(target: "lepic_wallet", "wallet debug kept");
        tracing::trace!(target: "lepic_wallet", "wallet trace dropped");
    });

    let messages: Vec<Value> = buffer
        .json_lines()
        .into_iter()
        .map(|line| line["message"].clone())
        .collect();
    assert_eq!(messages, ["node warn kept", "wallet debug kept"]);
}

#[test]
fn default_filter_records_info_and_above() {
    let (telemetry, buffer) = console(LogFormat::Json, LogFilter::default());

    tracing::dispatcher::with_default(telemetry.dispatch(), || {
        tracing::debug!("debug dropped");
        tracing::info!("info kept");
        tracing::error!("error kept");
    });

    let messages: Vec<Value> = buffer
        .json_lines()
        .into_iter()
        .map(|line| line["message"].clone())
        .collect();
    assert_eq!(messages, ["info kept", "error kept"]);
}

#[test]
fn pretty_and_compact_render_message_and_fields() {
    for format in [LogFormat::Pretty, LogFormat::Compact] {
        let (telemetry, buffer) = console(format, LogFilter::default());
        tracing::dispatcher::with_default(telemetry.dispatch(), || {
            tracing::info!(height = 42_u64, "output restored");
        });
        let text = buffer.text();
        assert!(text.contains("output restored"), "{format:?}: {text}");
        assert!(text.contains("height"), "{format:?}: {text}");
        assert!(
            !text.contains('\u{1b}'),
            "{format:?} wrote ansi escapes: {text}"
        );
    }
}

#[test]
fn file_log_receives_records_and_is_flushed_on_drop() {
    let directory = tempfile::tempdir().unwrap();
    let config = CliConfig {
        filter: LogFilter::default(),
        console: LogFormat::Compact,
        ansi: false,
        file: Some(FileLog {
            directory: directory.path().to_path_buf(),
            file_name_prefix: "lepic.log".to_owned(),
            rotation: Rotation::Never,
            max_files: None,
            format: LogFormat::Json,
        }),
    };
    let console = Buffer::default();
    let telemetry = CliTelemetry::with_console_writer(config, console.clone()).unwrap();
    tracing::dispatcher::with_default(telemetry.dispatch(), || {
        tracing::info!(transport = "file", "slate received");
    });
    drop(telemetry);

    let written = fs::read_to_string(directory.path().join("lepic.log")).unwrap();
    let line: Value = serde_json::from_str(written.trim_end()).unwrap();
    assert_eq!(line["message"], "slate received");
    assert_eq!(line["transport"], "file");
    assert!(console.text().contains("slate received"));
}

#[test]
fn rejects_log_directory_that_is_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let not_a_directory = directory.path().join("occupied");
    fs::write(&not_a_directory, b"").unwrap();
    let config = CliConfig {
        file: Some(FileLog {
            directory: not_a_directory,
            file_name_prefix: "lepic.log".to_owned(),
            rotation: Rotation::Daily,
            max_files: None,
            format: LogFormat::Json,
        }),
        ..CliConfig::default()
    };

    let result = CliTelemetry::with_console_writer(config, Buffer::default());
    assert!(matches!(result, Err(TelemetryError::LogFile { .. })));
}
