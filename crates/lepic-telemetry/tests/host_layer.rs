// The clippy.toml test allowance covers #[test] functions only, not the
// helpers of an integration test crate.
#![allow(clippy::unwrap_used)]

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use lepic_telemetry::{LogFilter, LogLevel, LogRecord, LogSink, host_dispatch};

#[derive(Default)]
struct Collect(Mutex<Vec<LogRecord>>);

impl LogSink for Collect {
    fn record(&self, record: LogRecord) {
        self.0.lock().unwrap().push(record);
    }
}

fn forwarded(filter: &str, f: impl FnOnce()) -> Vec<LogRecord> {
    let sink = Arc::new(Collect::default());
    let dispatch = host_dispatch(sink.clone(), LogFilter::parse(filter).unwrap());
    tracing::dispatcher::with_default(&dispatch, f);
    sink.0.lock().unwrap().clone()
}

#[derive(Debug)]
struct Outer(Inner);

#[derive(Debug)]
struct Inner;

impl fmt::Display for Outer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("finalize failed")
    }
}

impl fmt::Display for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("node unreachable")
    }
}

impl Error for Outer {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

impl Error for Inner {}

#[test]
fn host_sink_receives_every_field_of_event_and_spans() {
    let error = Outer(Inner);
    let records = forwarded("trace", || {
        let operation =
            tracing::info_span!("receive", wallet = "w1", tx_id = tracing::field::Empty);
        let _operation = operation.enter();
        operation.record("tx_id", 9_u64);
        let session = tracing::debug_span!("epicbox_session", relay = "relay.example");
        let _session = session.enter();
        tracing::warn!(
            target: "lepic_epicbox",
            attempt = 2_i64,
            transport = "epicbox",
            stage = ?Stage::S2,
            error = &error as &(dyn Error + 'static),
            "epicbox reconnected"
        );
    });

    assert_eq!(
        records,
        [LogRecord {
            level: LogLevel::Warn,
            target: "lepic_epicbox".to_owned(),
            message: "epicbox reconnected".to_owned(),
            spans: vec!["receive", "epicbox_session"],
            fields: vec![
                ("wallet", "w1".to_owned()),
                ("tx_id", "9".to_owned()),
                ("relay", "relay.example".to_owned()),
                ("attempt", "2".to_owned()),
                ("transport", "epicbox".to_owned()),
                ("stage", "S2".to_owned()),
                ("error", "finalize failed: node unreachable".to_owned()),
            ],
        }]
    );
    assert_eq!(records[0].field("tx_id"), Some("9"));
}

#[derive(Debug)]
enum Stage {
    S2,
}

#[test]
fn host_dispatch_applies_the_filter() {
    let records = forwarded("lepic_node=debug,warn", || {
        tracing::debug!(target: "lepic_node", "node debug kept");
        tracing::debug!(target: "lepic_store", "store debug dropped");
        tracing::error!(target: "lepic_store", "store error kept");
    });

    let messages: Vec<&str> = records
        .iter()
        .map(|record| record.message.as_str())
        .collect();
    assert_eq!(messages, ["node debug kept", "store error kept"]);
}

#[test]
fn events_outside_spans_have_no_span_context() {
    let records = forwarded("info", || tracing::info!(height = 5_u64, "sync finished"));

    assert_eq!(records.len(), 1);
    assert!(records[0].spans.is_empty());
    assert_eq!(records[0].fields, [("height", "5".to_owned())]);
    assert_eq!(records[0].level, LogLevel::Info);
}
