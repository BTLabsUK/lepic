//! Epicbox log lines written by the spawned inbox task reach the host's log layer, which is
//! installed for the calling thread only.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod client_support;

use std::sync::{Arc, Mutex};

use client_support::{BOB, client, reach};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{ConnectionState, Network};
use lepic_telemetry::{LogFilter, LogLevel, LogRecord, LogSink, host_dispatch};

#[derive(Default)]
struct Collect(Mutex<Vec<LogRecord>>);

impl LogSink for Collect {
    fn record(&self, record: LogRecord) {
        self.0.lock().unwrap().push(record);
    }
}

// A worker thread runs the inbox task, so only a task that carries the subscriber is logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_warning_from_the_inbox_task_reaches_the_host_log() {
    let sink = Arc::new(Collect::default());
    let dispatch = host_dispatch(sink.clone(), LogFilter::parse("info").unwrap());
    let _installed = tracing::dispatcher::set_default(&dispatch);

    let relay = MockRelay::new(Network::Mainnet);
    relay.set_refusing(true);
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| {
        matches!(s, ConnectionState::Waiting { attempt: 1.., .. })
    })
    .await;
    bob.stop().await.unwrap();

    let records = sink.0.lock().unwrap().clone();
    let retry = records
        .iter()
        .find(|record| record.message == "epicbox disconnected, retrying")
        .unwrap_or_else(|| panic!("no retry warning in {records:?}"));
    assert_eq!(retry.level, LogLevel::Warn);
    assert!(retry.field("retry_in_ms").is_some(), "{retry:?}");
    assert!(retry.field("error").is_some(), "{retry:?}");
    assert!(retry.spans.contains(&"epicbox_listen"), "{retry:?}");
    assert!(bob.last_disconnect().is_some());
}
