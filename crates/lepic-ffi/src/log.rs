//! Forwarding of log records to the app's Dart stream.

use std::sync::{PoisonError, RwLock};

use crate::api::diagnostics::LogEntry;
use crate::frb_generated::StreamSink;

/// Hands records to the Dart stream the app subscribed last, or drops them while there is none.
#[derive(Default)]
pub(crate) struct LogForwarder {
    sink: RwLock<Option<StreamSink<LogEntry>>>,
}

impl LogForwarder {
    pub(crate) fn replace(&self, sink: Option<StreamSink<LogEntry>>) {
        *self.sink.write().unwrap_or_else(PoisonError::into_inner) = sink;
    }
}

impl lepic_telemetry::LogSink for LogForwarder {
    fn record(&self, record: lepic_telemetry::LogRecord) {
        let sink = self.sink.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = sink.as_ref() {
            // A closed stream only means the app stopped listening.
            let _ = sink.add(record.into());
        }
    }
}
