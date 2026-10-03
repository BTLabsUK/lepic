//! Forwarding of log records to the app's Dart stream and to the on-device log ring.

use std::sync::{Arc, PoisonError, RwLock};

use lepic_telemetry::LogRing;

use crate::api::diagnostics::LogEntry;
use crate::frb_generated::StreamSink;

/// Hands records to the Dart stream the app subscribed last and to the log ring it opened
/// last, or drops them where there is none.
#[derive(Default)]
pub(crate) struct LogForwarder {
    sink: RwLock<Option<StreamSink<LogEntry>>>,
    ring: RwLock<Option<Arc<LogRing>>>,
}

impl LogForwarder {
    pub(crate) fn replace(&self, sink: Option<StreamSink<LogEntry>>) {
        *self.sink.write().unwrap_or_else(PoisonError::into_inner) = sink;
    }

    pub(crate) fn replace_ring(&self, ring: Option<Arc<LogRing>>) {
        *self.ring.write().unwrap_or_else(PoisonError::into_inner) = ring;
    }

    pub(crate) fn ring(&self) -> Option<Arc<LogRing>> {
        self.ring
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl lepic_telemetry::LogSink for LogForwarder {
    fn record(&self, record: lepic_telemetry::LogRecord) {
        if let Some(ring) = self.ring() {
            ring.record(record.clone());
        }
        let sink = self.sink.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = sink.as_ref() {
            // A closed stream only means the app stopped listening.
            let _ = sink.add(record.into());
        }
    }
}
