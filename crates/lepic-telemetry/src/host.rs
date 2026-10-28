// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use tracing::span::{Attributes, Id, Record};
use tracing::{Dispatch, Event, Subscriber};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

use crate::LogFilter;
use crate::record::{FieldValues, LogRecord};

/// Receives every record that passes the filter. The mobile binding
/// implements it to hand records to the app, which sends them on to Logcat,
/// os_log or its own log export.
///
/// Called synchronously on the thread that emitted the event, so an
/// implementation should queue the record rather than block.
pub trait LogSink: Send + Sync + 'static {
    fn record(&self, record: LogRecord);
}

/// A layer that renders each event, with the fields of its enclosing spans,
/// into a [`LogRecord`] for a [`LogSink`].
pub struct HostLayer {
    sink: Arc<dyn LogSink>,
}

impl HostLayer {
    #[must_use]
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        Self { sink }
    }
}

/// A subscriber that forwards everything `filter` lets through to `sink`.
/// The caller decides whether to install it globally or per thread.
#[must_use]
pub fn host_dispatch(sink: Arc<dyn LogSink>, filter: LogFilter) -> Dispatch {
    let subscriber = Registry::default()
        .with(filter.into_env_filter())
        .with(HostLayer::new(sink));
    Dispatch::new(subscriber)
}

/// Span fields stored in the registry's span extensions.
struct SpanFields(Vec<(&'static str, String)>);

impl<S> Layer<S> for HostLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut values = FieldValues::default();
        attrs.record(&mut values);
        span.extensions_mut().insert(SpanFields(values.fields));
    }

    fn on_record(&self, id: &Id, record: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut values = FieldValues::default();
        record.record(&mut values);
        let mut extensions = span.extensions_mut();
        match extensions.get_mut::<SpanFields>() {
            Some(SpanFields(fields)) => fields.extend(values.fields),
            None => extensions.insert(SpanFields(values.fields)),
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut spans = Vec::new();
        let mut span_fields = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                spans.push(span.name());
                if let Some(SpanFields(fields)) = span.extensions().get::<SpanFields>() {
                    span_fields.extend(fields.iter().cloned());
                }
            }
        }
        let mut values = FieldValues::default();
        event.record(&mut values);
        self.sink
            .record(LogRecord::new(event.metadata(), spans, span_fields, values));
    }
}
