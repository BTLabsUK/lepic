// SPDX-License-Identifier: Apache-2.0
//! Forwards the progress of a copy of a plain database into an encrypted one to the app's
//! stream.

use std::sync::{PoisonError, RwLock};

use crate::api::at_rest::StoreMigrationProgress;
use crate::frb_generated::StreamSink;

#[derive(Default)]
pub(crate) struct MigrationForwarder {
    sink: RwLock<Option<StreamSink<StoreMigrationProgress>>>,
}

impl MigrationForwarder {
    pub(crate) fn replace(&self, sink: Option<StreamSink<StoreMigrationProgress>>) {
        *self.sink.write().unwrap_or_else(PoisonError::into_inner) = sink;
    }

    pub(crate) fn send(&self, progress: lepic_store::MigrationProgress) {
        let sink = self.sink.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = sink.as_ref() {
            // A closed stream only means the app stopped listening.
            let _ = sink.add(progress.into());
        }
    }
}
