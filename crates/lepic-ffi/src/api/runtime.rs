//! The runtime the app creates once: the threads LEPIC works on, its log stream, and the
//! registry of open wallets.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use flutter_rust_bridge::frb;
use lepic_keychain::KdfParams;
use lepic_telemetry::{LogFilter, host_dispatch};
use tokio::runtime::Runtime;
use tracing::{error, info, warn};

use crate::api::diagnostics::{LogEntry, LogLevel};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::boundary::{Boundary, guard};
use crate::frb_generated::StreamSink;
use crate::log::LogForwarder;
use crate::node::NodeFactory;

/// Owns the threads every wallet runs on. Create one when the app starts and keep it; dropping
/// it stops work still running. Wallets keep the runtime alive while they are open.
#[frb(opaque)]
pub struct LepicRuntime {
    pub(crate) inner: Arc<RuntimeInner>,
}

pub(crate) struct RuntimeInner {
    runtime: Option<Runtime>,
    pub(crate) boundary: Boundary,
    logs: Arc<LogForwarder>,
    pub(crate) nodes: NodeFactory,
    pub(crate) kdf: KdfParams,
    open: Mutex<BTreeSet<PathBuf>>,
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // Dropping a runtime blocks, which panics when the last wallet is dropped on a
            // runtime thread.
            runtime.shutdown_background();
        }
    }
}

impl LepicRuntime {
    /// Starts the runtime. Records at `log_level` and above go to the stream from
    /// [`LepicRuntime::logs`].
    #[frb(sync)]
    pub fn new(log_level: LogLevel) -> Result<LepicRuntime, WalletError> {
        guard("runtime", || {
            Self::start(log_level, NodeFactory::Http, KdfParams::DEFAULT)
        })
    }

    pub(crate) fn start(
        log_level: LogLevel,
        nodes: NodeFactory,
        kdf: KdfParams,
    ) -> Result<Self, WalletError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("lepic")
            .enable_all()
            .build()
            .map_err(|error| WalletError::new(WalletErrorKind::Io, error.to_string()))?;
        let logs = Arc::new(LogForwarder::default());
        let filter = LogFilter::parse(log_level.directive()).map_err(|error| {
            WalletError::new(WalletErrorKind::InvalidArgument, error.to_string())
        })?;
        let dispatch = host_dispatch(logs.clone(), filter);
        let boundary = Boundary {
            handle: runtime.handle().clone(),
            dispatch,
        };
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                runtime: Some(runtime),
                boundary,
                logs,
                nodes,
                kdf,
                open: Mutex::default(),
            }),
        })
    }

    /// Sends every log record from now on to `sink`, replacing the stream subscribed before.
    pub fn logs(&self, sink: StreamSink<LogEntry>) {
        self.inner.logs.replace(Some(sink));
    }

    /// Ends the stream from [`LepicRuntime::logs`]. Cancelling the Dart subscription completes
    /// only once the stream has ended.
    #[frb(sync)]
    pub fn stop_logs(&self) {
        self.inner.logs.replace(None);
    }

    /// Logs one line from the app under the target `dart.<tag>`, through the same stream.
    /// `tag` keeps only ASCII letters, digits and `_`, at most 32 of them. Never pass secrets.
    #[frb(sync)]
    pub fn log_message(&self, level: LogLevel, tag: String, message: String) {
        let tag: String = tag
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(32)
            .collect();
        tracing::dispatcher::with_default(&self.inner.boundary.dispatch, || match level {
            LogLevel::Error => error!(target: "dart", tag, "{message}"),
            LogLevel::Warn => warn!(target: "dart", tag, "{message}"),
            LogLevel::Info => info!(target: "dart", tag, "{message}"),
            LogLevel::Debug => tracing::debug!(target: "dart", tag, "{message}"),
            LogLevel::Trace => tracing::trace!(target: "dart", tag, "{message}"),
        });
    }
}

impl RuntimeInner {
    /// Marks `data_dir` as in use until the returned claim is dropped. Fails with
    /// [`WalletErrorKind::WalletBusy`] when it already is.
    pub(crate) fn claim(self: &Arc<Self>, data_dir: &Path) -> Result<DirClaim, WalletError> {
        let dir = std::fs::canonicalize(data_dir).map_err(|error| {
            WalletError::new(
                WalletErrorKind::Io,
                format!("wallet directory is not usable: {error}"),
            )
        })?;
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        if !open.insert(dir.clone()) {
            return Err(WalletError::new(
                WalletErrorKind::WalletBusy,
                "a wallet on this directory is open",
            ));
        }
        Ok(DirClaim {
            runtime: Arc::clone(self),
            dir,
        })
    }
}

/// A data directory a wallet or a deletion is using.
pub(crate) struct DirClaim {
    pub(crate) runtime: Arc<RuntimeInner>,
    pub(crate) dir: PathBuf,
}

impl Drop for DirClaim {
    fn drop(&mut self) {
        self.runtime
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.dir);
    }
}
