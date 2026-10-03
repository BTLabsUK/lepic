//! The runtime the app creates once: the threads LEPIC works on, its log stream, and the
//! registry of open wallets.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use flutter_rust_bridge::frb;
use lepic_keychain::KdfParams;
use lepic_telemetry::{LogFilter, host_dispatch};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tokio::runtime::Runtime;
use tracing::{error, info, warn};

use crate::api::diagnostics::{LogEntry, LogLevel};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::boundary::{Boundary, guard, guard_or, install_panic_hook};
use crate::frb_generated::StreamSink;
use crate::log::LogForwarder;
use crate::node::NodeFactory;
use crate::pin::{PinGuard, PinPolicy};

/// Sets up the library once per process: blinds the secp256k1 context before any wallet uses
/// it, and installs a panic hook that reports where a panic happened but not its message.
/// `RustLib.init()` calls it; the app never does. The hook covers every panic in the process.
#[frb(init)]
pub fn init_app() {
    guard_or("init_app", (), || {
        randomize_crypto_context();
        install_panic_hook();
    });
}

/// Without OS randomness the context stays unblinded, which changes no result; a wallet call
/// that needs randomness then fails on its own.
fn randomize_crypto_context() {
    if let Ok(mut rng) = StdRng::try_from_rng(&mut getrandom::SysRng) {
        lepic_wallet::randomize_crypto_context(&mut rng);
    }
}

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
    pub(crate) pin: PinGuard,
    open: Mutex<BTreeSet<PathBuf>>,
    /// The in-process relay Epicbox connections go to in Rust tests.
    #[cfg(test)]
    pub(crate) relay: Option<Arc<dyn lepic_epicbox::Connector>>,
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
            Self::start(
                log_level,
                NodeFactory::Http,
                KdfParams::DEFAULT,
                PinPolicy::DEFAULT,
            )
        })
    }

    pub(crate) fn start(
        log_level: LogLevel,
        nodes: NodeFactory,
        kdf: KdfParams,
        pin: PinPolicy,
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
                pin: PinGuard::new(pin),
                open: Mutex::default(),
                #[cfg(test)]
                relay: None,
            }),
        })
    }

    /// Sends every log record from now on to `sink`, replacing the stream subscribed before.
    pub fn logs(&self, sink: StreamSink<LogEntry>) {
        self.inner
            .boundary
            .guard_or("logs", (), || self.inner.logs.replace(Some(sink)));
    }

    /// Ends the stream from [`LepicRuntime::logs`]. Cancelling the Dart subscription completes
    /// only once the stream has ended.
    #[frb(sync)]
    pub fn stop_logs(&self) {
        self.inner
            .boundary
            .guard_or("stop_logs", (), || self.inner.logs.replace(None));
    }

    /// Logs one line from the app under the target `dart.<tag>`, through the same stream.
    /// `tag` keeps only ASCII letters, digits and `_`, at most 32 of them, and `message` at
    /// most its first 1024 bytes, cut at a character boundary. Never pass secrets.
    #[frb(sync)]
    pub fn log_message(&self, level: LogLevel, tag: String, message: String) {
        self.inner.boundary.guard_or("log_message", (), || {
            let tag: String = tag
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(32)
                .collect();
            let message = app_log_message(&message);
            match level {
                LogLevel::Error => error!(target: "dart", tag, "{message}"),
                LogLevel::Warn => warn!(target: "dart", tag, "{message}"),
                LogLevel::Info => info!(target: "dart", tag, "{message}"),
                LogLevel::Debug => tracing::debug!(target: "dart", tag, "{message}"),
                LogLevel::Trace => tracing::trace!(target: "dart", tag, "{message}"),
            }
        });
    }
}

/// The longest app log message kept, in bytes, so one call cannot flood the log stream.
const MAX_APP_LOG_MESSAGE_LEN: usize = 1024;

fn app_log_message(message: &str) -> &str {
    message
        .get(..message.floor_char_boundary(MAX_APP_LOG_MESSAGE_LEN))
        .unwrap_or_default()
}

impl RuntimeInner {
    /// Marks `data_dir` as in use until the returned claim is dropped. Fails with
    /// [`WalletErrorKind::WalletBusy`] when it already is, in this runtime or any other.
    pub(crate) fn claim(self: &Arc<Self>, data_dir: &Path) -> Result<DirClaim, WalletError> {
        let dir = std::fs::canonicalize(data_dir).map_err(|error| {
            WalletError::new(
                WalletErrorKind::Io,
                format!("wallet directory is not usable: {error}"),
            )
        })?;
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        if open.contains(&dir) {
            return Err(busy());
        }
        let lock = lock_dir(&dir)?;
        open.insert(dir.clone());
        Ok(DirClaim {
            runtime: Arc::clone(self),
            dir,
            _lock: lock,
        })
    }
}

fn busy() -> WalletError {
    WalletError::new(
        WalletErrorKind::WalletBusy,
        "a wallet on this directory is open",
    )
}

/// An exclusive OS lock on `LOCK_FILE` in `dir`, so other runtimes and processes cannot open
/// the directory's database at the same time. Released when the file is closed.
fn lock_dir(dir: &Path) -> Result<std::fs::File, WalletError> {
    let file = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE))
        .map_err(|error| {
            WalletError::new(
                WalletErrorKind::Io,
                format!("wallet directory lock is not usable: {error}"),
            )
        })?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(busy()),
        Err(std::fs::TryLockError::Error(error)) => Err(WalletError::new(
            WalletErrorKind::Io,
            format!("wallet directory could not be locked: {error}"),
        )),
    }
}

/// The file in a data directory that holds the directory lock. It stays when the lock is
/// released: removing it would let two openers lock different files.
const LOCK_FILE: &str = ".lepic.lock";

/// A data directory a wallet or a deletion is using.
pub(crate) struct DirClaim {
    pub(crate) runtime: Arc<RuntimeInner>,
    pub(crate) dir: PathBuf,
    _lock: std::fs::File,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_log_messages_are_cut_at_a_character_boundary() {
        assert_eq!(app_log_message("short"), "short");
        let long = "x".repeat(MAX_APP_LOG_MESSAGE_LEN + 1);
        assert_eq!(app_log_message(&long).len(), MAX_APP_LOG_MESSAGE_LEN);
        // A two-byte character across the limit is dropped whole.
        let straddling = format!("{}é", "x".repeat(MAX_APP_LOG_MESSAGE_LEN - 1));
        assert_eq!(
            app_log_message(&straddling),
            &straddling[..MAX_APP_LOG_MESSAGE_LEN - 1]
        );
    }
}
