//! The runtime the app creates once: the threads LEPIC works on, its log stream, and the
//! registry of open wallets.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use flutter_rust_bridge::frb;
use lepic_keychain::KdfParams;
use lepic_telemetry::{ErrorChain, LogFilter, LogRing, LogRingError, LogRingLimit, host_dispatch};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tokio::runtime::Runtime;
use tracing::{error, info, warn};

use crate::api::diagnostics::{LogEntry, LogLevel};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::boundary::{Boundary, end_stream, guard, guard_or, install_panic_hook};
use crate::frb_generated::StreamSink;
use crate::log::LogForwarder;
use crate::node::NodeFactory;
use crate::pin::{PinGuard, PinPolicy};

/// Sets up the library once per process: blinds the secp256k1 context before any wallet uses
/// it, and installs a panic hook that reports where a panic happened but not its message.
/// `RustLib.init()` calls it; the app never does. The hook covers every panic in the process
/// and replaces any hook installed before, which is not called, since it might print the
/// message.
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
    /// Signalled whenever a claim in this runtime is released, so a claim waiting on the
    /// directory tries again at once.
    released: tokio::sync::Notify,
    /// The in-process relay Epicbox connections go to in tests.
    #[cfg(feature = "mock")]
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
                released: tokio::sync::Notify::new(),
                #[cfg(feature = "mock")]
                relay: None,
            }),
        })
    }

    /// Sends every log record from now on to `sink`, replacing the stream subscribed before.
    /// A failure to subscribe, which only a defect inside LEPIC causes, ends the stream with a
    /// `Panic` [`WalletError`] as its error.
    pub fn logs(&self, sink: StreamSink<LogEntry>) {
        let failed = sink.clone();
        let subscribed = self.inner.boundary.guard("logs", || {
            self.inner.logs.replace(Some(sink));
            Ok(())
        });
        end_stream(&failed, subscribed);
    }

    /// Ends the stream from [`LepicRuntime::logs`]. Cancelling the Dart subscription completes
    /// only once the stream has ended.
    #[frb(sync)]
    pub fn stop_logs(&self) {
        self.inner
            .boundary
            .guard_or("stop_logs", (), || self.inner.logs.replace(None));
    }

    /// Keeps every log record from now on, redacted, in a ring of files in `dir` of at most
    /// `max_bytes` together, and keeps the records a ring in `dir` already holds. Records reach
    /// it at the runtime's log level, whether or not a [`LepicRuntime::logs`] stream is
    /// subscribed. Replaces the ring opened before. `dir` should hold nothing else.
    ///
    /// Only the values of the fields in the LEPIC log vocabulary that say nothing about keys,
    /// amounts or addresses are kept; every other value is written as `[redacted]`, as is text
    /// quoted inside an `error` value. Messages are kept, including those of
    /// [`LepicRuntime::log_message`].
    ///
    /// Fails with `InvalidArgument` when `max_bytes` is below 4 KiB or above 16 MiB, and `Io`
    /// when the directory cannot be created or read.
    pub fn open_log_ring(&self, dir: String, max_bytes: u64) -> Result<(), WalletError> {
        self.inner.boundary.guard("open_log_ring", || {
            if max_bytes > MAX_LOG_RING_BYTES {
                return Err(WalletError::new(
                    WalletErrorKind::InvalidArgument,
                    format!("log ring limit is above {MAX_LOG_RING_BYTES} bytes"),
                ));
            }
            let limit = LogRingLimit::new(max_bytes).map_err(|error| {
                WalletError::new(WalletErrorKind::InvalidArgument, error.to_string())
            })?;
            let ring = LogRing::open(dir, limit).map_err(|error| log_ring_error(&error))?;
            self.inner.logs.replace_ring(Some(Arc::new(ring)));
            Ok(())
        })
    }

    /// The redacted support bundle of the ring from [`LepicRuntime::open_log_ring`]: a short
    /// header, then its records oldest first, one per line. Records logged meanwhile wait.
    ///
    /// Fails with `InvalidArgument` when no ring is open and `Io` when it cannot be read.
    pub fn export_support_bundle(&self) -> Result<String, WalletError> {
        self.inner.boundary.guard("export_support_bundle", || {
            let ring = self.inner.logs.ring().ok_or_else(|| {
                WalletError::new(WalletErrorKind::InvalidArgument, "no log ring is open")
            })?;
            ring.support_bundle()
                .map_err(|error| log_ring_error(&error))
        })
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

/// The largest log ring [`LepicRuntime::open_log_ring`] accepts, so one export stays a size a
/// phone can hold twice, in Rust and in Dart.
const MAX_LOG_RING_BYTES: u64 = 16 * 1024 * 1024;

fn log_ring_error(error: &LogRingError) -> WalletError {
    WalletError::new(WalletErrorKind::Io, ErrorChain(error).to_string())
}

/// The longest app log message kept, in bytes, so one call cannot flood the log stream.
const MAX_APP_LOG_MESSAGE_LEN: usize = 1024;

fn app_log_message(message: &str) -> &str {
    message
        .get(..message.floor_char_boundary(MAX_APP_LOG_MESSAGE_LEN))
        .unwrap_or_default()
}

impl RuntimeInner {
    /// Marks `data_dir` as in use until the returned claim is dropped. A directory in use, in
    /// this runtime or any other, is waited for up to [`CLAIM_WAIT`]: a wallet just locked on
    /// it releases it once the call still running on it has finished its store write. A
    /// release in this runtime wakes the wait at once; one elsewhere is seen at the next try,
    /// every [`CLAIM_RETRY_WAIT`]. Fails with [`WalletErrorKind::WalletBusy`] when the
    /// directory is still in use after the wait.
    pub(crate) async fn claim(self: &Arc<Self>, data_dir: &Path) -> Result<DirClaim, WalletError> {
        let dir = std::fs::canonicalize(data_dir).map_err(|error| {
            WalletError::new(
                WalletErrorKind::Io,
                format!("wallet directory is not usable: {error}"),
            )
        })?;
        let deadline = tokio::time::Instant::now().checked_add(CLAIM_WAIT);
        loop {
            // Listening before the try, so a release between the try and the wait is not
            // missed.
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            match self.try_claim(&dir) {
                Err(error) if error.kind == WalletErrorKind::WalletBusy => {
                    let now = tokio::time::Instant::now();
                    let Some(deadline) = deadline.filter(|deadline| *deadline > now) else {
                        return Err(error);
                    };
                    let wait = deadline
                        .saturating_duration_since(now)
                        .min(CLAIM_RETRY_WAIT);
                    // Timing out only means a release elsewhere is looked for.
                    drop(tokio::time::timeout(wait, released).await);
                }
                claimed => return claimed,
            }
        }
    }

    fn try_claim(self: &Arc<Self>, dir: &Path) -> Result<DirClaim, WalletError> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        if open.contains(dir) {
            return Err(busy());
        }
        let lock = lock_dir(dir)?;
        open.insert(dir.to_path_buf());
        Ok(DirClaim {
            runtime: Arc::clone(self),
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }
}

/// How long a busy directory is waited for, long enough for a wallet just locked on it to
/// finish the store write under way on a slow phone, and how often a release in another
/// runtime or process is looked for meanwhile.
const CLAIM_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
const CLAIM_RETRY_WAIT: std::time::Duration = std::time::Duration::from_millis(50);

fn busy() -> WalletError {
    WalletError::new(
        WalletErrorKind::WalletBusy,
        "a wallet on this directory is open",
    )
}

/// An exclusive OS lock on `LOCK_FILE` in `dir`, so other runtimes and processes cannot open
/// the directory's database at the same time. Released when the file is closed. A symbolic link
/// in place of the lock file is refused rather than followed, as the CLI refuses it. The file
/// is opened close-on-exec, as the standard library opens every file, so a child process the
/// app starts does not inherit the lock.
fn lock_dir(dir: &Path) -> Result<std::fs::File, WalletError> {
    let mut options = std::fs::File::options();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(lepic_transport::file::O_NOFOLLOW);
    }
    let file = options.open(dir.join(LOCK_FILE)).map_err(|error| {
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
        self.runtime.released.notify_waiters();
    }
}

/// A session's claim on its directory. The session holds it from its first check until it
/// is dropped, except that after the session is locked on purpose the claim goes as soon as
/// the database opened under it closes: at the lock when nothing runs, else when the last
/// call still running ends. A new open on the directory then needs no dispose of the old
/// handle first.
pub(crate) struct ClaimHolder {
    claim: Mutex<Option<DirClaim>>,
    release_on_close: std::sync::atomic::AtomicBool,
    /// How long every store write is stretched in tests, as a slow phone stretches it.
    #[cfg(test)]
    write_delay: Mutex<Option<std::time::Duration>>,
    #[cfg(test)]
    writes_begun: std::sync::atomic::AtomicU32,
}

impl ClaimHolder {
    pub(crate) fn new(claim: DirClaim) -> Arc<Self> {
        Arc::new(Self {
            claim: Mutex::new(Some(claim)),
            release_on_close: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            write_delay: Mutex::default(),
            #[cfg(test)]
            writes_begun: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// Stretches every store write from now on by `delay`, on the blocking thread that runs it.
    #[cfg(test)]
    pub(crate) fn delay_writes(&self, delay: std::time::Duration) {
        *self
            .write_delay
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(delay);
    }

    /// Store writes begun so far, counted before any delay.
    #[cfg(test)]
    pub(crate) fn writes_begun(&self) -> u32 {
        self.writes_begun.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    fn write_begins(&self) {
        self.writes_begun
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let delay = *self
            .write_delay
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
    }

    /// From now on the claim goes with the database. Call it before the wallet locks, so a
    /// database that closes at the lock releases it.
    pub(crate) fn release_when_closed(&self) {
        self.release_on_close
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn database_closed(&self) {
        if self
            .release_on_close
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.claim
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_held(&self) -> bool {
        self.claim
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

/// The engine's store opener for a session: the SQLite store, which tells the session's
/// [`ClaimHolder`] when it closes.
pub(crate) struct ClaimedStores(pub(crate) Arc<ClaimHolder>);

impl lepic_wallet::StoreOpener for ClaimedStores {
    type Store = ClaimedStore;

    fn open(
        &self,
        data_dir: &Path,
        key: lepic_store::ContextKey,
    ) -> Result<ClaimedStore, lepic_store::StoreError> {
        Ok(ClaimedStore::new(
            lepic_wallet::SqliteStores.open(data_dir, key)?,
            &self.0,
        ))
    }
}

/// A store that tells its session's [`ClaimHolder`] when it closes. Fields drop in order:
/// the store closes its database before `closed` reports it, so the directory is never
/// released while the database is still open.
pub(crate) struct ClaimedStore<S = lepic_store::SqliteStore> {
    inner: S,
    _closed: ReportsClosed,
}

impl<S> ClaimedStore<S> {
    fn new(inner: S, holder: &Arc<ClaimHolder>) -> Self {
        Self {
            inner,
            _closed: ReportsClosed(Arc::clone(holder)),
        }
    }
}

struct ReportsClosed(Arc<ClaimHolder>);

impl Drop for ReportsClosed {
    fn drop(&mut self) {
        self.0.database_closed();
    }
}

impl<S: lepic_store::WalletStore> lepic_store::WalletStore for ClaimedStore<S> {
    fn read<R, E>(
        &self,
        operation: impl FnOnce(&dyn lepic_store::Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<lepic_store::StoreError>,
    {
        self.inner.read(operation)
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn lepic_store::Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<lepic_store::StoreError>,
    {
        #[cfg(test)]
        self._closed.0.write_begins();
        self.inner.write(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lock file's descriptor is close-on-exec, read from its open-file description.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_directory_lock_is_not_inherited_by_child_processes() {
        use std::os::fd::AsRawFd as _;

        const O_CLOEXEC: u32 = 0o2000000;
        let dir = tempfile::tempdir().unwrap();
        let file = lock_dir(dir.path()).unwrap();
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .map(|flags| u32::from_str_radix(flags.trim(), 8).unwrap())
            .unwrap();
        assert_eq!(flags & O_CLOEXEC, O_CLOEXEC, "{info}");
    }

    fn new_runtime() -> LepicRuntime {
        crate::api::testing::MockChain::new(1)
            .unwrap()
            .runtime(LogLevel::Warn)
            .unwrap()
    }

    /// A directory another runtime releases well after the old 50 ms of retries, as a
    /// wallet locked during a slow store write releases it, is claimed once it is free. Time
    /// is paused, so the waits take no real time and the elapsed time is exact.
    #[tokio::test(start_paused = true)]
    async fn a_directory_released_elsewhere_within_the_wait_is_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = new_runtime();
        let other = new_runtime();
        let held = other.inner.claim(dir.path()).await.unwrap();
        let release_after = std::time::Duration::from_millis(307);
        let releasing = tokio::spawn(async move {
            tokio::time::sleep(release_after).await;
            drop(held);
        });

        let started = tokio::time::Instant::now();
        let claimed = runtime.inner.claim(dir.path()).await;

        releasing.await.unwrap();
        assert!(claimed.is_ok(), "{:?}", claimed.err());
        let waited = started.elapsed();
        assert!(waited >= release_after, "{waited:?}");
        assert!(waited <= release_after + CLAIM_RETRY_WAIT, "{waited:?}");
    }

    /// A release in the same runtime wakes the wait at once, without a retry interval.
    #[tokio::test(start_paused = true)]
    async fn a_directory_released_in_the_same_runtime_is_claimed_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = new_runtime();
        let held = runtime.inner.claim(dir.path()).await.unwrap();
        let release_after = std::time::Duration::from_millis(107);
        let releasing = tokio::spawn(async move {
            tokio::time::sleep(release_after).await;
            drop(held);
        });

        let started = tokio::time::Instant::now();
        let claimed = runtime.inner.claim(dir.path()).await;

        releasing.await.unwrap();
        assert!(claimed.is_ok(), "{:?}", claimed.err());
        assert_eq!(started.elapsed(), release_after);
    }

    #[tokio::test(start_paused = true)]
    async fn a_directory_still_in_use_after_the_wait_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = new_runtime();
        let _held = runtime.inner.claim(dir.path()).await.unwrap();

        let started = tokio::time::Instant::now();
        let busy = runtime.inner.claim(dir.path()).await.map(drop);

        assert_eq!(busy.unwrap_err().kind, WalletErrorKind::WalletBusy);
        assert_eq!(started.elapsed(), CLAIM_WAIT);
    }

    /// A store that records, as it closes, whether the directory is still claimed.
    struct ClosingStore {
        inner: lepic_store::MemoryStore,
        holder: Arc<ClaimHolder>,
        held_while_closing: Arc<Mutex<Option<bool>>>,
    }

    impl Drop for ClosingStore {
        fn drop(&mut self) {
            *self.held_while_closing.lock().unwrap() = Some(self.holder.is_held());
        }
    }

    impl lepic_store::WalletStore for ClosingStore {
        fn read<R, E>(
            &self,
            operation: impl FnOnce(&dyn lepic_store::Repositories) -> Result<R, E>,
        ) -> Result<R, E>
        where
            E: From<lepic_store::StoreError>,
        {
            self.inner.read(operation)
        }

        fn write<R, E>(
            &self,
            operation: impl FnOnce(&mut dyn lepic_store::Repositories) -> Result<R, E>,
        ) -> Result<R, E>
        where
            E: From<lepic_store::StoreError>,
        {
            self.inner.write(operation)
        }
    }

    /// The database closes before the directory is released, so a new open never finds it
    /// still open.
    #[tokio::test]
    async fn a_locked_session_closes_its_database_before_it_releases_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = new_runtime();
        let holder = ClaimHolder::new(runtime.inner.claim(dir.path()).await.unwrap());
        let held_while_closing = Arc::new(Mutex::new(None));
        let store = ClaimedStore::new(
            ClosingStore {
                inner: lepic_store::MemoryStore::new(lepic_store::ContextKey::from_bytes(
                    [2; lepic_store::CONTEXT_KEY_LEN],
                )),
                holder: Arc::clone(&holder),
                held_while_closing: Arc::clone(&held_while_closing),
            },
            &holder,
        );
        holder.release_when_closed();

        drop(store);

        assert_eq!(*held_while_closing.lock().unwrap(), Some(true));
        assert!(!holder.is_held());
    }

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

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_in_place_of_the_lock_file_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = elsewhere.path().join("created-through-the-link");
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).unwrap();

        let error = lock_dir(dir.path()).unwrap_err();
        assert_eq!(error.kind, WalletErrorKind::Io);
        assert!(!target.exists(), "the lock followed the link");
    }

    #[test]
    fn a_locked_directory_is_busy_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock_dir(dir.path()).unwrap();
        assert_eq!(
            lock_dir(dir.path()).unwrap_err().kind,
            WalletErrorKind::WalletBusy
        );
        drop(held);
        assert!(lock_dir(dir.path()).is_ok());
    }
}
