// SPDX-License-Identifier: Apache-2.0
//! Where Dart calls enter the engine: every operation runs as a task on the runtime's Tokio
//! runtime, under the runtime's log subscriber, and a panic in it becomes an error instead of
//! unwinding into Dart.

use std::any::Any;
use std::future::Future;
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, Location, catch_unwind};
use std::sync::Arc;

use tokio::runtime::Handle;
use tracing::instrument::WithSubscriber as _;
use tracing::{Dispatch, error};

use lepic_wallet::inbox::ListenHandle;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{ListenerEvent, ListenerEventKind};
use crate::frb_generated::{SseEncode, StreamSink};
use crate::session::Session;

/// What an operation runs with.
#[derive(Clone)]
pub(crate) struct Boundary {
    pub(crate) handle: Handle,
    pub(crate) dispatch: Dispatch,
}

impl Boundary {
    /// Runs `work` to completion on the runtime. The task keeps running if the Dart future is
    /// dropped, so a store write is never cut in half.
    pub(crate) async fn run<T, F>(&self, operation: &'static str, work: F) -> Result<T, WalletError>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, WalletError>> + Send + 'static,
    {
        let dispatch = self.dispatch.clone();
        let task = self.handle.spawn(work.with_subscriber(dispatch.clone()));
        self.finish(operation, task, &dispatch).await
    }

    /// [`Boundary::run`], with the task listed in `in_flight` until it ends, so
    /// [`InFlight::abort_all`] can end it early: at an await, never inside a store write,
    /// which runs to its end on the blocking pool.
    pub(crate) async fn run_tracked<T, F>(
        &self,
        operation: &'static str,
        work: F,
        in_flight: &Arc<InFlight>,
    ) -> Result<T, WalletError>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, WalletError>> + Send + 'static,
    {
        let dispatch = self.dispatch.clone();
        let ends = in_flight.starts();
        let id = ends.id;
        let task = self.handle.spawn(
            async move {
                let _ends = ends;
                work.await
            }
            .with_subscriber(dispatch.clone()),
        );
        in_flight.started(id, task.abort_handle());
        self.finish(operation, task, &dispatch).await
    }

    async fn finish<T>(
        &self,
        operation: &'static str,
        task: tokio::task::JoinHandle<Result<T, WalletError>>,
        dispatch: &Dispatch,
    ) -> Result<T, WalletError> {
        match task.await {
            Ok(result) => result,
            Err(join) if join.is_panic() => {
                tracing::dispatcher::with_default(dispatch, || {
                    error!(operation, "operation panicked");
                });
                Err(panicked(operation))
            }
            Err(_) => Err(WalletError::new(
                WalletErrorKind::Cancelled,
                format!("{operation} was cancelled"),
            )),
        }
    }

    /// [`guard_or`] under the runtime's log subscriber.
    pub(crate) fn guard_or<T>(
        &self,
        operation: &'static str,
        fallback: T,
        work: impl FnOnce() -> T,
    ) -> T {
        tracing::dispatcher::with_default(&self.dispatch, || guard_or(operation, fallback, work))
    }

    /// [`guard`] under the runtime's log subscriber.
    pub(crate) fn guard<T>(
        &self,
        operation: &'static str,
        work: impl FnOnce() -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        tracing::dispatcher::with_default(&self.dispatch, || guard(operation, work))
    }
}

/// The calls running on a wallet handle, so a lock can end them. A call is listed before it
/// starts and leaves when it ends, whether or not its Dart future is still awaited.
#[derive(Default)]
pub(crate) struct InFlight {
    /// Each running call by id.
    tasks: std::sync::Mutex<std::collections::HashMap<u64, Call>>,
    next: std::sync::atomic::AtomicU64,
}

/// Where a listed call is. Both [`InFlight::started`] and [`InFlight::abort_all`] change it
/// under the list's lock, so whichever comes second ends the task: an abort that finds a call
/// still `Starting` marks it `Aborted`, and its handle is aborted the moment it arrives.
enum Call {
    /// Spawned or about to be, its abort handle not given yet.
    Starting,
    Running(tokio::task::AbortHandle),
    /// Ended by [`InFlight::abort_all`], or to be once its handle arrives.
    Aborted,
}

impl InFlight {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<u64, Call>> {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lists a call about to start and gives what its task drops when it ends, to leave the
    /// list.
    fn starts(self: &Arc<Self>) -> Ends {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.lock().insert(id, Call::Starting);
        Ends {
            in_flight: Arc::clone(self),
            id,
        }
    }

    /// Gives a listed call its abort handle, or aborts the task at once when a lock came
    /// between its spawn and now. A call that already ended is not listed any more.
    fn started(&self, id: u64, handle: tokio::task::AbortHandle) {
        // Aborted after the list's lock is let go, as `abort_all` does.
        let aborted = match self.lock().get_mut(&id) {
            Some(Call::Aborted) => Some(handle),
            Some(call) => {
                *call = Call::Running(handle);
                None
            }
            None => None,
        };
        if let Some(handle) = aborted {
            handle.abort();
        }
    }

    /// Ends every listed call, also one whose task has no abort handle yet. Each fails for its
    /// caller with `Cancelled`. Calls listed after it are not touched.
    pub(crate) fn abort_all(&self) {
        let handles: Vec<_> = self
            .lock()
            .values_mut()
            .filter_map(|call| match std::mem::replace(call, Call::Aborted) {
                Call::Running(handle) => Some(handle),
                Call::Starting | Call::Aborted => None,
            })
            .collect();
        for handle in handles {
            handle.abort();
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

struct Ends {
    in_flight: Arc<InFlight>,
    id: u64,
}

impl Drop for Ends {
    fn drop(&mut self) {
        self.in_flight.lock().remove(&self.id);
    }
}

/// Runs `work`, turning a panic into an error. The panic payload is not reported: it is text
/// from inside LEPIC that no test has checked for secrets. Every synchronous API function runs
/// its body through this or [`guard_or`], since flutter_rust_bridge would hand the payload to
/// Dart.
pub(crate) fn guard<T>(
    operation: &'static str,
    work: impl FnOnce() -> Result<T, WalletError>,
) -> Result<T, WalletError> {
    catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|payload: Box<dyn Any + Send>| {
        drop(payload);
        error!(operation, "operation panicked");
        Err(panicked(operation))
    })
}

/// [`guard`] for a call with no error to return: after a panic it returns `fallback`.
pub(crate) fn guard_or<T>(operation: &'static str, fallback: T, work: impl FnOnce() -> T) -> T {
    guard(operation, || Ok(work())).unwrap_or(fallback)
}

/// Hands a stream call's failure to its stream, which ends the Dart stream with that error.
/// Stream calls return nothing to Dart: the generated code does not await them, so an error
/// they returned would reach the app's zone instead of the stream.
pub(crate) fn end_stream<T: SseEncode>(sink: &StreamSink<T>, result: Result<(), WalletError>) {
    if let Err(error) = result {
        // A closed stream only means the app stopped listening.
        let _ = sink.add_error(error);
    }
}

/// Runs the listener of `session` on the runtime until `handle` is stopped, and streams what it
/// does to `events`. A listener that fails reports an `Error` event, and the last event is
/// always `Stopped`.
pub(crate) fn spawn_listener(
    boundary: &Boundary,
    session: Arc<Session>,
    handle: ListenHandle,
    events: StreamSink<ListenerEvent>,
) {
    let runner = boundary.clone();
    boundary.handle.spawn(async move {
        let sink = events.clone();
        let listening = runner
            .run("listen", async move {
                // A closed stream only means the app stopped listening.
                let report = |event| drop(sink.add(event));
                session.listen(&handle, report).await
            })
            .await;
        if let Err(error) = listening {
            let _ = events.add(listener_event(ListenerEventKind::Error, error.to_string()));
        }
        let _ = events.add(listener_event(ListenerEventKind::Stopped, String::new()));
    });
}

/// A listener event that carries no transaction, slate or retry.
fn listener_event(kind: ListenerEventKind, message: String) -> ListenerEvent {
    ListenerEvent {
        kind,
        tx_id: None,
        slate_id: None,
        message,
        reason: None,
        retry_in_ms: None,
    }
}

/// Replaces the process's panic hook with one that reports where a panic happened but not its
/// payload, for the reason [`guard`] drops it. The default hook would print the payload to
/// stderr, which the platform may keep in its logs. Installing it again changes nothing.
///
/// The hook installed before is dropped, not called: every hook receives the payload, and an
/// earlier one, the default hook included, may print it. Code in the same process that needs
/// its own hook installs it after `RustLib.init()` and must not print payloads either.
pub(crate) fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        // Nothing is left to tell when stderr is closed.
        let _ = writeln!(std::io::stderr(), "{}", panic_report(info.location()));
    }));
}

fn panic_report(location: Option<&Location<'_>>) -> String {
    match location {
        Some(location) => format!(
            "lepic panicked at {}:{}:{}",
            source_path(location.file()),
            location.line(),
            location.column()
        ),
        None => "lepic panicked".to_owned(),
    }
}

/// `file` without the build machine's directories, which would put a home directory or CI
/// workspace into the platform log. Workspace files are already relative; a dependency keeps its
/// path from the package directory on, for example `tokio-1.0.0/src/runtime.rs`.
fn source_path(file: &str) -> &str {
    let is_absolute = file.starts_with(['/', '\\']) || file.get(1..3) == Some(":\\");
    if !is_absolute {
        return file;
    }
    let normalized = file.replace('\\', "/");
    for marker in ["/registry/src/", "/git/checkouts/"] {
        if let Some(start) = normalized.rfind(marker) {
            // Skip the registry or checkout directory that follows the marker.
            let after_marker = start.saturating_add(marker.len());
            if let Some(package) = normalized
                .get(after_marker..)
                .and_then(|rest| rest.find('/'))
                .map(|slash| after_marker.saturating_add(slash).saturating_add(1))
            {
                return file.get(package..).unwrap_or_default();
            }
        }
    }
    file.rsplit(['/', '\\']).next().unwrap_or_default()
}

fn panicked(operation: &'static str) -> WalletError {
    WalletError::new(
        WalletErrorKind::Panic,
        format!("{operation} failed inside lepic"),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{InFlight, source_path};

    #[tokio::test]
    async fn a_lock_between_spawn_and_started_still_ends_the_call() {
        let in_flight = Arc::new(InFlight::default());
        let ends = in_flight.starts();
        let id = ends.id;
        let task = tokio::spawn(async move {
            let _ends = ends;
            std::future::pending::<()>().await;
        });

        in_flight.abort_all();
        in_flight.started(id, task.abort_handle());

        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(in_flight.len(), 0);
        // A call listed after the lock runs.
        let ends = in_flight.starts();
        let id = ends.id;
        let task = tokio::spawn(async move {
            let _ends = ends;
        });
        in_flight.started(id, task.abort_handle());
        assert!(task.await.is_ok());
    }

    #[test]
    fn panic_locations_leave_out_the_build_machine_directories() {
        assert_eq!(
            source_path("crates/lepic-ffi/src/mock.rs"),
            "crates/lepic-ffi/src/mock.rs"
        );
        assert_eq!(
            source_path(
                "/home/dev/.cargo/registry/src/index.registry.example-1949cf8c6b5b557f/tokio-1.0.0/src/lib.rs"
            ),
            "tokio-1.0.0/src/lib.rs"
        );
        assert_eq!(
            source_path(
                "/home/dev/.cargo/git/checkouts/rust-secp256k1-zkp-0123/42fcb29/src/key.rs"
            ),
            "42fcb29/src/key.rs"
        );
        assert_eq!(
            source_path(
                r"C:\Users\dev\.cargo\registry\src\index.registry.example-1949\ring-0.17.0\src\a.rs"
            ),
            r"ring-0.17.0\src\a.rs"
        );
        assert_eq!(source_path("/home/dev/work/lepic/build.rs"), "build.rs");
        assert_eq!(
            source_path("/rustc/0123abcd/library/core/src/option.rs"),
            "option.rs"
        );
    }
}
