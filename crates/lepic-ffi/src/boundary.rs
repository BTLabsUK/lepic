//! Where Dart calls enter the engine: every operation runs as a task on the runtime's Tokio
//! runtime, under the runtime's log subscriber, and a panic in it becomes an error instead of
//! unwinding into Dart.

use std::any::Any;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};

use tokio::runtime::Handle;
use tracing::instrument::WithSubscriber as _;
use tracing::{Dispatch, error};

use crate::api::error::{WalletError, WalletErrorKind};

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
        match self
            .handle
            .spawn(work.with_subscriber(dispatch.clone()))
            .await
        {
            Ok(result) => result,
            Err(join) if join.is_panic() => {
                tracing::dispatcher::with_default(&dispatch, || {
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

fn panicked(operation: &'static str) -> WalletError {
    WalletError::new(
        WalletErrorKind::Panic,
        format!("{operation} failed inside lepic"),
    )
}
