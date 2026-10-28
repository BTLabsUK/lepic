// SPDX-License-Identifier: Apache-2.0
//! Stopping LEPIC at a persistence point. Every store write of the engine is one persistence
//! point: a `write` either leaves everything or nothing behind. A [`FaultyStore`] armed with a
//! [`CrashPoint`] lets the first writes commit and then behaves as a process that stopped: the
//! write at the crash point fails, and so does every later read and write, until the wallet is
//! reopened on a fresh handle.

use std::sync::{Arc, Mutex, PoisonError};

use lepic_store::{MemoryStore, Repositories, StoreError, WalletStore};

/// Where a step stops: after `commits` of its writes are durable. Zero stops it at its first
/// write, before anything is stored; `n` stops it right after its `n`-th write committed, before
/// whatever the step does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashPoint {
    pub commits: u32,
}

#[derive(Debug, Default)]
struct Plan {
    armed: Option<CrashPoint>,
    writes: u32,
    stopped: bool,
}

/// The crash plan the store handles of one wallet share.
#[derive(Debug, Clone, Default)]
pub struct Faults(Arc<Mutex<Plan>>);

impl Faults {
    /// Stops the wallet at `point` of the writes that follow.
    pub fn arm(&self, point: CrashPoint) {
        *self.plan() = Plan {
            armed: Some(point),
            writes: 0,
            stopped: false,
        };
    }

    /// Clears the plan. Returns whether the wallet stopped since [`Faults::arm`].
    pub fn disarm(&self) -> bool {
        std::mem::take(&mut *self.plan()).stopped
    }

    fn plan(&self) -> std::sync::MutexGuard<'_, Plan> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the next write does.
    fn next_write(&self) -> Write {
        let mut plan = self.plan();
        if plan.stopped {
            return Write::Refuse;
        }
        let Some(point) = plan.armed else {
            return Write::Proceed;
        };
        plan.writes = plan.writes.saturating_add(1);
        if plan.writes < point.commits.max(1) {
            return Write::Proceed;
        }
        plan.stopped = true;
        if point.commits == 0 {
            Write::Refuse
        } else {
            Write::CommitThenStop
        }
    }

    fn stopped(&self) -> bool {
        self.plan().stopped
    }
}

enum Write {
    Proceed,
    CommitThenStop,
    Refuse,
}

/// A memory store handle that obeys a crash plan.
pub struct FaultyStore {
    pub inner: MemoryStore,
    pub faults: Faults,
}

/// What a stopped process returns for every store call; the engine passes it up as a store
/// failure and does nothing after it.
fn stopped() -> StoreError {
    StoreError::Poisoned
}

impl WalletStore for FaultyStore {
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        if self.faults.stopped() {
            return Err(stopped().into());
        }
        self.inner.read(operation)
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        match self.faults.next_write() {
            Write::Proceed => self.inner.write(operation),
            Write::CommitThenStop => {
                self.inner.write(operation)?;
                Err(stopped().into())
            }
            Write::Refuse => Err(stopped().into()),
        }
    }
}
