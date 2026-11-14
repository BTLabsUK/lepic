// SPDX-License-Identifier: Apache-2.0
//! The session's work counters, kept in atomics so that a reader never waits for the session.

use std::sync::atomic::{AtomicU64, Ordering};

use super::MuxCounters;

#[derive(Debug, Default)]
pub(super) struct CounterCells {
    pub(super) sockets_opened: AtomicU64,
    pub(super) signatures: AtomicU64,
    pub(super) attaches: AtomicU64,
    pub(super) resumes: AtomicU64,
    pub(super) token_unknown: AtomicU64,
    pub(super) mails: AtomicU64,
    pub(super) duplicates: AtomicU64,
    pub(super) acks: AtomicU64,
    pub(super) holds: AtomicU64,
    pub(super) waiting_probes: AtomicU64,
    pub(super) stall_reconnects: AtomicU64,
}

pub(super) fn bump(cell: &AtomicU64) {
    cell.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn add(cell: &AtomicU64, count: usize) {
    cell.fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
}

impl CounterCells {
    pub(super) fn snapshot(&self) -> MuxCounters {
        let read = |cell: &AtomicU64| cell.load(Ordering::Relaxed);
        MuxCounters {
            sockets_opened: read(&self.sockets_opened),
            signatures: read(&self.signatures),
            attaches: read(&self.attaches),
            resumes: read(&self.resumes),
            token_unknown: read(&self.token_unknown),
            mails: read(&self.mails),
            duplicates: read(&self.duplicates),
            acks: read(&self.acks),
            holds: read(&self.holds),
            waiting_probes: read(&self.waiting_probes),
            stall_reconnects: read(&self.stall_reconnects),
        }
    }
}
