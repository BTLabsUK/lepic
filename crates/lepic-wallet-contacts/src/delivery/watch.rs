// SPDX-License-Identifier: Apache-2.0
//! The mailboxes the delivery layer watches: the rows of the watch set with the key each names,
//! and what a pass over the set did on each relay.

use lepic_epicbox::{Identity, MuxError};
use lepic_store::WatchRow;
use thiserror::Error;

use crate::ContactError;

/// The settings prefix of the replaced marks earlier builds stored, one per row whose mailbox
/// another socket of the same wallet took over. None is written now; reconcile deletes them.
pub(crate) const REPLACED_PREFIX: &str = "contact.replaced.";

/// Resolves the key reference of a watch row to the mailbox key it names.
pub(crate) trait MailboxKeys {
    /// The identity of the mailbox `row` names on its relay. [`Unresolved`] when the wallet
    /// holds no key by its reference.
    fn identity(&self, row: &WatchRow) -> Result<Identity, Unresolved>;

    /// The onion the relay of `row` is reached at over Tor, when its source names one.
    fn onion(&self, _row: &WatchRow) -> Option<String> {
        None
    }
}

/// A key reference that names no mailbox key the wallet holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the key reference names no mailbox key")]
pub(crate) struct Unresolved;

/// A watched mailbox: its row and the key the row names.
#[derive(Debug, Clone)]
pub(crate) struct Watched {
    pub(crate) row: WatchRow,
    pub(crate) identity: Identity,
}

/// What [`super::carrier::Carrier::claim`] did with a set.
#[derive(Debug, Default)]
pub(crate) struct WatchReport {
    /// Each relay of the set, as `domain:port`, in order. A relay whose rows were all skipped is
    /// not listed.
    pub(crate) relays: Vec<RelayWatch>,
    /// The rows not watched before any relay was asked.
    pub(crate) skipped: Vec<Skipped>,
    /// How many rows past their expiry the pass removed from the store.
    pub(crate) expired: usize,
}

/// The mailboxes of one relay.
#[derive(Debug)]
pub(crate) struct RelayWatch {
    /// The relay as `domain:port`.
    pub(crate) relay: String,
    /// How many mailboxes of the set are on it.
    pub(crate) mailboxes: usize,
    /// How many of its mailboxes a session claimed: attached, being attached, or to be attached
    /// when a lost socket comes back.
    pub(crate) watched: usize,
    /// Why some or all of its mailboxes are not watched.
    pub(crate) error: Option<WatchError>,
}

/// A row left out of the set.
#[derive(Debug)]
pub(crate) struct Skipped {
    pub(crate) row: WatchRow,
    pub(crate) reason: SkipReason,
}

/// Why a row was left out of the set.
#[derive(Debug, Error)]
pub(crate) enum SkipReason {
    #[error("the relay of the row cannot be reached as written")]
    Relay(#[source] ContactError),
    #[error(transparent)]
    Unresolved(#[from] Unresolved),
    #[error("another row names the same mailbox on the same relay")]
    Repeated,
}

/// Why the mailboxes of a relay are not all watched.
#[derive(Debug, Error)]
pub(crate) enum WatchError {
    /// The relay does not offer mux/1. Nothing is attached and nothing is read another way.
    #[error("the relay does not offer mux/1")]
    NoPush,
    /// No socket could be started for the relay.
    #[error("no mux/1 session was started")]
    Session(#[source] MuxError),
    /// Some mailboxes found no socket: the relay's sockets were full and no other could be had,
    /// or a socket refused the claim.
    #[error("{count} mailboxes were left out: a mux/1 socket carries at most {bound}")]
    LeftOut {
        count: usize,
        bound: usize,
        #[source]
        source: Option<MuxError>,
    },
}
