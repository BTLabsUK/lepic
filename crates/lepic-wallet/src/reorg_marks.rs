// SPDX-License-Identifier: Apache-2.0
//! What the wallet remembers of a reorganisation (ADR 0071), under settings keys: the store
//! schema stays as it is.
//!
//! - `send.inputs_reorged.<slate id>`: the tip at which a send was first seen waiting for inputs
//!   a reorganisation took. Set by a refused push or a refresh that found them gone, deleted by
//!   a push the node accepts. A send still waiting [`REORG_WAIT_BLOCKS`] blocks later ends
//!   `expired` ([`crate::details::ExpiredReason::InputsReorged`]); the key stays with it as the
//!   record of why.
//! - `tx.reopened.<slate id>`: the tip at which a refresh reopened a confirmed transaction whose
//!   block a reorganisation replaced.
//!
//! A refresh deletes a key whose transaction is gone, or ended any way the key does not
//! explain ([`sweep`]). [`ChainWatch`] keeps, for the session only, the last tip a refresh saw
//! and when it last saw a block replaced.

use std::sync::{Mutex, MutexGuard, PoisonError};

use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_store::{Repositories, StoreError, TransactionEntry, TxDirection, TxState};
use uuid::Uuid;

use crate::state::is_final;

/// How many blocks a send waits for inputs a reorganisation took, from the tip it was first
/// seen waiting at: about an hour of 60-second blocks. Reorganisations on mainnet replace one
/// to three blocks (ADR 0070), and the maker comes back as soon as any node or the payer's
/// wallet posts it again; the bound caps how long the send's other inputs stay held.
pub(crate) const REORG_WAIT_BLOCKS: u64 = 60;

/// The settings key prefix of a send waiting for inputs a reorganisation took.
const INPUTS_REORGED_PREFIX: &str = "send.inputs_reorged.";

/// The settings key prefix of a transaction a refresh reopened.
const REOPENED_PREFIX: &str = "tx.reopened.";

fn inputs_reorged_setting(slate_id: Uuid) -> String {
    format!("{INPUTS_REORGED_PREFIX}{slate_id}")
}

fn reopened_setting(slate_id: Uuid) -> String {
    format!("{REOPENED_PREFIX}{slate_id}")
}

fn height(value: Option<String>) -> Option<Height> {
    value.and_then(|value| value.parse().ok()).map(Height::new)
}

/// Marks the send under `slate_id` as waiting for reorged inputs at `tip`, unless it is marked
/// already, and returns the tip it was first marked at.
pub(crate) fn mark_inputs_reorged(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    tip: Height,
) -> Result<Height, StoreError> {
    let key = inputs_reorged_setting(slate_id);
    if let Some(marked) = height(repos.setting(&key)?) {
        return Ok(marked);
    }
    repos.put_setting(&key, &tip.value().to_string())?;
    Ok(tip)
}

/// Deletes the mark of the send under `slate_id`: its inputs are back.
pub(crate) fn clear_inputs_reorged(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
) -> Result<(), StoreError> {
    repos.delete_setting(&inputs_reorged_setting(slate_id))
}

/// The tip at which the send `entry` was first seen waiting for reorged inputs. `None` for any
/// other transaction.
pub(crate) fn inputs_reorged_at(
    repos: &dyn Repositories,
    entry: &TransactionEntry,
) -> Result<Option<Height>, StoreError> {
    let (TxDirection::Outgoing, Some(slate_id)) = (entry.direction, entry.slate_id) else {
        return Ok(None);
    };
    Ok(height(repos.setting(&inputs_reorged_setting(slate_id))?))
}

/// Whether a send first marked at `marked` has waited [`REORG_WAIT_BLOCKS`] at `tip`.
pub(crate) fn waited_out(marked: Height, tip: Height) -> bool {
    tip.value() >= marked.value().saturating_add(REORG_WAIT_BLOCKS)
}

/// Marks the transactions under `slate_id` as reopened at `tip`, unless they are marked
/// already.
pub(crate) fn mark_reopened(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    tip: Height,
) -> Result<(), StoreError> {
    let key = reopened_setting(slate_id);
    if repos.setting(&key)?.is_none() {
        repos.put_setting(&key, &tip.value().to_string())?;
    }
    Ok(())
}

/// The tip at which a refresh reopened the transaction `entry`, while it is open. `None` once
/// it ended, and for a transaction without a slate.
pub(crate) fn reopened_at(
    repos: &dyn Repositories,
    entry: &TransactionEntry,
) -> Result<Option<Height>, StoreError> {
    let Some(slate_id) = entry.slate_id.filter(|_| !is_final(entry.state)) else {
        return Ok(None);
    };
    Ok(height(repos.setting(&reopened_setting(slate_id))?))
}

/// The keys [`sweep`] deletes: an `inputs_reorged` key whose send is gone or ended other than
/// `expired`, a `reopened` key with no open transaction under its slate id, and any key that
/// does not parse.
pub(crate) fn sweep_due(repos: &dyn Repositories) -> Result<Vec<String>, StoreError> {
    let mut due = Vec::new();
    for (key, value) in repos.settings_with_prefix(INPUTS_REORGED_PREFIX)? {
        let slate_id = key
            .strip_prefix(INPUTS_REORGED_PREFIX)
            .and_then(|id| Uuid::parse_str(id).ok());
        let keep = match (slate_id, height(Some(value))) {
            (Some(slate_id), Some(_)) => repos
                .transaction_by_slate(slate_id, TxDirection::Outgoing)?
                .is_some_and(|stored| {
                    !is_final(stored.entry.state) || stored.entry.state == TxState::Expired
                }),
            _ => false,
        };
        if !keep {
            due.push(key);
        }
    }
    for (key, value) in repos.settings_with_prefix(REOPENED_PREFIX)? {
        let slate_id = key
            .strip_prefix(REOPENED_PREFIX)
            .and_then(|id| Uuid::parse_str(id).ok());
        let keep = match (slate_id, height(Some(value))) {
            (Some(slate_id), Some(_)) => {
                let mut open = false;
                for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                    open |= repos
                        .transaction_by_slate(slate_id, direction)?
                        .is_some_and(|stored| !is_final(stored.entry.state));
                }
                open
            }
            _ => false,
        };
        if !keep {
            due.push(key);
        }
    }
    Ok(due)
}

/// Deletes the keys [`sweep_due`] finds, read again inside the write.
pub(crate) fn sweep(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    for key in sweep_due(repos)? {
        repos.delete_setting(&key)?;
    }
    Ok(())
}

/// What a session saw of the chain: the last tip a refresh read, and the tip at which it last
/// saw a block replaced. Dropped when the wallet locks or closes.
#[derive(Default)]
pub(crate) struct ChainWatch {
    seen: Mutex<Seen>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    last_tip: Option<(Height, Hash)>,
    replaced_at: Option<Height>,
}

impl ChainWatch {
    /// The last tip a refresh read: its height and the hash of its block.
    pub(crate) fn last_tip(&self) -> Option<(Height, Hash)> {
        self.lock().last_tip
    }

    /// Remembers the tip a refresh read.
    pub(crate) fn saw_tip(&self, height: Height, hash: Hash) {
        self.lock().last_tip = Some((height, hash));
    }

    /// Remembers that a block was replaced, seen at the tip `at`.
    pub(crate) fn replaced(&self, at: Height) {
        let mut seen = self.lock();
        seen.replaced_at = Some(seen.replaced_at.map_or(at, |before| before.max(at)));
    }

    /// Whether the session saw a block replaced fewer than [`REORG_WAIT_BLOCKS`] blocks below
    /// the last tip a refresh read.
    pub(crate) fn replaced_recently(&self) -> bool {
        let seen = *self.lock();
        match (seen.replaced_at, seen.last_tip) {
            (Some(at), Some((tip, _))) => !waited_out(at, tip),
            _ => false,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Seen> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::hash::ZERO_HASH;

    use super::*;

    #[test]
    fn a_send_waits_out_sixty_blocks_from_its_mark() {
        let marked = Height::new(100);
        assert!(!waited_out(marked, Height::new(159)));
        assert!(waited_out(marked, Height::new(160)));
        assert!(!waited_out(
            Height::new(u64::MAX),
            Height::new(u64::MAX - 1)
        ));
    }

    #[test]
    fn a_replaced_block_reads_recent_for_sixty_blocks() {
        let watch = ChainWatch::default();
        assert!(!watch.replaced_recently());
        watch.replaced(Height::new(100));
        assert!(!watch.replaced_recently(), "no tip read yet");
        watch.saw_tip(Height::new(159), ZERO_HASH);
        assert!(watch.replaced_recently());
        watch.saw_tip(Height::new(160), ZERO_HASH);
        assert!(!watch.replaced_recently());
        // An earlier replacement seen later does not move the mark back.
        watch.replaced(Height::new(90));
        assert!(!watch.replaced_recently());
        watch.replaced(Height::new(150));
        assert!(watch.replaced_recently());
    }
}
