//! The wallet-local limit of a send: a height, kept by this wallet only and not in the slate,
//! past which the wallet neither finalizes nor posts the send and expires it if unanswered. It
//! works on every method, also those whose slate shape cannot carry a TTL.

use lepic_primitives::amount::Height;
use lepic_store::{Repositories, StoreError, TxId};

/// Records the local cutoff of the send `tx_id`, or clears a stale one when it has none. Run
/// it in the store transaction that stores the S1.
pub(crate) fn record_local_cutoff(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    cutoff: Option<Height>,
) -> Result<(), StoreError> {
    let mut marks = repos.tx_marks(tx_id)?;
    marks.local_cutoff = cutoff;
    repos.put_tx_marks(tx_id, &marks)
}

/// The local cutoff of the send `tx_id`.
pub(crate) fn local_cutoff(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<Height>, StoreError> {
    Ok(repos.tx_marks(tx_id)?.local_cutoff)
}

/// The height a send ends at: the earlier of its slate's TTL cutoff and its local cutoff.
pub(crate) fn effective_cutoff(
    repos: &dyn Repositories,
    tx_id: TxId,
    slate_ttl: Option<Height>,
) -> Result<Option<Height>, StoreError> {
    let local = local_cutoff(repos, tx_id)?;
    Ok(match (slate_ttl, local) {
        (Some(slate), Some(local)) => Some(slate.min(local)),
        (slate, local) => slate.or(local),
    })
}
