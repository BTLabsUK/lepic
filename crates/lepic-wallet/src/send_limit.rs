//! The wallet-local limit of a send: a height, kept by this wallet only and not in the slate,
//! past which the wallet neither finalizes nor posts the send and expires it if unanswered. It
//! works on every method, also those whose slate shape cannot carry a TTL.

use lepic_primitives::amount::Height;
use lepic_store::{Repositories, StoreError, TxId};
use tracing::warn;

const LOCAL_CUTOFF_PREFIX: &str = "send.local_cutoff.";

/// Records the local cutoff of the send `tx_id`, or clears a stale one when it has none. Run
/// it in the store transaction that stores the S1.
pub(crate) fn record_local_cutoff(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    cutoff: Option<Height>,
) -> Result<(), StoreError> {
    match cutoff {
        Some(cutoff) => repos.put_setting(&key(tx_id), &cutoff.value().to_string()),
        None => repos.delete_setting(&key(tx_id)),
    }
}

/// The local cutoff of the send `tx_id`. A stored height that does not parse counts as not
/// stored; the slate's own TTL, if any, still applies.
pub(crate) fn local_cutoff(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<Height>, StoreError> {
    Ok(match repos.setting(&key(tx_id))? {
        Some(text) => {
            let height = text.parse().ok().map(Height::new);
            if height.is_none() {
                warn!(tx_id = %tx_id, "send cutoff height unreadable");
            }
            height
        }
        None => None,
    })
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

fn key(tx_id: TxId) -> String {
    format!("{LOCAL_CUTOFF_PREFIX}{tx_id}")
}
