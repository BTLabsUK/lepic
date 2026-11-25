// SPDX-License-Identifier: Apache-2.0
//! The record of every push of a transaction to the node, and the pushes a refresh makes again
//! until the transaction is mined or its cutoff passes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::{NodeApi, NodeError, NodeRejection, Propagation};
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::error_chain::ErrorChain;
use lepic_store::{
    MAX_NODE_ERROR_LEN, NodeOutcome, NodePost, Repositories, StoreError, TxId, TxState, WalletStore,
};
use tracing::{debug, instrument, warn};

use crate::cancel::pool_kernels;
use crate::chain;
use crate::finalize::{FinalizeError, FinalizedSlate, PushFailure, postable, push_outcome};
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::recover::recovering;
use crate::refresh::{RefreshError, confirmed_by_output, open_transactions};
use crate::wallet::Wallet;

/// Blocks a refresh waits after a push that failed before it pushes again, by the number of
/// pushes made: the first entry follows the first push.
pub(crate) const RETRY_BACKOFF_BLOCKS: [u64; 5] = [1, 2, 4, 8, 16];

/// Blocks a refresh waits after every push past those [`RETRY_BACKOFF_BLOCKS`] covers.
pub(crate) const RETRY_BACKOFF_LAST_BLOCKS: u64 = 30;

/// Blocks after a push the node accepted before a refresh pushes the transaction again, when
/// neither the node's pool nor its chain holds it.
pub(crate) const POSTED_RECHECK_BLOCKS: u64 = 10;

/// How a refresh pushes a transaction again: as the inbox pushes a send it finalized.
pub(crate) const RETRY_PROPAGATION: Propagation = Propagation::Stem;

/// One push the node answered, as [`record_push`] stores it.
#[derive(Debug, Clone)]
pub(crate) struct PushRecord {
    pub tx_id: TxId,
    pub outcome: NodeOutcome,
    /// The text of a failed push, already cut by [`stored_error`].
    pub error: Option<String>,
    /// The tip the push was made at.
    pub height: Height,
}

/// The text of `error` as the record keeps it, with the node's own text of a rejection: cut at
/// a character boundary to at most [`MAX_NODE_ERROR_LEN`] bytes.
pub(crate) fn stored_error(error: &NodeError) -> String {
    let mut text = ErrorChain(error).to_string();
    if let NodeError::Rejected {
        rejection: NodeRejection {
            message: Some(message),
            ..
        },
        ..
    } = error
    {
        text.push_str(": ");
        text.push_str(message);
    }
    let end = text.floor_char_boundary(MAX_NODE_ERROR_LEN);
    text.truncate(end);
    text
}

/// Adds `push`, made at `at`, to the record of its transaction and returns the record as it was
/// before. An accepted push keeps the text of the last failed one.
pub(crate) fn record_push(
    repos: &mut dyn Repositories,
    push: PushRecord,
    at: Timestamp,
) -> Result<Option<NodePost>, StoreError> {
    let previous = repos.node_post(push.tx_id)?;
    let failed = push.outcome != NodeOutcome::Accepted;
    let post = match &previous {
        Some(previous) => NodePost {
            tx_id: push.tx_id,
            attempts: previous.attempts.saturating_add(1),
            last_at: at,
            last_height: push.height,
            last_outcome: push.outcome,
            last_error: if failed {
                push.error
            } else {
                previous.last_error.clone()
            },
            accepted_once: previous.accepted_once || !failed,
            unreachable_once: previous.unreachable_once || push.outcome == NodeOutcome::Unreachable,
        },
        None => NodePost {
            tx_id: push.tx_id,
            attempts: 1,
            last_at: at,
            last_height: push.height,
            last_outcome: push.outcome,
            last_error: push.error.filter(|_| failed),
            accepted_once: !failed,
            unreachable_once: push.outcome == NodeOutcome::Unreachable,
        },
    };
    repos.put_node_post(&post)?;
    Ok(previous)
}

/// Whether a failed push with `outcome` and the stored `text` tells the host something new
/// after the record `previous`: it is the first failure, or its class or text differ.
pub(crate) fn tells_something_new(
    previous: Option<&NodePost>,
    outcome: NodeOutcome,
    text: Option<&str>,
) -> bool {
    previous.is_none_or(|previous| {
        previous.last_outcome != outcome || previous.last_error.as_deref() != text
    })
}

/// Whether the node's pool refused every push in `post`: at least one push, none accepted and
/// none that found the node unreachable. An answer the wallet does not know counts as
/// unreachable, so a proxy's error or a timeout among the pushes keeps this false.
pub(crate) fn refused_every_time(post: &NodePost) -> bool {
    post.attempts > 0
        && !post.accepted_once
        && !post.unreachable_once
        && post.last_outcome == NodeOutcome::Refused
}

/// The height from which a refresh pushes the transaction of `post` again: `POSTED_RECHECK_BLOCKS`
/// after a push the node accepted, and after a failed one the backoff of
/// `RETRY_BACKOFF_BLOCKS` by the number of pushes, then `RETRY_BACKOFF_LAST_BLOCKS`.
pub fn next_attempt_height(post: &NodePost) -> Height {
    let wait = match post.last_outcome {
        NodeOutcome::Accepted => POSTED_RECHECK_BLOCKS,
        NodeOutcome::Refused | NodeOutcome::Unreachable => backoff_blocks(post.attempts),
    };
    Height::new(post.last_height.value().saturating_add(wait))
}

fn backoff_blocks(attempts: u32) -> u64 {
    usize::try_from(attempts.saturating_sub(1))
        .ok()
        .and_then(|index| RETRY_BACKOFF_BLOCKS.get(index))
        .copied()
        .unwrap_or(RETRY_BACKOFF_LAST_BLOCKS)
}

/// A transaction a refresh pushes again.
struct DuePush {
    tx_id: TxId,
    finalized: FinalizedSlate,
    /// Whether it is `posted`: it is pushed only when neither the pool nor the chain holds it.
    posted: bool,
    /// Whether this refresh would have confirmed it by its change output, so a transaction
    /// still open is not on chain without a kernel lookup.
    by_output: bool,
    /// The payment this transaction recovers, when it is the outgoing entry of an open
    /// recovery: the push's outcome is the recovery's.
    recovers: Option<TxId>,
    /// The pushes its record counted when it was found due; `None` when it had no record.
    attempts: Option<u32>,
}

/// The `finalized` and `posted` transactions this wallet may post whose next attempt is due at
/// `tip`, before their cutoff: one with no record of a push is due now.
fn due_pushes(
    repos: &dyn Repositories,
    base_fee: Fee,
    tip: Height,
) -> Result<Vec<DuePush>, RefreshError> {
    let recovery_of: BTreeMap<TxId, TxId> = repos
        .recoveries()?
        .into_iter()
        .filter(|recovery| recovery.state.is_open())
        .map(|recovery| (recovery.sent_tx, recovery.tx_id))
        .collect();
    let recovered = recovering(repos)?;
    let mut due = Vec::new();
    for stored in open_transactions(repos)? {
        if recovered.contains_key(&stored.id) {
            continue;
        }
        let posted = match stored.entry.state {
            TxState::Finalized => false,
            TxState::Posted => true,
            _ => continue,
        };
        let (finalized, cutoff) = match postable(repos, base_fee, stored.id) {
            Ok(postable) => postable,
            Err(FinalizeError::NotPostable { .. }) => continue,
            Err(error) => {
                debug!(tx_id = %stored.id, error = %ErrorChain(&error), "not pushed again");
                continue;
            }
        };
        if cutoff.is_some_and(|cutoff| tip >= cutoff) {
            continue;
        }
        let post = repos.node_post(stored.id)?;
        let waiting = post
            .as_ref()
            .is_some_and(|post| tip < next_attempt_height(post));
        if !waiting {
            due.push(DuePush {
                tx_id: stored.id,
                finalized,
                posted,
                by_output: confirmed_by_output(&stored.entry),
                recovers: recovery_of.get(&stored.id).copied(),
                attempts: post.map(|post| post.attempts),
            });
        }
    }
    Ok(due)
}

/// The node's pool, read once for every `posted` transaction one refresh pushes again.
enum Pool {
    Unread,
    Read(BTreeSet<Commitment>),
    Failed,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Pushes again, one after another, every transaction [`due_pushes`] names at `tip`; a
    /// `posted` one only when the node's pool does not hold its kernel and the chain does not
    /// either. `kernel_missing` names transactions whose kernel this refresh already looked
    /// up and did not find. Stops at the first push that ends unreachable, so a node that is
    /// down costs one push; the rest stay due. Nothing here fails the refresh, and nothing
    /// refreshes: a transaction the node refused for spent inputs is ended without one.
    pub(crate) async fn push_due(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: Height,
        kernel_missing: &BTreeSet<TxId>,
    ) {
        if self.config().offline {
            return;
        }
        let due = {
            let session = Arc::clone(session);
            self.blocking(move |_, config| {
                let base_fee = config.network.params().default_base_fee();
                Ok(session.store.read(|repos| due_pushes(repos, base_fee, tip)))
            })
            .await
        };
        let due = match due.map_err(RefreshError::from).and_then(|due| due) {
            Ok(due) => due,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "pushes due not read");
                return;
            }
        };
        let mut pool = Pool::Unread;
        let mut left = due.into_iter();
        while let Some(push) = left.next() {
            if push.posted && self.held(&push, &mut pool, tip, kernel_missing).await {
                continue;
            }
            if !self.push_again(session, &push, tip).await {
                let count = left.len();
                if count > 0 {
                    debug!(
                        count,
                        "pushes left for the next refresh: the node could not be reached"
                    );
                }
                return;
            }
        }
    }

    /// Whether the node holds the kernel of the posted `push`, or cannot say: in its pool,
    /// read at most once into `pool`, or on chain. The chain is asked only when this refresh
    /// knows nothing yet: neither its change output nor `kernel_missing` said it is not mined.
    async fn held(
        &self,
        push: &DuePush,
        pool: &mut Pool,
        tip: Height,
        kernel_missing: &BTreeSet<TxId>,
    ) -> bool {
        let Some(kernel) = push.finalized.slate.kernel() else {
            return true;
        };
        let node = &self.ports().node;
        if matches!(pool, Pool::Unread) {
            *pool = match pool_kernels(node).await {
                Ok(kernels) => Pool::Read(kernels),
                Err(error) => {
                    debug!(error = %ErrorChain(&error), "node pool not read");
                    Pool::Failed
                }
            };
        }
        let pooled = match pool {
            Pool::Read(kernels) => kernels.contains(&kernel.excess),
            Pool::Unread | Pool::Failed => true,
        };
        if pooled {
            return true;
        }
        if push.by_output || kernel_missing.contains(&push.tx_id) {
            return false;
        }
        let floor = chain::kernel_floor(push.finalized.slate.height(), tip);
        !matches!(
            node.get_kernel(&kernel.excess, Some(floor), None).await,
            Ok(None)
        )
    }

    /// Pushes `push` again at `tip`, unless it was pushed since it was found due or a finalize
    /// that is to make its first push still runs. Returns false when the push ended
    /// unreachable. A refusal for inputs that are gone ends the transaction as
    /// [`Wallet::end_spent`] does; the push of a recovery ends as [`Wallet::recover`] says.
    #[instrument(name = "push_again", skip_all, fields(tx_id = %push.tx_id))]
    async fn push_again(
        &self,
        session: &Arc<Session<S::Store>>,
        push: &DuePush,
        tip: Height,
    ) -> bool {
        let posting = self.posting_turn().await;
        if !self.still_due(push).await {
            debug!("pushed since it was found due; not pushed again");
            return true;
        }
        let pushed = self
            .push_final_in_turn(
                posting,
                &push.finalized,
                push.tx_id,
                RETRY_PROPAGATION,
                Some(tip),
            )
            .await;
        if let Some(payment) = push.recovers {
            let reachable = !matches!(
                &pushed,
                Err(PushFailure::NotPosted(source))
                    if push_outcome(source) == NodeOutcome::Unreachable
            );
            match self
                .recovery_pushed(session, payment, &push.finalized, tip, pushed)
                .await
            {
                Ok((recovery, true)) => self.emit_recovery(&recovery),
                Ok((_, false)) => {}
                Err(error) => warn!(error = %ErrorChain(&error), "recovery push not recorded"),
            }
            return reachable;
        }
        match pushed {
            Ok(_) => true,
            Err(PushFailure::NotPosted(source)) => {
                debug!(error = %ErrorChain(&source), "transaction not pushed again");
                push_outcome(&source) != NodeOutcome::Unreachable
            }
            Err(PushFailure::Unminable { spent, .. }) => {
                self.end_spent(push.tx_id, spent).await;
                true
            }
            // Never cancelled: the transaction is pushed again until its inputs are back.
            Err(PushFailure::Reorged(source)) => {
                debug!(error = %ErrorChain(&source), "transaction not pushed again, inputs reorged");
                true
            }
            Err(PushFailure::Wallet(error)) => {
                debug!(error = %ErrorChain(&error), "transaction not pushed again");
                true
            }
        }
    }

    /// Whether `push` is still due, read under the posting turn: its record counts the pushes
    /// it counted when found due, and a transaction never pushed has no finalize running that
    /// makes its first push. A store that cannot say counts as not due.
    async fn still_due(&self, push: &DuePush) -> bool {
        if push.attempts.is_none() && self.is_finalizing(push.finalized.slate.id()) {
            return false;
        }
        let tx_id = push.tx_id;
        let post = match self.session() {
            Ok(session) => {
                self.blocking(move |_, _| Ok(session.store.read(|repos| repos.node_post(tx_id))?))
                    .await
            }
            Err(error) => Err(error),
        };
        match post {
            Ok(post) => post.map(|post| post.attempts) == push.attempts,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "push record not read");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lepic_node::RejectionKind;

    use super::*;

    #[test]
    fn a_long_node_text_is_cut_at_a_character_boundary() {
        let error = NodeError::Rejected {
            method: "push_transaction",
            rejection: NodeRejection {
                kind: RejectionKind::Internal,
                message: Some("é".repeat(MAX_NODE_ERROR_LEN)),
            },
        };

        let text = stored_error(&error);

        assert!(text.len() <= MAX_NODE_ERROR_LEN);
        assert!(text.len() >= MAX_NODE_ERROR_LEN.saturating_sub(1));
        assert!(text.ends_with('é'));
    }
}
