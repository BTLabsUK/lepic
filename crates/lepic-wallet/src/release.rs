//! Releasing a send the network never took: a finalized or posted send whose kernel a refresh
//! did not find on chain [`RELEASE_AFTER_BLOCKS`] or more after it was finalized. Releasing it
//! cancels it as [`Wallet::cancel`] does, so its inputs can be spent again.
//!
//! Whether the node refused the post, never answered it, or took it and then dropped it, a
//! kernel still missing a day of blocks later means the transaction is not on its way to the
//! chain through that node. Another node may still hold it, so the release is the owner's
//! decision, never automatic.

use std::sync::Arc;

use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    Repositories, StoreError, StoredTransaction, TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::cancel::drop_holdings;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{final_kernel, legacy_codecs};
use crate::state::{apply_transition, state_name};
use crate::wallet::Wallet;

/// Blocks after finalizing that a send's kernel must still be missing before it may be
/// released: a day of blocks, the wait the Flutter app applies.
pub const RELEASE_AFTER_BLOCKS: u64 = 1_440;

const FINALIZED_HEIGHT_PREFIX: &str = "release.finalized_height.";
const KERNEL_ABSENT_PREFIX: &str = "release.kernel_absent.";

/// Why a transaction cannot be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ReleaseRefusal {
    /// Only an outgoing transaction in state `finalized` or `posted` is released.
    #[error("transaction is not a finalized or posted send, it is {}", state_name(*state))]
    NotPendingSend { state: TxState },
    /// The final slate is not stored or no longer decodes, so the kernel cannot be looked up.
    #[error("the kernel of the transaction is not known")]
    KernelUnknown,
    /// No refresh has yet looked the kernel up at or above `from` and missed it.
    #[error("the kernel was not yet looked up at or above height {from}")]
    TooEarly { from: Height },
}

/// What decides whether one finalized or posted send may be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleaseCheck {
    pub(crate) excess: Commitment,
    /// The height the slate was created at, below which the kernel cannot be.
    pub(crate) min_height: Height,
    /// The height from which a missing kernel makes the send releasable.
    pub(crate) from: Height,
    /// The height at which a refresh last looked the kernel up and missed it.
    pub(crate) absent_at: Option<Height>,
}

impl ReleaseCheck {
    pub(crate) fn releasable(&self) -> bool {
        self.absent_at.is_some_and(|absent| absent >= self.from)
    }

    /// Whether a refresh at `height` should look the kernel up for the release.
    pub(crate) fn due_at(&self, height: Height) -> bool {
        height >= self.from && !self.releasable()
    }
}

/// The release check of `stored`, or why it has none: it is not an outgoing finalized or posted
/// transaction, or its kernel is not known.
pub(crate) fn release_check(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<Result<ReleaseCheck, ReleaseRefusal>, StoreError> {
    let entry = &stored.entry;
    let pending_send = entry.direction == TxDirection::Outgoing
        && matches!(entry.state, TxState::Finalized | TxState::Posted);
    let Some(slate_id) = entry.slate_id.filter(|_| pending_send) else {
        return Ok(Err(ReleaseRefusal::NotPendingSend { state: entry.state }));
    };
    let Some((excess, min_height)) = final_kernel(repos, codecs, stored.id, slate_id)? else {
        return Ok(Err(ReleaseRefusal::KernelUnknown));
    };
    // Sends finalized before the height was stored count from the slate's creation, which is
    // never later than finalizing.
    let finalized = stored_height(repos, FINALIZED_HEIGHT_PREFIX, stored.id)?.unwrap_or(min_height);
    Ok(Ok(ReleaseCheck {
        excess,
        min_height,
        // A height that overflows is never reached, so the send is never releasable.
        from: finalized
            .checked_add_blocks(RELEASE_AFTER_BLOCKS)
            .unwrap_or(Height::new(u64::MAX)),
        absent_at: stored_height(repos, KERNEL_ABSENT_PREFIX, stored.id)?,
    }))
}

/// Records the tip a send was finalized at. Run it in the store transaction that finalizes.
pub(crate) fn record_finalized(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    tip: Height,
) -> Result<(), StoreError> {
    repos.put_setting(
        &key(FINALIZED_HEIGHT_PREFIX, tx_id),
        &tip.value().to_string(),
    )
}

/// Records that a lookup of the send's kernel up to `height` did not find it.
pub(crate) fn record_kernel_absent(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Height,
) -> Result<(), StoreError> {
    repos.put_setting(
        &key(KERNEL_ABSENT_PREFIX, tx_id),
        &height.value().to_string(),
    )
}

fn key(prefix: &str, tx_id: TxId) -> String {
    format!("{prefix}{tx_id}")
}

/// A stored height that does not parse counts as not stored: the send then waits for the next
/// lookup, which is the safe side.
fn stored_height(
    repos: &dyn Repositories,
    prefix: &str,
    tx_id: TxId,
) -> Result<Option<Height>, StoreError> {
    Ok(match repos.setting(&key(prefix, tx_id))? {
        Some(text) => {
            let height = text.parse().ok().map(Height::new);
            if height.is_none() {
                warn!(tx_id = %tx_id, "release height unreadable");
            }
            height
        }
        None => None,
    })
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Releases a finalized or posted send that the network never took, so its inputs can be
    /// spent again: the transaction is cancelled as [`Wallet::cancel`] cancels it, with its
    /// inputs unlocked, its change output dropped, its state `cancelled` and an
    /// [`crate::Event::Transaction`].
    ///
    /// The send must be releasable, as [`crate::details::TransactionDetails::releasable`]
    /// reports. At the call the node is asked once more: its tip must be plausible, and neither
    /// its chain nor its transaction pool may hold the kernel.
    ///
    /// If another node still holds the transaction and mines it later, the inputs are spent by
    /// it after all, and a new send that spends them fails.
    ///
    /// Fails with [`WalletError::Locked`], [`WalletError::UnknownTransaction`],
    /// [`WalletError::NotReleasable`] with the reason, [`WalletError::OnChain`] when the chain
    /// holds the kernel, [`WalletError::InPool`] when the node's pool holds it,
    /// [`WalletError::Node`] or [`WalletError::Implausible`] when the node cannot be asked, and
    /// [`WalletError::ChangedDuringCancel`] when another operation moved the transaction on
    /// meanwhile. Nothing is changed by a failed release.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn release(&self, tx_id: TxId) -> Result<(), WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let (observed, check) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                session
                    .store
                    .read(|repos| releasable(repos, &codecs, tx_id))
            })
            .await?
        };
        let node = &self.ports().node;
        let tip = node.get_tip().await.map_err(WalletError::Node)?.height;
        self.check_plausible_tip(&session, tip).await?;
        let kernel = node
            .get_kernel(&check.excess, Some(check.min_height), Some(tip))
            .await
            .map_err(WalletError::Node)?;
        if let Some(kernel) = kernel {
            debug!(height = %kernel.height, "kernel found on chain");
            return Err(WalletError::OnChain(tx_id));
        }
        let pool = node
            .get_unconfirmed_transactions()
            .await
            .map_err(WalletError::Node)?;
        let pooled = pool
            .iter()
            .flat_map(|transaction| &transaction.kernels)
            .any(|kernel| kernel.excess == check.excess);
        if pooled {
            debug!("kernel found in the node pool");
            return Err(WalletError::InPool(tx_id));
        }
        let change = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(WalletError::UnknownTransaction(tx_id))?;
                    if entry.state != observed {
                        return Err(WalletError::ChangedDuringCancel(tx_id));
                    }
                    drop_holdings(repos, tx_id, &entry)?;
                    apply_transition(repos, tx_id, TxState::Cancelled, now)
                })
            })
            .await?;
        if let Some(change) = change {
            info!(height = %tip, "transaction released");
            self.emit(change.into());
        }
        Ok(())
    }
}

/// The state and release check of a send that may be released now.
fn releasable(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<(TxState, ReleaseCheck), WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let state = entry.state;
    let refused = |reason| WalletError::NotReleasable { tx_id, reason };
    let check =
        release_check(repos, codecs, &StoredTransaction { id: tx_id, entry })?.map_err(refused)?;
    if !check.releasable() {
        return Err(refused(ReleaseRefusal::TooEarly { from: check.from }));
    }
    Ok((state, check))
}
