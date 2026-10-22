//! Cancelling a transaction that is not confirmed, as `epic-wallet`'s `cancel_tx` does: its
//! unconfirmed outputs are dropped, the inputs it locked become spendable again, and its private
//! context and pending deliveries are dropped with it. A posted transaction is not cancelled, nor
//! is one the peer may complete without this wallet whose kernel the node's chain or pool
//! already holds. Such a transaction stays watched after the cancel, so a refresh confirms it
//! and restores its outputs if the peer still completes it.

use std::collections::BTreeSet;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::{NodeApi, NodeError};
use lepic_primitives::amount::Height;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    OutboxStatus, OutputRecord, OutputStatus, ParticipantId, Repositories, StoredTransaction,
    TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use tracing::{debug, info, instrument};

use crate::chain;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{forget_receive_seen, legacy_codecs, pending_kernel};
use crate::release::record_watch;
use crate::self_send::SELF;
use crate::send::SENDER_CONTEXT;
use crate::state::{InvalidTransition, StateChange, apply_transition, check_transition};
use crate::wallet::Wallet;

/// The private context of the party that adds only an output, under the participant id
/// `epic-wallet` gives the receiver.
const RECEIVER_CONTEXT: ParticipantId = ParticipantId(1);

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Cancels the transaction: drops its unconfirmed outputs, unlocks the inputs it locked,
    /// drops its private context and pending deliveries, and moves it to `cancelled`, all in
    /// one store transaction. Either entry of a send to the wallet itself takes the other
    /// along, so the inputs, the change and the output of the amount are released together.
    /// Cancelling a cancelled transaction changes nothing.
    ///
    /// A slate already delivered is not recalled; if the peer still completes it, the
    /// transaction can no longer be finalized here. For an invoice issued over Epicbox, the
    /// payer is sent a `withdrawn` notice when it proved that it runs LEPIC; a failure to send
    /// it is logged and not returned.
    ///
    /// The peer may complete a transaction without this wallet once it holds this wallet's
    /// signature: a finalized one, whose post may have reached the node even though it failed,
    /// an invoice payment once its I2 exists, and a received payment once its S2 exists. Its
    /// kernel is looked up first, in the node's transaction pool and then in its chain up to
    /// the node's tip, which must be plausible; the node must be reachable to cancel one. The
    /// pool comes first, so a transaction that leaves the pool for a block between the two
    /// lookups is found by the second. A posted transaction, which includes one the node's
    /// pool answered it already holds, counts as on chain and is not cancelled. After the
    /// cancel, a refresh up to [`crate::release::RELEASED_WATCH_BLOCKS`] past that tip still
    /// looks the kernel up: a kernel found confirms the transaction and stores the outputs the
    /// cancel dropped as unspent ([`Wallet::refresh`]).
    ///
    /// Fails with [`WalletError::Locked`], [`WalletError::UnknownTransaction`],
    /// [`WalletError::Transition`] when the transaction is posted, confirmed or expired,
    /// [`WalletError::OnChain`] when the node's chain holds the kernel, [`WalletError::InPool`]
    /// when the node's pool holds it, [`WalletError::Node`] or [`WalletError::Implausible`]
    /// when the node cannot be asked, and [`WalletError::ChangedDuringCancel`] when another
    /// operation moved the transaction on after its state was read; cancelling again then
    /// decides from the new state.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn cancel(&self, tx_id: TxId) -> Result<(), WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let (observed, lookup) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                session
                    .store
                    .read(|repos| cancel_lookup(repos, &codecs, tx_id))
            })
            .await?
        };
        let mut watch = None;
        if let Some((excess, min_height)) = lookup {
            let node = &self.ports().node;
            // The pool is asked before the chain: a transaction that leaves the pool for a
            // block between the two lookups is then found by the second.
            let pooled = pool_holds(node, &excess).await.map_err(WalletError::Node)?;
            if pooled {
                debug!("kernel found in the node pool");
                return Err(WalletError::InPool(tx_id));
            }
            let tip = node.get_tip().await.map_err(WalletError::Node)?.height;
            self.check_plausible_tip(&session, tip).await?;
            let floor = chain::kernel_floor(min_height, tip);
            let kernel = node
                .get_kernel(&excess, Some(floor), Some(tip))
                .await
                .map_err(WalletError::Node)?;
            if let Some(kernel) = kernel {
                debug!(height = %kernel.height, "kernel found on chain");
                return Err(WalletError::OnChain(tx_id));
            }
            watch = Some(Watch {
                excess,
                min_height: floor,
                ended_at: tip,
            });
        }
        let changes = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session
                    .store
                    .write(|repos| cancel_transaction(repos, tx_id, observed, watch, now))
            })
            .await?;
        if changes.is_empty() {
            debug!("transaction already cancelled");
        } else {
            info!("transaction cancelled");
            for change in changes {
                self.emit(change.into());
            }
            self.notify_withdrawn(tx_id).await;
        }
        Ok(())
    }
}

/// Whether the node's transaction pool holds a transaction with the kernel `excess`.
pub(crate) async fn pool_holds<N: NodeApi>(
    node: &N,
    excess: &Commitment,
) -> Result<bool, NodeError> {
    Ok(pool_kernels(node).await?.contains(excess))
}

/// The kernel excesses of every transaction in the node's transaction pool.
pub(crate) async fn pool_kernels<N: NodeApi>(node: &N) -> Result<BTreeSet<Commitment>, NodeError> {
    let pool = node.get_unconfirmed_transactions().await?;
    Ok(pool
        .iter()
        .flat_map(|transaction| &transaction.kernels)
        .map(|kernel| kernel.excess)
        .collect())
}

/// The state a cancel starts from, and the kernel to look up before it is cancelled, of a
/// transaction the peer may complete without this wallet.
fn cancel_lookup(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<(TxState, Option<(Commitment, Height)>), WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let state = entry.state;
    let kernel = pending_kernel(repos, codecs, &StoredTransaction { id: tx_id, entry })?;
    Ok((state, kernel))
}

/// What keeps a cancelled transaction recognisable if the peer completes it later.
#[derive(Debug, Clone, Copy)]
struct Watch {
    excess: Commitment,
    min_height: Height,
    /// The tip the kernel was last looked up to.
    ended_at: Height,
}

/// Cancels the transaction if it is still in the state `observed`, the one the kernel lookup
/// was decided on, and keeps `watch` for it. A transaction finalized or posted since may be on
/// its way to the chain.
fn cancel_transaction(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    observed: TxState,
    watch: Option<Watch>,
    now: Timestamp,
) -> Result<Vec<StateChange>, WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    // A posted transaction may still be mined, so releasing its inputs and dropping its change
    // would show funds the chain may already have spent. Upstream refuses it as well once the
    // mempool has seen it.
    if entry.state == TxState::Posted {
        return Err(InvalidTransition {
            from: TxState::Posted,
            to: TxState::Cancelled,
        }
        .into());
    }
    if check_transition(tx_id, entry.state, TxState::Cancelled)?.is_none() {
        return Ok(Vec::new());
    }
    if entry.state != observed {
        return Err(WalletError::ChangedDuringCancel(tx_id));
    }
    let partner = self_send_partner(repos, &entry)?;
    if let Some(partner) = &partner
        && partner.entry.state == TxState::Posted
    {
        return Err(InvalidTransition {
            from: TxState::Posted,
            to: TxState::Cancelled,
        }
        .into());
    }
    if let Some(watch) = watch {
        record_watch(repos, tx_id, watch.excess, watch.min_height, watch.ended_at)?;
    }
    drop_holdings(repos, tx_id, &entry)?;
    let mut changes: Vec<StateChange> = apply_transition(repos, tx_id, TxState::Cancelled, now)?
        .into_iter()
        .collect();
    if let Some(partner) = partner {
        let watch = watch.map(|watch| (watch.excess, watch.min_height, watch.ended_at));
        changes.extend(cancel_partner(repos, &partner, watch, now)?);
    }
    Ok(changes)
}

/// The other entry of a send to the wallet itself: the one of the same slate over [`SELF`]
/// in the other direction. The outgoing entry spent the inputs and holds the change, the
/// incoming one holds the output of the amount, and the two end together. `None` for any
/// other transaction.
pub(crate) fn self_send_partner(
    repos: &dyn Repositories,
    entry: &TransactionEntry,
) -> Result<Option<StoredTransaction>, WalletError> {
    let is_self = entry.transport.as_deref() == Some(SELF.as_str());
    let Some(slate_id) = entry.slate_id.filter(|_| is_self) else {
        return Ok(None);
    };
    Ok(repos
        .transactions(entry.account)?
        .into_iter()
        .find(|stored| {
            stored.entry.direction != entry.direction
                && stored.entry.slate_id == Some(slate_id)
                && stored.entry.transport.as_deref() == Some(SELF.as_str())
        }))
}

/// Ends the other entry of a self-send with the one being cancelled: its outputs are dropped,
/// its inputs unlocked and it moves to `cancelled`, watched under the same kernel when
/// `watch` is given, so a late confirmation restores its outputs too.
pub(crate) fn cancel_partner(
    repos: &mut dyn Repositories,
    partner: &StoredTransaction,
    watch: Option<(Commitment, Height, Height)>,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    if let Some((excess, min_height, ended_at)) = watch {
        record_watch(repos, partner.id, excess, min_height, ended_at)?;
    }
    drop_holdings(repos, partner.id, &partner.entry)?;
    apply_transition(repos, partner.id, TxState::Cancelled, now)
}

/// What a transaction that ends unconfirmed gives up: its unconfirmed outputs are deleted, the
/// inputs it locked become spendable again, and its private context and pending deliveries are
/// dropped.
pub(crate) fn drop_holdings(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    entry: &TransactionEntry,
) -> Result<(), WalletError> {
    for output in repos.outputs_of_transaction(tx_id)? {
        match output.status {
            OutputStatus::Unconfirmed => repos.delete_output(output.commitment())?,
            OutputStatus::Locked => repos.put_output(&OutputRecord {
                status: OutputStatus::Unspent,
                ..output
            })?,
            OutputStatus::Unspent | OutputStatus::Spent => {}
        }
    }
    forget_receive_seen(repos, tx_id)?;
    if let Some(slate_id) = entry.slate_id {
        let participant = match entry.direction {
            TxDirection::Outgoing => SENDER_CONTEXT,
            TxDirection::Incoming => RECEIVER_CONTEXT,
        };
        repos.delete_context(slate_id, participant)?;
        for pending in repos.outbox(OutboxStatus::Pending)? {
            if pending.entry.slate_id == slate_id {
                repos.delete_outbox(pending.id)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Amount;
    use lepic_store::{
        AccountIndex, AccountRecord, CONTEXT_KEY_LEN, ContextKey, MemoryStore, TransactionEntry,
    };

    use super::*;

    fn at() -> Timestamp {
        Timestamp::from_second(1_790_000_000).unwrap()
    }

    fn store_with(state: TxState) -> (MemoryStore, TxId) {
        let store = MemoryStore::new(ContextKey::from_bytes([2; CONTEXT_KEY_LEN]));
        let tx_id = store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(0),
                    label: "default".to_owned(),
                    next_child: 0,
                })?;
                repos.insert_transaction(&TransactionEntry {
                    account: AccountIndex(0),
                    direction: TxDirection::Outgoing,
                    state,
                    slate_id: None,
                    transport: None,
                    amount_credited: Amount::ZERO,
                    amount_debited: Amount::ZERO,
                    fee: None,
                    created_at: at(),
                    updated_at: at(),
                })
            })
            .unwrap();
        (store, tx_id)
    }

    fn state(store: &MemoryStore, tx_id: TxId) -> TxState {
        store
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .unwrap()
            .state
    }

    #[test]
    fn refuses_a_transaction_finalized_after_its_state_was_read() {
        let (store, tx_id) = store_with(TxState::Finalized);

        let result =
            store.write(|repos| cancel_transaction(repos, tx_id, TxState::Sent, None, at()));

        assert!(
            matches!(result, Err(WalletError::ChangedDuringCancel(id)) if id == tx_id),
            "{result:?}"
        );
        assert_eq!(state(&store, tx_id), TxState::Finalized);
    }

    #[test]
    fn cancels_a_transaction_still_in_the_state_that_was_read() {
        let (store, tx_id) = store_with(TxState::Sent);

        let change = store
            .write(|repos| cancel_transaction(repos, tx_id, TxState::Sent, None, at()))
            .unwrap();

        assert_eq!(
            change.first().map(|change| change.to),
            Some(TxState::Cancelled)
        );
    }

    #[test]
    fn a_transaction_cancelled_meanwhile_stays_cancelled_without_an_error() {
        let (store, tx_id) = store_with(TxState::Cancelled);

        let change = store
            .write(|repos| cancel_transaction(repos, tx_id, TxState::Sent, None, at()))
            .unwrap();

        assert_eq!(change, Vec::new());
    }
}
