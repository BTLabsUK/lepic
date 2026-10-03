//! Cancelling a transaction that is not confirmed, as `epic-wallet`'s `cancel_tx` does: its
//! unconfirmed outputs are dropped, the inputs it locked become spendable again, and its private
//! context and pending deliveries are dropped with it. A posted transaction is not cancelled, nor
//! is a finalized one whose kernel the node already holds.

use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    OutboxStatus, OutputRecord, OutputStatus, ParticipantId, Repositories, TransactionEntry,
    TxDirection, TxId, TxState, WalletStore,
};
use tracing::{debug, info, instrument};

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{final_kernel, legacy_codecs};
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
    /// one store transaction. Cancelling a cancelled transaction changes nothing.
    ///
    /// A slate already delivered is not recalled; if the peer still completes it, the
    /// transaction can no longer be finalized here.
    ///
    /// A finalized transaction may have reached the node even though posting it failed, so its
    /// kernel is looked up first; the node must be reachable to cancel one. A posted
    /// transaction, which includes one the node's pool answered it already holds, counts as on
    /// chain and is not cancelled.
    ///
    /// Fails with [`WalletError::Locked`], [`WalletError::UnknownTransaction`],
    /// [`WalletError::Transition`] when the transaction is posted, confirmed or expired,
    /// [`WalletError::OnChain`] when the node holds the kernel of a finalized one,
    /// [`WalletError::Node`] when that lookup fails, and [`WalletError::ChangedDuringCancel`]
    /// when another operation moved the transaction on after its state was read; cancelling
    /// again then decides from the new state.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn cancel(&self, tx_id: TxId) -> Result<(), WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let (observed, lookup) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                session
                    .store
                    .read(|repos| finalized_kernel(repos, &codecs, tx_id))
            })
            .await?
        };
        if let Some((excess, min_height)) = lookup {
            let kernel = self
                .ports()
                .node
                .get_kernel(&excess, Some(min_height), None)
                .await
                .map_err(WalletError::Node)?;
            if let Some(kernel) = kernel {
                debug!(height = %kernel.height, "kernel found on chain");
                return Err(WalletError::OnChain(tx_id));
            }
        }
        let change = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session
                    .store
                    .write(|repos| cancel_transaction(repos, tx_id, observed, now))
            })
            .await?;
        match change {
            Some(change) => {
                info!("transaction cancelled");
                self.emit(change.into());
            }
            None => debug!("transaction already cancelled"),
        }
        Ok(())
    }
}

/// The state a cancel starts from, and the kernel of a finalized transaction, to look up
/// before it is cancelled.
fn finalized_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<(TxState, Option<(Commitment, Height)>), WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let Some(slate_id) = entry.slate_id.filter(|_| entry.state == TxState::Finalized) else {
        return Ok((entry.state, None));
    };
    Ok((entry.state, final_kernel(repos, codecs, tx_id, slate_id)?))
}

/// Cancels the transaction if it is still in the state `observed`, the one the kernel lookup
/// was decided on. A transaction finalized or posted since may be on its way to the chain.
fn cancel_transaction(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    observed: TxState,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
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
        return Ok(None);
    }
    if entry.state != observed {
        return Err(WalletError::ChangedDuringCancel(tx_id));
    }
    drop_holdings(repos, tx_id, &entry)?;
    apply_transition(repos, tx_id, TxState::Cancelled, now)
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

        let result = store.write(|repos| cancel_transaction(repos, tx_id, TxState::Sent, at()));

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
            .write(|repos| cancel_transaction(repos, tx_id, TxState::Sent, at()))
            .unwrap();

        assert_eq!(change.map(|change| change.to), Some(TxState::Cancelled));
    }

    #[test]
    fn a_transaction_cancelled_meanwhile_stays_cancelled_without_an_error() {
        let (store, tx_id) = store_with(TxState::Cancelled);

        let change = store
            .write(|repos| cancel_transaction(repos, tx_id, TxState::Sent, at()))
            .unwrap();

        assert_eq!(change, None);
    }
}
