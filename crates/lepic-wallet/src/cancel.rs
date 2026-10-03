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
    OutboxStatus, OutputRecord, OutputStatus, ParticipantId, Repositories, TxDirection, TxId,
    TxState, WalletStore,
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
    /// kernel is looked up first; the node must be reachable to cancel one.
    ///
    /// Fails with [`WalletError::Locked`], [`WalletError::UnknownTransaction`],
    /// [`WalletError::Transition`] when the transaction is posted, confirmed or expired,
    /// [`WalletError::OnChain`] when the node holds the kernel of a finalized one, and
    /// [`WalletError::Node`] when that lookup fails.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn cancel(&self, tx_id: TxId) -> Result<(), WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let lookup = {
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
                    .write(|repos| cancel_transaction(repos, tx_id, now))
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

/// The kernel of a finalized transaction, to look up before it is cancelled.
fn finalized_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<Option<(Commitment, Height)>, WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let Some(slate_id) = entry.slate_id.filter(|_| entry.state == TxState::Finalized) else {
        return Ok(None);
    };
    Ok(final_kernel(repos, codecs, tx_id, slate_id)?)
}

fn cancel_transaction(
    repos: &mut dyn Repositories,
    tx_id: TxId,
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
    apply_transition(repos, tx_id, TxState::Cancelled, now)
}
