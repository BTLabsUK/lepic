//! Cancelling a transaction that is not confirmed, as `epic-wallet`'s `cancel_tx` does: its
//! unconfirmed outputs are dropped, the inputs it locked become spendable again, and its private
//! context and pending deliveries are dropped with it.

use jiff::Timestamp;
use lepic_node::NodeApi;
use lepic_store::{
    OutboxStatus, OutputRecord, OutputStatus, ParticipantId, Repositories, TxDirection, TxId,
    TxState, WalletStore,
};
use tracing::{debug, info, instrument};

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::send::SENDER_CONTEXT;
use crate::state::{StateChange, apply_transition, check_transition};
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
    /// Fails with [`WalletError::Locked`], [`WalletError::UnknownTransaction`], or
    /// [`WalletError::Transition`] when the transaction is confirmed or expired.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn cancel(&self, tx_id: TxId) -> Result<(), WalletError> {
        let session = self.session()?;
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

fn cancel_transaction(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
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
