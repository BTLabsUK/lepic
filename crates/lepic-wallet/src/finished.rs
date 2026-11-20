// SPDX-License-Identifier: Apache-2.0
//! The finished payment of a transaction: its final slate as this wallet stored it, legacy V3
//! JSON that `epic-wallet post -i` reads, for the host to carry to a device that posts it.

use lepic_node::NodeApi;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{Repositories, SlateStage, TxDirection, TxId, TxState, WalletStore};
use tracing::instrument;

use crate::error::WalletError;
use crate::finalize::FinalizeError;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The stored S3 of `tx_id`, or the I3 of an invoice this wallet issued. Reads only the
    /// store. Fails with [`FinalizeError::NotPostable`] unless the transaction is `finalized`,
    /// `posted` or `confirmed`, and with [`FinalizeError::Wallet`] carrying
    /// [`WalletError::UnknownTransaction`].
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn finished_payment(&self, tx_id: TxId) -> Result<WireSlate, FinalizeError> {
        let session = self.session()?;
        self.blocking(move |_, _| Ok(session.store.read(|repos| stored_final(repos, tx_id))))
            .await?
    }
}

fn stored_final(repos: &dyn Repositories, tx_id: TxId) -> Result<WireSlate, FinalizeError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let not_finished = FinalizeError::NotPostable {
        tx_id,
        state: entry.state,
    };
    let (TxState::Finalized | TxState::Posted | TxState::Confirmed, Some(slate_id)) =
        (entry.state, entry.slate_id)
    else {
        return Err(not_finished);
    };
    let stage = match entry.direction {
        TxDirection::Outgoing => SlateStage::Standard3,
        TxDirection::Incoming => SlateStage::Invoice3,
    };
    let stored = repos.slate(slate_id, stage)?.ok_or(not_finished)?;
    Ok(WireSlate::binary(MediaType::JSON, stored.bytes))
}
