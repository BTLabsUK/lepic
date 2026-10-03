//! What the wallet knows about one stored transaction beyond its log entry.

use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{Repositories, StoredTransaction, TxId, WalletStore};
use tracing::instrument;

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{final_kernel, legacy_codecs};
use crate::wallet::Wallet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    pub transaction: StoredTransaction,
    /// The excess of the final kernel, read from the final slate stored with the transaction.
    /// `None` when no final slate is stored, as for one not yet finalized here, one the peer
    /// finalized, or an output restored by a scan.
    pub kernel_excess: Option<Commitment>,
    /// The height of the output or kernel that confirmed the transaction, or of the restored
    /// output. `None` while it is unconfirmed, and for one confirmed before heights were stored.
    pub confirmed_height: Option<Height>,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The stored transaction with its kernel excess and confirmation height. Reads only the
    /// store. Fails with [`WalletError::Locked`] or [`WalletError::UnknownTransaction`].
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn transaction_details(
        &self,
        tx_id: TxId,
    ) -> Result<TransactionDetails, WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        self.blocking(move |_, _| session.store.read(|repos| details(repos, &codecs, tx_id)))
            .await
    }
}

fn details(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<TransactionDetails, WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let kernel_excess = match entry.slate_id {
        Some(slate_id) => final_kernel(repos, codecs, tx_id, slate_id)?.map(|(excess, _)| excess),
        None => None,
    };
    Ok(TransactionDetails {
        transaction: StoredTransaction { id: tx_id, entry },
        kernel_excess,
        confirmed_height: repos.confirmed_height(tx_id)?,
    })
}
