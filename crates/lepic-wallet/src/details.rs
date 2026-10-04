//! What the wallet knows about one stored transaction beyond its log entry.

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{AccountIndex, Repositories, StoredTransaction, TxId, TxState, WalletStore};
use lepic_transport::transport::Destination;
use tracing::instrument;

use crate::account::AccountError;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{final_kernel, legacy_codecs, ttl_cutoff};
use crate::release::release_check;
use crate::wallet::Wallet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    pub transaction: StoredTransaction,
    /// The excess of the final kernel, read from the final slate stored with the transaction, or
    /// for an invoice payer from the stored I2. `None` when neither is stored: before this
    /// wallet finalizes, for a payment taken by receive, and for an output restored by a scan.
    pub kernel_excess: Option<Commitment>,
    /// The height of the output or kernel that confirmed the transaction, or of the restored
    /// output. `None` while it is unconfirmed, and for one confirmed before heights were stored.
    /// Refresh moves it when a reorganisation mines the confirming output at another height. A
    /// transaction confirmed by its kernel keeps the height of its first confirmation: refresh
    /// stops looking up the kernel once it is confirmed, so a reorganisation is not followed.
    pub confirmed_height: Option<Height>,
    /// The other party's address on the transport that carried the slate: where a send or an
    /// invoice was delivered, or where a slate taken from the Epicbox inbox came from. `None`
    /// for a file exchange, a slate the host passed in, a restored output, and a transaction
    /// stored before addresses were.
    pub counterparty: Option<Destination>,
    /// The height from which the slate may no longer be completed, as its stored stages carry
    /// it. `None` when the slate sets none or no stage is stored.
    pub ttl_cutoff_height: Option<Height>,
    /// When this wallet saw the transaction confirmed. `None` unless it is confirmed.
    pub confirmed_at: Option<Timestamp>,
    /// For a finalized or posted send, the height from which a refresh that still misses its
    /// kernel makes it releasable: [`crate::release::RELEASE_AFTER_BLOCKS`] after it was
    /// finalized. `None` for any other transaction, and when its kernel is not known.
    pub releasable_from: Option<Height>,
    /// Whether [`Wallet::release`] may release the send now: a refresh looked its kernel up at
    /// or above `releasable_from` and did not find it. The release asks the node once more.
    pub releasable: bool,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The stored transaction with what [`TransactionDetails`] adds to it. Reads only the
    /// store. Fails with [`WalletError::Locked`] or [`WalletError::UnknownTransaction`].
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn transaction_details(
        &self,
        tx_id: TxId,
    ) -> Result<TransactionDetails, WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        self.blocking(move |_, _| {
            session.store.read(|repos| {
                let entry = repos
                    .transaction(tx_id)?
                    .ok_or(WalletError::UnknownTransaction(tx_id))?;
                details(repos, &codecs, StoredTransaction { id: tx_id, entry })
            })
        })
        .await
    }

    /// Every stored transaction of `account` with its details, newest first: in the reverse of
    /// the order they were stored in. Reads only the store. Fails with [`WalletError::Locked`]
    /// or an [`AccountError::UnknownAccount`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn transactions(
        &self,
        account: AccountIndex,
    ) -> Result<Vec<TransactionDetails>, WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        self.blocking(move |_, _| {
            session.store.read(|repos| {
                if repos.account(account)?.is_none() {
                    return Err(AccountError::UnknownAccount(account).into());
                }
                repos
                    .transactions(account)?
                    .into_iter()
                    .rev()
                    .map(|stored| details(repos, &codecs, stored))
                    .collect()
            })
        })
        .await
    }
}

fn details(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    transaction: StoredTransaction,
) -> Result<TransactionDetails, WalletError> {
    let tx_id = transaction.id;
    let (kernel_excess, ttl_cutoff_height) = match transaction.entry.slate_id {
        Some(slate_id) => (
            final_kernel(repos, codecs, tx_id, slate_id)?.map(|(excess, _)| excess),
            ttl_cutoff(repos, codecs, tx_id, slate_id)?,
        ),
        None => (None, None),
    };
    // A confirmed transaction is final, and only a state change updates an entry, so its last
    // update is the moment it was confirmed.
    let confirmed_at =
        (transaction.entry.state == TxState::Confirmed).then_some(transaction.entry.updated_at);
    let release = release_check(repos, codecs, &transaction)?.ok();
    Ok(TransactionDetails {
        releasable_from: release.map(|check| check.from),
        releasable: release.is_some_and(|check| check.releasable()),
        kernel_excess,
        confirmed_height: repos.confirmed_height(tx_id)?,
        counterparty: repos.counterparty(tx_id)?.map(Destination::new),
        ttl_cutoff_height,
        confirmed_at,
        transaction,
    })
}
