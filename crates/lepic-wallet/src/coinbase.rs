// SPDX-License-Identifier: Apache-2.0
//! The coinbase a mining node asks the wallet for, as `epic-wallet`'s foreign `build_coinbase`
//! builds it: an output and a kernel for the block reward plus the block's fees, from the
//! wallet's keychain, so a restore from the phrase finds the output again.
//!
//! The output is stored as an unconfirmed coinbase with no transaction, a candidate. A
//! refresh that finds it on chain records the incoming transaction then. A node that mines no
//! block with it passes its key back on the next template and the candidate is replaced; one
//! left unconfirmed [`STALE_AFTER`] blocks below the tip is deleted.

use jiff::Timestamp;
use lepic_crypto::aggsig::{create_secnonce, sign_single, verify_single_from_commit};
use lepic_crypto::{Commitment, CryptoError, PublicKey};
use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, ProofBuilder, ProofError, SwitchCommitment};
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, Repositories, StoreError, TransactionEntry,
    TxDirection, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, instrument};

use crate::account::{self, DEFAULT_ACCOUNT_LABEL};
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::state::StateChange;
use crate::wallet::Wallet;

/// Blocks below the tip after which a candidate no block confirmed is deleted, as
/// `clean_old_unconfirmed` does upstream.
pub const STALE_AFTER: u64 = 50;

/// What the node sends: the fees of the block's transactions, the block's height, and the key
/// of the candidate it built the last template with, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinbaseRequest {
    pub fees: Fee,
    pub height: Height,
    pub key_id: Option<Identifier>,
}

/// The coinbase output and kernel for the block, and the key that blinds the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coinbase {
    pub output: Output,
    pub kernel: TxKernel,
    pub key_id: Identifier,
}

#[derive(Debug, Error)]
pub enum CoinbaseError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("coinbase output could not be built")]
    Output(#[source] ProofError),
    #[error("coinbase kernel could not be signed")]
    Signing(#[source] CryptoError),
    #[error("block height {0} leaves no room for the coinbase lock height")]
    Height(Height),
}

impl From<StoreError> for CoinbaseError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Builds the coinbase for the block `request` describes on the default account and stores
    /// its output as a candidate: unconfirmed, with no transaction, and locked until the
    /// network's coinbase maturity has passed above the block.
    ///
    /// The output takes the key the node passed back when that key blinds only candidates of
    /// this wallet, which this one replaces; any other key, or none, takes the account's next
    /// output key. The kernel is checked against its excess before it is returned.
    ///
    /// Fails with [`WalletError::Locked`] inside [`CoinbaseError::Wallet`] when the wallet is
    /// locked, and with [`WalletError::RestoreScanRequired`] on a database rebuilt from the
    /// seed before a scan from genesis completed. Nothing is stored on failure.
    #[instrument(
        name = "build_coinbase",
        skip_all,
        fields(wallet = %self.config().name, height = %request.height)
    )]
    pub async fn build_coinbase(
        &self,
        request: CoinbaseRequest,
    ) -> Result<Coinbase, CoinbaseError> {
        let session = self.session()?;
        let params = self.config().network.params();
        self.blocking(move |ports, _| {
            Ok(session.store.write(|repos| {
                let account = account::account_by_label(repos, DEFAULT_ACCOUNT_LABEL)?;
                let key_id = match request.key_id {
                    Some(key_id) if replace_candidates(repos, account.index, key_id)? => key_id,
                    _ => account::next_output_key(repos, account.index)?,
                };
                let value = params.coinbase_value(request.fees, request.height);
                let coinbase = build(&session.keychain, value, key_id, &mut **ports.rng.lock())?;
                repos.put_output(&OutputRecord {
                    id: coinbase.output.identifier(),
                    key_id: KeyId(key_id.to_bytes()),
                    account: account.index,
                    amount: value,
                    status: OutputStatus::Unconfirmed,
                    height: request.height,
                    lock_height: params
                        .coinbase_lock_height(request.height)
                        .map_err(|_| CoinbaseError::Height(request.height))?,
                    mmr_index: None,
                    tx: None,
                })?;
                debug!(amount = %value, "coinbase built");
                Ok::<_, CoinbaseError>(coinbase)
            }))
        })
        .await?
    }
}

/// The coinbase output for `value` at `key_id`, and the kernel signed by its excess over the
/// coinbase feature message, as upstream `reward::output` builds them.
pub fn build(
    keychain: &lepic_keychain::Keychain,
    value: Amount,
    key_id: Identifier,
    rng: &mut (impl rand_core::CryptoRng + ?Sized),
) -> Result<Coinbase, CoinbaseError> {
    let switch = SwitchCommitment::Regular;
    let amount = value.value();
    let builder = ProofBuilder::new(keychain).map_err(CoinbaseError::Output)?;
    let plain = create_output(keychain, &builder, amount, &key_id, switch)
        .map_err(CoinbaseError::Output)?;
    let output = Output::new(OutputFeatures::Coinbase, plain.commitment, plain.proof);
    let over_value = Commitment::commit_value(amount).map_err(CoinbaseError::Signing)?;
    let excess =
        Commitment::sum(&[output.commitment], &[over_value]).map_err(CoinbaseError::Signing)?;
    let key = keychain
        .derive_key(amount, &key_id, switch)
        .map_err(WalletError::from)?;
    let public = PublicKey::from_secret_key(&key).map_err(CoinbaseError::Signing)?;
    let nonce = create_secnonce(rng).map_err(CoinbaseError::Signing)?;
    let features = KernelFeatures::Coinbase;
    let message = features.signature_message();
    let signature =
        sign_single(&message, &key, &nonce, Some(&public)).map_err(CoinbaseError::Signing)?;
    verify_single_from_commit(&signature, &message, &excess).map_err(CoinbaseError::Signing)?;
    Ok(Coinbase {
        output,
        kernel: TxKernel::new(features, excess, signature),
        key_id,
    })
}

/// An output a coinbase built and no block has confirmed yet.
pub(crate) fn is_candidate(output: &OutputRecord) -> bool {
    output.status == OutputStatus::Unconfirmed
        && output.tx.is_none()
        && output.id.features == OutputFeatures::Coinbase
}

/// Deletes the candidates of `account` that `key_id` blinds, and says whether the key may be
/// used again: some output has it, and every one is such a candidate. A key that blinds
/// anything else, or nothing this wallet stored, is not reused.
fn replace_candidates(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    key_id: Identifier,
) -> Result<bool, StoreError> {
    let key = KeyId(key_id.to_bytes());
    let mut candidates = Vec::new();
    for accounts in repos.accounts()? {
        for output in repos.outputs(accounts.index, None)? {
            if output.key_id != key {
                continue;
            }
            if output.account != account || !is_candidate(&output) {
                return Ok(false);
            }
            candidates.push(*output.commitment());
        }
    }
    for commitment in &candidates {
        repos.delete_output(commitment)?;
    }
    Ok(!candidates.is_empty())
}

/// Records the incoming transaction of a candidate a block confirmed at `height`, links the
/// output to it, unspent until `lock_height`, and returns the change for the new entry.
pub(crate) fn confirm(
    repos: &mut dyn Repositories,
    output: &mut OutputRecord,
    height: Height,
    lock_height: Height,
    now: Timestamp,
) -> Result<StateChange, StoreError> {
    let tx_id = repos.insert_transaction(&TransactionEntry {
        account: output.account,
        direction: TxDirection::Incoming,
        state: TxState::Confirmed,
        slate_id: None,
        transport: None,
        amount_credited: output.amount,
        amount_debited: Amount::ZERO,
        fee: None,
        created_at: now,
        updated_at: now,
    })?;
    repos.set_confirmed_height(tx_id, height)?;
    output.tx = Some(tx_id);
    output.status = OutputStatus::Unspent;
    output.height = height;
    output.lock_height = lock_height;
    debug!(height = %height, "coinbase confirmed");
    Ok(StateChange {
        tx_id,
        from: TxState::Confirmed,
        to: TxState::Confirmed,
    })
}

/// Deletes the candidates built for a block more than [`STALE_AFTER`] below `tip`, which no
/// block confirmed, and returns how many.
pub(crate) fn delete_stale(repos: &mut dyn Repositories, tip: Height) -> Result<u64, StoreError> {
    let Some(below) = tip.value().checked_sub(STALE_AFTER) else {
        return Ok(0);
    };
    let mut deleted = 0u64;
    for account in repos.accounts()? {
        for output in repos.outputs(account.index, Some(OutputStatus::Unconfirmed))? {
            if is_candidate(&output) && output.height.value() > 0 && output.height.value() < below {
                repos.delete_output(output.commitment())?;
                deleted = deleted.saturating_add(1);
            }
        }
    }
    if deleted > 0 {
        debug!(deleted, "stale coinbase candidates deleted");
    }
    Ok(deleted)
}
