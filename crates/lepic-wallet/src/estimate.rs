// SPDX-License-Identifier: Apache-2.0
//! Fee estimates: the selection a send would make, without the send.

use lepic_node::NodeApi;
use lepic_primitives::amount::Amount;
use lepic_store::{OutputRecord, WalletStore};
use tracing::{debug, instrument};

use crate::account::AccountError;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::with_spend_confirmations;
use crate::selection::{
    self, Selection, SelectionError, SelectionOptions, SelectionRequest, SelfSendShape,
};
use crate::send::{SendError, spendable_here};
use crate::wallet::Wallet;

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The inputs, change and fee of a send of `amount` with `options`, chosen as
    /// [`Wallet::send`] chooses them, with nothing locked, derived or stored. A send with the
    /// same options at the same tip, with no outputs changed in between, takes the same inputs
    /// and charges the same fee.
    ///
    /// Asks the node for its tip, which decides the outputs that may be spent. Fails with
    /// [`SendError::Wallet`] carrying [`WalletError::Locked`], an unknown account or
    /// [`WalletError::Implausible`], with [`SendError::Node`], or with the
    /// [`SendError::Selection`] error the send would fail with.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn estimate_fee(
        &self,
        amount: Amount,
        options: SelectionOptions,
    ) -> Result<Selection, SendError> {
        self.estimate(options, amount, selection::select).await
    }

    /// The inputs, outputs and fee of [`Wallet::self_send`] with `options` and `shape`, chosen
    /// as it chooses them, with nothing locked, derived or stored. Fails as
    /// [`Wallet::estimate_fee`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn estimate_self_send(
        &self,
        options: SelectionOptions,
        shape: SelfSendShape,
    ) -> Result<Selection, SendError> {
        self.estimate(options, Amount::ZERO, move |outputs, request| {
            selection::select_self_send(outputs, request, shape)
        })
        .await
    }

    /// The largest amount a send with `options` can pay now, with the inputs, change and fee
    /// of that send, as [`selection::select_max`] finds it. [`Wallet::send`] of the returned
    /// amount with the same options at the same tip charges the returned fee.
    ///
    /// Fails as [`Wallet::estimate_fee`] does, with [`SelectionError::NotEnoughFunds`] when
    /// the spendable outputs cannot pay any amount and its fee.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn estimate_max(&self, options: SelectionOptions) -> Result<Selection, SendError> {
        self.estimate(options, Amount::ZERO, selection::select_max)
            .await
    }

    async fn estimate(
        &self,
        options: SelectionOptions,
        amount: Amount,
        choose: impl Fn(&[OutputRecord], &SelectionRequest) -> Result<Selection, SelectionError>
        + Send
        + 'static,
    ) -> Result<Selection, SendError> {
        let session = self.session()?;
        let (tip, _) = self.stage_tip(&session, SendError::Node).await?;
        let base_fee = self.config().network.params().default_base_fee();
        let selection = self
            .blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    if repos.account(options.account)?.is_none() {
                        return Err(SendError::from(WalletError::from(
                            AccountError::UnknownAccount(options.account),
                        )));
                    }
                    let outputs = spendable_here(
                        &session.keychain,
                        repos.outputs(options.account, None)?,
                        &options.exclude_outputs,
                    );
                    let request =
                        with_spend_confirmations(repos, options.request(amount, tip, base_fee))?;
                    Ok(choose(&outputs, &request)?)
                }))
            })
            .await??;
        debug!(height = %tip, "fee estimated");
        Ok(selection)
    }
}
