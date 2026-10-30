// SPDX-License-Identifier: Apache-2.0
//! Sends to the wallet itself, to split its outputs or merge them into one, as
//! `epic-wallet send -m self` does through its own foreign API: the S1 is built, received into
//! the same account and finalized in one store transaction, then posted. No transport carries
//! the slate, so it never goes to the wallet's own Epicbox address.

use std::num::NonZeroUsize;

use lepic_crypto::Commitment;
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::amount::Amount;
use lepic_slate::codec::EncodeContext;
use lepic_store::{OutputRecord, StoreError, TxId, WalletStore};
use lepic_transport::transport::TransportId;
use thiserror::Error;
use tracing::field::Empty;
use tracing::{Span, info, instrument};

use crate::account::AccountError;
use crate::error::WalletError;
use crate::event::{Event, SelfSentTransaction};
use crate::finalize::{FinalizeError, finalize_own};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::{ReceiveError, receive_own};
use crate::refresh::with_spend_confirmations;
use crate::selection::{
    self, Selection, SelectionError, SelectionOptions, SelectionRequest, SelectionStrategy,
    SelfSendShape,
};
use crate::send::{
    S1Randomness, S1Storage, SendError, SendRequest, block_header_version, spendable_here, store_s1,
};
use crate::wallet::Wallet;

/// The transport both entries of a self-send record.
pub const SELF: TransportId = TransportId::new("self");

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SelfSendError {
    /// Selecting or building failed, or the wallet is locked; nothing was stored.
    #[error("self-send could not be built")]
    Send(#[from] SendError),
    /// The wallet refused its own slate; nothing was stored.
    #[error("self-send could not be received")]
    Receive(#[from] ReceiveError),
    /// [`FinalizeError::NotPosted`] when it was stored finalized but the node did not take it;
    /// [`Wallet::post`] posts it again. Any other variant stored nothing.
    #[error("self-send could not be finalized or posted")]
    Finalize(#[from] FinalizeError),
}

impl From<StoreError> for SelfSendError {
    fn from(error: StoreError) -> Self {
        Self::from(WalletError::Store(error))
    }
}

impl From<WalletError> for SelfSendError {
    fn from(error: WalletError) -> Self {
        Self::Send(SendError::Wallet(error))
    }
}

/// A self-send that was stored, finalized and posted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSent {
    /// The outgoing entry: it spent the inputs and holds the change.
    pub tx_id: TxId,
    /// The incoming entry: it holds the output of `selection.amount`.
    pub received_tx_id: TxId,
    pub selection: Selection,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Spends what [`selection::select_self_send`] chooses for `options` and `shape` into
    /// outputs of this wallet, and posts the transaction with `propagation`. It is stored as an
    /// outgoing entry that spent the inputs and holds the change, and an incoming entry that
    /// holds the output of the amount, both over [`SELF`]; it confirms as any send does.
    /// It raises [`Event::SelfSent`], never [`Event::Received`]: nothing was received from
    /// anyone. [`Wallet::estimate_self_send`] tells what it will spend and pay.
    ///
    /// Fails, storing nothing, as [`Wallet::send`] fails before it delivers, or with
    /// [`SelfSendError::Receive`] or [`SelfSendError::Finalize`] when the wallet's own slate
    /// does not check. Fails with [`FinalizeError::NotPosted`] when it was stored finalized but
    /// the node did not take it: the inputs stay locked until [`Wallet::post`] posts it again
    /// or [`Wallet::cancel`] cancels the outgoing entry. Fails with
    /// [`FinalizeError::InputsSpentByOwnTransaction`] when the node refused it because another
    /// send of this wallet that the chain holds spent its inputs, and with
    /// [`FinalizeError::InputsSpentElsewhere`] when another wallet did: both entries are then
    /// cancelled, as [`Wallet::post`] describes.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = Empty))]
    pub async fn self_send(
        &self,
        options: SelectionOptions,
        shape: SelfSendShape,
        propagation: Propagation,
    ) -> Result<SelfSent, SelfSendError> {
        self.self_send_chosen(options, propagation, move |outputs, request| {
            selection::select_self_send(outputs, request, shape)
        })
        .await
    }

    /// Spends exactly the outputs `commitments` names into the outputs `shape` asks for, as
    /// [`Wallet::self_send`] does: [`SelfSendShape::Consolidate`] makes one, and
    /// [`SelfSendShape::Split`] makes that many of nearly equal value, so the wallet can keep
    /// its number of coins. It posts it with `propagation`. Nothing else is locked. A payment that was cancelled here, such as an
    /// invoice payment whose I2 the issuer still holds, can no longer be mined once its inputs
    /// are spent this way.
    ///
    /// Fails, storing nothing, with [`SelectionError::NoOutputsNamed`] or
    /// [`SelectionError::NamedOutputUnavailable`] when an output named is unknown, not unspent
    /// with `options.minimum_confirmations`, of another account or named twice, with
    /// [`SelectionError::NotEnoughFunds`] when their value less the fee leaves less than one
    /// base unit for each output, and otherwise as
    /// [`Wallet::self_send`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = Empty))]
    pub async fn spend_outputs_to_self(
        &self,
        options: SelectionOptions,
        commitments: Vec<Commitment>,
        shape: SelfSendShape,
        propagation: Propagation,
    ) -> Result<SelfSent, SelfSendError> {
        self.self_send_chosen(options, propagation, move |outputs, request| {
            selection::select_named(outputs, request, &commitments, shape)
        })
        .await
    }

    async fn self_send_chosen(
        &self,
        options: SelectionOptions,
        propagation: Propagation,
        choose: impl Fn(&[OutputRecord], &SelectionRequest) -> Result<Selection, SelectionError>
        + Send
        + 'static,
    ) -> Result<SelfSent, SelfSendError> {
        let session = self.session()?;
        let tip = self
            .ports()
            .node
            .get_tip()
            .await
            .map_err(SendError::Node)?
            .height;
        self.check_plausible_tip(&session, tip).await?;
        let network = self.config().network;
        let base_fee = network.params().default_base_fee();
        let account = options.account;
        let stored = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                let mut rng = ports.rng.lock();
                let randomness = match S1Randomness::draw(&mut **rng) {
                    Ok(randomness) => randomness,
                    Err(error) => return Ok(Err(SelfSendError::from(SendError::from(error)))),
                };
                Ok(session.store.write(|repos| {
                    if repos.account(options.account)?.is_none() {
                        return Err(SelfSendError::from(WalletError::from(
                            AccountError::UnknownAccount(options.account),
                        )));
                    }
                    let outputs = spendable_here(
                        &session.keychain,
                        repos.outputs(options.account, None)?,
                        &options.exclude_outputs,
                    );
                    let request = with_spend_confirmations(
                        repos,
                        options.request(Amount::ZERO, tip, base_fee),
                    )?;
                    let chosen = choose(&outputs, &request).map_err(SendError::from)?;
                    let request = SendRequest {
                        minimum_confirmations: options.minimum_confirmations,
                        max_outputs: options.max_outputs,
                        change_outputs: NonZeroUsize::new(chosen.change.len())
                            .unwrap_or(NonZeroUsize::MIN),
                        strategy: SelectionStrategy::All,
                        ..SendRequest::new(options.account, chosen.amount)
                    };
                    let s1 = store_s1(
                        repos,
                        &session.keychain,
                        &S1Storage {
                            network,
                            now,
                            tip,
                            transport: SELF,
                        },
                        &request,
                        chosen.clone(),
                        randomness,
                    )?;
                    let context = EncodeContext {
                        block_header_version: block_header_version(network, tip),
                    };
                    let (received_tx_id, s2) = receive_own(
                        repos,
                        &session,
                        network,
                        options.account,
                        &s1.slate,
                        SELF,
                        context,
                        &mut **rng,
                        now,
                    )?;
                    let finalized = finalize_own(repos, &session.keychain, network, tip, now, &s2)?;
                    Ok((chosen, received_tx_id, finalized))
                }))
            })
            .await??;
        let (chosen, received_tx_id, finalized) = stored;
        Span::current().record("tx_id", finalized.tx_id.0);
        info!("self-send finalized");
        self.emit(Event::SelfSent(SelfSentTransaction {
            tx_id: finalized.tx_id,
            received_tx_id,
            account,
            amount: chosen.amount,
        }));
        if let Some(change) = finalized.change {
            self.emit(change.into());
        }
        self.push(finalized.tx_id, &finalized.finalized, propagation)
            .await?;
        Ok(SelfSent {
            tx_id: finalized.tx_id,
            received_tx_id,
            selection: chosen,
        })
    }
}
