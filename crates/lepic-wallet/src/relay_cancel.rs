// SPDX-License-Identifier: Apache-2.0
//! Cancelling a transaction on its relay (Epicbox 3.1.0), and applying a cancellation the relay
//! reports.
//!
//! The sender of an S1, or the issuer of an I1, files it on the relay under a fresh relay
//! transaction id, and the receiver answers under the same id. Either party may then cancel
//! the transaction on the relay: the relay refuses further slates under the id and tells the
//! other party. The other party's wallet logs the report and changes nothing: a relay is not
//! the counterparty, so only the counterparty's own word or the chain ends a transaction.
//!
//! The id of each slate is kept in two settings, written before the slate is first posted, so a
//! retry posts under the same id and a reported id finds its slate:
//!
//! - [`TXID_PREFIX`] followed by the hyphenated slate id, valued with the relay transaction id;
//! - [`TXID_SLATE_PREFIX`] followed by the relay transaction id, valued with the hyphenated slate
//!   id.
//!
//! The first id written for a slate is kept. A transaction restored from the seed or imported
//! from `epic-wallet` has none, and is cancelled on this wallet only.

use std::sync::Arc;

use lepic_node::NodeApi;
use lepic_slate::model::SlateId;
use lepic_store::{Repositories, StoreError, TxDirection, TxId, TxState, WalletStore};
use lepic_transport::error::TransportError;
use lepic_transport::method::Method;
use lepic_transport::transport::{Outbound, RelayCancelOutcome, RelayTxId};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::state::is_final;
use crate::wallet::Wallet;
use lepic_primitives::error_chain::ErrorChain;

/// Prefix of the settings that hold the relay transaction id of a slate, keyed by its
/// hyphenated slate id.
pub const TXID_PREFIX: &str = "epicbox.txid.";

/// Prefix of the settings that hold the slate of a relay transaction id, keyed by the id and
/// valued with the hyphenated slate id.
pub const TXID_SLATE_PREFIX: &str = "epicbox.txid_slate.";

/// What the relay did with [`Wallet::relay_cancel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelayCancelResult {
    /// The relay cancelled the transaction and tells the other party.
    Cancelled,
    /// The relay took no action: it does not know the transaction, or this wallet's address is
    /// not one of its parties. It does not say which.
    NotFoundOrNotParticipant,
    /// The relay, or the method the wallet uses, cannot cancel transactions.
    Unsupported,
    /// The transaction was never filed on a relay under an id, so there is nothing to cancel
    /// there.
    NoRelayId,
}

/// What [`Wallet::end_on_relay`] did for one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayEnd {
    /// Nothing was asked: the transaction is filed under no relay id, went out on a method this
    /// wallet does not hold, or its filing could not be read.
    NotAsked,
    /// The relay, or the method, answered.
    Answered(RelayCancelResult),
    /// The relay could not be reached or answered with an error.
    Failed,
}

/// Why [`Wallet::relay_cancel`] failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayCancelError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    /// The relay could not be asked; nothing is known about the cancellation.
    #[error("relay cancellation failed")]
    Transport(#[source] TransportError),
}

impl From<StoreError> for RelayCancelError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// What a cancellation the relay reported found, from [`Wallet::apply_relay_cancellation`].
/// Each outcome means the report is settled and may be acknowledged; none changes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayCancelApplied {
    /// No transaction of this wallet is filed under the id.
    Unknown,
    /// The transaction filed under the id stays as it is.
    Kept { tx_id: TxId },
}

fn txid_setting(slate_id: Uuid) -> String {
    format!("{TXID_PREFIX}{slate_id}")
}

fn slate_setting(txid: &RelayTxId) -> String {
    format!("{TXID_SLATE_PREFIX}{txid}")
}

/// The relay transaction id the slate `slate_id` is filed under, if any.
pub(crate) fn stored_txid(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<RelayTxId>, StoreError> {
    Ok(repos.setting(&txid_setting(slate_id))?.map(RelayTxId::new))
}

/// Files the slate `slate_id` under `txid`, unless it is filed under an id already, and returns
/// the id it is filed under. An id another slate is filed under is not taken: `None`.
pub(crate) fn store_txid(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    txid: &RelayTxId,
) -> Result<Option<RelayTxId>, StoreError> {
    if let Some(stored) = stored_txid(repos, slate_id)? {
        return Ok(Some(stored));
    }
    let reverse = slate_setting(txid);
    if repos.setting(&reverse)?.is_some() {
        return Ok(None);
    }
    repos.put_setting(&txid_setting(slate_id), txid.as_str())?;
    repos.put_setting(&reverse, &slate_id.to_string())?;
    Ok(Some(txid.clone()))
}

/// The slate filed under `txid`, if any.
fn slate_of_txid(repos: &dyn Repositories, txid: &RelayTxId) -> Result<Option<Uuid>, StoreError> {
    Ok(repos
        .setting(&slate_setting(txid))?
        .and_then(|value| Uuid::parse_str(&value).ok()))
}

/// Whether the transaction of `slate_id` is filed on a relay and can still be cancelled there.
pub(crate) fn relay_cancellable(
    repos: &dyn Repositories,
    slate_id: Option<Uuid>,
    state: TxState,
) -> Result<bool, StoreError> {
    let Some(slate_id) = slate_id else {
        return Ok(false);
    };
    if is_final(state) || state == TxState::Posted {
        return Ok(false);
    }
    Ok(stored_txid(repos, slate_id)?.is_some())
}

/// The transaction of the slate `slate_id`, sent or received.
fn transaction_of(repos: &dyn Repositories, slate_id: Uuid) -> Result<Option<TxId>, StoreError> {
    for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
        if let Some(stored) = repos.transaction_by_slate(slate_id, direction)? {
            return Ok(Some(stored.id));
        }
    }
    Ok(None)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Cancels the transaction `tx_id` on the relay of `method`, as one of its parties: the
    /// relay refuses further slates filed under it and tells the other party. Nothing changes
    /// in this wallet; [`Wallet::cancel`] cancels the transaction here. Other transactions the
    /// relay reports as cancelled in its answer are taken as
    /// [`Wallet::apply_relay_cancellation`] takes them: logged, nothing changed.
    ///
    /// Returns [`RelayCancelResult::NoRelayId`] for a transaction not filed under a relay id, and
    /// [`RelayCancelResult::Unsupported`] when `method` or its relay cannot cancel.
    ///
    /// Fails with [`RelayCancelError::Wallet`] carrying [`WalletError::Locked`] or
    /// [`WalletError::UnknownTransaction`], or as the store does, and with
    /// [`RelayCancelError::Transport`] when the relay could not be asked.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = %method.id(), tx_id = %tx_id))]
    pub async fn relay_cancel(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
    ) -> Result<RelayCancelResult, RelayCancelError> {
        let session = self.session()?;
        let txid = self
            .blocking(move |_, _| {
                session.store.read(|repos| -> Result<_, WalletError> {
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(WalletError::UnknownTransaction(tx_id))?;
                    match entry.slate_id {
                        Some(slate_id) => Ok(stored_txid(repos, slate_id)?),
                        None => Ok(None),
                    }
                })
            })
            .await?;
        let Some(txid) = txid else {
            return Ok(RelayCancelResult::NoRelayId);
        };
        let outcome = self
            .cancel_txid_on_relay(method, &txid)
            .await
            .map_err(RelayCancelError::Transport)?;
        info!(outcome = ?outcome, "relay cancellation asked");
        Ok(outcome)
    }

    /// Cancels the relay transaction id `txid` on the relay of `method`, and logs the other
    /// cancellations the relay reports in its answer.
    async fn cancel_txid_on_relay(
        &self,
        method: &Arc<dyn Method>,
        txid: &RelayTxId,
    ) -> Result<RelayCancelResult, TransportError> {
        let Some(relay) = method.relay_cancel() else {
            return Ok(RelayCancelResult::Unsupported);
        };
        let report = relay.cancel_on_relay(txid).await?;
        for other in &report.other_cancelled {
            if let Err(error) = self.apply_relay_cancellation(other).await {
                warn!(error = %ErrorChain(&error), "relay cancellation not applied");
            }
        }
        let outcome = match report.outcome {
            RelayCancelOutcome::Cancelled => RelayCancelResult::Cancelled,
            RelayCancelOutcome::NotFoundOrNotParticipant => {
                RelayCancelResult::NotFoundOrNotParticipant
            }
            _ => RelayCancelResult::Unsupported,
        };
        Ok(outcome)
    }

    /// Cancels the transaction `tx_id` here as [`Wallet::cancel`] does and, when this call
    /// cancelled it, on its relay as well, as [`Wallet::relay_cancel`] does over the method the
    /// transaction went out on. The relay is asked only after the local cancel succeeded and
    /// only when it changed the transaction, so a repeat asks it nothing.
    ///
    /// The relay never fails this call: a transaction filed under no relay id, or sent over a
    /// method this wallet does not hold, asks nothing, and a relay that cannot be reached, that
    /// answers with an error or that cannot cancel is logged.
    ///
    /// Fails as [`Wallet::cancel`] fails.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn cancel_with_relay(&self, tx_id: TxId) -> Result<(), WalletError> {
        if self.cancel_inner(tx_id).await? {
            self.end_on_relay(tx_id).await;
        }
        Ok(())
    }

    /// Cancels the transaction `tx_id`, which this wallet just ended, on the relay it is filed
    /// on, if any. Holds no lock and no store transaction while the relay is asked, and logs
    /// every failure instead of returning it; the answer says what happened, so a caller asking
    /// for several transactions can stop when the relay cannot help.
    pub(crate) async fn end_on_relay(&self, tx_id: TxId) -> RelayEnd {
        let filed = match self.relay_filing(tx_id).await {
            Ok(filed) => filed,
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "relay cancellation not asked");
                return RelayEnd::NotAsked;
            }
        };
        let Some((transport, txid)) = filed else {
            return RelayEnd::NotAsked;
        };
        let Some(method) = self
            .ports()
            .methods
            .as_ref()
            .and_then(|methods| methods.method_named(&transport))
        else {
            debug!(tx_id = %tx_id, transport = %transport, "relay cancellation not asked: no such method");
            return RelayEnd::NotAsked;
        };
        match self.cancel_txid_on_relay(&method, &txid).await {
            Ok(outcome) => {
                info!(tx_id = %tx_id, transport = %transport, outcome = ?outcome, "relay cancellation asked");
                RelayEnd::Answered(outcome)
            }
            Err(error) => {
                warn!(tx_id = %tx_id, transport = %transport, error = %ErrorChain(&error), "relay cancellation failed");
                RelayEnd::Failed
            }
        }
    }

    /// The transport and relay transaction id the transaction `tx_id` is filed under, when it
    /// went out on a transport and is filed under an id.
    async fn relay_filing(&self, tx_id: TxId) -> Result<Option<(String, RelayTxId)>, WalletError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            session.store.read(|repos| -> Result<_, WalletError> {
                let Some(entry) = repos.transaction(tx_id)? else {
                    return Ok(None);
                };
                let (Some(transport), Some(slate_id)) = (entry.transport, entry.slate_id) else {
                    return Ok(None);
                };
                Ok(stored_txid(repos, slate_id)?.map(|txid| (transport, txid)))
            })
        })
        .await
    }

    /// Takes a cancellation the relay reported for the relay transaction id `txid`: the relay
    /// says the other party cancelled the transaction filed under it. The report is logged and
    /// changes nothing: no state, no mark, no event. Only the counterparty's own notice or the
    /// chain moves a transaction, and the relay is neither.
    ///
    /// Each result settles the report, so the caller acknowledges it to the relay. Fails with
    /// the wallet locked or as the store does; the caller keeps the report unacknowledged and
    /// takes it again.
    #[instrument(skip_all, fields(wallet = %self.config().name, txid = %txid))]
    pub async fn apply_relay_cancellation(
        &self,
        txid: &RelayTxId,
    ) -> Result<RelayCancelApplied, WalletError> {
        let session = self.session()?;
        let id = txid.clone();
        let found = self
            .blocking(move |_, _| {
                session.store.read(|repos| -> Result<_, WalletError> {
                    let Some(slate_id) = slate_of_txid(repos, &id)? else {
                        return Ok(None);
                    };
                    Ok(transaction_of(repos, slate_id)?)
                })
            })
            .await?;
        let Some(tx_id) = found else {
            info!("relay cancellation for no transaction of this wallet");
            return Ok(RelayCancelApplied::Unknown);
        };
        info!(tx_id = %tx_id, "relay cancellation reported; the transaction stays as it is");
        Ok(RelayCancelApplied::Kept { tx_id })
    }

    /// The relay transaction id to post the slate `slate_id` under over `outbound`: the one it
    /// is filed under, or, with `fresh`, a new one from `outbound`, filed before it is returned
    /// so a retry posts under the same id. `None` when the slate is filed under none and
    /// `outbound` makes none.
    pub(crate) async fn relay_txid_for(
        &self,
        outbound: &dyn Outbound,
        slate_id: SlateId,
        fresh: bool,
    ) -> Result<Option<RelayTxId>, RelayTxIdError> {
        let session = self.session()?;
        let id = Uuid::from_bytes(*slate_id.as_bytes());
        let stored = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| Ok(session.store.read(|repos| stored_txid(repos, id))?))
                .await?
        };
        if stored.is_some() || !fresh {
            return Ok(stored);
        }
        let Some(txid) = outbound
            .new_relay_txid()
            .map_err(RelayTxIdError::Transport)?
        else {
            return Ok(None);
        };
        Ok(self
            .inbox_write(move |repos, _| store_txid(repos, id, &txid))
            .await?)
    }

    /// Files the slate `slate_id` under the relay transaction id `txid` its peer posted it
    /// under, unless it is filed already, and returns the id to answer under.
    pub(crate) async fn file_relay_txid(
        &self,
        slate_id: SlateId,
        txid: RelayTxId,
    ) -> Result<Option<RelayTxId>, WalletError> {
        let id = Uuid::from_bytes(*slate_id.as_bytes());
        self.inbox_write(move |repos, _| store_txid(repos, id, &txid))
            .await
    }

    /// Takes the relay's refusal of a slate of `slate_id`: the relay holds a cancellation of
    /// the transaction it is filed under. It is logged as
    /// [`Wallet::apply_relay_cancellation`] logs a report, and changes nothing.
    pub(crate) async fn cancelled_on_relay(&self, slate_id: SlateId) {
        let session = match self.session() {
            Ok(session) => session,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "relay cancellation not applied");
                return;
            }
        };
        let id = Uuid::from_bytes(*slate_id.as_bytes());
        let txid = self
            .blocking(move |_, _| Ok(session.store.read(|repos| stored_txid(repos, id))?))
            .await;
        let applied = match txid {
            Ok(Some(txid)) => self.apply_relay_cancellation(&txid).await.map(|_| ()),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = applied {
            warn!(error = %ErrorChain(&error), "relay cancellation not applied");
        }
    }
}

/// Why no relay transaction id could be chosen for a post.
#[derive(Debug, Error)]
pub(crate) enum RelayTxIdError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("no relay transaction id")]
    Transport(#[source] TransportError),
}
