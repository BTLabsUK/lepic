// SPDX-License-Identifier: Apache-2.0
//! The recovery of a payment: a send to the wallet itself that spends the payment's own inputs,
//! so that the payment can never be mined and its coins come back.
//!
//! The payment's inputs stay linked to the payment while its recovery is open, so ending the
//! recovery's pair never unlocks or drops them.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::{NodeApi, NodeError, Propagation};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::EncodeContext;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, MAX_RECOVERY_ERROR_LEN, OutputRecord, OutputStatus, Recovery, RecoveryState,
    Repositories, SlateStage, StoreError, StoredTransaction, TransactionEntry, TxDirection, TxId,
    TxState, WalletStore,
};
use tracing::{debug, info, instrument, warn};

use crate::cancel::{cancel_partner, drop_holdings, pool_holds};
use crate::chain;
use crate::codecs;
use crate::error::WalletError;
use crate::event::{Event, RecoveryNews};
use crate::finalize::{
    FinalizedSlate, Posted, PushFailure, SpentInputs, finalize_own, push_outcome,
};
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::post_retry::stored_error;
use crate::receive::receive_own;
use crate::refresh::{RefreshError, confirm, final_kernel, minimum_confirmations, stored_slate};
use crate::selection::{Selection, SelectionRequest, SelectionStrategy, spend_all_into_one};
use crate::self_send::{SELF, SelfSendError};
use crate::send::{
    S1Randomness, S1Storage, SendError, SendRequest, block_header_version, store_s1,
};
use crate::state::{StateChange, apply_transition, is_final};
use crate::wallet::Wallet;

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Recovers the outgoing payment `tx_id`: builds, receives and finalizes a send to the
    /// wallet itself that spends exactly the payment's inputs into one output, stores it with
    /// the payment's recovery in one store transaction, then pushes it. Once the recovery is
    /// mined the payment can never be, and its coins are back.
    ///
    /// The payment must be finalized, posted, cancelled or expired, and every input of it must
    /// still be held for it. Its kernel is looked up first, in the node's transaction pool and
    /// then in its chain up to the node's tip, as [`Wallet::cancel`] does.
    ///
    /// Returns the recovery as the push left it: [`RecoveryState::Posted`] when the node took
    /// it, [`RecoveryState::Uncertain`] when the node could not be reached, which a refresh
    /// pushes again, and [`RecoveryState::Failed`] when the node refused it; the error is then
    /// on the recovery, and the pair is cancelled.
    ///
    /// Fails, storing nothing, with [`WalletError::UnknownTransaction`],
    /// [`WalletError::RecoveryOpen`] while an earlier recovery of the payment is open,
    /// [`WalletError::NotRecoverable`], [`WalletError::InPool`] or [`WalletError::OnChain`]
    /// when the node holds the payment's kernel, and [`WalletError::Node`] or
    /// [`WalletError::Implausible`] when the node cannot be asked, an offline session among
    /// them. Each comes wrapped as [`SelfSendError::Send`].
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn recover(&self, tx_id: TxId) -> Result<Recovery, SelfSendError> {
        let session = self.session()?;
        if self.config().offline {
            return Err(WalletError::Node(NodeError::Offline).into());
        }
        let posting = self.posting_turn().await;
        let network = self.config().network;
        let base_fee = network.params().default_base_fee();
        let lookup = {
            let session = Arc::clone(&session);
            let codecs = codecs::legacy(base_fee);
            self.blocking(move |_, _| {
                session
                    .store
                    .read(|repos| recovery_lookup(repos, &codecs, tx_id))
            })
            .await?
        };
        let tip = self.check_unmined(&session, tx_id, &lookup).await?;
        let built = {
            let session = Arc::clone(&session);
            self.blocking(move |ports, _| {
                let now = ports.clock.now();
                // The guard drops before the store write: store first, generator second.
                let drawn = S1Randomness::draw(&mut **ports.rng.lock());
                let randomness = match drawn {
                    Ok(randomness) => randomness,
                    Err(error) => return Ok(Err(SelfSendError::from(SendError::from(error)))),
                };
                let codecs = codecs::legacy(base_fee);
                Ok(session.store.write(|repos| {
                    let lookup = recovery_lookup(repos, &codecs, tx_id)?;
                    let entry = lookup.entry;
                    let selection = recovery_selection(
                        repos,
                        tx_id,
                        &entry,
                        &lookup.inputs,
                        &selection_request(entry.account, tip, base_fee),
                    )?;
                    let request = SendRequest {
                        minimum_confirmations: 1,
                        strategy: SelectionStrategy::All,
                        ..SendRequest::new(entry.account, selection.amount)
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
                        selection.clone(),
                        randomness,
                    )?;
                    let context = EncodeContext {
                        block_header_version: block_header_version(network, tip),
                    };
                    let (received_tx, s2) = receive_own(
                        repos,
                        &session,
                        network,
                        entry.account,
                        &s1.slate,
                        SELF,
                        context,
                        &mut **ports.rng.lock(),
                        now,
                    )?;
                    let finalized = finalize_own(repos, &session.keychain, network, tip, now, &s2)?;
                    let recovery = store_recovery(
                        repos,
                        tx_id,
                        selection.inputs,
                        (finalized.tx_id, received_tx),
                        now,
                    )?;
                    Ok::<_, SelfSendError>((recovery, finalized))
                }))
            })
            .await??
        };
        let (recovery, finalized) = built;
        info!(sent_tx = %recovery.sent_tx, "recovery stored");
        if let Some(change) = finalized.change {
            self.emit(change.into());
        }
        // The turn held from before the store write through the push, so a refresh cannot push
        // the recovery first.
        Ok(self
            .push_recovery(posting, &session, recovery, &finalized.finalized, tip)
            .await?)
    }

    /// Pushes the new `recovery`, built at `tip` as `finalized`, in the posting turn
    /// `posting`, and records what the push ended with. One event tells of the recovery as
    /// the push left it; an error recording the push leaves it stored as uncertain.
    async fn push_recovery(
        &self,
        posting: tokio::sync::MutexGuard<'_, ()>,
        session: &Arc<Session<S::Store>>,
        recovery: Recovery,
        finalized: &FinalizedSlate,
        tip: Height,
    ) -> Result<Recovery, WalletError> {
        let pushed = self
            .push_final_in_turn(
                posting,
                finalized,
                recovery.sent_tx,
                Propagation::Stem,
                None,
            )
            .await;
        match self
            .recovery_pushed(session, recovery.tx_id, finalized, tip, pushed)
            .await
        {
            Ok((pushed, _)) => {
                self.emit_recovery(&pushed);
                Ok(pushed)
            }
            Err(error) => {
                self.emit_recovery(&recovery);
                Err(error)
            }
        }
    }

    /// The node's tip, once neither its pool nor its chain up to that tip holds the kernel
    /// of the payment `tx_id`: [`WalletError::InPool`] or [`WalletError::OnChain`] otherwise.
    async fn check_unmined(
        &self,
        session: &Arc<Session<S::Store>>,
        tx_id: TxId,
        lookup: &Lookup,
    ) -> Result<Height, WalletError> {
        let node = &self.ports().node;
        // The pool is asked before the chain, as a cancel asks: a payment that leaves the pool
        // for a block between the two lookups is then found by the second.
        if pool_holds(node, &lookup.excess)
            .await
            .map_err(WalletError::Node)?
        {
            debug!("kernel found in the node pool");
            return Err(WalletError::InPool(tx_id));
        }
        let tip = node.get_tip().await.map_err(WalletError::Node)?.height;
        self.check_plausible_tip(session, tip).await?;
        let floor = chain::kernel_floor(lookup.min_height, tip);
        if let Some(kernel) = node
            .get_kernel(&lookup.excess, Some(floor), Some(tip))
            .await
            .map_err(WalletError::Node)?
        {
            debug!(height = %kernel.height, "kernel found on chain");
            return Err(WalletError::OnChain(tx_id));
        }
        Ok(tip)
    }

    /// Records what the push of the recovery of `tx_id` ended with, and returns the recovery
    /// as stored after it, with whether it changed. `tip` is the tip the push was made at.
    /// The caller tells of the recovery.
    pub(crate) async fn recovery_pushed(
        &self,
        session: &Arc<Session<S::Store>>,
        tx_id: TxId,
        finalized: &FinalizedSlate,
        tip: Height,
        pushed: Result<Posted, PushFailure>,
    ) -> Result<(Recovery, bool), WalletError> {
        let outcome = match pushed {
            Ok(Posted::Accepted) => PushEnd::Posted(None),
            Ok(Posted::AlreadyOnChain { height }) => PushEnd::Posted(Some(height)),
            Err(PushFailure::NotPosted(source)) => match push_outcome(&source) {
                lepic_store::NodeOutcome::Refused => {
                    let watch = finalized.slate.kernel().map(|kernel| {
                        (
                            kernel.excess,
                            chain::kernel_floor(finalized.slate.height(), tip),
                            tip,
                        )
                    });
                    PushEnd::Failed {
                        error: stored_error(&source),
                        watch,
                    }
                }
                _ => PushEnd::Unchanged,
            },
            Err(PushFailure::Unminable { source, spent }) => {
                let ended = self
                    .end_recovery(session, tx_id, stored_error(&source), None)
                    .await?;
                // The payment's own inputs are gone: by the payment itself, which a refresh
                // confirms, or by another wallet, which ends the payment as it ends any send.
                if spent == SpentInputs::OtherWallet {
                    self.end_spent(tx_id, spent).await;
                }
                return Ok(ended);
            }
            Err(PushFailure::Wallet(error)) => {
                warn!(error = %lepic_primitives::error_chain::ErrorChain(&error), "recovery not pushed");
                PushEnd::Unchanged
            }
        };
        match outcome {
            PushEnd::Posted(height) => self.recovery_posted(session, tx_id, height).await,
            PushEnd::Failed { error, watch } => {
                self.end_recovery(session, tx_id, error, watch).await
            }
            PushEnd::Unchanged => {
                let session = Arc::clone(session);
                let recovery = self
                    .blocking(move |_, _| session.store.read(|repos| stored_recovery(repos, tx_id)))
                    .await?;
                Ok((recovery, false))
            }
        }
    }

    /// Moves the recovery of `tx_id` from uncertain to posted, or to confirming when the
    /// chain already holds its kernel at `height`, and says whether it changed.
    async fn recovery_posted(
        &self,
        session: &Arc<Session<S::Store>>,
        tx_id: TxId,
        height: Option<Height>,
    ) -> Result<(Recovery, bool), WalletError> {
        let session = Arc::clone(session);
        let (recovery, changed) = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mut recovery = stored_recovery(repos, tx_id)?;
                    let state = match height {
                        Some(_) => RecoveryState::Confirming,
                        None => RecoveryState::Posted,
                    };
                    let changed = recovery.state == RecoveryState::Uncertain
                        || (recovery.state == RecoveryState::Posted && height.is_some());
                    if changed {
                        recovery.state = state;
                        recovery.kernel_height = height;
                        recovery.last_error = None;
                        recovery.updated_at = now;
                        repos.put_recovery(&recovery)?;
                    }
                    Ok::<_, WalletError>((recovery, changed))
                })
            })
            .await?;
        if changed {
            info!(state = ?recovery.state, "recovery posted");
        }
        Ok((recovery, changed))
    }

    /// Ends the recovery of `tx_id` unmined, with the node's `error`: cancels its pair, kept
    /// watched under `watch` when it may still be mined, and marks it failed. Says whether it
    /// changed: a recovery that had already ended is left as it is.
    async fn end_recovery(
        &self,
        session: &Arc<Session<S::Store>>,
        tx_id: TxId,
        error: String,
        watch: Option<(Commitment, Height, Height)>,
    ) -> Result<(Recovery, bool), WalletError> {
        let session = Arc::clone(session);
        let failed = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session
                    .store
                    .write(|repos| fail_recovery(repos, tx_id, error, watch, now))
            })
            .await?;
        if failed.ended {
            info!("recovery failed");
            for change in failed.changes {
                self.emit(change.into());
            }
        }
        Ok((failed.recovery, failed.ended))
    }

    /// Settles every open recovery against the chain at `tip`, as a refresh does after its
    /// pushes: one whose kernel the chain holds waits as confirming until the account's spend
    /// confirmations, then ends done in one write with the payment cancelled; one whose kernel
    /// left the chain before that waits as posted again. A recovery the node does not answer
    /// for is left to the next refresh.
    pub(crate) async fn settle_recoveries(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: Height,
        now: Timestamp,
    ) -> Result<Vec<StateChange>, RefreshError> {
        let node = &self.ports().node;
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let default = self.config().policy.default_minimum_confirmations;
        let (watched, minimum) = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| watched_recoveries(repos, &codecs, default)))
            })
            .await??
        };
        let mut changes = Vec::new();
        for watch in watched {
            let floor = chain::kernel_floor(watch.min_height, tip);
            let tx_id = watch.tx_id;
            if watch.payment_mined {
                let pair = Some((watch.excess, floor, tip));
                let session = Arc::clone(session);
                let failed = self
                    .blocking(move |_, _| {
                        Ok(session
                            .store
                            .write(|repos| mined_first(repos, tx_id, pair, now)))
                    })
                    .await??;
                if failed.ended {
                    info!(tx_id = %tx_id, "recovery failed: the payment was mined first");
                    changes.extend(failed.changes);
                    self.emit_recovery(&failed.recovery);
                }
                continue;
            }
            let height = match node.get_kernel(&watch.excess, Some(floor), Some(tip)).await {
                Ok(kernel) => kernel
                    .map(|kernel| kernel.height)
                    .filter(|height| *height <= tip),
                Err(error) => {
                    debug!(tx_id = %watch.tx_id, error = %ErrorChain(&error), "recovery kernel not looked up");
                    continue;
                }
            };
            let session = Arc::clone(session);
            let settled = self
                .blocking(move |_, _| {
                    Ok(session
                        .store
                        .write(|repos| settle_recovery(repos, tx_id, height, tip, minimum, now)))
                })
                .await??;
            if let Some((recovery, settled)) = settled {
                info!(tx_id = %tx_id, state = ?recovery.state, "recovery settled");
                changes.extend(settled);
                self.emit_recovery(&recovery);
            }
        }
        Ok(changes)
    }

    pub(crate) fn emit_recovery(&self, recovery: &Recovery) {
        self.emit(Event::RecoveryChanged(RecoveryNews {
            tx_id: recovery.tx_id,
            state: recovery.state,
        }));
    }
}

/// How the push of a recovery ended for its record.
enum PushEnd {
    /// The node took it; the chain holds its kernel at the height, if given.
    Posted(Option<Height>),
    /// The node refused it for a reason of its own.
    Failed {
        error: String,
        watch: Option<(Commitment, Height, Height)>,
    },
    /// The node could not be reached, or the push was not made.
    Unchanged,
}

/// The selection a recovery asks for: every input given, into one output, with no
/// confirmations required, as the inputs are already the payment's.
fn selection_request(account: AccountIndex, tip: Height, base_fee: Fee) -> SelectionRequest {
    SelectionRequest {
        account,
        amount: Amount::ZERO,
        tip,
        minimum_confirmations: 1,
        max_outputs: NonZeroUsize::MIN,
        change_outputs: NonZeroUsize::MIN,
        strategy: SelectionStrategy::All,
        base_fee,
    }
}

/// Stores the recovery of `tx_id` by the pair `(sent_tx, received_tx)` as uncertain, with
/// the payment's `inputs` locked and still linked to the payment, so a pair that ends unmined
/// leaves them as the payment holds them.
fn store_recovery(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    inputs: Vec<OutputRecord>,
    (sent_tx, received_tx): (TxId, TxId),
    now: Timestamp,
) -> Result<Recovery, StoreError> {
    for input in inputs {
        repos.put_output(&OutputRecord {
            status: OutputStatus::Locked,
            tx: Some(tx_id),
            ..input
        })?;
    }
    let recovery = Recovery {
        tx_id,
        sent_tx,
        received_tx,
        state: RecoveryState::Uncertain,
        kernel_height: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    };
    repos.put_recovery(&recovery)?;
    Ok(recovery)
}

/// The final kernel of an open recovery, to look up on chain.
struct RecoveryWatch {
    tx_id: TxId,
    excess: Commitment,
    min_height: Height,
    /// A refresh confirmed the payment itself: its recovery can no longer be mined.
    payment_mined: bool,
}

/// The error a recovery ends with when its payment was mined before it.
const MINED_FIRST: &str = "the payment was mined first";

/// The open recoveries whose kernel is known, and the account's spend confirmations, which
/// a recovery needs before it ends its payment.
fn watched_recoveries(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    default: u64,
) -> Result<(Vec<RecoveryWatch>, u64), RefreshError> {
    let minimum = minimum_confirmations(repos, default)?;
    let mut watched = Vec::new();
    for recovery in repos.recoveries()? {
        if !recovery.state.is_open() {
            continue;
        }
        let Some(slate_id) = repos
            .transaction(recovery.sent_tx)?
            .and_then(|entry| entry.slate_id)
        else {
            continue;
        };
        if let Some((excess, min_height)) = final_kernel(repos, codecs, recovery.sent_tx, slate_id)?
        {
            let payment_mined = repos
                .transaction(recovery.tx_id)?
                .is_some_and(|payment| payment.state == TxState::Confirmed);
            watched.push(RecoveryWatch {
                tx_id: recovery.tx_id,
                excess,
                min_height,
                payment_mined,
            });
        }
    }
    Ok((watched, minimum))
}

/// Applies where the chain holds the kernel of the recovery of `tx_id`: at `height`, or
/// nowhere. Below `minimum` confirmations at `tip` the recovery waits as confirming and
/// nothing ends. At the count the payment's inputs become spent by the recovery, an open
/// payment drops its change and is cancelled, the recovery's pair is confirmed and the
/// recovery is done. An ended payment keeps its state. A kernel gone from the chain before
/// the count puts the recovery back to posted. Returns the recovery when it changed.
fn settle_recovery(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Option<Height>,
    tip: Height,
    minimum: u64,
    now: Timestamp,
) -> Result<Option<(Recovery, Vec<StateChange>)>, RefreshError> {
    let Some(mut recovery) = repos
        .recovery(tx_id)?
        .filter(|recovery| recovery.state.is_open())
    else {
        return Ok(None);
    };
    let Some(height) = height else {
        if recovery.state != RecoveryState::Confirming {
            return Ok(None);
        }
        recovery.state = RecoveryState::Posted;
        recovery.kernel_height = None;
        recovery.updated_at = now;
        repos.put_recovery(&recovery)?;
        return Ok(Some((recovery, Vec::new())));
    };
    let confirmations = tip
        .value()
        .checked_sub(height.value())
        .map_or(0, |blocks| blocks.saturating_add(1));
    if confirmations < minimum {
        if recovery.state == RecoveryState::Confirming && recovery.kernel_height == Some(height) {
            return Ok(None);
        }
        recovery.state = RecoveryState::Confirming;
        recovery.kernel_height = Some(height);
        recovery.last_error = None;
        recovery.updated_at = now;
        repos.put_recovery(&recovery)?;
        return Ok(Some((recovery, Vec::new())));
    }
    let payment = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    for output in repos.outputs_of_transaction(tx_id)? {
        if output.status != OutputStatus::Unconfirmed {
            repos.put_output(&OutputRecord {
                status: OutputStatus::Spent,
                tx: Some(recovery.sent_tx),
                ..output
            })?;
        }
    }
    let mut changes = Vec::new();
    if !is_final(payment.state) {
        drop_holdings(repos, tx_id, &payment)?;
        changes.extend(apply_transition(repos, tx_id, TxState::Cancelled, now)?);
    }
    // The recovery's output is on chain in the block of its kernel; a refresh adds where.
    for output in repos.outputs_of_transaction(recovery.received_tx)? {
        if output.status == OutputStatus::Unconfirmed {
            repos.put_output(&OutputRecord {
                status: OutputStatus::Unspent,
                height,
                ..output
            })?;
        }
    }
    for id in [recovery.sent_tx, recovery.received_tx] {
        changes.extend(confirm(repos, id, height, now)?);
    }
    recovery.state = RecoveryState::Done;
    recovery.kernel_height = Some(height);
    recovery.last_error = None;
    recovery.updated_at = now;
    repos.put_recovery(&recovery)?;
    Ok(Some((recovery, changes)))
}

/// Ends the open recovery of `tx_id` failed when a refresh confirmed its payment: its pair is
/// cancelled and kept watched under `pair`, and the payment's inputs become spent by the
/// payment, which the refresh left to this step.
fn mined_first(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    pair: Option<(Commitment, Height, Height)>,
    now: Timestamp,
) -> Result<Failed, WalletError> {
    let recovery = stored_recovery(repos, tx_id)?;
    let mined = repos
        .transaction(tx_id)?
        .is_some_and(|payment| payment.state == TxState::Confirmed);
    if !mined || !recovery.state.is_open() {
        return Ok(Failed {
            recovery,
            changes: Vec::new(),
            ended: false,
        });
    }
    let failed = fail_recovery(repos, tx_id, MINED_FIRST.to_owned(), pair, now)?;
    for output in repos.outputs_of_transaction(tx_id)? {
        if output.status == OutputStatus::Locked {
            repos.put_output(&OutputRecord {
                status: OutputStatus::Spent,
                ..output
            })?;
        }
    }
    Ok(failed)
}

/// Ends the open recovery of `tx_id` as [`mined_first`] does when the payment, cancelled or
/// expired and watched, was just confirmed as mined at `height`, in the store transaction that
/// confirmed it: the refresh step that settles recoveries ran before it and does not run
/// again. The pair is kept watched from `height`. Returns the recovery and the changes to its
/// pair when it ended here.
pub(crate) fn end_for_mined_payment(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    height: Height,
    now: Timestamp,
) -> Result<Option<(Recovery, Vec<StateChange>)>, WalletError> {
    let Some(recovery) = repos
        .recovery(tx_id)?
        .filter(|recovery| recovery.state.is_open())
    else {
        return Ok(None);
    };
    let slate_id = repos
        .transaction(recovery.sent_tx)?
        .and_then(|entry| entry.slate_id);
    let kernel = match slate_id {
        Some(slate_id) => final_kernel(repos, codecs, recovery.sent_tx, slate_id)?,
        None => None,
    };
    let pair = kernel
        .map(|(excess, min_height)| (excess, chain::kernel_floor(min_height, height), height));
    let failed = mined_first(repos, tx_id, pair, now)?;
    Ok(failed.ended.then_some((failed.recovery, failed.changes)))
}

/// The payments with an open recovery, each with whether the node took the recovery: posted
/// or confirming. While it is open a refresh neither pushes, ends nor releases the payment,
/// and its change counts nowhere; once the node took it, neither do its inputs.
pub(crate) fn recovering(repos: &dyn Repositories) -> Result<BTreeMap<TxId, bool>, StoreError> {
    Ok(repos
        .recoveries()?
        .into_iter()
        .filter(|recovery| recovery.state.is_open())
        .map(|recovery| {
            let taken = matches!(
                recovery.state,
                RecoveryState::Posted | RecoveryState::Confirming
            );
            (recovery.tx_id, taken)
        })
        .collect())
}

/// The recoveries that are open.
pub(crate) fn open_recoveries(repos: &dyn Repositories) -> Result<Vec<Recovery>, StoreError> {
    Ok(repos
        .recoveries()?
        .into_iter()
        .filter(|recovery| recovery.state.is_open())
        .collect())
}

/// The entries of every open recovery: each payment recovered and both entries of its pair.
/// Until the recovery settles, neither a refresh nor a repair scan ends, releases or pushes
/// any of them on its own; [`Wallet::settle_recoveries`] does.
pub(crate) fn recovery_entries(repos: &dyn Repositories) -> Result<BTreeSet<TxId>, StoreError> {
    Ok(open_recoveries(repos)?
        .into_iter()
        .flat_map(|recovery| [recovery.tx_id, recovery.sent_tx, recovery.received_tx])
        .collect())
}

/// Whether a refresh leaves `output` as it is stored, whatever the chain shows, because a
/// recovery among `open` settles it: an input of the payment recovered, which the payment or
/// its recovery spends, or an output of the recovery's pair. A block that holds either one may
/// still be replaced below the account's spend confirmations.
pub(crate) fn kept_for_recovery(output: &OutputRecord, open: &[Recovery]) -> bool {
    let Some(tx) = output.tx else {
        return false;
    };
    open.iter().any(|recovery| {
        tx == recovery.sent_tx
            || tx == recovery.received_tx
            || (tx == recovery.tx_id && output.status == OutputStatus::Locked)
    })
}

/// What a recovery of a payment needs from the store: the payment, the kernel to look up and
/// the height below which it cannot be, and the inputs its slate spends.
struct Lookup {
    entry: TransactionEntry,
    excess: Commitment,
    min_height: Height,
    inputs: Vec<Commitment>,
}

/// The payment `tx_id` as a recovery reads it, refused as [`Wallet::recover`] describes.
fn recovery_lookup(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<Lookup, WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    if repos
        .recovery(tx_id)?
        .is_some_and(|recovery| recovery.state.is_open())
    {
        return Err(WalletError::RecoveryOpen(tx_id));
    }
    let refused = || WalletError::NotRecoverable(tx_id);
    held_status(&entry).ok_or_else(refused)?;
    let slate_id = entry.slate_id.ok_or_else(refused)?;
    let (excess, min_height) = final_kernel(repos, codecs, tx_id, slate_id)?.ok_or_else(refused)?;
    // The slate the kernel was read from: a send's S3, or an invoice payment's I2.
    let mut inputs = None;
    for stage in [SlateStage::Standard3, SlateStage::Invoice2] {
        if let Some(slate) = stored_slate(repos, codecs, tx_id, slate_id, stage)? {
            inputs = Some(
                slate
                    .inputs()
                    .iter()
                    .map(|input| input.commitment)
                    .collect(),
            );
            break;
        }
    }
    Ok(Lookup {
        entry,
        excess,
        min_height,
        inputs: inputs.ok_or_else(refused)?,
    })
}

/// The open recovery `tx_id` belongs to: as the payment recovered or as either entry of its
/// self-send pair.
pub(crate) fn open_recovery(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<Recovery>, StoreError> {
    Ok(open_recoveries(repos)?.into_iter().find(|recovery| {
        recovery.tx_id == tx_id || recovery.sent_tx == tx_id || recovery.received_tx == tx_id
    }))
}

/// Refuses with [`WalletError::RecoveryOpen`], naming the payment, when `tx_id` belongs to an
/// open recovery: cancelling or releasing either side would free inputs the other may spend.
pub(crate) fn check_no_recovery(repos: &dyn Repositories, tx_id: TxId) -> Result<(), WalletError> {
    match open_recovery(repos, tx_id)? {
        Some(recovery) => Err(WalletError::RecoveryOpen(recovery.tx_id)),
        None => Ok(()),
    }
}

fn stored_recovery(repos: &dyn Repositories, tx_id: TxId) -> Result<Recovery, WalletError> {
    repos
        .recovery(tx_id)?
        .ok_or(WalletError::NotRecoverable(tx_id))
}

/// What [`fail_recovery`] did.
struct Failed {
    /// The recovery as stored after it.
    recovery: Recovery,
    /// The changes to its pair.
    changes: Vec<StateChange>,
    /// Whether the recovery was open and ended here.
    ended: bool,
}

/// Cancels both entries of the recovery of `tx_id`, kept watched under `watch` when given,
/// gives the payment's inputs back to an ended payment as unspent, and marks the recovery
/// failed with `error`. A recovery that already ended is returned as it is.
fn fail_recovery(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    error: String,
    watch: Option<(Commitment, Height, Height)>,
    now: Timestamp,
) -> Result<Failed, WalletError> {
    let mut recovery = stored_recovery(repos, tx_id)?;
    if !recovery.state.is_open() {
        return Ok(Failed {
            recovery,
            changes: Vec::new(),
            ended: false,
        });
    }
    let mut changes = Vec::new();
    for id in [recovery.sent_tx, recovery.received_tx] {
        if let Some(entry) = repos.transaction(id)? {
            let stored = StoredTransaction { id, entry };
            changes.extend(cancel_partner(repos, &stored, watch, now)?);
        }
    }
    let payment = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    if held_status(&payment) == Some(OutputStatus::Unspent) {
        for output in repos.outputs_of_transaction(tx_id)? {
            if output.status == OutputStatus::Locked {
                repos.put_output(&OutputRecord {
                    status: OutputStatus::Unspent,
                    ..output
                })?;
            }
        }
    }
    recovery.state = RecoveryState::Failed;
    recovery.last_error = Some(cut(error));
    recovery.updated_at = now;
    repos.put_recovery(&recovery)?;
    Ok(Failed {
        recovery,
        changes,
        ended: true,
    })
}

/// `text` cut at a character boundary to at most [`MAX_RECOVERY_ERROR_LEN`] bytes.
fn cut(mut text: String) -> String {
    if text.len() > MAX_RECOVERY_ERROR_LEN {
        let mut end = MAX_RECOVERY_ERROR_LEN;
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        text.truncate(end);
    }
    text
}

/// The status the inputs of `entry` have while they are held for it: locked by an open
/// payment, unspent but still linked to an ended one. `None` for an entry that cannot be
/// recovered.
fn held_status(entry: &TransactionEntry) -> Option<OutputStatus> {
    if entry.direction != TxDirection::Outgoing {
        return None;
    }
    match entry.state {
        TxState::Finalized | TxState::Posted => Some(OutputStatus::Locked),
        TxState::Cancelled | TxState::Expired => Some(OutputStatus::Unspent),
        _ => None,
    }
}

/// The selection that spends every input of the payment `tx_id` into one output of the
/// wallet, with no change. `inputs` are the commitments the payment's slate spends.
///
/// Refused with [`WalletError::NotRecoverable`] when the payment is not an outgoing payment
/// that is finalized, posted, cancelled or expired, when it spends nothing or names an input
/// twice, when any input is not an output of its account held for it, or when the inputs
/// cannot pay the fee.
pub(crate) fn recovery_selection(
    repos: &dyn Repositories,
    tx_id: TxId,
    entry: &TransactionEntry,
    inputs: &[Commitment],
    request: &SelectionRequest,
) -> Result<Selection, WalletError> {
    let refused = || WalletError::NotRecoverable(tx_id);
    let held = held_status(entry).ok_or_else(refused)?;
    let distinct: BTreeSet<&Commitment> = inputs.iter().collect();
    if inputs.is_empty() || distinct.len() != inputs.len() {
        return Err(refused());
    }
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let output = repos.output(input.as_bytes())?.ok_or_else(refused)?;
        if output.tx != Some(tx_id) || output.status != held || output.account != entry.account {
            return Err(refused());
        }
        outputs.push(output);
    }
    spend_all_into_one(outputs.iter().collect(), request).map_err(|_| refused())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use jiff::Timestamp;
    use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
    use lepic_primitives::amount::{Amount, Height};
    use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
    use lepic_primitives::params::Network;
    use lepic_store::{
        AccountIndex, CONTEXT_KEY_LEN, KeyId, MemoryStore, OutputRecord, StoreKeys, WalletStore,
    };

    use super::*;
    use crate::selection::SelectionStrategy;

    const ACCOUNT: AccountIndex = AccountIndex(0);

    fn at() -> Timestamp {
        Timestamp::from_second(1_790_000_000).unwrap()
    }

    fn entry(direction: TxDirection, state: TxState) -> TransactionEntry {
        TransactionEntry {
            account: ACCOUNT,
            direction,
            state,
            slate_id: None,
            transport: None,
            amount_credited: Amount::ZERO,
            amount_debited: Amount::ZERO,
            fee: None,
            created_at: at(),
            updated_at: at(),
        }
    }

    /// A store with the default account and a payment in `state`, and the payment's id.
    fn store_with(state: TxState) -> (MemoryStore, TxId) {
        let store = MemoryStore::new(StoreKeys::from_bytes(
            [3; CONTEXT_KEY_LEN],
            [3; CONTEXT_KEY_LEN],
        ));
        let tx_id = store
            .write(|repos| {
                crate::account::ensure_default_account(repos)?;
                Ok::<_, WalletError>(
                    repos.insert_transaction(&entry(TxDirection::Outgoing, state))?,
                )
            })
            .unwrap();
        (store, tx_id)
    }

    /// Stores an output of `value` in `status`, linked to `tx`, and returns its commitment.
    fn put(
        store: &MemoryStore,
        child: u32,
        value: u64,
        status: OutputStatus,
        tx: Option<TxId>,
    ) -> Commitment {
        let keychain =
            Keychain::from_seed(&Seed::from_entropy(&[7; 32]).unwrap(), Network::Floonet).unwrap();
        let key_id = Identifier::new(3, [0, 0, child, 0]).unwrap();
        let commitment = keychain
            .commit(value, &key_id, SwitchCommitment::Regular)
            .unwrap();
        store
            .write(|repos| {
                repos.put_output(&OutputRecord {
                    id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
                    key_id: KeyId(key_id.to_bytes()),
                    account: ACCOUNT,
                    amount: Amount::new(value),
                    status,
                    height: Height::new(10),
                    lock_height: Height::ZERO,
                    mmr_index: None,
                    tx,
                })
            })
            .unwrap();
        commitment
    }

    fn request() -> SelectionRequest {
        SelectionRequest {
            account: ACCOUNT,
            amount: Amount::ZERO,
            tip: Height::new(100),
            minimum_confirmations: 1,
            max_outputs: NonZeroUsize::MIN,
            change_outputs: NonZeroUsize::MIN,
            strategy: SelectionStrategy::All,
            base_fee: Network::Floonet.params().default_base_fee(),
        }
    }

    fn select(
        store: &MemoryStore,
        tx_id: TxId,
        inputs: &[Commitment],
    ) -> Result<Selection, WalletError> {
        let entry = store
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .unwrap();
        store.read(|repos| recovery_selection(repos, tx_id, &entry, inputs, &request()))
    }

    fn assert_refused(result: &Result<Selection, WalletError>, tx_id: TxId) {
        assert!(
            matches!(result, Err(WalletError::NotRecoverable(id)) if *id == tx_id),
            "{result:?}"
        );
    }

    #[test]
    fn spends_every_input_locked_by_an_open_payment_into_one_output() {
        for state in [TxState::Finalized, TxState::Posted] {
            let (store, tx_id) = store_with(state);
            let large = put(&store, 0, 3_000_000_000, OutputStatus::Locked, Some(tx_id));
            let small = put(&store, 1, 2_000_000_000, OutputStatus::Locked, Some(tx_id));

            let selection = select(&store, tx_id, &[large, small]).unwrap();

            let spent: Vec<_> = selection
                .inputs
                .iter()
                .map(|output| output.id.commitment)
                .collect();
            assert_eq!(spent, vec![small, large]);
            assert_eq!(selection.change, Vec::new());
            assert_eq!(selection.total, Amount::new(5_000_000_000));
            assert_eq!(
                selection.amount.checked_add(selection.fee.to_amount()),
                Ok(selection.total)
            );
        }
    }

    #[test]
    fn spends_the_inputs_an_ended_payment_left_unspent() {
        for state in [TxState::Cancelled, TxState::Expired] {
            let (store, tx_id) = store_with(state);
            let input = put(&store, 0, 3_000_000_000, OutputStatus::Unspent, Some(tx_id));

            let selection = select(&store, tx_id, &[input]).unwrap();

            assert_eq!(selection.inputs.len(), 1);
        }
    }

    #[test]
    fn refuses_an_input_locked_by_another_transaction() {
        let (store, tx_id) = store_with(TxState::Finalized);
        let other = store
            .write(|repos| {
                repos.insert_transaction(&entry(TxDirection::Outgoing, TxState::Finalized))
            })
            .unwrap();
        let held = put(&store, 0, 3_000_000_000, OutputStatus::Locked, Some(tx_id));
        let taken = put(&store, 1, 3_000_000_000, OutputStatus::Locked, Some(other));

        assert_refused(&select(&store, tx_id, &[held, taken]), tx_id);
    }

    #[test]
    fn refuses_an_input_not_in_the_status_the_payment_holds_it_in() {
        let cases = [
            (TxState::Finalized, OutputStatus::Unspent),
            (TxState::Finalized, OutputStatus::Spent),
            (TxState::Cancelled, OutputStatus::Locked),
            (TxState::Expired, OutputStatus::Spent),
        ];
        for (state, status) in cases {
            let (store, tx_id) = store_with(state);
            let held = put(&store, 0, 3_000_000_000, held_status_of(state), Some(tx_id));
            let wrong = put(&store, 1, 3_000_000_000, status, Some(tx_id));

            assert_refused(&select(&store, tx_id, &[held, wrong]), tx_id);
        }
    }

    fn held_status_of(state: TxState) -> OutputStatus {
        held_status(&entry(TxDirection::Outgoing, state)).unwrap()
    }

    #[test]
    fn refuses_an_input_the_wallet_does_not_hold() {
        let (store, tx_id) = store_with(TxState::Finalized);
        let held = put(&store, 0, 3_000_000_000, OutputStatus::Locked, Some(tx_id));
        let unknown = Commitment::commit_value(5).unwrap();

        assert_refused(&select(&store, tx_id, &[held, unknown]), tx_id);
    }

    #[test]
    fn refuses_a_payment_that_spends_nothing_or_one_input_twice() {
        let (store, tx_id) = store_with(TxState::Finalized);
        let held = put(&store, 0, 3_000_000_000, OutputStatus::Locked, Some(tx_id));

        assert_refused(&select(&store, tx_id, &[]), tx_id);
        assert_refused(&select(&store, tx_id, &[held, held]), tx_id);
    }

    #[test]
    fn refuses_inputs_below_the_fee() {
        let (store, tx_id) = store_with(TxState::Finalized);
        let dust = put(&store, 0, 1, OutputStatus::Locked, Some(tx_id));

        assert_refused(&select(&store, tx_id, &[dust]), tx_id);
    }

    #[test]
    fn refuses_a_payment_that_is_not_an_open_or_ended_send() {
        let states = [
            (TxDirection::Outgoing, TxState::Sent),
            (TxDirection::Outgoing, TxState::Confirmed),
            (TxDirection::Incoming, TxState::Finalized),
        ];
        for (direction, state) in states {
            let (store, tx_id) = store_with(state);
            store
                .write(|repos| repos.update_transaction(tx_id, &entry(direction, state)))
                .unwrap();
            let held = put(&store, 0, 3_000_000_000, OutputStatus::Locked, Some(tx_id));

            assert_refused(&select(&store, tx_id, &[held]), tx_id);
        }
    }
}
