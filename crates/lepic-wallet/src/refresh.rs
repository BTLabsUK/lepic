// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/api_impl/owner.rs,
// libwallet/src/internal/updater.rs (Apache-2.0); see NOTICE and upstream.toml.

//! Refresh: bring stored outputs and transactions in line with the node's UTXO set and kernels,
//! as `epic-wallet`'s `update_wallet_state` does before its scan. The algorithm is in
//! `docs/compat/node-api.md` (refresh), the state mapping in `docs/compat/states.md`.
//!
//! A refresh runs in steps, each stored in its own store transaction: outputs, then kernel
//! confirmations, then received payments another transaction superseded, then finalized or
//! posted transactions whose inputs were spent elsewhere, then TTL expiry, then the watch of
//! transactions that ended unconfirmed ([`crate::release`]). Every step re-reads what it
//! changes inside its transaction, so dropping the future between steps, or a send running at
//! the same time, leaves a consistent store that the next refresh completes.
//!
//! Upstream's update also rescans the last blocks for outputs it does not know; in LEPIC that is
//! a separate [`Wallet::scan`] with [`crate::scan::ScanOptions::update`], run after a refresh.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::{NodeApi, NodeError, OutputLocation};
use lepic_primitives::amount::{Amount, ArithmeticError, Height};
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, OutputRecord, OutputStatus, Repositories, SlateStage, StoreError,
    StoredTransaction, TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::cancel::{cancel_partner, drop_holdings, pool_kernels, self_send_partner};
use crate::chain::{self, ChainPosition, ImplausibleNodeData};
use crate::codecs;
use crate::epicbox_invoice::epicbox_invoice_payment;
use crate::error::WalletError;
use crate::event::{Balance, Event, PostedInvoice, SlateId, SupersededReceive};
use crate::finalize::answered_excess;
use crate::invoice::{earliest_cutoff, payer_release_height};
use crate::lifecycle::Session;
use crate::other_wallet;
use crate::ports::{SecretVault, StoreOpener};
use crate::post_retry::refused_every_time;
use crate::recover::{kept_for_recovery, open_recoveries, recovering, recovery_entries};
use crate::relay_cancel::{RelayCancelResult, RelayEnd};
use crate::release::{RELEASED_WATCH_BLOCKS, lapsed_receipt, record_watch};
use crate::selection::SelectionRequest;
use crate::self_send::SELF;
use crate::send_limit::effective_cutoff;
use crate::state::{StateChange, apply_transition, is_final, reopen_confirmed};
use crate::wallet::Wallet;

/// Confirmations an unspent output needs to count as spendable, and to be selected for a send,
/// in a wallet that has not set its own ([`Wallet::set_minimum_confirmations`]), when the host
/// chose no other ([`crate::WalletPolicy::default_minimum_confirmations`]): 6. The old GUI
/// wallet counted 3 and `epic-wallet` defaults to 10; ADR 0027 gives the reasons.
pub const DEFAULT_MINIMUM_CONFIRMATIONS: u64 = 6;

pub(crate) const MINIMUM_CONFIRMATIONS_SETTING: &str = "wallet.minimum_confirmations";

/// Blocks after a refresh first saw a received payment with no TTL that its sender has not
/// finalized, after which a refresh ends it: a week of blocks, as long as a released send is
/// watched.
pub const UNFINALIZED_RECEIVE_BLOCKS: u64 = RELEASED_WATCH_BLOCKS;

/// Confirmations up to which a refresh checks that the chain still holds a confirmed
/// transaction: 1,440, a day of blocks, the most a service may require before it counts a
/// payment as final. Within them, a transaction none of whose own outputs the node holds has its
/// kernel looked up on every refresh; one whose kernel is gone too, which a reorganisation took
/// off the chain, is no longer confirmed ([`Wallet::refresh`]). Older confirmations cost no
/// lookup.
pub const CONFIRMATION_RECHECK_BLOCKS: u64 = 1_440;

pub(crate) const LAST_CONFIRMED_SETTING: &str = "refresh.last_confirmed_height";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RefreshError {
    /// The wallet is locked, or the database failed.
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    /// The node could not be reached or gave an answer that failed validation. Steps already
    /// stored are kept.
    #[error("node request failed")]
    Node(#[from] NodeError),
    /// The node's answer cannot be true. Steps already stored are kept; nothing derived from
    /// the answer is.
    #[error("node data rejected")]
    Implausible(#[from] ImplausibleNodeData),
    #[error("balance out of range")]
    Balance(#[from] ArithmeticError),
}

impl From<StoreError> for RefreshError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// What a refresh did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    Refreshed(RefreshSummary),
    /// The node's tip is below the height of the last refresh, so it is syncing or on another
    /// fork. Nothing was changed; refresh again once the node has caught up.
    NodeBehind {
        tip: Height,
        last_confirmed: Height,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefreshSummary {
    /// The node's tip. It raises the last confirmed height as [`Wallet::refresh`] describes.
    pub height: Height,
    /// Unconfirmed outputs found on chain, now unspent.
    pub confirmed_outputs: u64,
    /// Unspent and locked outputs missing from the UTXO set, now spent.
    pub spent_outputs: u64,
    /// Transactions confirmed by one of their outputs or by their kernel.
    pub confirmed_transactions: u64,
    /// Transactions at or past their TTL cutoff, now expired.
    pub expired_transactions: u64,
}

#[derive(Debug, Default)]
struct StepOutcome {
    confirmed_outputs: u64,
    spent_outputs: u64,
    changes: Vec<StateChange>,
}

/// What a refresh knows of the chain when it applies the node's answers.
#[derive(Debug, Clone, Copy)]
struct ChainSeen {
    tip: Height,
    /// The tip of the refresh before, at which every output still tracked was on chain.
    last_confirmed: Option<Height>,
    coinbase_maturity: u64,
}

/// The tip a refresh counts at, and what [`Wallet::cover`] needs to read it once more.
#[derive(Debug, Clone, Copy)]
struct RefreshTip {
    height: Height,
    position: ChainPosition,
    now: Timestamp,
    read_again: bool,
}

/// A kernel excess and the height below which the kernel cannot be on chain.
pub(crate) type KernelAt = (Commitment, Height);

/// What a refresh found out about received payments waiting for their sender.
struct ReceiveOutcome {
    /// Payments whose inputs a refresh saw all unspent for the first time.
    seen_unspent: Vec<TxId>,
    /// Payments whose kernel the chain holds, with its height.
    confirmed: Vec<(TxId, Height)>,
    /// Payments one of whose inputs another transaction spent, with the kernel to watch.
    superseded: Vec<(TxId, Uuid, KernelAt)>,
}

/// A received payment waiting for its sender: the inputs its slate spends, the unconfirmed
/// outputs it would create here, and the kernel the sender would finalize it to.
#[derive(Debug, Clone)]
struct WaitingReceive {
    tx_id: TxId,
    slate_id: Uuid,
    inputs: Vec<Commitment>,
    outputs: Vec<Commitment>,
    kernel: Option<KernelAt>,
    /// A refresh found every input unspent before.
    inputs_seen: bool,
}

/// A finalized or posted transaction: the inputs its final transaction spends, this wallet's
/// and the other party's, and its kernel.
#[derive(Debug, Clone)]
struct PendingPost {
    tx_id: TxId,
    inputs: Vec<Commitment>,
    kernel: KernelAt,
}

/// A pending post that can never be mined, as [`Wallet::end_spent_posts`] ends it.
#[derive(Debug, Clone)]
struct SpentPost {
    tx_id: TxId,
    /// The kernel to keep watching, from the floor it was looked up from.
    watch: KernelAt,
    /// Inputs this wallet held that another wallet spent; empty when no input of this wallet
    /// is gone or a transaction of its own spent them.
    lost: Vec<Commitment>,
}

/// An open transaction whose kernel can confirm it: one with no change output.
#[derive(Debug, Clone, Copy)]
struct KernelLookup {
    tx_id: TxId,
    excess: Commitment,
    min_height: Height,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Refreshes every account against the node: asks it for every output not stored as spent,
    /// checks that the chain still holds each transaction confirmed within the last
    /// [`CONFIRMATION_RECHECK_BLOCKS`], by one of its outputs or else its kernel, and reopens
    /// one it no longer holds (`confirmed` back to `posted`, `received` or `sent`, its
    /// confirmation height cleared), marks the outputs it holds unspent and confirms their
    /// transactions, marks unspent and locked ones it does not hold spent once a second
    /// request misses them too, confirms open
    /// transactions with no change output by their kernel, and expires transactions at or past
    /// their TTL cutoff, or a send at or past its local cutoff
    /// ([`crate::send::SendRequest::local_ttl_blocks`]), or an invoice payment
    /// [`crate::invoice::INVOICE_TTL_MARGIN_BLOCKS`] past its cutoff, releasing their inputs. A
    /// posted or finalized transaction is never expired, since it may still be mined, except at
    /// the cutoff from which [`Wallet::post`] no longer posts it an invoice this wallet issued,
    /// and a finalized send whose every recorded push the node's pool refused.
    /// One that can never be mined, because an input it spends is gone from the chain while
    /// neither the node's pool nor its chain holds its kernel, is cancelled. Either stays
    /// watched as below. Then, while the session is online and before their cutoff, it pushes
    /// to the node again each finalized transaction this wallet may post, after a wait in
    /// blocks that grows with each push ([`crate::post_retry::RETRY_BACKOFF_BLOCKS`]), and each
    /// posted one whose kernel neither the pool nor the chain holds
    /// [`crate::post_retry::POSTED_RECHECK_BLOCKS`] after the node accepted it. The first of
    /// these pushes that finds the node unreachable ends them for this refresh, and none fails
    /// it. Last, it looks for each transaction that was
    /// released, cancelled or expired although its peer may still complete it: by its kernel
    /// for [`crate::release::RELEASED_WATCH_BLOCKS`] after a send ended and
    /// [`crate::release::ENDED_RECEIVE_WATCH_BLOCKS`] after a received payment ended, then by
    /// its outputs, with no end. A received payment its sender's TTL ended with nothing
    /// posted is not looked for. One found moves from `cancelled` or `expired` to `confirmed`
    /// and has its outputs stored as unspent.
    ///
    /// Unspent outputs gone from the chain that no transaction here spent were spent by another
    /// wallet on the same recovery phrase: they become one confirmed outgoing entry per account
    /// of origin `OtherWallet` ([`crate::legacy_history::TxOrigin`]), raised as
    /// [`Event::Transaction`]; [`Wallet::refresh_scan`] after the refresh finds their change.
    /// Until a completed scan covers its blocks, such an entry rests on the node's answers
    /// alone and its details say it is unverified.
    ///
    /// The tip must be plausible: below the bounds [`crate::chain`] describes. Output and
    /// kernel heights must not be above the tip. An output or confirming kernel above it has
    /// the tip asked for once more, and a second tip that reaches it, is plausible and agrees
    /// with the first replaces the first. Before expiring anything the tip is asked for
    /// again, unless it already was, and the two must agree. When the tip expired nothing, it
    /// raises the last confirmed height if it is at most [`crate::chain::TIP_STEP_BLOCKS`]
    /// above it; a tip further ahead is held until a later refresh or scan sees the chain at
    /// or above it.
    ///
    /// Marks a send over stock Epicbox that a day has left unanswered, once, and raises
    /// [`Event::DeliveryChanged`] as uncertain for it: such a receiver cannot say that it
    /// refused the payment. The send stays `sent`.
    ///
    /// Emits [`Event::Transaction`] for every state change and one [`Event::Balance`] per
    /// account, computed as [`Wallet::balance`] computes it, at the highest confirmed tip
    /// rather than a tip held as pending. Returns [`RefreshOutcome::NodeBehind`], changing nothing, when the node's tip
    /// is below the last refresh's height.
    ///
    /// Fails with [`RefreshError::Node`], [`RefreshError::Implausible`], or
    /// [`WalletError::Locked`] inside [`RefreshError::Wallet`]. Steps stored before a failure
    /// are kept.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn refresh(&self) -> Result<RefreshOutcome, RefreshError> {
        let session = self.session()?;
        let node = &self.ports().node;
        let tip = node.get_tip().await?;
        let now = self.ports().clock.now();
        let known_tip = tip.height;
        let known = {
            let session = Arc::clone(&session);
            let height = tip.height;
            self.blocking(move |_, _| Ok(session.store.read(|repos| known_state(repos, height))))
                .await??
        };
        chain::check_tip(self.config().network, &known.position, tip.height, now)?;
        if let Some(last_confirmed) = known.last_confirmed
            && tip.height < last_confirmed
        {
            warn!(height = %tip.height, "refresh skipped behind the last confirmed height");
            return Ok(RefreshOutcome::NodeBehind {
                tip: tip.height,
                last_confirmed,
            });
        }
        let mut tip = RefreshTip {
            height: tip.height,
            position: known.position,
            now,
            read_again: false,
        };
        let tracked = known.tracked;
        let mut commitments: Vec<Commitment> =
            tracked.iter().map(|(commitment, _)| *commitment).collect();
        let mut found = self.locate(&commitments, &tracked, &mut tip).await?;
        let candidates = self
            .check_candidates(&session.coinbase_blocks, &known.candidates, known_tip)
            .await?;
        for location in candidates.found {
            commitments.push(location.commitment);
            found.insert(location.commitment, location);
        }
        let expired = candidates.expired;
        let found_outputs: BTreeSet<Commitment> = found.keys().copied().collect();
        let mut summary = RefreshSummary::default();
        let reopened = self
            .recheck_confirmed(&session, &found_outputs, &mut tip, now, &mut summary)
            .await?;

        let seen = ChainSeen {
            tip: tip.height,
            last_confirmed: known.last_confirmed,
            coinbase_maturity: self.config().network.params().coinbase_maturity(),
        };
        let outcome = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .write(|repos| apply_outputs(repos, &commitments, &found, &expired, seen, now)))
            })
            .await??
        };
        session.coinbase_blocks.replace(candidates.checked);

        summary.confirmed_outputs = outcome.confirmed_outputs;
        summary.spent_outputs = outcome.spent_outputs;
        self.record_changes(&mut summary, outcome.changes);

        let mut kernel_missing = self
            .confirm_kernels(&session, &mut tip, now, &mut summary)
            .await?;
        kernel_missing.extend(reopened);
        self.report_pooled_invoices(&session).await?;
        self.end_superseded(&session, &found_outputs, &mut tip, now, &mut summary)
            .await?;
        self.end_spent_posts(&session, &tip, now, &mut summary)
            .await?;

        summary.height = tip.height;
        self.expire_unheld(&session, &mut tip, now, &mut summary)
            .await?;
        self.mark_unanswered(&session, now).await?;
        // A recovery that settles or fails here needs no further push.
        let changes = self.settle_recoveries(&session, tip.height, now).await?;
        self.record_changes(&mut summary, changes);
        self.push_due(&session, tip.height, &kernel_missing).await;
        let changes = self.watch_released(&session, tip.height, now).await?;
        self.record_changes(&mut summary, changes);

        self.emit_balances(&session).await?;
        info!(height = %tip.height, "refresh completed");
        Ok(RefreshOutcome::Refreshed(summary))
    }

    /// Where the chain holds the kernel with `excess`, or `None` when the node knows none at or
    /// above `min_height` (any height when `None`), up to its current tip. Reads the node alone
    /// and changes nothing in the wallet.
    ///
    /// Fails with [`WalletError::Node`], which is [`NodeError::Offline`] in an offline session.
    pub async fn kernel_on_chain(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
    ) -> Result<Option<KernelLocation>, WalletError> {
        if self.config().offline {
            return Err(WalletError::Node(NodeError::Offline));
        }
        debug!(excess = %excess.to_hex(), "kernel lookup");
        let located = self
            .ports()
            .node
            .get_kernel(excess, min_height, None)
            .await
            .map_err(WalletError::Node)?;
        Ok(located.map(|kernel| KernelLocation {
            height: kernel.height,
            mmr_index: kernel.mmr_index,
        }))
    }

    /// Looks up the kernels of the transactions waiting to confirm and confirms those the
    /// chain holds. Returns the transactions whose kernel the node did not find.
    async fn confirm_kernels(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: &mut RefreshTip,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<BTreeSet<TxId>, RefreshError> {
        let node = &self.ports().node;
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let lookups = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| kernel_lookups(repos, &codecs)))
            })
            .await??
        };
        let mut kernel_confirmed = Vec::new();
        let mut kernel_missing = BTreeSet::new();
        for lookup in lookups {
            let floor = chain::kernel_floor(lookup.min_height, tip.height);
            let answer = node
                .get_kernel(&lookup.excess, Some(floor), Some(tip.height))
                .await;
            let Some(kernel) = unless_refused(lookup.tx_id, answer)? else {
                continue;
            };
            match kernel {
                Some(kernel) => {
                    self.cover(tip, kernel.height).await?;
                    chain::check_kernel_height(kernel.height, floor, tip.height)?;
                    kernel_confirmed.push((lookup.tx_id, kernel.height));
                }
                None => {
                    kernel_missing.insert(lookup.tx_id);
                }
            }
        }
        if !kernel_confirmed.is_empty() {
            let session = Arc::clone(session);
            let changes = self
                .blocking(move |_, _| {
                    Ok(session
                        .store
                        .write(|repos| confirm_all(repos, &kernel_confirmed, now)))
                })
                .await??;
            self.record_changes(summary, changes);
        }
        Ok(kernel_missing)
    }

    /// Raises [`Event::InvoicePosted`] for each paid invoice in `unposted` whose kernel the
    /// node's pool holds: the issuer finalized and posted it, and may not say so (a vendor
    /// checkout's shop sends no notice). Once per payment per open wallet. The pool is asked
    /// only when one is not reported yet; a failed lookup is logged and left to the next
    /// refresh, since nothing is stored.
    async fn report_pooled_invoices(
        &self,
        session: &Arc<Session<S::Store>>,
    ) -> Result<(), RefreshError> {
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let unposted = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| unposted_payments(repos, &codecs)))
            })
            .await??
        };
        let unposted: Vec<_> = {
            let reported = self.pool_posted();
            unposted
                .into_iter()
                .filter(|(tx_id, _, _)| !reported.contains(tx_id))
                .collect()
        };
        if unposted.is_empty() {
            return Ok(());
        }
        let pool = match pool_kernels(&self.ports().node).await {
            Ok(pool) => pool,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "pool lookup for paid invoices failed");
                return Ok(());
            }
        };
        for (tx_id, slate_id, excess) in unposted {
            if !pool.contains(&excess) || !self.pool_posted().insert(tx_id) {
                continue;
            }
            debug!(tx_id = %tx_id, "paid invoice found in the node pool");
            self.emit(Event::InvoicePosted(PostedInvoice {
                tx_id,
                slate_id,
                excess,
            }));
        }
        Ok(())
    }

    /// Checks that the chain still holds the transactions confirmed within the last
    /// [`CONFIRMATION_RECHECK_BLOCKS`]: one of its own outputs among those `found`, or else its
    /// kernel. A kernel mined again at another height moves the confirmation height; a kernel
    /// the chain no longer holds reopens the transaction ([`reopen`]). Returns the transactions
    /// reopened.
    async fn recheck_confirmed(
        &self,
        session: &Arc<Session<S::Store>>,
        found: &BTreeSet<Commitment>,
        tip: &mut RefreshTip,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<BTreeSet<TxId>, RefreshError> {
        let node = &self.ports().node;
        let base_fee = self.config().network.params().default_base_fee();
        let rechecks = {
            let session = Arc::clone(session);
            let found = found.clone();
            let height = tip.height;
            self.blocking(move |_, _| {
                let codecs = codecs::legacy(base_fee);
                Ok(session
                    .store
                    .read(|repos| confirmed_rechecks(repos, &codecs, height, &found)))
            })
            .await??
        };
        let mut moved = Vec::new();
        let mut gone = Vec::new();
        for recheck in rechecks {
            let floor = chain::kernel_floor(recheck.min_height, tip.height);
            let answer = node
                .get_kernel(&recheck.excess, Some(floor), Some(tip.height))
                .await;
            let Some(kernel) = unless_refused(recheck.tx_id, answer)? else {
                continue;
            };
            match kernel {
                Some(kernel) => {
                    self.cover(tip, kernel.height).await?;
                    chain::check_kernel_height(kernel.height, floor, tip.height)?;
                    if kernel.height != recheck.confirmed {
                        moved.push((recheck.tx_id, kernel.height));
                    }
                }
                None => gone.push(recheck.tx_id),
            }
        }
        if moved.is_empty() && gone.is_empty() {
            return Ok(BTreeSet::new());
        }
        let reopened = gone.iter().copied().collect();
        let session = Arc::clone(session);
        let changes = self
            .blocking(move |_, _| {
                let codecs = codecs::legacy(base_fee);
                Ok(session.store.write(|repos| {
                    for (tx_id, height) in &moved {
                        repos.set_confirmed_height(*tx_id, *height)?;
                        debug!(tx_id = %tx_id, height = %height, "confirmation height moved");
                    }
                    let mut changes = Vec::new();
                    for tx_id in &gone {
                        changes.extend(reopen(repos, &codecs, *tx_id, now)?);
                    }
                    Ok::<_, RefreshError>(changes)
                }))
            })
            .await??;
        self.record_changes(summary, changes);
        Ok(reopened)
    }

    /// Expires the transactions past their cutoff whose kernel neither the pool nor the chain
    /// holds, once a second tip agrees with the first, and records the receives seen and the
    /// confirmed tip.
    async fn expire_unheld(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: &mut RefreshTip,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<(), RefreshError> {
        let node = &self.ports().node;
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let candidates = {
            let session = Arc::clone(session);
            let height = tip.height;
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    Ok::<_, RefreshError>(
                        expiring(repos, &codecs, height)?
                            .into_iter()
                            .map(|(stored, kernel)| (stored.id, kernel))
                            .collect::<Vec<_>>(),
                    )
                }))
            })
            .await??
        };
        let due = !candidates.is_empty();
        // A tip read again already agreed with the first.
        if due && !tip.read_again {
            let second = node.get_tip().await?;
            chain::check_agreement(tip.height, second.height)?;
        }
        let cleared = self.not_held(&candidates, tip).await?;
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        // A push holds the turn until its outcome is recorded, so the write below sees a push
        // the node took meanwhile and does not end that send.
        let posting = if due {
            Some(self.posting_turn().await)
        } else {
            None
        };
        let changes = {
            let session = Arc::clone(session);
            let height = tip.height;
            self.blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    // Only a tip that was confirmed by a second one expires anything.
                    let changes = if due {
                        expire_all(repos, &codecs, height, &cleared, now)?
                    } else {
                        Vec::new()
                    };
                    record_receives_seen(repos, height)?;
                    // A tip that expired transactions is not trusted as a reference until a
                    // later refresh sees the chain there without expiring anything.
                    if changes.is_empty() {
                        record_confirmed(repos, height, now)?;
                    }
                    Ok::<_, RefreshError>(changes)
                }))
            })
            .await??
        };
        drop(posting);
        let expired: Vec<TxId> = changes
            .iter()
            .filter(|change| change.to == TxState::Expired)
            .map(|change| change.tx_id)
            .collect();
        self.record_changes(summary, changes);
        self.end_expired_on_relay(expired).await;
        Ok(())
    }

    /// Marks the sends over stock Epicbox left unanswered for a day and raises
    /// [`Event::DeliveryChanged`] as uncertain for each, once, and deletes the marks of sends
    /// that left `sent` ([`crate::unanswered`]). Reads first, and opens a write only when
    /// there is something to change.
    async fn mark_unanswered(
        &self,
        session: &Arc<Session<S::Store>>,
        now: Timestamp,
    ) -> Result<(), RefreshError> {
        let marked = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                match session
                    .store
                    .read(|repos| crate::unanswered::due(repos, now))
                {
                    Ok(due) if due.is_empty() => return Ok(Ok(Vec::new())),
                    Ok(_) => {}
                    Err(error) => return Ok(Err(error)),
                }
                Ok(session
                    .store
                    .write(|repos| crate::unanswered::mark_unanswered(repos, now)))
            })
            .await??
        };
        for send in marked {
            info!(slate_id = %send.slate_id, "send marked unanswered");
            self.emit(Event::DeliveryChanged(crate::event::DeliveryNews {
                slate_id: send.slate_id,
                state: lepic_store::OutboxState::Uncertain,
                route: send.route,
            }));
        }
        Ok(())
    }

    /// Asks the relay to cancel each transaction in `expired`, in turn, after the write that
    /// expired them, with no store transaction open. Expired is final, so each is asked about
    /// at most once.
    ///
    /// Stops at the first transaction whose relay could not be asked or cannot cancel, so many
    /// payments expiring together cost one relay timeout, or one connection, and not one per
    /// payment. The ones left are not asked, now or later.
    async fn end_expired_on_relay(&self, expired: Vec<TxId>) {
        let mut left = expired.into_iter();
        while let Some(tx_id) = left.next() {
            match self.end_on_relay(tx_id).await {
                RelayEnd::Failed => {
                    let count = left.len();
                    if count > 0 {
                        warn!(
                            count,
                            "relay cancellation not asked for the rest: the relay could not be asked"
                        );
                    }
                    return;
                }
                RelayEnd::Answered(RelayCancelResult::Unsupported) => {
                    let count = left.len();
                    if count > 0 {
                        debug!(
                            count,
                            "relay cancellation not asked for the rest: the relay cannot cancel"
                        );
                    }
                    return;
                }
                RelayEnd::NotAsked | RelayEnd::Answered(_) => {}
            }
        }
    }

    /// Raises a balance event per account.
    async fn emit_balances(&self, session: &Arc<Session<S::Store>>) -> Result<(), RefreshError> {
        let session = Arc::clone(session);
        let balances = self
            .blocking(move |_, config| {
                Ok(session
                    .store
                    .read(|repos| balances(repos, config.policy.default_minimum_confirmations)))
            })
            .await??;
        for balance in balances {
            self.emit(Event::Balance(balance));
        }
        Ok(())
    }

    /// Ends every received payment waiting for its sender that can never be mined: one whose
    /// kernel is not on chain, whose own outputs are not on chain, and one of whose inputs the
    /// node no longer holds unspent, as two of its answers agree, after an earlier refresh
    /// found them all unspent and once the tip is above the height its slate was made at. A
    /// refresh that finds them all unspent records that for the payment. Its sender completed another
    /// transaction with those inputs, as when another install of the wallet on the same
    /// recovery phrase answered the same S1 and the sender finalized that answer. It ends as a
    /// cancel ends it: its unconfirmed outputs are dropped, its kernel stays watched, and
    /// [`Event::ReceiveSuperseded`] follows its state change. A kernel found confirms it; an
    /// output found, which a twin may have created with the same key, already confirmed it in
    /// the outputs step. The node is asked only when a payment waits for its sender: once for every
    /// input together, again for the ones missing, then for the kernels of the payments with
    /// an input spent.
    async fn end_superseded(
        &self,
        session: &Arc<Session<S::Store>>,
        found_outputs: &BTreeSet<Commitment>,
        tip: &mut RefreshTip,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<(), RefreshError> {
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let mut waiting = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| waiting_receives(repos, &codecs)))
            })
            .await??
        };
        waiting.retain(|receive| {
            !receive.inputs.is_empty()
                && !receive
                    .outputs
                    .iter()
                    .any(|output| found_outputs.contains(output))
        });
        if waiting.is_empty() {
            return Ok(());
        }
        let inputs: Vec<Commitment> = waiting
            .iter()
            .flat_map(|receive| receive.inputs.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let node = &self.ports().node;
        let spent = self.missing_twice(&inputs).await?;
        let mut confirmed = Vec::new();
        let mut superseded = Vec::new();
        let mut seen_unspent = Vec::new();
        for receive in waiting {
            if !receive.inputs.iter().any(|input| spent.contains(input)) {
                if !receive.inputs_seen {
                    seen_unspent.push(receive.tx_id);
                }
                continue;
            }
            // Inputs never seen unspent may never have been on chain at all, as in a slate
            // nobody could complete; such a payment ends by its TTL or the unfinalized bound.
            if !receive.inputs_seen {
                continue;
            }
            // The inputs were confirmed at or below the height the slate was made at, so a node
            // whose tip is not past it, one still syncing, may simply not have them.
            let Some((excess, min_height)) = receive.kernel else {
                continue;
            };
            if tip.height <= min_height {
                continue;
            }
            let floor = chain::kernel_floor(min_height, tip.height);
            let answer = node
                .get_kernel(&excess, Some(floor), Some(tip.height))
                .await;
            match unless_refused(receive.tx_id, answer)? {
                Some(Some(kernel)) => {
                    self.cover(tip, kernel.height).await?;
                    chain::check_kernel_height(kernel.height, floor, tip.height)?;
                    confirmed.push((receive.tx_id, kernel.height));
                }
                Some(None) => superseded.push((receive.tx_id, receive.slate_id, (excess, floor))),
                None => {}
            }
        }
        if confirmed.is_empty() && superseded.is_empty() && seen_unspent.is_empty() {
            return Ok(());
        }
        let outcome = ReceiveOutcome {
            seen_unspent,
            confirmed,
            superseded,
        };
        self.store_receive_outcome(session, outcome, tip.height, now, summary)
            .await
    }

    /// Ends every finalized or posted transaction that can never be mined: one of the inputs
    /// its final transaction spends, this wallet's or the other party's, is missing from the
    /// node's UTXO set in two answers, once the tip is above the height its slate was made at,
    /// and neither the node's pool nor its chain holds its kernel. Its inputs went into another
    /// transaction: the other party's, after it cancelled; this wallet's own, such as a
    /// cancelled payment mined before the move of its coins back to the wallet; or another
    /// wallet's on the same recovery phrase. It ends as a superseded receive does: cancelled,
    /// its unconfirmed outputs dropped and its kernel watched, so a refresh still confirms it
    /// if it is mined after all, and a send to the wallet itself takes its other entry along.
    /// Inputs of this wallet that no kernel of its own spent are recorded as another wallet's
    /// spend, as a refused post records them. A transaction whose kernel is found is left to
    /// the steps that confirm it. The node is asked only while such a transaction waits: once
    /// for every input together, again for the ones missing, then for the pool and the kernels
    /// of the transactions with an input gone.
    async fn end_spent_posts(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: &RefreshTip,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<(), RefreshError> {
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let posts = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| Ok(session.store.read(|repos| pending_posts(repos, &codecs))))
                .await??
        };
        if posts.is_empty() {
            return Ok(());
        }
        let inputs: Vec<Commitment> = posts
            .iter()
            .flat_map(|post| post.inputs.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let gone = self.missing_twice(&inputs).await?;
        // The inputs were confirmed at or below the height the slate was made at, so a node
        // whose tip is not past it, one still syncing, may simply not have them.
        let candidates: Vec<PendingPost> = posts
            .into_iter()
            .filter(|post| {
                tip.height > post.kernel.1 && post.inputs.iter().any(|input| gone.contains(input))
            })
            .collect();
        let Some(first) = candidates.first() else {
            return Ok(());
        };
        let node = &self.ports().node;
        let Some(pool) = unless_refused(first.tx_id, pool_kernels(node).await)? else {
            return Ok(());
        };
        let mut spent = Vec::new();
        for post in candidates {
            let (excess, min_height) = post.kernel;
            if pool.contains(&excess) {
                debug!(tx_id = %post.tx_id, "kernel found in the node pool");
                continue;
            }
            // Up to the node's own tip, so a block mined since the refresh read it counts.
            let floor = chain::kernel_floor(min_height, tip.height);
            let answer = node.get_kernel(&excess, Some(floor), None).await;
            if !matches!(unless_refused(post.tx_id, answer)?, Some(None)) {
                continue;
            }
            let Some(lost) = self.lost_inputs(session, &post, &gone, tip.height).await? else {
                continue;
            };
            spent.push(SpentPost {
                tx_id: post.tx_id,
                watch: (excess, floor),
                lost,
            });
        }
        if spent.is_empty() {
            return Ok(());
        }
        let session = Arc::clone(session);
        let ended_at = tip.height;
        let changes = self
            .blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    let mut changes = Vec::new();
                    for post in &spent {
                        changes.extend(end_spent_post(repos, post, ended_at, now)?);
                    }
                    Ok::<_, RefreshError>(changes)
                }))
            })
            .await??;
        self.record_changes(summary, changes);
        Ok(())
    }

    /// The inputs of `post` among `gone` that this wallet held and another wallet spent: none
    /// when a transaction of its own spent them. `None` when the node refused the kernel
    /// lookup, so the post is left for the next refresh.
    async fn lost_inputs(
        &self,
        session: &Arc<Session<S::Store>>,
        post: &PendingPost,
        gone: &BTreeSet<Commitment>,
        tip: Height,
    ) -> Result<Option<Vec<Commitment>>, RefreshError> {
        let held = {
            let session = Arc::clone(session);
            let gone: Vec<Commitment> = post
                .inputs
                .iter()
                .copied()
                .filter(|input| gone.contains(input))
                .collect();
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    let mut held = Vec::new();
                    for commitment in gone {
                        if repos.output(commitment.as_bytes())?.is_some() {
                            held.push(commitment);
                        }
                    }
                    Ok::<_, StoreError>(held)
                }))
            })
            .await??
        };
        if held.is_empty() {
            return Ok(Some(held));
        }
        match self
            .own_spender(session, post.tx_id, held.clone(), tip)
            .await
        {
            Ok(Some(_)) => Ok(Some(Vec::new())),
            Ok(None) => Ok(Some(held)),
            Err(RefreshError::Node(error @ NodeError::Rejected { .. })) => {
                warn!(tx_id = %post.tx_id, error = %ErrorChain(&error), "kernel lookup refused");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Of `commitments`, those the node holds in neither of two answers: the second asks only
    /// for the ones the first left out.
    async fn missing_twice(
        &self,
        commitments: &[Commitment],
    ) -> Result<BTreeSet<Commitment>, RefreshError> {
        let node = &self.ports().node;
        let mut missing: BTreeSet<Commitment> = commitments.iter().copied().collect();
        for location in node.get_outputs(commitments).await? {
            missing.remove(&location.commitment);
        }
        if !missing.is_empty() {
            let again: Vec<Commitment> = missing.iter().copied().collect();
            for location in node.get_outputs(&again).await? {
                missing.remove(&location.commitment);
            }
        }
        Ok(missing)
    }

    /// Stores what [`Self::end_superseded`] found in one store transaction, at a tip of
    /// `ended_at`, and raises the events that follow.
    async fn store_receive_outcome(
        &self,
        session: &Arc<Session<S::Store>>,
        outcome: ReceiveOutcome,
        ended_at: Height,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<(), RefreshError> {
        let ReceiveOutcome {
            seen_unspent,
            confirmed,
            superseded,
        } = outcome;
        let session = Arc::clone(session);
        let (changes, ended) = self
            .blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    for &tx_id in &seen_unspent {
                        if repos.transaction(tx_id)?.is_some() {
                            let mut marks = repos.tx_marks(tx_id)?;
                            marks.receive_inputs_unspent = true;
                            repos.put_tx_marks(tx_id, &marks)?;
                        }
                    }
                    let mut changes = confirm_all(repos, &confirmed, now)?;
                    let mut ended = Vec::new();
                    for &(tx_id, slate_id, watch) in &superseded {
                        if let Some(change) = supersede(repos, tx_id, watch, ended_at, now)? {
                            changes.push(change);
                            ended.push((tx_id, slate_id));
                        }
                    }
                    Ok::<_, RefreshError>((changes, ended))
                }))
            })
            .await??;
        self.record_changes(summary, changes);
        for (tx_id, slate_id) in ended {
            info!(tx_id = %tx_id, slate_id = %slate_id, "received payment superseded");
            self.emit(Event::ReceiveSuperseded(SupersededReceive {
                tx_id,
                slate_id: SlateId::from_bytes(*slate_id.as_bytes()),
            }));
        }
        Ok(())
    }

    /// The transactions due to expire whose kernel, if one is known, neither the node's pool
    /// nor its chain up to the tip holds: the peer may have completed one that it does hold.
    /// The pool is asked once, before the chain, so a transaction that leaves it for a block
    /// between the lookups is found on chain. A transaction whose lookup fails counts as held
    /// and is decided by a later refresh.
    async fn not_held(
        &self,
        candidates: &[(TxId, Option<KernelAt>)],
        tip: &mut RefreshTip,
    ) -> Result<BTreeSet<TxId>, RefreshError> {
        let node = &self.ports().node;
        let mut pool = None;
        let mut cleared = BTreeSet::new();
        for &(tx_id, kernel) in candidates {
            if let Some((excess, min_height)) = kernel {
                let pool = match &mut pool {
                    Some(pool) => pool,
                    None => pool.insert(unless_refused(tx_id, pool_kernels(node).await)?),
                };
                match pool {
                    Some(pool) if pool.contains(&excess) => {
                        debug!(tx_id = %tx_id, "kernel found in the node pool");
                        continue;
                    }
                    Some(_) => {}
                    None => continue,
                }
                let floor = chain::kernel_floor(min_height, tip.height);
                let answer = node
                    .get_kernel(&excess, Some(floor), Some(tip.height))
                    .await;
                match unless_refused(tx_id, answer)? {
                    Some(Some(kernel)) => {
                        self.cover(tip, kernel.height).await?;
                        chain::check_kernel_height(kernel.height, floor, tip.height)?;
                        debug!(tx_id = %tx_id, height = %kernel.height, "kernel found on chain");
                        continue;
                    }
                    Some(None) => {}
                    None => continue,
                }
            }
            cleared.insert(tx_id);
        }
        Ok(cleared)
    }

    /// Where the node holds the tracked outputs. An unspent or locked output missing from the
    /// first answer is asked for again, and counts as missing only when the second answer
    /// misses it too.
    async fn locate(
        &self,
        commitments: &[Commitment],
        tracked: &[(Commitment, OutputStatus)],
        tip: &mut RefreshTip,
    ) -> Result<BTreeMap<Commitment, OutputLocation>, RefreshError> {
        if commitments.is_empty() {
            return Ok(BTreeMap::new());
        }
        let node = &self.ports().node;
        let mut found = BTreeMap::new();
        for location in node.get_outputs(commitments).await? {
            self.cover(tip, location.height).await?;
            chain::check_output_height(location.height, tip.height)?;
            found.insert(location.commitment, location);
        }
        let missing: Vec<Commitment> = tracked
            .iter()
            .filter(|(commitment, status)| {
                matches!(status, OutputStatus::Unspent | OutputStatus::Locked)
                    && !found.contains_key(commitment)
            })
            .map(|(commitment, _)| *commitment)
            .collect();
        if !missing.is_empty() {
            for location in node.get_outputs(&missing).await? {
                self.cover(tip, location.height).await?;
                chain::check_output_height(location.height, tip.height)?;
                debug!(height = %location.height, "output found on the second request");
                found.insert(location.commitment, location);
            }
        }
        Ok(found)
    }

    /// Reads the tip once more when `height`, of an output or kernel the node reported, is
    /// above it, since a block may have been mined after the tip was read. The second tip
    /// replaces the first only when it reaches `height`; it must then be plausible and agree
    /// with the first, as the tip read before expiry must. Reads at most once per refresh, so
    /// the caller's height check fails as before when the tip still does not reach `height`.
    async fn cover(&self, tip: &mut RefreshTip, height: Height) -> Result<(), RefreshError> {
        if height <= tip.height || tip.read_again {
            return Ok(());
        }
        tip.read_again = true;
        let second = self.ports().node.get_tip().await?.height;
        if second < height {
            return Ok(());
        }
        chain::check_tip(self.config().network, &tip.position, second, tip.now)?;
        chain::check_agreement(tip.height, second)?;
        debug!(height = %second, "tip advanced during refresh");
        tip.height = second;
        Ok(())
    }

    /// The node's tip at the last refresh that applied, or `None` before the first one. Fails
    /// with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn last_confirmed_height(&self) -> Result<Option<Height>, WalletError> {
        let session = self.session()?;
        session.store.read(|repos| Ok(last_confirmed(repos)?))
    }

    /// The balance of `account` from the stored outputs, at the highest tip a refresh or scan
    /// confirmed, without asking the node, so it is available offline. Before any tip is
    /// confirmed it is computed at height zero, where no output has a confirmation yet.
    ///
    /// Fails with [`WalletError::Locked`], or an [`crate::AccountError::UnknownAccount`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn balance(&self, account: AccountIndex) -> Result<Balance, WalletError> {
        let session = self.session()?;
        session.store.read(|repos| {
            if repos.account(account)?.is_none() {
                return Err(crate::AccountError::UnknownAccount(account).into());
            }
            let outputs = repos.outputs(account, None)?;
            let apart = counted_apart(repos, &outputs)?;
            balance(
                account,
                &outputs,
                balance_height(repos)?,
                minimum_confirmations(repos, self.default_minimum())?,
                &apart,
            )
            .map_err(WalletError::Balance)
        })
    }

    /// The confirmations an output needs to count as spendable in [`Wallet::balance`] and to be
    /// selected for a send: the stored setting, or the policy's default
    /// ([`DEFAULT_MINIMUM_CONFIRMATIONS`] unless the host chose another) for a wallet that never
    /// set one. Reads only the store.
    ///
    /// Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn minimum_confirmations(&self) -> Result<u64, WalletError> {
        let session = self.session()?;
        session
            .store
            .read(|repos| Ok(minimum_confirmations(repos, self.default_minimum())?))
    }

    fn default_minimum(&self) -> u64 {
        self.config().policy.default_minimum_confirmations
    }

    /// Stores the wallet's minimum confirmations, then re-splits the balance of every account
    /// at the stored tip and emits one [`Event::Balance`] for each, without asking the node.
    ///
    /// Fails with [`WalletError::MinimumConfirmationsOutOfRange`] for 0, which would spend
    /// unconfirmed outputs, or [`WalletError::Locked`]. There is no upper bound: the host
    /// decides how deep it lets its users ask, and a count above what the chain has makes
    /// nothing spendable.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn set_minimum_confirmations(&self, count: u64) -> Result<(), WalletError> {
        if count == 0 {
            return Err(WalletError::MinimumConfirmationsOutOfRange { count });
        }
        let session = self.session()?;
        session
            .store
            .write(|repos| repos.put_setting(MINIMUM_CONFIRMATIONS_SETTING, &count.to_string()))?;
        let default = self.default_minimum();
        let balances = session
            .store
            .read(|repos| account_balances(repos, default))?;
        for balance in balances {
            self.emit(Event::Balance(balance));
        }
        Ok(())
    }

    /// Every stored output of `account`, spent ones included, ordered by commitment, at the
    /// height [`Wallet::balance`] uses, so the outputs of each category add up to the balance.
    /// Reads only the store.
    ///
    /// Fails with [`WalletError::Locked`], or an [`crate::AccountError::UnknownAccount`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn outputs(&self, account: AccountIndex) -> Result<Vec<OutputDetails>, WalletError> {
        let session = self.session()?;
        session.store.read(|repos| {
            if repos.account(account)?.is_none() {
                return Err(crate::AccountError::UnknownAccount(account).into());
            }
            let height = balance_height(repos)?;
            let minimum = minimum_confirmations(repos, self.default_minimum())?;
            let outputs = repos.outputs(account, None)?;
            let apart = counted_apart(repos, &outputs)?;
            Ok(outputs
                .into_iter()
                .map(|output| OutputDetails {
                    confirmations: if output.status == OutputStatus::Unconfirmed {
                        0
                    } else {
                        confirmations(&output, height)
                    },
                    category: balance_category(&output, height, minimum, &apart),
                    output,
                })
                .collect())
        })
    }

    /// The short update scan to run after each [`Wallet::refresh`]: it finds what another
    /// wallet on the same recovery phrase received, stored as incoming entries of origin
    /// `OtherWallet`, and the change of spends such a wallet made, credited to them. It scans
    /// from [`crate::scan::UPDATE_RESCAN_BLOCKS`] behind the last completed scan, or from the
    /// lowest block such a spend can lie in when that is lower. It does nothing before a scan
    /// from genesis or a restore scan completed, or while a restore scan waits, so it never
    /// scans the whole chain.
    /// It then dates each spend by another wallet whose change it knows by the block of that
    /// change.
    /// Emits what [`Wallet::scan`] emits.
    ///
    /// Fails as [`Wallet::scan`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn refresh_scan(&self) -> Result<(), crate::scan::ScanError> {
        let session = self.session()?;
        let state = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    let ready = crate::scan::covered_from(repos)?.is_some()
                        && !crate::lifecycle::restore_scan_pending(repos)?;
                    Ok::<_, StoreError>((ready, other_wallet::change_window(repos)?))
                }))
            })
            .await?
        }?;
        let (true, window) = state else {
            return Ok(());
        };
        let start = match (window, self.last_scanned_block()?) {
            (Some(after), Some(last)) => {
                let update = last
                    .height
                    .value()
                    .saturating_sub(crate::scan::UPDATE_RESCAN_BLOCKS);
                crate::scan::ScanStart::Height(Height::new(
                    after.value().saturating_add(1).min(update),
                ))
            }
            _ => crate::scan::ScanStart::LastScanned,
        };
        let options = crate::scan::ScanOptions {
            start,
            ..crate::scan::ScanOptions::update(self.config().network)
        };
        self.scan(options, &crate::scan::ScanCancel::new()).await?;
        self.redate_other_wallet_spends(&session).await
    }

    /// Dates the entries of another wallet's spend that do not hold the block of their change
    /// by that block ([`other_wallet::misdated`]): those stored at the tip and time of the
    /// refresh that recorded them, and those whose change a scan found with no block time. A
    /// block the node gives no time for is left for the next refresh. Emits
    /// [`Event::Transaction`] for each entry it dates.
    async fn redate_other_wallet_spends(
        &self,
        session: &Arc<Session<S::Store>>,
    ) -> Result<(), crate::scan::ScanError> {
        let misdated = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| Ok(session.store.read(other_wallet::misdated)))
                .await?
        }?;
        if misdated.is_empty() {
            return Ok(());
        }
        let heights = misdated.iter().map(|(_, height)| *height).collect();
        let times = crate::legacy_history::block_times(&self.ports().node, heights).await;
        let session = Arc::clone(session);
        let redated = self
            .blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    let mut redated = Vec::new();
                    for (tx_id, height) in misdated {
                        if let Some(time) = times.get(&height) {
                            other_wallet::redate(repos, tx_id, height, *time)?;
                            redated.push(tx_id);
                        }
                    }
                    Ok::<_, StoreError>(redated)
                }))
            })
            .await??;
        for tx_id in redated {
            self.emit(
                StateChange {
                    tx_id,
                    from: TxState::Confirmed,
                    to: TxState::Confirmed,
                }
                .into(),
            );
        }
        Ok(())
    }

    fn record_changes(&self, summary: &mut RefreshSummary, changes: Vec<StateChange>) {
        for change in changes {
            match change.to {
                TxState::Confirmed => {
                    summary.confirmed_transactions =
                        summary.confirmed_transactions.saturating_add(1);
                    info!(tx_id = %change.tx_id, "transaction confirmed");
                }
                TxState::Expired => {
                    summary.expired_transactions = summary.expired_transactions.saturating_add(1);
                    info!(tx_id = %change.tx_id, "transaction expired");
                }
                // The steps that end transactions otherwise log what they ended.
                _ => {}
            }
            self.emit(change.into());
        }
    }
}

/// The wallet's minimum confirmations; an absent or unreadable setting reads as `default`.
pub(crate) fn minimum_confirmations(
    repos: &dyn Repositories,
    default: u64,
) -> Result<u64, StoreError> {
    Ok(repos
        .setting(MINIMUM_CONFIRMATIONS_SETTING)?
        .and_then(|text| text.parse().ok())
        .filter(|count| *count >= 1)
        .unwrap_or(default))
}

/// `request` as a spend from this wallet runs it: never with fewer confirmations than the
/// minimum the user stored (ADR 0027), whatever the caller asked for, and never with none, so
/// an unconfirmed output is never spent.
pub(crate) fn with_spend_confirmations(
    repos: &dyn Repositories,
    mut request: SelectionRequest,
) -> Result<SelectionRequest, StoreError> {
    let stored = repos
        .setting(MINIMUM_CONFIRMATIONS_SETTING)?
        .and_then(|text| text.parse().ok())
        .filter(|count| *count >= 1);
    request.minimum_confirmations = request
        .minimum_confirmations
        .max(stored.unwrap_or(1))
        .max(1);
    Ok(request)
}

/// A stored height that does not parse is ignored: the next refresh applies whatever the node
/// says, as on a new wallet.
pub(crate) fn last_confirmed(repos: &dyn Repositories) -> Result<Option<Height>, StoreError> {
    Ok(match repos.setting(LAST_CONFIRMED_SETTING)? {
        Some(text) => {
            let height = text.parse().ok().map(Height::new);
            if height.is_none() {
                warn!("last confirmed height unreadable");
            }
            height
        }
        None => None,
    })
}

/// Raises the last confirmed height to what `tip` confirms, as [`chain::observe_tip`] decides.
/// A scan confirms tips in the chain position only, so a confirmed position at or below `tip`
/// raises it too: otherwise a tip held by one refresh and confirmed by the update scan after it
/// would never reach the last confirmed height.
fn record_confirmed(
    repos: &mut dyn Repositories,
    tip: Height,
    now: Timestamp,
) -> Result<(), StoreError> {
    let stored = last_confirmed(repos)?;
    chain::observe_tip(repos, stored, tip, now)?;
    if let Some(height) = chain::position(repos)?
        .confirmed_height()
        .filter(|confirmed| *confirmed <= tip)
        && stored.is_none_or(|stored| height > stored)
    {
        repos.put_setting(LAST_CONFIRMED_SETTING, &height.value().to_string())?;
    }
    Ok(())
}

/// What a refresh starts from.
struct KnownState {
    last_confirmed: Option<Height>,
    position: ChainPosition,
    /// Every output the node is asked about, in every account: all those not stored as spent,
    /// and those a recent refresh took for another wallet's spend, apart from candidates.
    tracked: Vec<(Commitment, OutputStatus)>,
    /// The coinbase candidates, by the height they were built for, and the orphaned block
    /// rewards within [`CONFIRMATION_RECHECK_BLOCKS`] of the tip, by their height: their blocks
    /// are checked instead ([`Wallet::check_candidates`]).
    candidates: BTreeMap<Height, BTreeSet<Commitment>>,
}

fn known_state(repos: &dyn Repositories, tip: Height) -> Result<KnownState, RefreshError> {
    let recently_spent = other_wallet::recently_spent(repos, tip)?;
    let mut tracked = Vec::new();
    let mut candidates: BTreeMap<Height, BTreeSet<Commitment>> = BTreeMap::new();
    for account in repos.accounts()? {
        for output in repos.outputs(account.index, None)? {
            if crate::coinbase::is_candidate(&output) {
                candidates
                    .entry(output.height)
                    .or_default()
                    .insert(output.id.commitment);
            } else if crate::coinbase::is_orphaned(&output) {
                // Asked about by commitment, it would be a miss in the node's log on every
                // refresh. Its block is checked instead, for as long as a confirmed payment is
                // looked at again, so a lagging node's false orphan heals; past that, only a
                // scan finds it again.
                if output
                    .height
                    .value()
                    .saturating_add(CONFIRMATION_RECHECK_BLOCKS)
                    >= tip.value()
                {
                    candidates
                        .entry(output.height)
                        .or_default()
                        .insert(output.id.commitment);
                }
            } else if output.status != OutputStatus::Spent
                || recently_spent.contains(&output.id.commitment)
            {
                tracked.push((output.id.commitment, output.status));
            }
        }
    }
    Ok(KnownState {
        last_confirmed: last_confirmed(repos)?,
        position: chain::position(repos)?,
        tracked,
        candidates,
    })
}

/// Upstream's `apply_api_outputs`: what the node holds becomes unspent and confirms its
/// transaction, what it does not hold is spent unless it was never confirmed. Unspent outputs
/// no transaction here spent are recorded as spent by another wallet
/// ([`crate::other_wallet`]), unless the database still waits for its restore scan.
fn apply_outputs(
    repos: &mut dyn Repositories,
    tracked: &[Commitment],
    found: &BTreeMap<Commitment, OutputLocation>,
    expired: &BTreeSet<Commitment>,
    seen: ChainSeen,
    now: Timestamp,
) -> Result<StepOutcome, RefreshError> {
    let mut outcome = StepOutcome::default();
    let mut elsewhere = Vec::new();
    let recoveries = open_recoveries(repos)?;
    for commitment in tracked {
        // A concurrent cancel may have deleted it since it was read.
        let Some(stored) = repos.output(commitment.as_bytes())? else {
            continue;
        };
        // Its recovery settles it at the count: a block below it may still be replaced.
        if kept_for_recovery(&stored, &recoveries) {
            continue;
        }
        let updated = match found.get(commitment) {
            // Only another wallet's spend leaves a spent output tracked: the node holds it
            // unspent after all, so that spend is undone.
            Some(location) if stored.status == OutputStatus::Spent => {
                other_wallet::revived(repos, &stored)?;
                debug!(height = %location.height, "output taken for another wallet's spend found again");
                OutputRecord {
                    status: OutputStatus::Unspent,
                    height: location.height,
                    mmr_index: Some(location.mmr_index),
                    ..stored.clone()
                }
            }
            Some(location) => on_chain(
                repos,
                stored.clone(),
                location,
                seen.coinbase_maturity,
                now,
                &mut outcome,
            )?,
            None => {
                if other_wallet::spent_elsewhere(repos, &stored, seen.tip, seen.coinbase_maturity)?
                {
                    elsewhere.push(stored.clone());
                }
                missing(stored.clone(), &mut outcome)
            }
        };
        if updated != stored {
            repos.put_output(&updated)?;
        }
    }
    if !elsewhere.is_empty() && !crate::lifecycle::restore_scan_pending(repos)? {
        let highest = elsewhere
            .iter()
            .map(|output| output.height)
            .max()
            .unwrap_or(seen.tip);
        // The spend lies above the last tip that saw every output, and in or above the block of
        // the newest one.
        let after = seen
            .last_confirmed
            .unwrap_or(Height::ZERO)
            .max(Height::new(highest.value().saturating_sub(1)));
        outcome.changes.extend(other_wallet::record(
            repos, &elsewhere, after, seen.tip, now,
        )?);
    }
    crate::coinbase::delete_stale(repos, seen.tip, expired)?;
    Ok(outcome)
}

fn on_chain(
    repos: &mut dyn Repositories,
    mut output: OutputRecord,
    location: &OutputLocation,
    coinbase_maturity: u64,
    now: Timestamp,
    outcome: &mut StepOutcome,
) -> Result<OutputRecord, RefreshError> {
    if crate::coinbase::is_orphaned(&output) {
        outcome.confirmed_outputs = outcome.confirmed_outputs.saturating_add(1);
        let lock_height = location.height.checked_add_blocks(coinbase_maturity)?;
        outcome.changes.extend(crate::coinbase::confirm_again(
            repos,
            &mut output,
            location.height,
            lock_height,
            now,
        )?);
    } else if crate::coinbase::is_candidate(&output) {
        outcome.confirmed_outputs = outcome.confirmed_outputs.saturating_add(1);
        let lock_height = location.height.checked_add_blocks(coinbase_maturity)?;
        outcome.changes.push(crate::coinbase::confirm(
            repos,
            &mut output,
            location.height,
            lock_height,
            now,
        )?);
    } else if output.status == OutputStatus::Unconfirmed {
        output.status = OutputStatus::Unspent;
        outcome.confirmed_outputs = outcome.confirmed_outputs.saturating_add(1);
        debug!(height = %location.height, "output confirmed");
        // One output on chain is enough to confirm the transaction that created it.
        if let Some(tx_id) = output.tx {
            outcome
                .changes
                .extend(confirm(repos, tx_id, location.height, now)?);
        }
    } else if let Some(tx_id) = output.tx
        && location.height != output.height
    {
        follow_confirmation(repos, tx_id, output.height, location.height)?;
    }
    output.height = location.height;
    output.mmr_index = Some(location.mmr_index);
    Ok(output)
}

/// Moves a transaction's confirmation height with the output that confirmed it, which a
/// reorganisation mined again at another height. The confirming output is the one whose stored
/// height is the transaction's: an input it spent was mined earlier, below it.
fn follow_confirmation(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    stored: Height,
    found: Height,
) -> Result<(), StoreError> {
    if repos.confirmed_height(tx_id)? == Some(stored) {
        repos.set_confirmed_height(tx_id, found)?;
        debug!(tx_id = %tx_id, height = %found, "confirmation height moved");
    }
    Ok(())
}

fn missing(mut output: OutputRecord, outcome: &mut StepOutcome) -> OutputRecord {
    if matches!(output.status, OutputStatus::Unspent | OutputStatus::Locked) {
        output.status = OutputStatus::Spent;
        outcome.spent_outputs = outcome.spent_outputs.saturating_add(1);
        debug!(height = %output.height, "output spent");
    }
    output
}

/// Confirms an open transaction at `height`, the height of the output or kernel that confirmed
/// it. A cancelled or expired one stays as it is: the user ended it here, even though the peer
/// completed it; its outputs still count once found.
pub(crate) fn confirm(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Height,
    now: Timestamp,
) -> Result<Option<StateChange>, RefreshError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    if is_final(entry.state) {
        if entry.state != TxState::Confirmed {
            debug!(tx_id = %tx_id, "ended transaction found on chain");
        }
        return Ok(None);
    }
    let change = apply_transition(repos, tx_id, TxState::Confirmed, now)?;
    repos.set_confirmed_height(tx_id, height)?;
    forget_receive_seen(repos, tx_id)?;
    Ok(change)
}

fn confirm_all(
    repos: &mut dyn Repositories,
    confirmed: &[(TxId, Height)],
    now: Timestamp,
) -> Result<Vec<StateChange>, RefreshError> {
    let mut changes = Vec::new();
    for &(tx_id, height) in confirmed {
        changes.extend(confirm(repos, tx_id, height, now)?);
    }
    Ok(changes)
}

/// A confirmed transaction whose kernel a refresh looks up again.
struct ConfirmedRecheck {
    tx_id: TxId,
    /// The stored confirmation height.
    confirmed: Height,
    excess: Commitment,
    /// The height of the slate the kernel comes from, below which it cannot be.
    min_height: Height,
}

/// The transactions confirmed within the last [`CONFIRMATION_RECHECK_BLOCKS`] of `tip` none of
/// whose own outputs is among those `found`, with the kernel that shows them on chain. A block
/// reward's kernel follows from its output ([`crate::coinbase::reward_kernel`]). Those whose
/// kernel the wallet does not know are left out: another entry with no slate (a scan's find of a
/// plain output, another wallet's spend) or one with no final slate stored. So are the two
/// entries of an open recovery, which settles them itself.
fn confirmed_rechecks(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
    found: &BTreeSet<Commitment>,
) -> Result<Vec<ConfirmedRecheck>, RefreshError> {
    let from = Height::new(
        tip.value()
            .saturating_sub(CONFIRMATION_RECHECK_BLOCKS.saturating_sub(1)),
    );
    let pairs: BTreeSet<TxId> = open_recoveries(repos)?
        .into_iter()
        .flat_map(|recovery| [recovery.sent_tx, recovery.received_tx])
        .collect();
    let mut rechecks = Vec::new();
    for (tx_id, confirmed) in repos.confirmed_from(from)? {
        if pairs.contains(&tx_id) {
            continue;
        }
        let Some(entry) = repos.transaction(tx_id)? else {
            continue;
        };
        let outputs = repos.outputs_of_transaction(tx_id)?;
        let on_chain = outputs
            .iter()
            .any(|output| made_by(output, confirmed) && found.contains(&output.id.commitment));
        if on_chain {
            continue;
        }
        let kernel = match entry.slate_id {
            Some(slate_id) => confirmed_kernel(repos, codecs, tx_id, &entry, slate_id)?,
            None => crate::coinbase::reward_kernel(&entry, &outputs, confirmed)
                .map(|excess| (excess, confirmed)),
        };
        if let Some((excess, min_height)) = kernel {
            rechecks.push(ConfirmedRecheck {
                tx_id,
                confirmed,
                excess,
                min_height,
            });
        }
    }
    Ok(rechecks)
}

/// Whether `output`, linked to a transaction confirmed at `confirmed`, is one the transaction
/// made rather than an input it spent: an input was mined earlier, below it.
fn made_by(output: &OutputRecord, confirmed: Height) -> bool {
    output.status == OutputStatus::Unconfirmed || output.height >= confirmed
}

/// The kernel of a confirmed transaction and the height below which it cannot be: that of its
/// final slate ([`final_kernel`]), or for a payment received, the one its S2 answered to.
fn confirmed_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    entry: &TransactionEntry,
    slate_id: Uuid,
) -> Result<Option<(Commitment, Height)>, StoreError> {
    if let Some(kernel) = final_kernel(repos, codecs, tx_id, slate_id)? {
        return Ok(Some(kernel));
    }
    if entry.direction != TxDirection::Incoming {
        return Ok(None);
    }
    let reply = stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Standard2)?;
    Ok(reply.and_then(|slate| {
        answered_excess(&slate)
            .ok()
            .map(|excess| (excess, slate.height()))
    }))
}

/// Reopens a confirmed transaction whose outputs and kernel the chain no longer holds: a
/// reorganisation took the block that confirmed it. It waits again in the state it held before:
/// `posted` when this wallet holds the final transaction, which a refresh pushes again;
/// otherwise `received` for a payment received and `sent` for an invoice paid, for the peer to
/// post. The outputs it made are unconfirmed again, any record of another wallet's spend of
/// them is undone, and the inputs it spent are locked again. Its confirmation height is
/// cleared. A block reward, which has no slate, expires instead ([`crate::coinbase::orphan`]).
fn reopen(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    now: Timestamp,
) -> Result<Option<StateChange>, RefreshError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    if entry.slate_id.is_none() {
        return Ok(crate::coinbase::orphan(repos, tx_id, now)?);
    }
    let (TxState::Confirmed, Some(slate_id), Some(confirmed)) =
        (entry.state, entry.slate_id, repos.confirmed_height(tx_id)?)
    else {
        return Ok(None);
    };
    let holds_final = match entry.direction {
        TxDirection::Outgoing => {
            stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Standard3)?.is_some()
        }
        TxDirection::Incoming => {
            entry.transport.as_deref() != Some(SELF.as_str())
                && stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Invoice3)?.is_some()
        }
    };
    let to = match (holds_final, entry.direction) {
        (true, _) => TxState::Posted,
        (false, TxDirection::Outgoing) => TxState::Sent,
        (false, TxDirection::Incoming) => TxState::Received,
    };
    for mut output in repos.outputs_of_transaction(tx_id)? {
        if made_by(&output, confirmed) {
            if output.status == OutputStatus::Spent {
                other_wallet::revived(repos, &output)?;
            }
            output.status = OutputStatus::Unconfirmed;
            output.mmr_index = None;
        } else if output.status == OutputStatus::Spent {
            output.status = OutputStatus::Locked;
        } else {
            continue;
        }
        repos.put_output(&output)?;
    }
    let change = reopen_confirmed(repos, tx_id, to, now)?;
    repos.clear_confirmed_height(tx_id)?;
    warn!(tx_id = %tx_id, height = %confirmed, "confirmed transaction no longer on chain");
    Ok(change)
}

/// Where a kernel sits on chain: the height of its block and its index in the kernel MMR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelLocation {
    pub height: Height,
    pub mmr_index: u64,
}

/// The node's answer to a lookup for one transaction, or `None` when the node refused that
/// lookup, which is then left to a later refresh rather than failing this one. Any other
/// failure still fails the refresh.
pub(crate) fn unless_refused<T>(
    tx_id: TxId,
    answer: Result<T, NodeError>,
) -> Result<Option<T>, NodeError> {
    match answer {
        Ok(answer) => Ok(Some(answer)),
        Err(error @ NodeError::Rejected { .. }) => {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "kernel lookup refused");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Open transactions with no change output, which no output of this wallet can confirm, and
/// whose final kernel is known from the final slate stored with them. Upstream skips exactly
/// the entries that both credit and debit.
fn kernel_lookups(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<Vec<KernelLookup>, RefreshError> {
    let pairs: BTreeSet<TxId> = open_recoveries(repos)?
        .into_iter()
        .flat_map(|recovery| [recovery.sent_tx, recovery.received_tx])
        .collect();
    let mut lookups = Vec::new();
    for stored in open_transactions(repos)? {
        let entry = &stored.entry;
        // A recovery's pair is confirmed when the recovery settles, at the count.
        if confirmed_by_output(entry) || pairs.contains(&stored.id) {
            continue;
        }
        let Some(slate_id) = entry.slate_id else {
            continue;
        };
        if let Some((excess, min_height)) = final_kernel(repos, codecs, stored.id, slate_id)? {
            lookups.push(KernelLookup {
                tx_id: stored.id,
                excess,
                min_height,
            });
        }
    }
    Ok(lookups)
}

/// Whether a refresh confirms the transaction of `entry` by an output it receives, its change,
/// rather than by its kernel: it both spends and receives.
pub(crate) fn confirmed_by_output(entry: &TransactionEntry) -> bool {
    entry.amount_credited != Amount::ZERO && entry.amount_debited != Amount::ZERO
}

/// The kernel excess of the final slate stored for a transaction, and the height the slate was
/// created at, below which the kernel cannot be. An invoice payer never receives the I3, so its
/// excess is taken from the stored I2, which holds both parties' public excesses.
///
/// Slates are stored by slate id and stage alone, and one slate id may name an outgoing and an
/// incoming transaction, so only the stages of the transaction's own side are read: the S3 for
/// a send (and for the incoming entry of a send to the wallet itself), the I3 for an invoice
/// this wallet issued, the I2 for an invoice this wallet paid. A payment received with an S2
/// has none: its own output confirms it, never the kernel of another payment under its id.
pub(crate) fn final_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    slate_id: Uuid,
) -> Result<Option<(Commitment, Height)>, StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    let to_self = entry.transport.as_deref() == Some(SELF.as_str());
    let final_stages: &[SlateStage] = match entry.direction {
        TxDirection::Outgoing => &[SlateStage::Standard3],
        TxDirection::Incoming if to_self => &[SlateStage::Standard3, SlateStage::Invoice3],
        TxDirection::Incoming => &[SlateStage::Invoice3],
    };
    let final_slate = final_stages
        .iter()
        .find_map(|stage| stored_slate(repos, codecs, tx_id, slate_id, *stage).transpose())
        .transpose()?;
    if let Some(slate) = final_slate {
        return Ok(slate.kernel().map(|kernel| (kernel.excess, slate.height())));
    }
    if entry.direction != TxDirection::Outgoing {
        return Ok(None);
    }
    let payment = stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Invoice2)?;
    Ok(payment.and_then(|slate| {
        answered_excess(&slate)
            .ok()
            .map(|excess| (excess, slate.height()))
    }))
}

/// The kernel of a transaction the peer may still complete without this wallet, and the height
/// below which it cannot be: one finalized here, an invoice payment once its I2 exists, and a
/// received payment once its S2 exists. The S2 holds both parties' public excesses, so the
/// excess the sender finalizes to is taken from it, as for the I2.
pub(crate) fn pending_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<Option<KernelAt>, StoreError> {
    let entry = &stored.entry;
    let Some(slate_id) = entry.slate_id else {
        return Ok(None);
    };
    match (entry.direction, entry.state) {
        (_, TxState::Finalized) | (TxDirection::Outgoing, TxState::Sent) => {
            final_kernel(repos, codecs, stored.id, slate_id)
        }
        (TxDirection::Incoming, TxState::Received) => {
            let reply = stored_slate(repos, codecs, stored.id, slate_id, SlateStage::Standard2)?;
            Ok(reply.and_then(|slate| {
                answered_excess(&slate)
                    .ok()
                    .map(|excess| (excess, slate.height()))
            }))
        }
        _ => Ok(None),
    }
}

/// Open transactions that end at `tip`: those at or past their TTL cutoff, or a send's local
/// cutoff ([`crate::send::SendRequest::local_ttl_blocks`]) when that is earlier, an invoice
/// payment [`crate::invoice::INVOICE_TTL_MARGIN_BLOCKS`] past its cutoff, and a received
/// payment with no TTL, answered with an S2, once [`UNFINALIZED_RECEIVE_BLOCKS`] have passed
/// since a refresh first saw it. A finalized or posted transaction is left out, as upstream
/// leaves out what it has finalized: its kernel may reach the chain whatever the TTL says. So
/// is the payment of an invoice over Epicbox, which the issuer may have posted:
/// [`Wallet::sweep_invoices`] offers it to the user to cancel instead. So is the incoming
/// entry of a send to the wallet itself: the wallet finalized it, and it ends with the
/// outgoing entry. Each comes with the kernel the peer may still complete it with, which is
/// looked up before it ends. Two finalized transactions are the exception, since from their
/// cutoff [`Wallet::post`] no longer posts them and their kernel stays watched like any other:
/// an invoice this wallet issued ends once its cutoff passes, the earlier of its I3's and the
/// one it was issued with, and a send this wallet finalized ends at its cutoff when the node's
/// pool refused every push of it ([`refused_send_cutoff`]).
fn expiring(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<Vec<(StoredTransaction, Option<KernelAt>)>, RefreshError> {
    let recovering = recovery_entries(repos)?;
    let mut expiring = Vec::new();
    for stored in open_transactions(repos)? {
        // Its recovery ends it at the count, or fails and leaves it to this check again.
        if recovering.contains(&stored.id) {
            continue;
        }
        let ended_post = match issued_post_cutoff(repos, codecs, &stored)? {
            Some(issued) => Some(issued),
            None => refused_send_cutoff(repos, codecs, &stored)?
                .map(|(cutoff, kernel)| (cutoff, Some(kernel))),
        };
        if let Some((cutoff, kernel)) = ended_post {
            if tip >= cutoff {
                expiring.push((stored, kernel));
            }
            continue;
        }
        if matches!(stored.entry.state, TxState::Posted | TxState::Finalized)
            || epicbox_invoice_payment(repos, &stored)?.is_some()
            || stored.entry.transport.as_deref() == Some(SELF.as_str())
        {
            continue;
        }
        let Some(slate_id) = stored.entry.slate_id else {
            continue;
        };
        let slate_ttl = ttl_cutoff(repos, codecs, stored.id, slate_id)?;
        let cutoff = match effective_cutoff(repos, stored.id, slate_ttl)? {
            Some(cutoff) if invoice_payment(repos, &stored, slate_id)? => {
                Some(payer_release_height(cutoff))
            }
            Some(cutoff) => Some(cutoff),
            None => unfinalized_receive_cutoff(repos, codecs, &stored)?,
        };
        if cutoff.is_some_and(|cutoff| tip >= cutoff) {
            let kernel = pending_kernel(repos, codecs, &stored)?;
            expiring.push((stored, kernel));
        }
    }
    Ok(expiring)
}

/// The cutoff of an invoice this wallet issued and finalized, if it has one, and its kernel:
/// for an incoming finalized or posted transaction with its I3 stored, the earlier of the I3's
/// TTL cutoff and the one it was issued with, as [`Wallet::post`] counts it.
fn issued_post_cutoff(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<Option<(Height, Option<KernelAt>)>, StoreError> {
    let entry = &stored.entry;
    let issued_post = entry.direction == TxDirection::Incoming
        && matches!(entry.state, TxState::Finalized | TxState::Posted);
    let Some(slate_id) = entry.slate_id.filter(|_| issued_post) else {
        return Ok(None);
    };
    let Some(finalized) = stored_slate(repos, codecs, stored.id, slate_id, SlateStage::Invoice3)?
    else {
        return Ok(None);
    };
    let issued = stored_slate(repos, codecs, stored.id, slate_id, SlateStage::Invoice1)?;
    let cutoff = earliest_cutoff(
        finalized.ttl_cutoff_height(),
        issued.and_then(|slate| slate.ttl_cutoff_height()),
    );
    let kernel = finalized
        .kernel()
        .map(|kernel| (kernel.excess, finalized.height()));
    Ok(cutoff.map(|cutoff| (cutoff, kernel)))
}

/// The cutoff of a send this wallet finalized that the node's pool refused every time, as
/// [`refused_every_time`] counts it, and its kernel: an outgoing `finalized` transaction, not a
/// send to the wallet itself, with its S3 and its kernel stored. Its cutoff is the one
/// [`Wallet::post`] counts. A send with no push recorded, with any push the node took, or with
/// any the wallet could not class as a refusal stays open whatever its age: the node may hold
/// it, and a send ended here frees inputs a later push could still spend.
fn refused_send_cutoff(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<Option<(Height, KernelAt)>, StoreError> {
    let entry = &stored.entry;
    let finalized_send = entry.direction == TxDirection::Outgoing
        && entry.state == TxState::Finalized
        && entry.transport.as_deref() != Some(SELF.as_str());
    let Some(slate_id) = entry.slate_id.filter(|_| finalized_send) else {
        return Ok(None);
    };
    if !repos
        .node_post(stored.id)?
        .is_some_and(|post| refused_every_time(&post))
    {
        return Ok(None);
    }
    let Some(finalized) = stored_slate(repos, codecs, stored.id, slate_id, SlateStage::Standard3)?
    else {
        return Ok(None);
    };
    let Some(kernel) = finalized.kernel() else {
        return Ok(None);
    };
    let cutoff = effective_cutoff(repos, stored.id, finalized.ttl_cutoff_height())?;
    Ok(cutoff.map(|cutoff| (cutoff, (kernel.excess, finalized.height()))))
}

/// Every incoming payment in state `received` that this wallet answered with an S2, other than
/// the incoming entry of a send to the wallet itself, with what [`WaitingReceive`] holds. The
/// inputs are read from the stored S2, which carries the S1's inputs unchanged.
fn waiting_receives(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<Vec<WaitingReceive>, RefreshError> {
    let mut waiting = Vec::new();
    for stored in open_transactions(repos)? {
        let entry = &stored.entry;
        if entry.direction != TxDirection::Incoming
            || entry.state != TxState::Received
            || entry.transport.as_deref() == Some(SELF.as_str())
        {
            continue;
        }
        let Some(slate_id) = entry.slate_id else {
            continue;
        };
        let Some(reply) = stored_slate(repos, codecs, stored.id, slate_id, SlateStage::Standard2)?
        else {
            continue;
        };
        let outputs = repos
            .outputs_of_transaction(stored.id)?
            .into_iter()
            .filter(|output| output.status == OutputStatus::Unconfirmed)
            .map(|output| output.id.commitment)
            .collect();
        waiting.push(WaitingReceive {
            tx_id: stored.id,
            slate_id,
            inputs: reply
                .inputs()
                .iter()
                .map(|input| input.commitment)
                .collect(),
            outputs,
            kernel: pending_kernel(repos, codecs, &stored)?,
            inputs_seen: repos.tx_marks(stored.id)?.receive_inputs_unspent,
        });
    }
    Ok(waiting)
}

/// Every finalized or posted transaction with its final slate stored: the S3 a sender or a send
/// to the wallet itself finalized, the I3 an invoice issuer finalized.
fn pending_posts(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<Vec<PendingPost>, RefreshError> {
    let recovering = recovery_entries(repos)?;
    let mut posts = Vec::new();
    for stored in open_transactions(repos)? {
        // Its recovery spends its inputs: that ends it at the count, not as spent elsewhere.
        if recovering.contains(&stored.id) {
            continue;
        }
        let entry = &stored.entry;
        let Some(slate_id) = entry
            .slate_id
            .filter(|_| matches!(entry.state, TxState::Finalized | TxState::Posted))
        else {
            continue;
        };
        let stage = match entry.direction {
            TxDirection::Outgoing => SlateStage::Standard3,
            TxDirection::Incoming => SlateStage::Invoice3,
        };
        let Some(slate) = stored_slate(repos, codecs, stored.id, slate_id, stage)? else {
            continue;
        };
        let (Some(kernel), false) = (slate.kernel(), slate.inputs().is_empty()) else {
            continue;
        };
        posts.push(PendingPost {
            tx_id: stored.id,
            inputs: slate
                .inputs()
                .iter()
                .map(|input| input.commitment)
                .collect(),
            kernel: (kernel.excess, slate.height()),
        });
    }
    Ok(posts)
}

/// Ends a pending post that can never be mined, if it is still finalized or posted, as
/// [`supersede`] ends a receive, with its self-send partner, and records its `lost` inputs as
/// another wallet's spend.
fn end_spent_post(
    repos: &mut dyn Repositories,
    post: &SpentPost,
    ended_at: Height,
    now: Timestamp,
) -> Result<Vec<StateChange>, RefreshError> {
    let tx_id = post.tx_id;
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(Vec::new());
    };
    if !matches!(entry.state, TxState::Finalized | TxState::Posted) {
        return Ok(Vec::new());
    }
    let partner = self_send_partner(repos, &entry)?;
    let (excess, floor) = post.watch;
    let mut lost = Vec::new();
    for commitment in &post.lost {
        let Some(output) = repos.output(commitment.as_bytes())? else {
            continue;
        };
        // Spent before its transaction releases what it holds, so the cancel does not make it
        // spendable again.
        let output = OutputRecord {
            status: OutputStatus::Spent,
            ..output
        };
        repos.put_output(&output)?;
        lost.push(output);
    }
    record_watch(repos, tx_id, excess, floor, ended_at)?;
    drop_holdings(repos, tx_id, &entry)?;
    let mut changes: Vec<StateChange> = apply_transition(repos, tx_id, TxState::Cancelled, now)?
        .into_iter()
        .collect();
    if let Some(partner) = partner {
        changes.extend(cancel_partner(
            repos,
            &partner,
            Some((excess, floor, ended_at)),
            now,
        )?);
    }
    if !lost.is_empty() && !crate::lifecycle::restore_scan_pending(repos)? {
        other_wallet::mark_inputs_lost(repos, tx_id)?;
        let highest = lost
            .iter()
            .map(|output| output.height)
            .max()
            .unwrap_or(ended_at);
        let after = last_confirmed(repos)?
            .unwrap_or(Height::ZERO)
            .max(Height::new(highest.value().saturating_sub(1)));
        changes.extend(other_wallet::record(repos, &lost, after, ended_at, now)?);
    }
    info!(tx_id = %tx_id, "transaction that can never be mined ended");
    Ok(changes)
}

/// Ends a superseded received payment as a cancel does, if it still waits for its sender, and
/// keeps watching its kernel `watch` from `ended_at`.
fn supersede(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    watch: KernelAt,
    ended_at: Height,
    now: Timestamp,
) -> Result<Option<StateChange>, RefreshError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    if entry.direction != TxDirection::Incoming || entry.state != TxState::Received {
        return Ok(None);
    }
    let (excess, min_height) = watch;
    record_watch(repos, tx_id, excess, min_height, ended_at)?;
    drop_holdings(repos, tx_id, &entry)?;
    Ok(apply_transition(repos, tx_id, TxState::Cancelled, now)?)
}

/// The height a received payment with no TTL ends at, if it is one: an incoming `received`
/// transaction this wallet answered with an S2. The window counts from the tip it was received
/// at, or for one received before that was recorded, from the first refresh that saw it; never
/// from the slate's height, which the sender chose.
fn unfinalized_receive_cutoff(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<Option<Height>, StoreError> {
    if !awaits_finalization(repos, codecs, stored)? {
        return Ok(None);
    }
    let Some(seen) = receive_seen_at(repos, stored.id)? else {
        return Ok(None);
    };
    // A height that overflows is never reached, so the payment never ends by itself.
    Ok(Some(
        seen.checked_add_blocks(UNFINALIZED_RECEIVE_BLOCKS)
            .unwrap_or(Height::new(u64::MAX)),
    ))
}

/// Whether `stored` is a received payment with no TTL that waits for its sender to finalize.
fn awaits_finalization(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<bool, StoreError> {
    let Some(slate_id) = answered_receipt(repos, stored)? else {
        return Ok(false);
    };
    Ok(ttl_cutoff(repos, codecs, stored.id, slate_id)?.is_none())
}

/// The slate id of `stored` when it is a received payment that waits for its sender to
/// finalize: incoming, `received`, answered with an S2.
fn answered_receipt(
    repos: &dyn Repositories,
    stored: &StoredTransaction,
) -> Result<Option<Uuid>, StoreError> {
    let entry = &stored.entry;
    let Some(slate_id) = entry
        .slate_id
        .filter(|_| entry.direction == TxDirection::Incoming && entry.state == TxState::Received)
    else {
        return Ok(None);
    };
    Ok(repos
        .slate(slate_id, SlateStage::Standard2)?
        .map(|_| slate_id))
}

fn receive_seen_at(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<Height>, StoreError> {
    Ok(repos.tx_marks(tx_id)?.receive_seen_at)
}

/// Forgets when a refresh first saw a received payment. Run it when the payment ends.
pub(crate) fn forget_receive_seen(
    repos: &mut dyn Repositories,
    tx_id: TxId,
) -> Result<(), StoreError> {
    let mut marks = repos.tx_marks(tx_id)?;
    marks.receive_seen_at = None;
    marks.receive_inputs_unspent = false;
    repos.put_tx_marks(tx_id, &marks)
}

/// Records `tip` as the height the payment `tx_id` was received at, unless one is recorded.
pub(crate) fn record_receive_seen(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    tip: Height,
) -> Result<(), StoreError> {
    let mut marks = repos.tx_marks(tx_id)?;
    if marks.receive_seen_at.is_none() {
        marks.receive_seen_at = Some(tip);
        repos.put_tx_marks(tx_id, &marks)?;
    }
    Ok(())
}

/// Records `tip` as the height a refresh first saw each received payment that waits for its
/// sender and has none recorded: one received before receives recorded their tip.
fn record_receives_seen(repos: &mut dyn Repositories, tip: Height) -> Result<(), RefreshError> {
    for stored in open_transactions(repos)? {
        if answered_receipt(repos, &stored)?.is_some() {
            record_receive_seen(repos, stored.id, tip)?;
        }
    }
    Ok(())
}

/// Expires every transaction [`expiring`] lists that is in `cleared`, the ones whose kernel
/// the node's pool and chain were found not to hold, as upstream cancels it. One whose kernel
/// is known stays watched, so it is confirmed if the peer still completes it, unless it is a
/// payment its sender's TTL ended with nothing posted ([`lapsed_receipt`]).
fn expire_all(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
    cleared: &BTreeSet<TxId>,
    now: Timestamp,
) -> Result<Vec<StateChange>, RefreshError> {
    let mut changes = Vec::new();
    for (stored, kernel) in expiring(repos, codecs, tip)? {
        if !cleared.contains(&stored.id) {
            continue;
        }
        // Its kernel is in neither the pool nor the chain: a payment its sender's TTL ended
        // with nothing posted is not watched for after all.
        if let Some((excess, min_height)) = kernel
            && !lapsed_receipt(repos, codecs, stored.id, &stored.entry, tip)?
        {
            let floor = chain::kernel_floor(min_height, tip);
            record_watch(repos, stored.id, excess, floor, tip)?;
        }
        changes.extend(expire(repos, &stored, now)?);
    }
    Ok(changes)
}

/// This wallet's invoice payments still `sent`, with their kernel excess taken from the stored
/// I2: the issuer finalizes and posts them, and the payer learns of the post only from a notice
/// or the node's pool.
fn unposted_payments(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<Vec<(TxId, SlateId, Commitment)>, RefreshError> {
    let mut unposted = Vec::new();
    for stored in open_transactions(repos)? {
        let Some(slate_id) = stored.entry.slate_id else {
            continue;
        };
        if stored.entry.state != TxState::Sent || !invoice_payment(repos, &stored, slate_id)? {
            continue;
        }
        if let Some((excess, _)) = final_kernel(repos, codecs, stored.id, slate_id)? {
            unposted.push((stored.id, SlateId::from_bytes(*slate_id.as_bytes()), excess));
        }
    }
    Ok(unposted)
}

/// Whether `stored` is this wallet's payment of an invoice: outgoing, answered with an I2.
fn invoice_payment(
    repos: &dyn Repositories,
    stored: &StoredTransaction,
    slate_id: Uuid,
) -> Result<bool, StoreError> {
    Ok(stored.entry.direction == TxDirection::Outgoing
        && repos.slate(slate_id, SlateStage::Invoice2)?.is_some())
}

/// The TTL cutoff every stage of a slate carries, read from the first stage stored.
pub(crate) fn ttl_cutoff(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    slate_id: Uuid,
) -> Result<Option<Height>, StoreError> {
    for stored in repos.slates(slate_id)? {
        if let Some(slate) = decode_stored(codecs, tx_id, &stored.bytes) {
            return Ok(slate.ttl_cutoff_height());
        }
    }
    Ok(None)
}

/// Releases what the transaction holds, as the owner's cancel does, and marks it expired.
fn expire(
    repos: &mut dyn Repositories,
    stored: &StoredTransaction,
    now: Timestamp,
) -> Result<Option<StateChange>, RefreshError> {
    drop_holdings(repos, stored.id, &stored.entry)?;
    Ok(apply_transition(repos, stored.id, TxState::Expired, now)?)
}

pub(crate) fn open_transactions(
    repos: &dyn Repositories,
) -> Result<Vec<StoredTransaction>, RefreshError> {
    let mut open = Vec::new();
    for account in repos.accounts()? {
        open.extend(
            repos
                .transactions(account.index)?
                .into_iter()
                .filter(|stored| !is_final(stored.entry.state)),
        );
    }
    Ok(open)
}

pub(crate) fn stored_slate(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    slate_id: Uuid,
    stage: SlateStage,
) -> Result<Option<Slate>, StoreError> {
    Ok(repos
        .slate(slate_id, stage)?
        .and_then(|stored| decode_stored(codecs, tx_id, &stored.bytes)))
}

/// A stored slate was validated when it was stored, so one that no longer decodes is skipped
/// with a warning rather than blocking every later refresh.
pub(crate) fn decode_stored(codecs: &CodecRegistry, tx_id: TxId, bytes: &[u8]) -> Option<Slate> {
    match codecs.decode(&WireSlate::binary(MediaType::JSON, bytes.to_vec())) {
        Ok(slate) => Some(slate),
        Err(error) => {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "stored slate unreadable");
            None
        }
    }
}

/// The height balances are computed at: the highest tip a refresh or scan confirmed, or zero
/// before any. A tip held as pending does not count, so the balance a refresh reports equals
/// what [`Wallet::balance`] reads from the store afterwards.
pub(crate) fn balance_height(repos: &dyn Repositories) -> Result<Height, StoreError> {
    Ok([
        last_confirmed(repos)?,
        chain::position(repos)?.confirmed_height(),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(Height::ZERO))
}

/// The balance of every account at [`balance_height`], in the categories of upstream's
/// `retrieve_info`.
fn balances(repos: &dyn Repositories, default_minimum: u64) -> Result<Vec<Balance>, RefreshError> {
    Ok(account_balances(repos, default_minimum)?)
}

fn account_balances(
    repos: &dyn Repositories,
    default_minimum: u64,
) -> Result<Vec<Balance>, WalletError> {
    let height = balance_height(repos)?;
    let minimum = minimum_confirmations(repos, default_minimum)?;
    let mut balances = Vec::new();
    for account in repos.accounts()? {
        let outputs = repos.outputs(account.index, None)?;
        let apart = counted_apart(repos, &outputs)?;
        balances.push(
            balance(account.index, &outputs, height, minimum, &apart)
                .map_err(WalletError::Balance)?,
        );
    }
    Ok(balances)
}

fn balance(
    account: AccountIndex,
    outputs: &[OutputRecord],
    height: Height,
    minimum_confirmations: u64,
    apart: &CountedApart,
) -> Result<Balance, ArithmeticError> {
    let mut balance = Balance {
        account,
        height,
        minimum_confirmations,
        total: Amount::ZERO,
        spendable: Amount::ZERO,
        awaiting_confirmation: Amount::ZERO,
        awaiting_finalization: Amount::ZERO,
        immature: Amount::ZERO,
        locked: Amount::ZERO,
    };
    for output in outputs {
        let Some(category) = balance_category(output, height, minimum_confirmations, apart) else {
            continue;
        };
        let slot = match category {
            // Money nobody has sent yet: the payer may never pay.
            BalanceCategory::UnpaidInvoice => continue,
            BalanceCategory::Spendable => &mut balance.spendable,
            BalanceCategory::AwaitingConfirmation => &mut balance.awaiting_confirmation,
            BalanceCategory::AwaitingFinalization => &mut balance.awaiting_finalization,
            BalanceCategory::Immature => &mut balance.immature,
            BalanceCategory::Locked => &mut balance.locked,
        };
        if category == BalanceCategory::AwaitingFinalization {
            // Amounts not yet on chain are only what a slate claimed: a sum of them saturates
            // rather than failing the whole balance.
            *slot = Amount::new(slot.value().saturating_add(output.amount.value()));
            continue;
        }
        *slot = slot.checked_add(output.amount)?;
        balance.total = balance.total.checked_add(output.amount)?;
    }
    Ok(balance)
}

/// Where an output counts in [`Balance`]. Every category but
/// [`BalanceCategory::AwaitingFinalization`] also counts in its total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceCategory {
    Spendable,
    /// Unspent, with fewer confirmations than the wallet's [`Wallet::minimum_confirmations`],
    /// or an output a send to the wallet itself makes, from when the node took that send until
    /// it is mined.
    AwaitingConfirmation,
    /// Not yet on chain: the change or the received output of a transaction in progress.
    AwaitingFinalization,
    /// A coinbase output before its lock height.
    Immature,
    /// An input of a send in progress.
    Locked,
    /// The output an invoice this wallet issued asks for, while nobody has paid it. It counts
    /// in no figure of [`Balance`], its total included, where upstream's `retrieve_info`
    /// counts it as awaiting finalization. Once a payment is finalized it is
    /// [`BalanceCategory::AwaitingFinalization`].
    UnpaidInvoice,
}

/// The transactions among those of a set of outputs whose outputs count apart from their status.
#[derive(Debug, Default)]
struct CountedApart {
    unpaid_invoices: BTreeSet<TxId>,
    /// Both entries of every send to the wallet itself whose outgoing entry is posted.
    posted_self_sends: BTreeSet<TxId>,
    /// The payments with an open recovery, each with whether the node took the recovery.
    recovering: BTreeMap<TxId, bool>,
}

fn counted_apart(
    repos: &dyn Repositories,
    outputs: &[OutputRecord],
) -> Result<CountedApart, WalletError> {
    Ok(CountedApart {
        unpaid_invoices: unpaid_invoices(repos, outputs)?,
        posted_self_sends: posted_self_sends(repos, outputs)?,
        recovering: recovering(repos)?,
    })
}

/// The entries among those of `outputs` of a send to the wallet itself that the node took:
/// both entries of one whose outgoing entry is posted. Until it is mined its coins are on their
/// way back to the wallet, so they count once, as awaiting confirmation, and not also as the
/// inputs locked for it.
fn posted_self_sends(
    repos: &dyn Repositories,
    outputs: &[OutputRecord],
) -> Result<BTreeSet<TxId>, WalletError> {
    let mut checked = BTreeSet::new();
    let mut posted = BTreeSet::new();
    for output in outputs {
        let (OutputStatus::Locked | OutputStatus::Unconfirmed, Some(tx_id)) =
            (output.status, output.tx)
        else {
            continue;
        };
        if !checked.insert(tx_id) {
            continue;
        }
        let Some(entry) = repos
            .transaction(tx_id)?
            .filter(|entry| entry.transport.as_deref() == Some(SELF.as_str()))
        else {
            continue;
        };
        let outgoing_state = match entry.direction {
            TxDirection::Outgoing => Some(entry.state),
            TxDirection::Incoming => {
                self_send_partner(repos, &entry)?.map(|partner| partner.entry.state)
            }
        };
        if outgoing_state == Some(TxState::Posted) {
            posted.insert(tx_id);
        }
    }
    Ok(posted)
}

/// The transactions among those of `outputs` that are invoices this wallet issued and nobody
/// paid yet: incoming, still `received`, with the I1 stored. Finalizing a payment moves the
/// transaction to `finalized`; cancelling it, or a sweep, drops its output.
fn unpaid_invoices(
    repos: &dyn Repositories,
    outputs: &[OutputRecord],
) -> Result<BTreeSet<TxId>, StoreError> {
    let mut unpaid = BTreeSet::new();
    for output in outputs {
        let (OutputStatus::Unconfirmed, Some(tx_id)) = (output.status, output.tx) else {
            continue;
        };
        if unpaid.contains(&tx_id) {
            continue;
        }
        let Some(entry) = repos.transaction(tx_id)? else {
            continue;
        };
        let (TxDirection::Incoming, TxState::Received, Some(slate_id)) =
            (entry.direction, entry.state, entry.slate_id)
        else {
            continue;
        };
        if repos.slate(slate_id, SlateStage::Invoice1)?.is_some() {
            unpaid.insert(tx_id);
        }
    }
    Ok(unpaid)
}

/// The category `output` counts in at `height`, as upstream's `retrieve_info` sorts it; `None`
/// for a spent output and an unconfirmed coinbase output, which count nowhere. The output of an
/// unpaid invoice is [`BalanceCategory::UnpaidInvoice`]. A send to the wallet itself that the
/// node took is counted by what it makes, as [`BalanceCategory::AwaitingConfirmation`], and the
/// inputs it spends count nowhere, as once it is mined. A payment with an open recovery
/// counts no change, and once the node took the recovery its inputs count nowhere either.
fn balance_category(
    output: &OutputRecord,
    height: Height,
    minimum_confirmations: u64,
    apart: &CountedApart,
) -> Option<BalanceCategory> {
    let coinbase = output.id.features.is_coinbase();
    let self_sent = output
        .tx
        .is_some_and(|tx| apart.posted_self_sends.contains(&tx));
    let unpaid = &apart.unpaid_invoices;
    // A payment being recovered never makes its change, and once the node took the recovery
    // its inputs count as what the recovery makes.
    let recovery_taken = output.tx.and_then(|tx| apart.recovering.get(&tx).copied());
    match output.status {
        OutputStatus::Unconfirmed if recovery_taken.is_some() => None,
        OutputStatus::Locked if recovery_taken == Some(true) => None,
        OutputStatus::Unspent if coinbase && output.lock_height > height => {
            Some(BalanceCategory::Immature)
        }
        OutputStatus::Unspent if confirmations(output, height) < minimum_confirmations => {
            Some(BalanceCategory::AwaitingConfirmation)
        }
        OutputStatus::Unspent => Some(BalanceCategory::Spendable),
        // Upstream ignores unconfirmed coinbase outputs, which a wallet that does not mine
        // never has.
        OutputStatus::Unconfirmed
            if !coinbase && output.tx.is_some_and(|tx| unpaid.contains(&tx)) =>
        {
            Some(BalanceCategory::UnpaidInvoice)
        }
        OutputStatus::Unconfirmed if !coinbase && self_sent => {
            Some(BalanceCategory::AwaitingConfirmation)
        }
        OutputStatus::Unconfirmed if !coinbase => Some(BalanceCategory::AwaitingFinalization),
        OutputStatus::Locked if self_sent => None,
        OutputStatus::Locked => Some(BalanceCategory::Locked),
        OutputStatus::Unconfirmed | OutputStatus::Spent => None,
    }
}

/// A stored output with what [`Wallet::outputs`] adds to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDetails {
    pub output: OutputRecord,
    /// At the height [`Wallet::balance`] is computed at. Zero for an unconfirmed output.
    pub confirmations: u64,
    /// Where it counts in [`Wallet::balance`]; `None` for a spent output and an input of a send
    /// to the wallet itself that the node took.
    pub category: Option<BalanceCategory>,
}

/// An output at height `n` has one confirmation at height `n`, none above the tip.
fn confirmations(output: &OutputRecord, height: Height) -> u64 {
    height
        .value()
        .checked_sub(output.height.value())
        .map_or(0, |blocks| blocks.saturating_add(1))
}
