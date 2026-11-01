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
//! posted transactions whose inputs were spent elsewhere, then TTL expiry, then the kernel checks
//! that make a send releasable
//! ([`crate::release`]). Every step re-reads what it changes inside its transaction,
//! so dropping the future between steps, or a send running at the same time, leaves a
//! consistent store that the next refresh completes.
//!
//! Upstream's update also rescans the last blocks for outputs it does not know; in LEPIC that is
//! a separate [`Wallet::scan`] with [`crate::scan::ScanOptions::update`], run after a refresh.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::ops::RangeInclusive;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::{NodeApi, NodeError, OutputLocation};
use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, OutputRecord, OutputStatus, Repositories, SlateStage, StoreError,
    StoredTransaction, TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::cancel::{cancel_partner, drop_holdings, pool_kernels, self_send_partner};
use crate::chain::{self, ChainPosition, ImplausibleNodeData};
use crate::epicbox_invoice::epicbox_invoice_payment;
use crate::error::WalletError;
use crate::event::{Balance, Event, SlateId, SupersededReceive};
use crate::finalize::kernel_excess;
use crate::invoice::{earliest_cutoff, payer_release_height};
use crate::lifecycle::Session;
use crate::other_wallet;
use crate::ports::{SecretVault, StoreOpener};
use crate::release::{
    RELEASED_WATCH_BLOCKS, ReleaseCheck, record_kernel_absent, record_watch, release_check,
};
use crate::selection::SelectionRequest;
use crate::self_send::SELF;
use crate::send_limit::effective_cutoff;
use crate::state::{StateChange, apply_transition, is_final};
use crate::wallet::Wallet;

/// Confirmations an unspent output needs to count as spendable, and to be selected for a send,
/// in a wallet that has not set its own ([`Wallet::set_minimum_confirmations`]): 6. The old GUI
/// wallet counted 3 and `epic-wallet` defaults to 10; ADR 0027 gives the reasons.
pub const DEFAULT_MINIMUM_CONFIRMATIONS: u64 = 6;

/// The values [`Wallet::set_minimum_confirmations`] accepts: 1 is the fastest, and nothing
/// deeper than 30 blocks is useful on Epic Cash (ADR 0027).
pub const MINIMUM_CONFIRMATIONS_RANGE: RangeInclusive<u64> = 1..=30;

pub(crate) const MINIMUM_CONFIRMATIONS_SETTING: &str = "wallet.minimum_confirmations";

/// Blocks after a refresh first saw a received payment with no TTL that its sender has not
/// finalized, after which a refresh ends it: a week of blocks, as long as a released send is
/// watched.
pub const UNFINALIZED_RECEIVE_BLOCKS: u64 = RELEASED_WATCH_BLOCKS;

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
    /// marks the ones it holds unspent and confirms their transactions, marks unspent and
    /// locked ones it does not hold spent once a second request misses them too, confirms open
    /// transactions with no change output by their kernel, and expires transactions at or past
    /// their TTL cutoff, or a send at or past its local cutoff
    /// ([`crate::send::SendRequest::local_ttl_blocks`]), or an invoice payment
    /// [`crate::invoice::INVOICE_TTL_MARGIN_BLOCKS`] past its cutoff, releasing their inputs. A
    /// posted or finalized transaction is never expired, since it may still be mined, except an
    /// invoice this wallet issued, at the cutoff from which [`Wallet::post`] no longer posts it.
    /// One that can never be mined, because an input it spends is gone from the chain while
    /// neither the node's pool nor its chain holds its kernel, is cancelled. Either stays
    /// watched as below. Last, it
    /// looks up the kernel of each finalized or posted send
    /// [`crate::release::RELEASE_AFTER_BLOCKS`] or more after it was finalized,
    /// counted at the highest confirmed tip: a kernel found confirms the send, a missing one
    /// makes it releasable (`Wallet::release`). Then it looks for each transaction that was
    /// released, cancelled or expired although its peer may still complete it: by its kernel
    /// for [`crate::release::RELEASED_WATCH_BLOCKS`] after a send ended and
    /// [`crate::release::ENDED_RECEIVE_WATCH_BLOCKS`] after a received payment ended, then by
    /// its outputs, with no end. One found moves from `cancelled` or `expired` to `confirmed`
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
    /// with the first replaces the first. The release check's kernels do not, so the tip it
    /// counts at is the one reported and stored. Before expiring anything the tip is asked for
    /// again, unless it already was, and the two must agree. When the tip expired nothing, it
    /// raises the last confirmed height if it is at most [`crate::chain::TIP_STEP_BLOCKS`]
    /// above it; a tip further ahead is held until a later refresh or scan sees the chain at
    /// or above it.
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
        let commitments: Vec<Commitment> =
            tracked.iter().map(|(commitment, _)| *commitment).collect();
        let found = self.locate(&commitments, &tracked, &mut tip).await?;
        let found_outputs: BTreeSet<Commitment> = found.keys().copied().collect();
        let mut summary = RefreshSummary::default();

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
                    .write(|repos| apply_outputs(repos, &commitments, &found, seen, now)))
            })
            .await??
        };

        summary.confirmed_outputs = outcome.confirmed_outputs;
        summary.spent_outputs = outcome.spent_outputs;
        self.record_changes(&mut summary, outcome.changes);

        let kernel_missing = self
            .confirm_kernels(&session, &mut tip, now, &mut summary)
            .await?;
        self.end_superseded(&session, &found_outputs, &mut tip, now, &mut summary)
            .await?;
        self.end_spent_posts(&session, &tip, now, &mut summary)
            .await?;

        summary.height = tip.height;
        self.expire_unheld(&session, &mut tip, now, &mut summary)
            .await?;
        self.check_releases(&session, tip.height, &kernel_missing, now, &mut summary)
            .await?;
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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
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
                    record_receives_seen(repos, &codecs, height)?;
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
        self.record_changes(summary, changes);
        Ok(())
    }

    /// Raises a balance event per account.
    async fn emit_balances(&self, session: &Arc<Session<S::Store>>) -> Result<(), RefreshError> {
        let session = Arc::clone(session);
        let balances = self
            .blocking(move |_, _| Ok(session.store.read(balances)))
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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
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

    /// Looks up the kernel of every finalized or posted send that a missing kernel would make
    /// releasable at the highest confirmed tip, unless this refresh already missed it. A kernel
    /// found confirms its transaction; a missing one is recorded at that height.
    async fn check_releases(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: Height,
        missing: &BTreeSet<TxId>,
        now: Timestamp,
        summary: &mut RefreshSummary,
    ) -> Result<(), RefreshError> {
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let (height, due) = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| releases_due(repos, &codecs, tip)))
            })
            .await??
        };
        if due.is_empty() {
            return Ok(());
        }
        let mut confirmed = Vec::new();
        let mut absent = Vec::new();
        for (tx_id, check) in due {
            if missing.contains(&tx_id) {
                absent.push(tx_id);
                continue;
            }
            let floor = chain::kernel_floor(check.min_height, tip);
            let answer = self
                .ports()
                .node
                .get_kernel(&check.excess, Some(floor), Some(tip))
                .await;
            let Some(kernel) = unless_refused(tx_id, answer)? else {
                continue;
            };
            match kernel {
                Some(kernel) => {
                    chain::check_kernel_height(kernel.height, floor, tip)?;
                    confirmed.push((tx_id, kernel.height));
                }
                None => absent.push(tx_id),
            }
        }
        let session = Arc::clone(session);
        let changes = self
            .blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    for &tx_id in &absent {
                        debug!(tx_id = %tx_id, height = %height, "kernel still not on chain");
                        record_kernel_absent(repos, tx_id, height)?;
                    }
                    confirm_all(repos, &confirmed, now)
                }))
            })
            .await??;
        self.record_changes(summary, changes);
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
                minimum_confirmations(repos)?,
                &apart,
            )
            .map_err(WalletError::Balance)
        })
    }

    /// The confirmations an output needs to count as spendable in [`Wallet::balance`] and to be
    /// selected for a send: the stored setting, or [`DEFAULT_MINIMUM_CONFIRMATIONS`] for a
    /// wallet that never set one. Reads only the store.
    ///
    /// Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn minimum_confirmations(&self) -> Result<u64, WalletError> {
        let session = self.session()?;
        session
            .store
            .read(|repos| Ok(minimum_confirmations(repos)?))
    }

    /// Stores the wallet's minimum confirmations, then re-splits the balance of every account
    /// at the stored tip and emits one [`Event::Balance`] for each, without asking the node.
    ///
    /// Fails with [`WalletError::MinimumConfirmationsOutOfRange`] outside
    /// [`MINIMUM_CONFIRMATIONS_RANGE`], or [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn set_minimum_confirmations(&self, count: u64) -> Result<(), WalletError> {
        if !MINIMUM_CONFIRMATIONS_RANGE.contains(&count) {
            return Err(WalletError::MinimumConfirmationsOutOfRange { count });
        }
        let session = self.session()?;
        session
            .store
            .write(|repos| repos.put_setting(MINIMUM_CONFIRMATIONS_SETTING, &count.to_string()))?;
        let balances = session.store.read(account_balances)?;
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
            let minimum = minimum_confirmations(repos)?;
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
    /// from genesis completed or while a restore scan waits, so it never scans the whole chain.
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
                    let ready = crate::scan::has_scanned(repos)?
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

/// The wallet's minimum confirmations; an absent or unreadable setting reads as the default.
pub(crate) fn minimum_confirmations(repos: &dyn Repositories) -> Result<u64, StoreError> {
    Ok(repos
        .setting(MINIMUM_CONFIRMATIONS_SETTING)?
        .and_then(|text| text.parse().ok())
        .filter(|count| MINIMUM_CONFIRMATIONS_RANGE.contains(count))
        .unwrap_or(DEFAULT_MINIMUM_CONFIRMATIONS))
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
        .filter(|count| MINIMUM_CONFIRMATIONS_RANGE.contains(count));
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
fn record_confirmed(
    repos: &mut dyn Repositories,
    tip: Height,
    now: Timestamp,
) -> Result<(), StoreError> {
    let stored = last_confirmed(repos)?;
    if let Some(height) = chain::observe_tip(repos, stored, tip, now)?
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
    /// and those a recent refresh took for another wallet's spend.
    tracked: Vec<(Commitment, OutputStatus)>,
}

fn known_state(repos: &dyn Repositories, tip: Height) -> Result<KnownState, RefreshError> {
    let recently_spent = other_wallet::recently_spent(repos, tip)?;
    let mut tracked = Vec::new();
    for account in repos.accounts()? {
        tracked.extend(
            repos
                .outputs(account.index, None)?
                .into_iter()
                .filter(|output| {
                    output.status != OutputStatus::Spent
                        || recently_spent.contains(&output.id.commitment)
                })
                .map(|output| (output.id.commitment, output.status)),
        );
    }
    Ok(KnownState {
        last_confirmed: last_confirmed(repos)?,
        position: chain::position(repos)?,
        tracked,
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
    seen: ChainSeen,
    now: Timestamp,
) -> Result<StepOutcome, RefreshError> {
    let mut outcome = StepOutcome::default();
    let mut elsewhere = Vec::new();
    for commitment in tracked {
        // A concurrent cancel may have deleted it since it was read.
        let Some(stored) = repos.output(commitment.as_bytes())? else {
            continue;
        };
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
            Some(location) => on_chain(repos, stored.clone(), location, now, &mut outcome)?,
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
    Ok(outcome)
}

fn on_chain(
    repos: &mut dyn Repositories,
    mut output: OutputRecord,
    location: &OutputLocation,
    now: Timestamp,
    outcome: &mut StepOutcome,
) -> Result<OutputRecord, RefreshError> {
    if output.status == OutputStatus::Unconfirmed {
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
fn confirm(
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

/// The height a release check counts at, the highest confirmed tip but not above `tip`, and
/// the sends due for a check there. A tip held as pending does not count, so one implausible
/// answer cannot make a send releasable.
fn releases_due(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<(Height, Vec<(TxId, ReleaseCheck)>), RefreshError> {
    let height = balance_height(repos)?.min(tip);
    let mut due = Vec::new();
    for stored in open_transactions(repos)? {
        if let Ok(check) = release_check(repos, codecs, &stored)?
            && check.due_at(height)
        {
            due.push((stored.id, check));
        }
    }
    Ok((height, due))
}

/// Open transactions with no change output, which no output of this wallet can confirm, and
/// whose final kernel is known from the final slate stored with them. Upstream skips exactly
/// the entries that both credit and debit.
fn kernel_lookups(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<Vec<KernelLookup>, RefreshError> {
    let mut lookups = Vec::new();
    for stored in open_transactions(repos)? {
        let entry = &stored.entry;
        if entry.amount_credited != Amount::ZERO && entry.amount_debited != Amount::ZERO {
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

/// The kernel excess of the final slate stored for a transaction, and the height the slate was
/// created at, below which the kernel cannot be. An invoice payer never receives the I3, so its
/// excess is computed from the stored I2, which already holds every input, output and the final
/// offset, as `epic-wallet` does when it locks the payer's outputs.
pub(crate) fn final_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    slate_id: Uuid,
) -> Result<Option<(Commitment, Height)>, StoreError> {
    let final_slate = [SlateStage::Standard3, SlateStage::Invoice3]
        .into_iter()
        .find_map(|stage| stored_slate(repos, codecs, tx_id, slate_id, stage).transpose())
        .transpose()?;
    if let Some(slate) = final_slate {
        return Ok(slate.kernel().map(|kernel| (kernel.excess, slate.height())));
    }
    let payment = stored_slate(repos, codecs, tx_id, slate_id, SlateStage::Invoice2)?;
    Ok(payment.and_then(|slate| {
        kernel_excess(&slate)
            .ok()
            .map(|excess| (excess, slate.height()))
    }))
}

/// The kernel of a transaction the peer may still complete without this wallet, and the height
/// below which it cannot be: one finalized here, an invoice payment once its I2 exists, and a
/// received payment once its S2 exists. The S2 holds every input, output and the final offset,
/// so the excess the sender finalizes to is computed from it, as for the I2.
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
                kernel_excess(&slate)
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
/// looked up before it ends. An invoice this wallet issued and finalized is the exception: it
/// ends once its cutoff passes, the earlier of its I3's and the one it was issued with, from
/// which [`Wallet::post`] no longer posts it; its kernel stays watched like any other.
fn expiring(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<Vec<(StoredTransaction, Option<KernelAt>)>, RefreshError> {
    let mut expiring = Vec::new();
    for stored in open_transactions(repos)? {
        if let Some((cutoff, kernel)) = issued_post_cutoff(repos, codecs, &stored)? {
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
    let mut posts = Vec::new();
    for stored in open_transactions(repos)? {
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
/// transaction this wallet answered with an S2. The window counts from the first refresh that
/// saw it, not from the slate's height, which the sender chose.
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
    let entry = &stored.entry;
    let Some(slate_id) = entry
        .slate_id
        .filter(|_| entry.direction == TxDirection::Incoming && entry.state == TxState::Received)
    else {
        return Ok(false);
    };
    Ok(repos.slate(slate_id, SlateStage::Standard2)?.is_some()
        && ttl_cutoff(repos, codecs, stored.id, slate_id)?.is_none())
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

/// Records `tip` as the height a refresh first saw each received payment with no TTL that
/// waits for its sender.
fn record_receives_seen(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<(), RefreshError> {
    for stored in open_transactions(repos)? {
        if awaits_finalization(repos, codecs, &stored)? {
            let mut marks = repos.tx_marks(stored.id)?;
            if marks.receive_seen_at.is_none() {
                marks.receive_seen_at = Some(tip);
                repos.put_tx_marks(stored.id, &marks)?;
            }
        }
    }
    Ok(())
}

/// Expires every transaction [`expiring`] lists that is in `cleared`, the ones whose kernel
/// the node's pool and chain were found not to hold, as upstream cancels it. One whose kernel
/// is known stays watched, so it is confirmed if the peer still completes it.
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
        if let Some((excess, min_height)) = kernel {
            let floor = chain::kernel_floor(min_height, tip);
            record_watch(repos, stored.id, excess, floor, tip)?;
        }
        changes.extend(expire(repos, &stored, now)?);
    }
    Ok(changes)
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

fn open_transactions(repos: &dyn Repositories) -> Result<Vec<StoredTransaction>, RefreshError> {
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

/// Errors nested deeper than this are cut from a log line.
const MAX_ERROR_SOURCES: usize = 16;

/// Displays an error followed by its sources, separated by `": "`, for the `error` log field.
struct ErrorChain<'a>(&'a (dyn StdError + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let sources = std::iter::successors(self.0.source(), |&error| error.source());
        for source in sources.take(MAX_ERROR_SOURCES) {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

/// The codecs stored slates are written in, in the detection order `receive` uses.
pub(crate) fn legacy_codecs(base_fee: Fee) -> CodecRegistry {
    crate::codecs::legacy(base_fee)
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
fn balances(repos: &dyn Repositories) -> Result<Vec<Balance>, RefreshError> {
    Ok(account_balances(repos)?)
}

fn account_balances(repos: &dyn Repositories) -> Result<Vec<Balance>, WalletError> {
    let height = balance_height(repos)?;
    let minimum = minimum_confirmations(repos)?;
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
        *slot = slot.checked_add(output.amount)?;
        if category != BalanceCategory::AwaitingFinalization {
            balance.total = balance.total.checked_add(output.amount)?;
        }
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
}

fn counted_apart(
    repos: &dyn Repositories,
    outputs: &[OutputRecord],
) -> Result<CountedApart, WalletError> {
    Ok(CountedApart {
        unpaid_invoices: unpaid_invoices(repos, outputs)?,
        posted_self_sends: posted_self_sends(repos, outputs)?,
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
/// inputs it spends count nowhere, as once it is mined.
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
    match output.status {
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
