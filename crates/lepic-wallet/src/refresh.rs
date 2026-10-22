//! Refresh: bring stored outputs and transactions in line with the node's UTXO set and kernels,
//! as `epic-wallet`'s `update_wallet_state` does before its scan. The algorithm is in
//! `docs/compat/node-api.md` (refresh), the state mapping in `docs/compat/states.md`.
//!
//! A refresh runs in steps, each stored in its own store transaction: outputs, then kernel
//! confirmations, then TTL expiry, then the kernel checks that make a send releasable
//! ([`crate::release`]). Every step re-reads what it changes inside its transaction,
//! so dropping the future between steps, or a send running at the same time, leaves a
//! consistent store that the next refresh completes.
//!
//! Upstream's update also rescans the last blocks for outputs it does not know; in LEPIC that is
//! a separate [`Wallet::scan`] with [`crate::scan::ScanOptions::update`], run after a refresh.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::{NodeApi, NodeError, OutputLocation};
use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
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

use crate::cancel::{drop_holdings, pool_kernels};
use crate::chain::{self, ChainPosition, ImplausibleNodeData};
use crate::epicbox_invoice::epicbox_invoice_payment;
use crate::error::WalletError;
use crate::event::{Balance, Event};
use crate::finalize::kernel_excess;
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::release::{
    RELEASED_WATCH_BLOCKS, ReleaseCheck, record_kernel_absent, record_watch, release_check,
};
use crate::state::{StateChange, apply_transition, is_final};
use crate::wallet::Wallet;

/// Confirmations an unspent output needs to count as spendable in the balance events and in
/// `summary()`: 3, as the Epic GUI wallet counts (decision D1). `epic-wallet info` counts 10 by
/// default; the app reads this value from the summary, so balance and sends agree.
pub const BALANCE_MINIMUM_CONFIRMATIONS: u64 = 3;

/// Blocks after a refresh first saw a received payment with no TTL that its sender has not
/// finalized, after which a refresh ends it: a week of blocks, as long as a released send is
/// watched.
pub const UNFINALIZED_RECEIVE_BLOCKS: u64 = RELEASED_WATCH_BLOCKS;

pub(crate) const LAST_CONFIRMED_SETTING: &str = "refresh.last_confirmed_height";

const RECEIVE_SEEN_PREFIX: &str = "refresh.receive_seen.";

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

/// The tip a refresh counts at, and what [`Wallet::cover`] needs to read it once more.
#[derive(Debug, Clone, Copy)]
struct RefreshTip {
    height: Height,
    position: ChainPosition,
    now: Timestamp,
    read_again: bool,
}

/// A kernel excess and the height below which the kernel cannot be on chain.
type KernelAt = (Commitment, Height);

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
    /// their TTL cutoff, releasing their inputs. A posted or finalized transaction is never
    /// expired, since it may still be mined. Last, it looks up the kernel of each finalized or
    /// posted send [`crate::release::RELEASE_AFTER_BLOCKS`] or more after it was finalized,
    /// counted at the highest confirmed tip: a kernel found confirms the send, a missing one
    /// makes it releasable (`Wallet::release`). Then it looks up the kernel of each send
    /// released at most [`crate::release::RELEASED_WATCH_BLOCKS`] before that tip: a kernel
    /// found moves the send from `cancelled` to `confirmed` and stores its change as unspent.
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
            self.blocking(move |_, _| Ok(session.store.read(known_state)))
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
        let mut summary = RefreshSummary::default();

        let outcome = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .write(|repos| apply_outputs(repos, &commitments, &found, now)))
            })
            .await??
        };
        summary.confirmed_outputs = outcome.confirmed_outputs;
        summary.spent_outputs = outcome.spent_outputs;
        self.record_changes(&mut summary, outcome.changes);

        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let lookups = {
            let session = Arc::clone(&session);
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
                    self.cover(&mut tip, kernel.height).await?;
                    chain::check_kernel_height(kernel.height, floor, tip.height)?;
                    kernel_confirmed.push((lookup.tx_id, kernel.height));
                }
                None => {
                    kernel_missing.insert(lookup.tx_id);
                }
            }
        }
        if !kernel_confirmed.is_empty() {
            let session = Arc::clone(&session);
            let changes = self
                .blocking(move |_, _| {
                    Ok(session
                        .store
                        .write(|repos| confirm_all(repos, &kernel_confirmed, now)))
                })
                .await??;
            self.record_changes(&mut summary, changes);
        }

        summary.height = tip.height;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let candidates = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    Ok::<_, RefreshError>(
                        expiring(repos, &codecs, tip.height)?
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
        let cleared = self.not_held(&candidates, &mut tip).await?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let changes = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    // Only a tip that was confirmed by a second one expires anything.
                    let changes = if due {
                        expire_all(repos, &codecs, tip.height, &cleared, now)?
                    } else {
                        Vec::new()
                    };
                    record_receives_seen(repos, &codecs, tip.height)?;
                    // A tip that expired transactions is not trusted as a reference until a
                    // later refresh sees the chain there without expiring anything.
                    if changes.is_empty() {
                        record_confirmed(repos, tip.height, now)?;
                    }
                    Ok::<_, RefreshError>(changes)
                }))
            })
            .await??
        };
        self.record_changes(&mut summary, changes);
        self.check_releases(&session, tip.height, &kernel_missing, now, &mut summary)
            .await?;
        let changes = self.watch_released(&session, tip.height, now).await?;
        self.record_changes(&mut summary, changes);

        let balances = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| Ok(session.store.read(balances)))
                .await??
        };
        for balance in balances {
            self.emit(Event::Balance(balance));
        }
        info!(height = %tip.height, "refresh completed");
        Ok(RefreshOutcome::Refreshed(summary))
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
            balance(
                account,
                &repos.outputs(account, None)?,
                balance_height(repos)?,
            )
            .map_err(WalletError::Balance)
        })
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
                // A refresh moves transactions only to these two states.
                _ => {}
            }
            self.emit(change.into());
        }
    }
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
    /// Every output the node is asked about, all those not stored as spent, in every account.
    tracked: Vec<(Commitment, OutputStatus)>,
}

fn known_state(repos: &dyn Repositories) -> Result<KnownState, RefreshError> {
    let mut tracked = Vec::new();
    for account in repos.accounts()? {
        tracked.extend(
            repos
                .outputs(account.index, None)?
                .into_iter()
                .filter(|output| output.status != OutputStatus::Spent)
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
/// transaction, what it does not hold is spent unless it was never confirmed.
fn apply_outputs(
    repos: &mut dyn Repositories,
    tracked: &[Commitment],
    found: &BTreeMap<Commitment, OutputLocation>,
    now: Timestamp,
) -> Result<StepOutcome, RefreshError> {
    let mut outcome = StepOutcome::default();
    for commitment in tracked {
        // A concurrent cancel may have deleted it since it was read.
        let Some(stored) = repos.output(commitment.as_bytes())? else {
            continue;
        };
        let updated = match found.get(commitment) {
            Some(location) => on_chain(repos, stored.clone(), location, now, &mut outcome)?,
            None => missing(stored.clone(), &mut outcome),
        };
        if updated != stored {
            repos.put_output(&updated)?;
        }
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

/// Open transactions that end at `tip`: those at or past their TTL cutoff, and a received
/// payment with no TTL, answered with an S2, once [`UNFINALIZED_RECEIVE_BLOCKS`] have passed
/// since a refresh first saw it. A finalized or posted transaction is left out, as upstream
/// leaves out what it has finalized: its kernel may reach the chain whatever the TTL says. So
/// is the payment of an invoice over Epicbox, which the issuer may have posted:
/// [`Wallet::sweep_invoices`] offers it to the user to cancel instead. Each comes with the
/// kernel the peer may still complete it with, which is looked up before it ends.
fn expiring(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<Vec<(StoredTransaction, Option<KernelAt>)>, RefreshError> {
    let mut expiring = Vec::new();
    for stored in open_transactions(repos)? {
        if matches!(stored.entry.state, TxState::Posted | TxState::Finalized)
            || epicbox_invoice_payment(repos, &stored)?.is_some()
        {
            continue;
        }
        let Some(slate_id) = stored.entry.slate_id else {
            continue;
        };
        let cutoff = match ttl_cutoff(repos, codecs, stored.id, slate_id)? {
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
    Ok(match repos.setting(&receive_seen_key(tx_id))? {
        Some(text) => {
            let height = text.parse().ok().map(Height::new);
            if height.is_none() {
                warn!(tx_id = %tx_id, "receive height unreadable");
            }
            height
        }
        None => None,
    })
}

/// Forgets when a refresh first saw a received payment. Run it when the payment ends.
pub(crate) fn forget_receive_seen(
    repos: &mut dyn Repositories,
    tx_id: TxId,
) -> Result<(), StoreError> {
    repos.delete_setting(&receive_seen_key(tx_id))
}

fn receive_seen_key(tx_id: TxId) -> String {
    format!("{RECEIVE_SEEN_PREFIX}{tx_id}")
}

/// Records `tip` as the height a refresh first saw each received payment with no TTL that
/// waits for its sender.
fn record_receives_seen(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<(), RefreshError> {
    for stored in open_transactions(repos)? {
        if awaits_finalization(repos, codecs, &stored)?
            && repos.setting(&receive_seen_key(stored.id))?.is_none()
        {
            repos.put_setting(&receive_seen_key(stored.id), &tip.value().to_string())?;
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
fn decode_stored(codecs: &CodecRegistry, tx_id: TxId, bytes: &[u8]) -> Option<Slate> {
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
    let mut codecs = CodecRegistry::new();
    // Registration fails only for a duplicate id, and these ids differ.
    let _ = codecs.register(Box::new(V3JsonCodec::new(base_fee)));
    let _ = codecs.register(Box::new(V2JsonCodec::new(base_fee)));
    codecs
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
    let height = balance_height(repos)?;
    let mut balances = Vec::new();
    for account in repos.accounts()? {
        balances.push(balance(
            account.index,
            &repos.outputs(account.index, None)?,
            height,
        )?);
    }
    Ok(balances)
}

fn balance(
    account: AccountIndex,
    outputs: &[OutputRecord],
    height: Height,
) -> Result<Balance, ArithmeticError> {
    let mut balance = Balance {
        account,
        height,
        total: Amount::ZERO,
        spendable: Amount::ZERO,
        awaiting_confirmation: Amount::ZERO,
        awaiting_finalization: Amount::ZERO,
        immature: Amount::ZERO,
        locked: Amount::ZERO,
    };
    for output in outputs {
        let coinbase = output.id.features.is_coinbase();
        match output.status {
            OutputStatus::Unspent if coinbase && output.lock_height > height => {
                balance.immature = balance.immature.checked_add(output.amount)?;
                balance.total = balance.total.checked_add(output.amount)?;
            }
            OutputStatus::Unspent
                if confirmations(output, height) < BALANCE_MINIMUM_CONFIRMATIONS =>
            {
                balance.awaiting_confirmation =
                    balance.awaiting_confirmation.checked_add(output.amount)?;
                balance.total = balance.total.checked_add(output.amount)?;
            }
            OutputStatus::Unspent => {
                balance.spendable = balance.spendable.checked_add(output.amount)?;
                balance.total = balance.total.checked_add(output.amount)?;
            }
            // Upstream ignores unconfirmed coinbase outputs, which a wallet that does not mine
            // never has.
            OutputStatus::Unconfirmed if !coinbase => {
                balance.awaiting_finalization =
                    balance.awaiting_finalization.checked_add(output.amount)?;
            }
            OutputStatus::Locked => {
                balance.locked = balance.locked.checked_add(output.amount)?;
                balance.total = balance.total.checked_add(output.amount)?;
            }
            OutputStatus::Unconfirmed | OutputStatus::Spent => {}
        }
    }
    Ok(balance)
}

/// An output at height `n` has one confirmation at height `n`, none above the tip.
fn confirmations(output: &OutputRecord, height: Height) -> u64 {
    height
        .value()
        .checked_sub(output.height.value())
        .map_or(0, |blocks| blocks.saturating_add(1))
}
