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
    AccountIndex, OutboxStatus, OutputRecord, OutputStatus, ParticipantId, Repositories,
    SlateStage, StoreError, StoredTransaction, TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::chain::{self, ChainPosition, ImplausibleNodeData};
use crate::error::WalletError;
use crate::event::{Balance, Event};
use crate::finalize::kernel_excess;
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::release::{ReleaseCheck, record_kernel_absent, release_check};
use crate::send::SENDER_CONTEXT;
use crate::state::{StateChange, apply_transition, is_final};
use crate::wallet::Wallet;

/// Confirmations an unspent output needs to count as spendable in the balance events, as
/// `epic-wallet info` counts by default.
pub const BALANCE_MINIMUM_CONFIRMATIONS: u64 = 10;

pub(crate) const LAST_CONFIRMED_SETTING: &str = "refresh.last_confirmed_height";

/// The private context of the party that adds only an output, under the participant id
/// `epic-wallet` gives the receiver.
const RECEIVER_CONTEXT: ParticipantId = ParticipantId(1);

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
    /// makes it releasable (`Wallet::release`).
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
            let kernel = node
                .get_kernel(&lookup.excess, Some(lookup.min_height), Some(tip.height))
                .await?;
            match kernel {
                Some(kernel) => {
                    self.cover(&mut tip, kernel.height).await?;
                    chain::check_kernel_height(kernel.height, lookup.min_height, tip.height)?;
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
        let due = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| expiry_due(repos, &codecs, tip.height)))
            })
            .await??
        };
        // A tip read again already agreed with the first.
        if due && !tip.read_again {
            let second = node.get_tip().await?;
            chain::check_agreement(tip.height, second.height)?;
        }
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let changes = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    // Only a tip that was confirmed by a second one expires anything.
                    let changes = if due {
                        expire_all(repos, &codecs, tip.height, now)?
                    } else {
                        Vec::new()
                    };
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
            let kernel = self
                .ports()
                .node
                .get_kernel(&check.excess, Some(check.min_height), Some(tip))
                .await?;
            match kernel {
                Some(kernel) => {
                    chain::check_kernel_height(kernel.height, check.min_height, tip)?;
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

/// Open transactions at or past their TTL cutoff at `tip`. A finalized or posted transaction
/// is left out, as upstream leaves out what it has finalized: its kernel may reach the chain
/// whatever the TTL says.
fn expiring(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<Vec<StoredTransaction>, RefreshError> {
    let mut expiring = Vec::new();
    for stored in open_transactions(repos)? {
        if matches!(stored.entry.state, TxState::Posted | TxState::Finalized) {
            continue;
        }
        let Some(slate_id) = stored.entry.slate_id else {
            continue;
        };
        let Some(cutoff) = ttl_cutoff(repos, codecs, stored.id, slate_id)? else {
            continue;
        };
        if tip >= cutoff {
            expiring.push(stored);
        }
    }
    Ok(expiring)
}

fn expiry_due(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
) -> Result<bool, RefreshError> {
    Ok(!expiring(repos, codecs, tip)?.is_empty())
}

/// Expires every transaction [`expiring`] lists, as upstream cancels it.
fn expire_all(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tip: Height,
    now: Timestamp,
) -> Result<Vec<StateChange>, RefreshError> {
    let mut changes = Vec::new();
    for stored in expiring(repos, codecs, tip)? {
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
    for output in repos.outputs_of_transaction(stored.id)? {
        match output.status {
            OutputStatus::Unconfirmed => repos.delete_output(output.commitment())?,
            OutputStatus::Locked => repos.put_output(&OutputRecord {
                status: OutputStatus::Unspent,
                ..output
            })?,
            OutputStatus::Unspent | OutputStatus::Spent => {}
        }
    }
    if let Some(slate_id) = stored.entry.slate_id {
        let participant = match stored.entry.direction {
            TxDirection::Outgoing => SENDER_CONTEXT,
            TxDirection::Incoming => RECEIVER_CONTEXT,
        };
        repos.delete_context(slate_id, participant)?;
        for pending in repos.outbox(OutboxStatus::Pending)? {
            if pending.entry.slate_id == slate_id {
                repos.delete_outbox(pending.id)?;
            }
        }
    }
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

fn stored_slate(
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
fn balance_height(repos: &dyn Repositories) -> Result<Height, StoreError> {
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
