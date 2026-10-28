// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/internal/scan.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Scan and restore: find the wallet's outputs in the node's UTXO set by rewinding their range
//! proofs, and reconcile what is found with the store, as `epic-wallet` does. The algorithm is in
//! `docs/compat/node-api.md` (restore and scan), the output transitions in
//! `docs/compat/states.md`.
//!
//! A scan pages through the output MMR index range of a height range. Each page is identified
//! and stored in its own store transaction together with a checkpoint, so a large restore never
//! holds one huge transaction, and a scan that was cancelled, failed or was killed resumes after
//! the last stored page.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_keychain::{Identifier, OutputRewinder, ProofError, SwitchCommitment};
use lepic_node::{NodeApi, NodeError, UnspentOutput, UnspentOutputs};
use lepic_primitives::amount::{Amount, ArithmeticError, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::output::OutputIdentifier;
use lepic_primitives::params::Network;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, AccountRecord, CommitmentBytes, KeyId, OutputRecord, OutputStatus, Repositories,
    ScanFoundRecord, StoreError, StoredTransaction, TransactionEntry, TxDirection, TxId, TxState,
    WalletStore,
};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, instrument, warn};

use crate::account::{FIRST_HARDENED, OWN_KEY_WINDOW, key_counter_start};
use crate::cancel::{drop_holdings, self_send_partner};
use crate::chain::{self, ChainPosition, ImplausibleNodeData};
use crate::error::WalletError;
use crate::event::{Event, SyncProgress};
use crate::legacy_history::{self, block_times};
use crate::lifecycle::{self, Session};
use crate::other_wallet;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{KernelAt, final_kernel, legacy_codecs, pending_kernel};
use crate::release::record_watch;
use crate::state::{StateChange, apply_transition, is_final};
use crate::wallet::Wallet;

/// Outputs asked for per `get_unspent_outputs` request, as `epic-wallet` asks.
pub const DEFAULT_PAGE_SIZE: NonZeroU64 = match NonZeroU64::new(1_000) {
    Some(size) => size,
    None => NonZeroU64::MIN,
};

/// Blocks an update scan reaches back behind the last scanned height, as `epic-wallet` does, so
/// outputs of a short reorganisation are found again.
pub const UPDATE_RESCAN_BLOCKS: u64 = 100;

const LAST_SCANNED_SETTING: &str = "scan.last_scanned";
const CHECKPOINT_SETTING: &str = "scan.checkpoint";
/// Set once a scan from genesis completed: from then on an output no scan found is not on
/// chain.
const GENESIS_SCANNED_SETTING: &str = "scan.genesis_completed";

/// Label prefix `epic-wallet` gives an account that a restore finds outputs of.
const RESTORED_ACCOUNT_LABEL: &str = "account";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The wallet is locked, or the database failed.
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    /// The node could not be reached or gave an answer that failed validation.
    #[error("node request failed")]
    Node(#[from] NodeError),
    #[error("range proof rewind failed")]
    Proof(#[from] ProofError),
    /// A height from the node is too large to add the coinbase maturity to.
    #[error("block height out of range")]
    Height(#[from] ArithmeticError),
    /// The node's paging did not move past the last page.
    #[error("node paged its unspent outputs backwards")]
    Paging,
    /// The node's answer cannot be true. Pages already stored are kept.
    #[error("node data rejected")]
    Implausible(#[from] ImplausibleNodeData),
    /// What earlier pages stored is kept; the next scan resumes after it.
    #[error("scan was cancelled")]
    Cancelled,
}

impl From<StoreError> for ScanError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// Where a scan starts. It always ends at the node's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStart {
    /// The whole chain: what a wallet restored from its recovery phrase needs.
    Genesis,
    Height(Height),
    /// [`UPDATE_RESCAN_BLOCKS`] behind the last completed scan, or behind the node's tip when
    /// that is lower, or the whole chain when no scan has completed.
    LastScanned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    pub start: ScanStart,
    /// Also unlock locked outputs found on chain and delete unconfirmed outputs not found,
    /// cancelling their transactions: the repair `epic-wallet scan --delete_unconfirmed` runs.
    /// It applies to the outputs that were locked or unconfirmed when the scan started, and
    /// such a scan always starts from genesis, whatever `start` says, since an output mined
    /// below the start would not be found. A scan resumes an interrupted one only when this
    /// setting matches, so a repair is never skipped for pages an earlier plain scan stored.
    pub delete_unconfirmed: bool,
    /// Blocks a restored coinbase output stays locked after the block that mined it.
    pub coinbase_maturity: u64,
    /// Outputs asked for per node request; each page is stored in its own transaction.
    pub page_size: NonZeroU64,
}

impl ScanOptions {
    /// A full scan of the chain, with the network's coinbase maturity.
    pub const fn restore(network: Network) -> Self {
        Self {
            start: ScanStart::Genesis,
            delete_unconfirmed: false,
            coinbase_maturity: network.params().coinbase_maturity(),
            page_size: DEFAULT_PAGE_SIZE,
        }
    }

    /// The scan of a regular update, from shortly before the last scanned height.
    pub const fn update(network: Network) -> Self {
        Self {
            start: ScanStart::LastScanned,
            ..Self::restore(network)
        }
    }
}

/// Stops a running scan at its next node request or page boundary. Clones share the signal.
#[derive(Debug, Clone)]
pub struct ScanCancel(Arc<watch::Sender<bool>>);

impl ScanCancel {
    /// A signal that is not cancelled.
    pub fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    /// Ends the scan with [`ScanError::Cancelled`]. A node request in flight is abandoned, a
    /// page being stored is kept, and the next scan with the same options resumes after the
    /// last stored page. The signal stays set; use a new one for the next scan.
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    /// Whether `other` is this signal or a clone of it.
    pub fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Whether [`ScanCancel::cancel`] was called on this signal or a clone.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    async fn cancelled(&self) {
        let mut signal = self.0.subscribe();
        // The sender lives in `self`, so waiting ends only when the scan is cancelled.
        let _ = signal.wait_for(|cancelled| *cancelled).await;
    }
}

impl Default for ScanCancel {
    fn default() -> Self {
        Self::new()
    }
}

/// The chain position a completed scan reached, as `epic-wallet` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannedBlock {
    pub height: Height,
    pub hash: Hash,
    pub start_pmmr_index: u64,
    pub last_pmmr_index: u64,
}

impl ScannedBlock {
    fn encode(&self) -> String {
        format!(
            "{} {} {} {}",
            self.height,
            self.hash.to_hex(),
            self.start_pmmr_index,
            self.last_pmmr_index
        )
    }

    fn decode(text: &str) -> Option<Self> {
        let mut fields = text.split(' ');
        let block = Self {
            height: Height::new(fields.next()?.parse().ok()?),
            hash: Hash::from_hex(fields.next()?).ok()?,
            start_pmmr_index: fields.next()?.parse().ok()?,
            last_pmmr_index: fields.next()?.parse().ok()?,
        };
        fields.next().is_none().then_some(block)
    }
}

/// What a scan starts from.
struct ScanPlan {
    /// Where an interrupted scan stopped, if one did.
    checkpoint: Option<Checkpoint>,
    /// An update scan of recent blocks on a wallet whose scan from genesis completed.
    update: bool,
    /// What a repairing scan compares the chain against.
    repair: Option<Arc<Repair>>,
    start_height: Height,
}

/// How far an unfinished scan got: every output below `next_index` is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checkpoint {
    start_height: Height,
    first_index: u64,
    next_index: u64,
    delete_unconfirmed: bool,
}

const DELETE_UNCONFIRMED: &str = "delete_unconfirmed";
const KEEP_UNCONFIRMED: &str = "keep_unconfirmed";

impl Checkpoint {
    fn encode(&self) -> String {
        let mode = if self.delete_unconfirmed {
            DELETE_UNCONFIRMED
        } else {
            KEEP_UNCONFIRMED
        };
        format!(
            "{} {} {} {mode}",
            self.start_height, self.first_index, self.next_index
        )
    }

    fn decode(text: &str) -> Option<Self> {
        let mut fields = text.split(' ');
        let checkpoint = Self {
            start_height: Height::new(fields.next()?.parse().ok()?),
            first_index: fields.next()?.parse().ok()?,
            next_index: fields.next()?.parse().ok()?,
            delete_unconfirmed: match fields.next()? {
                DELETE_UNCONFIRMED => true,
                KEEP_UNCONFIRMED => false,
                _ => return None,
            },
        };
        fields.next().is_none().then_some(checkpoint)
    }
}

/// What a scan did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanSummary {
    pub start_height: Height,
    pub end_height: Height,
    /// Whether the scan continued an interrupted one instead of starting over.
    pub resumed: bool,
    /// Outputs of this wallet found on chain, stored before or not.
    pub found: u64,
    /// Outputs found that were not stored, now stored with a transaction each.
    pub restored: u64,
    /// Outputs stored as spent that were found unspent.
    pub revived: u64,
    /// Locked outputs made spendable again: found on chain by a scan with
    /// `delete_unconfirmed`, or inputs of a transaction the scan cancelled.
    pub unlocked: u64,
    /// Unconfirmed outputs deleted: not found by a scan with `delete_unconfirmed`, or the
    /// change of a transaction the scan cancelled.
    pub deleted: u64,
}

pub use lepic_store::FoundDuring;

/// How a scan stored an entry for an output it found with no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanFound {
    pub during: FoundDuring,
    /// The entry is dated by the output's block; false when the block's header could not be
    /// fetched and the time of the scan was used instead.
    pub dated_by_block: bool,
}

/// How a scan stored the entry `tx_id`. `None` for an entry no scan stored, and for one stored
/// before this was recorded.
pub(crate) fn scan_found(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<ScanFound>, StoreError> {
    Ok(repos.scan_found(tx_id)?.and_then(|record| {
        record.during.map(|during| ScanFound {
            during,
            dated_by_block: record.dated_by_block,
        })
    }))
}

/// The commitment of the output the scan stored the entry `tx_id` for. `None` for an entry no
/// scan stored, and for one stored before this was recorded.
pub(crate) fn found_output(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<Commitment>, StoreError> {
    Ok(repos
        .scan_found(tx_id)?
        .and_then(|record| record.output)
        .and_then(|bytes| Commitment::from_bytes(&bytes).ok()))
}

/// Records that the entry `tx_id` a scan stored is now dated by its output's block.
pub(crate) fn record_dated_by_block(
    repos: &mut dyn Repositories,
    tx_id: TxId,
) -> Result<(), StoreError> {
    if let Some(mut record) = repos.scan_found(tx_id)?
        && record.during.is_some()
        && !record.dated_by_block
    {
        record.dated_by_block = true;
        repos.put_scan_found(tx_id, &record)?;
    }
    Ok(())
}

/// Removes the entry `tx_id` and, with it, what a scan recorded about it. Fails as
/// [`lepic_store::TransactionRepository::delete_transaction`] does.
pub(crate) fn delete_found_entry(
    repos: &mut dyn Repositories,
    tx_id: TxId,
) -> Result<(), StoreError> {
    repos.delete_transaction(tx_id)
}

/// A page of the node's unspent outputs, with the checkpoint stored with it and the tip the
/// scan runs to.
struct Page {
    outputs: Vec<UnspentOutput>,
    checkpoint: Checkpoint,
    tip: Height,
    /// An update scan of recent blocks on a wallet whose scan from genesis completed: an output
    /// it finds with no record here was received by another wallet on the phrase.
    update: bool,
}

/// When a scan ends the open transactions whose inputs the chain holds unspent again.
struct Ending<'a> {
    now: Timestamp,
    /// The tip the scan runs to, from which the kernel of an ended transaction stays watched.
    tip: Height,
    codecs: &'a CodecRegistry,
}

/// An output of this wallet found on chain.
#[derive(Debug, Clone, Copy)]
struct FoundOutput {
    id: OutputIdentifier,
    key_id: Identifier,
    account: AccountIndex,
    /// The key's child number when it advances the account's key counter.
    child: Option<u32>,
    amount: Amount,
    height: Height,
    lock_height: Height,
    mmr_index: u64,
}

#[derive(Debug, Default)]
struct PageOutcome {
    found: u64,
    restored: u64,
    revived: u64,
    unlocked: u64,
    deleted: u64,
    changes: Vec<StateChange>,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Scans the chain from `options.start` to the node's tip for this wallet's outputs and
    /// reconciles the store with what it finds: missing outputs are restored with a confirmed
    /// incoming transaction each, outputs stored as spent but still unspent are revived and their
    /// transactions cancelled. Emits [`Event::Sync`] after each page and
    /// [`Event::Transaction`] for every cancelled transaction.
    ///
    /// An output stored as spent is revived only when the node, asked for it again, still holds
    /// it. The tip must be plausible as [`Wallet::refresh`] checks it, no output may be above
    /// it, and the output index range may not be larger than the blocks up to it can hold.
    ///
    /// Every page is stored as it is scanned. When the scan fails or is cancelled, the next scan
    /// from the same start resumes after the last stored page. Fails with
    /// [`ScanError::Cancelled`], [`ScanError::Node`], [`ScanError::Implausible`], or
    /// [`WalletError::Locked`] inside [`ScanError::Wallet`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn scan(
        &self,
        options: ScanOptions,
        cancel: &ScanCancel,
    ) -> Result<ScanSummary, ScanError> {
        let session = self.session()?;
        let node = &self.ports().node;
        let tip = until_cancelled(cancel, node.get_tip()).await?;
        let ScanPlan {
            checkpoint,
            update,
            repair,
            start_height,
        } = self.plan_scan(&session, options, tip.height).await?;
        let mut summary = ScanSummary {
            start_height,
            end_height: tip.height,
            ..ScanSummary::default()
        };
        if start_height > tip.height {
            debug!(height = %tip.height, "scan skipped");
            return Ok(summary);
        }
        let indices = until_cancelled(
            cancel,
            node.get_pmmr_indices(start_height, Some(tip.height)),
        )
        .await?;
        chain::check_output_index(indices.last_index, tip.height)?;
        let mut next_index = indices.first_index;
        if let Some(resumed) = resume_index(checkpoint, start_height, indices.first_index, options)
        {
            next_index = resumed;
            summary.resumed = true;
        }
        info!(height = %start_height, "scan started");
        self.emit(Event::Sync(SyncProgress {
            height: start_height,
            target: tip.height,
        }));
        let mut progress = start_height;
        while next_index <= indices.last_index {
            if cancel.is_cancelled() {
                return Err(ScanError::Cancelled);
            }
            let (page, after, finished) = self
                .fetch_page(next_index, indices.last_index, tip.height, options, cancel)
                .await?;
            if let Some(highest) = page.outputs.iter().map(|output| output.height).max() {
                progress = progress.max(highest.min(tip.height));
            }
            let checkpoint = Checkpoint {
                start_height,
                first_index: indices.first_index,
                next_index: after,
                delete_unconfirmed: options.delete_unconfirmed,
            };
            let outcome = self
                .store_page(
                    Arc::clone(&session),
                    Page {
                        outputs: page.outputs,
                        checkpoint,
                        tip: tip.height,
                        update,
                    },
                    repair.clone(),
                    options,
                    cancel,
                )
                .await?;
            summary.add(&outcome);
            self.emit_changes(outcome.changes);
            self.emit(Event::Sync(SyncProgress {
                height: progress,
                target: tip.height,
            }));
            next_index = after;
            if finished {
                break;
            }
        }
        let block = ScannedBlock {
            height: tip.height,
            hash: tip.last_block_pushed,
            start_pmmr_index: indices.first_index,
            last_pmmr_index: next_index.saturating_sub(1),
        };
        let outcome = self
            .finish_scan(&session, repair, start_height, block)
            .await?;
        summary.add(&outcome);
        self.emit_changes(outcome.changes);
        self.emit(Event::Sync(SyncProgress {
            height: tip.height,
            target: tip.height,
        }));
        info!(height = %tip.height, "scan completed");
        Ok(summary)
    }

    /// What a scan to `tip` with `options` starts from: the stored scan state, checked against
    /// the tip.
    async fn plan_scan(
        &self,
        session: &Arc<Session<S::Store>>,
        options: ScanOptions,
        tip: Height,
    ) -> Result<ScanPlan, ScanError> {
        let state = {
            let session = Arc::clone(session);
            let repairing = options.delete_unconfirmed;
            self.blocking(move |_, _| Ok(session.store.read(|repos| scan_state(repos, repairing))))
                .await??
        };
        chain::check_tip(
            self.config().network,
            &state.position,
            tip,
            self.ports().clock.now(),
        )?;
        let start = if options.delete_unconfirmed {
            ScanStart::Genesis
        } else {
            options.start
        };
        Ok(ScanPlan {
            checkpoint: state.checkpoint,
            update: !options.delete_unconfirmed
                && !matches!(options.start, ScanStart::Genesis)
                && state.genesis_scanned,
            repair: state.repair.map(Arc::new),
            start_height: resolve_start(start, state.last_scanned.as_ref(), tip),
        })
    }

    /// The page of unspent outputs from `next_index` on, checked against the tip, with the index
    /// after it and whether it is the last page.
    async fn fetch_page(
        &self,
        next_index: u64,
        last_index: u64,
        tip: Height,
        options: ScanOptions,
        cancel: &ScanCancel,
    ) -> Result<(UnspentOutputs, u64, bool), ScanError> {
        let page = until_cancelled(
            cancel,
            self.ports().node.get_unspent_outputs(
                next_index,
                Some(last_index),
                options.page_size.get(),
            ),
        )
        .await?;
        let finished = page.highest_index <= page.last_retrieved_index;
        let after = page
            .last_retrieved_index
            .checked_add(1)
            .ok_or(ScanError::Paging)?;
        if after <= next_index {
            return Err(ScanError::Paging);
        }
        for output in &page.outputs {
            chain::check_output_height(output.height, tip)?;
        }
        Ok((page, after, finished))
    }

    /// Records the scanned `block`, ends what the scan settled, and closes the spends of
    /// another wallet whose blocks the scan from `start_height` covered.
    async fn finish_scan(
        &self,
        session: &Arc<Session<S::Store>>,
        repair: Option<Arc<Repair>>,
        start_height: Height,
        block: ScannedBlock,
    ) -> Result<PageOutcome, ScanError> {
        let now = self.ports().clock.now();
        let outcome = {
            let session = Arc::clone(session);
            self.blocking(move |_, config| {
                let codecs = legacy_codecs(config.network.params().default_base_fee());
                let ending = Ending {
                    now,
                    tip: block.height,
                    codecs: &codecs,
                };
                Ok(session
                    .store
                    .write(|repos| finish(repos, repair.as_deref(), start_height, &block, &ending)))
            })
            .await??
        };
        let session = Arc::clone(session);
        let end = block.height;
        self.blocking(move |_, _| {
            Ok(session
                .store
                .write(|repos| other_wallet::close_scanned(repos, start_height, end)))
        })
        .await??;
        Ok(outcome)
    }

    /// Where the last completed scan ended, or `None` before the first one completes. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn last_scanned_block(&self) -> Result<Option<ScannedBlock>, WalletError> {
        let session = self.session()?;
        session.store.read(|repos| Ok(last_scanned(repos)?))
    }

    /// Forgets where the chain was, the last confirmed height, the last scanned block and the
    /// tip the wallet measures new tips against, then scans the whole chain with `options`
    /// starting from genesis. This recovers a wallet that stored a height the chain has not
    /// reached, which leaves every later refresh behind it.
    ///
    /// Fails as [`Wallet::scan`] does. The stored heights are forgotten even when the scan
    /// fails; the next refresh or scan stores them again.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn reset_chain_position(
        &self,
        options: ScanOptions,
        cancel: &ScanCancel,
    ) -> Result<ScanSummary, ScanError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            session.store.write(|repos| {
                repos.delete_setting(crate::refresh::LAST_CONFIRMED_SETTING)?;
                repos.delete_setting(LAST_SCANNED_SETTING)?;
                repos.delete_setting(CHECKPOINT_SETTING)?;
                chain::forget(repos)?;
                Ok::<_, WalletError>(())
            })
        })
        .await?;
        info!("chain position reset");
        self.scan(
            ScanOptions {
                start: ScanStart::Genesis,
                ..options
            },
            cancel,
        )
        .await
    }

    /// Identifies a page on the blocking pool, since rewinding a full page of proofs takes a
    /// while, asks the node again about the outputs found that are stored as spent, and stores
    /// the page with its checkpoint in one transaction.
    async fn store_page(
        &self,
        session: Arc<Session<S::Store>>,
        page: Page,
        repair: Option<Arc<Repair>>,
        options: ScanOptions,
        cancel: &ScanCancel,
    ) -> Result<PageOutcome, ScanError> {
        let Page {
            outputs,
            checkpoint,
            tip,
            update,
        } = page;
        let (found, spent, undated) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(
                    identify(&session.keychain, &outputs, options.coinbase_maturity).and_then(
                        |found| {
                            let (spent, undated) = session.store.read(|repos| {
                                Ok::<_, ScanError>((
                                    stored_as_spent(repos, &found)?,
                                    unexplained_heights(repos, &found)?,
                                ))
                            })?;
                            Ok((found, spent, undated))
                        },
                    ),
                )
            })
            .await??
        };
        let block_times = until_cancelled(cancel, async {
            Ok::<_, NodeError>(block_times(&self.ports().node, undated).await)
        })
        .await?;
        let mut revivable = BTreeSet::new();
        if !spent.is_empty() {
            let held = until_cancelled(cancel, self.ports().node.get_outputs(&spent)).await?;
            for location in held {
                chain::check_output_height(location.height, tip)?;
                revivable.insert(location.commitment);
            }
        }
        let now = self.ports().clock.now();
        self.blocking(move |_, config| {
            let codecs = legacy_codecs(config.network.params().default_base_fee());
            let ending = Ending {
                now,
                tip,
                codecs: &codecs,
            };
            Ok(session.store.write(|repos| {
                store_found(
                    repos,
                    &found,
                    &revivable,
                    &block_times,
                    repair.as_deref(),
                    checkpoint,
                    update,
                    &ending,
                )
            }))
        })
        .await?
    }

    fn emit_changes(&self, changes: Vec<StateChange>) {
        for change in changes {
            self.emit(change.into());
        }
    }
}

impl ScanSummary {
    fn add(&mut self, outcome: &PageOutcome) {
        self.found = self.found.saturating_add(outcome.found);
        self.restored = self.restored.saturating_add(outcome.restored);
        self.revived = self.revived.saturating_add(outcome.revived);
        self.unlocked = self.unlocked.saturating_add(outcome.unlocked);
        self.deleted = self.deleted.saturating_add(outcome.deleted);
    }
}

/// Where an interrupted scan goes on: the index its `checkpoint` stored, when the checkpoint
/// is of a scan from the same `start_height` and output index `first_index` with the same
/// options. `None` starts over.
fn resume_index(
    checkpoint: Option<Checkpoint>,
    start_height: Height,
    first_index: u64,
    options: ScanOptions,
) -> Option<u64> {
    checkpoint
        .filter(|checkpoint| {
            checkpoint.start_height == start_height
                && checkpoint.first_index == first_index
                && checkpoint.delete_unconfirmed == options.delete_unconfirmed
        })
        .map(|checkpoint| checkpoint.next_index)
}

async fn until_cancelled<T>(
    cancel: &ScanCancel,
    request: impl Future<Output = Result<T, NodeError>>,
) -> Result<T, ScanError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ScanError::Cancelled),
        result = request => Ok(result?),
    }
}

/// A last scanned block above the tip is from a node that was ahead, or on another fork, so the
/// scan reaches back from the tip instead.
fn resolve_start(start: ScanStart, last_scanned: Option<&ScannedBlock>, tip: Height) -> Height {
    match start {
        ScanStart::Genesis => Height::ZERO,
        ScanStart::Height(height) => height,
        ScanStart::LastScanned => last_scanned.map_or(Height::ZERO, |block| {
            Height::new(
                block
                    .height
                    .min(tip)
                    .value()
                    .saturating_sub(UPDATE_RESCAN_BLOCKS),
            )
        }),
    }
}

/// What a scan starts from.
struct ScanState {
    last_scanned: Option<ScannedBlock>,
    /// A scan from genesis completed before this one.
    genesis_scanned: bool,
    checkpoint: Option<Checkpoint>,
    position: ChainPosition,
    repair: Option<Repair>,
}

/// The outputs a `delete_unconfirmed` scan repairs: those locked or unconfirmed when it
/// started, as `epic-wallet` reads them before it scans. Outputs a send or receive makes while
/// the scan runs are left alone.
#[derive(Debug, Default)]
struct Repair {
    locked: BTreeSet<CommitmentBytes>,
    unconfirmed: BTreeSet<CommitmentBytes>,
}

fn repair_set(repos: &dyn Repositories) -> Result<Repair, StoreError> {
    let mut repair = Repair::default();
    for account in repos.accounts()? {
        for output in repos.outputs(account.index, Some(OutputStatus::Locked))? {
            repair.locked.insert(*output.commitment());
        }
        for output in repos.outputs(account.index, Some(OutputStatus::Unconfirmed))? {
            repair.unconfirmed.insert(*output.commitment());
        }
    }
    Ok(repair)
}

fn scan_state(repos: &dyn Repositories, repairing: bool) -> Result<ScanState, ScanError> {
    let checkpoint = match repos.setting(CHECKPOINT_SETTING)? {
        Some(text) => {
            let checkpoint = Checkpoint::decode(&text);
            if checkpoint.is_none() {
                warn!("scan checkpoint unreadable");
            }
            checkpoint
        }
        None => None,
    };
    Ok(ScanState {
        last_scanned: last_scanned(repos)?,
        genesis_scanned: has_scanned(repos)?,
        checkpoint,
        position: chain::position(repos)?,
        repair: repairing.then(|| repair_set(repos)).transpose()?,
    })
}

/// The found outputs that are stored as spent.
fn stored_as_spent(
    repos: &dyn Repositories,
    found: &[FoundOutput],
) -> Result<Vec<Commitment>, ScanError> {
    let mut spent = Vec::new();
    for output in found {
        let commitment = output.id.commitment;
        if repos
            .output(commitment.as_bytes())?
            .is_some_and(|stored| stored.status == OutputStatus::Spent)
        {
            spent.push(commitment);
        }
    }
    Ok(spent)
}

/// Whether a scan from genesis has completed.
pub(crate) fn has_scanned(repos: &dyn Repositories) -> Result<bool, StoreError> {
    Ok(repos.setting(GENESIS_SCANNED_SETTING)?.is_some())
}

/// A stored position that does not parse is ignored, which costs a full scan and loses nothing.
fn last_scanned(repos: &dyn Repositories) -> Result<Option<ScannedBlock>, StoreError> {
    Ok(match repos.setting(LAST_SCANNED_SETTING)? {
        Some(text) => {
            let block = ScannedBlock::decode(&text);
            if block.is_none() {
                warn!("last scanned block unreadable");
            }
            block
        }
        None => None,
    })
}

/// The page's outputs that belong to this wallet, in the node's order.
fn identify(
    keychain: &lepic_keychain::Keychain,
    outputs: &[UnspentOutput],
    coinbase_maturity: u64,
) -> Result<Vec<FoundOutput>, ScanError> {
    let rewinder = OutputRewinder::new(keychain)?;
    let mut found = Vec::new();
    for output in outputs {
        let Some(rewound) = rewinder.rewind(&output.commitment, &output.proof)? else {
            continue;
        };
        let (account, child) = placement(&rewound.identifier);
        if rewound.switch != SwitchCommitment::Regular {
            warn!(height = %output.height, "unexpected switch commitment found");
        }
        let lock_height = if output.features.is_coinbase() {
            output.height.checked_add_blocks(coinbase_maturity)?
        } else {
            output.height
        };
        found.push(FoundOutput {
            id: OutputIdentifier::new(output.features, output.commitment),
            key_id: rewound.identifier,
            account,
            child,
            amount: Amount::new(rewound.amount),
            height: output.height,
            lock_height,
            mmr_index: output.mmr_index,
        });
    }
    Ok(found)
}

/// The account a restored output is stored under, and the child number that advances that
/// account's key counter.
///
/// Every output whose proof rewinds is restored, as `epic-wallet` restores it, so no funds are
/// missed on unusual paths. A key `m/<a>/0/<c>` belongs to account `a`, the account of its parent
/// path. The store keeps accounts as `m/<a>/0` only, so a key under any other parent is stored
/// under the default account; its exact key id is kept, so it is spent with the right key. A
/// hardened child never advances the counter, which hands out unhardened keys only.
fn placement(key_id: &Identifier) -> (AccountIndex, Option<u32>) {
    match (key_id.depth(), key_id.components()) {
        (3, [account, 0, child, _]) => (
            AccountIndex(account),
            (child < FIRST_HARDENED).then_some(child),
        ),
        _ => {
            debug!("output key outside the account paths found");
            (AccountIndex(0), None)
        }
    }
}

/// The heights of found outputs that are new and that no imported entry explains: their
/// entries are dated by their block.
fn unexplained_heights(
    repos: &dyn Repositories,
    found: &[FoundOutput],
) -> Result<BTreeSet<Height>, ScanError> {
    let mut heights = BTreeSet::new();
    for output in found {
        let commitment = output.id.commitment.as_bytes();
        if repos.output(commitment)?.is_none() && repos.imported_output(commitment)?.is_none() {
            heights.insert(output.height);
        }
    }
    Ok(heights)
}

#[allow(clippy::too_many_arguments)] // The page and what the scan knows about it.
fn store_found(
    repos: &mut dyn Repositories,
    found: &[FoundOutput],
    revivable: &BTreeSet<Commitment>,
    block_times: &BTreeMap<Height, Timestamp>,
    repair: Option<&Repair>,
    checkpoint: Checkpoint,
    update: bool,
    ending: &Ending<'_>,
) -> Result<PageOutcome, ScanError> {
    let now = ending.now;
    let mut outcome = PageOutcome::default();
    let mut highest_child: BTreeMap<AccountIndex, u32> = BTreeMap::new();
    let during = if lifecycle::restore_scan_pending(repos)? {
        FoundDuring::Restore
    } else {
        FoundDuring::Rescan
    };
    for output in found {
        outcome.found = outcome.found.saturating_add(1);
        match repos.output(output.id.commitment.as_bytes())? {
            Some(stored) => {
                let revivable = revivable.contains(&output.id.commitment);
                reconcile(
                    repos,
                    stored,
                    output,
                    revivable,
                    repair,
                    ending,
                    &mut outcome,
                )?;
            }
            None => {
                let block_time = block_times.get(&output.height).copied();
                let found = ScanFound {
                    during,
                    dated_by_block: block_time.is_some(),
                };
                if let Some(change) =
                    restore_missing(repos, output, block_time.unwrap_or(now), found, update, now)?
                {
                    outcome.changes.push(change);
                }
                outcome.restored = outcome.restored.saturating_add(1);
                debug!(height = %output.height, "output restored");
                if let Some(child) = output.child {
                    let highest = highest_child.entry(output.account).or_insert(child);
                    *highest = (*highest).max(child);
                }
            }
        }
    }
    for (account, child) in highest_child {
        advance_next_child(repos, account, child)?;
    }
    repos.put_setting(CHECKPOINT_SETTING, &checkpoint.encode())?;
    Ok(outcome)
}

/// Brings a stored output in line with the chain without touching what only a refresh decides.
/// A spent output is revived only when `revivable`: the node held it when asked again.
fn reconcile(
    repos: &mut dyn Repositories,
    mut stored: OutputRecord,
    found: &FoundOutput,
    revivable: bool,
    repair: Option<&Repair>,
    ending: &Ending<'_>,
    outcome: &mut PageOutcome,
) -> Result<(), ScanError> {
    let changed = stored.mmr_index != Some(found.mmr_index);
    stored.mmr_index = Some(found.mmr_index);
    let repaired = |set: fn(&Repair) -> &BTreeSet<CommitmentBytes>| {
        repair.is_some_and(|repair| set(repair).contains(stored.commitment()))
    };
    // The output is stored before its transaction is cancelled, which then leaves it alone.
    let cancel = match stored.status {
        OutputStatus::Spent if !revivable => {
            debug!(height = %found.height, "output revival not confirmed");
            false
        }
        OutputStatus::Spent => {
            outcome.revived = outcome.revived.saturating_add(1);
            debug!(height = %found.height, "output revived");
            other_wallet::revived(repos, &stored)?;
            true
        }
        OutputStatus::Locked if repaired(|repair| &repair.locked) => {
            outcome.unlocked = outcome.unlocked.saturating_add(1);
            true
        }
        // The repair deletes the unconfirmed outputs it started with that are left at the end;
        // one on chain is kept as unspent instead of being lost until the next scan.
        OutputStatus::Unconfirmed if repaired(|repair| &repair.unconfirmed) => {
            stored.status = OutputStatus::Unspent;
            repos.put_output(&stored)?;
            return Ok(());
        }
        OutputStatus::Unconfirmed | OutputStatus::Unspent | OutputStatus::Locked => false,
    };
    if cancel {
        stored.status = OutputStatus::Unspent;
        repos.put_output(&stored)?;
        cancel_open(repos, stored.tx, ending, outcome)?;
    } else if changed {
        repos.put_output(&stored)?;
    }
    Ok(())
}

/// Stores an output the store did not hold. One an imported entry created is linked to it;
/// any other gets a confirmed incoming entry of its own, dated `created_at`, with `found`
/// recorded for it.
fn restore_missing(
    repos: &mut dyn Repositories,
    output: &FoundOutput,
    created_at: Timestamp,
    found: ScanFound,
    update: bool,
    now: Timestamp,
) -> Result<Option<StateChange>, ScanError> {
    ensure_account(repos, output.account)?;
    let commitment = *output.id.commitment.as_bytes();
    let linked = match legacy_history::link_found_output(
        repos,
        &commitment,
        output.account,
        output.height,
        now,
    )? {
        Some(imported) => Some(imported),
        None => other_wallet::take_change(
            repos,
            output.account,
            &output.id.commitment,
            output.amount,
            output.height,
        )?,
    };
    let mut change = None;
    let tx = match linked {
        Some(linked) => linked,
        None => {
            let tx = repos.insert_transaction(&TransactionEntry {
                account: output.account,
                direction: TxDirection::Incoming,
                state: TxState::Confirmed,
                slate_id: None,
                transport: None,
                amount_credited: output.amount,
                amount_debited: Amount::ZERO,
                fee: None,
                created_at,
                updated_at: created_at,
            })?;
            repos.set_confirmed_height(tx, output.height)?;
            // An update scan over recent blocks finds what another wallet on the phrase
            // received; a restore or a scan from genesis finds what no record explains.
            let received_elsewhere = update && found.during == FoundDuring::Rescan;
            repos.put_scan_found(
                tx,
                &ScanFoundRecord {
                    output: Some(*output.id.commitment.as_bytes()),
                    during: (!received_elsewhere).then_some(found.during),
                    dated_by_block: !received_elsewhere && found.dated_by_block,
                },
            )?;
            if received_elsewhere {
                other_wallet::mark_received(repos, tx, output.height)?;
                change = Some(StateChange {
                    tx_id: tx,
                    from: TxState::Confirmed,
                    to: TxState::Confirmed,
                });
            }
            tx
        }
    };
    repos.put_output(&OutputRecord {
        id: output.id,
        key_id: KeyId(output.key_id.to_bytes()),
        account: output.account,
        amount: output.amount,
        status: OutputStatus::Unspent,
        height: output.height,
        lock_height: output.lock_height,
        mmr_index: Some(output.mmr_index),
        tx: Some(tx),
    })?;
    Ok(change)
}

/// Adds an account a restored output belongs to under the label `epic-wallet` would give it.
fn ensure_account(repos: &mut dyn Repositories, index: AccountIndex) -> Result<(), ScanError> {
    if repos.account(index)?.is_some() {
        return Ok(());
    }
    let mut number = repos.accounts()?.len();
    let label = loop {
        let label = format!("{RESTORED_ACCOUNT_LABEL}_{number}");
        if repos.account_by_label(&label)?.is_none() {
            break label;
        }
        number = number.checked_add(1).ok_or(ArithmeticError::Overflow)?;
    };
    repos.put_account(&AccountRecord {
        index,
        label: label.clone(),
        next_child: key_counter_start(repos, index)?,
    })?;
    info!(account = %label, "account restored");
    Ok(())
}

/// Moves the account's key counter past a restored output's key, so no key is handed out twice.
/// Only a key within [`OWN_KEY_WINDOW`] of the counter moves it: one further up was handed out
/// by another install of the phrase, whose next keys the counter would otherwise walk into.
fn advance_next_child(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    child: u32,
) -> Result<(), ScanError> {
    let Some(mut record) = repos.account(account)? else {
        return Ok(());
    };
    let own = child
        .checked_sub(record.next_child)
        .is_some_and(|above| above < OWN_KEY_WINDOW);
    if own {
        record.next_child = child.checked_add(1).ok_or(ArithmeticError::Overflow)?;
        repos.put_account(&record)?;
    }
    Ok(())
}

/// Cancels the open transaction an output belongs to as a cancel by the user does: its
/// unconfirmed outputs are deleted, the inputs it locked unlocked, and its private context and
/// pending deliveries dropped. Either entry of a send to the wallet itself takes the other
/// along. A confirmed, cancelled or expired one is left alone, as `epic-wallet` leaves every
/// type but the open ones.
fn cancel_open(
    repos: &mut dyn Repositories,
    tx: Option<TxId>,
    ending: &Ending<'_>,
    outcome: &mut PageOutcome,
) -> Result<(), ScanError> {
    let Some(tx_id) = tx else {
        return Ok(());
    };
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(());
    };
    if is_final(entry.state) {
        return Ok(());
    }
    let kernel = ended_kernel(repos, ending.codecs, tx_id, &entry)?;
    cancel_one(repos, tx_id, &entry, kernel, ending, outcome)?;
    if let Some(partner) = self_send_partner(repos, &entry)?
        && !is_final(partner.entry.state)
    {
        cancel_one(repos, partner.id, &partner.entry, kernel, ending, outcome)?;
    }
    Ok(())
}

/// The kernel a transaction the scan ends may still be mined with, and the height below which
/// it cannot be: one finalized or posted here, an invoice payment with its I2, or a received
/// payment with its S2. A posted transaction whose block a reorganisation undid is usually
/// mined again.
fn ended_kernel(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    entry: &TransactionEntry,
) -> Result<Option<KernelAt>, StoreError> {
    match (entry.state, entry.slate_id) {
        (TxState::Posted, Some(slate_id)) => final_kernel(repos, codecs, tx_id, slate_id),
        _ => pending_kernel(
            repos,
            codecs,
            &StoredTransaction {
                id: tx_id,
                entry: entry.clone(),
            },
        ),
    }
}

/// Ends the transaction as a cancel does: with `kernel` watched from the scan's tip, so a
/// refresh confirms it and restores its outputs if the chain mines it after all.
fn cancel_one(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    entry: &TransactionEntry,
    kernel: Option<KernelAt>,
    ending: &Ending<'_>,
    outcome: &mut PageOutcome,
) -> Result<(), ScanError> {
    for output in repos.outputs_of_transaction(tx_id)? {
        match output.status {
            OutputStatus::Unconfirmed => outcome.deleted = outcome.deleted.saturating_add(1),
            OutputStatus::Locked => outcome.unlocked = outcome.unlocked.saturating_add(1),
            OutputStatus::Unspent | OutputStatus::Spent => {}
        }
    }
    if let Some((excess, min_height)) = kernel {
        record_watch(repos, tx_id, excess, min_height, ending.tip)?;
    }
    drop_holdings(repos, tx_id, entry)?;
    if let Some(change) = apply_transition(repos, tx_id, TxState::Cancelled, ending.now)? {
        outcome.changes.push(change);
    }
    Ok(())
}

/// Ends a scan: the `delete_unconfirmed` repair, then the scanned position replaces the
/// checkpoint. A scan from genesis has found every output key in use.
fn finish(
    repos: &mut dyn Repositories,
    repair: Option<&Repair>,
    start_height: Height,
    block: &ScannedBlock,
    ending: &Ending<'_>,
) -> Result<PageOutcome, ScanError> {
    let now = ending.now;
    let mut outcome = PageOutcome::default();
    for commitment in repair.iter().flat_map(|repair| &repair.unconfirmed) {
        let unconfirmed = |repos: &dyn Repositories| {
            Ok::<_, StoreError>(
                repos
                    .output(commitment)?
                    .filter(|output| output.status == OutputStatus::Unconfirmed),
            )
        };
        let Some(output) = unconfirmed(repos)? else {
            continue;
        };
        cancel_open(repos, output.tx, ending, &mut outcome)?;
        // An output of a transaction no cancel applies to is deleted on its own.
        if unconfirmed(repos)?.is_some() {
            repos.delete_output(commitment)?;
            outcome.deleted = outcome.deleted.saturating_add(1);
        }
    }
    repos.put_setting(LAST_SCANNED_SETTING, &block.encode())?;
    repos.delete_setting(CHECKPOINT_SETTING)?;
    let last_confirmed = crate::refresh::last_confirmed(repos)?;
    chain::observe_tip(repos, last_confirmed, block.height, now)?;
    if start_height == Height::ZERO {
        lifecycle::restore_scan_completed(repos)?;
        repos.put_setting(GENESIS_SCANNED_SETTING, "1")?;
        legacy_history::flag_missing_outputs(repos)?;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A posted send whose input a scan finds unspent again, as after a reorganisation undid
    /// its block, is cancelled with its kernel watched, so a refresh confirms it if the chain
    /// mines it again.
    #[test]
    fn a_posted_send_a_scan_cancels_keeps_its_kernel_watched() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/slates/send_file_plain_s3_v3.json"
        ))
        .unwrap();
        let s3 = vector["expected"]["json"].as_str().unwrap().to_owned();
        let slate_id: uuid::Uuid = vector["expected"]["slate_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let store = lepic_store::MemoryStore::new(lepic_store::ContextKey::from_bytes(
            [1; lepic_store::CONTEXT_KEY_LEN],
        ));
        let now = Timestamp::UNIX_EPOCH;
        let tx_id = store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(0),
                    label: "default".to_owned(),
                    next_child: 0,
                })?;
                let tx_id = repos.insert_transaction(&TransactionEntry {
                    account: AccountIndex(0),
                    direction: TxDirection::Outgoing,
                    state: TxState::Posted,
                    slate_id: Some(slate_id),
                    transport: Some("file".to_owned()),
                    amount_credited: Amount::ZERO,
                    amount_debited: Amount::ZERO,
                    fee: None,
                    created_at: now,
                    updated_at: now,
                })?;
                repos.insert_slate(&lepic_store::StoredSlate {
                    slate_id,
                    stage: lepic_store::SlateStage::Standard3,
                    codec: "legacy-v3".to_owned(),
                    bytes: s3.into_bytes(),
                })?;
                Ok::<_, StoreError>(tx_id)
            })
            .unwrap();
        let codecs = legacy_codecs(Network::Floonet.params().default_base_fee());
        let ending = Ending {
            now,
            tip: Height::new(100),
            codecs: &codecs,
        };

        store
            .write(|repos| cancel_open(repos, Some(tx_id), &ending, &mut PageOutcome::default()))
            .unwrap();

        let (state, watch) = store
            .read(|repos| {
                Ok::<_, StoreError>((
                    repos.transaction(tx_id)?.unwrap().state,
                    repos.tx_watch(tx_id)?,
                ))
            })
            .unwrap();
        assert_eq!(state, TxState::Cancelled);
        assert!(watch.is_some(), "the kernel stays watched");
    }

    #[test]
    fn found_keys_move_the_counter_only_within_this_installs_window() {
        let store = lepic_store::MemoryStore::new(lepic_store::ContextKey::from_bytes(
            [1; lepic_store::CONTEXT_KEY_LEN],
        ));
        let counter = |store: &lepic_store::MemoryStore| {
            store
                .read(|repos| repos.account(AccountIndex(0)))
                .unwrap()
                .unwrap()
                .next_child
        };
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(0),
                    label: "default".to_owned(),
                    next_child: 5_000_000,
                })
            })
            .unwrap();
        for child in [12, 4_999_999, 5_000_000 + OWN_KEY_WINDOW, 900_000_000] {
            store
                .write(|repos| advance_next_child(repos, AccountIndex(0), child))
                .unwrap();
            assert_eq!(counter(&store), 5_000_000, "{child}");
        }
        store
            .write(|repos| advance_next_child(repos, AccountIndex(0), 5_000_000 + 40))
            .unwrap();
        assert_eq!(counter(&store), 5_000_041);
    }

    #[test]
    fn scanned_block_round_trips_and_rejects_malformed_text() {
        let block = ScannedBlock {
            height: Height::new(14),
            hash: Hash::from_slice(&[7; 32]).unwrap(),
            start_pmmr_index: 1,
            last_pmmr_index: 38,
        };
        assert_eq!(ScannedBlock::decode(&block.encode()), Some(block));
        for text in ["", "14", "14 zz 1 38", &format!("{} 9", block.encode())] {
            assert_eq!(ScannedBlock::decode(text), None, "{text}");
        }
    }

    #[test]
    fn checkpoint_round_trips_and_rejects_malformed_text() {
        for delete_unconfirmed in [false, true] {
            let checkpoint = Checkpoint {
                start_height: Height::new(3),
                first_index: 1,
                next_index: 9,
                delete_unconfirmed,
            };
            assert_eq!(Checkpoint::decode(&checkpoint.encode()), Some(checkpoint));
        }
        for text in [
            "",
            "3 1",
            "3 1 9",
            "3 1 x keep_unconfirmed",
            "3 1 9 9",
            "3 1 9 keep_unconfirmed 9",
            "-3 1 9 keep_unconfirmed",
        ] {
            assert_eq!(Checkpoint::decode(text), None, "{text}");
        }
    }

    #[test]
    fn update_scans_reach_back_from_the_last_scanned_height() {
        let block = |height| ScannedBlock {
            height: Height::new(height),
            hash: Hash::from_slice(&[0; 32]).unwrap(),
            start_pmmr_index: 1,
            last_pmmr_index: 1,
        };
        let last = ScanStart::LastScanned;
        let tip = Height::new(300);
        assert_eq!(resolve_start(last, None, tip), Height::ZERO);
        assert_eq!(resolve_start(last, Some(&block(14)), tip), Height::ZERO);
        assert_eq!(
            resolve_start(last, Some(&block(250)), tip),
            Height::new(150)
        );
        assert_eq!(
            resolve_start(last, Some(&block(u64::MAX)), tip),
            Height::new(200)
        );
        assert_eq!(
            resolve_start(ScanStart::Height(Height::new(5)), Some(&block(250)), tip),
            Height::new(5)
        );
        assert_eq!(
            resolve_start(ScanStart::Genesis, Some(&block(250)), tip),
            Height::ZERO
        );
    }

    #[test]
    fn outputs_go_to_the_account_of_their_parent_path_or_the_default() {
        let key = |depth, components| Identifier::new(depth, components).unwrap();
        let default = (AccountIndex(0), None);
        assert_eq!(placement(&key(3, [0, 0, 5, 0])), (AccountIndex(0), Some(5)));
        assert_eq!(placement(&key(3, [2, 0, 0, 0])), (AccountIndex(2), Some(0)));
        assert_eq!(
            placement(&key(3, [FIRST_HARDENED, 0, 5, 0])),
            (AccountIndex(FIRST_HARDENED), Some(5))
        );
        assert_eq!(
            placement(&key(3, [0, 0, FIRST_HARDENED, 0])),
            (AccountIndex(0), None)
        );
        assert_eq!(placement(&key(2, [0, 0, 0, 0])), default);
        assert_eq!(placement(&key(3, [0, 1, 5, 0])), default);
        assert_eq!(placement(&key(4, [0, 0, 5, 1])), default);
        assert_eq!(placement(&key(1, [7, 0, 0, 0])), default);
    }
}
