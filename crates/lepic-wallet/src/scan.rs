//! Scan and restore: find the wallet's outputs in the node's UTXO set by rewinding their range
//! proofs, and reconcile what is found with the store, as `epic-wallet` does. The algorithm is in
//! `docs/compat/node-api.md` (restore and scan), the output transitions in
//! `docs/compat/states.md`.
//!
//! A scan pages through the output MMR index range of a height range. Each page is identified
//! and stored in its own store transaction together with a checkpoint, so a large restore never
//! holds one huge transaction, and a scan that was cancelled, failed or was killed resumes after
//! the last stored page.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_keychain::{Identifier, OutputRewinder, ProofError, SwitchCommitment};
use lepic_node::{NodeApi, NodeError, UnspentOutput};
use lepic_primitives::amount::{Amount, ArithmeticError, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::output::OutputIdentifier;
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, AccountRecord, KeyId, OutputRecord, OutputStatus, Repositories, StoreError,
    TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, instrument, warn};

use crate::account::FIRST_HARDENED;
use crate::error::WalletError;
use crate::event::{Event, SyncProgress};
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
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
    /// [`UPDATE_RESCAN_BLOCKS`] behind the last completed scan, or the whole chain when no scan
    /// has completed.
    LastScanned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    pub start: ScanStart,
    /// Also unlock locked outputs found on chain and delete unconfirmed outputs not found,
    /// cancelling their transactions: the repair `epic-wallet scan --delete_unconfirmed` runs.
    /// A scan resumes an interrupted one only when this setting matches, so a repair is never
    /// skipped for pages an earlier plain scan stored.
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
    /// Locked outputs unlocked by a scan with `delete_unconfirmed`.
    pub unlocked: u64,
    /// Unconfirmed outputs deleted by a scan with `delete_unconfirmed`.
    pub deleted: u64,
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
    /// Every page is stored as it is scanned. When the scan fails or is cancelled, the next scan
    /// from the same start resumes after the last stored page. Fails with
    /// [`ScanError::Cancelled`], [`ScanError::Node`], or [`WalletError::Locked`] inside
    /// [`ScanError::Wallet`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn scan(
        &self,
        options: ScanOptions,
        cancel: &ScanCancel,
    ) -> Result<ScanSummary, ScanError> {
        let session = self.session()?;
        let node = &self.ports().node;
        let tip = until_cancelled(cancel, node.get_tip()).await?;
        let (last_scanned, checkpoint) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| Ok(session.store.read(|repos| scan_state(repos))))
                .await??
        };
        let start_height = resolve_start(options.start, last_scanned.as_ref());
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
        let mut next_index = indices.first_index;
        if let Some(checkpoint) = checkpoint
            && checkpoint.start_height == start_height
            && checkpoint.first_index == indices.first_index
            && checkpoint.delete_unconfirmed == options.delete_unconfirmed
        {
            next_index = checkpoint.next_index;
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
            let page = until_cancelled(
                cancel,
                node.get_unspent_outputs(
                    next_index,
                    Some(indices.last_index),
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
                .store_page(Arc::clone(&session), page.outputs, options, checkpoint)
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
        let now = self.ports().clock.now();
        let outcome = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .write(|repos| finish(repos, options, &block, now)))
            })
            .await??
        };
        summary.add(&outcome);
        self.emit_changes(outcome.changes);
        self.emit(Event::Sync(SyncProgress {
            height: tip.height,
            target: tip.height,
        }));
        info!(height = %tip.height, "scan completed");
        Ok(summary)
    }

    /// Where the last completed scan ended, or `None` before the first one completes. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn last_scanned_block(&self) -> Result<Option<ScannedBlock>, WalletError> {
        let session = self.session()?;
        session.store.read(|repos| Ok(last_scanned(repos)?))
    }

    /// Identifies a page on the blocking pool, since rewinding a full page of proofs takes a
    /// while, and stores it with its checkpoint in one transaction.
    async fn store_page(
        &self,
        session: Arc<Session<S::Store>>,
        outputs: Vec<UnspentOutput>,
        options: ScanOptions,
        checkpoint: Checkpoint,
    ) -> Result<PageOutcome, ScanError> {
        let now = self.ports().clock.now();
        self.blocking(move |_, _| {
            Ok(
                identify(&session.keychain, &outputs, options.coinbase_maturity).and_then(
                    |found| {
                        session
                            .store
                            .write(|repos| store_found(repos, &found, options, checkpoint, now))
                    },
                ),
            )
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

fn resolve_start(start: ScanStart, last_scanned: Option<&ScannedBlock>) -> Height {
    match start {
        ScanStart::Genesis => Height::ZERO,
        ScanStart::Height(height) => height,
        ScanStart::LastScanned => last_scanned.map_or(Height::ZERO, |block| {
            Height::new(block.height.value().saturating_sub(UPDATE_RESCAN_BLOCKS))
        }),
    }
}

fn scan_state(
    repos: &dyn Repositories,
) -> Result<(Option<ScannedBlock>, Option<Checkpoint>), ScanError> {
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
    Ok((last_scanned(repos)?, checkpoint))
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

fn store_found(
    repos: &mut dyn Repositories,
    found: &[FoundOutput],
    options: ScanOptions,
    checkpoint: Checkpoint,
    now: Timestamp,
) -> Result<PageOutcome, ScanError> {
    let mut outcome = PageOutcome::default();
    let mut highest_child: BTreeMap<AccountIndex, u32> = BTreeMap::new();
    for output in found {
        outcome.found = outcome.found.saturating_add(1);
        match repos.output(output.id.commitment.as_bytes())? {
            Some(stored) => reconcile(repos, stored, output, options, now, &mut outcome)?,
            None => {
                restore_missing(repos, output, now)?;
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
fn reconcile(
    repos: &mut dyn Repositories,
    mut stored: OutputRecord,
    found: &FoundOutput,
    options: ScanOptions,
    now: Timestamp,
    outcome: &mut PageOutcome,
) -> Result<(), ScanError> {
    let mut changed = stored.mmr_index != Some(found.mmr_index);
    stored.mmr_index = Some(found.mmr_index);
    match stored.status {
        OutputStatus::Spent => {
            stored.status = OutputStatus::Unspent;
            changed = true;
            outcome.revived = outcome.revived.saturating_add(1);
            cancel_transaction(repos, stored.tx, now, &mut outcome.changes)?;
            debug!(height = %found.height, "output revived");
        }
        OutputStatus::Locked if options.delete_unconfirmed => {
            stored.status = OutputStatus::Unspent;
            changed = true;
            outcome.unlocked = outcome.unlocked.saturating_add(1);
            cancel_transaction(repos, stored.tx, now, &mut outcome.changes)?;
        }
        // A delete_unconfirmed repair deletes every unconfirmed output left at the end; one on
        // chain is kept as unspent instead of being lost until the next scan.
        OutputStatus::Unconfirmed if options.delete_unconfirmed => {
            stored.status = OutputStatus::Unspent;
            changed = true;
        }
        OutputStatus::Unconfirmed | OutputStatus::Unspent | OutputStatus::Locked => {}
    }
    if changed {
        repos.put_output(&stored)?;
    }
    Ok(())
}

fn restore_missing(
    repos: &mut dyn Repositories,
    output: &FoundOutput,
    now: Timestamp,
) -> Result<(), ScanError> {
    ensure_account(repos, output.account)?;
    let tx = repos.insert_transaction(&TransactionEntry {
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
    Ok(())
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
        next_child: 0,
    })?;
    info!(account = %label, "account restored");
    Ok(())
}

/// Moves the account's key counter past a restored output's key, so no key is handed out twice.
fn advance_next_child(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    child: u32,
) -> Result<(), ScanError> {
    let Some(mut record) = repos.account(account)? else {
        return Ok(());
    };
    if child >= record.next_child {
        record.next_child = child.checked_add(1).ok_or(ArithmeticError::Overflow)?;
        repos.put_account(&record)?;
    }
    Ok(())
}

/// Cancels the open transaction an output belongs to. A confirmed, cancelled or expired one is
/// left alone, as `epic-wallet` leaves every type but the open ones.
fn cancel_transaction(
    repos: &mut dyn Repositories,
    tx: Option<TxId>,
    now: Timestamp,
    changes: &mut Vec<StateChange>,
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
    if let Some(change) = apply_transition(repos, tx_id, TxState::Cancelled, now)? {
        changes.push(change);
    }
    Ok(())
}

/// Ends a scan: the `delete_unconfirmed` repair, then the scanned position replaces the
/// checkpoint.
fn finish(
    repos: &mut dyn Repositories,
    options: ScanOptions,
    block: &ScannedBlock,
    now: Timestamp,
) -> Result<PageOutcome, ScanError> {
    let mut outcome = PageOutcome::default();
    if options.delete_unconfirmed {
        for account in repos.accounts()? {
            for output in repos.outputs(account.index, Some(OutputStatus::Unconfirmed))? {
                cancel_transaction(repos, output.tx, now, &mut outcome.changes)?;
                repos.delete_output(output.commitment())?;
                outcome.deleted = outcome.deleted.saturating_add(1);
            }
        }
    }
    repos.put_setting(LAST_SCANNED_SETTING, &block.encode())?;
    repos.delete_setting(CHECKPOINT_SETTING)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(resolve_start(last, None), Height::ZERO);
        assert_eq!(resolve_start(last, Some(&block(14))), Height::ZERO);
        assert_eq!(resolve_start(last, Some(&block(250))), Height::new(150));
        assert_eq!(
            resolve_start(ScanStart::Height(Height::new(5)), Some(&block(250))),
            Height::new(5)
        );
        assert_eq!(
            resolve_start(ScanStart::Genesis, Some(&block(250))),
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
