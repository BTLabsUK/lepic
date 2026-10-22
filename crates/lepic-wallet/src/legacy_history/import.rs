//! Reading the old wallet's database and storing its history.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::{Commitment, PublicKey, Signature};
use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_store::legacy::{
    self, LegacyDbError, LegacyHistory, LegacyLimits, LegacyMessage, LegacyOutput,
    LegacyOutputStatus, LegacyTxKind, LegacyTxLogEntry,
};
use lepic_store::{
    AccountIndex, AccountRecord, ChainCheck, CommitmentBytes, ImportedKind, ImportedMessage,
    ImportedOutput, ImportedOutputStatus, ImportedTransaction, KeyId, MAX_IMPORTED_MESSAGE_BYTES,
    Repositories, StoreError, TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use tracing::{debug, info, instrument, warn};

use crate::account::{AccountLabel, FIRST_HARDENED};
use crate::epicbox_invoice::display_message;
use crate::error::WalletError;
use crate::lifecycle;
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::verify_signed_text;
use crate::state::is_final;
use crate::wallet::Wallet;

use super::{
    block_times, confirm_imported, flag_missing_outputs, is_found_entry, link_found_output,
};

/// The setting that records which history was imported: the SHA-256 of the copied database.
const IMPORTED_SETTING: &str = "legacy_history.source";

/// The most open imported transactions whose kernel is looked up on the node in one import.
const MAX_KERNEL_LOOKUPS: usize = 200;

/// The longest counterparty address kept from the old log.
const MAX_COUNTERPARTY_LEN: usize = 512;

/// What `epic-wallet` writes as the counterparty of an output a restore found.
const RESTORE_COUNTERPARTY: &str = "Restore";

/// Why no history was imported, or that it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyImportStatus {
    Imported,
    /// This wallet already holds this history; links and dates were brought up to date.
    AlreadyImported,
    /// The folder holds no `epic-wallet` database.
    NoHistory,
    /// The wallet was made by an `epic-wallet` older than 3.3, whose database is not read.
    OldFormat,
    /// The database is encrypted, damaged or not an `epic-wallet` database.
    Unreadable,
    /// The database kept changing while it was copied: the old wallet is running.
    SourceBusy,
    TooLarge,
    /// The history belongs to a wallet with another seed. Nothing was imported.
    OtherWallet,
    /// This wallet already holds a different imported history. Nothing was imported.
    OtherHistory,
}

/// What an import did. Counts are of records, not of money.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyImportOutcome {
    pub status: LegacyImportStatus,
    pub transactions: u32,
    pub outputs: u32,
    pub accounts_named: u32,
    /// Outputs a scan had already found, now linked to the imported entry that created them.
    pub linked: u32,
    /// Records of the old wallet left out: unreadable, of another seed, or outside the
    /// wallet's accounts.
    pub skipped: u32,
    /// Open imported entries the node found the kernel of, now confirmed.
    pub confirmed_by_kernel: u32,
    /// Entries of outputs found by a scan with no record in the old wallet, now dated by their
    /// block.
    pub dated: u32,
}

impl LegacyImportOutcome {
    const fn empty(status: LegacyImportStatus) -> Self {
        Self {
            status,
            transactions: 0,
            outputs: 0,
            accounts_named: 0,
            linked: 0,
            skipped: 0,
            confirmed_by_kernel: 0,
            dated: 0,
        }
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Imports the transaction history of the `epic-wallet` wallet in `source` (the wallet
    /// folder holding `wallet_data`, or `wallet_data` itself), read from a copy made in
    /// `work_dir`, an empty directory the caller owns and removes afterwards. Nothing in
    /// `source` is opened, locked or written.
    ///
    /// Run it after the wallet was created from the same seed, before or after the restore
    /// scan. Outputs the scan already found are linked to the imported entries, the entries of
    /// the others are dated by their block, and open imported entries whose kernel the node
    /// holds are confirmed. Running it again with the same history only repeats that.
    ///
    /// A history that cannot be imported is reported in the outcome's status, not as an error.
    /// Fails with [`WalletError::Locked`] or a store error.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn import_legacy_history(
        &self,
        source: &Path,
        work_dir: &Path,
    ) -> Result<LegacyImportOutcome, WalletError> {
        let session = self.session()?;
        let source = source.to_path_buf();
        let work_dir = work_dir.to_path_buf();
        let history = self
            .blocking(move |_, _| Ok(read_history(&source, &work_dir)))
            .await?;
        let history = match history {
            Ok(history) => history,
            Err(status) => {
                info!(status = ?status, "legacy history not imported");
                return Ok(LegacyImportOutcome::empty(status));
            }
        };
        let now = self.ports().clock.now();
        let mut outcome = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                let plan = plan_import(&session.keychain, &history);
                session
                    .store
                    .write(|repos| store_import(repos, &history, &plan, now))
            })
            .await?
        };
        if matches!(
            outcome.status,
            LegacyImportStatus::OtherWallet | LegacyImportStatus::OtherHistory
        ) {
            info!(status = ?outcome.status, "legacy history not imported");
            return Ok(outcome);
        }
        outcome.confirmed_by_kernel = self.confirm_by_kernel(&session).await?;
        outcome.dated = self.date_found_entries(&session).await?;
        info!(
            status = ?outcome.status,
            count = outcome.transactions,
            "legacy history imported"
        );
        Ok(outcome)
    }

    /// Confirms open imported entries whose kernel the node holds. A node error stops the
    /// lookups and leaves the remaining entries open: the import itself is already stored.
    async fn confirm_by_kernel(
        &self,
        session: &Arc<lifecycle::Session<S::Store>>,
    ) -> Result<u32, WalletError> {
        let pending = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| session.store.read(|repos| open_imported_kernels(repos)))
                .await?
        };
        let mut found = Vec::new();
        for (tx_id, excess) in pending {
            match self.ports().node.get_kernel(&excess, None, None).await {
                Ok(Some(located)) => found.push((tx_id, located.height)),
                Ok(None) => {}
                Err(error) => {
                    warn!(error = %error, "imported kernel lookup failed");
                    break;
                }
            }
        }
        if found.is_empty() {
            return Ok(0);
        }
        let now = self.ports().clock.now();
        let session = Arc::clone(session);
        self.blocking(move |_, _| {
            session.store.write(|repos| {
                let mut confirmed = 0_u32;
                for (tx_id, height) in found {
                    if confirm_imported(repos, tx_id, height, ChainCheck::OnChain, now)? {
                        confirmed = confirmed.saturating_add(1);
                    }
                }
                Ok(confirmed)
            })
        })
        .await
    }

    /// Dates the entries of outputs a scan found with no record, and those the old wallet's own
    /// restore made, by the time of their block.
    async fn date_found_entries(
        &self,
        session: &Arc<lifecycle::Session<S::Store>>,
    ) -> Result<u32, WalletError> {
        let undated = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| session.store.read(|repos| found_entries(repos)))
                .await?
        };
        let heights: BTreeSet<Height> = undated.iter().map(|(_, height)| *height).collect();
        let times = block_times(&self.ports().node, heights).await;
        if times.is_empty() {
            return Ok(0);
        }
        let session = Arc::clone(session);
        self.blocking(move |_, _| {
            session.store.write(|repos| {
                let mut dated = 0_u32;
                for (tx_id, height) in undated {
                    let Some(time) = times.get(&height) else {
                        continue;
                    };
                    let Some(mut entry) = repos.transaction(tx_id)? else {
                        continue;
                    };
                    if entry.created_at != *time {
                        entry.created_at = *time;
                        entry.updated_at = *time;
                        repos.update_transaction(tx_id, &entry)?;
                        dated = dated.saturating_add(1);
                    }
                }
                Ok(dated)
            })
        })
        .await
    }
}

fn read_history(source: &Path, work_dir: &Path) -> Result<LegacyHistory, LegacyImportStatus> {
    legacy::read_copy(source, work_dir, &LegacyLimits::default()).map_err(|error| {
        let status = match &error {
            LegacyDbError::NotFound => LegacyImportStatus::NoHistory,
            LegacyDbError::LmdbUnsupported => LegacyImportStatus::OldFormat,
            LegacyDbError::SourceChanging => LegacyImportStatus::SourceBusy,
            LegacyDbError::TooLarge { .. } | LegacyDbError::TooMany { .. } => {
                LegacyImportStatus::TooLarge
            }
            _ => LegacyImportStatus::Unreadable,
        };
        warn!(error = %error, "legacy history unreadable");
        status
    })
}

/// What the keychain decides before anything is written: which outputs the seed made.
struct ImportPlan {
    /// Outputs whose commitment the seed reproduces, by index into the history's outputs.
    ours: BTreeSet<usize>,
    /// Outputs with a commitment the seed does not reproduce.
    foreign: u32,
}

/// The most outputs checked against the seed. Outputs past it are not imported, unspent ones
/// first in line, so a scan can still link every output it finds in all but huge histories.
const MAX_CHECKED_OUTPUTS: usize = 200_000;

fn plan_import(keychain: &Keychain, history: &LegacyHistory) -> ImportPlan {
    let mut order: Vec<(usize, &LegacyOutput)> = history.outputs.iter().enumerate().collect();
    order.sort_by_key(|(_, output)| output_priority(output.status));
    let mut plan = ImportPlan {
        ours: BTreeSet::new(),
        foreign: 0,
    };
    for (index, output) in order.into_iter().take(MAX_CHECKED_OUTPUTS) {
        let Some(commitment) = output.commitment else {
            continue;
        };
        match made_by_seed(keychain, output, &commitment) {
            true => {
                plan.ours.insert(index);
            }
            false => plan.foreign = plan.foreign.saturating_add(1),
        }
    }
    plan
}

const fn output_priority(status: LegacyOutputStatus) -> u8 {
    match status {
        LegacyOutputStatus::Unspent | LegacyOutputStatus::Locked => 0,
        LegacyOutputStatus::Unconfirmed => 1,
        LegacyOutputStatus::Spent => 2,
        LegacyOutputStatus::Deleted => 3,
    }
}

/// Whether the seed commits to the output's value under its key as `epic-wallet` builds
/// outputs, with a regular switch commitment.
fn made_by_seed(keychain: &Keychain, output: &LegacyOutput, commitment: &CommitmentBytes) -> bool {
    let Ok(id) = Identifier::from_bytes(&output.key_id.0) else {
        return false;
    };
    keychain
        .commit(output.value.value(), &id, SwitchCommitment::Regular)
        .is_ok_and(|computed| computed.as_bytes() == commitment)
}

/// Writes the import in one store transaction, then links what a scan already found.
fn store_import(
    repos: &mut dyn Repositories,
    history: &LegacyHistory,
    plan: &ImportPlan,
    now: Timestamp,
) -> Result<LegacyImportOutcome, WalletError> {
    let fingerprint = hex(&history.source_fingerprint);
    let mut outcome = LegacyImportOutcome::empty(LegacyImportStatus::Imported);
    match repos.setting(IMPORTED_SETTING)? {
        Some(stored) if stored == fingerprint => {
            outcome.status = LegacyImportStatus::AlreadyImported;
        }
        Some(_) => return Ok(LegacyImportOutcome::empty(LegacyImportStatus::OtherHistory)),
        None => {
            if plan.foreign > 0 && plan.ours.is_empty() {
                return Ok(LegacyImportOutcome::empty(LegacyImportStatus::OtherWallet));
            }
            import_records(repos, history, plan, &mut outcome)?;
            repos.put_setting(IMPORTED_SETTING, &fingerprint)?;
        }
    }
    outcome.linked = link_found_outputs(repos, now)?;
    flag_missing_outputs(repos)?;
    Ok(outcome)
}

fn import_records(
    repos: &mut dyn Repositories,
    history: &LegacyHistory,
    plan: &ImportPlan,
    outcome: &mut LegacyImportOutcome,
) -> Result<(), WalletError> {
    let skipped = &history.skipped;
    outcome.skipped = skipped
        .transactions
        .saturating_add(skipped.outputs)
        .saturating_add(skipped.accounts)
        .saturating_add(skipped.counters)
        .saturating_add(plan.foreign);
    outcome.accounts_named = name_accounts(repos, history, &mut outcome.skipped)?;
    advance_children(repos, history, plan)?;

    let mut by_source: BTreeMap<(AccountIndex, u32), TxId> = BTreeMap::new();
    let heights = confirmation_heights(history, plan);
    for entry in &history.transactions {
        let Some(account) = account_of(&entry.parent_key_id) else {
            outcome.skipped = outcome.skipped.saturating_add(1);
            continue;
        };
        ensure_account(repos, account)?;
        match import_entry(repos, entry, account, heights.get(&(account, entry.id)))? {
            Some(tx_id) => {
                by_source.insert((account, entry.id), tx_id);
                outcome.transactions = outcome.transactions.saturating_add(1);
            }
            None => outcome.skipped = outcome.skipped.saturating_add(1),
        }
    }
    for index in &plan.ours {
        let Some(output) = history.outputs.get(*index) else {
            continue;
        };
        let (Some(commitment), Some(log_id), Some(account)) = (
            output.commitment,
            output.tx_log_entry,
            account_of(&output.root_key_id),
        ) else {
            continue;
        };
        let Some(tx) = by_source.get(&(account, log_id)) else {
            continue;
        };
        repos.put_imported_output(&ImportedOutput {
            commitment,
            tx: *tx,
            status: imported_output_status(output.status),
            height: output.height,
            amount: output.value,
        })?;
        outcome.outputs = outcome.outputs.saturating_add(1);
    }
    Ok(())
}

/// The height each log entry's outputs were confirmed at, from the outputs the seed made.
fn confirmation_heights(
    history: &LegacyHistory,
    plan: &ImportPlan,
) -> BTreeMap<(AccountIndex, u32), Height> {
    let mut heights = BTreeMap::new();
    for index in &plan.ours {
        let Some(output) = history.outputs.get(*index) else {
            continue;
        };
        if matches!(
            output.status,
            LegacyOutputStatus::Unconfirmed | LegacyOutputStatus::Deleted
        ) {
            continue;
        }
        let (Some(log_id), Some(account)) = (output.tx_log_entry, account_of(&output.root_key_id))
        else {
            continue;
        };
        let height = heights.entry((account, log_id)).or_insert(output.height);
        *height = (*height).max(output.height);
    }
    heights
}

/// Stores one log entry and its record. `None` when the store refuses its values.
fn import_entry(
    repos: &mut dyn Repositories,
    source: &LegacyTxLogEntry,
    account: AccountIndex,
    confirmed_height: Option<&Height>,
) -> Result<Option<TxId>, WalletError> {
    let (direction, kind) = direction_and_kind(source.kind);
    let state = state_of(source);
    // An open entry keeps no transport: the engine looks up open entries by transport, and
    // this wallet cannot continue one the old wallet started.
    let transport = is_final(state)
        .then(|| counterparty(source).and_then(transport_of))
        .flatten();
    let mut entry = TransactionEntry {
        account,
        direction,
        state,
        slate_id: source.slate_id,
        transport: transport.map(str::to_owned),
        amount_credited: source.amount_credited,
        amount_debited: source.amount_debited,
        fee: source.fee,
        created_at: source.created_at,
        updated_at: source.confirmed_at.unwrap_or(source.created_at),
    };
    let tx_id = match repos.insert_transaction(&entry) {
        Ok(tx_id) => tx_id,
        // Two entries of one direction with the same slate: the second keeps its slate id in
        // its record only.
        Err(StoreError::Duplicate { .. }) => {
            entry.slate_id = None;
            repos.insert_transaction(&entry)?
        }
        Err(StoreError::OutOfRange { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if let Some(height) = confirmed_height.filter(|_| entry.state == TxState::Confirmed) {
        repos.set_confirmed_height(tx_id, *height)?;
    }
    if let Some(address) = counterparty(source).filter(|address| !is_file_path(address)) {
        repos.set_counterparty(tx_id, address)?;
    }
    let record = ImportedTransaction {
        source_id: source.id,
        kind,
        slate_id: source.slate_id,
        // The old wallet's own restore saw the output only when it scanned; its block dates it.
        confirmed_at: source.confirmed_at.filter(|_| !restored_by_source(source)),
        input_count: source.num_inputs,
        output_count: source.num_outputs,
        kernel_excess: source.kernel_excess,
        ttl_cutoff_height: source.ttl_cutoff_height,
        messages: verified_messages(&source.messages),
        check: ChainCheck::Unchecked,
    };
    match repos.put_imported_transaction(tx_id, &record) {
        Ok(()) => {}
        Err(StoreError::OutOfRange { .. }) => {
            repos.put_imported_transaction(
                tx_id,
                &ImportedTransaction {
                    confirmed_at: None,
                    ..record
                },
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    debug!(tx_id = %tx_id, "transaction imported");
    Ok(Some(tx_id))
}

const fn direction_and_kind(kind: LegacyTxKind) -> (TxDirection, ImportedKind) {
    match kind {
        LegacyTxKind::ConfirmedCoinbase => (TxDirection::Incoming, ImportedKind::Coinbase),
        LegacyTxKind::TxReceived => (TxDirection::Incoming, ImportedKind::Received),
        LegacyTxKind::TxReceivedCancelled => {
            (TxDirection::Incoming, ImportedKind::ReceivedCancelled)
        }
        LegacyTxKind::TxReceivedMempool => (TxDirection::Incoming, ImportedKind::ReceivedMempool),
        LegacyTxKind::TxSent => (TxDirection::Outgoing, ImportedKind::Sent),
        LegacyTxKind::TxSentCancelled => (TxDirection::Outgoing, ImportedKind::SentCancelled),
        LegacyTxKind::TxSentMempool => (TxDirection::Outgoing, ImportedKind::SentMempool),
        LegacyTxKind::TxSentCreated => (TxDirection::Outgoing, ImportedKind::SentCreated),
    }
}

/// The state an entry takes, as `epic-wallet` would show it. An open entry stays open: this
/// wallet cannot complete it, since its private keys stay in the old wallet, but a scan or the
/// node may still show it confirmed.
fn state_of(source: &LegacyTxLogEntry) -> TxState {
    match source.kind {
        LegacyTxKind::TxReceivedCancelled | LegacyTxKind::TxSentCancelled => TxState::Cancelled,
        _ if source.confirmed => TxState::Confirmed,
        LegacyTxKind::ConfirmedCoinbase
        | LegacyTxKind::TxReceived
        | LegacyTxKind::TxReceivedMempool => TxState::Received,
        LegacyTxKind::TxSent | LegacyTxKind::TxSentMempool if source.kernel_excess.is_some() => {
            TxState::Posted
        }
        LegacyTxKind::TxSent | LegacyTxKind::TxSentMempool | LegacyTxKind::TxSentCreated => {
            TxState::Sent
        }
    }
}

/// An entry the old wallet's own restore made: a receipt with no slate.
fn restored_by_source(source: &LegacyTxLogEntry) -> bool {
    source.kind == LegacyTxKind::TxReceived && source.slate_id.is_none()
}

/// The transport an old wallet's counterparty address implies, as the GUI tells them apart.
fn transport_of(address: &str) -> Option<&'static str> {
    let lower = address.to_ascii_lowercase();
    if is_file_path(address) {
        Some("file")
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        if lower.contains(".onion") {
            Some("tor")
        } else {
            Some("http")
        }
    } else if address.contains('@') {
        Some("epicbox")
    } else {
        None
    }
}

/// `epic-wallet` records the file path as the counterparty of a file exchange.
fn is_file_path(address: &str) -> bool {
    address.starts_with('/')
        || address.starts_with('\\')
        || matches!(address.as_bytes().get(1..3), Some(b":\\" | b":/"))
}

fn counterparty(source: &LegacyTxLogEntry) -> Option<&str> {
    let address = source.public_addr.as_deref()?.trim();
    (!address.is_empty()
        && address != RESTORE_COUNTERPARTY
        && address.len() <= MAX_COUNTERPARTY_LEN
        && !address.chars().any(char::is_control))
    .then_some(address)
}

/// The messages whose signature verifies under their party's key, as the slate path keeps
/// only verified messages. Text is made safe to display and cut to the stored bound.
fn verified_messages(messages: &[LegacyMessage]) -> Vec<ImportedMessage> {
    let mut kept: Vec<ImportedMessage> = messages
        .iter()
        .filter_map(|message| {
            let participant = u8::try_from(message.participant).ok().filter(|p| *p <= 1)?;
            let text = message.text.as_deref()?;
            let signature = Signature::from_compact(&message.signature?).ok()?;
            let signer = PublicKey::from_bytes(&message.public_key).ok()?;
            verify_signed_text(text, &signature, &signer).ok()?;
            Some(ImportedMessage {
                participant,
                text: truncate(&display_message(text), MAX_IMPORTED_MESSAGE_BYTES),
            })
        })
        .collect();
    kept.sort_by_key(|message| message.participant);
    kept.dedup_by_key(|message| message.participant);
    kept
}

fn truncate(text: &str, max_bytes: usize) -> String {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default().to_owned()
}

const fn imported_output_status(status: LegacyOutputStatus) -> ImportedOutputStatus {
    match status {
        LegacyOutputStatus::Unconfirmed => ImportedOutputStatus::Unconfirmed,
        LegacyOutputStatus::Unspent => ImportedOutputStatus::Unspent,
        LegacyOutputStatus::Locked => ImportedOutputStatus::Locked,
        LegacyOutputStatus::Spent => ImportedOutputStatus::Spent,
        LegacyOutputStatus::Deleted => ImportedOutputStatus::Deleted,
    }
}

/// The account of a parent path `m/<a>/0`, the only kind `epic-wallet` makes.
fn account_of(parent: &KeyId) -> Option<AccountIndex> {
    let id = Identifier::from_bytes(&parent.0).ok()?;
    match (id.depth(), id.components()) {
        (2, [account, 0, 0, 0]) => Some(AccountIndex(account)),
        _ => None,
    }
}

/// The account and child number of an output key `m/<a>/0/<c>`.
fn child_of(key: &KeyId) -> Option<(AccountIndex, u32)> {
    let id = Identifier::from_bytes(&key.0).ok()?;
    match (id.depth(), id.components()) {
        (3, [account, 0, child, 0]) if child < FIRST_HARDENED => {
            Some((AccountIndex(account), child))
        }
        _ => None,
    }
}

fn ensure_account(repos: &mut dyn Repositories, index: AccountIndex) -> Result<(), WalletError> {
    if repos.account(index)?.is_some() {
        return Ok(());
    }
    let label = free_label(repos, &format!("account_{}", index.0))?;
    repos.put_account(&AccountRecord {
        index,
        label,
        next_child: 0,
    })?;
    Ok(())
}

/// Gives each account the old wallet's label, unless this wallet's user already named it.
fn name_accounts(
    repos: &mut dyn Repositories,
    history: &LegacyHistory,
    skipped: &mut u32,
) -> Result<u32, WalletError> {
    let mut named = 0_u32;
    for source in &history.accounts {
        let (Some(index), Ok(label)) = (account_of(&source.path), AccountLabel::new(&source.label))
        else {
            *skipped = skipped.saturating_add(1);
            continue;
        };
        let label = label.as_str();
        match repos.account(index)? {
            Some(record) if record.label == label => {}
            Some(mut record) if is_generated_label(&record.label, index) => {
                if repos.account_by_label(label)?.is_none() {
                    record.label = label.to_owned();
                    repos.put_account(&record)?;
                    named = named.saturating_add(1);
                }
            }
            Some(_) => {}
            None => {
                let label = free_label(repos, label)?;
                repos.put_account(&AccountRecord {
                    index,
                    label,
                    next_child: 0,
                })?;
                named = named.saturating_add(1);
            }
        }
    }
    Ok(named)
}

/// A label this wallet made itself: the default account's, or one a scan gave an account.
fn is_generated_label(label: &str, index: AccountIndex) -> bool {
    (index == AccountIndex(0) && label == crate::account::DEFAULT_ACCOUNT_LABEL)
        || label
            .strip_prefix("account_")
            .is_some_and(|rest| rest.parse::<u32>().is_ok())
}

fn free_label(repos: &dyn Repositories, wanted: &str) -> Result<String, WalletError> {
    if repos.account_by_label(wanted)?.is_none() {
        return Ok(wanted.to_owned());
    }
    for number in 2_u32..1_000 {
        let label = format!("{wanted} ({number})");
        if AccountLabel::new(&label).is_ok() && repos.account_by_label(&label)?.is_none() {
            return Ok(label);
        }
    }
    Err(StoreError::LabelTaken.into())
}

/// Moves each account's key counter past every key the old wallet used, spent ones included,
/// so this wallet never hands out a key the old one already put on chain.
fn advance_children(
    repos: &mut dyn Repositories,
    history: &LegacyHistory,
    plan: &ImportPlan,
) -> Result<(), WalletError> {
    let mut next: BTreeMap<AccountIndex, u32> = BTreeMap::new();
    for counter in &history.next_child {
        if let Some(account) = account_of(&counter.parent) {
            let value = next.entry(account).or_insert(0);
            *value = (*value).max(counter.next_child.min(FIRST_HARDENED));
        }
    }
    for index in &plan.ours {
        let Some((account, child)) = history
            .outputs
            .get(*index)
            .and_then(|output| child_of(&output.key_id))
        else {
            continue;
        };
        let value = next.entry(account).or_insert(0);
        *value = (*value).max(child.saturating_add(1));
    }
    for (account, child) in next {
        ensure_account(repos, account)?;
        if let Some(mut record) = repos.account(account)?
            && child > record.next_child
        {
            record.next_child = child;
            repos.put_account(&record)?;
        }
    }
    Ok(())
}

/// Moves outputs a scan stored with an entry of their own to the imported entry that created
/// them, and drops the entries left empty.
fn link_found_outputs(repos: &mut dyn Repositories, now: Timestamp) -> Result<u32, StoreError> {
    let mut linked = 0_u32;
    for account in repos.accounts()? {
        for mut output in repos.outputs(account.index, None)? {
            let Some(found_tx) = output.tx else {
                continue;
            };
            let Some(entry) = repos.transaction(found_tx)? else {
                continue;
            };
            if !is_found_entry(repos, found_tx, &entry)? {
                continue;
            }
            let commitment = *output.commitment();
            let Some(target) =
                link_found_output(repos, &commitment, output.account, output.height, now)?
            else {
                continue;
            };
            output.tx = Some(target);
            repos.put_output(&output)?;
            if repos.outputs_of_transaction(found_tx)?.is_empty() {
                repos.delete_transaction(found_tx)?;
            }
            linked = linked.saturating_add(1);
        }
    }
    Ok(linked)
}

fn open_imported_kernels(repos: &dyn Repositories) -> Result<Vec<(TxId, Commitment)>, WalletError> {
    let mut open = Vec::new();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            if is_final(stored.entry.state) {
                continue;
            }
            let Some(excess) = repos
                .imported_transaction(stored.id)?
                .and_then(|record| record.kernel_excess)
            else {
                continue;
            };
            if let Ok(excess) = Commitment::from_bytes(&excess) {
                open.push((stored.id, excess));
            }
            if open.len() >= MAX_KERNEL_LOOKUPS {
                return Ok(open);
            }
        }
    }
    Ok(open)
}

/// The entries a scan stored for outputs with no record, and those the old wallet's own restore
/// made, with their confirming height.
fn found_entries(repos: &dyn Repositories) -> Result<Vec<(TxId, Height)>, WalletError> {
    let mut found = Vec::new();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            let restored_by_source = stored.entry.slate_id.is_none()
                && repos
                    .imported_transaction(stored.id)?
                    .is_some_and(|record| {
                        record.kind == ImportedKind::Received && record.slate_id.is_none()
                    });
            if !restored_by_source && !is_found_entry(repos, stored.id, &stored.entry)? {
                continue;
            }
            if let Some(height) = repos.confirmed_height(stored.id)? {
                found.push((stored.id, height));
            }
        }
    }
    Ok(found)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A work directory for one import inside `data_dir`, removed when dropped.
pub struct ImportWorkDir {
    path: PathBuf,
}

impl ImportWorkDir {
    /// Creates `<data_dir>/legacy-import-<suffix>`, which must not exist yet.
    pub fn create(data_dir: &Path, suffix: &str) -> std::io::Result<Self> {
        let path = data_dir.join(format!("legacy-import-{suffix}"));
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ImportWorkDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            warn!(error = %error, "legacy import copy not removed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(depth: u8, components: [u32; 4]) -> KeyId {
        KeyId(Identifier::new(depth, components).unwrap().to_bytes())
    }

    #[test]
    fn accounts_come_from_parent_paths_of_depth_two_only() {
        assert_eq!(account_of(&key(2, [0, 0, 0, 0])), Some(AccountIndex(0)));
        assert_eq!(account_of(&key(2, [3, 0, 0, 0])), Some(AccountIndex(3)));
        assert_eq!(account_of(&key(2, [3, 1, 0, 0])), None);
        assert_eq!(account_of(&key(3, [0, 0, 1, 0])), None);
    }

    #[test]
    fn output_children_skip_hardened_and_foreign_paths() {
        assert_eq!(child_of(&key(3, [1, 0, 7, 0])), Some((AccountIndex(1), 7)));
        assert_eq!(child_of(&key(3, [1, 0, FIRST_HARDENED, 0])), None);
        assert_eq!(child_of(&key(2, [1, 0, 0, 0])), None);
    }

    #[test]
    fn generated_labels_are_told_apart_from_chosen_ones() {
        assert!(is_generated_label("default", AccountIndex(0)));
        assert!(!is_generated_label("default", AccountIndex(1)));
        assert!(is_generated_label("account_2", AccountIndex(2)));
        assert!(!is_generated_label("savings", AccountIndex(2)));
        assert!(!is_generated_label("account_x", AccountIndex(2)));
    }

    #[test]
    fn counterparty_addresses_imply_their_transport() {
        assert_eq!(transport_of("esAbc@epicbox.epiccash.com"), Some("epicbox"));
        assert_eq!(transport_of("https://wallet.example:3415"), Some("http"));
        assert_eq!(transport_of("http://abc.onion"), Some("tor"));
        assert_eq!(transport_of("C:\\Users\\a\\send.tx"), Some("file"));
        assert_eq!(transport_of("/home/a/send.tx"), Some("file"));
        assert_eq!(transport_of("esAbc"), None);
        assert!(!is_file_path("esAbc@epicbox.epiccash.com"));
    }

    #[test]
    fn truncation_keeps_whole_characters() {
        assert_eq!(truncate("héllo", 2), "h");
        assert_eq!(truncate("héllo", 3), "hé");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
