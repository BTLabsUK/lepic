// SPDX-License-Identifier: Apache-2.0
//! Import of an `epic-wallet` wallet's transaction history (ADR 0019), and what the scan and
//! the transaction list need of imported entries.
//!
//! The old wallet's database is read from a private copy and never opened in place. Its log
//! entries become ordinary log entries with a record of what only the old wallet knew; its
//! outputs are remembered by commitment, never stored as outputs. Balances and spendable funds
//! still come from the chain scan alone: a scan that finds an output the old wallet recorded
//! links it to the imported entry that created it, instead of storing a new entry for it.

#[cfg(feature = "sqlite")]
mod import;

use std::collections::{BTreeMap, BTreeSet};

use futures_util::{StreamExt as _, stream};
use jiff::Timestamp;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_store::{
    AccountIndex, ChainCheck, CommitmentBytes, ImportedOutputStatus, Repositories, StoreError,
    TransactionEntry, TxDirection, TxId, TxState,
};
use tracing::debug;

use crate::lifecycle;

#[cfg(feature = "sqlite")]
pub use import::{ImportWorkDir, LegacyImportOutcome, LegacyImportStatus};

/// Block headers asked for at once when dating outputs a scan found.
const HEADER_CONCURRENCY: usize = 8;

/// Where an entry of the log came from, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxOrigin {
    /// Made by this wallet.
    Wallet,
    /// Imported from the old wallet's history.
    Imported,
    /// An output a scan found that no record explains.
    FoundByScan,
    /// Outputs of this wallet that another wallet on the same recovery phrase spent: a refresh
    /// found them spent with no transaction here.
    OtherWallet,
}

/// The time of the block at each height the node answers for. A failed or missing header
/// leaves its height out: a date is shown, never relied on.
pub(crate) async fn block_times<N: NodeApi>(
    node: &N,
    heights: BTreeSet<Height>,
) -> BTreeMap<Height, Timestamp> {
    let answers: Vec<(Height, Option<Timestamp>)> = stream::iter(heights)
        .map(|height| async move {
            match node.get_header(height).await {
                Ok(header) => (height, header.map(|header| header.timestamp)),
                Err(error) => {
                    debug!(height = %height, error = %error, "block header unavailable");
                    (height, None)
                }
            }
        })
        .buffer_unordered(HEADER_CONCURRENCY)
        .collect()
        .await;
    answers
        .into_iter()
        .filter_map(|(height, time)| time.map(|time| (height, time)))
        .collect()
}

/// Links an output a scan found to the imported entry that created it, confirming the entry.
/// Returns that entry, or `None` when no imported entry of the output's account made it.
pub(crate) fn link_found_output(
    repos: &mut dyn Repositories,
    commitment: &CommitmentBytes,
    account: AccountIndex,
    height: Height,
    now: Timestamp,
) -> Result<Option<TxId>, StoreError> {
    let Some(imported) = repos.imported_output(commitment)? else {
        return Ok(None);
    };
    let Some(entry) = repos.transaction(imported.tx)? else {
        return Ok(None);
    };
    if entry.account != account {
        return Ok(None);
    }
    let check = match entry.state {
        TxState::Cancelled | TxState::Expired => ChainCheck::CancelledButOnChain,
        _ => ChainCheck::OnChain,
    };
    confirm_imported(repos, imported.tx, height, check, now)?;
    Ok(Some(imported.tx))
}

/// Confirms an imported entry the chain shows, keeping the earliest confirming height and a
/// contradiction once recorded. Returns whether its state changed.
pub(crate) fn confirm_imported(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Height,
    check: ChainCheck,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let Some(mut entry) = repos.transaction(tx_id)? else {
        return Ok(false);
    };
    let Some(record) = repos.imported_transaction(tx_id)? else {
        return Ok(false);
    };
    let changed = entry.state != TxState::Confirmed;
    if changed {
        entry.state = TxState::Confirmed;
        entry.updated_at = record.confirmed_at.unwrap_or(now);
        repos.update_transaction(tx_id, &entry)?;
    }
    if repos
        .confirmed_height(tx_id)?
        .is_none_or(|stored| height < stored)
    {
        repos.set_confirmed_height(tx_id, height)?;
    }
    if record.check != ChainCheck::CancelledButOnChain && record.check != check {
        repos.set_chain_check(tx_id, check)?;
    }
    Ok(changed)
}

/// Whether `tx_id` is an entry a scan stored for an output it found with no record.
pub(crate) fn is_found_entry(
    repos: &dyn Repositories,
    tx_id: TxId,
    entry: &TransactionEntry,
) -> Result<bool, StoreError> {
    Ok(entry.direction == TxDirection::Incoming
        && entry.slate_id.is_none()
        && entry.transport.is_none()
        && repos.imported_transaction(tx_id)?.is_none())
}

/// Where an entry came from.
pub(crate) fn origin(
    repos: &dyn Repositories,
    tx_id: TxId,
    entry: &TransactionEntry,
) -> Result<TxOrigin, StoreError> {
    if repos.imported_transaction(tx_id)?.is_some() {
        Ok(TxOrigin::Imported)
    } else if crate::other_wallet::is_entry(repos, tx_id)? {
        Ok(TxOrigin::OtherWallet)
    } else if is_found_entry(repos, tx_id, entry)? {
        Ok(TxOrigin::FoundByScan)
    } else {
        Ok(TxOrigin::Wallet)
    }
}

/// After a full scan, marks the imported entries whose output the old wallet held unspent
/// but no scan found.
pub(crate) fn flag_missing_outputs(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    if lifecycle::restore_scan_pending(repos)? || !crate::scan::has_scanned(repos)? {
        return Ok(());
    }
    for output in repos.imported_outputs(ImportedOutputStatus::Unspent)? {
        if repos.output(&output.commitment)?.is_some() {
            continue;
        }
        if let Some(record) = repos.imported_transaction(output.tx)?
            && matches!(record.check, ChainCheck::Unchecked | ChainCheck::OnChain)
        {
            repos.set_chain_check(output.tx, ChainCheck::UnspentNotOnChain)?;
        }
    }
    Ok(())
}
