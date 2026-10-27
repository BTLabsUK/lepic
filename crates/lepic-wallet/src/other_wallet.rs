//! What another wallet on the same recovery phrase did, as the chain shows it.
//!
//! Spent: a refresh that finds outputs this wallet held unspent gone from the chain, with no
//! transaction of its own spending them, records them as one outgoing entry per account and
//! refresh, "sent from another wallet": its debit is their value, its fee is unknown, and a
//! scan over the blocks where the spend can lie credits it with the outputs it finds there,
//! taken to be the spend's change.
//!
//! Received: an update scan, which covers recent blocks only, stores an output it finds with no
//! record here as an incoming entry of its own, "received by another wallet"; a restore and a
//! scan from genesis keep storing such outputs as found by the scan.
//!
//! The chain does not say who received or what the fee was, so the change is a guess: an
//! output the other wallet received in the blocks of an open spend counts as its change, not
//! as a receive. A spend or receive the chain has not mined is not seen at all.

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_store::{
    AccountIndex, OutputRecord, OutputStatus, Repositories, StoreError, TransactionEntry,
    TxDirection, TxId, TxState,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::state::StateChange;

const PREFIX: &str = "tx.other_wallet.";
/// A send the node refused because another wallet spent its inputs.
const LOST_PREFIX: &str = "tx.inputs_spent_elsewhere.";
/// The entries whose change a scan may still find.
const OPEN_KEY: &str = "tx.other_wallet.open";

/// What an entry of another wallet's spend records besides the log entry.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Spend {
    /// The outputs it spent, as hex commitments.
    spent: Vec<String>,
    /// The outputs a scan took for its change.
    change: Vec<String>,
    /// The spend lies above this height and at or below `to`.
    after: u64,
    to: u64,
}

fn key(tx_id: TxId) -> String {
    format!("{PREFIX}{tx_id}")
}

/// Drops every record this module keeps for the entry `tx_id`, for an entry that is deleted:
/// the store hands its id to the next transaction, which must not inherit them.
pub(crate) fn forget(repos: &mut dyn Repositories, tx_id: TxId) -> Result<(), StoreError> {
    repos.delete_setting(&key(tx_id))?;
    repos.delete_setting(&lost_key(tx_id))?;
    let open = open_entries(repos)?;
    if open.contains(&tx_id.0) {
        let rest: Vec<u32> = open.into_iter().filter(|id| *id != tx_id.0).collect();
        write_open(repos, &rest)?;
    }
    Ok(())
}

fn corrupt(field: &'static str) -> StoreError {
    StoreError::Corrupt {
        record: lepic_store::Record::Transaction,
        field,
    }
}

fn read(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<Spend>, StoreError> {
    Ok(repos
        .setting(&key(tx_id))?
        .and_then(|text| serde_json::from_str(&text).ok()))
}

fn write(repos: &mut dyn Repositories, tx_id: TxId, spend: &Spend) -> Result<(), StoreError> {
    let text = serde_json::to_string(spend).map_err(|_| corrupt("other wallet spend"))?;
    repos.put_setting(&key(tx_id), &text)
}

fn open_entries(repos: &dyn Repositories) -> Result<Vec<u32>, StoreError> {
    Ok(repos
        .setting(OPEN_KEY)?
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default())
}

fn write_open(repos: &mut dyn Repositories, open: &[u32]) -> Result<(), StoreError> {
    let text = serde_json::to_string(open).map_err(|_| corrupt("other wallet spends"))?;
    repos.put_setting(OPEN_KEY, &text)
}

/// Whether the entry records another wallet's spend.
pub(crate) fn is_entry(repos: &dyn Repositories, tx_id: TxId) -> Result<bool, StoreError> {
    Ok(repos.setting(&key(tx_id))?.is_some())
}

/// The outputs of ours the entry of another wallet's spend spent, `None` for any other entry.
pub(crate) fn spent_by(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<Vec<Commitment>>, StoreError> {
    Ok(read(repos, tx_id)?.map(|spend| {
        spend
            .spent
            .iter()
            .filter_map(|hex| Commitment::from_hex(hex).ok())
            .collect()
    }))
}

/// Whether `stored`, which a refresh is about to mark spent, was spent by another wallet: it was
/// unspent here, not an immature coinbase output, which nobody can spend and which leaves the
/// chain only when its block does, and not an input of a send that ended here, which may still
/// be mined and which the release watch looks for.
pub(crate) fn spent_elsewhere(
    repos: &dyn Repositories,
    stored: &OutputRecord,
    tip: Height,
    coinbase_maturity: u64,
) -> Result<bool, StoreError> {
    if stored.status != OutputStatus::Unspent {
        return Ok(false);
    }
    if stored.id.features == OutputFeatures::Coinbase
        && tip.value() < stored.height.value().saturating_add(coinbase_maturity)
    {
        return Ok(false);
    }
    if let Some(tx_id) = stored.tx
        && let Some(entry) = repos.transaction(tx_id)?
        && matches!(entry.state, TxState::Cancelled | TxState::Expired)
        && repos.setting(&lost_key(tx_id))?.is_none()
    {
        return Ok(false);
    }
    Ok(true)
}

fn lost_key(tx_id: TxId) -> String {
    format!("{LOST_PREFIX}{tx_id}")
}

/// Marks `tx_id`, a send the node refused because another wallet spent its inputs, so the
/// inputs its cancel released count as that wallet's spend: the send itself can never be mined.
pub(crate) fn mark_inputs_lost(
    repos: &mut dyn Repositories,
    tx_id: TxId,
) -> Result<(), StoreError> {
    repos.put_setting(&lost_key(tx_id), "1")
}

/// Records `spent`, outputs another wallet spent above `after` and at or below `tip`, as one
/// confirmed outgoing entry per account, open for a scan to credit its change. Returns the
/// entries made.
pub(crate) fn record(
    repos: &mut dyn Repositories,
    spent: &[OutputRecord],
    after: Height,
    tip: Height,
    now: Timestamp,
) -> Result<Vec<StateChange>, StoreError> {
    let mut accounts: Vec<AccountIndex> = spent.iter().map(|output| output.account).collect();
    accounts.sort_unstable();
    accounts.dedup();
    let mut open = open_entries(repos)?;
    let mut changes = Vec::new();
    for account in accounts {
        let outputs: Vec<&OutputRecord> = spent
            .iter()
            .filter(|output| output.account == account)
            .collect();
        let debited = outputs
            .iter()
            .try_fold(Amount::ZERO, |sum, output| sum.checked_add(output.amount))
            .map_err(|_| corrupt("other wallet spend amount"))?;
        let tx_id = repos.insert_transaction(&TransactionEntry {
            account,
            direction: TxDirection::Outgoing,
            state: TxState::Confirmed,
            slate_id: None,
            transport: None,
            amount_credited: Amount::ZERO,
            amount_debited: debited,
            fee: None,
            created_at: now,
            updated_at: now,
        })?;
        repos.set_confirmed_height(tx_id, tip)?;
        write(
            repos,
            tx_id,
            &Spend {
                spent: outputs
                    .iter()
                    .map(|output| output.id.commitment.to_hex())
                    .collect(),
                change: Vec::new(),
                after: after.value(),
                to: tip.value(),
            },
        )?;
        open.push(tx_id.0);
        info!(tx_id = %tx_id, count = outputs.len(), "spend by another wallet recorded");
        changes.push(StateChange {
            tx_id,
            from: TxState::Confirmed,
            to: TxState::Confirmed,
        });
    }
    write_open(repos, &open)?;
    Ok(changes)
}

/// Marks `tx_id`, the entry an update scan stored for an output it found with no record here,
/// as received by another wallet in the block at `height`.
pub(crate) fn mark_received(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Height,
) -> Result<(), StoreError> {
    write(
        repos,
        tx_id,
        &Spend {
            after: height.value().saturating_sub(1),
            to: height.value(),
            ..Spend::default()
        },
    )
}

/// The window, above `after` and at or below `to`, that the open entries' change lies in: the
/// scan that finds it starts above the lowest `after`. `None` when no entry is open.
pub(crate) fn change_window(repos: &dyn Repositories) -> Result<Option<Height>, StoreError> {
    let mut lowest: Option<u64> = None;
    for id in open_entries(repos)? {
        if let Some(spend) = read(repos, TxId(id))? {
            lowest = Some(lowest.map_or(spend.after, |low| low.min(spend.after)));
        }
    }
    Ok(lowest.map(Height::new))
}

/// The open entry of another wallet's spend in `account` whose blocks hold `height`, which a
/// scan found an output of this wallet at: that output is taken for its change and credited to
/// it. The oldest such entry wins.
pub(crate) fn take_change(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    commitment: &Commitment,
    amount: Amount,
    height: Height,
) -> Result<Option<TxId>, StoreError> {
    for id in open_entries(repos)? {
        let tx_id = TxId(id);
        let (Some(mut spend), Some(mut entry)) = (read(repos, tx_id)?, repos.transaction(tx_id)?)
        else {
            continue;
        };
        if entry.account != account || height.value() <= spend.after || height.value() > spend.to {
            continue;
        }
        entry.amount_credited = entry
            .amount_credited
            .checked_add(amount)
            .map_err(|_| corrupt("other wallet change amount"))?;
        repos.update_transaction(tx_id, &entry)?;
        spend.change.push(commitment.to_hex());
        write(repos, tx_id, &spend)?;
        debug!(tx_id = %tx_id, height = %height, "change of another wallet's spend found");
        return Ok(Some(tx_id));
    }
    Ok(None)
}

/// Closes the open entries whose blocks a completed scan from `start` to `end` covered: their
/// change is found or never will be.
pub(crate) fn close_scanned(
    repos: &mut dyn Repositories,
    start: Height,
    end: Height,
) -> Result<(), StoreError> {
    let open = open_entries(repos)?;
    let mut still = Vec::with_capacity(open.len());
    for id in open {
        let covered = read(repos, TxId(id))?.is_none_or(|spend| {
            start.value() <= spend.after.saturating_add(1) && spend.to <= end.value()
        });
        if !covered {
            still.push(id);
        }
    }
    write_open(repos, &still)
}

/// An output a scan found on chain again after a refresh took it for another wallet's spend,
/// as when a reorganisation undid the block: it leaves the entry, whose debit drops by its
/// value. An entry left with no spent output is deleted.
pub(crate) fn revived(
    repos: &mut dyn Repositories,
    output: &OutputRecord,
) -> Result<(), StoreError> {
    let hex = output.id.commitment.to_hex();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            let Some(mut spend) = read(repos, stored.id)? else {
                continue;
            };
            if !spend.spent.contains(&hex) {
                continue;
            }
            spend.spent.retain(|spent| *spent != hex);
            if spend.spent.is_empty() {
                forget(repos, stored.id)?;
                repos.delete_transaction(stored.id)?;
                info!(tx_id = %stored.id, "spend by another wallet undone");
            } else {
                let mut entry = stored.entry;
                entry.amount_debited = entry
                    .amount_debited
                    .checked_sub(output.amount)
                    .unwrap_or(Amount::ZERO);
                repos.update_transaction(stored.id, &entry)?;
                write(repos, stored.id, &spend)?;
            }
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_store::{CONTEXT_KEY_LEN, ContextKey, MemoryStore, WalletStore};

    use super::*;

    #[test]
    fn a_deleted_entry_leaves_nothing_for_the_next_transaction_with_its_id() {
        let store = MemoryStore::new(ContextKey::from_bytes([1; CONTEXT_KEY_LEN]));
        let id = TxId(7);
        store
            .write(|repos| {
                mark_received(repos, id, Height::new(345))?;
                write_open(repos, &[3, id.0])?;
                repos.put_setting(&lost_key(id), "1")?;
                forget(repos, id)
            })
            .unwrap();
        store
            .read(|repos| {
                assert!(!is_entry(repos, id)?);
                assert_eq!(repos.setting(&lost_key(id))?, None);
                assert_eq!(open_entries(repos)?, vec![3]);
                Ok::<_, StoreError>(())
            })
            .unwrap();
    }
}
