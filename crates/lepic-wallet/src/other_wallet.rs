// SPDX-License-Identifier: Apache-2.0
//! What another wallet on the same recovery phrase did, as the chain shows it.
//!
//! Spent: a refresh that finds outputs this wallet held unspent gone from the chain, with no
//! transaction of its own spending them, records them as one outgoing entry per account and
//! refresh, "sent from another wallet": its debit is their value, its fee is unknown, and a
//! scan over the blocks where the spend can lie credits it with the outputs it finds there,
//! taken to be the spend's change. Until that scan completes the entry is unverified: only the
//! node's answers back it.
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
    AccountIndex, OtherWalletSpend, OutputRecord, OutputStatus, Repositories, StoreError,
    TransactionEntry, TxDirection, TxId, TxState,
};
use tracing::{debug, info};

use crate::state::StateChange;

/// Blocks after a refresh took outputs for another wallet's spend during which a refresh still
/// asks the node for them, so a node that left them out of two answers cannot make them
/// disappear until a scan from genesis.
const REVIVE_WINDOW: u64 = 1_440;

fn corrupt(field: &'static str) -> StoreError {
    StoreError::Corrupt {
        record: lepic_store::Record::Transaction,
        field,
    }
}

/// The entries a scan may still credit change to, oldest first.
fn open_entries(repos: &dyn Repositories) -> Result<Vec<(TxId, OtherWalletSpend)>, StoreError> {
    let mut spends = repos.other_wallet_spends()?;
    spends.retain(|(_, spend)| spend.open);
    Ok(spends)
}

/// Whether the entry is another wallet's spend that no completed scan has covered yet, so only
/// the node's answers back it.
pub(crate) fn is_unverified(repos: &dyn Repositories, tx_id: TxId) -> Result<bool, StoreError> {
    Ok(repos
        .other_wallet_spend(tx_id)?
        .is_some_and(|spend| spend.open))
}

/// Whether the entry records another wallet's spend or receive.
pub(crate) fn is_entry(repos: &dyn Repositories, tx_id: TxId) -> Result<bool, StoreError> {
    Ok(repos.other_wallet_spend(tx_id)?.is_some())
}

/// The outputs of ours the entry of another wallet's spend spent, `None` for any other entry.
pub(crate) fn spent_by(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<Vec<Commitment>>, StoreError> {
    Ok(repos.other_wallet_spend(tx_id)?.map(|spend| {
        spend
            .spent
            .iter()
            .filter_map(|bytes| Commitment::from_bytes(bytes).ok())
            .collect()
    }))
}

/// The outputs entries of another wallet's spend took, recorded at a tip at most
/// [`REVIVE_WINDOW`] blocks below `tip`. A refresh still asks for them and undoes the spend
/// when the node holds one unspent after all.
pub(crate) fn recently_spent(
    repos: &dyn Repositories,
    tip: Height,
) -> Result<Vec<Commitment>, StoreError> {
    let mut spent = Vec::new();
    for (tx_id, spend) in repos.other_wallet_spends()? {
        if spend.to.value().saturating_add(REVIVE_WINDOW) < tip.value() {
            continue;
        }
        let is_spend = repos.transaction(tx_id)?.is_some_and(|entry| {
            entry.direction == TxDirection::Outgoing && entry.slate_id.is_none()
        });
        if is_spend {
            spent.extend(
                spend
                    .spent
                    .iter()
                    .filter_map(|bytes| Commitment::from_bytes(bytes).ok()),
            );
        }
    }
    Ok(spent)
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
        && !repos.tx_marks(tx_id)?.inputs_spent_elsewhere
    {
        return Ok(false);
    }
    Ok(true)
}

/// Marks `tx_id`, a send the node refused because another wallet spent its inputs, so the
/// inputs its cancel released count as that wallet's spend: the send itself can never be mined.
pub(crate) fn mark_inputs_lost(
    repos: &mut dyn Repositories,
    tx_id: TxId,
) -> Result<(), StoreError> {
    let mut marks = repos.tx_marks(tx_id)?;
    marks.inputs_spent_elsewhere = true;
    repos.put_tx_marks(tx_id, &marks)
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
        repos.put_other_wallet_spend(
            tx_id,
            &OtherWalletSpend {
                after,
                to: tip,
                open: true,
                spent: outputs
                    .iter()
                    .map(|output| *output.id.commitment.as_bytes())
                    .collect(),
                change: Vec::new(),
            },
        )?;
        info!(tx_id = %tx_id, count = outputs.len(), "spend by another wallet recorded");
        changes.push(StateChange {
            tx_id,
            from: TxState::Confirmed,
            to: TxState::Confirmed,
        });
    }
    Ok(changes)
}

/// Marks `tx_id`, the entry an update scan stored for an output it found with no record here,
/// as received by another wallet in the block at `height`.
pub(crate) fn mark_received(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Height,
) -> Result<(), StoreError> {
    repos.put_other_wallet_spend(
        tx_id,
        &OtherWalletSpend {
            after: Height::new(height.value().saturating_sub(1)),
            to: height,
            ..OtherWalletSpend::default()
        },
    )
}

/// The window, above `after` and at or below `to`, that the open entries' change lies in: the
/// scan that finds it starts above the lowest `after`. `None` when no entry is open.
pub(crate) fn change_window(repos: &dyn Repositories) -> Result<Option<Height>, StoreError> {
    Ok(open_entries(repos)?
        .into_iter()
        .map(|(_, spend)| spend.after)
        .min())
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
    for (tx_id, mut spend) in open_entries(repos)? {
        let Some(mut entry) = repos.transaction(tx_id)? else {
            continue;
        };
        if entry.account != account || height <= spend.after || height > spend.to {
            continue;
        }
        entry.amount_credited = entry
            .amount_credited
            .checked_add(amount)
            .map_err(|_| corrupt("other wallet change amount"))?;
        repos.update_transaction(tx_id, &entry)?;
        spend.change.push(*commitment.as_bytes());
        repos.put_other_wallet_spend(tx_id, &spend)?;
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
    for (tx_id, mut spend) in open_entries(repos)? {
        if start.value() <= spend.after.value().saturating_add(1) && spend.to <= end {
            spend.open = false;
            repos.put_other_wallet_spend(tx_id, &spend)?;
        }
    }
    Ok(())
}

/// An output a scan found on chain again after a refresh took it for another wallet's spend,
/// as when a reorganisation undid the block: it leaves the entry, whose debit drops by its
/// value. An entry left with no spent output is deleted, unless a scan credited change to it:
/// the change stays linked to it, so it becomes what the chain still shows, outputs received
/// by another wallet.
pub(crate) fn revived(
    repos: &mut dyn Repositories,
    output: &OutputRecord,
) -> Result<(), StoreError> {
    let commitment = *output.id.commitment.as_bytes();
    for (tx_id, mut spend) in repos.other_wallet_spends()? {
        if !spend.spent.contains(&commitment) {
            continue;
        }
        let Some(mut entry) = repos.transaction(tx_id)? else {
            continue;
        };
        spend.spent.retain(|spent| *spent != commitment);
        if spend.spent.is_empty() {
            let linked = repos.outputs_of_transaction(tx_id)?;
            let Some(height) = linked.iter().map(|linked| linked.height).min() else {
                repos.delete_transaction(tx_id)?;
                info!(tx_id = %tx_id, "spend by another wallet undone");
                return Ok(());
            };
            entry.direction = TxDirection::Incoming;
            entry.amount_debited = Amount::ZERO;
            repos.update_transaction(tx_id, &entry)?;
            repos.set_confirmed_height(tx_id, height)?;
            mark_received(repos, tx_id, height)?;
            info!(tx_id = %tx_id, "spend by another wallet undone, its change kept as received");
        } else {
            entry.amount_debited = entry
                .amount_debited
                .checked_sub(output.amount)
                .unwrap_or(Amount::ZERO);
            repos.update_transaction(tx_id, &entry)?;
            repos.put_other_wallet_spend(tx_id, &spend)?;
        }
        return Ok(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
    use lepic_primitives::output::OutputIdentifier;
    use lepic_primitives::params::Network;
    use lepic_store::{CONTEXT_KEY_LEN, ContextKey, KeyId, MemoryStore, WalletStore};

    use super::*;

    const ACCOUNT: AccountIndex = AccountIndex(0);

    fn store() -> MemoryStore {
        let store = MemoryStore::new(ContextKey::from_bytes([1; CONTEXT_KEY_LEN]));
        store
            .write(|repos| crate::account::ensure_default_account(repos))
            .unwrap();
        store
    }

    fn output(child: u32, value: u64, status: OutputStatus, height: u64) -> OutputRecord {
        let keychain =
            Keychain::from_seed(&Seed::from_entropy(&[7; 32]).unwrap(), Network::Floonet).unwrap();
        let key_id = Identifier::new(3, [0, 0, child, 0]).unwrap();
        OutputRecord {
            id: OutputIdentifier::new(
                OutputFeatures::Plain,
                keychain
                    .commit(value, &key_id, SwitchCommitment::Regular)
                    .unwrap(),
            ),
            key_id: KeyId(key_id.to_bytes()),
            account: ACCOUNT,
            amount: Amount::new(value),
            status,
            height: Height::new(height),
            lock_height: Height::ZERO,
            mmr_index: None,
            tx: None,
        }
    }

    /// Records `spent` as another wallet's spend over blocks 11 to 20 and returns the entry.
    fn recorded(store: &MemoryStore, spent: &OutputRecord) -> TxId {
        let now = Timestamp::from_second(1_790_000_000).unwrap();
        store
            .write(|repos| {
                repos.put_output(spent)?;
                let changes = record(
                    repos,
                    std::slice::from_ref(spent),
                    Height::new(10),
                    Height::new(20),
                    now,
                )?;
                Ok::<_, StoreError>(changes[0].tx_id)
            })
            .unwrap()
    }

    #[test]
    fn an_undone_spend_with_credited_change_is_kept_as_received() {
        let store = store();
        let spent = output(0, 5_000, OutputStatus::Spent, 2);
        let tx_id = recorded(&store, &spent);
        let change = output(1, 3_000, OutputStatus::Unspent, 15);
        store
            .write(|repos| {
                let taken = take_change(
                    repos,
                    ACCOUNT,
                    &change.id.commitment,
                    change.amount,
                    change.height,
                )?;
                assert_eq!(taken, Some(tx_id));
                // A scan stores the change linked to the entry it was credited to.
                repos.put_output(&OutputRecord {
                    tx: Some(tx_id),
                    ..change.clone()
                })
            })
            .unwrap();

        store.write(|repos| revived(repos, &spent)).unwrap();

        let entry = store
            .read(|repos| repos.transaction(tx_id))
            .unwrap()
            .unwrap();
        assert_eq!(entry.direction, TxDirection::Incoming);
        assert_eq!(entry.amount_debited, Amount::ZERO);
        assert_eq!(entry.amount_credited, Amount::new(3_000));
        assert_eq!(
            store.read(|repos| repos.other_wallet_spend(tx_id)).unwrap(),
            Some(OtherWalletSpend {
                after: Height::new(14),
                to: Height::new(15),
                ..OtherWalletSpend::default()
            })
        );
        assert_eq!(
            store.read(|repos| repos.confirmed_height(tx_id)).unwrap(),
            Some(Height::new(15))
        );
        assert!(!store.read(|repos| is_unverified(repos, tx_id)).unwrap());
        assert!(
            store
                .read(|repos| recently_spent(repos, Height::new(20)))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_undone_spend_with_no_linked_output_is_deleted() {
        let store = store();
        let spent = output(0, 5_000, OutputStatus::Spent, 2);
        let tx_id = recorded(&store, &spent);

        store.write(|repos| revived(repos, &spent)).unwrap();

        assert_eq!(store.read(|repos| repos.transaction(tx_id)).unwrap(), None);
    }
}
