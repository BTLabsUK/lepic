// SPDX-License-Identifier: Apache-2.0
//! The epic1 addresses an account issued (RFC 0003 §5.14). Each address is an index of the
//! account; index 0 is the account's first address and is always issued. The wallet keeps the
//! highest index it issued, the highest one a payment came to, the index of the most recent
//! payment, and the index each payment came to. Coins do not depend on any of it: it only says
//! which seal keys open what is sealed to the account's addresses.
//!
//! A wallet whose database was rebuilt from the recovery phrase does not know how far it
//! issued. It tries [`RESTORE_GAP`] indexes past the highest one it knows, and the first address
//! an account issues after the restore comes after them, so an address that may have been
//! handed out is not handed out again. From then on the account counts from that address.
//!
//! Another install on the same recovery phrase may still be issuing, and two installs that
//! both issue would hand the same index to two payers. So a restored wallet issues no address
//! until the host confirms this install is the one that issues ([`issue_here`]). Until then it
//! keeps trying the gap past the highest index a payment came to, so its window follows the
//! install that issues.

use lepic_contact::EncSecretKey;
use lepic_store::{AccountIndex, Record, Repositories, StoreError, TxId};
use thiserror::Error;

/// How many indexes past the highest one known a restored wallet tries, and skips before it
/// issues the next address.
pub const RESTORE_GAP: u32 = 50;

/// The settings prefix of the highest index each account issued.
const ISSUED_PREFIX: &str = "epic1.issued.";
/// The settings prefix of the highest index a payment came to, by account.
const SEEN_PREFIX: &str = "epic1.seen.";
/// The settings prefix of the index of the most recent payment, by account.
const LAST_PREFIX: &str = "epic1.last.";
/// The settings prefix of the index each payment came to, by transaction.
const TX_PREFIX: &str = "epic1.tx.";
/// Set when the database was rebuilt from the recovery phrase.
const RESTORED_SETTING: &str = "epic1.restored";
/// The settings prefix of the accounts that issued an address since the restore, which ends
/// their gap.
const PAST_GAP_PREFIX: &str = "epic1.past_gap.";
/// Set when the host confirmed that this restored install is the one that issues addresses.
const ISSUER_SETTING: &str = "epic1.issuer";

/// Why [`issue_next`] issued no address.
#[derive(Debug, Error)]
pub enum IssueError {
    /// The database was rebuilt from the recovery phrase and the host has not confirmed that
    /// this install is the one that issues addresses ([`issue_here`]).
    #[error("this install does not issue epic1 addresses")]
    NotIssuingInstall,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The address index stored under `key`. A value that is not one is
/// [`StoreError::Corrupt`]: read as absent, a damaged count of issued addresses would issue
/// them again.
fn number(repos: &dyn Repositories, key: &str) -> Result<Option<u32>, StoreError> {
    repos
        .setting(key)?
        .map(|text| {
            text.parse::<u32>().map_err(|_| StoreError::Corrupt {
                record: Record::Setting,
                field: "epic1 address index",
            })
        })
        .transpose()
}

fn account_key(prefix: &str, account: AccountIndex) -> String {
    format!("{prefix}{}", account.0)
}

/// The highest index `account` issued; 0 when it issued only its first address.
pub fn highest_issued(repos: &dyn Repositories, account: AccountIndex) -> Result<u32, StoreError> {
    Ok(number(repos, &account_key(ISSUED_PREFIX, account))?.unwrap_or(0))
}

/// The highest index a payment to `account` came to, if any did.
pub fn highest_seen(
    repos: &dyn Repositories,
    account: AccountIndex,
) -> Result<Option<u32>, StoreError> {
    number(repos, &account_key(SEEN_PREFIX, account))
}

/// Whether the database was rebuilt from the recovery phrase.
pub fn restored(repos: &dyn Repositories) -> Result<bool, StoreError> {
    Ok(repos.setting(RESTORED_SETTING)?.is_some())
}

/// Records that the database was rebuilt from the recovery phrase, so the wallet tries
/// [`RESTORE_GAP`] indexes past the highest one it knows.
pub(crate) fn mark_restored(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    repos.put_setting(RESTORED_SETTING, "true")
}

/// Whether this install issues new addresses: a wallet created fresh does, a restored one only
/// once the host confirmed it with [`issue_here`].
pub fn issuing(repos: &dyn Repositories) -> Result<bool, StoreError> {
    Ok(!restored(repos)? || repos.setting(ISSUER_SETTING)?.is_some())
}

/// Makes this install the one that issues new addresses. Its first address per account comes
/// after the restore gap. Calling it again changes nothing.
pub fn issue_here(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    if repos.setting(ISSUER_SETTING)?.is_none() {
        repos.put_setting(ISSUER_SETTING, "true")?;
    }
    Ok(())
}

/// Whether `account` is inside its restore gap: the database was rebuilt from the recovery
/// phrase and the account issued no address since.
fn in_gap(repos: &dyn Repositories, account: AccountIndex) -> Result<bool, StoreError> {
    Ok(restored(repos)?
        && repos
            .setting(&account_key(PAST_GAP_PREFIX, account))?
            .is_none())
}

/// The highest index whose seal key the wallet tries for `account`: the highest one issued or
/// paid, plus [`RESTORE_GAP`] after a restore until the account issues an address.
pub fn highest_tried(repos: &dyn Repositories, account: AccountIndex) -> Result<u32, StoreError> {
    let known = highest_issued(repos, account)?.max(highest_seen(repos, account)?.unwrap_or(0));
    Ok(if in_gap(repos, account)? {
        known.saturating_add(RESTORE_GAP)
    } else {
        known
    })
}

/// The indexes of `account` whose seal keys are tried, in order: the index of the most recent
/// payment, then index 0, then the rest from the highest down.
pub fn trial_order(
    repos: &dyn Repositories,
    account: AccountIndex,
) -> Result<Vec<u32>, StoreError> {
    let top = highest_tried(repos, account)?;
    let last = number(repos, &account_key(LAST_PREFIX, account))?.filter(|last| *last <= top);
    let mut order = Vec::new();
    if let Some(last) = last {
        order.push(last);
    }
    if last != Some(0) {
        order.push(0);
    }
    order.extend((1..=top).rev().filter(|index| Some(*index) != last));
    Ok(order)
}

/// Issues the next address of `account` and returns its index: the first index past those
/// tried. The first one after a restore skips the gap, so an address handed out before the
/// restore is not issued again; the ones after it follow on.
///
/// Fails with [`IssueError::NotIssuingInstall`] on a restored install the host has not made
/// the issuer, and [`IssueError::Store`]; an account that issued `u32::MAX` issues no more and
/// gets `Ok(None)`.
pub fn issue_next(
    repos: &mut dyn Repositories,
    account: AccountIndex,
) -> Result<Option<u32>, IssueError> {
    if !issuing(repos)? {
        return Err(IssueError::NotIssuingInstall);
    }
    let Some(next) = highest_tried(repos, account)?.checked_add(1) else {
        return Ok(None);
    };
    repos.put_setting(&account_key(ISSUED_PREFIX, account), &next.to_string())?;
    if in_gap(repos, account)? {
        repos.put_setting(&account_key(PAST_GAP_PREFIX, account), "true")?;
    }
    Ok(Some(next))
}

/// Records that the payment `tx_id` to `account` came to the address `index`: the index is
/// kept with the transaction, it becomes the first one tried, and a payment past the highest
/// index known raises it.
pub(crate) fn record_payment(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    account: AccountIndex,
    index: u32,
) -> Result<(), StoreError> {
    repos.put_setting(&format!("{TX_PREFIX}{}", tx_id.0), &index.to_string())?;
    repos.put_setting(&account_key(LAST_PREFIX, account), &index.to_string())?;
    if highest_seen(repos, account)?.is_none_or(|seen| seen < index) {
        repos.put_setting(&account_key(SEEN_PREFIX, account), &index.to_string())?;
    }
    Ok(())
}

/// The epic1 address index the payment `tx_id` came to; `None` for a transaction that did not
/// come to an epic1 address, or whose stored index is damaged: it is only shown, and a
/// damaged one does not keep the transaction from being listed.
pub fn index_of(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<u32>, StoreError> {
    Ok(number(repos, &format!("{TX_PREFIX}{}", tx_id.0)).unwrap_or_else(|_| None))
}

/// Tries the seal keys `keys`, `(index, key)` in the order given, and returns the index of the
/// first one `open` opens with, and what it opened. Envelopes to an epic1 address carry a zero
/// hint, so nothing tells which address they were sealed to: each key is tried until one opens.
pub fn trial_open<T>(
    keys: &[(u32, EncSecretKey)],
    mut open: impl FnMut(&EncSecretKey) -> Option<T>,
) -> Option<(u32, T)> {
    keys.iter()
        .find_map(|(index, key)| open(key).map(|opened| (*index, opened)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lepic_store::{CONTEXT_KEY_LEN, MemoryStore, StoreKeys, WalletStore};

    fn new_store() -> MemoryStore {
        MemoryStore::new(StoreKeys::from_bytes(
            [2; CONTEXT_KEY_LEN],
            [2; CONTEXT_KEY_LEN],
        ))
    }

    const A: AccountIndex = AccountIndex(0);
    const B: AccountIndex = AccountIndex(1);

    #[test]
    fn a_new_account_tries_index_0_and_issues_from_1() {
        let store = new_store();
        store
            .write(|repos| {
                assert_eq!(trial_order(repos, A)?, vec![0]);
                assert_eq!(issue_next(repos, A)?, Some(1));
                assert_eq!(issue_next(repos, A)?, Some(2));
                assert_eq!(issue_next(repos, B)?, Some(1));
                assert_eq!(trial_order(repos, A)?, vec![0, 2, 1]);
                Ok::<_, IssueError>(())
            })
            .unwrap();
    }

    #[test]
    fn the_most_recent_payment_is_tried_first_and_kept_with_its_transaction() {
        let store = new_store();
        store
            .write(|repos| {
                for _ in 0..4 {
                    issue_next(repos, A)?;
                }
                record_payment(repos, TxId(7), A, 2)?;
                assert_eq!(trial_order(repos, A)?, vec![2, 0, 4, 3, 1]);
                assert_eq!(index_of(repos, TxId(7))?, Some(2));
                assert_eq!(index_of(repos, TxId(8))?, None);
                record_payment(repos, TxId(8), A, 0)?;
                assert_eq!(trial_order(repos, A)?, vec![0, 4, 3, 2, 1]);
                assert_eq!(highest_seen(repos, A)?, Some(2));
                Ok::<_, IssueError>(())
            })
            .unwrap();
    }

    #[test]
    fn a_restored_wallet_tries_the_gap_and_issues_past_it() {
        let store = new_store();
        store
            .write(|repos| {
                mark_restored(repos)?;
                assert_eq!(highest_tried(repos, A)?, RESTORE_GAP);
                assert_eq!(trial_order(repos, A)?.len(), 51);
                // A payment found at 30 moves the window to 80.
                record_payment(repos, TxId(1), A, 30)?;
                assert_eq!(highest_tried(repos, A)?, 30 + RESTORE_GAP);
                issue_here(repos)?;
                assert_eq!(issue_next(repos, A)?, Some(31 + RESTORE_GAP));
                // The gap ends with the first address issued: the next ones follow on.
                assert_eq!(highest_tried(repos, A)?, 31 + RESTORE_GAP);
                assert_eq!(issue_next(repos, A)?, Some(32 + RESTORE_GAP));
                // A payment to an address issued since moves nothing past it.
                record_payment(repos, TxId(2), A, 32 + RESTORE_GAP)?;
                assert_eq!(issue_next(repos, A)?, Some(33 + RESTORE_GAP));
                // Another account is still inside its gap.
                assert_eq!(issue_next(repos, B)?, Some(1 + RESTORE_GAP));
                Ok::<_, IssueError>(())
            })
            .unwrap();
    }

    #[test]
    fn a_restored_wallet_issues_only_once_made_the_issuer() {
        let store = new_store();
        store
            .write(|repos| {
                assert!(issuing(repos)?);
                mark_restored(repos)?;
                assert!(!issuing(repos)?);
                assert!(matches!(
                    issue_next(repos, A),
                    Err(IssueError::NotIssuingInstall)
                ));
                assert_eq!(repos.setting(&account_key(ISSUED_PREFIX, A))?, None);
                // Payments the issuing install's addresses bring move the window along.
                record_payment(repos, TxId(1), A, 40)?;
                assert_eq!(highest_tried(repos, A)?, 40 + RESTORE_GAP);
                record_payment(repos, TxId(2), A, 70)?;
                assert_eq!(highest_tried(repos, A)?, 70 + RESTORE_GAP);
                assert_eq!(trial_order(repos, A)?[..2], [70, 0]);
                issue_here(repos)?;
                issue_here(repos)?;
                assert!(issuing(repos)?);
                assert_eq!(issue_next(repos, A)?, Some(71 + RESTORE_GAP));
                assert_eq!(issue_next(repos, A)?, Some(72 + RESTORE_GAP));
                Ok::<_, IssueError>(())
            })
            .unwrap();
    }

    fn corrupt<T, E: Into<IssueError>>(result: Result<T, E>) -> bool {
        matches!(
            result.map_err(Into::into),
            Err(IssueError::Store(StoreError::Corrupt {
                record: Record::Setting,
                ..
            }))
        )
    }

    #[test]
    fn a_damaged_count_refuses_to_issue_and_issues_nothing_again() {
        let store = new_store();
        store
            .write(|repos| {
                for _ in 0..3 {
                    issue_next(repos, A)?;
                }
                let key = account_key(ISSUED_PREFIX, A);
                repos.put_setting(&key, "3x")?;
                assert!(corrupt(issue_next(repos, A)));
                assert!(corrupt(highest_tried(repos, A)));
                assert_eq!(repos.setting(&key)?.as_deref(), Some("3x"));
                repos.put_setting(&account_key(SEEN_PREFIX, B), "")?;
                assert!(corrupt(issue_next(repos, B)));
                assert!(corrupt(trial_order(repos, B)));
                // A damaged index kept with a transaction only hides it.
                repos.put_setting(&format!("{TX_PREFIX}9"), "-1")?;
                assert_eq!(index_of(repos, TxId(9))?, None);
                Ok::<_, IssueError>(())
            })
            .unwrap();
    }

    #[test]
    fn an_account_at_the_last_index_issues_no_more() {
        let store = new_store();
        store
            .write(|repos| {
                repos.put_setting(&account_key(ISSUED_PREFIX, A), &u32::MAX.to_string())?;
                assert_eq!(issue_next(repos, A)?, None);
                Ok::<_, IssueError>(())
            })
            .unwrap();
    }
}
