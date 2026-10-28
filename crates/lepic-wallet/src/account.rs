// SPDX-License-Identifier: Apache-2.0
//! Accounts: the derivation subtrees `m/<index>/0` that hold a wallet's outputs, with a label and
//! the counter of the next unused output key.

use std::collections::HashSet;
use std::fmt;

use lepic_keychain::Identifier;
use lepic_store::{AccountIndex, AccountRecord, KeyId, Repositories};
use thiserror::Error;

use crate::epicbox_invoice::HIDDEN_FORMATTING;
use crate::error::WalletError;
use crate::lifecycle;

pub const MAX_ACCOUNT_LABEL_LEN: usize = 64;

/// The label `epic-wallet` gives account `m/0/0`.
pub const DEFAULT_ACCOUNT_LABEL: &str = "default";

/// Account indices and output key child numbers stay below the hardened range, because
/// `epic-wallet` turns a component at or above it into a hardened derivation step.
pub(crate) const FIRST_HARDENED: u32 = 1 << 31;

/// Where this install's output key counters start, drawn once per database. Two installs of one
/// recovery phrase each walk their own counter, and a counter that starts where the other's
/// is makes the same key, which for the same value is the same commitment.
const KEY_START_SETTING: &str = "wallet.output_key_start";

/// Starts lie above any counter an install that started at zero reaches, and leave room below
/// the hardened range for the keys an install hands out.
const KEY_START_FLOOR: u32 = 1 << 20;
const KEY_START_CEILING: u32 = FIRST_HARDENED - (1 << 24);

/// A key a scan finds this far above an account's counter can still be one this install
/// handed out after the database it runs on was copied; anything further belongs to another
/// install's range, and following it would hand out that install's next keys.
pub(crate) const OWN_KEY_WINDOW: u32 = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AccountError {
    #[error("account label has {actual} bytes, expected 1 to {MAX_ACCOUNT_LABEL_LEN}")]
    LabelLength { actual: usize },
    #[error("account label character {position} is a control or hidden formatting character")]
    LabelCharacter { position: usize },
    #[error("account label is already used by another account")]
    LabelTaken,
    #[error("no account has this label")]
    UnknownLabel,
    #[error("account {0} does not exist")]
    UnknownAccount(AccountIndex),
    #[error("every account index is in use")]
    NoFreeIndex,
    #[error("account {0} has used every output key index")]
    ChildIndexExhausted(AccountIndex),
}

/// A validated account label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountLabel(String);

impl AccountLabel {
    pub fn new(label: &str) -> Result<Self, AccountError> {
        if label.is_empty() || label.len() > MAX_ACCOUNT_LABEL_LEN {
            return Err(AccountError::LabelLength {
                actual: label.len(),
            });
        }
        match label.chars().position(is_hidden) {
            Some(position) => Err(AccountError::LabelCharacter { position }),
            None => Ok(Self(label.to_owned())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Characters a label may not hold: they would make it display differently from what it is.
pub(crate) fn is_hidden(c: char) -> bool {
    c.is_control() || HIDDEN_FORMATTING.contains(&c)
}

impl fmt::Display for AccountLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub index: AccountIndex,
    pub label: String,
}

impl Account {
    /// The parent key of the account's outputs, `m/<index>/0`.
    pub fn parent_key_id(&self) -> Result<Identifier, WalletError> {
        parent_key_id(self.index)
    }
}

impl From<AccountRecord> for Account {
    fn from(record: AccountRecord) -> Self {
        Self {
            index: record.index,
            label: record.label,
        }
    }
}

pub fn parent_key_id(index: AccountIndex) -> Result<Identifier, WalletError> {
    Ok(Identifier::new(2, [index.0, 0, 0, 0])?)
}

/// A random start for this install's output key counters, uniform in
/// `KEY_START_FLOOR..KEY_START_CEILING`.
pub(crate) fn draw_key_start(rng: &mut (impl rand_core::CryptoRng + ?Sized)) -> u32 {
    let span = u64::from(KEY_START_CEILING.saturating_sub(KEY_START_FLOOR));
    let offset = u64::from(rng.next_u32())
        .checked_mul(span)
        .map_or(0, |scaled| scaled >> 32);
    KEY_START_FLOOR.saturating_add(u32::try_from(offset).unwrap_or(0))
}

/// The counter an account added now starts at: this install's start for an account it may hand
/// out keys from, zero for a hardened one and in a database that has no start yet.
pub(crate) fn key_counter_start(
    repos: &dyn Repositories,
    index: AccountIndex,
) -> Result<u32, WalletError> {
    if index.0 >= FIRST_HARDENED {
        return Ok(0);
    }
    Ok(repos
        .setting(KEY_START_SETTING)?
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|start| (KEY_START_FLOOR..KEY_START_CEILING).contains(start))
        .unwrap_or(0))
}

/// Gives a database without a key start `start`, once, and moves every account's counter up to
/// it, so this install's next keys are its own whatever another install of the phrase uses.
/// Keys below stay where they are; a database that has a start keeps it.
pub(crate) fn place_key_counters(
    repos: &mut dyn Repositories,
    start: u32,
) -> Result<(), WalletError> {
    if repos.setting(KEY_START_SETTING)?.is_some() {
        return Ok(());
    }
    repos.put_setting(KEY_START_SETTING, &start.to_string())?;
    for mut record in repos.accounts()? {
        let start = key_counter_start(repos, record.index)?;
        if record.next_child < start {
            record.next_child = start;
            repos.put_account(&record)?;
        }
    }
    Ok(())
}

/// Stores the default account `m/0/0` unless an account with index 0 exists.
pub(crate) fn ensure_default_account(repos: &mut dyn Repositories) -> Result<(), WalletError> {
    if repos.account(AccountIndex(0))?.is_none() {
        repos.put_account(&AccountRecord {
            index: AccountIndex(0),
            label: DEFAULT_ACCOUNT_LABEL.to_owned(),
            next_child: key_counter_start(repos, AccountIndex(0))?,
        })?;
    }
    Ok(())
}

/// Adds an account under the index after the highest one in use, as `epic-wallet` does. A
/// hardened account that a restore found does not count, so it cannot use up every index.
pub(crate) fn create_account(
    repos: &mut dyn Repositories,
    label: &AccountLabel,
) -> Result<Account, WalletError> {
    if repos.account_by_label(label.as_str())?.is_some() {
        return Err(AccountError::LabelTaken.into());
    }
    let next_index = match repos
        .accounts()?
        .iter()
        .map(|account| account.index.0)
        .filter(|index| *index < FIRST_HARDENED)
        .max()
    {
        Some(highest) => highest.checked_add(1).ok_or(AccountError::NoFreeIndex)?,
        None => 0,
    };
    if next_index >= FIRST_HARDENED {
        return Err(AccountError::NoFreeIndex.into());
    }
    let record = AccountRecord {
        index: AccountIndex(next_index),
        label: label.as_str().to_owned(),
        next_child: key_counter_start(repos, AccountIndex(next_index))?,
    };
    repos.put_account(&record)?;
    Ok(record.into())
}

pub(crate) fn account_by_label(
    repos: &dyn Repositories,
    label: &str,
) -> Result<Account, WalletError> {
    repos
        .account_by_label(label)?
        .map(Account::from)
        .ok_or_else(|| AccountError::UnknownLabel.into())
}

/// Reserves the account's next output key, `m/<index>/0/<child>`, and advances its counter in
/// the same store transaction, so a key is never handed out twice. Keys a stored output of the
/// account already uses are skipped: the counter can fall behind them when the database is an
/// older copy, or when a scan found an output past the counter.
///
/// Fails with [`WalletError::RestoreScanRequired`] on a database rebuilt from the seed before a
/// scan from genesis completed, since a key the counter has not passed may already be in use on
/// chain.
pub fn next_output_key(
    repos: &mut dyn Repositories,
    account: AccountIndex,
) -> Result<Identifier, WalletError> {
    lifecycle::ensure_restore_scanned(repos)?;
    let mut record = repos
        .account(account)?
        .ok_or(AccountError::UnknownAccount(account))?;
    let used: HashSet<KeyId> = repos
        .outputs(account, None)?
        .into_iter()
        .map(|output| output.key_id)
        .collect();
    let mut child = record.next_child;
    loop {
        if child >= FIRST_HARDENED {
            return Err(AccountError::ChildIndexExhausted(account).into());
        }
        let key_id = Identifier::new(3, [account.0, 0, child, 0])?;
        child = child
            .checked_add(1)
            .ok_or(AccountError::ChildIndexExhausted(account))?;
        if !used.contains(&KeyId(key_id.to_bytes())) {
            record.next_child = child;
            repos.put_account(&record)?;
            return Ok(key_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use lepic_store::{CONTEXT_KEY_LEN, ContextKey, MemoryStore, WalletStore};

    use super::*;

    fn store_with_default_account() -> MemoryStore {
        let store = MemoryStore::new(ContextKey::from_bytes([1; CONTEXT_KEY_LEN]));
        store.write(|repos| ensure_default_account(repos)).unwrap();
        store
    }

    #[test]
    fn new_labels_refuse_control_and_hidden_formatting_characters() {
        for (label, position) in [
            ("a\u{202E}b", 1),
            ("\u{200B}ab", 0),
            ("ab\u{2068}", 2),
            ("a\u{FEFF}", 1),
            ("a\tb", 1),
        ] {
            assert_eq!(
                AccountLabel::new(label),
                Err(AccountError::LabelCharacter { position }),
                "{label:?}"
            );
        }
        assert!(AccountLabel::new("savings – 2").is_ok());
    }

    #[test]
    fn a_stored_label_with_hidden_formatting_still_loads() {
        let store = store_with_default_account();
        let label = "old\u{202E}name";
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(4),
                    label: label.to_owned(),
                    next_child: 0,
                })?;
                Ok::<_, WalletError>(())
            })
            .unwrap();
        let account = store.read(|repos| account_by_label(repos, label)).unwrap();
        assert_eq!(account.index, AccountIndex(4));
        assert_eq!(account.label, label);
    }

    #[test]
    fn default_account_is_m_0_0() {
        let store = store_with_default_account();
        let account = store
            .read(|repos| account_by_label(repos, DEFAULT_ACCOUNT_LABEL))
            .unwrap();
        assert_eq!(account.index, AccountIndex(0));
        assert_eq!(account.parent_key_id().unwrap().to_bip32_path(), "m/0/0");
    }

    #[test]
    fn ensure_default_account_keeps_an_existing_counter() {
        let store = store_with_default_account();
        store
            .write(|repos| next_output_key(repos, AccountIndex(0)))
            .unwrap();
        store.write(|repos| ensure_default_account(repos)).unwrap();
        let record = store
            .read(|repos| Ok::<_, WalletError>(repos.account(AccountIndex(0))?))
            .unwrap()
            .unwrap();
        assert_eq!(record.next_child, 1);
    }

    #[test]
    fn output_keys_follow_the_counter_under_the_account_path() {
        let store = store_with_default_account();
        let second = store
            .write(|repos| create_account(repos, &AccountLabel::new("savings").unwrap()))
            .unwrap();
        let keys: Vec<String> = [0, 0, 1, 0]
            .into_iter()
            .map(|account| {
                store
                    .write(|repos| next_output_key(repos, AccountIndex(account)))
                    .unwrap()
                    .to_bip32_path()
            })
            .collect();
        assert_eq!(second.index, AccountIndex(1));
        assert_eq!(keys, ["m/0/0/0", "m/0/0/1", "m/1/0/0", "m/0/0/2"]);
    }

    #[test]
    fn new_accounts_take_the_index_after_the_highest() {
        let store = store_with_default_account();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(7),
                    label: "imported".to_owned(),
                    next_child: 0,
                })
            })
            .unwrap();
        let account = store
            .write(|repos| create_account(repos, &AccountLabel::new("next").unwrap()))
            .unwrap();
        assert_eq!(account.index, AccountIndex(8));
    }

    #[test]
    fn rejects_a_label_already_in_use() {
        let store = store_with_default_account();
        let result = store.write(|repos| {
            create_account(repos, &AccountLabel::new(DEFAULT_ACCOUNT_LABEL).unwrap())
        });
        assert!(matches!(
            result,
            Err(WalletError::Account(AccountError::LabelTaken))
        ));
    }

    #[test]
    fn rejects_account_indices_in_the_hardened_range() {
        let store = store_with_default_account();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(FIRST_HARDENED - 1),
                    label: "last".to_owned(),
                    next_child: 0,
                })
            })
            .unwrap();
        let result =
            store.write(|repos| create_account(repos, &AccountLabel::new("over").unwrap()));
        assert!(matches!(
            result,
            Err(WalletError::Account(AccountError::NoFreeIndex))
        ));
    }

    #[test]
    fn a_restored_hardened_account_leaves_new_accounts_below_the_hardened_range() {
        let store = store_with_default_account();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(FIRST_HARDENED),
                    label: "restored".to_owned(),
                    next_child: 0,
                })
            })
            .unwrap();
        let account = store
            .write(|repos| create_account(repos, &AccountLabel::new("next").unwrap()))
            .unwrap();
        assert_eq!(account.index, AccountIndex(1));
    }

    #[test]
    fn rejects_output_keys_in_the_hardened_range() {
        let store = store_with_default_account();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(0),
                    label: DEFAULT_ACCOUNT_LABEL.to_owned(),
                    next_child: FIRST_HARDENED,
                })
            })
            .unwrap();
        let result = store.write(|repos| next_output_key(repos, AccountIndex(0)));
        assert!(matches!(
            result,
            Err(WalletError::Account(AccountError::ChildIndexExhausted(
                AccountIndex(0)
            )))
        ));
    }

    #[test]
    fn refuses_output_keys_until_the_restore_scan_of_a_rebuilt_database_completes() {
        let store = store_with_default_account();
        store
            .write(|repos| repos.put_setting("wallet.restore_scan_required", "true"))
            .unwrap();
        let result = store.write(|repos| next_output_key(repos, AccountIndex(0)));
        assert!(matches!(result, Err(WalletError::RestoreScanRequired)));
        store
            .write(|repos| Ok::<_, WalletError>(lifecycle::restore_scan_completed(repos)?))
            .unwrap();
        let key = store
            .write(|repos| next_output_key(repos, AccountIndex(0)))
            .unwrap();
        assert_eq!(key.to_bip32_path(), "m/0/0/0");
    }

    #[test]
    fn skips_output_keys_a_stored_output_already_uses() {
        use lepic_keychain::{Keychain, Seed, SwitchCommitment};
        use lepic_primitives::amount::{Amount, Height};
        use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
        use lepic_primitives::params::Network;
        use lepic_store::{KeyId, OutputRecord, OutputStatus};

        let store = store_with_default_account();
        let keychain =
            Keychain::from_seed(&Seed::from_entropy(&[7; 32]).unwrap(), Network::Floonet).unwrap();
        // The counter stands at 0 while keys 0 and 1 are on stored outputs, as in an older
        // copy of the database.
        for child in [0, 1] {
            let key_id = Identifier::new(3, [0, 0, child, 0]).unwrap();
            let commitment = keychain
                .commit(1_000, &key_id, SwitchCommitment::Regular)
                .unwrap();
            store
                .write(|repos| {
                    repos.put_output(&OutputRecord {
                        id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
                        key_id: KeyId(key_id.to_bytes()),
                        account: AccountIndex(0),
                        amount: Amount::new(1_000),
                        status: OutputStatus::Unspent,
                        height: Height::new(1),
                        lock_height: Height::ZERO,
                        mmr_index: None,
                        tx: None,
                    })
                })
                .unwrap();
        }

        let key = store
            .write(|repos| next_output_key(repos, AccountIndex(0)))
            .unwrap();

        assert_eq!(key.to_bip32_path(), "m/0/0/2");
        let account = store
            .read(|repos| repos.account(AccountIndex(0)))
            .unwrap()
            .unwrap();
        assert_eq!(account.next_child, 3);
    }

    #[test]
    fn rejects_output_keys_of_an_unknown_account() {
        let store = store_with_default_account();
        let result = store.write(|repos| next_output_key(repos, AccountIndex(3)));
        assert!(matches!(
            result,
            Err(WalletError::Account(AccountError::UnknownAccount(
                AccountIndex(3)
            )))
        ));
    }

    struct FixedRng(u32);

    impl rand_core::TryRng for FixedRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.0))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for FixedRng {}

    fn counter(store: &MemoryStore, index: u32) -> u32 {
        store
            .read(|repos| Ok::<_, WalletError>(repos.account(AccountIndex(index))?))
            .unwrap()
            .unwrap()
            .next_child
    }

    #[test]
    fn key_starts_stay_between_the_floor_and_the_ceiling() {
        assert_eq!(draw_key_start(&mut FixedRng(0)), KEY_START_FLOOR);
        let top = draw_key_start(&mut FixedRng(u32::MAX));
        assert!(
            top < KEY_START_CEILING && top > KEY_START_CEILING - 1024,
            "{top}"
        );
    }

    #[test]
    fn a_key_start_moves_every_account_once_and_keeps_counters_above_it() {
        let store = store_with_default_account();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(1),
                    label: "far".to_owned(),
                    next_child: KEY_START_CEILING,
                })?;
                repos.put_account(&AccountRecord {
                    index: AccountIndex(FIRST_HARDENED),
                    label: "hardened".to_owned(),
                    next_child: 0,
                })?;
                place_key_counters(repos, KEY_START_FLOOR + 5)
            })
            .unwrap();
        assert_eq!(counter(&store, 0), KEY_START_FLOOR + 5);
        assert_eq!(counter(&store, 1), KEY_START_CEILING);
        assert_eq!(counter(&store, FIRST_HARDENED), 0);

        store
            .write(|repos| place_key_counters(repos, KEY_START_FLOOR + 9))
            .unwrap();
        assert_eq!(
            counter(&store, 0),
            KEY_START_FLOOR + 5,
            "the start is drawn once"
        );
        let added = store
            .write(|repos| create_account(repos, &AccountLabel::new("new").unwrap()))
            .unwrap();
        assert_eq!(counter(&store, added.index.0), KEY_START_FLOOR + 5);
        let key = store
            .write(|repos| next_output_key(repos, AccountIndex(0)))
            .unwrap();
        assert_eq!(
            key.to_bip32_path(),
            format!("m/0/0/{}", KEY_START_FLOOR + 5)
        );
    }

    #[test]
    fn rejects_empty_long_and_control_labels() {
        assert_eq!(
            AccountLabel::new(""),
            Err(AccountError::LabelLength { actual: 0 })
        );
        assert_eq!(
            AccountLabel::new(&"a".repeat(65)),
            Err(AccountError::LabelLength { actual: 65 })
        );
        assert_eq!(
            AccountLabel::new("a\nb"),
            Err(AccountError::LabelCharacter { position: 1 })
        );
        assert_eq!(
            AccountLabel::new("Spare cash ✓").unwrap().as_str(),
            "Spare cash ✓"
        );
    }
}
