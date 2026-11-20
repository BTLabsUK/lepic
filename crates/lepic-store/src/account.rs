// SPDX-License-Identifier: Apache-2.0
use std::fmt;

use crate::error::StoreError;

/// The account component of a derivation path, `m/<index>/0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountIndex(pub u32);

impl fmt::Display for AccountIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    pub index: AccountIndex,
    /// Unique across accounts.
    pub label: String,
    /// The next unused output key child index under this account.
    pub next_child: u32,
}

pub trait AccountRepository {
    /// Inserts or replaces the account with the same index. Fails with
    /// [`StoreError::LabelTaken`] when another account has the label.
    fn put_account(&mut self, account: &AccountRecord) -> Result<(), StoreError>;

    fn account(&self, index: AccountIndex) -> Result<Option<AccountRecord>, StoreError>;

    fn account_by_label(&self, label: &str) -> Result<Option<AccountRecord>, StoreError>;

    /// All accounts, ordered by index.
    fn accounts(&self) -> Result<Vec<AccountRecord>, StoreError>;
}
