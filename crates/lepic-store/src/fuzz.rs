// SPDX-License-Identifier: Apache-2.0
//! Entry points for the fuzz targets in `fuzz/` into the parsers of foreign bytes that are not
//! public on their own. Not part of the API: it may change in any release.

use lepic_primitives::params::Network;

use crate::contact_backup::{CardReader, ImportSummary, import_contacts};
use crate::context::{CONTEXT_KEY_LEN, StoreKeys};
use crate::error::StoreError;
use crate::memory::MemoryStore;
use crate::store::WalletStore;

/// Runs the parser the legacy history import runs on one row of an `epic-wallet` database:
/// `kind` 0 reads `data` as an account, 1 as a transaction, 2 as an output, and any other as
/// the derivation counter stored under the row key `key`. Returns whether the row parsed.
pub fn legacy_row(kind: u8, key: &[u8], data: &[u8]) -> bool {
    crate::legacy::parse_row(kind, key, data)
}

/// Imports the contact backup `json` into an empty memory store, as a restore imports it in one
/// store write, with every card read by `read_card`.
pub fn contact_backup_import(
    json: &str,
    network: Network,
    read_card: &CardReader<'_>,
) -> Result<ImportSummary, StoreError> {
    let store = MemoryStore::new(StoreKeys::from_bytes(
        [0; CONTEXT_KEY_LEN],
        [0; CONTEXT_KEY_LEN],
    ));
    store.write(|repos| import_contacts(repos, json, network, read_card))
}
