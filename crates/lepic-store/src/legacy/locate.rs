// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Portions Copyright 2023 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/backends/db.rs, impls/src/backends/lmdb.rs,
// impls/src/serialization.rs, libwallet/src/types.rs, libwallet/src/slate.rs (Apache-2.0); see
// NOTICE and upstream.toml.

use std::path::Path;

use super::LegacyDbLocation;

// Layout from epic-wallet `impls/src/backends/lmdb.rs` and `db.rs`: SQLite wallets (3.3 on) keep
// `wallet_data/db/sqlite/epic.db`; older wallets kept an LMDB environment in `wallet_data/db/lmdb`.
const WALLET_DATA_DIR: &str = "wallet_data";
const DB_DIR: &str = "db";
const SQLITE_DIR: &str = "sqlite";
const SQLITE_FILE: &str = "epic.db";
const LMDB_DIR: &str = "lmdb";

/// Finds the database of the wallet folder `wallet_dir`: the folder holding `wallet_data`, or
/// `wallet_data` itself. A SQLite database wins over an LMDB one left beside it, because upstream
/// starts a new SQLite database without migrating the LMDB data.
pub fn locate(wallet_dir: &Path) -> LegacyDbLocation {
    let nested = wallet_dir.join(WALLET_DATA_DIR);
    let data_dir = if nested.is_dir() {
        nested
    } else {
        wallet_dir.to_path_buf()
    };
    let db_dir = data_dir.join(DB_DIR);
    let sqlite = db_dir.join(SQLITE_DIR).join(SQLITE_FILE);
    if sqlite.is_file() {
        LegacyDbLocation::Sqlite { db: sqlite }
    } else if db_dir.join(LMDB_DIR).is_dir() {
        LegacyDbLocation::LmdbUnsupported
    } else {
        LegacyDbLocation::Missing
    }
}
