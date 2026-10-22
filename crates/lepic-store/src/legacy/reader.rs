use std::path::Path;

use rusqlite::config::DbConfig;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, params};

use super::rows::{self, RowRejection};
use super::{LegacyDbError, LegacyHistory, LegacyLimits, LegacyRecord, LegacySkipped};

/// A derivation counter key is `d:` and 17 bytes, about ninety characters as upstream stores it.
const MAX_KEY_TEXT_BYTES: i64 = 512;

// Prefixes from epic-wallet `impls/src/backends/lmdb.rs`. Rows under any other prefix are never
// read: `p` holds private transaction contexts.
const ACCOUNT_PREFIX: &str = "a";
const DERIVATION_PREFIX: &str = "d";
const TX_LOG_PREFIX: &str = "t";
const OUTPUT_PREFIX: &str = "o";

pub(super) fn read(
    db: &Path,
    source_fingerprint: [u8; 32],
    limits: &LegacyLimits,
) -> Result<LegacyHistory, LegacyDbError> {
    let conn = open(db)?;
    check_table(&conn)?;
    let mut skipped = LegacySkipped::default();
    let mut scan = Scan {
        conn: &conn,
        max_row_bytes: i64::try_from(limits.max_row_bytes).unwrap_or(i64::MAX),
        skipped: &mut skipped,
    };

    let mut accounts = scan.rows(
        ACCOUNT_PREFIX,
        LegacyRecord::Account,
        limits.max_accounts,
        |_, data| rows::parse_account(data),
    )?;
    let mut next_child = scan.rows(
        DERIVATION_PREFIX,
        LegacyRecord::ChildCounter,
        limits.max_accounts,
        |key, data| rows::parse_counter(key.ok_or(RowRejection::RowKey)?, data),
    )?;
    let mut transactions = scan.rows(
        TX_LOG_PREFIX,
        LegacyRecord::Transaction,
        limits.max_transactions,
        |_, data| rows::parse_transaction(data),
    )?;
    let mut outputs = scan.rows(
        OUTPUT_PREFIX,
        LegacyRecord::Output,
        limits.max_outputs,
        |_, data| rows::parse_output(data),
    )?;

    accounts.sort_by(|a, b| (a.path.0, &a.label).cmp(&(b.path.0, &b.label)));
    next_child.sort_by_key(|counter| (counter.parent.0, counter.next_child));
    transactions.sort_by_key(|tx| (tx.parent_key_id.0, tx.id));
    outputs.sort_by(|a, b| {
        (
            a.key_id.0,
            a.mmr_index,
            a.root_key_id.0,
            a.commitment,
            a.n_child,
        )
            .cmp(&(
                b.key_id.0,
                b.mmr_index,
                b.root_key_id.0,
                b.commitment,
                b.n_child,
            ))
    });

    Ok(LegacyHistory {
        accounts,
        transactions,
        outputs,
        next_child,
        skipped,
        source_fingerprint,
    })
}

/// Opens a private copy. Read-write so SQLite can replay a write-ahead log copied beside it; the
/// schema is treated as untrusted.
fn open(db: &Path) -> Result<Connection, LegacyDbError> {
    if !db.is_file() {
        return Err(LegacyDbError::NotFound);
    }
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.pragma_update(None, "cell_size_check", true)?;
    // Reading the schema is the first access to the file, where a non-database fails.
    conn.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(conn)
}

/// Upstream creates `data (id, key, prefix, data, q_tx_id, q_confirmed, q_tx_status)`; the
/// import needs the table and the three columns it reads.
fn check_table(conn: &Connection) -> Result<(), LegacyDbError> {
    let columns: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_schema AS s, pragma_table_info(s.name) AS c
         WHERE s.type = 'table' AND s.name = 'data' AND c.name IN ('key', 'prefix', 'data')",
        [],
        |row| row.get(0),
    )?;
    if columns == 3 {
        Ok(())
    } else {
        Err(LegacyDbError::MissingTable)
    }
}

struct Scan<'a> {
    conn: &'a Connection,
    max_row_bytes: i64,
    skipped: &'a mut LegacySkipped,
}

impl Scan<'_> {
    /// Streams the rows under `prefix`, refusing the whole import above `limit` rows. Oversized
    /// rows are counted in SQL and never loaded.
    fn rows<T>(
        &mut self,
        prefix: &str,
        record: LegacyRecord,
        limit: usize,
        parse: impl Fn(Option<&[u8]>, &[u8]) -> Result<T, RowRejection>,
    ) -> Result<Vec<T>, LegacyDbError> {
        let found: i64 = self.conn.query_row(
            "SELECT count(*) FROM data WHERE prefix = ?1",
            [prefix],
            |row| row.get(0),
        )?;
        let found = u64::try_from(found).unwrap_or(0);
        if found > u64::try_from(limit).unwrap_or(u64::MAX) {
            return Err(LegacyDbError::TooMany {
                record,
                found,
                limit,
            });
        }

        let fits = "coalesce(octet_length(data), 0) <= ?2
                    AND coalesce(octet_length(key), 0) <= ?3";
        let oversized: i64 = self.conn.query_row(
            &format!("SELECT count(*) FROM data WHERE prefix = ?1 AND NOT ({fits})"),
            params![prefix, self.max_row_bytes, MAX_KEY_TEXT_BYTES],
            |row| row.get(0),
        )?;
        if oversized > 0 {
            let oversized = u32::try_from(oversized).unwrap_or(u32::MAX);
            self.skipped.count(record, oversized);
            log_skipped(record, RowRejection::TooLarge);
        }

        let mut statement = self.conn.prepare(&format!(
            "SELECT key, data FROM data WHERE prefix = ?1 AND {fits}"
        ))?;
        let mut cursor =
            statement.query(params![prefix, self.max_row_bytes, MAX_KEY_TEXT_BYTES])?;
        let capacity = usize::try_from(found).unwrap_or(0).min(4096);
        let mut records = Vec::with_capacity(capacity);
        while let Some(row) = cursor.next()? {
            let key = text(row.get_ref(0)?);
            let parsed = match text(row.get_ref(1)?) {
                Some(data) => parse(key, data),
                None => Err(RowRejection::NotText),
            };
            match parsed {
                Ok(parsed) => records.push(parsed),
                Err(rejection) => {
                    self.skipped.count(record, 1);
                    log_skipped(record, rejection);
                }
            }
        }
        Ok(records)
    }
}

fn log_skipped(record: LegacyRecord, rejection: RowRejection) {
    match record {
        LegacyRecord::Account => tracing::debug!(error = %rejection, "legacy account row skipped"),
        LegacyRecord::Transaction => {
            tracing::debug!(error = %rejection, "legacy transaction row skipped");
        }
        LegacyRecord::Output => tracing::debug!(error = %rejection, "legacy output row skipped"),
        LegacyRecord::ChildCounter => {
            tracing::debug!(error = %rejection, "legacy derivation counter row skipped");
        }
    }
}

fn text(value: ValueRef<'_>) -> Option<&[u8]> {
    match value {
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => Some(bytes),
        ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) => None,
    }
}
