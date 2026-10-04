use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::OutputIdentifier;
use lepic_primitives::ser::{ProtocolVersion, deserialize};
use rusqlite::{Connection, OptionalExtension, Row, params};
use uuid::Uuid;

use crate::account::{AccountIndex, AccountRecord, AccountRepository};
use crate::context::{self, ContextKey, ContextRepository, ParticipantId, PrivateContext};
use crate::encoding::{timestamp_from_column, timestamp_to_column, u64_from_column, u64_to_column};
use crate::error::{Record, StoreError};
use crate::invoice::{
    self, InvoiceAddressIndex, InvoiceRepository, PendingInvoice, PendingInvoiceStatus,
};
use crate::output::{CommitmentBytes, KeyId, OutputRecord, OutputRepository, OutputStatus};
use crate::peer::{AllowedPeer, PeerCapability, PeerRepository, PeerSupport};
use crate::relay::{
    InboxEntry, InboxStatus, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
use crate::settings::SettingsRepository;
use crate::slate::{SlateRepository, SlateStage, StoredSlate};
use crate::transaction::{
    StoredTransaction, TransactionEntry, TransactionRepository, TxDirection, TxId, TxState,
};

/// The repositories over one open SQLite transaction.
pub(super) struct SqliteRepos<'a> {
    conn: &'a Connection,
    key: &'a ContextKey,
}

impl<'a> SqliteRepos<'a> {
    pub(super) fn new(conn: &'a Connection, key: &'a ContextKey) -> Self {
        Self { conn, key }
    }

    fn exists(&self, sql: &str, params: impl rusqlite::Params) -> Result<bool, StoreError> {
        Ok(self.conn.query_row(sql, params, |row| row.get(0))?)
    }

    fn require_account(&self, index: AccountIndex) -> Result<(), StoreError> {
        if self.exists(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE idx = ?1)",
            [i64::from(index.0)],
        )? {
            Ok(())
        } else {
            Err(StoreError::UnknownAccount(index))
        }
    }

    fn require_transaction(&self, id: TxId) -> Result<(), StoreError> {
        if self.exists(
            "SELECT EXISTS (SELECT 1 FROM transactions WHERE id = ?1)",
            [i64::from(id.0)],
        )? {
            Ok(())
        } else {
            Err(StoreError::UnknownTransaction(id))
        }
    }

    fn check_transaction(
        &self,
        id: Option<TxId>,
        entry: &TransactionEntry,
    ) -> Result<(), StoreError> {
        self.require_account(entry.account)?;
        let Some(slate_id) = entry.slate_id else {
            return Ok(());
        };
        let taken = self.exists(
            "SELECT EXISTS (SELECT 1 FROM transactions
                 WHERE slate_id = ?1 AND direction = ?2 AND id IS NOT ?3)",
            params![
                &slate_id.as_bytes()[..],
                entry.direction.code(),
                id.map(|id| i64::from(id.0)),
            ],
        )?;
        if taken {
            Err(StoreError::Duplicate {
                record: Record::Transaction,
            })
        } else {
            Ok(())
        }
    }

    fn collect<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        decode: impl Fn(&Row<'_>) -> Result<T, StoreError>,
    ) -> Result<Vec<T>, StoreError> {
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query(params)?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            items.push(decode(row)?);
        }
        Ok(items)
    }

    fn first<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        decode: impl Fn(&Row<'_>) -> Result<T, StoreError>,
    ) -> Result<Option<T>, StoreError> {
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query(params)?;
        rows.next()?.map(decode).transpose()
    }
}

const fn corrupt(record: Record, field: &'static str) -> StoreError {
    StoreError::Corrupt { record, field }
}

fn decode_u32(value: i64, record: Record, field: &'static str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| corrupt(record, field))
}

fn decode_uuid(bytes: &[u8], record: Record) -> Result<Uuid, StoreError> {
    Uuid::from_slice(bytes).map_err(|_| corrupt(record, "slate id"))
}

fn decode_code<T>(
    code: &str,
    parse: impl Fn(&str) -> Option<T>,
    record: Record,
    field: &'static str,
) -> Result<T, StoreError> {
    parse(code).ok_or(corrupt(record, field))
}

const ACCOUNT_COLUMNS: &str = "idx, label, next_child";

fn decode_account(row: &Row<'_>) -> Result<AccountRecord, StoreError> {
    let record = Record::Account;
    Ok(AccountRecord {
        index: AccountIndex(decode_u32(row.get(0)?, record, "index")?),
        label: row.get(1)?,
        next_child: decode_u32(row.get(2)?, record, "next child")?,
    })
}

impl AccountRepository for SqliteRepos<'_> {
    fn put_account(&mut self, account: &AccountRecord) -> Result<(), StoreError> {
        let index = i64::from(account.index.0);
        if self.exists(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE label = ?1 AND idx <> ?2)",
            params![account.label, index],
        )? {
            return Err(StoreError::LabelTaken);
        }
        self.conn.execute(
            "INSERT INTO accounts (idx, label, next_child) VALUES (?1, ?2, ?3)
             ON CONFLICT (idx) DO UPDATE SET label = excluded.label, next_child = excluded.next_child",
            params![index, account.label, i64::from(account.next_child)],
        )?;
        Ok(())
    }

    fn account(&self, index: AccountIndex) -> Result<Option<AccountRecord>, StoreError> {
        self.first(
            &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE idx = ?1"),
            [i64::from(index.0)],
            decode_account,
        )
    }

    fn account_by_label(&self, label: &str) -> Result<Option<AccountRecord>, StoreError> {
        self.first(
            &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE label = ?1"),
            [label],
            decode_account,
        )
    }

    fn accounts(&self) -> Result<Vec<AccountRecord>, StoreError> {
        self.collect(
            &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts ORDER BY idx"),
            [],
            decode_account,
        )
    }
}

const OUTPUT_COLUMNS: &str =
    "commitment, features, key_id, account, amount, status, height, lock_height, mmr_index, tx_id";

fn decode_output(row: &Row<'_>) -> Result<OutputRecord, StoreError> {
    let record = Record::Output;
    let commitment: Vec<u8> = row.get(0)?;
    let features: i64 = row.get(1)?;
    let mut identifier = vec![u8::try_from(features).map_err(|_| corrupt(record, "features"))?];
    identifier.extend_from_slice(&commitment);
    let key_id: Vec<u8> = row.get(2)?;
    let status: String = row.get(5)?;
    let tx_id: Option<i64> = row.get(9)?;
    Ok(OutputRecord {
        id: deserialize::<OutputIdentifier>(&identifier, ProtocolVersion::V1)
            .map_err(|_| corrupt(record, "identifier"))?,
        key_id: KeyId(
            key_id
                .as_slice()
                .try_into()
                .map_err(|_| corrupt(record, "key id"))?,
        ),
        account: AccountIndex(decode_u32(row.get(3)?, record, "account")?),
        amount: Amount::new(u64_from_column(row.get(4)?)),
        status: decode_code(&status, OutputStatus::from_code, record, "status")?,
        height: Height::new(u64_from_column(row.get(6)?)),
        lock_height: Height::new(u64_from_column(row.get(7)?)),
        mmr_index: row.get::<_, Option<i64>>(8)?.map(u64_from_column),
        tx: tx_id
            .map(|id| decode_u32(id, record, "transaction").map(TxId))
            .transpose()?,
    })
}

impl OutputRepository for SqliteRepos<'_> {
    fn put_output(&mut self, output: &OutputRecord) -> Result<(), StoreError> {
        self.require_account(output.account)?;
        if let Some(tx) = output.tx {
            self.require_transaction(tx)?;
        }
        self.conn.execute(
            &format!(
                "INSERT INTO outputs ({OUTPUT_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (commitment) DO UPDATE SET
                     features = excluded.features, key_id = excluded.key_id,
                     account = excluded.account, amount = excluded.amount,
                     status = excluded.status, height = excluded.height,
                     lock_height = excluded.lock_height, mmr_index = excluded.mmr_index,
                     tx_id = excluded.tx_id"
            ),
            params![
                &output.commitment()[..],
                output.id.features.as_u8(),
                &output.key_id.0[..],
                i64::from(output.account.0),
                u64_to_column(output.amount.value()),
                output.status.code(),
                u64_to_column(output.height.value()),
                u64_to_column(output.lock_height.value()),
                output.mmr_index.map(u64_to_column),
                output.tx.map(|tx| i64::from(tx.0)),
            ],
        )?;
        Ok(())
    }

    fn output(&self, commitment: &CommitmentBytes) -> Result<Option<OutputRecord>, StoreError> {
        self.first(
            &format!("SELECT {OUTPUT_COLUMNS} FROM outputs WHERE commitment = ?1"),
            [&commitment[..]],
            decode_output,
        )
    }

    fn outputs(
        &self,
        account: AccountIndex,
        status: Option<OutputStatus>,
    ) -> Result<Vec<OutputRecord>, StoreError> {
        self.collect(
            &format!(
                "SELECT {OUTPUT_COLUMNS} FROM outputs
                 WHERE account = ?1 AND (?2 IS NULL OR status = ?2) ORDER BY commitment"
            ),
            params![i64::from(account.0), status.map(OutputStatus::code)],
            decode_output,
        )
    }

    fn outputs_of_transaction(&self, tx: TxId) -> Result<Vec<OutputRecord>, StoreError> {
        self.collect(
            &format!("SELECT {OUTPUT_COLUMNS} FROM outputs WHERE tx_id = ?1 ORDER BY commitment"),
            [i64::from(tx.0)],
            decode_output,
        )
    }

    fn delete_output(&mut self, commitment: &CommitmentBytes) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM outputs WHERE commitment = ?1",
            [&commitment[..]],
        )?;
        Ok(())
    }
}

const TRANSACTION_COLUMNS: &str = "id, account, direction, state, slate_id, transport, \
     amount_credited, amount_debited, fee, created_at, updated_at";

fn decode_transaction(row: &Row<'_>) -> Result<StoredTransaction, StoreError> {
    let record = Record::Transaction;
    let direction: String = row.get(2)?;
    let state: String = row.get(3)?;
    let slate_id: Option<Vec<u8>> = row.get(4)?;
    Ok(StoredTransaction {
        id: TxId(decode_u32(row.get(0)?, record, "id")?),
        entry: TransactionEntry {
            account: AccountIndex(decode_u32(row.get(1)?, record, "account")?),
            direction: decode_code(&direction, TxDirection::from_code, record, "direction")?,
            state: decode_code(&state, TxState::from_code, record, "state")?,
            slate_id: slate_id
                .map(|bytes| decode_uuid(&bytes, record))
                .transpose()?,
            transport: row.get(5)?,
            amount_credited: Amount::new(u64_from_column(row.get(6)?)),
            amount_debited: Amount::new(u64_from_column(row.get(7)?)),
            fee: row
                .get::<_, Option<i64>>(8)?
                .map(|fee| Fee::new(u64_from_column(fee))),
            created_at: timestamp_from_column(row.get(9)?, record, "created at")?,
            updated_at: timestamp_from_column(row.get(10)?, record, "updated at")?,
        },
    })
}

impl SqliteRepos<'_> {
    fn write_transaction(
        &self,
        sql: &str,
        id: TxId,
        entry: &TransactionEntry,
    ) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            sql,
            params![
                i64::from(id.0),
                i64::from(entry.account.0),
                entry.direction.code(),
                entry.state.code(),
                entry.slate_id.as_ref().map(|id| &id.as_bytes()[..]),
                entry.transport,
                u64_to_column(entry.amount_credited.value()),
                u64_to_column(entry.amount_debited.value()),
                entry.fee.map(|fee| u64_to_column(fee.value())),
                timestamp_to_column(entry.created_at)?,
                timestamp_to_column(entry.updated_at)?,
            ],
        )?)
    }
}

impl TransactionRepository for SqliteRepos<'_> {
    fn insert_transaction(&mut self, entry: &TransactionEntry) -> Result<TxId, StoreError> {
        self.check_transaction(None, entry)?;
        let last: Option<i64> =
            self.conn
                .query_row("SELECT MAX(id) FROM transactions", [], |row| row.get(0))?;
        let id = match last {
            None => Some(1),
            Some(last) => u32::try_from(last)
                .ok()
                .and_then(|last| last.checked_add(1)),
        }
        .map(TxId)
        .ok_or(StoreError::OutOfRange {
            field: "transaction id",
        })?;
        self.write_transaction(
            &format!(
                "INSERT INTO transactions ({TRANSACTION_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
            ),
            id,
            entry,
        )?;
        Ok(id)
    }

    fn update_transaction(&mut self, id: TxId, entry: &TransactionEntry) -> Result<(), StoreError> {
        if !self.exists(
            "SELECT EXISTS (SELECT 1 FROM transactions WHERE id = ?1)",
            [i64::from(id.0)],
        )? {
            return Err(StoreError::NotFound {
                record: Record::Transaction,
            });
        }
        self.check_transaction(Some(id), entry)?;
        self.write_transaction(
            "UPDATE transactions SET account = ?2, direction = ?3, state = ?4, slate_id = ?5,
                 transport = ?6, amount_credited = ?7, amount_debited = ?8, fee = ?9,
                 created_at = ?10, updated_at = ?11
             WHERE id = ?1",
            id,
            entry,
        )?;
        Ok(())
    }

    fn transaction(&self, id: TxId) -> Result<Option<TransactionEntry>, StoreError> {
        Ok(self
            .first(
                &format!("SELECT {TRANSACTION_COLUMNS} FROM transactions WHERE id = ?1"),
                [i64::from(id.0)],
                decode_transaction,
            )?
            .map(|stored| stored.entry))
    }

    fn delete_transaction(&mut self, id: TxId) -> Result<(), StoreError> {
        let linked: bool = self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM outputs WHERE tx_id = ?1)",
            [i64::from(id.0)],
            |row| row.get(0),
        )?;
        if linked {
            return Err(StoreError::InUse {
                record: Record::Transaction,
            });
        }
        let deleted = self
            .conn
            .execute("DELETE FROM transactions WHERE id = ?1", [i64::from(id.0)])?;
        if deleted == 0 {
            return Err(StoreError::UnknownTransaction(id));
        }
        Ok(())
    }

    fn transaction_by_slate(
        &self,
        slate_id: Uuid,
        direction: TxDirection,
    ) -> Result<Option<StoredTransaction>, StoreError> {
        self.first(
            &format!(
                "SELECT {TRANSACTION_COLUMNS} FROM transactions
                 WHERE slate_id = ?1 AND direction = ?2"
            ),
            params![&slate_id.as_bytes()[..], direction.code()],
            decode_transaction,
        )
    }

    fn transactions(&self, account: AccountIndex) -> Result<Vec<StoredTransaction>, StoreError> {
        self.collect(
            &format!(
                "SELECT {TRANSACTION_COLUMNS} FROM transactions WHERE account = ?1 ORDER BY id"
            ),
            [i64::from(account.0)],
            decode_transaction,
        )
    }

    fn set_confirmed_height(&mut self, id: TxId, height: Height) -> Result<(), StoreError> {
        let updated = self.conn.execute(
            "UPDATE transactions SET confirmed_height = ?2 WHERE id = ?1",
            params![i64::from(id.0), u64_to_column(height.value())],
        )?;
        if updated == 0 {
            return Err(StoreError::UnknownTransaction(id));
        }
        Ok(())
    }

    fn confirmed_height(&self, id: TxId) -> Result<Option<Height>, StoreError> {
        let height: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT confirmed_height FROM transactions WHERE id = ?1",
                [i64::from(id.0)],
                |row| row.get(0),
            )
            .optional()?;
        Ok(height
            .flatten()
            .map(|height| Height::new(u64_from_column(height))))
    }

    fn set_counterparty(&mut self, id: TxId, address: &str) -> Result<(), StoreError> {
        let updated = self.conn.execute(
            "UPDATE transactions SET counterparty = ?2 WHERE id = ?1",
            params![i64::from(id.0), address],
        )?;
        if updated == 0 {
            return Err(StoreError::UnknownTransaction(id));
        }
        Ok(())
    }

    fn counterparty(&self, id: TxId) -> Result<Option<String>, StoreError> {
        let address: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT counterparty FROM transactions WHERE id = ?1",
                [i64::from(id.0)],
                |row| row.get(0),
            )
            .optional()?;
        Ok(address.flatten())
    }
}

const SLATE_COLUMNS: &str = "slate_id, stage, codec, bytes";

fn decode_slate(row: &Row<'_>) -> Result<StoredSlate, StoreError> {
    let record = Record::Slate;
    let slate_id: Vec<u8> = row.get(0)?;
    let stage: String = row.get(1)?;
    Ok(StoredSlate {
        slate_id: decode_uuid(&slate_id, record)?,
        stage: decode_code(&stage, SlateStage::from_code, record, "stage")?,
        codec: row.get(2)?,
        bytes: row.get(3)?,
    })
}

impl SlateRepository for SqliteRepos<'_> {
    fn insert_slate(&mut self, slate: &StoredSlate) -> Result<(), StoreError> {
        let slate_id = &slate.slate_id.as_bytes()[..];
        if self.exists(
            "SELECT EXISTS (SELECT 1 FROM slates WHERE slate_id = ?1 AND stage = ?2)",
            params![slate_id, slate.stage.code()],
        )? {
            return Err(StoreError::Duplicate {
                record: Record::Slate,
            });
        }
        self.conn.execute(
            &format!("INSERT INTO slates ({SLATE_COLUMNS}) VALUES (?1, ?2, ?3, ?4)"),
            params![slate_id, slate.stage.code(), slate.codec, slate.bytes],
        )?;
        Ok(())
    }

    fn slate(&self, slate_id: Uuid, stage: SlateStage) -> Result<Option<StoredSlate>, StoreError> {
        self.first(
            &format!("SELECT {SLATE_COLUMNS} FROM slates WHERE slate_id = ?1 AND stage = ?2"),
            params![&slate_id.as_bytes()[..], stage.code()],
            decode_slate,
        )
    }

    fn slates(&self, slate_id: Uuid) -> Result<Vec<StoredSlate>, StoreError> {
        self.collect(
            &format!("SELECT {SLATE_COLUMNS} FROM slates WHERE slate_id = ?1 ORDER BY stage"),
            [&slate_id.as_bytes()[..]],
            decode_slate,
        )
    }
}

impl ContextRepository for SqliteRepos<'_> {
    fn put_context(
        &mut self,
        slate_id: Uuid,
        participant: ParticipantId,
        context: &PrivateContext,
    ) -> Result<(), StoreError> {
        let sealed = context::seal(self.key, slate_id, participant, context)?;
        self.conn.execute(
            "INSERT INTO private_contexts (slate_id, participant, sealed) VALUES (?1, ?2, ?3)
             ON CONFLICT (slate_id, participant) DO UPDATE SET sealed = excluded.sealed",
            params![&slate_id.as_bytes()[..], participant.0, sealed],
        )?;
        Ok(())
    }

    fn context(
        &self,
        slate_id: Uuid,
        participant: ParticipantId,
    ) -> Result<Option<PrivateContext>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sealed FROM private_contexts WHERE slate_id = ?1 AND participant = ?2",
                params![&slate_id.as_bytes()[..], participant.0],
                |row| row.get(0),
            )
            .optional()?;
        sealed
            .map(|sealed| context::open(self.key, slate_id, participant, &sealed))
            .transpose()
    }

    fn delete_context(
        &mut self,
        slate_id: Uuid,
        participant: ParticipantId,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM private_contexts WHERE slate_id = ?1 AND participant = ?2",
            params![&slate_id.as_bytes()[..], participant.0],
        )?;
        Ok(())
    }
}

fn decode_inbox(row: &Row<'_>) -> Result<InboxEntry, StoreError> {
    let record = Record::InboxMessage;
    let status: String = row.get(1)?;
    Ok(InboxEntry {
        msg_id: row.get(0)?,
        status: decode_code(&status, InboxStatus::from_code, record, "status")?,
        received_at: timestamp_from_column(row.get(2)?, record, "received at")?,
        updated_at: timestamp_from_column(row.get(3)?, record, "updated at")?,
    })
}

const OUTBOX_COLUMNS: &str =
    "id, transport, destination, slate_id, stage, status, attempts, created_at, updated_at";

fn decode_outbox(row: &Row<'_>) -> Result<StoredOutbox, StoreError> {
    let record = Record::OutboxMessage;
    let id: i64 = row.get(0)?;
    let slate_id: Vec<u8> = row.get(3)?;
    let stage: String = row.get(4)?;
    let status: String = row.get(5)?;
    Ok(StoredOutbox {
        id: OutboxId(u64::try_from(id).map_err(|_| corrupt(record, "id"))?),
        entry: OutboxEntry {
            transport: row.get(1)?,
            destination: row.get(2)?,
            slate_id: decode_uuid(&slate_id, record)?,
            stage: decode_code(&stage, SlateStage::from_code, record, "stage")?,
            status: decode_code(&status, OutboxStatus::from_code, record, "status")?,
            attempts: decode_u32(row.get(6)?, record, "attempts")?,
            created_at: timestamp_from_column(row.get(7)?, record, "created at")?,
            updated_at: timestamp_from_column(row.get(8)?, record, "updated at")?,
        },
    })
}

fn outbox_id_column(id: OutboxId) -> Result<i64, StoreError> {
    i64::try_from(id.0).map_err(|_| StoreError::OutOfRange { field: "outbox id" })
}

impl RelayRepository for SqliteRepos<'_> {
    fn put_inbox(&mut self, entry: &InboxEntry) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO relay_inbox (msg_id, status, received_at, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (msg_id) DO UPDATE SET status = excluded.status,
                 received_at = excluded.received_at, updated_at = excluded.updated_at",
            params![
                entry.msg_id,
                entry.status.code(),
                timestamp_to_column(entry.received_at)?,
                timestamp_to_column(entry.updated_at)?,
            ],
        )?;
        Ok(())
    }

    fn inbox(&self, msg_id: &str) -> Result<Option<InboxEntry>, StoreError> {
        self.first(
            "SELECT msg_id, status, received_at, updated_at FROM relay_inbox WHERE msg_id = ?1",
            [msg_id],
            decode_inbox,
        )
    }

    fn prune_inbox(&mut self, received_before: Timestamp) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM relay_inbox WHERE received_at < ?1",
            [timestamp_to_column(received_before)?],
        )?)
    }

    fn enqueue_outbox(&mut self, entry: &OutboxEntry) -> Result<OutboxId, StoreError> {
        self.conn.execute(
            "INSERT INTO relay_outbox (transport, destination, slate_id, stage, status, attempts,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.transport,
                entry.destination,
                &entry.slate_id.as_bytes()[..],
                entry.stage.code(),
                entry.status.code(),
                i64::from(entry.attempts),
                timestamp_to_column(entry.created_at)?,
                timestamp_to_column(entry.updated_at)?,
            ],
        )?;
        u64::try_from(self.conn.last_insert_rowid())
            .map(OutboxId)
            .map_err(|_| corrupt(Record::OutboxMessage, "id"))
    }

    fn update_outbox(&mut self, id: OutboxId, entry: &OutboxEntry) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE relay_outbox SET transport = ?2, destination = ?3, slate_id = ?4, stage = ?5,
                 status = ?6, attempts = ?7, created_at = ?8, updated_at = ?9
             WHERE id = ?1",
            params![
                outbox_id_column(id)?,
                entry.transport,
                entry.destination,
                &entry.slate_id.as_bytes()[..],
                entry.stage.code(),
                entry.status.code(),
                i64::from(entry.attempts),
                timestamp_to_column(entry.created_at)?,
                timestamp_to_column(entry.updated_at)?,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                record: Record::OutboxMessage,
            });
        }
        Ok(())
    }

    fn outbox(&self, status: OutboxStatus) -> Result<Vec<StoredOutbox>, StoreError> {
        self.collect(
            &format!("SELECT {OUTBOX_COLUMNS} FROM relay_outbox WHERE status = ?1 ORDER BY id"),
            [status.code()],
            decode_outbox,
        )
    }

    fn delete_outbox(&mut self, id: OutboxId) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM relay_outbox WHERE id = ?1",
            [outbox_id_column(id)?],
        )?;
        Ok(())
    }
}

impl SettingsRepository for SqliteRepos<'_> {
    fn put_setting(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    fn delete_setting(&mut self, key: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }
}

const PENDING_INVOICE_COLUMNS: &str =
    "slate_id, sender_key, sender_address, received_at, status, codec, sealed";

impl SqliteRepos<'_> {
    fn decode_pending_invoice(&self, row: &Row<'_>) -> Result<PendingInvoice, StoreError> {
        let record = Record::PendingInvoice;
        let slate_id: Vec<u8> = row.get(0)?;
        let slate_id = decode_uuid(&slate_id, record)?;
        let sender_key: String = row.get(1)?;
        let status: String = row.get(4)?;
        let sealed: Vec<u8> = row.get(6)?;
        Ok(PendingInvoice {
            slate_id,
            bytes: invoice::open(self.key, slate_id, &sender_key, &sealed)?,
            sender_key,
            sender_address: row.get(2)?,
            received_at: timestamp_from_column(row.get(3)?, record, "received at")?,
            status: decode_code(&status, PendingInvoiceStatus::from_code, record, "status")?,
            codec: row.get(5)?,
        })
    }

    fn count(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize, StoreError> {
        let count: i64 = self.conn.query_row(sql, params, |row| row.get(0))?;
        usize::try_from(count).map_err(|_| corrupt(Record::PendingInvoice, "count"))
    }
}

impl InvoiceRepository for SqliteRepos<'_> {
    fn park_invoice(&mut self, invoice: &PendingInvoice) -> Result<(), StoreError> {
        let slate_id = &invoice.slate_id.as_bytes()[..];
        if self.exists(
            "SELECT EXISTS (SELECT 1 FROM pending_invoices WHERE slate_id = ?1)",
            [slate_id],
        )? {
            return Err(StoreError::Duplicate {
                record: Record::PendingInvoice,
            });
        }
        let parked = PendingInvoiceStatus::Parked.code();
        invoice::check_caps(
            invoice,
            self.count(
                "SELECT COUNT(*) FROM pending_invoices WHERE status = ?1",
                [parked],
            )?,
            self.count(
                "SELECT COUNT(*) FROM pending_invoices WHERE status = ?1 AND sender_key = ?2",
                [parked, invoice.sender_key.as_str()],
            )?,
        )?;
        let sealed = invoice::seal(self.key, invoice)?;
        self.conn.execute(
            &format!(
                "INSERT INTO pending_invoices ({PENDING_INVOICE_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            ),
            params![
                slate_id,
                invoice.sender_key,
                invoice.sender_address,
                timestamp_to_column(invoice.received_at)?,
                invoice.status.code(),
                invoice.codec,
                sealed,
            ],
        )?;
        Ok(())
    }

    fn pending_invoice(&self, slate_id: Uuid) -> Result<Option<PendingInvoice>, StoreError> {
        self.first(
            &format!("SELECT {PENDING_INVOICE_COLUMNS} FROM pending_invoices WHERE slate_id = ?1"),
            [&slate_id.as_bytes()[..]],
            |row| self.decode_pending_invoice(row),
        )
    }

    fn pending_invoices(&self) -> Result<Vec<PendingInvoice>, StoreError> {
        self.collect(
            &format!(
                "SELECT {PENDING_INVOICE_COLUMNS} FROM pending_invoices
                 ORDER BY received_at, slate_id"
            ),
            [],
            |row| self.decode_pending_invoice(row),
        )
    }

    fn set_pending_invoice_status(
        &mut self,
        slate_id: Uuid,
        status: PendingInvoiceStatus,
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE pending_invoices SET status = ?2 WHERE slate_id = ?1",
            params![&slate_id.as_bytes()[..], status.code()],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                record: Record::PendingInvoice,
            });
        }
        Ok(())
    }

    fn delete_pending_invoice(&mut self, slate_id: Uuid) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM pending_invoices WHERE slate_id = ?1",
            [&slate_id.as_bytes()[..]],
        )?;
        Ok(())
    }

    fn prune_parked_invoices(&mut self, received_before: Timestamp) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM pending_invoices WHERE status = ?1 AND received_at < ?2",
            params![
                PendingInvoiceStatus::Parked.code(),
                timestamp_to_column(received_before)?,
            ],
        )?)
    }

    fn invoice_address_index(&self) -> Result<Option<InvoiceAddressIndex>, StoreError> {
        let index: Option<i64> = self
            .conn
            .query_row("SELECT idx FROM invoice_address WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        index
            .map(|index| {
                u32::try_from(index)
                    .ok()
                    .and_then(InvoiceAddressIndex::new)
                    .ok_or(corrupt(Record::InvoiceAddress, "index"))
            })
            .transpose()
    }

    fn set_invoice_address_index(&mut self, index: InvoiceAddressIndex) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO invoice_address (id, idx) VALUES (1, ?1)
             ON CONFLICT (id) DO UPDATE SET idx = excluded.idx",
            [i64::from(index.get())],
        )?;
        Ok(())
    }
}

const ALLOWED_PEER_COLUMNS: &str = "key, address, label, added_at";

fn decode_allowed_peer(row: &Row<'_>) -> Result<AllowedPeer, StoreError> {
    Ok(AllowedPeer {
        key: row.get(0)?,
        address: row.get(1)?,
        label: row.get(2)?,
        added_at: timestamp_from_column(row.get(3)?, Record::AllowedPeer, "added at")?,
    })
}

fn decode_peer_capability(row: &Row<'_>) -> Result<PeerCapability, StoreError> {
    let record = Record::PeerCapability;
    let support: String = row.get(1)?;
    Ok(PeerCapability {
        key: row.get(0)?,
        support: decode_code(&support, PeerSupport::from_code, record, "support")?,
        learned_at: timestamp_from_column(row.get(2)?, record, "learned at")?,
    })
}

impl PeerRepository for SqliteRepos<'_> {
    fn put_allowed_peer(&mut self, peer: &AllowedPeer) -> Result<(), StoreError> {
        self.conn.execute(
            &format!(
                "INSERT INTO allowed_peers ({ALLOWED_PEER_COLUMNS}) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (key) DO UPDATE SET address = excluded.address,
                     label = excluded.label, added_at = excluded.added_at"
            ),
            params![
                peer.key,
                peer.address,
                peer.label,
                timestamp_to_column(peer.added_at)?,
            ],
        )?;
        Ok(())
    }

    fn allowed_peer(&self, key: &str) -> Result<Option<AllowedPeer>, StoreError> {
        self.first(
            &format!("SELECT {ALLOWED_PEER_COLUMNS} FROM allowed_peers WHERE key = ?1"),
            [key],
            decode_allowed_peer,
        )
    }

    fn allowed_peers(&self) -> Result<Vec<AllowedPeer>, StoreError> {
        self.collect(
            &format!("SELECT {ALLOWED_PEER_COLUMNS} FROM allowed_peers ORDER BY added_at, key"),
            [],
            decode_allowed_peer,
        )
    }

    fn remove_allowed_peer(&mut self, key: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM allowed_peers WHERE key = ?1", [key])?
            > 0)
    }

    fn put_peer_capability(&mut self, capability: &PeerCapability) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO peer_capabilities (key, support, learned_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (key) DO UPDATE SET support = excluded.support,
                 learned_at = excluded.learned_at",
            params![
                capability.key,
                capability.support.code(),
                timestamp_to_column(capability.learned_at)?,
            ],
        )?;
        Ok(())
    }

    fn peer_capability(&self, key: &str) -> Result<Option<PeerCapability>, StoreError> {
        self.first(
            "SELECT key, support, learned_at FROM peer_capabilities WHERE key = ?1",
            [key],
            decode_peer_capability,
        )
    }
}
