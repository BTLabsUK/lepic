// SPDX-License-Identifier: Apache-2.0
use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::OutputIdentifier;
use lepic_primitives::ser::{ProtocolVersion, deserialize};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, params};
use uuid::Uuid;

use crate::account::{AccountIndex, AccountRecord, AccountRepository};
use crate::api_log::{self, ApiEvent, ApiLogRepository, ApiRequest, KindPattern};
use crate::contact::{
    self, CARD_KEY_LEN, ContactCap, ContactId, ContactKind, ContactMailbox, ContactRecord,
    ContactRepository, ContactState, DomainClaimBytes, INVITE_ID_LEN, MAX_CANCELLED_PAIRINGS,
    MAX_CONTACTS, MAX_PENDING_PAIRINGS, PAYMENTS_KEY_LEN, PairingEndReason, PairingFacts,
    PairingId, PairingRole, PairingState, PeerCard, PendingPairing, PreviousHome, RelayBackoff,
    SealMode,
};
use crate::context::{
    self, ContextKey, ContextRepository, ParticipantId, PrivateContext, StoreKeys,
};
use crate::delivery::{
    self, CopyState, MailClass, NativeOutboxEntry, NativeOutboxId, NativeOutboxRepository,
    OutboxCopy, OutboxState, PaymentDelivery, PaymentDeliveryRepository, StoredNativeOutbox,
    StoredOutboxCopy, WatchRow, WatchSetRepository,
};
use crate::encoding::{timestamp_from_column, timestamp_to_column, u64_from_column, u64_to_column};
use crate::error::{Record, StoreError};
use crate::imported::{
    self, ChainCheck, ImportedKind, ImportedMessage, ImportedOutput, ImportedOutputStatus,
    ImportedRepository, ImportedTransaction,
};
use crate::invoice::{self, InvoiceRepository, PendingInvoice, PendingInvoiceStatus};
use crate::node_post::{self, NodeOutcome, NodePost, NodePostRepository};
use crate::output::{CommitmentBytes, KeyId, OutputRecord, OutputRepository, OutputStatus};
use crate::recovery::{self, Recovery, RecoveryRepository, RecoveryState};
use crate::relay::{
    InboxEntry, InboxStatus, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
use crate::settings::SettingsRepository;
use crate::slate::{SlateRepository, SlateStage, StoredSlate};
use crate::transaction::{
    OpenReceipt, StateTally, StoredTransaction, TransactionEntry, TransactionRepository,
    TxDirection, TxId, TxState, next_transaction_id,
};
use crate::tx_record::{
    FoundDuring, OtherWalletSpend, ScanFoundRecord, TxMarks, TxRecordRepository, TxWatch,
    WatchPhase, WatchedOutput,
};

/// The repositories over one open SQLite transaction.
pub(super) struct SqliteRepos<'a> {
    conn: &'a Connection,
    key: &'a ContextKey,
}

impl<'a> SqliteRepos<'a> {
    pub(super) fn new(conn: &'a Connection, keys: &'a StoreKeys) -> Self {
        Self {
            conn,
            key: &keys.context,
        }
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

    fn insert_output(&mut self, output: &OutputRecord) -> Result<(), StoreError> {
        if self.output(output.commitment())?.is_some() {
            return Err(StoreError::Duplicate {
                record: Record::Output,
            });
        }
        self.put_output(output)
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

    fn touch_output(&mut self, commitment: &CommitmentBytes) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE outputs SET touched = (SELECT MAX(touched) + 1 FROM outputs)
             WHERE commitment = ?1",
            [&commitment[..]],
        )?;
        Ok(())
    }

    fn outputs_by_touch(&self, status: OutputStatus) -> Result<Vec<OutputRecord>, StoreError> {
        self.collect(
            &format!(
                "SELECT {OUTPUT_COLUMNS} FROM outputs WHERE status = ?1
                 ORDER BY touched, commitment"
            ),
            [status.code()],
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
    /// Drops the settings kept beside contact `id` once neither the contact nor a pairing in
    /// progress for it is stored.
    fn forget_unused_extras(&mut self, id: ContactId) -> Result<(), StoreError> {
        let used = self.exists(
            "SELECT EXISTS (SELECT 1 FROM contacts WHERE contact_id = ?1)
                 OR EXISTS (SELECT 1 FROM pairings WHERE contact_id = ?1)",
            [&id.0[..]],
        )?;
        if !used {
            self.conn.execute(
                "DELETE FROM settings WHERE substr(key, 1, length(?1)) = ?1",
                [contact::contact_extras_prefix(id)],
            )?;
        }
        Ok(())
    }

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
        let in_table = last
            .map(|last| {
                u32::try_from(last)
                    .map(TxId)
                    .map_err(|_| StoreError::OutOfRange {
                        field: "transaction id",
                    })
            })
            .transpose()?;
        let id = next_transaction_id(self, in_table)?;
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
        for sql in [
            "DELETE FROM imported_messages WHERE tx_id = ?1",
            "DELETE FROM imported_transactions WHERE tx_id = ?1",
            "DELETE FROM imported_outputs WHERE tx_id = ?1",
        ] {
            self.conn.execute(sql, [i64::from(id.0)])?;
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

    fn transactions_before(
        &self,
        before: Option<Timestamp>,
        at_least: u32,
    ) -> Result<Vec<StoredTransaction>, StoreError> {
        const NANOS_PER_MILLI: i64 = 1_000_000;
        let before = before
            .map(timestamp_to_column)
            .transpose()?
            .unwrap_or(i64::MAX);
        // The creation time of the entry that ends the step, on its millisecond's start.
        let last: Option<i64> = self
            .conn
            .query_row(
                "SELECT created_at FROM transactions WHERE created_at < ?1
                 ORDER BY created_at DESC LIMIT 1 OFFSET ?2",
                params![before, i64::from(at_least.saturating_sub(1))],
                |row| row.get(0),
            )
            .optional()?;
        let floor = last.map_or(i64::MIN, |last| {
            last.div_euclid(NANOS_PER_MILLI)
                .saturating_mul(NANOS_PER_MILLI)
        });
        self.collect(
            &format!(
                "SELECT {TRANSACTION_COLUMNS} FROM transactions
                 WHERE created_at < ?1 AND created_at >= ?2
                 ORDER BY created_at DESC, id DESC"
            ),
            params![before, floor],
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

    fn clear_confirmed_height(&mut self, id: TxId) -> Result<(), StoreError> {
        let updated = self.conn.execute(
            "UPDATE transactions SET confirmed_height = NULL WHERE id = ?1",
            [i64::from(id.0)],
        )?;
        if updated == 0 {
            return Err(StoreError::UnknownTransaction(id));
        }
        Ok(())
    }

    fn confirmed_from(&self, from: Height) -> Result<Vec<(TxId, Height)>, StoreError> {
        // Heights are stored bit for bit as signed integers, so they are compared here.
        let confirmed = self.collect(
            "SELECT id, confirmed_height FROM transactions
             WHERE state = ?1 AND confirmed_height IS NOT NULL ORDER BY id",
            [TxState::Confirmed.code()],
            |row| {
                Ok((
                    TxId(decode_u32(row.get(0)?, Record::Transaction, "id")?),
                    Height::new(u64_from_column(row.get(1)?)),
                ))
            },
        )?;
        Ok(confirmed
            .into_iter()
            .filter(|(_, height)| *height >= from)
            .collect())
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

    fn set_receive_listing(
        &mut self,
        id: TxId,
        listing: &crate::transaction::ReceiveListing,
    ) -> Result<(), StoreError> {
        let updated = self.conn.execute(
            "UPDATE transactions SET receive_listing_dkey = ?2, receive_listing_gen = ?3 \
             WHERE id = ?1",
            params![
                i64::from(id.0),
                &listing.service_key[..],
                i64::from(listing.generation)
            ],
        )?;
        if updated == 0 {
            return Err(StoreError::UnknownTransaction(id));
        }
        Ok(())
    }

    fn receive_listing(
        &self,
        id: TxId,
    ) -> Result<Option<crate::transaction::ReceiveListing>, StoreError> {
        let row: Option<(Option<Vec<u8>>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT receive_listing_dkey, receive_listing_gen FROM transactions WHERE id = ?1",
                [i64::from(id.0)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let bad = || StoreError::Corrupt {
            record: crate::error::Record::Transaction,
            field: "receive listing",
        };
        match row {
            None | Some((None, None)) => Ok(None),
            Some((Some(service_key), Some(generation))) => {
                Ok(Some(crate::transaction::ReceiveListing {
                    service_key: <[u8; 33]>::try_from(service_key.as_slice()).map_err(|_| bad())?,
                    generation: u32::try_from(generation).map_err(|_| bad())?,
                }))
            }
            // Both columns are written together; one without the other is damage.
            Some(_) => Err(bad()),
        }
    }

    fn open_receipts(&self, transport: &str) -> Result<Vec<OpenReceipt>, StoreError> {
        self.collect(
            "SELECT t.id, t.counterparty FROM transactions t
             WHERE t.direction = ?1 AND t.state = ?2 AND t.transport = ?3
               AND EXISTS (SELECT 1 FROM slates s
                           WHERE s.slate_id = t.slate_id AND s.stage = ?4)
             ORDER BY t.id",
            params![
                TxDirection::Incoming.code(),
                TxState::Received.code(),
                transport,
                SlateStage::Standard2.code()
            ],
            |row| {
                Ok(OpenReceipt {
                    id: TxId(decode_u32(row.get(0)?, Record::Transaction, "id")?),
                    counterparty: row.get(1)?,
                })
            },
        )
    }

    fn transactions_in_state(
        &self,
        state: TxState,
        skip_incoming_transport: &str,
        oldest: u32,
    ) -> Result<StateTally, StoreError> {
        let count: i64 = self.conn.query_row(
            STATE_COUNT,
            params![
                state.code(),
                TxDirection::Incoming.code(),
                skip_incoming_transport
            ],
            |row| row.get(0),
        )?;
        let oldest = self.collect(
            STATE_OLDEST,
            params![
                state.code(),
                TxDirection::Incoming.code(),
                skip_incoming_transport,
                oldest
            ],
            |row| {
                Ok((
                    TxId(decode_u32(row.get(0)?, Record::Transaction, "id")?),
                    timestamp_from_column(row.get(1)?, Record::Transaction, "created at")?,
                ))
            },
        )?;
        Ok(StateTally {
            count: u64::try_from(count).map_err(|_| StoreError::Corrupt {
                record: Record::Transaction,
                field: "count",
            })?,
            oldest,
        })
    }
}

/// The entries in a state but the receiving halves of a payment to self. Both search an index on
/// `state` and read the rows of that state only; the oldest take the one on
/// `(state, created_at)`, whose row id is `id`, so their order needs no sort.
pub(super) const STATE_COUNT: &str = "SELECT COUNT(*) FROM transactions
     WHERE state = ?1 AND NOT (direction = ?2 AND transport IS ?3)";
pub(super) const STATE_OLDEST: &str = "SELECT id, created_at FROM transactions
     WHERE state = ?1 AND NOT (direction = ?2 AND transport IS ?3)
     ORDER BY created_at, id LIMIT ?4";

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

/// The position of an item in a stored list, as its column holds it.
fn position_column(position: usize) -> Result<i64, StoreError> {
    i64::try_from(position).map_err(|_| StoreError::OutOfRange {
        field: "list position",
    })
}

fn decode_contact_link(bytes: &[u8]) -> Result<ContactId, StoreError> {
    Ok(ContactId(bytes.try_into().map_err(|_| {
        corrupt(Record::Contact, "linked contact id")
    })?))
}

fn decode_height(value: Option<i64>) -> Option<Height> {
    value.map(|value| Height::new(u64_from_column(value)))
}

fn encode_height(height: Option<Height>) -> Option<i64> {
    height.map(|height| u64_to_column(height.value()))
}

fn decode_commitment(bytes: &[u8], field: &'static str) -> Result<CommitmentBytes, StoreError> {
    bytes
        .try_into()
        .map_err(|_| corrupt(Record::TransactionRecord, field))
}

fn decode_flag(value: i64, field: &'static str) -> Result<bool, StoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt(Record::TransactionRecord, field)),
    }
}

fn decode_marks(row: &Row<'_>) -> Result<TxMarks, StoreError> {
    Ok(TxMarks {
        local_cutoff: decode_height(row.get(0)?),
        finalized_at: decode_height(row.get(1)?),
        kernel_absent_at: decode_height(row.get(2)?),
        receive_seen_at: decode_height(row.get(3)?),
        receive_inputs_unspent: decode_flag(row.get(4)?, "receive inputs unspent")?,
        inputs_spent_elsewhere: decode_flag(row.get(5)?, "inputs spent elsewhere")?,
        sender_posted_at: row
            .get::<_, Option<i64>>(6)?
            .map(|value| {
                timestamp_from_column(value, Record::TransactionRecord, "sender posted at")
            })
            .transpose()?,
        withdrawn_answered: decode_flag(row.get(7)?, "withdrawn answered")?,
        sender_cancelled_at: row
            .get::<_, Option<i64>>(8)?
            .map(|value| {
                timestamp_from_column(value, Record::TransactionRecord, "sender cancelled at")
            })
            .transpose()?,
        cancelled_answered: decode_flag(row.get(9)?, "cancelled answered")?,
    })
}

fn decode_watched_output(row: &Row<'_>) -> Result<WatchedOutput, StoreError> {
    let record = Record::TransactionRecord;
    let key_id: Vec<u8> = row.get(1)?;
    Ok(WatchedOutput {
        commitment: decode_commitment(&row.get::<_, Vec<u8>>(0)?, "watched output")?,
        key_id: KeyId(
            key_id
                .try_into()
                .map_err(|_| corrupt(record, "watched output key id"))?,
        ),
        amount: Amount::new(u64_from_column(row.get(2)?)),
    })
}

impl SqliteRepos<'_> {
    fn watch_from_row(&self, row: &Row<'_>) -> Result<(TxId, TxWatch), StoreError> {
        let record = Record::TransactionRecord;
        let id = TxId(decode_u32(row.get(0)?, record, "transaction id")?);
        let phase: String = row.get(1)?;
        let watch = TxWatch {
            phase: decode_code(&phase, WatchPhase::from_code, record, "watch phase")?,
            excess: decode_commitment(&row.get::<_, Vec<u8>>(2)?, "watch excess")?,
            min_height: Height::new(u64_from_column(row.get(3)?)),
            ended_at: Height::new(u64_from_column(row.get(4)?)),
            outputs: self.collect(
                "SELECT commitment, key_id, amount FROM tx_watch_outputs
                 WHERE tx_id = ?1 ORDER BY position",
                [i64::from(id.0)],
                decode_watched_output,
            )?,
        };
        Ok((id, watch))
    }

    fn spend_from_row(&self, row: &Row<'_>) -> Result<(TxId, OtherWalletSpend), StoreError> {
        let record = Record::TransactionRecord;
        let id = TxId(decode_u32(row.get(0)?, record, "transaction id")?);
        let outputs = |role: &str| {
            self.collect(
                "SELECT commitment FROM other_wallet_outputs
                 WHERE tx_id = ?1 AND role = ?2 ORDER BY position",
                params![i64::from(id.0), role],
                |row| decode_commitment(&row.get::<_, Vec<u8>>(0)?, "other wallet output"),
            )
        };
        let spend = OtherWalletSpend {
            after: Height::new(u64_from_column(row.get(1)?)),
            to: Height::new(u64_from_column(row.get(2)?)),
            open: decode_flag(row.get(3)?, "other wallet spend open")?,
            spent: outputs("spent")?,
            change: outputs("change")?,
        };
        Ok((id, spend))
    }
}

const WATCH_COLUMNS: &str = "tx_id, phase, excess, min_height, ended_at";
const SPEND_COLUMNS: &str = "tx_id, after_height, to_height, open";

impl TxRecordRepository for SqliteRepos<'_> {
    fn tx_marks(&self, id: TxId) -> Result<TxMarks, StoreError> {
        Ok(self
            .first(
                "SELECT local_cutoff, finalized_at, kernel_absent_at, receive_seen_at,
                     receive_inputs_unspent, inputs_spent_elsewhere, sender_posted_at,
                     withdrawn_answered, sender_cancelled_at, cancelled_answered
                 FROM tx_marks WHERE tx_id = ?1",
                [i64::from(id.0)],
                decode_marks,
            )?
            .unwrap_or_default())
    }

    fn put_tx_marks(&mut self, id: TxId, marks: &TxMarks) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        if *marks == TxMarks::default() {
            self.conn
                .execute("DELETE FROM tx_marks WHERE tx_id = ?1", [i64::from(id.0)])?;
            return Ok(());
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO tx_marks (tx_id, local_cutoff, finalized_at,
                 kernel_absent_at, receive_seen_at, receive_inputs_unspent,
                 inputs_spent_elsewhere, sender_posted_at, withdrawn_answered,
                 sender_cancelled_at, cancelled_answered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                i64::from(id.0),
                encode_height(marks.local_cutoff),
                encode_height(marks.finalized_at),
                encode_height(marks.kernel_absent_at),
                encode_height(marks.receive_seen_at),
                marks.receive_inputs_unspent,
                marks.inputs_spent_elsewhere,
                marks
                    .sender_posted_at
                    .map(timestamp_to_column)
                    .transpose()?,
                marks.withdrawn_answered,
                marks
                    .sender_cancelled_at
                    .map(timestamp_to_column)
                    .transpose()?,
                marks.cancelled_answered,
            ],
        )?;
        Ok(())
    }

    fn tx_watch(&self, id: TxId) -> Result<Option<TxWatch>, StoreError> {
        Ok(self
            .first(
                &format!("SELECT {WATCH_COLUMNS} FROM tx_watch WHERE tx_id = ?1"),
                [i64::from(id.0)],
                |row| self.watch_from_row(row),
            )?
            .map(|(_, watch)| watch))
    }

    fn tx_watches(&self) -> Result<Vec<(TxId, TxWatch)>, StoreError> {
        self.collect(
            &format!("SELECT {WATCH_COLUMNS} FROM tx_watch ORDER BY tx_id"),
            [],
            |row| self.watch_from_row(row),
        )
    }

    fn put_tx_watch(&mut self, id: TxId, watch: &TxWatch) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        self.delete_tx_watch(id)?;
        self.conn.execute(
            &format!("INSERT INTO tx_watch ({WATCH_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5)"),
            params![
                i64::from(id.0),
                watch.phase.code(),
                &watch.excess[..],
                u64_to_column(watch.min_height.value()),
                u64_to_column(watch.ended_at.value()),
            ],
        )?;
        for (position, output) in watch.outputs.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO tx_watch_outputs (tx_id, position, commitment, key_id, amount)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    i64::from(id.0),
                    position_column(position)?,
                    &output.commitment[..],
                    &output.key_id.0[..],
                    u64_to_column(output.amount.value()),
                ],
            )?;
        }
        Ok(())
    }

    fn delete_tx_watch(&mut self, id: TxId) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM tx_watch WHERE tx_id = ?1", [i64::from(id.0)])?;
        Ok(())
    }

    fn other_wallet_spend(&self, id: TxId) -> Result<Option<OtherWalletSpend>, StoreError> {
        Ok(self
            .first(
                &format!("SELECT {SPEND_COLUMNS} FROM other_wallet_spends WHERE tx_id = ?1"),
                [i64::from(id.0)],
                |row| self.spend_from_row(row),
            )?
            .map(|(_, spend)| spend))
    }

    fn other_wallet_spends(&self) -> Result<Vec<(TxId, OtherWalletSpend)>, StoreError> {
        self.collect(
            &format!("SELECT {SPEND_COLUMNS} FROM other_wallet_spends ORDER BY tx_id"),
            [],
            |row| self.spend_from_row(row),
        )
    }

    fn put_other_wallet_spend(
        &mut self,
        id: TxId,
        spend: &OtherWalletSpend,
    ) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        self.conn.execute(
            "DELETE FROM other_wallet_spends WHERE tx_id = ?1",
            [i64::from(id.0)],
        )?;
        self.conn.execute(
            &format!("INSERT INTO other_wallet_spends ({SPEND_COLUMNS}) VALUES (?1, ?2, ?3, ?4)"),
            params![
                i64::from(id.0),
                u64_to_column(spend.after.value()),
                u64_to_column(spend.to.value()),
                spend.open,
            ],
        )?;
        for (role, list) in [("spent", &spend.spent), ("change", &spend.change)] {
            for (position, commitment) in list.iter().enumerate() {
                self.conn.execute(
                    "INSERT INTO other_wallet_outputs (tx_id, role, position, commitment)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        i64::from(id.0),
                        role,
                        position_column(position)?,
                        &commitment[..]
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn scan_found(&self, id: TxId) -> Result<Option<ScanFoundRecord>, StoreError> {
        let record = Record::TransactionRecord;
        self.first(
            "SELECT output, during, dated_by_block FROM scan_found WHERE tx_id = ?1",
            [i64::from(id.0)],
            |row| {
                let output: Option<Vec<u8>> = row.get(0)?;
                let during: Option<String> = row.get(1)?;
                Ok(ScanFoundRecord {
                    output: output
                        .map(|bytes| decode_commitment(&bytes, "scan found output"))
                        .transpose()?,
                    during: during
                        .map(|code| {
                            decode_code(&code, FoundDuring::from_code, record, "scan found during")
                        })
                        .transpose()?,
                    dated_by_block: decode_flag(row.get(2)?, "scan found dated by block")?,
                })
            },
        )
    }

    fn put_scan_found(&mut self, id: TxId, found: &ScanFoundRecord) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_found (tx_id, output, during, dated_by_block)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                i64::from(id.0),
                found.output.as_ref().map(|output| &output[..]),
                found.during.map(FoundDuring::code),
                found.dated_by_block,
            ],
        )?;
        Ok(())
    }
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

    fn slate_stages(&self, slate_id: Uuid) -> Result<Vec<(SlateStage, usize)>, StoreError> {
        // Slates are stored as blobs, whose length SQLite reads without loading them.
        self.collect(
            "SELECT stage, length(bytes) FROM slates WHERE slate_id = ?1 ORDER BY stage",
            [&slate_id.as_bytes()[..]],
            |row| {
                let record = Record::Slate;
                let stage: String = row.get(0)?;
                let length: i64 = row.get(1)?;
                Ok((
                    decode_code(&stage, SlateStage::from_code, record, "stage")?,
                    usize::try_from(length).map_err(|_| corrupt(record, "bytes"))?,
                ))
            },
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

    fn outbox_of_slate(&self, slate_id: Uuid) -> Result<Vec<StoredOutbox>, StoreError> {
        self.collect(
            &format!("SELECT {OUTBOX_COLUMNS} FROM relay_outbox WHERE slate_id = ?1 ORDER BY id"),
            [&slate_id.as_bytes()[..]],
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

    fn settings_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>, StoreError> {
        let pair = |row: &rusqlite::Row<'_>| Ok((row.get(0)?, row.get(1)?));
        let rows = match prefix_end(prefix) {
            Some(end) => self
                .conn
                .prepare(SETTINGS_RANGE)?
                .query_map([prefix, end.as_str()], pair)?
                .collect::<Result<_, _>>()?,
            None => self
                .conn
                .prepare(
                    "SELECT key, value FROM settings
                     WHERE substr(key, 1, length(?1)) = ?1 ORDER BY key",
                )?
                .query_map([prefix], pair)?
                .collect::<Result<_, _>>()?,
        };
        Ok(rows)
    }

    fn delete_setting(&mut self, key: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }
}

/// The settings whose key lies in `[?1, ?2)`, read along the key's index.
pub(super) const SETTINGS_RANGE: &str =
    "SELECT key, value FROM settings WHERE key >= ?1 AND key < ?2 ORDER BY key";

/// The first key after every key that starts with `prefix`, when its last character is ASCII
/// below DEL, as every prefix the wallet uses is. Keys compare bytewise, so the range from
/// `prefix` up to this key holds exactly the keys with the prefix.
fn prefix_end(prefix: &str) -> Option<String> {
    let (head, last) = prefix.split_at_checked(prefix.len().checked_sub(1)?)?;
    match last.as_bytes() {
        [byte] if *byte < 0x7f => Some(format!("{head}{}", char::from(byte.wrapping_add(1)))),
        _ => None,
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
        invoice::check_parkable(
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
        let record = Record::PendingInvoice;
        let slate_id = &slate_id.as_bytes()[..];
        let current: String = self
            .conn
            .query_row(
                "SELECT status FROM pending_invoices WHERE slate_id = ?1",
                [slate_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound { record })?;
        invoice::check_status_change(
            decode_code(&current, PendingInvoiceStatus::from_code, record, "status")?,
            status,
        )?;
        self.conn.execute(
            "UPDATE pending_invoices SET status = ?2 WHERE slate_id = ?1",
            params![slate_id, status.code()],
        )?;
        Ok(())
    }

    fn delete_pending_invoice(&mut self, slate_id: Uuid) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM pending_invoices WHERE slate_id = ?1",
            [&slate_id.as_bytes()[..]],
        )?;
        Ok(())
    }

    fn parked_invoice_count(&self) -> Result<usize, StoreError> {
        self.count(
            "SELECT COUNT(*) FROM pending_invoices WHERE status = ?1",
            [PendingInvoiceStatus::Parked.code()],
        )
    }
}

fn decode_api_event(row: &Row<'_>) -> Result<ApiEvent, StoreError> {
    Ok(ApiEvent {
        id: u64_from_column(row.get(0)?),
        kind: row.get(1)?,
        created_at: timestamp_from_column(row.get(2)?, Record::ApiEvent, "created at")?,
        data: row.get(3)?,
    })
}

fn decode_api_request(row: &Row<'_>) -> Result<ApiRequest, StoreError> {
    let record = Record::ApiRequest;
    Ok(ApiRequest {
        scope: row.get(0)?,
        id: row.get(1)?,
        digest: row
            .get::<_, Vec<u8>>(2)?
            .try_into()
            .map_err(|_| corrupt(record, "digest"))?,
        created_at: timestamp_from_column(row.get(3)?, record, "created at")?,
    })
}

impl ApiLogRepository for SqliteRepos<'_> {
    fn append_api_event(
        &mut self,
        kind: &str,
        created_at: Timestamp,
        data: &[u8],
    ) -> Result<u64, StoreError> {
        api_log::check_kind(kind)?;
        api_log::check_event_data(data)?;
        self.conn.execute(
            "INSERT INTO api_events (kind, created_at, data) VALUES (?1, ?2, ?3)",
            params![kind, timestamp_to_column(created_at)?, data],
        )?;
        Ok(u64_from_column(self.conn.last_insert_rowid()))
    }

    fn api_events_after(
        &self,
        after: u64,
        limit: usize,
        kinds: &[String],
    ) -> Result<Vec<ApiEvent>, StoreError> {
        api_log::check_limit(limit)?;
        let patterns = api_log::parse_patterns(kinds)?;
        // Ids come from a signed column: nothing lies above the largest one.
        let Ok(after) = i64::try_from(after) else {
            return Ok(Vec::new());
        };
        // Only placeholders are pasted into the statement; every value is bound.
        let mut values: Vec<Value> = vec![Value::Integer(after)];
        let mut filters = Vec::new();
        for pattern in &patterns {
            match pattern {
                KindPattern::Exact(kind) => {
                    values.push(Value::Text((*kind).to_owned()));
                    filters.push(format!("kind = ?{}", values.len()));
                }
                KindPattern::Prefix(prefix) => {
                    values.push(Value::Integer(i64::try_from(prefix.len()).map_err(
                        |_| StoreError::OutOfRange {
                            field: "api event kind filter",
                        },
                    )?));
                    let length = values.len();
                    values.push(Value::Text((*prefix).to_owned()));
                    filters.push(format!("substr(kind, 1, ?{length}) = ?{}", values.len()));
                }
            }
        }
        let filter = if filters.is_empty() {
            String::new()
        } else {
            format!(" AND ({})", filters.join(" OR "))
        };
        values.push(Value::Integer(i64::try_from(limit).map_err(|_| {
            StoreError::OutOfRange {
                field: "api event limit",
            }
        })?));
        let limit_slot = values.len();
        self.collect(
            &format!(
                "SELECT id, kind, created_at, data FROM api_events WHERE id > ?1{filter}
                 ORDER BY id LIMIT ?{limit_slot}"
            ),
            rusqlite::params_from_iter(values),
            decode_api_event,
        )
    }

    fn api_event_bounds(&self) -> Result<Option<(u64, u64)>, StoreError> {
        let bounds: (Option<i64>, Option<i64>) =
            self.conn
                .query_row("SELECT MIN(id), MAX(id) FROM api_events", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
        Ok(match bounds {
            (Some(low), Some(high)) => Some((u64_from_column(low), u64_from_column(high))),
            _ => None,
        })
    }

    fn api_event_last_id(&self) -> Result<u64, StoreError> {
        let last: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'api_events'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(last.map_or(0, u64_from_column))
    }

    fn prune_api_events(&mut self, before: Timestamp) -> Result<u64, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM api_events WHERE created_at < ?1",
            [timestamp_to_column(before)?],
        )?;
        Ok(u64::try_from(deleted).unwrap_or(u64::MAX))
    }

    fn put_api_request(&mut self, request: &ApiRequest) -> Result<(), StoreError> {
        api_log::check_request_key(&request.scope, &request.id)?;
        let inserted = self.conn.execute(
            "INSERT INTO api_requests (scope, id, digest, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (scope, id) DO NOTHING",
            params![
                request.scope,
                request.id,
                request.digest.as_slice(),
                timestamp_to_column(request.created_at)?,
            ],
        )?;
        if inserted == 0 {
            return Err(StoreError::Duplicate {
                record: Record::ApiRequest,
            });
        }
        Ok(())
    }

    fn api_request(&self, scope: &str, id: &str) -> Result<Option<ApiRequest>, StoreError> {
        self.first(
            "SELECT scope, id, digest, created_at FROM api_requests
             WHERE scope = ?1 AND id = ?2",
            params![scope, id],
            decode_api_request,
        )
    }

    fn delete_api_request(&mut self, scope: &str, id: &str) -> Result<bool, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM api_requests WHERE scope = ?1 AND id = ?2",
            params![scope, id],
        )?;
        Ok(deleted > 0)
    }

    fn prune_api_requests(&mut self, before: Timestamp) -> Result<u64, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM api_requests WHERE created_at < ?1",
            [timestamp_to_column(before)?],
        )?;
        Ok(u64::try_from(deleted).unwrap_or(u64::MAX))
    }
}

const IMPORTED_TRANSACTION_COLUMNS: &str = "source_id, kind, slate_id, confirmed_at, \
    input_count, output_count, kernel_excess, ttl_cutoff_height, chain_check, \
    kernel_lookup_min_height";

const IMPORTED_OUTPUT_COLUMNS: &str = "commitment, tx_id, status, height, amount";

impl ImportedRepository for SqliteRepos<'_> {
    fn put_imported_transaction(
        &mut self,
        tx: TxId,
        imported: &ImportedTransaction,
    ) -> Result<(), StoreError> {
        self.require_transaction(tx)?;
        imported::check_messages(&imported.messages)?;
        self.conn.execute(
            &format!(
                "INSERT INTO imported_transactions (tx_id, {IMPORTED_TRANSACTION_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT (tx_id) DO UPDATE SET
                     source_id = excluded.source_id, kind = excluded.kind,
                     slate_id = excluded.slate_id, confirmed_at = excluded.confirmed_at,
                     input_count = excluded.input_count, output_count = excluded.output_count,
                     kernel_excess = excluded.kernel_excess,
                     ttl_cutoff_height = excluded.ttl_cutoff_height,
                     chain_check = excluded.chain_check,
                     kernel_lookup_min_height = excluded.kernel_lookup_min_height"
            ),
            params![
                i64::from(tx.0),
                i64::from(imported.source_id),
                imported.kind.code(),
                imported.slate_id.as_ref().map(|id| &id.as_bytes()[..]),
                imported.confirmed_at.map(timestamp_to_column).transpose()?,
                i64::from(imported.input_count),
                i64::from(imported.output_count),
                imported.kernel_excess.as_ref().map(|excess| &excess[..]),
                imported
                    .ttl_cutoff_height
                    .map(|height| u64_to_column(height.value())),
                imported.check.code(),
                imported
                    .kernel_lookup_min_height
                    .map(|height| u64_to_column(height.value())),
            ],
        )?;
        self.conn.execute(
            "DELETE FROM imported_messages WHERE tx_id = ?1",
            [i64::from(tx.0)],
        )?;
        for (position, message) in imported.messages.iter().enumerate() {
            let position = i64::try_from(position).map_err(|_| StoreError::OutOfRange {
                field: "imported message",
            })?;
            self.conn.execute(
                "INSERT INTO imported_messages (tx_id, position, participant, text)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    i64::from(tx.0),
                    position,
                    i64::from(message.participant),
                    message.text,
                ],
            )?;
        }
        Ok(())
    }

    fn imported_transaction(&self, tx: TxId) -> Result<Option<ImportedTransaction>, StoreError> {
        let Some(mut imported) = self.first(
            &format!(
                "SELECT {IMPORTED_TRANSACTION_COLUMNS} FROM imported_transactions
                 WHERE tx_id = ?1"
            ),
            [i64::from(tx.0)],
            decode_imported_transaction,
        )?
        else {
            return Ok(None);
        };
        imported.messages = self.collect(
            "SELECT participant, text FROM imported_messages WHERE tx_id = ?1
             ORDER BY position",
            [i64::from(tx.0)],
            decode_imported_message,
        )?;
        Ok(Some(imported))
    }

    fn set_chain_check(&mut self, tx: TxId, check: ChainCheck) -> Result<(), StoreError> {
        let updated = self.conn.execute(
            "UPDATE imported_transactions SET chain_check = ?2 WHERE tx_id = ?1",
            params![i64::from(tx.0), check.code()],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound {
                record: Record::ImportedTransaction,
            });
        }
        Ok(())
    }

    fn put_imported_output(&mut self, output: &ImportedOutput) -> Result<(), StoreError> {
        self.require_transaction(output.tx)?;
        self.conn.execute(
            &format!(
                "INSERT INTO imported_outputs ({IMPORTED_OUTPUT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (commitment) DO UPDATE SET tx_id = excluded.tx_id,
                     status = excluded.status, height = excluded.height,
                     amount = excluded.amount"
            ),
            params![
                &output.commitment[..],
                i64::from(output.tx.0),
                output.status.code(),
                u64_to_column(output.height.value()),
                u64_to_column(output.amount.value()),
            ],
        )?;
        Ok(())
    }

    fn imported_output(
        &self,
        commitment: &CommitmentBytes,
    ) -> Result<Option<ImportedOutput>, StoreError> {
        self.first(
            &format!(
                "SELECT {IMPORTED_OUTPUT_COLUMNS} FROM imported_outputs WHERE commitment = ?1"
            ),
            [&commitment[..]],
            decode_imported_output,
        )
    }

    fn imported_outputs(
        &self,
        status: ImportedOutputStatus,
    ) -> Result<Vec<ImportedOutput>, StoreError> {
        self.collect(
            &format!(
                "SELECT {IMPORTED_OUTPUT_COLUMNS} FROM imported_outputs WHERE status = ?1
                 ORDER BY commitment"
            ),
            [status.code()],
            decode_imported_output,
        )
    }
}

fn decode_imported_transaction(row: &Row<'_>) -> Result<ImportedTransaction, StoreError> {
    let record = Record::ImportedTransaction;
    let kind: String = row.get(1)?;
    let slate_id: Option<Vec<u8>> = row.get(2)?;
    let kernel_excess: Option<Vec<u8>> = row.get(6)?;
    let check: String = row.get(8)?;
    Ok(ImportedTransaction {
        source_id: decode_u32(row.get(0)?, record, "source id")?,
        kind: decode_code(&kind, ImportedKind::from_code, record, "kind")?,
        slate_id: slate_id
            .map(|bytes| decode_uuid(&bytes, record))
            .transpose()?,
        confirmed_at: row
            .get::<_, Option<i64>>(3)?
            .map(|value| timestamp_from_column(value, record, "confirmed at"))
            .transpose()?,
        input_count: decode_u32(row.get(4)?, record, "input count")?,
        output_count: decode_u32(row.get(5)?, record, "output count")?,
        kernel_excess: kernel_excess
            .map(|bytes| {
                CommitmentBytes::try_from(bytes.as_slice())
                    .map_err(|_| corrupt(record, "kernel excess"))
            })
            .transpose()?,
        ttl_cutoff_height: row
            .get::<_, Option<i64>>(7)?
            .map(|value| Height::new(u64_from_column(value))),
        messages: Vec::new(),
        check: decode_code(&check, ChainCheck::from_code, record, "chain check")?,
        kernel_lookup_min_height: row
            .get::<_, Option<i64>>(9)?
            .map(|value| Height::new(u64_from_column(value))),
    })
}

fn decode_imported_message(row: &Row<'_>) -> Result<ImportedMessage, StoreError> {
    let participant: i64 = row.get(0)?;
    Ok(ImportedMessage {
        participant: u8::try_from(participant)
            .map_err(|_| corrupt(Record::ImportedTransaction, "message participant"))?,
        text: row.get(1)?,
    })
}

fn decode_imported_output(row: &Row<'_>) -> Result<ImportedOutput, StoreError> {
    let record = Record::ImportedOutput;
    let commitment: Vec<u8> = row.get(0)?;
    let status: String = row.get(2)?;
    Ok(ImportedOutput {
        commitment: CommitmentBytes::try_from(commitment.as_slice())
            .map_err(|_| corrupt(record, "commitment"))?,
        tx: TxId(decode_u32(row.get(1)?, record, "transaction")?),
        status: decode_code(&status, ImportedOutputStatus::from_code, record, "status")?,
        height: Height::new(u64_from_column(row.get(3)?)),
        amount: Amount::new(u64_from_column(row.get(4)?)),
    })
}

fn fixed<const N: usize>(
    bytes: &[u8],
    record: Record,
    field: &'static str,
) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(bytes).map_err(|_| corrupt(record, field))
}

fn optional_time(
    value: Option<i64>,
    record: Record,
    field: &'static str,
) -> Result<Option<Timestamp>, StoreError> {
    value
        .map(|value| timestamp_from_column(value, record, field))
        .transpose()
}

fn optional_column(time: Option<Timestamp>) -> Result<Option<i64>, StoreError> {
    time.map(timestamp_to_column).transpose()
}

/// The seven columns of a card slot, starting at `first`.
fn decode_card(
    row: &Row<'_>,
    first: usize,
    record: Record,
) -> Result<Option<PeerCard>, StoreError> {
    let at = |offset: usize| first.saturating_add(offset);
    let bytes: Option<Vec<u8>> = row.get(first)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let sig_key: Option<Vec<u8>> = row.get(at(1))?;
    let enc_key: Option<Vec<u8>> = row.get(at(2))?;
    let hint_key: Option<Vec<u8>> = row.get(at(3))?;
    let seq: Option<i64> = row.get(at(4))?;
    let kind: Option<String> = row.get(at(5))?;
    let name: Option<String> = row.get(at(6))?;
    let (Some(sig_key), Some(enc_key), Some(hint_key), Some(seq), Some(kind), Some(name)) =
        (sig_key, enc_key, hint_key, seq, kind, name)
    else {
        return Err(corrupt(record, "peer card"));
    };
    Ok(Some(PeerCard {
        bytes,
        sig_key: fixed(&sig_key, record, "peer sig key")?,
        enc_key: fixed(&enc_key, record, "peer enc key")?,
        hint_key: fixed(&hint_key, record, "peer hint key")?,
        seq: decode_u32(seq, record, "card seq")?,
        kind: decode_code(&kind, ContactKind::from_code, record, "kind")?,
        claimed_name: name,
    }))
}

const CONTACT_COLUMNS: &str = "contact_id, card, peer_sig_key, peer_enc_key, peer_hint_key, \
    card_seq, kind, claimed_name, alt_card, alt_sig_key, alt_enc_key, alt_hint_key, alt_seq, \
    alt_kind, alt_name, label, state, verified_at, allow_invoices, seal, last_sealed_in, \
    app_contact, imported_from_backup, created_at, updated_at, account, slot, box_salt, sas, own_card, \
    payments_address, payments_key, peer_features, peer_heard_at, peer_verified_at, peer_verdict, \
    ended_reason, ended_at, heard_wait, heard_wait_mark, \
    peer_domain, peer_domain_attestation";

fn decode_contact(row: &Row<'_>) -> Result<ContactRecord, StoreError> {
    let record = Record::Contact;
    let id: Vec<u8> = row.get(0)?;
    let state: String = row.get(16)?;
    let seal: String = row.get(19)?;
    Ok(ContactRecord {
        contact_id: ContactId(fixed(&id, record, "contact id")?),
        peer: decode_card(row, 1, record)?,
        alternate: decode_card(row, 8, record)?,
        label: row.get(15)?,
        state: decode_code(&state, ContactState::from_code, record, "state")?,
        verified_at: optional_time(row.get(17)?, record, "verified at")?,
        allow_invoices: row.get(18)?,
        seal: decode_code(&seal, SealMode::from_code, record, "seal")?,
        last_sealed_in: optional_time(row.get(20)?, record, "last sealed in")?,
        app_contact: row.get(21)?,
        imported_from_backup: row.get(22)?,
        created_at: timestamp_from_column(row.get(23)?, record, "created at")?,
        updated_at: timestamp_from_column(row.get(24)?, record, "updated at")?,
        account: AccountIndex(decode_u32(row.get(25)?, record, "account")?),
        slot: decode_u32(row.get(26)?, record, "slot")?,
        box_salt: fixed(&row.get::<_, Vec<u8>>(27)?, record, "box salt")?,
        sas: row
            .get::<_, Option<Vec<u8>>>(28)?
            .map(|sas| fixed(&sas, record, "sas"))
            .transpose()?,
        own_card: row.get(29)?,
        facts: decode_facts(row, 30)?,
    })
}

/// The pairing facts of a contact row, starting at column `first`.
fn decode_facts(row: &Row<'_>, first: usize) -> Result<PairingFacts, StoreError> {
    let record = Record::Contact;
    let at = |offset: usize| first.saturating_add(offset);
    let payments_address: Option<String> = row.get(first)?;
    let payments_key: Option<Vec<u8>> = row.get(at(1))?;
    let payments_key = payments_key
        .map(|key| fixed::<PAYMENTS_KEY_LEN>(&key, record, "payments key"))
        .transpose()?;
    if payments_address.is_some() != payments_key.is_some() {
        return Err(corrupt(record, "payments address"));
    }
    let features: i64 = row.get(at(2))?;
    let verdict: Option<Vec<u8>> = row.get(at(5))?;
    let ended: Option<String> = row.get(at(6))?;
    let wait: i64 = row.get(at(8))?;
    let domain: Option<String> = row.get(at(10))?;
    let attestation: Option<Vec<u8>> = row.get(at(11))?;
    let peer_domain = match (domain, attestation) {
        (None, None) => None,
        (Some(domain), Some(attestation))
            if attestation.len() <= contact::MAX_DOMAIN_ATTESTATION_LEN =>
        {
            Some(DomainClaimBytes {
                domain,
                attestation,
            })
        }
        _ => return Err(corrupt(record, "peer domain")),
    };
    Ok(PairingFacts {
        payments_address,
        payments_key,
        peer_features: decode_u32(features, record, "peer features")?,
        peer_heard_at: optional_time(row.get(at(3))?, record, "peer heard at")?,
        peer_verified_at: optional_time(row.get(at(4))?, record, "peer verified at")?,
        peer_verdict: verdict
            .map(|verdict| fixed(&verdict, record, "peer verdict"))
            .transpose()?,
        ended_reason: ended
            .map(|code| decode_code(&code, PairingEndReason::from_code, record, "ended reason"))
            .transpose()?,
        ended_at: optional_time(row.get(at(7))?, record, "ended at")?,
        heard_wait: std::time::Duration::from_nanos(
            u64::try_from(wait).map_err(|_| corrupt(record, "heard wait"))?,
        ),
        heard_wait_mark: optional_time(row.get(at(9))?, record, "heard wait mark")?,
        peer_domain,
    })
}

fn facts_params(facts: &PairingFacts) -> Result<Vec<rusqlite::types::Value>, StoreError> {
    Ok(vec![
        facts.payments_address.clone().into(),
        facts.payments_key.map(|key| key.to_vec()).into(),
        i64::from(facts.peer_features).into(),
        optional_column(facts.peer_heard_at)?.into(),
        optional_column(facts.peer_verified_at)?.into(),
        facts.peer_verdict.map(|verdict| verdict.to_vec()).into(),
        facts
            .ended_reason
            .map(|reason| reason.code().to_owned())
            .into(),
        optional_column(facts.ended_at)?.into(),
        contact::duration_to_column(facts.heard_wait)?.into(),
        optional_column(facts.heard_wait_mark)?.into(),
        facts
            .peer_domain
            .as_ref()
            .map(|claim| claim.domain.clone())
            .into(),
        facts
            .peer_domain
            .as_ref()
            .map(|claim| claim.attestation.clone())
            .into(),
    ])
}

const PAIRING_COLUMNS: &str = "pairing_id, role, contact_id, sealed, invite_id, expires_at, \
    our_mailbox, peer_mailbox, state, created_at, invite, expect_address, expect_key, reply, \
    cancelled_at";

impl SqliteRepos<'_> {
    fn contact_where(
        &self,
        condition: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<ContactRecord>, StoreError> {
        self.collect(
            &format!(
                "SELECT {CONTACT_COLUMNS} FROM contacts WHERE {condition} \
                 ORDER BY created_at, contact_id"
            ),
            params,
            decode_contact,
        )
    }

    fn decode_pairing(&self, row: &Row<'_>) -> Result<PendingPairing, StoreError> {
        let record = Record::PendingPairing;
        let id: Vec<u8> = row.get(0)?;
        let role: String = row.get(1)?;
        let contact_id: Vec<u8> = row.get(2)?;
        let sealed: Vec<u8> = row.get(3)?;
        let invite_id: Vec<u8> = row.get(4)?;
        let state: String = row.get(8)?;
        let pairing_id = PairingId(fixed(&id, record, "pairing id")?);
        let invite_id: [u8; INVITE_ID_LEN] = fixed(&invite_id, record, "invite id")?;
        Ok(PendingPairing {
            pairing_id,
            role: decode_code(&role, PairingRole::from_code, record, "role")?,
            contact_id: ContactId(fixed(&contact_id, record, "contact id")?),
            secrets: contact::open_secrets(self.key, pairing_id, &invite_id, &sealed)?,
            invite_id,
            expires_at: timestamp_from_column(row.get(5)?, record, "expires at")?,
            our_mailbox: row.get(6)?,
            peer_mailbox: row.get(7)?,
            state: decode_code(&state, PairingState::from_code, record, "state")?,
            created_at: timestamp_from_column(row.get(9)?, record, "created at")?,
            invite: row.get(10)?,
            expect_address: row.get(11)?,
            expect_key: row
                .get::<_, Option<Vec<u8>>>(12)?
                .map(|key| fixed(&key, record, "expected key"))
                .transpose()?,
            reply: row.get(13)?,
            cancelled_at: optional_time(row.get(14)?, record, "cancelled at")?,
        })
    }

    /// The pairings not cancelled that wait for their answer, counted up to `cap`.
    fn waiting_pairings(&self, cap: usize) -> Result<usize, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT role, pairing_id, invite_id, sealed FROM pairings WHERE cancelled_at IS NULL",
        )?;
        let mut rows = statement.query([])?;
        let mut waiting = 0;
        while waiting < cap
            && let Some(row) = rows.next()?
        {
            if !self.answered(row) {
                waiting = waiting.saturating_add(1);
            }
        }
        Ok(waiting)
    }

    /// A row whose columns cannot be read counts as waiting.
    fn answered(&self, row: &Row<'_>) -> bool {
        let read = || {
            let role = PairingRole::from_code(&row.get::<_, String>(0).ok()?)?;
            let id = PairingId(row.get::<_, Vec<u8>>(1).ok()?.try_into().ok()?);
            let invite_id: [u8; INVITE_ID_LEN] = row.get::<_, Vec<u8>>(2).ok()?.try_into().ok()?;
            let sealed: Vec<u8> = row.get(3).ok()?;
            Some(contact::answered(self.key, role, id, &invite_id, &sealed))
        };
        read().unwrap_or(false)
    }

    fn require_contact(&self, id: ContactId) -> Result<(), StoreError> {
        if self.exists(
            "SELECT EXISTS (SELECT 1 FROM contacts WHERE contact_id = ?1)",
            [&id.0[..]],
        )? {
            Ok(())
        } else {
            Err(StoreError::NotFound {
                record: Record::Contact,
            })
        }
    }
}

fn card_params(card: Option<&PeerCard>) -> [rusqlite::types::Value; 7] {
    use rusqlite::types::Value;
    match card {
        Some(card) => [
            Value::Blob(card.bytes.clone()),
            Value::Blob(card.sig_key.to_vec()),
            Value::Blob(card.enc_key.to_vec()),
            Value::Blob(card.hint_key.to_vec()),
            Value::Integer(i64::from(card.seq)),
            Value::Text(card.kind.code().to_owned()),
            Value::Text(card.claimed_name.clone()),
        ],
        None => [
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ],
    }
}

/// An insert of `columns` into `table` that updates the row in place when `key` is taken. Never
/// `INSERT OR REPLACE`: with foreign keys on, a replace deletes the old row first, and the delete
/// cascades to the contact's mailbox, backoff and outbox.
fn upsert(table: &str, columns: &str, key: &str) -> String {
    let names: Vec<&str> = columns.split(',').map(str::trim).collect();
    let values = (1..=names.len())
        .map(|at| format!("?{at}"))
        .collect::<Vec<_>>()
        .join(", ");
    let keys: Vec<&str> = key.split(',').map(str::trim).collect();
    let updates = names
        .iter()
        .filter(|name| !keys.contains(name))
        .map(|name| format!("{name} = excluded.{name}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO {table} ({columns}) VALUES ({values}) \
         ON CONFLICT ({key}) DO UPDATE SET {updates}"
    )
}

const MAILBOX_COLUMNS: &str = "contact_id, peer_mailbox, our_mailbox, home_relay, onion, \
    prev_relay, prev_peer_mailbox, prev_our_mailbox, prev_until";

const BACKOFF_COLUMNS: &str = "contact_id, relay, next_try_at, failures";

impl ContactRepository for SqliteRepos<'_> {
    fn put_contact(&mut self, contact: &ContactRecord) -> Result<(), StoreError> {
        contact::check_contact(contact)?;
        let id = &contact.contact_id.0[..];
        if let Some(peer) = &contact.peer {
            let taken = self.exists(
                "SELECT EXISTS (SELECT 1 FROM contacts WHERE peer_sig_key = ?1 AND contact_id != ?2)",
                params![&peer.sig_key[..], id],
            )?;
            if taken {
                return Err(StoreError::Duplicate {
                    record: Record::Contact,
                });
            }
        }
        let stored = self.exists(
            "SELECT EXISTS (SELECT 1 FROM contacts WHERE contact_id = ?1)",
            [id],
        )?;
        if !stored && self.count("SELECT COUNT(*) FROM contacts", [])? >= MAX_CONTACTS {
            return Err(StoreError::ContactCapReached {
                cap: ContactCap::Contacts,
            });
        }
        let mut values: Vec<rusqlite::types::Value> = vec![id.to_vec().into()];
        values.extend(card_params(contact.peer.as_ref()));
        values.extend(card_params(contact.alternate.as_ref()));
        values.extend([
            contact.label.clone().into(),
            contact.state.code().to_owned().into(),
            optional_column(contact.verified_at)?.into(),
            contact.allow_invoices.into(),
            contact.seal.code().to_owned().into(),
            optional_column(contact.last_sealed_in)?.into(),
            contact.app_contact.clone().into(),
            contact.imported_from_backup.into(),
            timestamp_to_column(contact.created_at)?.into(),
            timestamp_to_column(contact.updated_at)?.into(),
            i64::from(contact.account.0).into(),
            i64::from(contact.slot).into(),
            contact.box_salt.to_vec().into(),
            contact.sas.map(|sas| sas.to_vec()).into(),
            contact.own_card.clone().into(),
        ]);
        values.extend(facts_params(&contact.facts)?);
        self.conn.execute(
            &upsert("contacts", CONTACT_COLUMNS, "contact_id"),
            rusqlite::params_from_iter(values),
        )?;
        Ok(())
    }

    fn contact(&self, id: ContactId) -> Result<Option<ContactRecord>, StoreError> {
        Ok(self
            .contact_where("contact_id = ?1", [&id.0[..]])?
            .into_iter()
            .next())
    }

    fn contact_by_peer_sig_key(
        &self,
        key: &[u8; CARD_KEY_LEN],
    ) -> Result<Option<ContactRecord>, StoreError> {
        Ok(self
            .contact_where("peer_sig_key = ?1", [&key[..]])?
            .into_iter()
            .next())
    }

    fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError> {
        self.contact_where("1", [])
    }

    fn contact_slot_counters(&self) -> Result<Vec<(AccountIndex, u32)>, StoreError> {
        self.collect(
            "SELECT account, next_slot FROM contact_slot_counters ORDER BY account",
            [],
            |row| {
                Ok((
                    AccountIndex(decode_u32(row.get(0)?, Record::Contact, "account")?),
                    decode_u32(row.get(1)?, Record::Contact, "slot counter")?,
                ))
            },
        )
    }

    fn contact_slot_counter(&self, account: AccountIndex) -> Result<Option<u32>, StoreError> {
        self.first(
            "SELECT next_slot FROM contact_slot_counters WHERE account = ?1",
            [i64::from(account.0)],
            |row| decode_u32(row.get(0)?, Record::Contact, "slot counter"),
        )
    }

    fn take_contact_slot(&mut self, account: AccountIndex, start: u32) -> Result<u32, StoreError> {
        contact::check_slot_start(start)?;
        let current = self.contact_slot_counter(account)?.unwrap_or(start);
        let (slot, next) = contact::next_slot(current)?;
        self.conn.execute(
            "INSERT INTO contact_slot_counters (account, next_slot) VALUES (?1, ?2) \
             ON CONFLICT (account) DO UPDATE SET next_slot = excluded.next_slot",
            params![i64::from(account.0), i64::from(next)],
        )?;
        Ok(slot)
    }

    fn raise_contact_slot_counter(
        &mut self,
        account: AccountIndex,
        next: u32,
    ) -> Result<(), StoreError> {
        contact::check_slot_counter(next)?;
        self.conn.execute(
            "INSERT INTO contact_slot_counters (account, next_slot) VALUES (?1, ?2) \
             ON CONFLICT (account) DO UPDATE SET next_slot = max(next_slot, excluded.next_slot)",
            params![i64::from(account.0), i64::from(next)],
        )?;
        Ok(())
    }

    fn delete_contact(&mut self, id: ContactId) -> Result<bool, StoreError> {
        // The mailbox, its backoff and the outbox entries go with the contact by cascade.
        let removed = self
            .conn
            .execute("DELETE FROM contacts WHERE contact_id = ?1", [&id.0[..]])?
            > 0;
        self.forget_unused_extras(id)?;
        Ok(removed)
    }

    fn put_contact_mailbox(&mut self, mailbox: &ContactMailbox) -> Result<(), StoreError> {
        contact::check_mailbox(mailbox)?;
        self.require_contact(mailbox.contact_id)?;
        let id = &mailbox.contact_id.0[..];
        let previous = mailbox.previous.as_ref();
        self.conn.execute(
            &upsert("contact_mailboxes", MAILBOX_COLUMNS, "contact_id"),
            params![
                id,
                mailbox.peer_mailbox,
                mailbox.our_mailbox,
                mailbox.home_relay,
                mailbox.onion,
                previous.map(|p| p.relay.as_str()),
                previous.map(|p| p.peer_mailbox.as_str()),
                previous.map(|p| p.our_mailbox.as_str()),
                optional_column(previous.map(|p| p.until))?,
            ],
        )?;
        self.conn.execute(
            "DELETE FROM contact_relay_backoff WHERE contact_id = ?1",
            [id],
        )?;
        for backoff in &mailbox.backoff {
            self.conn.execute(
                &upsert(
                    "contact_relay_backoff",
                    BACKOFF_COLUMNS,
                    "contact_id, relay",
                ),
                params![
                    id,
                    backoff.relay,
                    timestamp_to_column(backoff.next_try_at)?,
                    i64::from(backoff.failures),
                ],
            )?;
        }
        Ok(())
    }

    fn contact_mailbox(&self, id: ContactId) -> Result<Option<ContactMailbox>, StoreError> {
        let record = Record::ContactMailbox;
        let Some(mut mailbox) = self.first(
            "SELECT peer_mailbox, our_mailbox, home_relay, onion, prev_relay, prev_peer_mailbox, \
                 prev_our_mailbox, prev_until FROM contact_mailboxes WHERE contact_id = ?1",
            [&id.0[..]],
            |row| {
                let relay: Option<String> = row.get(4)?;
                let peer: Option<String> = row.get(5)?;
                let ours: Option<String> = row.get(6)?;
                let until: Option<i64> = row.get(7)?;
                let previous = match (relay, peer, ours, until) {
                    (None, None, None, None) => None,
                    (Some(relay), Some(peer_mailbox), Some(our_mailbox), Some(until)) => {
                        Some(PreviousHome {
                            relay,
                            peer_mailbox,
                            our_mailbox,
                            until: timestamp_from_column(until, record, "previous until")?,
                        })
                    }
                    _ => return Err(corrupt(record, "previous home")),
                };
                Ok(ContactMailbox {
                    contact_id: id,
                    peer_mailbox: row.get(0)?,
                    our_mailbox: row.get(1)?,
                    home_relay: row.get(2)?,
                    onion: row.get(3)?,
                    previous,
                    backoff: Vec::new(),
                })
            },
        )?
        else {
            return Ok(None);
        };
        mailbox.backoff = self.collect(
            "SELECT relay, next_try_at, failures FROM contact_relay_backoff \
             WHERE contact_id = ?1 ORDER BY relay",
            [&id.0[..]],
            |row| {
                Ok(RelayBackoff {
                    relay: row.get(0)?,
                    next_try_at: timestamp_from_column(row.get(1)?, record, "next try at")?,
                    failures: decode_u32(row.get(2)?, record, "failures")?,
                })
            },
        )?;
        Ok(Some(mailbox))
    }

    fn put_pending_pairing(&mut self, pairing: &PendingPairing) -> Result<(), StoreError> {
        contact::check_pairing(pairing)?;
        let id = &pairing.pairing_id.0[..];
        let taken = self.exists(
            "SELECT EXISTS (SELECT 1 FROM pairings WHERE invite_id = ?1 AND pairing_id != ?2)",
            params![&pairing.invite_id[..], id],
        )?;
        if taken {
            return Err(StoreError::Duplicate {
                record: Record::PendingPairing,
            });
        }
        let was_cancelled: Option<bool> = self.first(
            "SELECT cancelled_at IS NOT NULL FROM pairings WHERE pairing_id = ?1",
            [id],
            |row| Ok(row.get::<_, bool>(0)?),
        )?;
        let cancelled = pairing.cancelled_at.is_some();
        if was_cancelled != Some(cancelled) {
            let full = if cancelled {
                self.count(
                    "SELECT COUNT(*) FROM pairings WHERE cancelled_at IS NOT NULL",
                    [],
                )? >= MAX_CANCELLED_PAIRINGS
            } else {
                self.waiting_pairings(MAX_PENDING_PAIRINGS)? >= MAX_PENDING_PAIRINGS
            };
            if full {
                return Err(StoreError::ContactCapReached {
                    cap: ContactCap::PendingPairings,
                });
            }
        }
        let sealed = contact::seal_secrets(self.key, pairing)?;
        self.conn.execute(
            &upsert("pairings", PAIRING_COLUMNS, "pairing_id"),
            params![
                id,
                pairing.role.code(),
                &pairing.contact_id.0[..],
                sealed,
                &pairing.invite_id[..],
                timestamp_to_column(pairing.expires_at)?,
                pairing.our_mailbox,
                pairing.peer_mailbox,
                pairing.state.code(),
                timestamp_to_column(pairing.created_at)?,
                pairing.invite,
                pairing.expect_address,
                pairing.expect_key.map(|key| key.to_vec()),
                pairing.reply,
                optional_column(pairing.cancelled_at)?,
            ],
        )?;
        Ok(())
    }

    fn pending_pairing(&self, id: PairingId) -> Result<Option<PendingPairing>, StoreError> {
        self.first(
            &format!("SELECT {PAIRING_COLUMNS} FROM pairings WHERE pairing_id = ?1"),
            [&id.0[..]],
            |row| self.decode_pairing(row),
        )
    }

    fn pending_pairing_by_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> Result<Option<PendingPairing>, StoreError> {
        self.first(
            &format!("SELECT {PAIRING_COLUMNS} FROM pairings WHERE invite_id = ?1"),
            [&invite_id[..]],
            |row| self.decode_pairing(row),
        )
    }

    fn pending_pairings(&self) -> Result<Vec<PendingPairing>, StoreError> {
        self.collect(
            &format!("SELECT {PAIRING_COLUMNS} FROM pairings ORDER BY created_at, pairing_id"),
            [],
            |row| self.decode_pairing(row),
        )
    }

    fn delete_pending_pairing(&mut self, id: PairingId) -> Result<bool, StoreError> {
        let contact: Option<Vec<u8>> = self
            .conn
            .query_row(
                "DELETE FROM pairings WHERE pairing_id = ?1 RETURNING contact_id",
                [&id.0[..]],
                |row| row.get(0),
            )
            .optional()?;
        let Some(contact) = contact else {
            return Ok(false);
        };
        self.forget_unused_extras(decode_contact_link(&contact)?)?;
        Ok(true)
    }

    fn envelope_seen(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
        self.exists(
            "SELECT EXISTS (SELECT 1 FROM contact_seen WHERE hash = ?1)",
            [&hash[..]],
        )
    }

    fn remember_envelope(&mut self, hash: &[u8; 32], at: Timestamp) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO contact_seen (hash, seen_at) VALUES (?1, ?2) \
             ON CONFLICT (hash) DO UPDATE SET seen_at = excluded.seen_at",
            params![&hash[..], timestamp_to_column(at)?],
        )?;
        Ok(())
    }

    fn slate_contact(&self, slate_id: Uuid) -> Result<Option<ContactId>, StoreError> {
        self.first(
            "SELECT contact_id FROM contact_slates WHERE slate_id = ?1",
            [&slate_id.as_bytes()[..]],
            |row| decode_contact_link(&row.get::<_, Vec<u8>>(0)?),
        )
    }

    fn set_slate_contact(&mut self, slate_id: Uuid, contact: ContactId) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO contact_slates (slate_id, contact_id) VALUES (?1, ?2)
             ON CONFLICT (slate_id) DO UPDATE SET contact_id = excluded.contact_id",
            params![&slate_id.as_bytes()[..], &contact.0[..]],
        )?;
        Ok(())
    }

    fn tx_contact(&self, tx_id: TxId) -> Result<Option<ContactId>, StoreError> {
        self.first(
            "SELECT contact_id FROM contact_transactions WHERE tx_id = ?1",
            [i64::from(tx_id.0)],
            |row| decode_contact_link(&row.get::<_, Vec<u8>>(0)?),
        )
    }

    fn set_tx_contact(&mut self, tx_id: TxId, contact: ContactId) -> Result<(), StoreError> {
        self.require_transaction(tx_id)?;
        self.conn.execute(
            "INSERT INTO contact_transactions (tx_id, contact_id) VALUES (?1, ?2)
             ON CONFLICT (tx_id) DO UPDATE SET contact_id = excluded.contact_id",
            params![i64::from(tx_id.0), &contact.0[..]],
        )?;
        Ok(())
    }

    fn forget_envelopes_before(&mut self, cutoff: Timestamp) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM contact_seen WHERE seen_at < ?1",
            [timestamp_to_column(cutoff)?],
        )?)
    }

    fn contacts_by_payments_key(
        &self,
        key: &[u8; PAYMENTS_KEY_LEN],
    ) -> Result<Vec<ContactRecord>, StoreError> {
        self.contact_where("payments_key = ?1", [&key[..]])
    }
}

const WATCH_SET_COLUMNS: &str = "key_ref, relay, class, expires_at";

fn decode_watch(row: &Row<'_>) -> Result<WatchRow, StoreError> {
    let record = Record::WatchRow;
    let class: String = row.get(2)?;
    Ok(WatchRow {
        key_ref: row.get(0)?,
        relay: row.get(1)?,
        class: decode_code(&class, MailClass::from_code, record, "class")?,
        expires_at: optional_time(row.get(3)?, record, "expires at")?,
    })
}

impl WatchSetRepository for SqliteRepos<'_> {
    fn put_watch(&mut self, row: &WatchRow) -> Result<(), StoreError> {
        delivery::check_watch(row)?;
        self.conn.execute(
            &upsert("watch_set", WATCH_SET_COLUMNS, "key_ref, relay"),
            params![
                row.key_ref,
                row.relay,
                row.class.code(),
                optional_column(row.expires_at)?,
            ],
        )?;
        Ok(())
    }

    fn delete_watch(&mut self, key_ref: &str, relay: &str) -> Result<bool, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM watch_set WHERE key_ref = ?1 AND relay = ?2",
            params![key_ref, relay],
        )?;
        Ok(deleted > 0)
    }

    fn watch_set(&self) -> Result<Vec<WatchRow>, StoreError> {
        self.collect(
            &format!("SELECT {WATCH_SET_COLUMNS} FROM watch_set ORDER BY relay, key_ref"),
            [],
            decode_watch,
        )
    }

    fn remove_expired_watches(&mut self, now: Timestamp) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM watch_set WHERE expires_at <= ?1",
            [timestamp_to_column(now)?],
        )?)
    }
}

const NATIVE_OUTBOX_COLUMNS: &str = "id, payment_id, from_ref, route_method, route_value, \
    envelope, state, attempts, next_at, cutoff_height, stage, created_at, posted_at, notice";

fn native_outbox_id_column(id: NativeOutboxId) -> Result<i64, StoreError> {
    i64::try_from(id.0).map_err(|_| StoreError::OutOfRange {
        field: "native outbox id",
    })
}

fn decode_native_outbox(row: &Row<'_>) -> Result<StoredNativeOutbox, StoreError> {
    let record = Record::NativeOutbox;
    let id: i64 = row.get(0)?;
    let payment_id: Vec<u8> = row.get(1)?;
    let state: String = row.get(6)?;
    let cutoff: Option<i64> = row.get(9)?;
    let stage: Option<String> = row.get(10)?;
    let posted_at: Option<i64> = row.get(12)?;
    Ok(StoredNativeOutbox {
        id: NativeOutboxId(u64::try_from(id).map_err(|_| corrupt(record, "id"))?),
        entry: NativeOutboxEntry {
            payment_id: decode_uuid(&payment_id, record)?,
            from_ref: row.get(2)?,
            route_method: row.get(3)?,
            route_value: row.get(4)?,
            envelope: row.get(5)?,
            state: decode_code(&state, OutboxState::from_code, record, "state")?,
            attempts: decode_u32(row.get(7)?, record, "attempts")?,
            next_at: timestamp_from_column(row.get(8)?, record, "next at")?,
            cutoff_height: cutoff.map(|height| Height::new(u64_from_column(height))),
            stage: stage
                .map(|stage| decode_code(&stage, SlateStage::from_code, record, "stage"))
                .transpose()?,
            notice: row.get(13)?,
            created_at: timestamp_from_column(row.get(11)?, record, "created at")?,
            posted_at: posted_at
                .map(|at| timestamp_from_column(at, record, "posted at"))
                .transpose()?,
        },
    })
}

impl NativeOutboxRepository for SqliteRepos<'_> {
    fn enqueue_native_outbox(
        &mut self,
        entry: &NativeOutboxEntry,
    ) -> Result<NativeOutboxId, StoreError> {
        delivery::check_native_outbox(entry)?;
        self.conn.execute(
            "INSERT INTO native_outbox (payment_id, from_ref, route_method, route_value, \
                 envelope, state, attempts, next_at, cutoff_height, stage, created_at, posted_at, \
                 notice)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &entry.payment_id.as_bytes()[..],
                entry.from_ref,
                entry.route_method,
                entry.route_value,
                entry.envelope,
                entry.state.code(),
                i64::from(entry.attempts),
                timestamp_to_column(entry.next_at)?,
                entry
                    .cutoff_height
                    .map(|height| u64_to_column(height.value())),
                entry.stage.map(SlateStage::code),
                timestamp_to_column(entry.created_at)?,
                entry.posted_at.map(timestamp_to_column).transpose()?,
                entry.notice,
            ],
        )?;
        u64::try_from(self.conn.last_insert_rowid())
            .map(NativeOutboxId)
            .map_err(|_| StoreError::OutOfRange {
                field: "native outbox id",
            })
    }

    fn update_native_outbox(
        &mut self,
        id: NativeOutboxId,
        entry: &NativeOutboxEntry,
    ) -> Result<(), StoreError> {
        delivery::check_native_outbox(entry)?;
        let changed = self.conn.execute(
            "UPDATE native_outbox SET payment_id = ?2, from_ref = ?3, route_method = ?4, \
                 route_value = ?5, envelope = ?6, state = ?7, attempts = ?8, next_at = ?9, \
                 cutoff_height = ?10, stage = ?11, created_at = ?12, posted_at = ?13, \
                 notice = ?14 WHERE id = ?1",
            params![
                native_outbox_id_column(id)?,
                &entry.payment_id.as_bytes()[..],
                entry.from_ref,
                entry.route_method,
                entry.route_value,
                entry.envelope,
                entry.state.code(),
                i64::from(entry.attempts),
                timestamp_to_column(entry.next_at)?,
                entry
                    .cutoff_height
                    .map(|height| u64_to_column(height.value())),
                entry.stage.map(SlateStage::code),
                timestamp_to_column(entry.created_at)?,
                entry.posted_at.map(timestamp_to_column).transpose()?,
                entry.notice,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                record: Record::NativeOutbox,
            });
        }
        Ok(())
    }

    fn native_outbox_entry(
        &self,
        id: NativeOutboxId,
    ) -> Result<Option<StoredNativeOutbox>, StoreError> {
        self.first(
            &format!("SELECT {NATIVE_OUTBOX_COLUMNS} FROM native_outbox WHERE id = ?1"),
            [native_outbox_id_column(id)?],
            decode_native_outbox,
        )
    }

    fn native_outbox_of(&self, payment_id: Uuid) -> Result<Vec<StoredNativeOutbox>, StoreError> {
        self.collect(
            &format!(
                "SELECT {NATIVE_OUTBOX_COLUMNS} FROM native_outbox WHERE payment_id = ?1 \
                 ORDER BY id"
            ),
            [&payment_id.as_bytes()[..]],
            decode_native_outbox,
        )
    }

    fn due_native_outbox(&self, now: Timestamp) -> Result<Vec<StoredNativeOutbox>, StoreError> {
        self.collect(
            &format!(
                "SELECT {NATIVE_OUTBOX_COLUMNS} FROM native_outbox \
                 WHERE state IN ('queued', 'uncertain') AND next_at <= ?1 \
                 ORDER BY next_at, id"
            ),
            [timestamp_to_column(now)?],
            decode_native_outbox,
        )
    }

    fn delete_native_outbox(&mut self, id: NativeOutboxId) -> Result<bool, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM native_outbox WHERE id = ?1",
            [native_outbox_id_column(id)?],
        )?;
        Ok(deleted > 0)
    }

    fn native_outbox_from(&self, from_ref: &str) -> Result<Vec<StoredNativeOutbox>, StoreError> {
        self.collect(
            &format!(
                "SELECT {NATIVE_OUTBOX_COLUMNS} FROM native_outbox WHERE from_ref = ?1 \
                 ORDER BY id"
            ),
            [from_ref],
            decode_native_outbox,
        )
    }

    fn redirect_native_outbox(
        &mut self,
        from_ref: &str,
        old: &str,
        new: &str,
    ) -> Result<usize, StoreError> {
        delivery::check_route_value(new)?;
        Ok(self.conn.execute(
            "UPDATE native_outbox SET route_value = ?3 \
             WHERE from_ref = ?1 AND route_value = ?2 AND state = 'queued'",
            params![from_ref, old, new],
        )?)
    }

    fn delete_native_outbox_from(&mut self, from_ref: &str) -> Result<usize, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM native_outbox WHERE from_ref = ?1", [from_ref])?)
    }

    fn put_outbox_copy(&mut self, id: NativeOutboxId, copy: &OutboxCopy) -> Result<(), StoreError> {
        delivery::check_outbox_copy(copy)?;
        let id = native_outbox_id_column(id)?;
        if !self.exists(
            "SELECT EXISTS (SELECT 1 FROM native_outbox WHERE id = ?1)",
            [id],
        )? {
            return Err(StoreError::NotFound {
                record: Record::NativeOutbox,
            });
        }
        self.conn.execute(
            &upsert(
                "native_outbox_mailbox",
                OUTBOX_COPY_COLUMNS,
                "outbox_id, mailbox",
            ),
            params![
                id,
                copy.mailbox,
                copy.state.code(),
                i64::from(copy.attempts),
                timestamp_to_column(copy.next_at)?,
            ],
        )?;
        Ok(())
    }

    fn delete_outbox_copy(
        &mut self,
        id: NativeOutboxId,
        mailbox: &str,
    ) -> Result<bool, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM native_outbox_mailbox WHERE outbox_id = ?1 AND mailbox = ?2",
            params![native_outbox_id_column(id)?, mailbox],
        )?;
        Ok(deleted > 0)
    }

    fn outbox_copies(&self, id: NativeOutboxId) -> Result<Vec<OutboxCopy>, StoreError> {
        let copies = self.collect(
            &format!(
                "SELECT {OUTBOX_COPY_COLUMNS} FROM native_outbox_mailbox WHERE outbox_id = ?1 \
                 ORDER BY mailbox"
            ),
            [native_outbox_id_column(id)?],
            decode_outbox_copy,
        )?;
        Ok(copies.into_iter().map(|stored| stored.copy).collect())
    }

    fn due_outbox_copies(&self, now: Timestamp) -> Result<Vec<StoredOutboxCopy>, StoreError> {
        self.collect(
            &format!(
                "SELECT {OUTBOX_COPY_COLUMNS} FROM native_outbox_mailbox \
                 WHERE state IN ('owed', 'cancel') AND next_at <= ?1 \
                 ORDER BY next_at, outbox_id, mailbox"
            ),
            [timestamp_to_column(now)?],
            decode_outbox_copy,
        )
    }
}

const OUTBOX_COPY_COLUMNS: &str = "outbox_id, mailbox, state, attempts, next_at";

fn decode_outbox_copy(row: &Row<'_>) -> Result<StoredOutboxCopy, StoreError> {
    let record = Record::NativeOutbox;
    let id: i64 = row.get(0)?;
    let state: String = row.get(2)?;
    Ok(StoredOutboxCopy {
        id: NativeOutboxId(u64::try_from(id).map_err(|_| corrupt(record, "copy entry"))?),
        copy: OutboxCopy {
            mailbox: row.get(1)?,
            state: decode_code(&state, CopyState::from_code, record, "copy state")?,
            attempts: decode_u32(row.get(3)?, record, "copy attempts")?,
            next_at: timestamp_from_column(row.get(4)?, record, "copy next at")?,
        },
    })
}

const PAYMENT_DELIVERY_COLUMNS: &str = "payment_id, alias, state, state_reason, updated_at";

fn decode_payment_delivery(row: &Row<'_>) -> Result<PaymentDelivery, StoreError> {
    let record = Record::PaymentDelivery;
    let payment_id: Vec<u8> = row.get(0)?;
    let state: Option<String> = row.get(2)?;
    Ok(PaymentDelivery {
        payment_id: decode_uuid(&payment_id, record)?,
        alias: row.get(1)?,
        state: state
            .map(|state| decode_code(&state, OutboxState::from_code, record, "state"))
            .transpose()?,
        state_reason: row.get(3)?,
        updated_at: timestamp_from_column(row.get(4)?, record, "updated at")?,
    })
}

impl PaymentDeliveryRepository for SqliteRepos<'_> {
    fn put_payment_delivery(&mut self, delivery: &PaymentDelivery) -> Result<(), StoreError> {
        delivery::check_payment_delivery(delivery)?;
        let payment_id = &delivery.payment_id.as_bytes()[..];
        if let Some(alias) = &delivery.alias
            && self.exists(
                "SELECT EXISTS (SELECT 1 FROM payment_delivery \
                 WHERE alias = ?1 AND payment_id != ?2)",
                params![alias, payment_id],
            )?
        {
            return Err(StoreError::Duplicate {
                record: Record::PaymentDelivery,
            });
        }
        self.conn.execute(
            &upsert("payment_delivery", PAYMENT_DELIVERY_COLUMNS, "payment_id"),
            params![
                payment_id,
                delivery.alias,
                delivery.state.map(OutboxState::code),
                delivery.state_reason,
                timestamp_to_column(delivery.updated_at)?,
            ],
        )?;
        Ok(())
    }

    fn payment_delivery(&self, payment_id: Uuid) -> Result<Option<PaymentDelivery>, StoreError> {
        self.first(
            &format!(
                "SELECT {PAYMENT_DELIVERY_COLUMNS} FROM payment_delivery WHERE payment_id = ?1"
            ),
            [&payment_id.as_bytes()[..]],
            decode_payment_delivery,
        )
    }

    fn payment_delivery_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<PaymentDelivery>, StoreError> {
        self.first(
            &format!("SELECT {PAYMENT_DELIVERY_COLUMNS} FROM payment_delivery WHERE alias = ?1"),
            [alias],
            decode_payment_delivery,
        )
    }
}

const NODE_POST_COLUMNS: &str = "tx_id, attempts, last_at, last_height, last_outcome, last_error, \
    accepted_once, unreachable_once";

fn decode_node_post(row: &Row<'_>) -> Result<NodePost, StoreError> {
    let record = Record::NodePost;
    let outcome: String = row.get(4)?;
    Ok(NodePost {
        tx_id: TxId(decode_u32(row.get(0)?, record, "tx id")?),
        attempts: decode_u32(row.get(1)?, record, "attempts")?,
        last_at: timestamp_from_column(row.get(2)?, record, "last at")?,
        last_height: Height::new(u64_from_column(row.get(3)?)),
        last_outcome: decode_code(&outcome, NodeOutcome::from_code, record, "last outcome")?,
        last_error: row.get(5)?,
        accepted_once: row.get(6)?,
        unreachable_once: row.get(7)?,
    })
}

impl NodePostRepository for SqliteRepos<'_> {
    fn put_node_post(&mut self, post: &NodePost) -> Result<(), StoreError> {
        node_post::check_node_post(post)?;
        self.require_transaction(post.tx_id)?;
        self.conn.execute(
            &upsert("node_post", NODE_POST_COLUMNS, "tx_id"),
            params![
                i64::from(post.tx_id.0),
                i64::from(post.attempts),
                timestamp_to_column(post.last_at)?,
                u64_to_column(post.last_height.value()),
                post.last_outcome.code(),
                post.last_error,
                post.accepted_once,
                post.unreachable_once,
            ],
        )?;
        Ok(())
    }

    fn node_post(&self, tx_id: TxId) -> Result<Option<NodePost>, StoreError> {
        self.first(
            &format!("SELECT {NODE_POST_COLUMNS} FROM node_post WHERE tx_id = ?1"),
            [i64::from(tx_id.0)],
            decode_node_post,
        )
    }
}

const RECOVERY_COLUMNS: &str = "tx_id, sent_tx, received_tx, state, kernel_height, last_error, \
    created_at, updated_at";

fn decode_recovery(row: &Row<'_>) -> Result<Recovery, StoreError> {
    let record = Record::Recovery;
    let state: String = row.get(3)?;
    let kernel_height: Option<i64> = row.get(4)?;
    Ok(Recovery {
        tx_id: TxId(decode_u32(row.get(0)?, record, "tx id")?),
        sent_tx: TxId(decode_u32(row.get(1)?, record, "sent tx")?),
        received_tx: TxId(decode_u32(row.get(2)?, record, "received tx")?),
        state: decode_code(&state, RecoveryState::from_code, record, "state")?,
        kernel_height: kernel_height.map(|height| Height::new(u64_from_column(height))),
        last_error: row.get(5)?,
        created_at: timestamp_from_column(row.get(6)?, record, "created at")?,
        updated_at: timestamp_from_column(row.get(7)?, record, "updated at")?,
    })
}

impl RecoveryRepository for SqliteRepos<'_> {
    fn put_recovery(&mut self, recovery: &Recovery) -> Result<(), StoreError> {
        recovery::check_recovery(recovery)?;
        self.require_transaction(recovery.tx_id)?;
        self.require_transaction(recovery.sent_tx)?;
        self.require_transaction(recovery.received_tx)?;
        self.conn.execute(
            &upsert("recovery", RECOVERY_COLUMNS, "tx_id"),
            params![
                i64::from(recovery.tx_id.0),
                i64::from(recovery.sent_tx.0),
                i64::from(recovery.received_tx.0),
                recovery.state.code(),
                recovery
                    .kernel_height
                    .map(|height| u64_to_column(height.value())),
                recovery.last_error,
                timestamp_to_column(recovery.created_at)?,
                timestamp_to_column(recovery.updated_at)?,
            ],
        )?;
        Ok(())
    }

    fn recovery(&self, tx_id: TxId) -> Result<Option<Recovery>, StoreError> {
        self.first(
            &format!("SELECT {RECOVERY_COLUMNS} FROM recovery WHERE tx_id = ?1"),
            [i64::from(tx_id.0)],
            decode_recovery,
        )
    }

    fn recoveries(&self) -> Result<Vec<Recovery>, StoreError> {
        self.collect(
            &format!("SELECT {RECOVERY_COLUMNS} FROM recovery ORDER BY tx_id"),
            [],
            decode_recovery,
        )
    }
}
