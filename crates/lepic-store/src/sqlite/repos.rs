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
    self, CARD_KEY_LEN, ContactCap, ContactId, ContactKind, ContactMailbox, ContactOutboxEntry,
    ContactOutboxId, ContactOutboxState, ContactRecord, ContactRepository, ContactState,
    DomainClaimBytes, INVITE_ID_LEN, MAX_CANCELLED_PAIRINGS, MAX_CONTACTS, MAX_PENDING_PAIRINGS,
    PAYMENTS_KEY_LEN, PairRequest, PairingEndReason, PairingFacts, PairingId, PairingRole,
    PairingState, PeerCard, PendingPairing, PreviousHome, RelayBackoff, SealMode, StatusKind,
    StatusNotice, StatusNoticeId, StoredContactOutbox, StoredStatusNotice,
};
use crate::context::{
    self, ContextKey, ContextRepository, ParticipantId, PrivateContext, StoreKeys,
};
use crate::encoding::{timestamp_from_column, timestamp_to_column, u64_from_column, u64_to_column};
use crate::error::{Record, StoreError};
use crate::imported::{
    self, ChainCheck, ImportedKind, ImportedMessage, ImportedOutput, ImportedOutputStatus,
    ImportedRepository, ImportedTransaction,
};
use crate::invoice::{
    self, InvoiceAddressIndex, InvoiceRepository, PendingInvoice, PendingInvoiceStatus,
};
use crate::output::{CommitmentBytes, KeyId, OutputRecord, OutputRepository, OutputStatus};
use crate::peer::{self, PeerCompat, PeerRepository, PeerTag, PeerTagKey};
use crate::pin::{self, PIN_KEY_LEN, PeerPin, PeerPinRepository};
use crate::relay::{
    InboxEntry, InboxStatus, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
use crate::settings::SettingsRepository;
use crate::slate::{SlateRepository, SlateStage, StoredSlate};
use crate::transaction::{
    OpenReceipt, StoredTransaction, TransactionEntry, TransactionRepository, TxDirection, TxId,
    TxState, next_transaction_id,
};
use crate::tx_record::{
    FoundDuring, OtherWalletSpend, ScanFoundRecord, TxMarks, TxRecordRepository, TxWatch,
    WatchPhase, WatchedOutput,
};

/// The repositories over one open SQLite transaction.
pub(super) struct SqliteRepos<'a> {
    conn: &'a Connection,
    key: &'a ContextKey,
    peer_tag: &'a PeerTagKey,
}

impl<'a> SqliteRepos<'a> {
    pub(super) fn new(conn: &'a Connection, keys: &'a StoreKeys) -> Self {
        Self {
            conn,
            key: &keys.context,
            peer_tag: &keys.peer_tag,
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
        answer_marked: decode_flag(row.get(10)?, "answer marked")?,
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
                     withdrawn_answered, sender_cancelled_at, cancelled_answered, answer_marked
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
                 sender_cancelled_at, cancelled_answered, answer_marked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                marks.answer_marked,
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
        let mut statement = self.conn.prepare(
            "SELECT key, value FROM settings WHERE substr(key, 1, length(?1)) = ?1 ORDER BY key",
        )?;
        let rows = statement.query_map([prefix], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
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

impl PeerRepository for SqliteRepos<'_> {
    fn put_peer_compat(&mut self, key: &str, compat: &PeerCompat) -> Result<(), StoreError> {
        let tag = self.peer_tag.tag(key)?;
        let sealed = peer::seal(self.key, &tag, compat)?;
        self.conn.execute(
            "INSERT INTO peer_compat (key_tag, sealed) VALUES (?1, ?2)
             ON CONFLICT (key_tag) DO UPDATE SET sealed = excluded.sealed",
            params![tag.0.as_slice(), sealed],
        )?;
        Ok(())
    }

    fn peer_compat(&self, key: &str) -> Result<Option<PeerCompat>, StoreError> {
        let tag = self.peer_tag.tag(key)?;
        self.first(
            "SELECT sealed FROM peer_compat WHERE key_tag = ?1",
            [tag.0.as_slice()],
            |row| peer::open(self.key, &tag, &row.get::<_, Vec<u8>>(0)?),
        )
    }

    fn forget_peers(&mut self, before: Timestamp) -> Result<usize, StoreError> {
        let rows = self.collect("SELECT key_tag, sealed FROM peer_compat", [], |row| {
            let tag: [u8; 32] = row
                .get::<_, Vec<u8>>(0)?
                .try_into()
                .map_err(|_| corrupt(Record::PeerCompat, "key tag"))?;
            let compat = peer::open(self.key, &PeerTag(tag), &row.get::<_, Vec<u8>>(1)?)?;
            Ok((tag, compat))
        })?;
        let mut forgotten = 0_usize;
        for (tag, compat) in rows {
            if compat.last_seen().is_none_or(|seen| seen < before) {
                forgotten = forgotten.saturating_add(self.conn.execute(
                    "DELETE FROM peer_compat WHERE key_tag = ?1",
                    [tag.as_slice()],
                )?);
            }
        }
        Ok(forgotten)
    }
}

const PEER_PIN_COLUMNS: &str = "account, origin, seal_key, first_seen, last_seen";

fn decode_peer_pin(row: &Row<'_>) -> Result<PeerPin, StoreError> {
    let record = Record::PeerPin;
    let seal_key: [u8; PIN_KEY_LEN] = row
        .get::<_, Vec<u8>>(2)?
        .try_into()
        .map_err(|_| corrupt(record, "seal key"))?;
    Ok(PeerPin {
        account: AccountIndex(decode_u32(row.get(0)?, record, "account")?),
        origin: row.get(1)?,
        seal_key,
        first_seen: timestamp_from_column(row.get(3)?, record, "first seen")?,
        last_seen: timestamp_from_column(row.get(4)?, record, "last seen")?,
    })
}

impl PeerPinRepository for SqliteRepos<'_> {
    fn put_peer_pin(&mut self, pin: &PeerPin) -> Result<(), StoreError> {
        pin::check_origin(&pin.origin)?;
        self.conn.execute(
            "INSERT INTO peer_pins (account, origin, seal_key, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (account, origin) DO UPDATE SET seal_key = excluded.seal_key,
                 first_seen = excluded.first_seen, last_seen = excluded.last_seen",
            params![
                i64::from(pin.account.0),
                pin.origin,
                pin.seal_key.as_slice(),
                timestamp_to_column(pin.first_seen)?,
                timestamp_to_column(pin.last_seen)?,
            ],
        )?;
        Ok(())
    }

    fn peer_pin(&self, account: AccountIndex, origin: &str) -> Result<Option<PeerPin>, StoreError> {
        self.first(
            &format!("SELECT {PEER_PIN_COLUMNS} FROM peer_pins WHERE account = ?1 AND origin = ?2"),
            params![i64::from(account.0), origin],
            decode_peer_pin,
        )
    }

    fn peer_pins(&self, account: AccountIndex) -> Result<Vec<PeerPin>, StoreError> {
        self.collect(
            &format!("SELECT {PEER_PIN_COLUMNS} FROM peer_pins WHERE account = ?1 ORDER BY origin"),
            [i64::from(account.0)],
            decode_peer_pin,
        )
    }

    fn forget_peer_pin(&mut self, account: AccountIndex, origin: &str) -> Result<bool, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM peer_pins WHERE account = ?1 AND origin = ?2",
            params![i64::from(account.0), origin],
        )?;
        Ok(deleted > 0)
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

fn decode_contact_outbox(row: &Row<'_>) -> Result<StoredContactOutbox, StoreError> {
    let record = Record::ContactOutbox;
    let id: i64 = row.get(0)?;
    let contact_id: Vec<u8> = row.get(1)?;
    let slate_id: Vec<u8> = row.get(2)?;
    let stage: String = row.get(3)?;
    let state: String = row.get(8)?;
    Ok(StoredContactOutbox {
        id: ContactOutboxId(u64::try_from(id).map_err(|_| corrupt(record, "id"))?),
        entry: ContactOutboxEntry {
            contact_id: ContactId(fixed(&contact_id, record, "contact id")?),
            slate_id: decode_uuid(&slate_id, record)?,
            stage: decode_code(&stage, SlateStage::from_code, record, "stage")?,
            payload: row.get(4)?,
            destination: row.get(5)?,
            attempts: decode_u32(row.get(6)?, record, "attempts")?,
            next_try_at: timestamp_from_column(row.get(7)?, record, "next try at")?,
            state: decode_code(&state, ContactOutboxState::from_code, record, "state")?,
            created_at: timestamp_from_column(row.get(9)?, record, "created at")?,
            delivered_at: optional_time(row.get(10)?, record, "delivered at")?,
        },
    })
}

const CONTACT_OUTBOX_COLUMNS: &str = "id, contact_id, slate_id, stage, payload, destination, \
    attempts, next_try_at, state, created_at, delivered_at";

fn contact_outbox_id_column(id: ContactOutboxId) -> Result<i64, StoreError> {
    i64::try_from(id.0).map_err(|_| StoreError::OutOfRange { field: "outbox id" })
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

    fn contact_by_peer_hint_key(
        &self,
        key: &[u8; CARD_KEY_LEN],
    ) -> Result<Option<ContactRecord>, StoreError> {
        Ok(self
            .contact_where("peer_hint_key = ?1", [&key[..]])?
            .into_iter()
            .next())
    }

    fn contacts_by_our_mailbox(&self, address: &str) -> Result<Vec<ContactRecord>, StoreError> {
        self.contact_where(
            "contact_id IN (SELECT contact_id FROM contact_mailboxes \
                 WHERE our_mailbox = ?1 OR prev_our_mailbox = ?1)",
            [address],
        )
    }

    fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError> {
        self.contact_where("1", [])
    }

    fn contacts_allowing_invoices(&self) -> Result<Vec<ContactRecord>, StoreError> {
        self.contact_where("allow_invoices = 1", [])
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
        Ok(self
            .conn
            .execute("DELETE FROM contacts WHERE contact_id = ?1", [&id.0[..]])?
            > 0)
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
            let (sql, cap) = if cancelled {
                (
                    "SELECT COUNT(*) FROM pairings WHERE cancelled_at IS NOT NULL",
                    MAX_CANCELLED_PAIRINGS,
                )
            } else {
                (
                    "SELECT COUNT(*) FROM pairings WHERE cancelled_at IS NULL",
                    MAX_PENDING_PAIRINGS,
                )
            };
            if self.count(sql, [])? >= cap {
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
        Ok(self
            .conn
            .execute("DELETE FROM pairings WHERE pairing_id = ?1", [&id.0[..]])?
            > 0)
    }

    fn prune_expired_pairings(&mut self, now: Timestamp) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM pairings WHERE expires_at <= ?1",
            [timestamp_to_column(now)?],
        )?)
    }

    fn enqueue_contact_outbox(
        &mut self,
        entry: &ContactOutboxEntry,
    ) -> Result<ContactOutboxId, StoreError> {
        contact::check_outbox(entry)?;
        self.require_contact(entry.contact_id)?;
        self.conn.execute(
            "INSERT INTO contact_outbox (contact_id, slate_id, stage, payload, destination, \
                 attempts, next_try_at, state, created_at, delivered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                &entry.contact_id.0[..],
                &entry.slate_id.as_bytes()[..],
                entry.stage.code(),
                entry.payload,
                entry.destination,
                i64::from(entry.attempts),
                timestamp_to_column(entry.next_try_at)?,
                entry.state.code(),
                timestamp_to_column(entry.created_at)?,
                optional_column(entry.delivered_at)?,
            ],
        )?;
        u64::try_from(self.conn.last_insert_rowid())
            .map(ContactOutboxId)
            .map_err(|_| StoreError::OutOfRange { field: "outbox id" })
    }

    fn update_contact_outbox(
        &mut self,
        id: ContactOutboxId,
        entry: &ContactOutboxEntry,
    ) -> Result<(), StoreError> {
        contact::check_outbox(entry)?;
        self.require_contact(entry.contact_id)?;
        let changed = self.conn.execute(
            "UPDATE contact_outbox SET contact_id = ?2, slate_id = ?3, stage = ?4, payload = ?5, \
                 destination = ?6, attempts = ?7, next_try_at = ?8, state = ?9, created_at = ?10, \
                 delivered_at = ?11 WHERE id = ?1",
            params![
                contact_outbox_id_column(id)?,
                &entry.contact_id.0[..],
                &entry.slate_id.as_bytes()[..],
                entry.stage.code(),
                entry.payload,
                entry.destination,
                i64::from(entry.attempts),
                timestamp_to_column(entry.next_try_at)?,
                entry.state.code(),
                timestamp_to_column(entry.created_at)?,
                optional_column(entry.delivered_at)?,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                record: Record::ContactOutbox,
            });
        }
        Ok(())
    }

    fn contact_outbox_entry(
        &self,
        id: ContactOutboxId,
    ) -> Result<Option<StoredContactOutbox>, StoreError> {
        self.first(
            &format!("SELECT {CONTACT_OUTBOX_COLUMNS} FROM contact_outbox WHERE id = ?1"),
            [contact_outbox_id_column(id)?],
            decode_contact_outbox,
        )
    }

    fn contact_outbox(&self, contact: ContactId) -> Result<Vec<StoredContactOutbox>, StoreError> {
        self.collect(
            &format!(
                "SELECT {CONTACT_OUTBOX_COLUMNS} FROM contact_outbox WHERE contact_id = ?1 ORDER BY id"
            ),
            [&contact.0[..]],
            decode_contact_outbox,
        )
    }

    fn due_contact_outbox(&self, now: Timestamp) -> Result<Vec<StoredContactOutbox>, StoreError> {
        self.collect(
            &format!(
                "SELECT {CONTACT_OUTBOX_COLUMNS} FROM contact_outbox \
                 WHERE state = 'queued' AND next_try_at <= ?1 ORDER BY next_try_at, id"
            ),
            [timestamp_to_column(now)?],
            decode_contact_outbox,
        )
    }

    fn redirect_contact_outbox(
        &mut self,
        contact: ContactId,
        destination: &str,
    ) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "UPDATE contact_outbox SET destination = ?2 \
             WHERE contact_id = ?1 AND state != 'delivered' AND destination != ?2",
            params![&contact.0[..], destination],
        )?)
    }

    fn delete_contact_outbox(&mut self, id: ContactOutboxId) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM contact_outbox WHERE id = ?1",
            [contact_outbox_id_column(id)?],
        )?;
        Ok(())
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

    fn put_pair_request(&mut self, request: &PairRequest) -> Result<(), StoreError> {
        contact::check_pair_request(request)?;
        self.conn.execute(
            &upsert("pair_requests", PAIR_REQUEST_COLUMNS, "sender_key"),
            params![
                &request.sender_key[..],
                request.sender_address,
                &request.invite_id[..],
                request.invite,
                timestamp_to_column(request.expires_at)?,
                timestamp_to_column(request.received_at)?,
                optional_column(request.dismissed_at)?,
                optional_column(request.answered_at)?,
            ],
        )?;
        Ok(())
    }

    fn pair_request(
        &self,
        sender_key: &[u8; PAYMENTS_KEY_LEN],
    ) -> Result<Option<PairRequest>, StoreError> {
        self.first(
            &format!("SELECT {PAIR_REQUEST_COLUMNS} FROM pair_requests WHERE sender_key = ?1"),
            [&sender_key[..]],
            decode_pair_request,
        )
    }

    fn pair_request_by_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> Result<Option<PairRequest>, StoreError> {
        self.first(
            &format!(
                "SELECT {PAIR_REQUEST_COLUMNS} FROM pair_requests WHERE invite_id = ?1 \
                 ORDER BY received_at"
            ),
            [&invite_id[..]],
            decode_pair_request,
        )
    }

    fn pair_requests(&self) -> Result<Vec<PairRequest>, StoreError> {
        self.collect(
            &format!(
                "SELECT {PAIR_REQUEST_COLUMNS} FROM pair_requests ORDER BY received_at, sender_key"
            ),
            [],
            decode_pair_request,
        )
    }

    fn delete_pair_request(
        &mut self,
        sender_key: &[u8; PAYMENTS_KEY_LEN],
    ) -> Result<bool, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM pair_requests WHERE sender_key = ?1",
            [&sender_key[..]],
        )? > 0)
    }

    fn enqueue_status_notice(
        &mut self,
        notice: &StatusNotice,
    ) -> Result<StatusNoticeId, StoreError> {
        contact::check_status_notice(notice)?;
        self.conn.execute(
            "INSERT INTO contact_status_out (contact_id, kind, payload, destination, attempts, \
                 next_try_at, created_at, expires_at, delivered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            status_params(notice)?,
        )?;
        let id = self.conn.last_insert_rowid();
        Ok(StatusNoticeId(u64::try_from(id).map_err(|_| {
            StoreError::OutOfRange {
                field: "status notice id",
            }
        })?))
    }

    fn update_status_notice(
        &mut self,
        id: StatusNoticeId,
        notice: &StatusNotice,
    ) -> Result<(), StoreError> {
        contact::check_status_notice(notice)?;
        let [
            contact_id,
            kind,
            payload,
            destination,
            attempts,
            next,
            created,
            expires,
            delivered,
        ] = status_params(notice)?;
        let changed = self.conn.execute(
            "UPDATE contact_status_out SET contact_id = ?1, kind = ?2, payload = ?3, \
                 destination = ?4, attempts = ?5, next_try_at = ?6, created_at = ?7, \
                 expires_at = ?8, delivered_at = ?9 WHERE id = ?10",
            params![
                contact_id,
                kind,
                payload,
                destination,
                attempts,
                next,
                created,
                expires,
                delivered,
                status_id_column(id)?
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                record: Record::StatusNotice,
            });
        }
        Ok(())
    }

    fn due_status_notices(&self, now: Timestamp) -> Result<Vec<StoredStatusNotice>, StoreError> {
        self.collect(
            &format!(
                "SELECT {STATUS_COLUMNS} FROM contact_status_out \
                 WHERE delivered_at IS NULL AND next_try_at <= ?1 ORDER BY next_try_at, id"
            ),
            [timestamp_to_column(now)?],
            decode_status_notice,
        )
    }

    fn status_notices(&self, contact: ContactId) -> Result<Vec<StoredStatusNotice>, StoreError> {
        self.collect(
            &format!(
                "SELECT {STATUS_COLUMNS} FROM contact_status_out WHERE contact_id = ?1 ORDER BY id"
            ),
            [&contact.0[..]],
            decode_status_notice,
        )
    }

    fn delete_status_notice(&mut self, id: StatusNoticeId) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM contact_status_out WHERE id = ?1",
            [status_id_column(id)?],
        )?;
        Ok(())
    }
}

const PAIR_REQUEST_COLUMNS: &str = "sender_key, sender_address, invite_id, invite, expires_at, \
    received_at, dismissed_at, answered_at";

fn decode_pair_request(row: &Row<'_>) -> Result<PairRequest, StoreError> {
    let record = Record::PairRequest;
    Ok(PairRequest {
        sender_key: fixed(&row.get::<_, Vec<u8>>(0)?, record, "sender key")?,
        sender_address: row.get(1)?,
        invite_id: fixed(&row.get::<_, Vec<u8>>(2)?, record, "invite id")?,
        invite: row.get(3)?,
        expires_at: timestamp_from_column(row.get(4)?, record, "expires at")?,
        received_at: timestamp_from_column(row.get(5)?, record, "received at")?,
        dismissed_at: optional_time(row.get(6)?, record, "dismissed at")?,
        answered_at: optional_time(row.get(7)?, record, "answered at")?,
    })
}

const STATUS_COLUMNS: &str = "id, contact_id, kind, payload, destination, attempts, next_try_at, \
    created_at, expires_at, delivered_at";

fn status_id_column(id: StatusNoticeId) -> Result<i64, StoreError> {
    i64::try_from(id.0).map_err(|_| StoreError::OutOfRange {
        field: "status notice id",
    })
}

fn status_params(notice: &StatusNotice) -> Result<[rusqlite::types::Value; 9], StoreError> {
    Ok([
        notice.contact_id.0.to_vec().into(),
        notice.kind.code().to_owned().into(),
        notice.payload.clone().into(),
        notice.destination.clone().into(),
        i64::from(notice.attempts).into(),
        timestamp_to_column(notice.next_try_at)?.into(),
        timestamp_to_column(notice.created_at)?.into(),
        timestamp_to_column(notice.expires_at)?.into(),
        optional_column(notice.delivered_at)?.into(),
    ])
}

fn decode_status_notice(row: &Row<'_>) -> Result<StoredStatusNotice, StoreError> {
    let record = Record::StatusNotice;
    let id: i64 = row.get(0)?;
    let kind: String = row.get(2)?;
    Ok(StoredStatusNotice {
        id: StatusNoticeId(u64::try_from(id).map_err(|_| corrupt(record, "id"))?),
        notice: StatusNotice {
            contact_id: ContactId(fixed(&row.get::<_, Vec<u8>>(1)?, record, "contact id")?),
            kind: decode_code(&kind, StatusKind::from_code, record, "kind")?,
            payload: row.get(3)?,
            destination: row.get(4)?,
            attempts: decode_u32(row.get(5)?, record, "attempts")?,
            next_try_at: timestamp_from_column(row.get(6)?, record, "next try at")?,
            created_at: timestamp_from_column(row.get(7)?, record, "created at")?,
            expires_at: timestamp_from_column(row.get(8)?, record, "expires at")?,
            delivered_at: optional_time(row.get(9)?, record, "delivered at")?,
        },
    })
}
