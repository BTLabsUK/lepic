//! Backends and record builders shared by the store tests.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::ser::{ProtocolVersion, deserialize};
use lepic_store::{
    AccountIndex, AccountRecord, CONTEXT_KEY_LEN, ContextKey, KEY_ID_LEN, KeyId, MemoryStore,
    OutputRecord, OutputStatus, SlateStage, SqliteStore, StoredSlate, TransactionEntry,
    TxDirection, TxState, WalletStore,
};
use tempfile::TempDir;
use uuid::Uuid;

/// Valid commitments taken from the primitives golden vectors.
const COMMITMENTS: [&str; 3] = [
    "0800b2b0747f49edaf03545b1f2d628204dcc6999db0479d97f6f4dc0fce6a4171",
    "0801a9bc52cb7febe68a8ddc75de2bef16251e1ecd72c2f1ab73803e25cbeeac24",
    "0806f6e3985898ebd7b898ccafd33df5e31a1a653862d6ecabafc6eea307733094",
];

/// A store implementation under test, able to reopen the same data with another key.
pub trait Backend {
    type Store: WalletStore;

    fn create(key: ContextKey) -> Self;
    fn store(&self) -> &Self::Store;
    fn reopen(&self, key: ContextKey) -> Self::Store;
}

pub struct SqliteBackend {
    dir: TempDir,
    store: SqliteStore,
}

impl SqliteBackend {
    pub fn path(&self) -> PathBuf {
        database_path(self.dir.path())
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
}

pub fn database_path(dir: &Path) -> PathBuf {
    dir.join("wallet.sqlite")
}

impl Backend for SqliteBackend {
    type Store = SqliteStore;

    fn create(key: ContextKey) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&database_path(dir.path()), key).unwrap();
        Self { dir, store }
    }

    fn store(&self) -> &SqliteStore {
        &self.store
    }

    fn reopen(&self, key: ContextKey) -> SqliteStore {
        SqliteStore::open(&self.path(), key).unwrap()
    }
}

pub struct MemoryBackend {
    store: MemoryStore,
}

impl Backend for MemoryBackend {
    type Store = MemoryStore;

    fn create(key: ContextKey) -> Self {
        Self {
            store: MemoryStore::new(key),
        }
    }

    fn store(&self) -> &MemoryStore {
        &self.store
    }

    fn reopen(&self, key: ContextKey) -> MemoryStore {
        self.store.reopen(key)
    }
}

pub fn context_key(byte: u8) -> ContextKey {
    ContextKey::from_bytes([byte; CONTEXT_KEY_LEN])
}

pub fn time(seconds: i64) -> Timestamp {
    Timestamp::from_second(1_700_000_000 + seconds).unwrap()
}

pub fn account(index: u32, label: &str) -> AccountRecord {
    AccountRecord {
        index: AccountIndex(index),
        label: label.to_owned(),
        next_child: index,
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// An output with the `n`th test commitment.
pub fn output(n: usize, account: AccountIndex, status: OutputStatus) -> OutputRecord {
    let mut identifier = vec![OutputFeatures::Plain.as_u8()];
    identifier.extend(hex(COMMITMENTS[n]));
    let mut key_id = [0; KEY_ID_LEN];
    key_id[0] = 3;
    key_id[KEY_ID_LEN - 1] = u8::try_from(n).unwrap();
    OutputRecord {
        id: deserialize::<OutputIdentifier>(&identifier, ProtocolVersion::V1).unwrap(),
        key_id: KeyId(key_id),
        account,
        amount: Amount::new(1_000 + u64::try_from(n).unwrap()),
        status,
        height: Height::new(10),
        lock_height: Height::new(0),
        mmr_index: None,
        tx: None,
    }
}

pub fn transaction(account: AccountIndex, slate_id: Option<Uuid>) -> TransactionEntry {
    TransactionEntry {
        account,
        direction: TxDirection::Outgoing,
        state: TxState::Sent,
        slate_id,
        transport: Some("file".to_owned()),
        amount_credited: Amount::new(0),
        amount_debited: Amount::new(250_000_000),
        fee: Some(Fee::new(800_000)),
        created_at: Timestamp::from_nanosecond(1_727_000_000_123_456_789).unwrap(),
        updated_at: Timestamp::from_nanosecond(1_727_000_001_000_000_000).unwrap(),
    }
}

pub fn slate(slate_id: Uuid, stage: SlateStage, bytes: &[u8]) -> StoredSlate {
    StoredSlate {
        slate_id,
        stage,
        codec: "legacy-v3".to_owned(),
        bytes: bytes.to_vec(),
    }
}
