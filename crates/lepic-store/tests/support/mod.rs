//! Backends and record builders shared by the store tests.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::ser::{ProtocolVersion, deserialize};
use lepic_store::{
    AccountIndex, AccountRecord, CONTEXT_KEY_LEN, ContactId, ContactKind, ContactMailbox,
    ContactOutboxEntry, ContactOutboxState, ContactRecord, ContactState, ContextKey, KEY_ID_LEN,
    KeyId, MemoryStore, OutputRecord, OutputStatus, PairingId, PairingRole, PairingSecrets,
    PairingState, PeerCard, PendingInvoice, PendingInvoiceStatus, PendingPairing, PreviousHome,
    RelayBackoff, SealMode, SlateStage, SqliteStore, StoredSlate, TransactionEntry, TxDirection,
    TxState, WalletStore,
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

/// A test Epicbox public key, distinct per `n`.
pub fn peer_key(n: u32) -> String {
    format!("es{n:0>50}")
}

/// A parked invoice from the peer with `peer_key(sender)`, received at `time(second)`.
pub fn invoice(slate_id: Uuid, sender: u32, second: i64) -> PendingInvoice {
    PendingInvoice {
        slate_id,
        sender_key: peer_key(sender),
        sender_address: format!("{}@relay.example:443", peer_key(sender)),
        received_at: time(second),
        status: PendingInvoiceStatus::Parked,
        codec: "legacy-v3".to_owned(),
        bytes: format!("{{\"invoice\":\"{slate_id}\"}}").into_bytes(),
    }
}

/// The slate id of the `n`th generated invoice.
pub fn invoice_id(n: u32) -> Uuid {
    Uuid::from_u128(0x1000_0000 + u128::from(n))
}

pub fn contact_id(n: u8) -> ContactId {
    ContactId([n; 16])
}

pub fn peer_card(n: u8) -> PeerCard {
    PeerCard {
        bytes: vec![0xc0, n, 0xde, 0xad],
        sig_key: [n; 32],
        enc_key: [n.wrapping_add(100); 32],
        hint_key: [n.wrapping_add(200); 32],
        seq: 1,
        kind: ContactKind::Shop,
        claimed_name: format!("Shop {n}"),
    }
}

/// A paired contact created at `time(second)`.
pub fn contact(n: u8, second: i64) -> ContactRecord {
    ContactRecord {
        contact_id: contact_id(n),
        account: AccountIndex(0),
        slot: u32::from(n),
        box_salt: [n.wrapping_add(50); 16],
        sas: Some([n, 1, 2, 3]),
        own_card: vec![n; 60],
        peer: Some(peer_card(n)),
        alternate: None,
        label: format!("contact {n}"),
        state: ContactState::Paired,
        verified_at: None,
        allow_invoices: false,
        seal: SealMode::On,
        last_sealed_in: None,
        app_contact: None,
        imported_from_backup: false,
        created_at: time(second),
        updated_at: time(second),
    }
}

pub fn contact_mailbox(n: u8) -> ContactMailbox {
    ContactMailbox {
        contact_id: contact_id(n),
        peer_mailbox: format!("peer{n}@relay.example:443"),
        our_mailbox: format!("our{n}@relay.example:443"),
        home_relay: "relay.example:443".to_owned(),
        onion: Some("relayonion.onion".to_owned()),
        previous: Some(PreviousHome {
            relay: "old.example:443".to_owned(),
            peer_mailbox: format!("oldpeer{n}@old.example:443"),
            our_mailbox: format!("oldour{n}@old.example:443"),
            until: time(7 * 86_400),
        }),
        backoff: vec![RelayBackoff {
            relay: "relay.example:443".to_owned(),
            next_try_at: time(30),
            failures: 3,
        }],
    }
}

/// A pairing in progress whose secrets are all set to bytes of `n`.
pub fn pairing(n: u8, second: i64) -> PendingPairing {
    PendingPairing {
        pairing_id: PairingId([n; 16]),
        role: PairingRole::Inviter,
        contact_id: contact_id(n),
        secrets: PairingSecrets {
            code: Some([n; 16]),
            na: Some([n.wrapping_add(1); 16]),
            nb: None,
            rc: Some([n.wrapping_add(2); 16]),
        },
        invite_id: [n; 8],
        expires_at: time(second + 600),
        our_mailbox: format!("our{n}@relay.example:443"),
        peer_mailbox: None,
        state: PairingState::PendingInvite,
        created_at: time(second),
        invite: vec![n; 40],
    }
}

pub fn contact_outbox_entry(n: u8, next_try: i64) -> ContactOutboxEntry {
    ContactOutboxEntry {
        contact_id: contact_id(n),
        slate_id: Uuid::from_u128(0x2000 + u128::from(next_try.unsigned_abs())),
        stage: SlateStage::Invoice1,
        payload: "BEGINSLATEPACK. payload. ENDSLATEPACK.".to_owned(),
        destination: format!("peer{n}@relay.example:443"),
        attempts: 0,
        next_try_at: time(next_try),
        state: ContactOutboxState::Queued,
        created_at: time(0),
        delivered_at: None,
    }
}
