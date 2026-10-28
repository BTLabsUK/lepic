// SPDX-License-Identifier: Apache-2.0
//! An `epic-wallet` wallet folder built as upstream writes it, for a seed the test controls, and
//! the chain that wallet's unspent outputs sit on. Row keys are the `{:?}` text of the key
//! bytes and row data is the serde JSON of the record, as `crates/lepic-store/tests/legacy.rs`
//! writes them.

// Each test binary uses a different subset of these helpers, and test helpers may unwrap, index
// and panic (docs/rules.md).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lepic_crypto::aggsig::{create_secnonce, sign_single};
use lepic_crypto::{Commitment, Message, PublicKey, SecretKey, Signature};
use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, Keychain, ProofBuilder, SwitchCommitment};
use lepic_node::LocatedKernel;
use lepic_node::mock::{ChainOutput, MockNode};
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::hash::blake2b_256;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rusqlite::Connection;
use serde_json::{Value, json};

/// The wallet the tests restore: the phrase of `tests/messages.rs`.
pub const MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// A valid phrase of another seed.
pub const OTHER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

/// The height the scripted chain's tip is at.
pub const TIP: u64 = 100;

/// `Store::check_or_create` of epic-wallet 4.0.2 `impls/src/backends/db.rs`.
const UPSTREAM_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS data (
        id INTEGER PRIMARY KEY,
        key BLOB NOT NULL UNIQUE,
        prefix TEXT,
        data TEXT NOT NULL,
        q_tx_id INTEGER,
        q_confirmed INTEGER,
        q_tx_status TEXT);
    CREATE INDEX IF NOT EXISTS prefix_index ON data (prefix);
    CREATE INDEX IF NOT EXISTS q_tx_id_index ON data (q_tx_id);
    CREATE INDEX IF NOT EXISTS q_confirmed_index ON data (q_confirmed);
    CREATE INDEX IF NOT EXISTS q_tx_status_index ON data (q_tx_status);
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA wal_checkpoint(TRUNCATE);
"#;

pub fn keychain(phrase: &str) -> Keychain {
    Keychain::from_mnemonic(phrase, lepic_primitives::params::Network::Mainnet).unwrap()
}

pub fn parent_path(account: u32) -> Identifier {
    Identifier::new(2, [account, 0, 0, 0]).unwrap()
}

pub fn output_key(account: u32, child: u32) -> Identifier {
    Identifier::new(3, [account, 0, child, 0]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn to_key(prefix: u8, rest: &[u8], number: Option<u64>) -> Vec<u8> {
    let mut key = vec![prefix, b':'];
    key.extend_from_slice(rest);
    if let Some(number) = number {
        key.extend_from_slice(&number.to_be_bytes());
    }
    key
}

fn put(conn: &Connection, key: &[u8], data: &Value) {
    conn.execute(
        "INSERT INTO data (key, data, prefix) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET data = excluded.data",
        rusqlite::params![
            format!("{key:?}"),
            serde_json::to_string(data).unwrap(),
            (key[0] as char).to_string()
        ],
    )
    .unwrap();
}

/// A participant message the old wallet signed: the signature is over the BLAKE2b hash of
/// `signed_text` under `secret`, and the row shows `shown_text`. They differ for a message
/// whose signature does not verify.
pub fn message(participant: u8, shown_text: &str, signed_text: &str, secret: u8) -> Value {
    let secret = SecretKey::from_array([secret; 32]).unwrap();
    let public = PublicKey::from_secret_key(&secret).unwrap();
    let digest = Message::from(*blake2b_256(signed_text.as_bytes()).as_bytes());
    let nonce = create_secnonce(&mut StdRng::seed_from_u64(u64::from(participant) + 5)).unwrap();
    let signature: Signature = sign_single(&digest, &secret, &nonce, Some(&public)).unwrap();
    json!({
        "id": participant.to_string(),
        "public_key": public.to_hex(),
        "message": shown_text,
        "message_sig": signature.to_compact_hex(),
    })
}

/// A message signed correctly.
pub fn signed(participant: u8, text: &str) -> Value {
    message(participant, text, text, participant + 21)
}

/// A message whose signature belongs to other text.
pub fn forged(participant: u8, text: &str) -> Value {
    message(
        participant,
        text,
        "what was really signed",
        participant + 21,
    )
}

/// A `TxLogEntry` of the old wallet.
#[derive(Clone)]
pub struct OldTx {
    pub account: u32,
    pub id: u32,
    pub kind: &'static str,
    pub slate: Option<&'static str>,
    pub created: &'static str,
    pub confirmed_at: Option<&'static str>,
    pub confirmed: bool,
    pub credited: u64,
    pub debited: u64,
    pub fee: Option<u64>,
    pub kernel: Option<Commitment>,
    pub ttl: Option<u64>,
    pub address: Option<&'static str>,
    pub messages: Vec<Value>,
}

impl OldTx {
    pub fn new(account: u32, id: u32, kind: &'static str, created: &'static str) -> Self {
        Self {
            account,
            id,
            kind,
            slate: None,
            created,
            confirmed_at: None,
            confirmed: false,
            credited: 0,
            debited: 0,
            fee: None,
            kernel: None,
            ttl: None,
            address: None,
            messages: Vec::new(),
        }
    }

    fn json(&self) -> Value {
        let messages = if self.messages.is_empty() {
            Value::Null
        } else {
            json!({"messages": self.messages})
        };
        json!({
            "confirmation_height": null,
            "parent_key_id": hex(&parent_path(self.account).to_bytes()),
            "id": self.id,
            "tx_slate_id": self.slate,
            "tx_type": self.kind,
            "creation_ts": self.created,
            "confirmation_ts": self.confirmed_at,
            "confirmed": self.confirmed,
            // As epic-wallet counts them: a receipt makes one output, a send one change
            // output when it has change, and spends at least one input.
            "num_inputs": u32::from(self.debited > 0),
            "num_outputs": u32::from(self.credited > 0),
            "amount_credited": self.credited.to_string(),
            "amount_debited": self.debited.to_string(),
            "fee": self.fee.map(|fee| fee.to_string()),
            "ttl_cutoff_height": self.ttl.map(|ttl| ttl.to_string()),
            "messages": messages,
            "stored_tx": null,
            "kernel_excess": self.kernel.map(|kernel| kernel.to_hex()),
            "kernel_lookup_min_height": null,
            "payment_proof": null,
            "public_addr": self.address,
        })
    }
}

/// An `OutputData` of the old wallet. `on_chain` says whether the scripted chain holds it
/// unspent.
#[derive(Clone)]
pub struct OldOutput {
    pub account: u32,
    pub child: u32,
    pub value: u64,
    pub status: &'static str,
    pub height: u64,
    pub tx: u32,
    pub on_chain: bool,
}

impl OldOutput {
    fn json(&self, keychain: &Keychain) -> Value {
        let id = output_key(self.account, self.child);
        let commit = keychain
            .commit(self.value, &id, SwitchCommitment::Regular)
            .unwrap();
        json!({
            "root_key_id": hex(&parent_path(self.account).to_bytes()),
            "key_id": hex(&id.to_bytes()),
            "n_child": self.child,
            "commit": commit.to_hex(),
            "mmr_index": null,
            "value": self.value.to_string(),
            "status": self.status,
            "height": self.height.to_string(),
            "lock_height": "0",
            "is_coinbase": false,
            "tx_log_entry": self.tx,
        })
    }

    pub fn commitment(&self, keychain: &Keychain) -> Commitment {
        keychain
            .commit(
                self.value,
                &output_key(self.account, self.child),
                SwitchCommitment::Regular,
            )
            .unwrap()
    }
}

/// What `epic-wallet` kept of a wallet's life, written to `epic.db`.
#[derive(Clone)]
pub struct OldWallet {
    pub accounts: Vec<(&'static str, u32)>,
    /// The `d` counter of each account: the next child number.
    pub counters: Vec<(u32, u32)>,
    pub txs: Vec<OldTx>,
    pub outputs: Vec<OldOutput>,
}

pub const SLATE_RECEIVED: &str = "0436430c-2b02-624c-2032-570501212b01";
pub const SLATE_SENT: &str = "0436430c-2b02-624c-2032-570501212b02";
pub const SLATE_PIZZA: &str = "0436430c-2b02-624c-2032-570501212b03";
pub const SLATE_RECEIVED_CANCELLED: &str = "0436430c-2b02-624c-2032-570501212b04";
pub const SLATE_SENT_CANCELLED: &str = "0436430c-2b02-624c-2032-570501212b05";
pub const SLATE_POSTED: &str = "0436430c-2b02-624c-2032-570501212b06";
pub const SLATE_CREATED: &str = "0436430c-2b02-624c-2032-570501212b07";
pub const SLATE_MISSING: &str = "0436430c-2b02-624c-2032-570501212b08";
pub const SLATE_SAVINGS: &str = "0436430c-2b02-624c-2032-570501212b09";

pub const ADDRESS_RENT: &str =
    "esZ9vkLRuuGCqwsQZpw7MaDTGaQSXHU3y5pKJ8xTm3TZgnDtvBYX@epicbox.epiccash.com";
pub const ADDRESS_PIZZA: &str =
    "esWTvWLpXSQ2PMo8ZhrmGgSbJxUBMFYtKsBwBAGWFB8n9pYtCqG5@epicbox.epiccash.com";

/// The excess of the old wallet's posted send.
pub fn posted_excess(keychain: &Keychain) -> Commitment {
    keychain
        .commit(0, &output_key(0, 900), SwitchCommitment::None)
        .unwrap()
}

/// The excess of the old wallet's confirmed send.
pub fn sent_excess(keychain: &Keychain) -> Commitment {
    keychain
        .commit(0, &output_key(0, 901), SwitchCommitment::None)
        .unwrap()
}

impl OldWallet {
    /// The default account and `savings`, with transactions of every kind (log ids 0..=7 in the
    /// default account, a log id 0 in `savings` as well) and a counter below the highest key.
    ///
    /// On the chain: the 69 M, 50 M and savings 25 M outputs. Off the chain: spent, cancelled
    /// and unconfirmed outputs, and an 11 M output the old wallet still held unspent.
    pub fn standard(keychain: &Keychain) -> Self {
        let mut received = OldTx::new(0, 0, "TxReceived", "2024-03-01T10:20:30.123456789Z");
        received.slate = Some(SLATE_RECEIVED);
        received.confirmed = true;
        received.confirmed_at = Some("2024-03-01T10:25:00Z");
        received.credited = 100_000_000;
        received.address = Some("Restore");

        let mut sent = OldTx::new(0, 1, "TxSent", "2024-03-02T09:00:01.5Z");
        sent.slate = Some(SLATE_SENT);
        sent.confirmed = true;
        sent.confirmed_at = Some("2024-03-02T09:30:00Z");
        sent.debited = 100_000_000;
        sent.credited = 69_000_000;
        sent.fee = Some(1_000_000);
        sent.kernel = Some(sent_excess(keychain));
        sent.ttl = Some(500);
        sent.address = Some(ADDRESS_RENT);
        sent.messages = vec![signed(0, "rent for march"), signed(1, "thanks")];

        let mut pizza = OldTx::new(0, 2, "TxReceived", "2024-03-03T12:00:00Z");
        pizza.slate = Some(SLATE_PIZZA);
        pizza.confirmed = true;
        pizza.confirmed_at = Some("2024-03-03T12:10:00Z");
        pizza.credited = 50_000_000;
        pizza.address = Some(ADDRESS_PIZZA);
        pizza.messages = vec![signed(0, "for the pizza"), forged(1, "bogus reply")];

        let mut received_cancelled =
            OldTx::new(0, 3, "TxReceivedCancelled", "2024-03-04T08:00:00Z");
        received_cancelled.slate = Some(SLATE_RECEIVED_CANCELLED);
        received_cancelled.credited = 7_000_000;

        let mut sent_cancelled = OldTx::new(0, 4, "TxSentCancelled", "2024-03-05T08:00:00Z");
        sent_cancelled.slate = Some(SLATE_SENT_CANCELLED);
        sent_cancelled.debited = 20_000_000;
        sent_cancelled.credited = 18_000_000;
        sent_cancelled.fee = Some(2_000_000);

        let mut posted = OldTx::new(0, 5, "TxSent", "2024-03-06T08:00:00Z");
        posted.slate = Some(SLATE_POSTED);
        posted.debited = 30_000_000;
        posted.credited = 28_000_000;
        posted.fee = Some(2_000_000);
        posted.kernel = Some(posted_excess(keychain));
        posted.ttl = Some(900);

        let mut created = OldTx::new(0, 6, "TxSent", "2024-03-07T08:00:00Z");
        created.slate = Some(SLATE_CREATED);
        created.debited = 10_000_000;
        created.credited = 9_000_000;
        created.fee = Some(1_000_000);

        let mut missing = OldTx::new(0, 7, "TxReceived", "2024-03-08T08:00:00Z");
        missing.slate = Some(SLATE_MISSING);
        missing.confirmed = true;
        missing.confirmed_at = Some("2024-03-08T08:05:00Z");
        missing.credited = 11_000_000;

        let mut savings = OldTx::new(1, 0, "TxReceived", "2024-03-09T08:00:00Z");
        savings.slate = Some(SLATE_SAVINGS);
        savings.confirmed = true;
        savings.confirmed_at = Some("2024-03-09T08:05:00Z");
        savings.credited = 25_000_000;

        let output = |account, child, value, status, height, tx, on_chain| OldOutput {
            account,
            child,
            value,
            status,
            height,
            tx,
            on_chain,
        };
        Self {
            accounts: vec![("default", 0), ("savings", 1)],
            counters: vec![(0, 4), (1, 3)],
            txs: vec![
                received,
                sent,
                pizza,
                received_cancelled,
                sent_cancelled,
                posted,
                created,
                missing,
                savings,
            ],
            outputs: vec![
                output(0, 0, 100_000_000, "Spent", 10, 0, false),
                output(0, 1, 69_000_000, "Unspent", 20, 1, true),
                output(0, 2, 50_000_000, "Unspent", 30, 2, true),
                output(0, 3, 7_000_000, "Deleted", 40, 3, false),
                output(0, 4, 18_000_000, "Deleted", 45, 4, false),
                output(0, 5, 28_000_000, "Unconfirmed", 0, 5, false),
                output(0, 6, 9_000_000, "Unconfirmed", 0, 6, false),
                output(0, 7, 11_000_000, "Unspent", 60, 7, false),
                output(1, 0, 25_000_000, "Unspent", 50, 0, true),
            ],
        }
    }

    pub fn tx_mut(&mut self, account: u32, id: u32) -> &mut OldTx {
        self.txs
            .iter_mut()
            .find(|tx| tx.account == account && tx.id == id)
            .unwrap()
    }

    pub fn output_mut(&mut self, account: u32, child: u32) -> &mut OldOutput {
        self.outputs
            .iter_mut()
            .find(|output| output.account == account && output.child == child)
            .unwrap()
    }

    /// Writes `<dir>/wallet_data/db/sqlite/epic.db` and returns its path.
    pub fn write(&self, keychain: &Keychain, dir: &Path) -> PathBuf {
        let sqlite = dir.join("wallet_data/db/sqlite");
        fs::create_dir_all(&sqlite).unwrap();
        fs::create_dir_all(dir.join("wallet_data/saved_txs")).unwrap();
        let db = sqlite.join("epic.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(UPSTREAM_SCHEMA).unwrap();
        for (label, account) in &self.accounts {
            put(
                &conn,
                &to_key(b'a', label.as_bytes(), None),
                &json!({"label": label, "path": hex(&parent_path(*account).to_bytes())}),
            );
        }
        for (account, next) in &self.counters {
            put(
                &conn,
                &to_key(b'd', &parent_path(*account).to_bytes(), None),
                &json!(next),
            );
        }
        // Private contexts must never be read.
        put(
            &conn,
            &to_key(b'p', &[7; 16], Some(0)),
            &json!({"sec_key": "not for import"}),
        );
        for tx in &self.txs {
            put(
                &conn,
                &to_key(
                    b't',
                    &parent_path(tx.account).to_bytes(),
                    Some(u64::from(tx.id)),
                ),
                &tx.json(),
            );
        }
        for output in &self.outputs {
            put(
                &conn,
                &to_key(
                    b'o',
                    &output_key(output.account, output.child).to_bytes(),
                    None,
                ),
                &output.json(keychain),
            );
        }
        drop(conn);
        db
    }

    /// The outputs the scripted chain holds: (account, child, value, height).
    pub fn chain_outputs(&self) -> Vec<(u32, u32, u64, u64)> {
        self.outputs
            .iter()
            .filter(|output| output.on_chain)
            .map(|output| (output.account, output.child, output.value, output.height))
            .collect()
    }
}

/// Puts plain outputs on the scripted chain, one per `(account, child, value, height)`, with
/// range proofs the wallet's scan recognises, and moves the tip to [`TIP`].
pub fn put_outputs(node: &MockNode, keychain: &Keychain, outputs: &[(u32, u32, u64, u64)]) {
    let builder = ProofBuilder::new(keychain).unwrap();
    let mut sorted = outputs.to_vec();
    sorted.sort_by_key(|(_, _, _, height)| *height);
    let made: Vec<ChainOutput> = sorted
        .iter()
        .map(|(account, child, value, height)| {
            let output = create_output(
                keychain,
                &builder,
                *value,
                &output_key(*account, *child),
                SwitchCommitment::Regular,
            )
            .unwrap();
            ChainOutput {
                commitment: output.commitment,
                features: output.features,
                proof: output.proof.clone(),
                height: Height::new(*height),
                mmr_index: 0,
                spent: false,
            }
        })
        .collect();
    node.update_chain(|chain| {
        chain.tip.height = Height::new(TIP);
        let first = chain.outputs.len() as u64;
        for (position, mut output) in made.into_iter().enumerate() {
            output.mmr_index = first + position as u64 + 1;
            chain.outputs.push(output);
        }
    });
}

/// The kernel `excess` as the node holds it, mined at `height`.
pub fn put_kernel(node: &MockNode, excess: Commitment, height: u64) {
    let kernel = TxKernel::new(
        KernelFeatures::Plain {
            fee: Fee::new(2_000_000),
        },
        excess,
        Signature::from_raw(&[9; 64]).unwrap(),
    );
    node.update_chain(|chain| {
        let mmr_index = chain.kernels.len() as u64 + 1;
        chain.kernels.push(LocatedKernel {
            kernel,
            height: Height::new(height),
            mmr_index,
        });
    });
}

/// Every file under `dir` with its bytes, directories with none.
pub fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.insert(path.clone(), Vec::new());
                pending.push(path);
            } else {
                files.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    files
}
