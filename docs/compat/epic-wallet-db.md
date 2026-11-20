# epic-wallet database (SQLite)

LEPIC imports the history of a wallet made by `epic-wallet` v4.1.0 or earlier from its SQLite
database. The format is read from `epic-wallet` v4.1.0 (`845b3fcf`): `impls/src/backends/{db,lmdb}.rs`,
`impls/src/serialization.rs`, `libwallet/src/types.rs`, `libwallet/src/slate.rs`. The serde helpers
and key types come from the Epic node crates that release links: `core/src/libtx/secp_ser.rs`,
`keychain/src/types.rs`, `store/src/lib.rs`. The reader is `lepic_store::legacy`
(`crates/lepic-store/src/legacy/`). It only reads this format and never writes it.

## Location

The database is `<wallet>/wallet_data/db/sqlite/epic.db` (`DB_DIR` and `SQLITE_DIR` in
`lmdb.rs`, `SQLITE_FILENAME` in `db.rs`). `locate()` takes either the wallet folder or its
`wallet_data` folder.

- If `db/sqlite/epic.db` exists, it is the source, even when `db/lmdb/` exists too.
- If only an LMDB environment is present, the result is `LegacyDbError::LmdbUnsupported`.
- Otherwise there is no database, and the import fails with `LegacyDbError::NotFound`.

The database runs in WAL mode (`PRAGMA journal_mode=WAL`, `synchronous=NORMAL`), so committed rows
may sit only in `epic.db-wal` until a checkpoint. `epic.db-shm` is SQLite's index of that log. A
copy of `epic.db` alone can miss the newest rows.

## Table

`db.rs`:

```sql
CREATE TABLE IF NOT EXISTS data (
    id INTEGER PRIMARY KEY,
    key BLOB NOT NULL UNIQUE,
    prefix TEXT,
    data TEXT NOT NULL,
    q_tx_id INTEGER,
    q_confirmed INTEGER,
    q_tx_status TEXT);
```

It has indexes on `prefix`, `q_tx_id`, `q_confirmed` and `q_tx_status`.

- `key` holds text despite its declared type: the Rust `format!("{:?}", key_bytes)` of the key,
  for example `[100, 58, 2, 0, 0, ...]` (`encoded_key`).
- `prefix` is the first key byte as a one-character string. Upstream lists records with
  `WHERE prefix = ?` and ignores the key when it does.
- `data` is the compact `serde_json::to_string` of the record, wrapped in the untagged enum
  `Serializable` (`serialization.rs`). A `Serializable::Numeric(u64)` is a bare JSON number.
- `q_tx_id`, `q_confirmed` and `q_tx_status` repeat a few fields for queries (`q_tx_status`
  holds the `Display` text, for example `Coinbase Confirmed`). The reader ignores them.

The reader needs the columns `key`, `prefix` and `data` in a table named `data`. Without them the
result is `LegacyDbError::MissingTable`.

## Keys

`epic_store::to_key(prefix, bytes)` is `prefix`, `b':'`, `bytes`. `to_key_u64` appends a
big-endian `u64`. The prefixes (`lmdb.rs`):

| Prefix | Key | `data` | Read by LEPIC |
|---|---|---|---|
| `a` | `a:` + label bytes | `AcctPathMapping` | yes |
| `d` | `d:` + parent key id (17 bytes) | `Numeric`: next child index under that parent | yes, parent taken from the key |
| `t` | `t:` + parent key id + `u64` BE tx id | `TxLogEntry` | yes |
| `o` | `o:` + key id, + `u64` BE MMR index when known | `OutputData` | yes |
| `p` | `p:` + slate id + `u64` BE participant | `Context`, holding private keys | never |
| `h` | `h:` + `u32` LE history id | `OutputData`, earlier states of outputs | no |
| `i`, `j` | next tx log id per parent; next history id | `Numeric` | no |
| `c`, `l`, `w` | last confirmed height; last scanned block; init status | various | no |

A `d` row is read from its key as well as its data: the key text must be a list of canonical
decimal bytes (`[100, 58, ...]`), start with `d:` and be followed by exactly 17 bytes. Rows under
any other prefix are never read. A key or data column longer than the limit under
[Limits](#limits) is skipped without being loaded.

## Records

Presence rules are serde's: a plain `Option` may be missing. A field read through a `with` helper
must be present (as `null` or a value) unless it also has `#[serde(default)]`. Unknown fields are
ignored. Upstream writes every field, `null` included, in struct order.

Value encodings:

| Name | JSON |
|---|---|
| Identifier (key id) | lowercase hex of 17 bytes: depth, then four big-endian `u32` path components |
| `string_or_u64` | written as a decimal string; read from a JSON integer or a string `u64::from_str` accepts |
| `opt_string_or_u64` | `null` or as above |
| commitment | `null` or hex of the 33-byte commitment |
| `pubkey_serde` | hex of the 33-byte compressed key |
| `option_sig_serde` | `null` or hex of the 64-byte compact signature, as in slates |
| `DateTime<Utc>` | RFC 3339 with nanoseconds and `Z`, e.g. `2026-08-30T07:39:56.288835010Z` |
| `Uuid` | hyphenated lowercase |

### AcctPathMapping (`a`)

`{"label": string, "path": Identifier}`, both required. Accounts sit at depth 2: `default` is
`0200000000000000000000000000000000`.

### TxLogEntry (`t`)

| Field | Type | Required |
|---|---|---|
| `confirmation_height` | integer or `null` | no (default) |
| `parent_key_id` | Identifier | yes |
| `id` | integer (`u32`) | yes |
| `tx_slate_id` | Uuid or `null` | no |
| `tx_type` | `ConfirmedCoinbase`, `TxReceived`, `TxSent`, `TxReceivedCancelled`, `TxSentCancelled`, `TxSentMempool`, `TxReceivedMempool`, `TxSentCreated` | yes |
| `creation_ts` | DateTime | yes |
| `confirmation_ts` | DateTime or `null` | no |
| `confirmed` | bool | yes |
| `num_inputs`, `num_outputs` | integer | yes |
| `amount_credited`, `amount_debited` | `string_or_u64` | yes |
| `fee` | `opt_string_or_u64` | yes, may be `null` |
| `ttl_cutoff_height` | `opt_string_or_u64` | no (default) |
| `messages` | `{"messages": [ParticipantMessageData]}` or `null` | no |
| `stored_tx` | string or `null`: file name in `wallet_data/saved_txs/` | no |
| `kernel_excess` | commitment | no (default) |
| `kernel_lookup_min_height` | integer or `null` | no (default) |
| `public_addr` | string or `null`: the peer's address, or `Restore` for scanned outputs | no (default) |

Rows from wallets that predate `confirmation_height`, `public_addr` or the last three
`TxLogEntryType` variants read the same way, because both fields have defaults. A row may carry a
`payment_proof` field. It is ignored and not carried over.

`ParticipantMessageData`: `id` (`string_or_u64`, required), `public_key` (`pubkey_serde`,
required), `message` (string or `null`, may be missing), `message_sig` (`option_sig_serde`,
required, may be `null`). Upstream truncates its own message to 256 bytes
(`USER_MESSAGE_MAX_LEN` in `api_impl/owner.rs` and `foreign.rs`). A message from the peer is
stored as it arrived.

### OutputData (`o`)

| Field | Type | Required |
|---|---|---|
| `root_key_id`, `key_id` | Identifier | yes |
| `n_child` | integer (`u32`) | yes |
| `commit` | hex of the 33-byte commitment, or `null` | no |
| `mmr_index` | `opt_string_or_u64` | yes, may be `null` |
| `value`, `height`, `lock_height` | `string_or_u64` | yes |
| `status` | `Unconfirmed`, `Unspent`, `Locked`, `Spent`, `Deleted` | yes |
| `is_coinbase` | bool | yes |
| `tx_log_entry` | integer (`u32`) or `null` | no |

## What LEPIC accepts

`lepic_store::legacy` accepts the shapes above, and refuses these values that upstream's readers
let through:

- Hex must be exactly twice the byte length, either case, with no `0x`.
- A public key is the 33-byte compressed form and a signature is exactly 64 bytes. Neither is
  checked to be a valid point or signature here; the wallet layer does that with `lepic-crypto`.
- A key id has a depth of at most four.
- Text is bounded in characters: account label 256, message 1,024, `public_addr` 512, `stored_tx`
  512. An entry holds at most 16 messages.
- `num_inputs`, `num_outputs` and a derivation counter must fit in a `u32`.
- A timestamp must parse as RFC 3339, a slate id as a UUID.

A row that breaks any rule is skipped and counted in `LegacyHistory::skipped`, by record kind
(transactions, outputs, accounts, counters). A skipped row never fails the import.

## Limits

`LegacyLimits` bounds what the reader takes. Going over a count fails the import with
`TooMany { record, found, limit }`. Going over a size is `TooLarge`, or a skipped row for a row.

| Limit | Default |
|---|---|
| `max_db_bytes` | 256 MiB, database plus WAL |
| `max_row_bytes` | 256 KiB, per `data` column |
| `max_transactions` | 250,000 |
| `max_outputs` | 500,000 |
| `max_accounts` | 1,000, for accounts and for derivation counters each |

A key column over 512 bytes is skipped as well. Rows over the size limits are counted in SQL and
never loaded.

## Reading safely

The reader never opens the wallet's own folder with SQLite. Opening a WAL database, even
read-only, creates `-shm` and `-wal` files beside it and may checkpoint.

1. It copies `epic.db` and `epic.db-wal`, if there is one, with plain file reads into an empty work
   directory, as `epic.db` and `epic.db-wal`. A work directory that is not empty is
   `WorkDirNotEmpty`.
2. It compares length and modification time of both files, and a SHA-256 of each file read before
   and after the copy. If anything differs it removes the copy and tries again, up to three
   attempts, then fails with `SourceChanging`.
3. It opens only the copy.

`read_copy(wallet_dir, work_dir, limits)` does these steps and removes the copy and the files
SQLite added beside it before it returns. `read_db_file(db, limits)` reads a file that is already
a private copy; it must never be pointed at a wallet's own database.

`LegacyHistory::source_fingerprint` is the SHA-256 of the database bytes followed by the WAL
bytes.
