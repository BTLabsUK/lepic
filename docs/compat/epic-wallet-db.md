# epic-wallet database (SQLite)

Derived from `epic-wallet` `v4.0.2` (`465d499f`) and checked against `v3.3.2` (`a323ae6c`) and
`v4.1.0` (`845b3fcf`): `impls/src/backends/{db,lmdb}.rs`, `impls/src/serialization.rs`,
`libwallet/src/types.rs`, `libwallet/src/slate.rs`, `libwallet/src/api_impl/{owner,foreign}.rs`.
Serde helpers and keys come from the Epic node `v4.0.4` (`9d022b1d`) that `epic-wallet` `v4.0.2`
pins: `core/src/libtx/secp_ser.rs`, `keychain/src/types.rs`, `store/src/lib.rs`. The reader is
`lepic_store::legacy`; it only reads this format and never writes it.

## Location

| Wallet | Database | Source |
|---|---|---|
| 3.3.2 to 4.1.0 (CLI and GUI) | `<wallet>/wallet_data/db/sqlite/epic.db` | `lmdb.rs:38-39` `DB_DIR`, `SQLITE_DIR`; `db.rs:28` `SQLITE_FILENAME` |
| before 3.3 | an LMDB environment in `<wallet>/wallet_data/db/lmdb/` | `v3.0.0` `lmdb.rs:131`; node `store/src/lmdb.rs` default environment name `lmdb` |

Upstream never migrates LMDB data into SQLite, so a folder holding both is read from SQLite. The
database runs in WAL mode (`db.rs:65` `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`), so committed
rows may sit only in `epic.db-wal` until a checkpoint; `epic.db-shm` is SQLite's index of that log.
A copy of `epic.db` alone can miss the newest rows.

## Table

`db.rs:48-62` (`v4.1.0` `db.rs:69-83`, same text):

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

plus indexes on `prefix`, `q_tx_id`, `q_confirmed`, `q_tx_status`.

- `key` holds TEXT despite its declared type: the Rust `format!("{:?}", key_bytes)` of the key, for
  example `[100, 58, 2, 0, 0, ...]`. `v4.0.2` splices it into the SQL as a double-quoted literal
  (`db.rs:82`), `v4.1.0` binds it (`db.rs:48` `encoded_key`); the stored text is the same.
- `prefix` is the first key byte as a one-character string (`db.rs:189`). Upstream lists records by
  `WHERE prefix = ?` (`db.rs:121` `iter`) and ignores the key when it does.
- `data` is the `serde_json::to_string` of the record, compact, wrapped in the untagged enum
  `Serializable` (`serialization.rs:24-35`). A `Serializable::Numeric(u64)` is a bare JSON number.
- `q_tx_id`, `q_confirmed`, `q_tx_status` repeat a few fields for queries (`q_tx_status` holds the
  `Display` text, for example `Coinbase Confirmed`). They are derived data; the reader ignores them.

## Keys

`epic_store::to_key(prefix, bytes)` is `prefix, b':', bytes`; `to_key_u64` appends a big-endian
`u64` (`store/src/lib.rs:31-53`). Prefixes, `lmdb.rs:42-54`:

| Prefix | Key | `data` | Read by LEPIC |
|---|---|---|---|
| `a` | `a:` + label bytes | `AcctPathMapping` | yes |
| `d` | `d:` + parent key id (17 bytes) | `Numeric`: next child index under that parent (`save_child_index`, `lmdb.rs:794`) | yes, parent taken from the key |
| `t` | `t:` + parent key id + `u64` BE tx id (`lmdb.rs:804`) | `TxLogEntry` | yes |
| `o` | `o:` + key id, + `u64` BE MMR index when known (`lmdb.rs:582`) | `OutputData` | yes |
| `p` | `p:` + slate id + `u64` BE participant | `Context`, holding private keys | never |
| `h` | `h:` + `u32` LE history id | `OutputData`, earlier states of outputs | no |
| `i`, `j` | next tx log id per parent; next history id | `Numeric` | no |
| `c`, `l`, `w` | last confirmed height; last scanned block; init status | various | no |

## Records

All field shapes below are for `v4.0.2` (`types.rs:486`, `808`, `846`, `994`; `slate.rs:108`,
`222`). `v4.1.0` is identical. `v3.3.2` lacks `confirmation_height` and `public_addr` and the last
three `TxLogEntryType` variants; both fields are `#[serde(default)]` upstream, so its rows read the
same way.

Presence rules are serde's: a plain `Option` may be missing; a field read through a `with` helper
must be present (as `null` or a value) unless it also has `#[serde(default)]`; unknown fields are
ignored. Upstream serializes every field, `null` included, in struct order.

Value encodings:

| Name | JSON | Source |
|---|---|---|
| Identifier (key id) | lowercase hex of 17 bytes: depth, then four big-endian `u32` path components | `keychain/src/types.rs:61` |
| `string_or_u64` | written as a decimal string; read from a JSON integer or a string `u64::from_str` accepts | `secp_ser.rs:254` |
| `opt_string_or_u64` | `null` or as above | `secp_ser.rs:297` |
| `option_commitment_serde` | `null` or hex of the 33-byte commitment | `secp_ser.rs:175` |
| `pubkey_serde` | hex of the 33-byte compressed key | `secp_ser.rs:23` |
| `option_sig_serde` | `null` or hex of the 64-byte compact signature, as in slates | `secp_ser.rs:56` |
| `DateTime<Utc>` | RFC 3339 with nanoseconds and `Z`, e.g. `2026-08-30T07:39:56.288835010Z` | chrono 0.4.41 |
| `Uuid` | hyphenated lowercase | uuid 1.17 |

### AcctPathMapping (`a`)

`{"label": string, "path": Identifier}`, both required. Accounts sit at depth 2:
`default` is `0200000000000000000000000000000000`.

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
| `num_inputs`, `num_outputs` | integer (`usize`) | yes |
| `amount_credited`, `amount_debited` | `string_or_u64` | yes |
| `fee` | `opt_string_or_u64` | yes, may be `null` |
| `ttl_cutoff_height` | `opt_string_or_u64` | no (default) |
| `messages` | `{"messages": [ParticipantMessageData]}` or `null` | no |
| `stored_tx` | string or `null`: file name in `wallet_data/saved_txs/` | no |
| `kernel_excess` | `option_commitment_serde` | no (default) |
| `kernel_lookup_min_height` | integer or `null` | no (default) |
| `payment_proof` | `StoredProofInfo` or `null` | no (default); not imported |
| `public_addr` | string or `null`: the peer's address, or `Restore` for scanned outputs | no (default) |

`ParticipantMessageData`: `id` (`string_or_u64`, required), `public_key` (`pubkey_serde`,
required), `message` (string or `null`, may be missing), `message_sig` (`option_sig_serde`,
required, may be `null`). Upstream truncates its own message to 256 bytes
(`owner.rs:47`, `foreign.rs:29` `USER_MESSAGE_MAX_LEN`); a peer's message arrives as the peer sent it.

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

`lepic_store::legacy` accepts exactly the shapes above, with these deliberate differences, each a
rejection of something upstream never writes:

- Hex must be exactly twice the byte length, either case, no `0x`. Upstream's readers accept a
  `0x` prefix and pad or ignore length mismatches.
- Public keys must be the 33-byte compressed form (upstream also reads 65-byte keys) and
  signatures exactly 64 bytes (upstream reads the first 64). Neither is checked to be valid here;
  the wallet layer does that with `lepic-crypto`.
- Key ids deeper than four levels are rejected.
- Text is bounded in characters: account label 256, message 1024, `public_addr` 512, `stored_tx`
  512; at most 16 messages per entry. Rows are bounded by `LegacyLimits::max_row_bytes`.
- Counters above `u32::MAX` are rejected (upstream truncates with `as u32`).

A row that breaks any rule is skipped and counted in `LegacyHistory::skipped`; it never fails the
import. Counts above `LegacyLimits` fail it with `TooMany`.

## Reading safely

The reader copies `epic.db` and `epic.db-wal` with plain file reads into a work directory, checking
length, modification time and SHA-256 before and after (three attempts), and opens only the copy.
Opening a WAL database with SQLite, even read-only, creates `-shm` and `-wal` files beside it and may
checkpoint, so the wallet's own folder is never opened with SQLite.
