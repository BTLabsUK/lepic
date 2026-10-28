// Portions Copyright 2019 The Epic Developers
// Portions Copyright 2023 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/backends/db.rs, impls/src/backends/lmdb.rs,
// impls/src/serialization.rs, libwallet/src/types.rs, libwallet/src/slate.rs (Apache-2.0); see
// NOTICE and upstream.toml.

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use serde_json::{Value, json};
use uuid::Uuid;

use super::rows::{
    self, MAX_LABEL_CHARS, MAX_MESSAGE_CHARS, MAX_MESSAGES, MAX_PUBLIC_ADDR_CHARS,
    MAX_STORED_TX_CHARS, RowRejection,
};
use super::{LegacyOutputStatus, LegacyTxKind};
use crate::output::KeyId;

const ACCOUNT_PATH: &str = "0200000000000000000000000000000000";
const OUTPUT_KEY: &str = "0300000000000000000000000000000007";
const COMMIT: &str = "08b7e0d1f02a9c4e7d1b33c0a1f2e3d4c5b6a79881726354f0e1d2c3b4a5968778";
const PUBKEY: &str = "02e3c1b1a4b6a2c1d5f0e9d8c7b6a5948372615049f8e7d6c5b4a39281706f5e4d";
const SIG: &str = "8f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0\
                   0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A `TxLogEntry` as epic-wallet 4.0.2 serializes it: every field present, in struct order.
fn tx_v4() -> Value {
    json!({
        "confirmation_height": 1203,
        "parent_key_id": ACCOUNT_PATH,
        "id": 3,
        "tx_slate_id": "0436430c-2b02-624c-2032-570501212b00",
        "tx_type": "TxSent",
        "creation_ts": "2024-03-01T10:20:30.123456789Z",
        "confirmation_ts": "2024-03-01T10:25:00Z",
        "confirmed": true,
        "num_inputs": 1,
        "num_outputs": 1,
        "amount_credited": "99000000",
        "amount_debited": "200000000",
        "fee": "1000000",
        "ttl_cutoff_height": null,
        "messages": {"messages": [
            {"id": "0", "public_key": PUBKEY, "message": "for lunch", "message_sig": SIG},
            {"id": "1", "public_key": PUBKEY, "message": null, "message_sig": null}
        ]},
        "stored_tx": "0436430c-2b02-624c-2032-570501212b00.epictx",
        "kernel_excess": COMMIT,
        "kernel_lookup_min_height": 1200,
        "payment_proof": null,
        "public_addr": "esZ9vkLRuuGCqwsQZpw7MaDTGaQSXHU3y5pKJ8xTm3TZgnDtvBYX@epicbox.epiccash.com"
    })
}

/// A `TxLogEntry` as epic-wallet 3.3.2 serializes it: no `confirmation_height`, no `public_addr`.
fn tx_v3() -> Value {
    json!({
        "parent_key_id": ACCOUNT_PATH,
        "id": 0,
        "tx_slate_id": null,
        "tx_type": "TxReceived",
        "creation_ts": "2021-06-01T08:00:00.5+00:00",
        "confirmation_ts": null,
        "confirmed": false,
        "num_inputs": 0,
        "num_outputs": 1,
        "amount_credited": 500000000,
        "amount_debited": 0,
        "fee": null,
        "ttl_cutoff_height": null,
        "messages": null,
        "stored_tx": null,
        "kernel_excess": null,
        "kernel_lookup_min_height": null,
        "payment_proof": null
    })
}

fn output() -> Value {
    json!({
        "root_key_id": ACCOUNT_PATH,
        "key_id": OUTPUT_KEY,
        "n_child": 7,
        "commit": COMMIT,
        "mmr_index": "4021",
        "value": "100000000",
        "status": "Unspent",
        "height": "1203",
        "lock_height": "0",
        "is_coinbase": false,
        "tx_log_entry": 3
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn with(mut value: Value, field: &str, replacement: Value) -> Value {
    value[field] = replacement;
    value
}

fn without(mut value: Value, field: &str) -> Value {
    value.as_object_mut().unwrap().remove(field);
    value
}

fn tx_rejection(value: &Value) -> RowRejection {
    rows::parse_transaction(&bytes(value)).unwrap_err()
}

fn output_rejection(value: &Value) -> RowRejection {
    rows::parse_output(&bytes(value)).unwrap_err()
}

fn path_key(depth: u8) -> KeyId {
    let mut id = [0; 17];
    id[0] = depth;
    KeyId(id)
}

#[test]
fn parses_transaction_as_epic_wallet_4_writes_it() {
    let tx = rows::parse_transaction(&bytes(&tx_v4())).unwrap();
    assert_eq!(tx.id, 3);
    assert_eq!(tx.parent_key_id, path_key(2));
    assert_eq!(
        tx.slate_id,
        Some(Uuid::parse_str("0436430c-2b02-624c-2032-570501212b00").unwrap())
    );
    assert_eq!(tx.kind, LegacyTxKind::TxSent);
    assert_eq!(
        tx.created_at,
        "2024-03-01T10:20:30.123456789Z"
            .parse::<Timestamp>()
            .unwrap()
    );
    assert_eq!(
        tx.confirmed_at,
        Some("2024-03-01T10:25:00Z".parse::<Timestamp>().unwrap())
    );
    assert!(tx.confirmed);
    assert_eq!(tx.confirmation_height, Some(Height::new(1203)));
    assert_eq!((tx.num_inputs, tx.num_outputs), (1, 1));
    assert_eq!(tx.amount_credited, Amount::new(99_000_000));
    assert_eq!(tx.amount_debited, Amount::new(200_000_000));
    assert_eq!(tx.fee, Some(Fee::new(1_000_000)));
    assert_eq!(tx.ttl_cutoff_height, None);
    assert_eq!(tx.messages.len(), 2);
    assert_eq!(tx.messages[0].participant, 0);
    assert_eq!(tx.messages[0].public_key[0], 0x02);
    assert_eq!(tx.messages[0].text.as_deref(), Some("for lunch"));
    assert_eq!(tx.messages[0].signature.unwrap()[..2], [0x8f, 0x1e]);
    assert_eq!(tx.messages[1].text, None);
    assert_eq!(tx.messages[1].signature, None);
    assert_eq!(
        tx.stored_tx.as_deref(),
        Some("0436430c-2b02-624c-2032-570501212b00.epictx")
    );
    assert_eq!(tx.kernel_excess.unwrap()[..2], [0x08, 0xb7]);
    assert_eq!(tx.kernel_lookup_min_height, Some(Height::new(1200)));
    assert!(tx.public_addr.unwrap().ends_with("@epicbox.epiccash.com"));
}

#[test]
fn parses_transaction_as_epic_wallet_3_3_writes_it() {
    let tx = rows::parse_transaction(&bytes(&tx_v3())).unwrap();
    assert_eq!(tx.kind, LegacyTxKind::TxReceived);
    assert_eq!(tx.confirmation_height, None);
    assert_eq!(tx.public_addr, None);
    assert_eq!(tx.slate_id, None);
    assert_eq!(tx.messages, Vec::new());
    assert_eq!(tx.amount_credited, Amount::new(500_000_000));
    assert_eq!(
        tx.created_at,
        "2021-06-01T08:00:00.5Z".parse::<Timestamp>().unwrap()
    );
}

#[test]
fn accepts_every_transaction_type() {
    let kinds = [
        ("ConfirmedCoinbase", LegacyTxKind::ConfirmedCoinbase),
        ("TxReceived", LegacyTxKind::TxReceived),
        ("TxSent", LegacyTxKind::TxSent),
        ("TxReceivedCancelled", LegacyTxKind::TxReceivedCancelled),
        ("TxSentCancelled", LegacyTxKind::TxSentCancelled),
        ("TxSentMempool", LegacyTxKind::TxSentMempool),
        ("TxReceivedMempool", LegacyTxKind::TxReceivedMempool),
        ("TxSentCreated", LegacyTxKind::TxSentCreated),
    ];
    for (code, kind) in kinds {
        let tx = rows::parse_transaction(&bytes(&with(tx_v4(), "tx_type", json!(code)))).unwrap();
        assert_eq!(tx.kind, kind);
    }
}

#[test]
fn reads_numbers_as_strings_or_integers_where_upstream_does() {
    let tx = with(tx_v4(), "amount_credited", json!(5));
    let tx = with(tx, "fee", json!(7));
    let tx = with(tx, "ttl_cutoff_height", json!("1500"));
    let tx = rows::parse_transaction(&bytes(&tx)).unwrap();
    assert_eq!(tx.amount_credited, Amount::new(5));
    assert_eq!(tx.fee, Some(Fee::new(7)));
    assert_eq!(tx.ttl_cutoff_height, Some(Height::new(1500)));

    let out = with(output(), "mmr_index", json!(12));
    let out = with(out, "value", json!(9));
    let out = rows::parse_output(&bytes(&out)).unwrap();
    assert_eq!(out.mmr_index, Some(12));
    assert_eq!(out.value, Amount::new(9));

    let msg = json!({"messages": [{"id": 1, "public_key": PUBKEY, "message_sig": null}]});
    let tx = rows::parse_transaction(&bytes(&with(tx_v4(), "messages", msg))).unwrap();
    assert_eq!(tx.messages[0].participant, 1);
}

#[test]
fn rejects_strings_where_upstream_takes_only_integers() {
    for field in [
        "id",
        "num_inputs",
        "confirmation_height",
        "kernel_lookup_min_height",
    ] {
        assert!(matches!(
            tx_rejection(&with(tx_v4(), field, json!("3"))),
            RowRejection::Json(_)
        ));
    }
}

#[test]
fn rejects_out_of_range_numbers() {
    assert!(matches!(
        tx_rejection(&with(
            tx_v4(),
            "amount_credited",
            json!("18446744073709551616")
        )),
        RowRejection::Json(_)
    ));
    assert!(matches!(
        tx_rejection(&with(tx_v4(), "amount_debited", json!(-1))),
        RowRejection::Json(_)
    ));
    assert!(matches!(
        tx_rejection(&with(tx_v4(), "fee", json!(1.5))),
        RowRejection::Json(_)
    ));
    assert!(matches!(
        tx_rejection(&with(tx_v4(), "id", json!(4_294_967_296_u64))),
        RowRejection::Json(_)
    ));
    assert_eq!(
        tx_rejection(&with(tx_v4(), "num_outputs", json!(4_294_967_296_u64))),
        RowRejection::OutOfRange {
            field: "output count"
        }
    );
    assert!(matches!(
        output_rejection(&with(output(), "n_child", json!(-1))),
        RowRejection::Json(_)
    ));
}

#[test]
fn requires_fields_upstream_requires() {
    for field in [
        "parent_key_id",
        "id",
        "tx_type",
        "creation_ts",
        "confirmed",
        "num_inputs",
        "num_outputs",
        "amount_credited",
        "amount_debited",
        "fee",
    ] {
        assert!(
            matches!(
                tx_rejection(&without(tx_v4(), field)),
                RowRejection::Json(_)
            ),
            "{field}"
        );
    }
    for field in [
        "root_key_id",
        "key_id",
        "n_child",
        "mmr_index",
        "value",
        "status",
    ] {
        assert!(
            matches!(
                output_rejection(&without(output(), field)),
                RowRejection::Json(_)
            ),
            "{field}"
        );
    }
    let no_sig = json!({"messages": [{"id": "0", "public_key": PUBKEY, "message": null}]});
    assert!(matches!(
        tx_rejection(&with(tx_v4(), "messages", no_sig)),
        RowRejection::Json(_)
    ));
}

#[test]
fn defaults_fields_upstream_defaults() {
    let mut tx = tx_v4();
    for field in [
        "confirmation_height",
        "tx_slate_id",
        "confirmation_ts",
        "ttl_cutoff_height",
        "messages",
        "stored_tx",
        "kernel_excess",
        "kernel_lookup_min_height",
        "payment_proof",
        "public_addr",
    ] {
        tx = without(tx, field);
    }
    let tx = rows::parse_transaction(&bytes(&tx)).unwrap();
    assert_eq!(tx.kernel_excess, None);
    assert_eq!(tx.ttl_cutoff_height, None);

    let out = rows::parse_output(&bytes(&without(
        without(output(), "commit"),
        "tx_log_entry",
    )));
    assert_eq!(out.unwrap().commitment, None);
}

#[test]
fn ignores_unknown_fields() {
    let tx = with(tx_v4(), "added_in_a_later_version", json!({"x": 1}));
    assert!(rows::parse_transaction(&bytes(&tx)).is_ok());
}

#[test]
fn rejects_unknown_transaction_type_and_output_status() {
    assert!(matches!(
        tx_rejection(&with(tx_v4(), "tx_type", json!("TxReverted"))),
        RowRejection::Json(_)
    ));
    assert!(matches!(
        output_rejection(&with(output(), "status", json!("Burned"))),
        RowRejection::Json(_)
    ));
}

#[test]
fn reads_every_output_status() {
    let statuses = [
        ("Unconfirmed", LegacyOutputStatus::Unconfirmed),
        ("Unspent", LegacyOutputStatus::Unspent),
        ("Locked", LegacyOutputStatus::Locked),
        ("Spent", LegacyOutputStatus::Spent),
        ("Deleted", LegacyOutputStatus::Deleted),
    ];
    for (code, status) in statuses {
        let out = rows::parse_output(&bytes(&with(output(), "status", json!(code)))).unwrap();
        assert_eq!(out.status, status);
    }
}

#[test]
fn parses_output_as_upstream_writes_it() {
    let out = rows::parse_output(&bytes(&output())).unwrap();
    assert_eq!(out.root_key_id, path_key(2));
    assert_eq!(out.key_id.0[0], 3);
    assert_eq!(out.key_id.0[16], 7);
    assert_eq!(out.n_child, 7);
    assert_eq!(out.commitment.unwrap()[0], 0x08);
    assert_eq!(out.mmr_index, Some(4021));
    assert_eq!(out.value, Amount::new(100_000_000));
    assert_eq!(out.height, Height::new(1203));
    assert_eq!(out.lock_height, Height::ZERO);
    assert!(!out.is_coinbase);
    assert_eq!(out.tx_log_entry, Some(3));
}

#[test]
fn rejects_bad_hex_and_wrong_lengths() {
    let short = &ACCOUNT_PATH[..32];
    let odd = &ACCOUNT_PATH[..33];
    let not_hex = "zz00000000000000000000000000000000";
    let prefixed = "0x020000000000000000000000000000000000";
    for bad in [
        short,
        odd,
        not_hex,
        prefixed,
        "",
        "+2000000000000000000000000000000000",
    ] {
        assert_eq!(
            tx_rejection(&with(tx_v4(), "parent_key_id", json!(bad))),
            RowRejection::Hex {
                field: "parent key id"
            }
        );
    }
    assert_eq!(
        tx_rejection(&with(tx_v4(), "kernel_excess", json!(&COMMIT[..64]))),
        RowRejection::Hex {
            field: "kernel excess"
        }
    );
    assert_eq!(
        output_rejection(&with(output(), "commit", json!(format!("{COMMIT}00")))),
        RowRejection::Hex {
            field: "commitment"
        }
    );
    let long_sig = json!({"messages": [
        {"id": "0", "public_key": PUBKEY, "message": null, "message_sig": format!("{SIG}00")}
    ]});
    assert_eq!(
        tx_rejection(&with(tx_v4(), "messages", long_sig)),
        RowRejection::Hex {
            field: "message signature"
        }
    );
    let uncompressed = json!({"messages": [
        {"id": "0", "public_key": format!("{PUBKEY}{}", &SIG[..64]), "message_sig": null}
    ]});
    assert_eq!(
        tx_rejection(&with(tx_v4(), "messages", uncompressed)),
        RowRejection::Hex {
            field: "message public key"
        }
    );
}

#[test]
fn accepts_uppercase_hex() {
    let tx = with(tx_v4(), "kernel_excess", json!(COMMIT.to_uppercase()));
    assert!(rows::parse_transaction(&bytes(&tx)).is_ok());
}

#[test]
fn rejects_key_ids_deeper_than_four_levels() {
    assert!(rows::key_id("0400000000000000000000000000000000", "key id").is_ok());
    assert_eq!(
        output_rejection(&with(
            output(),
            "key_id",
            json!("0500000000000000000000000000000000")
        )),
        RowRejection::KeyDepth { field: "key id" }
    );
}

#[test]
fn rejects_oversize_strings() {
    let at = |n: usize| "é".repeat(n);
    let label = json!({"label": at(MAX_LABEL_CHARS), "path": ACCOUNT_PATH});
    assert!(rows::parse_account(&bytes(&label)).is_ok());
    let label = json!({"label": at(MAX_LABEL_CHARS + 1), "path": ACCOUNT_PATH});
    assert_eq!(
        rows::parse_account(&bytes(&label)).unwrap_err(),
        RowRejection::TooLong { field: "label" }
    );
    assert_eq!(
        tx_rejection(&with(
            tx_v4(),
            "public_addr",
            json!(at(MAX_PUBLIC_ADDR_CHARS + 1))
        )),
        RowRejection::TooLong {
            field: "public address"
        }
    );
    assert_eq!(
        tx_rejection(&with(
            tx_v4(),
            "stored_tx",
            json!(at(MAX_STORED_TX_CHARS + 1))
        )),
        RowRejection::TooLong {
            field: "stored transaction"
        }
    );
    let long_message = json!({"messages": [{
        "id": "0", "public_key": PUBKEY, "message": at(MAX_MESSAGE_CHARS + 1), "message_sig": null
    }]});
    assert_eq!(
        tx_rejection(&with(tx_v4(), "messages", long_message)),
        RowRejection::TooLong { field: "message" }
    );
}

#[test]
fn rejects_too_many_messages() {
    let one = json!({"id": "0", "public_key": PUBKEY, "message": null, "message_sig": null});
    let many = json!({ "messages": vec![one; MAX_MESSAGES + 1] });
    assert_eq!(
        tx_rejection(&with(tx_v4(), "messages", many)),
        RowRejection::TooManyMessages
    );
}

#[test]
fn rejects_bad_timestamps_and_slate_ids() {
    for bad in ["2024-03-01 10:20:30", "yesterday", "2024-03-01T10:20:30"] {
        assert_eq!(
            tx_rejection(&with(tx_v4(), "creation_ts", json!(bad))),
            RowRejection::Timestamp {
                field: "creation time"
            }
        );
    }
    assert!(matches!(
        tx_rejection(&with(tx_v4(), "creation_ts", json!(1_700_000_000))),
        RowRejection::Json(_)
    ));
    assert_eq!(
        tx_rejection(&with(tx_v4(), "tx_slate_id", json!("not-a-uuid"))),
        RowRejection::SlateId
    );
}

#[test]
fn rejects_non_json_rows() {
    assert!(matches!(
        rows::parse_transaction(b"{\"id\": 3"),
        Err(RowRejection::Json(_))
    ));
    assert!(matches!(
        rows::parse_output(&[0xff, 0xfe]),
        Err(RowRejection::Json(_))
    ));
    assert!(matches!(
        rows::parse_account(b"42"),
        Err(RowRejection::Json(_))
    ));
}

#[test]
fn parses_account_mapping() {
    let account = json!({"label": "default", "path": ACCOUNT_PATH});
    let account = rows::parse_account(&bytes(&account)).unwrap();
    assert_eq!(account.label, "default");
    assert_eq!(account.path, path_key(2));
}

fn debug_key(bytes: &[u8]) -> Vec<u8> {
    format!("{bytes:?}").into_bytes()
}

fn counter_key(parent: KeyId) -> Vec<u8> {
    let mut key = vec![b'd', b':'];
    key.extend_from_slice(&parent.0);
    key
}

#[test]
fn parses_derivation_counter_from_key_and_number() {
    let mut parent = path_key(2);
    parent.0[4] = 1;
    let counter = rows::parse_counter(&debug_key(&counter_key(parent)), b"12").unwrap();
    assert_eq!(counter.parent, parent);
    assert_eq!(counter.next_child, 12);
}

#[test]
fn rejects_malformed_derivation_counters() {
    let key = debug_key(&counter_key(path_key(2)));
    assert!(matches!(
        rows::parse_counter(&key, b"\"12\""),
        Err(RowRejection::Json(_))
    ));
    assert_eq!(
        rows::parse_counter(&key, b"4294967296").unwrap_err(),
        RowRejection::OutOfRange {
            field: "derivation counter"
        }
    );
    let mut short = counter_key(path_key(2));
    short.pop();
    let mut no_separator = counter_key(path_key(2));
    no_separator.remove(1);
    let mut other_prefix = counter_key(path_key(2));
    other_prefix[0] = b'i';
    for bad in [short, no_separator, other_prefix] {
        assert_eq!(
            rows::parse_counter(&debug_key(&bad), b"1").unwrap_err(),
            RowRejection::RowKey
        );
    }
    assert_eq!(
        rows::parse_counter(&debug_key(&counter_key(path_key(5))), b"1").unwrap_err(),
        RowRejection::KeyDepth {
            field: "parent key id"
        }
    );
}

#[test]
fn parses_only_canonical_debug_key_text() {
    assert_eq!(rows::debug_bytes(b"[]").unwrap(), Vec::<u8>::new());
    assert_eq!(
        rows::debug_bytes(b"[100, 58, 0, 255]").unwrap(),
        vec![100, 58, 0, 255]
    );
    for bad in [
        &b"100, 58"[..],
        b"[100,58]",
        b"[100, 058]",
        b"[100, 256]",
        b"[100, -1]",
        b"[100, ]",
        b"[ 100]",
        b"[100, 0x3a]",
        &[0xff],
    ] {
        assert_eq!(rows::debug_bytes(bad).unwrap_err(), RowRejection::RowKey);
    }
}

#[test]
fn rejection_text_carries_no_row_values() {
    let tx = with(
        tx_v4(),
        "public_addr",
        json!("a".repeat(MAX_PUBLIC_ADDR_CHARS + 1)),
    );
    let shown = tx_rejection(&tx).to_string();
    assert!(!shown.contains("aaaa"));
    let shown = tx_rejection(&with(tx_v4(), "amount_credited", json!("12x34"))).to_string();
    assert!(!shown.contains("12x34"));
}
