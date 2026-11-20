// SPDX-License-Identifier: Apache-2.0
//! Moves the per-transaction settings of schema version 7 into the tables version 8 adds.
//!
//! The decoders here read the text formats version 7 stored and are frozen with it. A setting
//! whose transaction is gone, or whose value does not decode, is dropped: version 7 read such a
//! value as absent too. Every moved setting is deleted.

use std::collections::BTreeMap;

use rusqlite::{Connection, params};
use serde::Deserialize;
use tracing::warn;

use crate::encoding::u64_to_column;
use crate::error::StoreError;
use crate::output::{COMMITMENT_LEN, CommitmentBytes, KEY_ID_LEN};

const LOCAL_CUTOFF: &str = "send.local_cutoff.";
const FINALIZED: &str = "release.finalized_height.";
const KERNEL_ABSENT: &str = "release.kernel_absent.";
const RECEIVE_SEEN: &str = "refresh.receive_seen.";
const RECEIVE_INPUTS: &str = "refresh.receive_inputs_unspent.";
const SPENT_ELSEWHERE: &str = "tx.inputs_spent_elsewhere.";
const RELEASED: &str = "release.released.";
const LATE: &str = "release.late.";
const OTHER_WALLET: &str = "tx.other_wallet.";
const OTHER_WALLET_OPEN: &str = "tx.other_wallet.open";
const FOUND: &str = "scan.found.";
const FOUND_OUTPUT: &str = "scan.found_output.";

const PREFIXES: [&str; 12] = [
    LOCAL_CUTOFF,
    FINALIZED,
    KERNEL_ABSENT,
    RECEIVE_SEEN,
    RECEIVE_INPUTS,
    SPENT_ELSEWHERE,
    RELEASED,
    LATE,
    OTHER_WALLET,
    FOUND,
    FOUND_OUTPUT,
    // Listed last: it shares the prefix of another wallet's spends.
    OTHER_WALLET_OPEN,
];

#[derive(Default)]
struct Marks {
    local_cutoff: Option<u64>,
    finalized_at: Option<u64>,
    kernel_absent_at: Option<u64>,
    receive_seen_at: Option<u64>,
    receive_inputs_unspent: bool,
    inputs_spent_elsewhere: bool,
}

struct Watch {
    phase: &'static str,
    excess: CommitmentBytes,
    min_height: u64,
    ended_at: u64,
    outputs: Vec<(CommitmentBytes, [u8; KEY_ID_LEN], u64)>,
}

#[derive(Deserialize)]
struct Spend {
    spent: Vec<String>,
    change: Vec<String>,
    after: u64,
    to: u64,
}

#[derive(Default)]
struct Found {
    output: Option<CommitmentBytes>,
    during: Option<&'static str>,
    dated_by_block: bool,
}

#[derive(Default)]
struct Moved {
    marks: BTreeMap<u32, Marks>,
    watches: BTreeMap<u32, Watch>,
    spends: BTreeMap<u32, Spend>,
    found: BTreeMap<u32, Found>,
    open: Vec<u32>,
}

pub(super) fn move_settings(conn: &Connection) -> Result<(), StoreError> {
    let mut moved = Moved::default();
    let mut statement = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let key: String = row.get(0)?;
        let value: String = row.get(1)?;
        read_setting(conn, &mut moved, &key, &value)?;
    }
    drop(rows);
    drop(statement);
    write_moved(conn, &moved)?;
    for prefix in PREFIXES {
        conn.execute(
            "DELETE FROM settings WHERE substr(key, 1, length(?1)) = ?1",
            [prefix],
        )?;
    }
    Ok(())
}

fn read_setting(
    conn: &Connection,
    moved: &mut Moved,
    key: &str,
    value: &str,
) -> Result<(), StoreError> {
    if key == OTHER_WALLET_OPEN {
        match serde_json::from_str::<Vec<u32>>(value) {
            Ok(open) => moved.open = open,
            Err(_) => warn!("open entries of another wallet's spends unreadable, dropped"),
        }
        return Ok(());
    }
    let Some((prefix, id)) = PREFIXES
        .iter()
        .find_map(|prefix| Some((*prefix, transaction_id(key.strip_prefix(prefix)?)?)))
    else {
        return Ok(());
    };
    let known: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM transactions WHERE id = ?1)",
        [i64::from(id)],
        |row| row.get(0),
    )?;
    if !known {
        return Ok(());
    }
    let readable = match prefix {
        LOCAL_CUTOFF | FINALIZED | KERNEL_ABSENT | RECEIVE_SEEN => {
            value.parse::<u64>().ok().map(|height| {
                let marks = moved.marks.entry(id).or_default();
                let field = match prefix {
                    LOCAL_CUTOFF => &mut marks.local_cutoff,
                    FINALIZED => &mut marks.finalized_at,
                    KERNEL_ABSENT => &mut marks.kernel_absent_at,
                    _ => &mut marks.receive_seen_at,
                };
                *field = Some(height);
            })
        }
        RECEIVE_INPUTS => {
            moved.marks.entry(id).or_default().receive_inputs_unspent = true;
            Some(())
        }
        SPENT_ELSEWHERE => {
            moved.marks.entry(id).or_default().inputs_spent_elsewhere = true;
            Some(())
        }
        RELEASED | LATE => {
            let phase = if prefix == RELEASED {
                "kernel"
            } else {
                "outputs"
            };
            decode_watch(phase, value).map(|watch| {
                moved.watches.entry(id).or_insert(watch);
            })
        }
        OTHER_WALLET => serde_json::from_str::<Spend>(value).ok().map(|spend| {
            moved.spends.insert(id, spend);
        }),
        FOUND => decode_found(value).map(|(during, dated_by_block)| {
            let found = moved.found.entry(id).or_default();
            found.during = Some(during);
            found.dated_by_block = dated_by_block;
        }),
        _ => {
            commitment(value).map(|output| moved.found.entry(id).or_default().output = Some(output))
        }
    };
    if readable.is_none() {
        warn!(
            tx_id = id,
            setting = prefix,
            "unreadable transaction record dropped"
        );
    }
    Ok(())
}

fn write_moved(conn: &Connection, moved: &Moved) -> Result<(), StoreError> {
    let height = |height: Option<u64>| height.map(u64_to_column);
    for (id, marks) in &moved.marks {
        conn.execute(
            "INSERT INTO tx_marks (tx_id, local_cutoff, finalized_at, kernel_absent_at,
                 receive_seen_at, receive_inputs_unspent, inputs_spent_elsewhere)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                height(marks.local_cutoff),
                height(marks.finalized_at),
                height(marks.kernel_absent_at),
                height(marks.receive_seen_at),
                marks.receive_inputs_unspent,
                marks.inputs_spent_elsewhere,
            ],
        )?;
    }
    for (id, watch) in &moved.watches {
        conn.execute(
            "INSERT INTO tx_watch (tx_id, phase, excess, min_height, ended_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                watch.phase,
                &watch.excess[..],
                u64_to_column(watch.min_height),
                u64_to_column(watch.ended_at),
            ],
        )?;
        for (position, (commitment, key_id, amount)) in watch.outputs.iter().enumerate() {
            conn.execute(
                "INSERT INTO tx_watch_outputs (tx_id, position, commitment, key_id, amount)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id,
                    position_column(position)?,
                    &commitment[..],
                    &key_id[..],
                    u64_to_column(*amount)
                ],
            )?;
        }
    }
    for (id, spend) in &moved.spends {
        conn.execute(
            "INSERT INTO other_wallet_spends (tx_id, after_height, to_height, open)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                id,
                u64_to_column(spend.after),
                u64_to_column(spend.to),
                moved.open.contains(id),
            ],
        )?;
        for (role, list) in [("spent", &spend.spent), ("change", &spend.change)] {
            // Version 7 skipped a commitment that did not decode when it read the list.
            for (position, output) in list.iter().filter_map(|hex| commitment(hex)).enumerate() {
                conn.execute(
                    "INSERT INTO other_wallet_outputs (tx_id, role, position, commitment)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![id, role, position_column(position)?, &output[..]],
                )?;
            }
        }
    }
    for (id, found) in &moved.found {
        conn.execute(
            "INSERT INTO scan_found (tx_id, output, during, dated_by_block)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                id,
                found.output.as_ref().map(|output| &output[..]),
                found.during,
                found.dated_by_block,
            ],
        )?;
    }
    Ok(())
}

/// The position of an item in a stored list, as its column holds it.
fn position_column(position: usize) -> Result<i64, StoreError> {
    i64::try_from(position).map_err(|_| StoreError::OutOfRange {
        field: "list position",
    })
}

/// A transaction id written in decimal, as version 7 appended it to a key.
fn transaction_id(text: &str) -> Option<u32> {
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// `<excess> <min height> <ended at>` and one `<commitment>:<key id>:<amount>` per output, all
/// separated by single spaces.
fn decode_watch(phase: &'static str, text: &str) -> Option<Watch> {
    let mut fields = text.split(' ');
    let excess = commitment(fields.next()?)?;
    let min_height = fields.next()?.parse().ok()?;
    let ended_at = fields.next()?.parse().ok()?;
    let outputs = fields
        .map(|field| {
            let mut parts = field.split(':');
            let output = (
                commitment(parts.next()?)?,
                hex_array(parts.next()?)?,
                parts.next()?.parse().ok()?,
            );
            parts.next().is_none().then_some(output)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Watch {
        phase,
        excess,
        min_height,
        ended_at,
        outputs,
    })
}

fn decode_found(text: &str) -> Option<(&'static str, bool)> {
    let (during, dated) = text.split_once(' ')?;
    let during = match during {
        "restore" => "restore",
        "rescan" => "rescan",
        _ => return None,
    };
    let dated_by_block = match dated {
        "block" => true,
        "scan" => false,
        _ => return None,
    };
    Some((during, dated_by_block))
}

fn commitment(text: &str) -> Option<CommitmentBytes> {
    hex_array::<COMMITMENT_LEN>(text)
}

fn hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N.checked_mul(2)? || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut bytes = [0u8; N];
    for (byte, pair) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
        let text = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(text, 16).ok()?;
    }
    Some(bytes)
}
