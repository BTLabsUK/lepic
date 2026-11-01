// SPDX-License-Identifier: Apache-2.0
//! Moves what schema version 11 kept per peer key in clear into the sealed rows version 12 adds,
//! then drops the old table.
//!
//! A version 11 row said either that a marked message came from the key (`lepic`) or that the
//! key sent an invoice back unchanged (`no-invoices`), with when it was learned. The first
//! becomes the date of the last marked message, with the marker's own feature bit claimed and
//! working; the second the date of the last unmarked one. A row whose values do not decode is
//! dropped, which leaves the peer unknown: nothing but slates goes to an unknown peer.

use jiff::Timestamp;
use rusqlite::{Connection, params};
use tracing::warn;

use crate::context::StoreKeys;
use crate::error::StoreError;
use crate::peer::{self, PeerCompat};

/// The bit any LEPIC marker claims.
const MARKER_BIT: u32 = 1;

fn migrated(support: &str, learned_at: Timestamp) -> Option<PeerCompat> {
    match support {
        "lepic" => Some(PeerCompat {
            last_marked_at: Some(learned_at),
            claimed: MARKER_BIT,
            works: MARKER_BIT,
            ..PeerCompat::default()
        }),
        "no-invoices" => Some(PeerCompat {
            last_unmarked_at: Some(learned_at),
            ..PeerCompat::default()
        }),
        _ => None,
    }
}

pub(super) fn move_peer_capabilities(
    conn: &Connection,
    keys: &StoreKeys,
) -> Result<(), StoreError> {
    let mut statement = conn.prepare("SELECT key, support, learned_at FROM peer_capabilities")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut dropped = 0_usize;
    for (key, support, learned_at) in rows {
        let compat = Timestamp::from_nanosecond(i128::from(learned_at))
            .ok()
            .and_then(|learned_at| migrated(&support, learned_at));
        let Some(compat) = compat else {
            dropped = dropped.saturating_add(1);
            continue;
        };
        let tag = keys.peer_tag.tag(&key)?;
        let sealed = peer::seal(&keys.context, &tag, &compat)?;
        conn.execute(
            "INSERT INTO peer_compat (key_tag, sealed) VALUES (?1, ?2)",
            params![tag.0.as_slice(), sealed],
        )?;
    }
    if dropped > 0 {
        warn!(count = dropped, "undecodable peer records dropped");
    }
    conn.execute_batch("DROP TABLE peer_capabilities;")?;
    Ok(())
}
