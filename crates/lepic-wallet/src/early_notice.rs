// SPDX-License-Identifier: Apache-2.0
//! Notices that came before their slate (ADR 0049). A host that sets both
//! [`early_notice_max_count`](crate::WalletPolicy::early_notice_max_count) and
//! [`early_notice_max_age`](crate::WalletPolicy::early_notice_max_age) has a `declined`,
//! `withdrawn` or `cancelled` for a slate this wallet does not hold kept, as a settings row
//! under the slate and its sender, and applied once the slate arrives. Applying goes through
//! the rules of a notice just received, so one from anyone but the slate's recorded
//! counterparty changes nothing.
//!
//! An entry past the age cap goes at the next write or apply. At the count cap the oldest entry
//! goes, so older entries never stop newer ones.

use std::time::Duration;

use lepic_slate::model::SlateId;
use lepic_store::{CONTACT_ID_LEN, ContactId, Record, Repositories, StoreError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::WalletPolicy;
use crate::epicbox_notice::NoticeFrom;
use crate::notice::{Notice, NoticeKind};

const EARLY_PREFIX: &str = "notice.early.";

/// The host's caps on the buffer, present only when it is on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EarlyLimits {
    count: u32,
    age: Duration,
}

impl EarlyLimits {
    pub(crate) fn of(policy: &WalletPolicy) -> Option<Self> {
        Some(Self {
            count: policy.early_notice_max_count?,
            age: policy.early_notice_max_age?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Declined,
    Withdrawn,
    Cancelled,
}

impl Kind {
    /// `None` for a `posted`, which only a slate this wallet answered can be about.
    const fn of(kind: NoticeKind) -> Option<Self> {
        match kind {
            NoticeKind::Declined => Some(Self::Declined),
            NoticeKind::Withdrawn => Some(Self::Withdrawn),
            NoticeKind::Cancelled => Some(Self::Cancelled),
            NoticeKind::Posted { .. } => None,
        }
    }

    const fn notice(self) -> NoticeKind {
        match self {
            Self::Declined => NoticeKind::Declined,
            Self::Withdrawn => NoticeKind::Withdrawn,
            Self::Cancelled => NoticeKind::Cancelled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Sender {
    Epicbox(String),
    Contact([u8; CONTACT_ID_LEN]),
}

impl Sender {
    fn of(from: &NoticeFrom) -> Self {
        match from {
            NoticeFrom::Epicbox(key) => Self::Epicbox(key.clone()),
            NoticeFrom::Contact(id) => Self::Contact(id.0),
        }
    }

    fn from(self) -> NoticeFrom {
        match self {
            Self::Epicbox(key) => NoticeFrom::Epicbox(key),
            Self::Contact(id) => NoticeFrom::Contact(ContactId(id)),
        }
    }
}

/// One kept notice, as JSON under its key.
#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    kind: Kind,
    /// Unix seconds it first arrived.
    at: i64,
    from: Sender,
}

fn slate_prefix(slate_id: Uuid) -> String {
    format!("{EARLY_PREFIX}{slate_id}.")
}

fn key_for(slate_id: Uuid, from: &NoticeFrom) -> String {
    let prefix = slate_prefix(slate_id);
    match from {
        NoticeFrom::Epicbox(key) => format!("{prefix}epicbox:{key}"),
        NoticeFrom::Contact(id) => format!("{prefix}contact:{id}"),
    }
}

/// The kept entries still within the age cap, oldest first; the rest are deleted, and so is a
/// row that does not read.
fn live(
    repos: &mut dyn Repositories,
    limits: EarlyLimits,
    now: jiff::Timestamp,
) -> Result<Vec<(String, Entry)>, StoreError> {
    let age = i64::try_from(limits.age.as_secs()).unwrap_or(i64::MAX);
    let oldest = now.as_second().saturating_sub(age);
    let mut entries = Vec::new();
    for (key, value) in repos.settings_with_prefix(EARLY_PREFIX)? {
        match serde_json::from_str::<Entry>(&value) {
            Ok(entry) if entry.at >= oldest => entries.push((key, entry)),
            _ => repos.delete_setting(&key)?,
        }
    }
    entries.sort_by(|(a_key, a), (b_key, b)| a.at.cmp(&b.at).then_with(|| a_key.cmp(b_key)));
    Ok(entries)
}

/// Keeps `notice` from `from`, for a slate this wallet does not hold, and says whether it did.
/// A sender's later notice for the slate replaces its earlier one of another kind; a repeat
/// keeps the time of the first.
pub(crate) fn keep(
    repos: &mut dyn Repositories,
    limits: EarlyLimits,
    notice: Notice,
    from: &NoticeFrom,
    now: jiff::Timestamp,
) -> Result<bool, StoreError> {
    let Some(kind) = Kind::of(notice.kind) else {
        return Ok(false);
    };
    let key = key_for(Uuid::from_bytes(*notice.slate_id.as_bytes()), from);
    let entries = live(repos, limits, now)?;
    let same = entries.iter().find(|(held, _)| *held == key);
    if same.is_some_and(|(_, entry)| entry.kind == kind) {
        return Ok(true);
    }
    if same.is_none() {
        let room = usize::try_from(limits.count).unwrap_or(usize::MAX);
        let over = entries.len().saturating_add(1).saturating_sub(room);
        for (oldest, _) in entries.iter().take(over) {
            repos.delete_setting(oldest)?;
        }
    }
    let entry = Entry {
        kind,
        at: now.as_second(),
        from: Sender::of(from),
    };
    let text = serde_json::to_string(&entry).map_err(|_| StoreError::Corrupt {
        record: Record::Setting,
        field: "early notice",
    })?;
    repos.put_setting(&key, &text)?;
    Ok(true)
}

/// Takes the notices kept for `slate_id` off the buffer, oldest first, with who sent them, for
/// the caller to apply in the same store transaction.
pub(crate) fn take(
    repos: &mut dyn Repositories,
    limits: EarlyLimits,
    slate_id: SlateId,
    now: jiff::Timestamp,
) -> Result<Vec<(Notice, NoticeFrom)>, StoreError> {
    let prefix = slate_prefix(Uuid::from_bytes(*slate_id.as_bytes()));
    let mut taken = Vec::new();
    for (key, entry) in live(repos, limits, now)? {
        if key.starts_with(&prefix) {
            repos.delete_setting(&key)?;
            let notice = Notice {
                slate_id,
                kind: entry.kind.notice(),
            };
            taken.push((notice, entry.from.from()));
        }
    }
    Ok(taken)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]

    use lepic_store::{CONTEXT_KEY_LEN, MemoryStore, StoreKeys, WalletStore};

    use super::*;

    const LIMITS: EarlyLimits = EarlyLimits {
        count: 2,
        age: Duration::from_secs(100),
    };

    fn store() -> MemoryStore {
        MemoryStore::new(StoreKeys::from_bytes(
            [1; CONTEXT_KEY_LEN],
            [1; CONTEXT_KEY_LEN],
        ))
    }

    fn at(second: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(second).unwrap()
    }

    fn cancelled(byte: u8) -> Notice {
        Notice {
            slate_id: SlateId::from_bytes([byte; 16]),
            kind: NoticeKind::Cancelled,
        }
    }

    fn from(key: &str) -> NoticeFrom {
        NoticeFrom::Epicbox(key.to_owned())
    }

    fn keep_one(store: &MemoryStore, notice: Notice, sender: &NoticeFrom, second: i64) -> bool {
        store
            .write(|repos| keep(repos, LIMITS, notice, sender, at(second)))
            .unwrap()
    }

    fn take_slate(store: &MemoryStore, byte: u8, second: i64) -> usize {
        let id = SlateId::from_bytes([byte; 16]);
        store
            .write(|repos| take(repos, LIMITS, id, at(second)))
            .unwrap()
            .len()
    }

    #[test]
    fn a_posted_is_not_kept() {
        let store = store();
        let notice = Notice {
            kind: NoticeKind::Posted {
                excess: lepic_crypto::Commitment::commit_value(1).unwrap(),
            },
            ..cancelled(1)
        };

        assert!(!keep_one(&store, notice, &from("a"), 10));
    }

    #[test]
    fn two_senders_of_one_slate_are_kept_side_by_side() {
        let store = store();
        assert!(keep_one(&store, cancelled(1), &from("a"), 10));
        assert!(keep_one(&store, cancelled(1), &from("b"), 10));

        assert_eq!(take_slate(&store, 1, 10), 2);
        assert_eq!(take_slate(&store, 1, 10), 0);
    }

    #[test]
    fn at_the_count_cap_the_oldest_goes() {
        let store = store();
        keep_one(&store, cancelled(1), &from("a"), 10);
        keep_one(&store, cancelled(2), &from("a"), 11);
        keep_one(&store, cancelled(3), &from("a"), 12);

        assert_eq!(take_slate(&store, 1, 12), 0);
        assert_eq!(take_slate(&store, 2, 12), 1);
        assert_eq!(take_slate(&store, 3, 12), 1);
    }

    #[test]
    fn a_repeat_keeps_its_first_time_and_takes_no_room() {
        let store = store();
        keep_one(&store, cancelled(1), &from("a"), 10);
        keep_one(&store, cancelled(2), &from("a"), 11);
        keep_one(&store, cancelled(1), &from("a"), 90);

        assert_eq!(take_slate(&store, 2, 12), 1);
        assert_eq!(take_slate(&store, 1, 111), 0);
    }

    #[test]
    fn an_entry_past_its_age_goes_at_the_next_write_or_apply() {
        let store = store();
        keep_one(&store, cancelled(1), &from("a"), 10);
        keep_one(&store, cancelled(2), &from("a"), 10);

        assert_eq!(take_slate(&store, 1, 110), 1);
        keep_one(&store, cancelled(3), &from("a"), 111);

        let rows = store
            .read(|repos| repos.settings_with_prefix(EARLY_PREFIX))
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn a_row_that_does_not_read_is_cleared() {
        let store = store();
        store
            .write(|repos| repos.put_setting("notice.early.x", "damaged"))
            .unwrap();

        assert_eq!(take_slate(&store, 1, 10), 0);

        let rows = store
            .read(|repos| repos.settings_with_prefix(EARLY_PREFIX))
            .unwrap();
        assert!(rows.is_empty());
    }
}
