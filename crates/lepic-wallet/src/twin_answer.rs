//! Answers over Epicbox for a slate this store does not know (ADR 0016, amendment of 26.10.8).
//!
//! Two installs on one recovery phrase share the payments address, and the relay hands each
//! message to whichever of their sockets subscribes, so an S2 or I2 for a slate the other
//! install started may reach this one first. Such an answer is not refused at once: its
//! message is held for [`TWIN_HOLD`], at least one relay challenge round, during which the
//! relay also hands it to the other install when that one subscribes. A message still here at
//! the bound is requeued: posted back to the address exactly as its sender signed it, then
//! acknowledged, so the copy waits at the back of the queue for the other install.
//!
//! What each such answer did is kept per `(slate_id, stage)` in one setting: when it was first
//! and last seen and how often it was requeued. An answer first seen [`TWIN_REQUEUE_WINDOW`] or
//! longer ago is refused for good, and so is a new one while [`MAX_TWIN_ANSWERS`] others are
//! cycling, so payments nobody started cannot keep the inbox busy.

use std::time::Duration;

use jiff::Timestamp;
use lepic_slate::stage::Stage;
use lepic_store::{Repositories, StoreError};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

/// How long the message of an answer for an unknown slate is held after it first arrived
/// before it is requeued: more than the relay's challenge interval of a minute, so the other
/// install subscribes at least once meanwhile and is handed the message too, and well under
/// the three rounds of three subscribes after which the relay discards the address's queue.
pub const TWIN_HOLD: Duration = Duration::from_secs(90);

/// How long after it was first seen an answer for an unknown slate is still requeued. Past it
/// the answer is refused for good and acknowledged: an install that stayed away for a day may
/// cancel the send and send again.
pub const TWIN_REQUEUE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Distinct answers for unknown slates that are held or requeued at once. A further one is
/// refused for good and acknowledged, as before this rule.
pub const MAX_TWIN_ANSWERS: usize = 4;

/// An answer last seen this long ago no longer counts toward [`MAX_TWIN_ANSWERS`]: its copy
/// was collected elsewhere, or waits for an install that is away. It is kept until its window
/// ends, so a copy that comes back is still requeued.
const TWIN_ACTIVE: Duration = Duration::from_secs(60 * 60);

/// Answers recorded at most, active or not, which bounds the setting.
const MAX_TWIN_RECORDS: usize = 32;

/// How far the wallet clock may step back before a message that seems to have arrived in the
/// future counts as having waited, as for the other holds of the inbox.
const CLOCK_STEP_TOLERANCE: Duration = Duration::from_secs(60);

pub(crate) const TWIN_ANSWERS_SETTING: &str = "inbox.twin_answers";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    /// Hyphenated.
    slate_id: String,
    stage: String,
    /// Unix seconds on the wallet clock.
    first_seen: i64,
    last_seen: i64,
    requeued: u32,
}

impl Record {
    fn is(&self, slate_id: Uuid, stage: Stage) -> bool {
        self.slate_id == slate_id.to_string() && self.stage == stage.as_str()
    }
}

/// What to do with the message of an answer for an unknown slate now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Leave it unacknowledged on the relay. `first` is true when the answer was not seen
    /// before.
    Hold { first: bool },
    /// Post it back to the address, then acknowledge it.
    Requeue { first: bool },
    /// Refuse it for good and acknowledge it.
    Refuse(Refused),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// [`MAX_TWIN_ANSWERS`] other answers are cycling; this one was never held.
    Crowded,
    /// It was first seen [`TWIN_REQUEUE_WINDOW`] or longer ago.
    WindowPassed,
}

fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn read(repos: &dyn Repositories) -> Result<Vec<Record>, StoreError> {
    Ok(match repos.setting(TWIN_ANSWERS_SETTING)? {
        Some(text) => serde_json::from_str(&text).unwrap_or_else(|_| {
            warn!("unknown slate answers unreadable");
            Vec::new()
        }),
        None => Vec::new(),
    })
}

fn write(repos: &mut dyn Repositories, records: &[Record]) -> Result<(), StoreError> {
    if records.is_empty() {
        return repos.delete_setting(TWIN_ANSWERS_SETTING);
    }
    // Plain data always serializes.
    let text = serde_json::to_string(records).unwrap_or_default();
    repos.put_setting(TWIN_ANSWERS_SETTING, &text)
}

fn window_passed(record: &Record, now: i64) -> bool {
    now.saturating_sub(record.first_seen) >= seconds(TWIN_REQUEUE_WINDOW)
}

/// Decides what becomes of the message of an answer for the unknown slate `slate_id` at
/// `stage`, which first arrived at `arrived`, and records that it was seen at `now`. A message
/// without an arrival, one the relay sent without an id and so never delivers again, is
/// requeued at once.
pub(crate) fn step(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    stage: Stage,
    arrived: Option<Timestamp>,
    now: Timestamp,
) -> Result<Step, StoreError> {
    let now_s = now.as_second();
    let mut records = read(repos)?;
    let index = records.iter().position(|record| record.is(slate_id, stage));
    if let Some(at) = index
        && records
            .get(at)
            .is_some_and(|record| window_passed(record, now_s))
    {
        records.remove(at);
        records.retain(|record| !window_passed(record, now_s));
        write(repos, &records)?;
        return Ok(Step::Refuse(Refused::WindowPassed));
    }
    records.retain(|record| !window_passed(record, now_s));
    let first = match records.iter_mut().find(|record| record.is(slate_id, stage)) {
        Some(record) => {
            record.last_seen = now_s;
            false
        }
        None => {
            let active_from = now_s.saturating_sub(seconds(TWIN_ACTIVE));
            let active = records
                .iter()
                .filter(|record| record.last_seen > active_from)
                .count();
            if active >= MAX_TWIN_ANSWERS || records.len() >= MAX_TWIN_RECORDS {
                write(repos, &records)?;
                return Ok(Step::Refuse(Refused::Crowded));
            }
            records.push(Record {
                slate_id: slate_id.to_string(),
                stage: stage.as_str().to_owned(),
                first_seen: now_s,
                last_seen: now_s,
                requeued: 0,
            });
            true
        }
    };
    write(repos, &records)?;
    Ok(if waited(arrived, now, TWIN_HOLD) {
        Step::Requeue { first }
    } else {
        Step::Hold { first }
    })
}

/// Whether a message that first arrived at `arrived` has waited `bound` by `now`, or arrived
/// more than [`CLOCK_STEP_TOLERANCE`] after `now`, which only a clock set back explains. A
/// message without an arrival has.
pub(crate) fn waited(arrived: Option<Timestamp>, now: Timestamp, bound: Duration) -> bool {
    let Some(arrived) = arrived else {
        return true;
    };
    let now_s = now.as_second();
    let arrived_s = arrived.as_second();
    arrived_s.saturating_sub(now_s) > seconds(CLOCK_STEP_TOLERANCE)
        || now_s.saturating_sub(arrived_s) >= seconds(bound)
}

/// Records that the answer's message was requeued, and returns how often it was so far.
pub(crate) fn record_requeued(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    stage: Stage,
) -> Result<u32, StoreError> {
    let mut records = read(repos)?;
    let Some(record) = records.iter_mut().find(|record| record.is(slate_id, stage)) else {
        return Ok(0);
    };
    record.requeued = record.requeued.saturating_add(1);
    let requeued = record.requeued;
    write(repos, &records)?;
    Ok(requeued)
}

/// Forgets the answer, which is no longer cycling.
pub(crate) fn forget(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    stage: Stage,
) -> Result<(), StoreError> {
    let mut records = read(repos)?;
    let before = records.len();
    records.retain(|record| !record.is(slate_id, stage));
    if records.len() == before {
        return Ok(());
    }
    write(repos, &records)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and use plain arithmetic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use lepic_store::{ContextKey, MemoryStore, WalletStore};

    use super::*;

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_790_000_000 + second).unwrap()
    }

    fn id(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn step_at(store: &MemoryStore, byte: u8, arrived: i64, now: i64) -> Step {
        store
            .write(|repos| step(repos, id(byte), Stage::S2, Some(at(arrived)), at(now)))
            .unwrap()
    }

    fn store() -> MemoryStore {
        MemoryStore::new(ContextKey::from_bytes([0; 32]))
    }

    #[test]
    fn an_answer_is_held_for_a_relay_round_then_requeued() {
        let store = store();
        let hold = seconds(TWIN_HOLD);
        assert_eq!(step_at(&store, 1, 0, 0), Step::Hold { first: true });
        assert_eq!(step_at(&store, 1, 0, hold - 1), Step::Hold { first: false });
        assert_eq!(step_at(&store, 1, 0, hold), Step::Requeue { first: false });
        // The copy that comes back is held again from its own arrival.
        assert_eq!(
            step_at(&store, 1, hold + 5, hold + 5),
            Step::Hold { first: false }
        );
        // A message the relay sent without an id is requeued at once.
        let at_once = store
            .write(|repos| step(repos, id(2), Stage::S2, None, at(0)))
            .unwrap();
        assert_eq!(at_once, Step::Requeue { first: true });
    }

    #[test]
    fn an_answer_is_refused_once_its_window_passed_and_then_forgotten() {
        let store = store();
        let window = seconds(TWIN_REQUEUE_WINDOW);
        assert_eq!(step_at(&store, 1, 0, 0), Step::Hold { first: true });
        assert_eq!(
            step_at(&store, 1, window - 10, window - 1),
            Step::Hold { first: false }
        );
        assert_eq!(
            step_at(&store, 1, window - 200, window),
            Step::Refuse(Refused::WindowPassed)
        );
        assert_eq!(
            store
                .read(|repos| repos.setting(TWIN_ANSWERS_SETTING))
                .unwrap(),
            None
        );
    }

    #[test]
    fn only_a_few_answers_cycle_at_once() {
        let store = store();
        for byte in 1..=4 {
            assert_eq!(step_at(&store, byte, 0, 0), Step::Hold { first: true });
        }
        assert_eq!(step_at(&store, 5, 0, 0), Step::Refuse(Refused::Crowded));
        // One the cap refused was not recorded; one forgotten makes room.
        store
            .write(|repos| forget(repos, id(2), Stage::S2))
            .unwrap();
        assert_eq!(step_at(&store, 5, 1, 1), Step::Hold { first: true });
        // Answers not seen for an hour no longer count.
        let later = seconds(TWIN_ACTIVE) + 1;
        assert_eq!(step_at(&store, 6, later, later), Step::Hold { first: true });
    }

    #[test]
    fn stages_are_answers_of_their_own_and_requeues_are_counted() {
        let store = store();
        assert_eq!(step_at(&store, 1, 0, 0), Step::Hold { first: true });
        let invoice = store
            .write(|repos| step(repos, id(1), Stage::I2, Some(at(0)), at(0)))
            .unwrap();
        assert_eq!(invoice, Step::Hold { first: true });
        for expected in 1..=2 {
            let count = store
                .write(|repos| record_requeued(repos, id(1), Stage::S2))
                .unwrap();
            assert_eq!(count, expected);
        }
        let unknown = store
            .write(|repos| record_requeued(repos, id(9), Stage::S2))
            .unwrap();
        assert_eq!(unknown, 0);
    }

    #[test]
    fn a_message_from_the_future_has_waited_once_past_the_tolerance() {
        let tolerance = seconds(CLOCK_STEP_TOLERANCE);
        assert!(!waited(Some(at(tolerance)), at(0), TWIN_HOLD));
        assert!(waited(Some(at(tolerance + 1)), at(0), TWIN_HOLD));
        assert!(waited(None, at(0), TWIN_HOLD));
    }
}
