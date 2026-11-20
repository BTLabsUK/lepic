// SPDX-License-Identifier: Apache-2.0
//! Sends over stock Epicbox that wait unanswered. Such a receiver cannot tell the sender that
//! it refused a payment, as one at its open receipt caps does, so a send whose answer has not
//! come within [`UNANSWERED_AFTER`] is marked once: the time is kept under a settings key, and
//! [`crate::Event::DeliveryChanged`] is raised as uncertain. A mark only: the send stays
//! `sent`, an answer that comes later finalizes it as before, and its funds unlock at its
//! cutoff or when it is cancelled. The key is deleted by the first refresh after the send
//! leaves `sent`.

use std::collections::HashSet;

use jiff::{SignedDuration, Timestamp};
use lepic_store::{
    Repositories, SlateStage, StoreError, TransactionEntry, TxDirection, TxId, TxState,
};
use uuid::Uuid;

use crate::event::SlateId;
use crate::refresh::{RefreshError, open_transactions};

/// How long a send over stock Epicbox waits for its answer before it is marked: a day, as the
/// contact outbox waits before it marks a payment stuck.
pub(crate) const UNANSWERED_AFTER: SignedDuration = SignedDuration::from_hours(24);

/// The settings key prefix recording when a send was marked unanswered.
const SEND_UNANSWERED_PREFIX: &str = "send.unanswered.";

fn unanswered_setting(slate_id: Uuid) -> String {
    format!("{SEND_UNANSWERED_PREFIX}{slate_id}")
}

/// A send marked by [`mark_unanswered`], with the address it was posted to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unanswered {
    pub slate_id: SlateId,
    pub route: String,
}

/// What a refresh has to change: the sends to mark now, and the keys of marks whose send left
/// `sent`.
#[derive(Debug, Default)]
pub(crate) struct Due {
    mark: Vec<(TxId, Uuid)>,
    clear: Vec<String>,
}

impl Due {
    pub(crate) fn is_empty(&self) -> bool {
        self.mark.is_empty() && self.clear.is_empty()
    }
}

/// Whether `slate_id` is a send this wallet posted to a stock Epicbox address and waits on:
/// its S1 stored, and no contact or epic1 outbox behind it, which marks its own posts. A send
/// whose answer came is finalized and stores S3, so it is no longer `sent`; the S2 check only
/// guards a send left `sent` with its answer stored.
fn waits_on_stock_epicbox(repos: &dyn Repositories, slate_id: Uuid) -> Result<bool, StoreError> {
    Ok(repos.slate(slate_id, SlateStage::Standard1)?.is_some()
        && repos.slate(slate_id, SlateStage::Standard2)?.is_none()
        && repos.native_outbox_of(slate_id)?.is_empty()
        && repos
            .payment_delivery(slate_id)?
            .and_then(|row| row.state)
            .is_none())
}

/// Reads what [`mark_unanswered`] would change at `now`, without writing: each send over stock
/// Epicbox that has waited [`UNANSWERED_AFTER`] or longer for its answer and is not marked yet,
/// and each mark of a send that is no longer `sent`.
pub(crate) fn due(repos: &dyn Repositories, now: Timestamp) -> Result<Due, RefreshError> {
    let mut due = Due::default();
    let mut waiting = HashSet::new();
    for stored in open_transactions(repos)? {
        let entry = &stored.entry;
        let (TxDirection::Outgoing, TxState::Sent, Some(slate_id)) =
            (entry.direction, entry.state, entry.slate_id)
        else {
            continue;
        };
        waiting.insert(unanswered_setting(slate_id));
        if entry.transport.as_deref() != Some("epicbox")
            || now.duration_since(entry.created_at) < UNANSWERED_AFTER
            || repos.setting(&unanswered_setting(slate_id))?.is_some()
            || !waits_on_stock_epicbox(repos, slate_id)?
        {
            continue;
        }
        due.mark.push((stored.id, slate_id));
    }
    due.clear = repos
        .settings_with_prefix(SEND_UNANSWERED_PREFIX)?
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| !waiting.contains(key))
        .collect();
    Ok(due)
}

/// Marks the sends [`due`] finds at `now` and deletes the marks it finds left behind, and
/// returns the sends marked now. Reads again inside the write, so a send answered since the
/// read is not marked.
pub(crate) fn mark_unanswered(
    repos: &mut dyn Repositories,
    now: Timestamp,
) -> Result<Vec<Unanswered>, RefreshError> {
    let due = due(repos, now)?;
    for key in &due.clear {
        repos.delete_setting(key)?;
    }
    let mut marked = Vec::with_capacity(due.mark.len());
    for (tx_id, slate_id) in due.mark {
        repos.put_setting(&unanswered_setting(slate_id), &now.to_string())?;
        marked.push(Unanswered {
            slate_id: SlateId::from_bytes(*slate_id.as_bytes()),
            route: repos.counterparty(tx_id)?.unwrap_or_default(),
        });
    }
    Ok(marked)
}

/// When the send `entry` was marked unanswered, while it still waits: `None` once it was
/// answered or ended, and for any other transaction.
pub(crate) fn unanswered_at(
    repos: &dyn Repositories,
    entry: &TransactionEntry,
) -> Result<Option<Timestamp>, StoreError> {
    let (TxState::Sent, Some(slate_id)) = (entry.state, entry.slate_id) else {
        return Ok(None);
    };
    Ok(repos
        .setting(&unanswered_setting(slate_id))?
        .and_then(|time| time.parse().ok()))
}
