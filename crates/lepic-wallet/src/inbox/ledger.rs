use std::time::Duration;

use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_store::{InboxEntry, InboxStatus, Repositories, StoreError, WalletStore};
use tracing::warn;
use uuid::Uuid;

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::last_confirmed;
use crate::twin_answer;
use crate::wallet::Wallet;

use super::{Handled, Hold, Requeue};

/// Settling messages prunes the relay inbox at most this often, on the wallet clock.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Tries of a message in one listen before a reply that keeps failing, or a slate that only the
/// node's tip says has expired, is settled anyway. The relay discards every message queued for
/// an address when one stays unacknowledged across several of its challenge rounds, which come
/// about a minute apart, and every message behind a held one waits meanwhile; so a held message
/// is settled well before that, while its payment can still be stored.
pub(super) const MAX_HOLD_ATTEMPTS: u32 = 3;

/// How long after its message first arrived such a message is still held, for drains, which
/// try each message once: well under the relay's challenge rounds that end in the queue being
/// discarded, as for [`MAX_HOLD_ATTEMPTS`].
pub(super) const HOLD_PATIENCE: Duration = Duration::from_secs(3 * 60);

/// How far the wallet clock may step back, as time synchronisation steps it, before a message
/// that seems to have arrived in the future counts as held for [`HOLD_PATIENCE`].
const CLOCK_STEP_TOLERANCE: Duration = Duration::from_secs(60);

/// An expired slate makes the inbox refresh the tip at most this often, on the wallet clock, so
/// a stream of expired slates costs bounded node work.
const TIP_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

const TIP_REFRESHED_SETTING: &str = "inbox.tip_refreshed_at";

/// Inserts or updates the inbox entry of `msg_id`, keeping when it was first received.
fn put_inbox(
    repos: &mut dyn Repositories,
    msg_id: &str,
    status: InboxStatus,
    now: jiff::Timestamp,
) -> Result<(), StoreError> {
    let received_at = repos.inbox(msg_id)?.map_or(now, |entry| entry.received_at);
    repos.put_inbox(&InboxEntry {
        msg_id: msg_id.to_owned(),
        status,
        received_at,
        updated_at: now,
    })
}

/// Forgets message ids received longer ago than `retention`, how long the method's relay keeps
/// messages, since the relay can no longer deliver them; `(slate_id, stage)` still makes a late
/// copy harmless.
pub(crate) fn prune_inbox(
    repos: &mut dyn Repositories,
    now: jiff::Timestamp,
    retention: Duration,
) -> Result<usize, StoreError> {
    match now.checked_sub(retention) {
        Ok(cutoff) => repos.prune_inbox(cutoff),
        Err(_) => Ok(0),
    }
}

fn prune_due(last: Option<jiff::Timestamp>, now: jiff::Timestamp) -> bool {
    last.is_none_or(|last| {
        now.checked_sub(PRUNE_INTERVAL)
            .is_ok_and(|due_from| last <= due_from)
    })
}

/// Records how a message settled. When a prune is due after `last_pruned`, it runs in the same
/// write, so a listen held open for longer than the relay retention keeps the inbox bounded
/// too; returns when it ran.
fn record_settled(
    repos: &mut dyn Repositories,
    msg_id: &str,
    status: InboxStatus,
    now: jiff::Timestamp,
    last_pruned: Option<jiff::Timestamp>,
    retention: Duration,
) -> Result<Option<jiff::Timestamp>, StoreError> {
    let pruned = if prune_due(last_pruned, now) {
        prune_inbox(repos, now, retention)?;
        Some(now)
    } else {
        None
    };
    put_inbox(repos, msg_id, status, now)?;
    Ok(pruned)
}

/// The status a message had before this delivery, recording it as received when it is new.
pub(super) fn begin_inbox(
    repos: &mut dyn Repositories,
    msg_id: &str,
    now: jiff::Timestamp,
) -> Result<Option<InboxStatus>, StoreError> {
    let previous = repos.inbox(msg_id)?.map(|entry| entry.status);
    if previous.is_none() {
        put_inbox(repos, msg_id, InboxStatus::Received, now)?;
    }
    Ok(previous)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Forgets the ids of messages received longer ago than `retention`, how long the method's
    /// relay keeps messages. A method's loop calls it before its subscription starts; a failure
    /// is logged and changes nothing else.
    pub async fn prune_arrivals(&self, retention: Duration) {
        if let Err(error) = self
            .inbox_write(move |repos, now| prune_inbox(repos, now, retention))
            .await
        {
            warn!(error = %ErrorChain(&error), "epicbox inbox not pruned");
        }
    }

    /// Records that `requeue` was posted back to the address for another install, and returns
    /// how often its answer was. A failed write is logged and counts 0.
    pub async fn requeued(&self, requeue: &Requeue) -> u32 {
        let uuid = Uuid::from_bytes(*requeue.slate_id.as_bytes());
        let stage = requeue.stage;
        let count = self
            .inbox_write(move |repos, _| twin_answer::record_requeued(repos, uuid, stage))
            .await;
        match count {
            Ok(count) => count,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "requeue not recorded");
                0
            }
        }
    }

    /// Whether the message `msg_id`, whose requeue the method failed to post, first arrived
    /// [`HOLD_PATIENCE`] ago or longer: then it is refused for good, as before requeues were
    /// made; until then it is held.
    pub async fn requeue_failed(&self, msg_id: Option<&str>) -> Result<bool, Hold> {
        let arrived = self.first_arrival(msg_id).await?;
        let now = self.ports().clock.now();
        Ok(twin_answer::waited(arrived, now, HOLD_PATIENCE))
    }

    /// Records how the message `msg_id` settled. When a prune is due after `last_pruned`, it
    /// forgets ids older than `retention` in the same write and returns when it ran, for the
    /// loop to pass as the next `last_pruned`. A failed write holds the message.
    pub async fn arrival_settled(
        &self,
        msg_id: &str,
        handled: Handled,
        last_pruned: Option<jiff::Timestamp>,
        retention: Duration,
    ) -> Result<Option<jiff::Timestamp>, Hold> {
        let msg_id = msg_id.to_owned();
        let status = handled.inbox_status();
        Ok(self
            .inbox_write(move |repos, now| {
                record_settled(repos, &msg_id, status, now, last_pruned, retention)
            })
            .await?)
    }

    /// Records that the method acknowledged the message `msg_id`, which settled as `handled`.
    /// A method's loop calls it after the acknowledgement; a message refused or dropped keeps
    /// the row [`Wallet::arrival_settled`] wrote. A failed write is logged.
    pub async fn arrival_acknowledged(&self, msg_id: &str, handled: Handled) {
        if handled.inbox_status() == InboxStatus::Rejected {
            return;
        }
        let msg_id = msg_id.to_owned();
        let recorded = self
            .inbox_write(move |repos, now| {
                put_inbox(repos, &msg_id, InboxStatus::Acknowledged, now)
            })
            .await;
        if let Err(error) = recorded {
            warn!(error = %ErrorChain(&error), "epicbox acknowledgement not recorded");
        }
    }

    /// When the message `msg_id` first arrived, from its relay inbox entry. `None` for a
    /// message without a relay id.
    pub(super) async fn first_arrival(
        &self,
        msg_id: Option<&str>,
    ) -> Result<Option<jiff::Timestamp>, Hold> {
        let Some(msg_id) = msg_id.map(str::to_owned) else {
            return Ok(None);
        };
        let session = self.session()?;
        Ok(self
            .blocking(move |_, _| Ok(session.store.read(|repos| repos.inbox(&msg_id))?))
            .await?
            .map(|entry| entry.received_at))
    }

    /// Whether a slate the node's tip says expired at `cutoff` is refused for good: a refresh
    /// stored a confirmed height at or past it, before or in one refresh made now, or the
    /// message reached the hold bound. A failed refresh leaves it held.
    pub(super) async fn expired_for_good(
        &self,
        msg_id: Option<&str>,
        attempt: u32,
        cutoff: lepic_primitives::amount::Height,
    ) -> Result<bool, Hold> {
        if self.confirmed_at(cutoff).await? {
            return Ok(true);
        }
        if self.tip_refresh_due().await? {
            match self.refresh().await {
                Ok(_) => {
                    if self.confirmed_at(cutoff).await? {
                        return Ok(true);
                    }
                }
                Err(error) => warn!(error = %ErrorChain(&error), "tip not refreshed"),
            }
        }
        self.hold_exhausted(msg_id, attempt).await
    }

    /// Records a tip refresh for the inbox now when none was made in the last
    /// [`TIP_REFRESH_INTERVAL`], and says whether it is due.
    pub(crate) async fn tip_refresh_due(&self) -> Result<bool, WalletError> {
        self.inbox_write(|repos, now| {
            let last = repos
                .setting(TIP_REFRESHED_SETTING)?
                .and_then(|text| text.parse::<jiff::Timestamp>().ok());
            let due = last.is_none_or(|last| {
                now.checked_sub(TIP_REFRESH_INTERVAL)
                    .is_ok_and(|due_from| last <= due_from || last > now)
            });
            if due {
                repos.put_setting(TIP_REFRESHED_SETTING, &now.to_string())?;
            }
            Ok(due)
        })
        .await
    }

    /// Whether the message `msg_id`, on its try `attempt`, reached the hold bound: this is try
    /// [`MAX_HOLD_ATTEMPTS`], or it first arrived [`HOLD_PATIENCE`] or longer ago, or more than
    /// [`CLOCK_STEP_TOLERANCE`] after the wallet clock's now, which only a clock set back
    /// explains.
    pub(super) async fn hold_exhausted(
        &self,
        msg_id: Option<&str>,
        attempt: u32,
    ) -> Result<bool, Hold> {
        if attempt >= MAX_HOLD_ATTEMPTS {
            return Ok(true);
        }
        // A relay gives every message a relay id on a subscription of protocol version 2.0.0 or
        // later, and marks one it sends without an id as handled as it sends it: that one is
        // never delivered again, so holding it gains nothing.
        let Some(msg_id) = msg_id.map(str::to_owned) else {
            return Ok(true);
        };
        let session = self.session()?;
        let now = self.ports().clock.now();
        let first_seen = self
            .blocking(move |_, _| Ok(session.store.read(|repos| repos.inbox(&msg_id))?))
            .await?
            .map(|entry| entry.received_at);
        let stepped_back_from = now.checked_add(CLOCK_STEP_TOLERANCE).ok();
        Ok(match (first_seen, now.checked_sub(HOLD_PATIENCE)) {
            (Some(first_seen), _) if stepped_back_from.is_some_and(|late| first_seen > late) => {
                true
            }
            (Some(first_seen), Ok(held_from)) => first_seen <= held_from,
            _ => false,
        })
    }

    /// Whether a refresh stored a confirmed height at or past `cutoff`. Only then is a slate
    /// that expired by the node's tip refused for good; until then the tip alone may be wrong,
    /// so the message stays on the relay.
    pub(crate) async fn confirmed_at(
        &self,
        cutoff: lepic_primitives::amount::Height,
    ) -> Result<bool, Hold> {
        let session = self.session()?;
        let confirmed = self
            .blocking(move |_, _| Ok(session.store.read(|repos| last_confirmed(repos))?))
            .await?;
        Ok(confirmed.is_some_and(|height| height >= cutoff))
    }

    pub(crate) async fn inbox_write<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut dyn Repositories, jiff::Timestamp) -> Result<T, StoreError>
        + Send
        + 'static,
    ) -> Result<T, WalletError> {
        let session = self.session()?;
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| Ok(work(repos, now)?))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn at(second: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(second).unwrap()
    }

    #[test]
    fn settling_prunes_at_most_once_per_interval() {
        let interval = i64::try_from(PRUNE_INTERVAL.as_secs()).unwrap();
        let last = at(1_000_000);
        assert!(prune_due(None, last));
        assert!(!prune_due(Some(last), last));
        assert!(!prune_due(Some(last), at(1_000_000 + interval - 1)));
        assert!(prune_due(Some(last), at(1_000_000 + interval)));
    }
}
