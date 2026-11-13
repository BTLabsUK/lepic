// SPDX-License-Identifier: Apache-2.0
//! Polling faster for a while (ADR 0058). A host runs a loop per poller at a base interval: the
//! contact collect cycle against the relays, and the refresh against the node. A boost makes one
//! of those loops run at a shorter interval until its window ends; it starts no loop of its own.
//! The host asks [`Boosts::interval`] before each sleep and wakes when [`Boosts::changed`]
//! does.
//!
//! A poller has one boost at most. A boost that overlaps the running one keeps the later end and
//! the shorter interval. The interval is at least [`MIN_INTERVAL`] and the window at most
//! [`MAX_DURATION`]: a value outside is clamped, and the caller is answered the window that took
//! effect.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use jiff::Timestamp;
use tokio::sync::watch;
use tokio::time::Instant;

/// The shortest interval a boost polls at.
pub const MIN_INTERVAL: Duration = Duration::from_secs(5);
/// The longest window one call starts.
pub const MAX_DURATION: Duration = Duration::from_secs(10 * 60);

/// A loop a boost speeds up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poller {
    /// The contact collect cycle: contact, pairing and epic1 link mailboxes on the relays.
    Relays,
    /// The wallet refresh against the node.
    Node,
}

/// A boost that runs: its poller polls every `interval` until `until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub poller: Poller,
    pub until: Timestamp,
    pub interval: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Running {
    ends: Instant,
    until: Timestamp,
    interval: Duration,
}

/// The boost of each poller, if it has one.
#[derive(Debug, Default)]
struct Slots {
    relays: Option<Running>,
    node: Option<Running>,
}

impl Slots {
    const fn of(&mut self, poller: Poller) -> &mut Option<Running> {
        match poller {
            Poller::Relays => &mut self.relays,
            Poller::Node => &mut self.node,
        }
    }
}

/// The boosts of one wallet.
#[derive(Debug)]
pub struct Boosts {
    running: Mutex<Slots>,
    changed: watch::Sender<u64>,
}

impl Default for Boosts {
    fn default() -> Self {
        Self {
            running: Mutex::default(),
            changed: watch::Sender::new(0),
        }
    }
}

impl Boosts {
    /// Polls `poller` every `interval` for `duration` from `now`, merged with the boost it has,
    /// and returns the window that took effect.
    pub fn boost(
        &self,
        poller: Poller,
        duration: Duration,
        interval: Duration,
        now: Timestamp,
    ) -> Window {
        let duration = duration.min(MAX_DURATION);
        let interval = interval.max(MIN_INTERVAL);
        let start = Instant::now();
        let asked = Running {
            ends: start.checked_add(duration).unwrap_or(start),
            until: now.checked_add(duration).unwrap_or(Timestamp::MAX),
            interval,
        };
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = running.of(poller);
        let merged = match slot.filter(|old| old.ends > start) {
            Some(old) => Running {
                ends: old.ends.max(asked.ends),
                until: old.until.max(asked.until),
                interval: old.interval.min(asked.interval),
            },
            None => asked,
        };
        *slot = Some(merged);
        drop(running);
        self.changed
            .send_modify(|count| *count = count.wrapping_add(1));
        Window {
            poller,
            until: merged.until,
            interval: merged.interval,
        }
    }

    /// The boost `poller` has now, if any.
    pub fn window(&self, poller: Poller) -> Option<Window> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = running.of(poller);
        if slot.is_some_and(|boost| boost.ends <= Instant::now()) {
            *slot = None;
        }
        slot.map(|boost| Window {
            poller,
            until: boost.until,
            interval: boost.interval,
        })
    }

    /// How long `poller` sleeps from now: its boost's interval while one runs, never more than
    /// `base`, or `base` when it has none.
    pub fn interval(&self, poller: Poller, base: Duration) -> Duration {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        match running.of(poller).filter(|boost| boost.ends > now) {
            Some(boost) => boost.interval.min(base),
            None => base,
        }
    }

    /// Changes each time a boost starts or changes.
    pub fn changed(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    const BASE: Duration = Duration::from_secs(30);

    fn now() -> Timestamp {
        Timestamp::from_second(1_800_000_000).unwrap()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[tokio::test(start_paused = true)]
    async fn a_boost_shortens_the_interval_until_its_window_ends() {
        let boosts = Boosts::default();
        assert_eq!(boosts.interval(Poller::Relays, BASE), BASE);
        let window = boosts.boost(Poller::Relays, secs(120), secs(5), now());
        assert_eq!(window.interval, secs(5));
        assert_eq!(window.until, now().checked_add(secs(120)).unwrap());
        assert_eq!(boosts.interval(Poller::Relays, BASE), secs(5));
        assert_eq!(boosts.interval(Poller::Node, BASE), BASE);
        tokio::time::advance(secs(120)).await;
        assert_eq!(boosts.interval(Poller::Relays, BASE), BASE);
        assert_eq!(boosts.window(Poller::Relays), None);
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_boosts_keep_the_later_end_and_the_shorter_interval() {
        let boosts = Boosts::default();
        boosts.boost(Poller::Relays, secs(300), secs(20), now());
        tokio::time::advance(secs(60)).await;
        let later = now().checked_add(secs(60)).unwrap();
        let window = boosts.boost(Poller::Relays, secs(60), secs(5), later);
        assert_eq!(window.interval, secs(5));
        assert_eq!(window.until, now().checked_add(secs(300)).unwrap());
        let window = boosts.boost(Poller::Relays, secs(600), secs(10), later);
        assert_eq!(window.interval, secs(5));
        assert_eq!(window.until, later.checked_add(secs(600)).unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn a_boost_after_the_window_ended_starts_afresh() {
        let boosts = Boosts::default();
        boosts.boost(Poller::Node, secs(10), secs(5), now());
        tokio::time::advance(secs(11)).await;
        let window = boosts.boost(Poller::Node, secs(60), secs(15), now());
        assert_eq!(window.interval, secs(15));
    }

    #[tokio::test(start_paused = true)]
    async fn values_outside_the_limits_are_clamped() {
        let boosts = Boosts::default();
        let window = boosts.boost(Poller::Relays, secs(86_400), Duration::ZERO, now());
        assert_eq!(window.interval, MIN_INTERVAL);
        assert_eq!(window.until, now().checked_add(MAX_DURATION).unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn a_boost_is_never_slower_than_the_base() {
        let boosts = Boosts::default();
        boosts.boost(Poller::Relays, secs(60), secs(300), now());
        assert_eq!(boosts.interval(Poller::Relays, BASE), BASE);
    }

    #[tokio::test(start_paused = true)]
    async fn each_boost_wakes_the_drivers() {
        let boosts = Boosts::default();
        let changed = boosts.changed();
        boosts.boost(Poller::Relays, secs(60), secs(5), now());
        assert!(changed.has_changed().unwrap());
    }
}
