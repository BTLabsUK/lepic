// SPDX-License-Identifier: Apache-2.0
//! Polling faster for a while (ADR 0058). A host runs a loop per poller at a base interval: the
//! contact collect cycle against the relays, and the refresh against the node. A boost makes one
//! of those loops run at a shorter interval until its window ends or its caller ends it; it
//! starts no loop of its own. The host asks [`Boosts::interval`] before each sleep and wakes when
//! [`Boosts::changed`] does.
//!
//! Each call starts its own boost and gets a [`Lease`] on it. Its id is random, so a caller
//! that may end a boost by its id cannot guess the id of another caller's boost. A poller with several boosts runs
//! at the shortest interval among them until the last one ends; ending one recomputes that from
//! the rest. The interval is at least [`MIN_INTERVAL`] and the window at most [`MAX_DURATION`]: a
//! value outside is clamped.

use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use jiff::Timestamp;
use rand_core::CryptoRng;
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

/// What a poller runs at now: every `interval` until `until`, from the boosts it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub poller: Poller,
    pub until: Timestamp,
    pub interval: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Running {
    id: u64,
    poller: Poller,
    ends: Instant,
    until: Timestamp,
    interval: Duration,
}

#[derive(Debug, Default)]
struct State {
    running: Vec<Running>,
}

impl State {
    /// Forgets the boosts whose window ended, then merges those of `poller`.
    fn window(&mut self, poller: Poller) -> Option<Window> {
        let now = Instant::now();
        self.running.retain(|boost| boost.ends > now);
        self.running
            .iter()
            .filter(|boost| boost.poller == poller)
            .fold(None, |merged: Option<Window>, boost| {
                Some(Window {
                    poller,
                    until: merged.map_or(boost.until, |m| m.until.max(boost.until)),
                    interval: merged.map_or(boost.interval, |m| m.interval.min(boost.interval)),
                })
            })
    }
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    changed: watch::Sender<u64>,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self) {
        self.changed
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    fn end(&self, id: u64) -> bool {
        let mut state = self.state();
        let before = state.running.len();
        state.running.retain(|boost| boost.id != id);
        let ended = state.running.len() < before;
        drop(state);
        if ended {
            self.notify();
        }
        ended
    }
}

/// The boosts of one wallet.
#[derive(Debug)]
pub struct Boosts {
    shared: Arc<Shared>,
}

impl Default for Boosts {
    fn default() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::default(),
                changed: watch::Sender::new(0),
            }),
        }
    }
}

impl Boosts {
    /// Starts a boost: `poller` runs at most every `interval` for `duration` from `now`. Its
    /// id is drawn from `rng`. The lease ends it when dropped, unless [`Lease::keep`] hands
    /// its id on.
    pub fn boost(
        &self,
        poller: Poller,
        duration: Duration,
        interval: Duration,
        now: Timestamp,
        rng: &mut dyn CryptoRng,
    ) -> Lease {
        let duration = duration.min(MAX_DURATION);
        let start = Instant::now();
        let mut state = self.shared.state();
        let id = loop {
            let mut bytes = [0u8; 8];
            rng.fill_bytes(&mut bytes);
            // 1 to 2^53 - 1: an integer every JSON reader keeps exact.
            let id = u64::from_le_bytes(bytes) >> 11;
            if id != 0 && state.running.iter().all(|boost| boost.id != id) {
                break id;
            }
        };
        let asked = Running {
            id,
            poller,
            ends: start.checked_add(duration).unwrap_or(start),
            until: now.checked_add(duration).unwrap_or(Timestamp::MAX),
            interval: interval.max(MIN_INTERVAL),
        };
        state.running.push(asked);
        // Empty only for a zero duration, which ended as it started.
        let window = state.window(poller).unwrap_or(Window {
            poller,
            until: asked.until,
            interval: asked.interval,
        });
        drop(state);
        self.shared.notify();
        Lease {
            id: asked.id,
            window,
            shared: Some(Arc::downgrade(&self.shared)),
        }
    }

    /// Ends the boost `id`, if it still runs; the poller's window is then that of the rest.
    pub fn end(&self, id: u64) -> bool {
        self.shared.end(id)
    }

    /// What `poller` runs at now, if a boost runs.
    pub fn window(&self, poller: Poller) -> Option<Window> {
        self.shared.state().window(poller)
    }

    /// How long `poller` sleeps from now: its boosts' interval while one runs, never more than
    /// `base`, or `base` when it has none.
    pub fn interval(&self, poller: Poller, base: Duration) -> Duration {
        self.window(poller)
            .map_or(base, |window| window.interval.min(base))
    }

    /// Changes each time a boost starts or is ended.
    pub fn changed(&self) -> watch::Receiver<u64> {
        self.shared.changed.subscribe()
    }
}

/// One boost: ended when dropped, unless kept.
#[derive(Debug)]
#[must_use = "dropping a lease ends its boost; keep() lets it run"]
pub struct Lease {
    id: u64,
    window: Window,
    shared: Option<Weak<Shared>>,
}

impl Lease {
    /// The boost's id, for [`Boosts::end`].
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// The poller's window once this boost started.
    pub const fn window(&self) -> Window {
        self.window
    }

    /// Lets the boost run until its window ends or [`Boosts::end`] is called with the id
    /// returned.
    pub fn keep(mut self) -> u64 {
        self.shared = None;
        self.id
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take().and_then(|shared| shared.upgrade()) {
            shared.end(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;

    use super::*;

    const BASE: Duration = Duration::from_secs(30);

    fn now() -> Timestamp {
        Timestamp::from_second(1_800_000_000).unwrap()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn start(
        boosts: &Boosts,
        poller: Poller,
        duration: u64,
        interval: u64,
        at: Timestamp,
    ) -> Lease {
        let mut rng = rand::rngs::StdRng::seed_from_u64(duration ^ interval);
        boosts.boost(poller, secs(duration), secs(interval), at, &mut rng)
    }

    #[tokio::test(start_paused = true)]
    async fn a_boost_shortens_the_interval_until_its_window_ends() {
        let boosts = Boosts::default();
        assert_eq!(boosts.interval(Poller::Relays, BASE), BASE);
        let lease = start(&boosts, Poller::Relays, 120, 5, now());
        assert_eq!(lease.window().interval, secs(5));
        assert_eq!(lease.window().until, now().checked_add(secs(120)).unwrap());
        assert!(lease.id() > 1 && lease.id() < 1 << 53, "{}", lease.id());
        assert_eq!(boosts.interval(Poller::Relays, BASE), secs(5));
        assert_eq!(boosts.interval(Poller::Node, BASE), BASE);
        tokio::time::advance(secs(120)).await;
        assert_eq!(boosts.interval(Poller::Relays, BASE), BASE);
        assert_eq!(boosts.window(Poller::Relays), None);
        assert!(!boosts.end(lease.keep()));
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_boosts_run_at_the_shortest_interval_until_the_last_ends() {
        let boosts = Boosts::default();
        let long = start(&boosts, Poller::Relays, 300, 20, now()).keep();
        tokio::time::advance(secs(60)).await;
        let later = now().checked_add(secs(60)).unwrap();
        let short = start(&boosts, Poller::Relays, 60, 5, later);
        assert_eq!(short.window().interval, secs(5));
        assert_eq!(short.window().until, now().checked_add(secs(300)).unwrap());
        let short = short.keep();
        assert_ne!(long, short);
        tokio::time::advance(secs(60)).await;
        assert_eq!(boosts.interval(Poller::Relays, BASE), secs(20));
        assert!(boosts.end(long));
        assert!(!boosts.end(short));
        assert_eq!(boosts.window(Poller::Relays), None);
    }

    #[tokio::test(start_paused = true)]
    async fn ending_a_boost_recomputes_the_window_from_the_rest() {
        let boosts = Boosts::default();
        let slow = start(&boosts, Poller::Node, 600, 15, now());
        let fast = start(&boosts, Poller::Node, 60, 5, now());
        let changed = boosts.changed();
        assert!(boosts.end(fast.keep()));
        assert!(changed.has_changed().unwrap());
        let window = boosts.window(Poller::Node).unwrap();
        assert_eq!(window.interval, secs(15));
        assert_eq!(window.until, now().checked_add(secs(600)).unwrap());
        // Dropping a lease ends its boost.
        drop(slow);
        assert_eq!(boosts.interval(Poller::Node, BASE), BASE);
    }

    #[tokio::test(start_paused = true)]
    async fn values_outside_the_limits_are_clamped() {
        let boosts = Boosts::default();
        let lease = start(&boosts, Poller::Relays, 86_400, 0, now());
        assert_eq!(lease.window().interval, MIN_INTERVAL);
        assert_eq!(
            lease.window().until,
            now().checked_add(MAX_DURATION).unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_boost_is_never_slower_than_the_base() {
        let boosts = Boosts::default();
        let _lease = start(&boosts, Poller::Relays, 60, 300, now());
        assert_eq!(boosts.interval(Poller::Relays, BASE), BASE);
    }

    #[tokio::test(start_paused = true)]
    async fn each_boost_wakes_the_drivers() {
        let boosts = Boosts::default();
        let changed = boosts.changed();
        let _lease = start(&boosts, Poller::Relays, 60, 5, now());
        assert!(changed.has_changed().unwrap());
    }
}
