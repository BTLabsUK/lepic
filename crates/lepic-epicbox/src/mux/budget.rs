// SPDX-License-Identifier: Apache-2.0
//! How many `Waiting` requests a session sends: a cap over a rolling window, and a pause after
//! the relay answered one `rate_limited`.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// The shortest pause after a `rate_limited` answer to `Waiting`. Epicmail never asks for less.
const MIN_PAUSE: Duration = Duration::from_secs(1);

/// `Waiting` requests sent in the last window, the caller's and the session's own probes. Kept
/// across sockets: a socket that came back soon after the last one was lost still counts what
/// that one sent.
#[derive(Debug)]
pub(super) struct WaitingBudget {
    cap: u32,
    window: Duration,
    sent: VecDeque<Instant>,
    paused_until: Option<Instant>,
}

impl WaitingBudget {
    pub(super) fn new(cap: u32, window: Duration) -> Self {
        Self {
            cap,
            window,
            sent: VecDeque::new(),
            paused_until: None,
        }
    }

    /// Spends one request at `now`. `Err` with the time until the next one may go when the
    /// window's requests are spent, or the relay asked for a pause that has not ended.
    pub(super) fn take(&mut self, now: Instant) -> Result<(), Duration> {
        if let Some(until) = self.paused_until {
            if until > now {
                return Err(until.saturating_duration_since(now));
            }
            self.paused_until = None;
        }
        while self
            .sent
            .front()
            .is_some_and(|sent| now.saturating_duration_since(*sent) >= self.window)
        {
            self.sent.pop_front();
        }
        let cap = usize::try_from(self.cap).unwrap_or(usize::MAX);
        if self.sent.len() >= cap {
            // A cap of zero sends nothing: the next request is a whole window away.
            let next = self.sent.front().map_or(self.window, |first| {
                self.window
                    .saturating_sub(now.saturating_duration_since(*first))
            });
            return Err(next);
        }
        self.sent.push_back(now);
        Ok(())
    }

    /// Sends nothing more until `retry_after` from `now`, at least a second.
    pub(super) fn pause(&mut self, now: Instant, retry_after: Duration) {
        let until = now
            .checked_add(retry_after.max(MIN_PAUSE))
            .or_else(|| now.checked_add(MIN_PAUSE))
            .unwrap_or(now);
        self.paused_until = Some(
            self.paused_until
                .map_or(until, |current| current.max(until)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    #[test]
    fn the_cap_holds_over_any_window() {
        let start = Instant::now();
        let mut budget = WaitingBudget::new(3, WINDOW);
        for second in 0..3 {
            assert_eq!(budget.take(start + Duration::from_secs(second)), Ok(()));
        }
        assert_eq!(
            budget.take(start + Duration::from_secs(10)),
            Err(Duration::from_secs(50))
        );
        // The first request leaves the window at 60 s; the second at 61 s.
        assert_eq!(budget.take(start + Duration::from_secs(60)), Ok(()));
        assert_eq!(
            budget.take(start + Duration::from_secs(60)),
            Err(Duration::from_secs(1))
        );
        assert_eq!(budget.take(start + Duration::from_secs(61)), Ok(()));
    }

    #[test]
    fn a_refused_request_is_not_spent() {
        let start = Instant::now();
        let mut budget = WaitingBudget::new(1, WINDOW);
        assert_eq!(budget.take(start), Ok(()));
        for second in 1..10 {
            assert!(budget.take(start + Duration::from_secs(second)).is_err());
        }
        assert_eq!(budget.take(start + WINDOW), Ok(()));
    }

    #[test]
    fn a_pause_stops_requests_until_it_ends() {
        let start = Instant::now();
        let mut budget = WaitingBudget::new(20, WINDOW);
        budget.pause(start, Duration::from_secs(30));
        assert_eq!(
            budget.take(start + Duration::from_secs(10)),
            Err(Duration::from_secs(20))
        );
        // A shorter pause does not cut a longer one.
        budget.pause(start + Duration::from_secs(10), Duration::from_secs(5));
        assert!(budget.take(start + Duration::from_secs(29)).is_err());
        assert_eq!(budget.take(start + Duration::from_secs(30)), Ok(()));
    }

    #[test]
    fn a_pause_lasts_at_least_a_second() {
        let start = Instant::now();
        let mut budget = WaitingBudget::new(20, WINDOW);
        budget.pause(start, Duration::ZERO);
        assert_eq!(budget.take(start), Err(MIN_PAUSE));
        assert_eq!(budget.take(start + MIN_PAUSE), Ok(()));
    }

    #[test]
    fn a_zero_cap_sends_nothing() {
        let start = Instant::now();
        let mut budget = WaitingBudget::new(0, WINDOW);
        assert_eq!(budget.take(start), Err(WINDOW));
    }
}
