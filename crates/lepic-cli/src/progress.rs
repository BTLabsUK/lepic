// SPDX-License-Identifier: Apache-2.0
//! Lines a long-running command writes to stderr while it runs, for people watching it: scan
//! progress during a restore, and the relay connection and transaction changes while
//! listening. Only with human output; JSON output keeps stderr for logs.

use lepic_wallet::Event;
use lepic_wallet::event::{SyncProgress, TransportState};
use lepic_wallet::state::state_name;

/// Scan progress is reported in steps of this many percent of the range.
const SCAN_STEP_PERCENT: u64 = 10;

#[derive(Debug, Default)]
pub struct Progress {
    /// The last scan height reported, so a step is reported once.
    reported_height: Option<u64>,
}

impl Progress {
    /// The line to show for `event`, if it is worth one.
    pub fn line(&mut self, event: &Event) -> Option<String> {
        match event {
            Event::Sync(progress) => self.scan_line(*progress),
            Event::Transport(status) => match status.state {
                TransportState::Connected => {
                    Some("connected to the relay; waiting for slates".to_owned())
                }
                TransportState::Disconnected => {
                    Some("relay connection lost; reconnecting".to_owned())
                }
                _ => None,
            },
            Event::Transaction(change) => Some(format!(
                "transaction {} {}",
                change.tx_id,
                state_name(change.to)
            )),
            _ => None,
        }
    }

    fn scan_line(&mut self, progress: SyncProgress) -> Option<String> {
        let height = progress.height.value();
        let target = progress.target.value();
        let step = (target / (100 / SCAN_STEP_PERCENT)).max(1);
        let due = match self.reported_height {
            None => true,
            Some(last) => height >= target || height.saturating_sub(last) >= step,
        };
        if !due || self.reported_height == Some(height) {
            return None;
        }
        self.reported_height = Some(height);
        Some(format!("scanned to height {height} of {target}"))
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Height;

    use super::*;

    fn sync(height: u64, target: u64) -> Event {
        Event::Sync(SyncProgress {
            height: Height::new(height),
            target: Height::new(target),
        })
    }

    #[test]
    fn scan_progress_is_reported_in_steps_and_at_the_end() {
        let mut progress = Progress::default();
        let lines: Vec<String> = [0, 50, 99, 100, 150, 400, 999, 1000, 1000]
            .into_iter()
            .filter_map(|height| progress.line(&sync(height, 1000)))
            .collect();
        assert_eq!(
            lines,
            [
                "scanned to height 0 of 1000",
                "scanned to height 100 of 1000",
                "scanned to height 400 of 1000",
                "scanned to height 999 of 1000",
                "scanned to height 1000 of 1000",
            ]
        );
    }

    #[test]
    fn a_short_scan_reports_every_height_once() {
        let mut progress = Progress::default();
        let lines: Vec<String> = [0, 1, 1, 2]
            .into_iter()
            .filter_map(|height| progress.line(&sync(height, 2)))
            .collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
    }
}
