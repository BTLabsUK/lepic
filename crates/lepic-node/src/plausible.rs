//! How far the chain can honestly move between two answers, so a single lying answer cannot
//! move the wallet's view of the chain arbitrarily far.

use std::time::Duration;

use lepic_primitives::amount::Height;

// Epic targets one block every 60 seconds (`consensus::BLOCK_TIME_SEC`). Difficulty adjustment
// lags, so blocks may come faster for a while; a tip that grows more than four times faster than
// the target is not believed.
const FASTEST_PLAUSIBLE_BLOCK_SECS: u64 = 60 / 4;

// One day of blocks at the target interval. It covers requests made moments apart to a node
// that was catching up after a short outage, or a switch to a node slightly ahead.
const TIP_ADVANCE_ALLOWANCE: u64 = 24 * 60;

/// The highest tip an honest node can report `elapsed` after it reported `previous`.
pub(crate) fn max_tip_after(previous: Height, elapsed: Duration) -> Height {
    let produced = elapsed
        .as_secs()
        .checked_div(FASTEST_PLAUSIBLE_BLOCK_SECS)
        .unwrap_or(0);
    let advance = produced.saturating_add(TIP_ADVANCE_ALLOWANCE);
    Height::new(previous.value().saturating_add(advance))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_a_day_of_blocks_at_once() {
        let previous = Height::new(1_000);
        assert_eq!(
            max_tip_after(previous, Duration::ZERO),
            Height::new(1_000 + 1_440)
        );
    }

    #[test]
    fn grows_four_times_faster_than_the_block_target() {
        let previous = Height::new(1_000);
        let hour = Duration::from_secs(3_600);
        assert_eq!(
            max_tip_after(previous, hour),
            Height::new(1_000 + 1_440 + 240)
        );
    }

    #[test]
    fn saturates_instead_of_overflowing() {
        let previous = Height::new(u64::MAX - 1);
        assert_eq!(
            max_tip_after(previous, Duration::MAX),
            Height::new(u64::MAX)
        );
    }
}
