//! How far the wallet knows the chain has come, and the checks a node's tip and heights pass
//! before refresh or scan act on them.
//!
//! A node's tip decides which transactions expire and where the next scan starts, so a tip far
//! above anything the chain can have reached is refused instead of stored. The bound grows with
//! the time since the wallet last stored a tip, at twice the target block rate, and never
//! exceeds twice the blocks the chain can have produced since genesis, so a tip that is refused
//! once cannot be reached by many small steps either.

use jiff::Timestamp;
use lepic_primitives::amount::Height;
use lepic_store::{Repositories, StoreError};
use thiserror::Error;
use tracing::warn;

/// Epic's target block interval, `BLOCK_TIME_SEC` in the node's consensus rules.
pub const BLOCK_TIME_SECONDS: u64 = 60;

/// How many times the target block rate a plausible tip may have advanced at.
const BLOCK_RATE_MARGIN: u64 = 2;

/// Blocks a tip may lead the time-based bound by, for short bursts of fast blocks.
pub const TIP_SLACK_BLOCKS: u64 = 60;

/// Blocks a second tip asked for within one refresh may lead the first by.
pub const TIP_AGREEMENT_BLOCKS: u64 = 3;

/// Timestamp of the mainnet and floonet genesis blocks of Epic node v4.0.4, 2019-08-09
/// 17:04:38 UTC.
const GENESIS_SECONDS: i64 = 1_565_370_278;

const REFERENCE_SETTING: &str = "chain.reference";

/// Node data the wallet refuses to act on. Nothing derived from the answer is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ImplausibleNodeData {
    #[error("node tip {tip} is above the highest plausible height {limit}")]
    TipTooHigh { tip: Height, limit: Height },
    #[error("node reported an output at height {height} above its tip {tip}")]
    OutputAboveTip { height: Height, tip: Height },
    #[error("node reported a kernel at height {height} outside the heights {min} to {tip}")]
    KernelOutOfRange {
        height: Height,
        min: Height,
        tip: Height,
    },
    /// Two tips asked for within one refresh disagree; nothing that depends on the tip was
    /// changed.
    #[error("node tip moved from {first} to {second} within one refresh")]
    TipChanged { first: Height, second: Height },
}

/// The highest tip the wallet stored, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainReference {
    height: Height,
    seen_at: i64,
}

impl ChainReference {
    fn encode(self) -> String {
        format!("{} {}", self.height, self.seen_at)
    }

    fn decode(text: &str) -> Option<Self> {
        let (height, seen_at) = text.split_once(' ')?;
        Some(Self {
            height: Height::new(height.parse().ok()?),
            seen_at: seen_at.parse().ok()?,
        })
    }
}

/// A stored reference that does not parse is ignored; the genesis bound still applies.
pub(crate) fn reference(repos: &dyn Repositories) -> Result<Option<ChainReference>, StoreError> {
    Ok(match repos.setting(REFERENCE_SETTING)? {
        Some(text) => {
            let reference = ChainReference::decode(&text);
            if reference.is_none() {
                warn!("chain reference unreadable");
            }
            reference
        }
        None => None,
    })
}

/// Records `tip` as seen at `now`, unless a higher tip is already recorded.
pub(crate) fn record_tip(
    repos: &mut dyn Repositories,
    tip: Height,
    now: Timestamp,
) -> Result<(), StoreError> {
    if reference(repos)?.is_some_and(|stored| stored.height >= tip) {
        return Ok(());
    }
    let reference = ChainReference {
        height: tip,
        seen_at: now.as_second(),
    };
    repos.put_setting(REFERENCE_SETTING, &reference.encode())
}

pub(crate) fn forget(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    repos.delete_setting(REFERENCE_SETTING)
}

/// Blocks the chain can plausibly have grown by between two instants.
fn plausible_growth(from_seconds: i64, now: Timestamp) -> u64 {
    let elapsed = u64::try_from(now.as_second().saturating_sub(from_seconds)).unwrap_or(0);
    (elapsed / BLOCK_TIME_SECONDS).saturating_mul(BLOCK_RATE_MARGIN)
}

/// The highest tip accepted at `now`. A device clock behind the chain never pushes the bound
/// below the stored reference plus the slack.
pub(crate) fn plausible_limit(reference: Option<ChainReference>, now: Timestamp) -> Height {
    let since_genesis = plausible_growth(GENESIS_SECONDS, now).saturating_add(TIP_SLACK_BLOCKS);
    let limit = match reference {
        None => since_genesis,
        Some(reference) => {
            let floor = reference.height.value().saturating_add(TIP_SLACK_BLOCKS);
            let relative = floor.saturating_add(plausible_growth(reference.seen_at, now));
            relative.min(since_genesis.max(floor))
        }
    };
    Height::new(limit)
}

pub(crate) fn check_tip(
    reference: Option<ChainReference>,
    tip: Height,
    now: Timestamp,
) -> Result<(), ImplausibleNodeData> {
    let limit = plausible_limit(reference, now);
    if tip > limit {
        return Err(ImplausibleNodeData::TipTooHigh { tip, limit });
    }
    Ok(())
}

pub(crate) fn check_output_height(height: Height, tip: Height) -> Result<(), ImplausibleNodeData> {
    if height > tip {
        return Err(ImplausibleNodeData::OutputAboveTip { height, tip });
    }
    Ok(())
}

pub(crate) fn check_kernel_height(
    height: Height,
    min: Height,
    tip: Height,
) -> Result<(), ImplausibleNodeData> {
    if height < min || height > tip {
        return Err(ImplausibleNodeData::KernelOutOfRange { height, min, tip });
    }
    Ok(())
}

/// A second tip agrees with the first when it is the same or a few blocks ahead.
pub(crate) fn check_agreement(first: Height, second: Height) -> Result<(), ImplausibleNodeData> {
    let agrees = second
        .value()
        .checked_sub(first.value())
        .is_some_and(|lead| lead <= TIP_AGREEMENT_BLOCKS);
    if !agrees {
        return Err(ImplausibleNodeData::TipChanged { first, second });
    }
    Ok(())
}

#[cfg(test)]
// Tests may use plain arithmetic (docs/rules.md).
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    const DAY: i64 = 86_400;

    #[test]
    fn reference_round_trips_and_rejects_malformed_text() {
        let reference = ChainReference {
            height: Height::new(14),
            seen_at: 1_790_000_000,
        };
        assert_eq!(ChainReference::decode(&reference.encode()), Some(reference));
        for text in ["", "14", "14 x", "x 1", "-1 5", "14 5 6"] {
            assert_eq!(ChainReference::decode(text), None, "{text}");
        }
    }

    #[test]
    fn without_a_reference_the_tip_is_bounded_by_the_time_since_genesis() {
        let now = at(GENESIS_SECONDS + DAY);
        let limit = 2 * 1_440 + TIP_SLACK_BLOCKS;
        assert_eq!(plausible_limit(None, now), Height::new(limit));
        assert!(check_tip(None, Height::new(limit), now).is_ok());
        assert_eq!(
            check_tip(None, Height::new(u64::MAX), now),
            Err(ImplausibleNodeData::TipTooHigh {
                tip: Height::new(u64::MAX),
                limit: Height::new(limit),
            })
        );
    }

    #[test]
    fn a_reference_bounds_the_tip_by_the_time_since_it_was_seen() {
        let seen_at = GENESIS_SECONDS + 1_000 * DAY;
        let reference = Some(ChainReference {
            height: Height::new(1_000_000),
            seen_at,
        });
        let hour_later = at(seen_at + 3_600);
        assert_eq!(
            plausible_limit(reference, hour_later),
            Height::new(1_000_000 + TIP_SLACK_BLOCKS + 120)
        );
        // A clock that went backwards leaves only the slack.
        assert_eq!(
            plausible_limit(reference, at(seen_at - DAY)),
            Height::new(1_000_000 + TIP_SLACK_BLOCKS)
        );
    }

    #[test]
    fn small_steps_cannot_climb_past_the_genesis_bound() {
        let now = at(GENESIS_SECONDS + 10 * DAY);
        let since_genesis = plausible_limit(None, now);
        let reference = Some(ChainReference {
            height: since_genesis,
            seen_at: now.as_second() - 3_600,
        });
        assert_eq!(
            plausible_limit(reference, now),
            Height::new(since_genesis.value() + TIP_SLACK_BLOCKS)
        );
    }

    #[test]
    fn heights_from_the_node_stay_at_or_below_its_tip() {
        let tip = Height::new(10);
        assert!(check_output_height(Height::new(10), tip).is_ok());
        assert!(check_output_height(Height::new(11), tip).is_err());
        assert!(check_kernel_height(Height::new(5), Height::new(5), tip).is_ok());
        assert!(check_kernel_height(Height::new(4), Height::new(5), tip).is_err());
        assert!(check_kernel_height(Height::new(11), Height::new(5), tip).is_err());
    }

    #[test]
    fn a_second_tip_agrees_when_equal_or_slightly_ahead() {
        let first = Height::new(100);
        assert!(check_agreement(first, first).is_ok());
        assert!(check_agreement(first, Height::new(100 + TIP_AGREEMENT_BLOCKS)).is_ok());
        assert!(check_agreement(first, Height::new(101 + TIP_AGREEMENT_BLOCKS)).is_err());
        assert!(check_agreement(first, Height::new(99)).is_err());
    }
}
