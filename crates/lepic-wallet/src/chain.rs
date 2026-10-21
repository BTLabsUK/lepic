//! How far the wallet knows the chain has come, and the checks a node's tip, heights and
//! indices pass before the engine acts on them.
//!
//! A node's tip decides which transactions expire, which slates are refused as expired and
//! where the next scan starts, so a tip far above anything the chain can have reached is
//! refused. A tip must stay below two bounds. One grows from a checkpoint of the network, a
//! height the chain had reached at a known time; the other from the first tip the wallet
//! confirmed. Both grow at the target block rate plus a small margin, and neither moves with
//! later tips, so a tip that is refused once cannot be reached by many small steps.
//!
//! One node answer moves the confirmed position only a few blocks. A tip further ahead is held
//! as pending and confirmed only by a later answer at or above it, so a single wrong answer
//! cannot leave the wallet waiting for the chain to catch up with it.

use std::sync::Arc;

use jiff::Timestamp;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_primitives::params::{BLOCK_OUTPUT_WEIGHT, MAX_BLOCK_WEIGHT, Network};
use lepic_store::{Repositories, StoreError, WalletStore};
use thiserror::Error;
use tracing::{debug, instrument, warn};

use crate::error::WalletError;
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// Epic's target block interval, `BLOCK_TIME_SEC` in the node's consensus rules.
pub const BLOCK_TIME_SECONDS: u64 = 60;

/// The bounds grow by one block per target interval and one more per this many, for a chain
/// that runs slightly fast for a long time.
const BLOCK_RATE_MARGIN_DIVISOR: u64 = 16;

/// Blocks a tip may lead the time-based bounds by, for bursts of fast blocks after a rise in
/// hash rate: a day of blocks.
pub const TIP_SLACK_BLOCKS: u64 = 1_440;

/// Blocks one node answer may move the confirmed position by. A tip further ahead waits for a
/// later answer that agrees.
pub const TIP_STEP_BLOCKS: u64 = 60;

/// Blocks a second tip asked for within one refresh may lead the first by.
pub const TIP_AGREEMENT_BLOCKS: u64 = 3;

/// Blocks a peer's slate height may lead this wallet's tip by, for a peer whose node has seen
/// a few blocks more. A slate further ahead is refused.
pub const SLATE_LEAD_BLOCKS: u64 = 10;

/// Timestamp of the mainnet and floonet genesis blocks of Epic node v4.0.4, 2019-08-09
/// 17:04:38 UTC.
const GENESIS_SECONDS: i64 = 1_565_370_278;

/// A mainnet tip read from the public explorer, and a time at or before which it was read. The
/// chain had not passed this height at that time.
///
/// Move it forward when a release is prepared: read the tip from a node's `get_tip` or a public
/// explorer, and record it with a time at or before the reading. The bound stays safe only while
/// the chain had not passed the height at the recorded time; a newer checkpoint makes it tighter.
const MAINNET_CHECKPOINT: ChainReference = ChainReference {
    height: Height::new(3_737_173),
    seen_at: 1_791_011_820,
};

/// No floonet checkpoint is recorded, so floonet is bounded from its genesis block.
const FLOONET_CHECKPOINT: ChainReference = ChainReference {
    height: Height::ZERO,
    seen_at: GENESIS_SECONDS,
};

/// Output MMR positions one block can add at most: two per output, for the leaf and at most
/// one parent, with every block filled with outputs.
const MAX_MMR_POSITIONS_PER_BLOCK: u64 = 2 * (MAX_BLOCK_WEIGHT / BLOCK_OUTPUT_WEIGHT + 1);

/// The first tip the wallet confirmed, which the relative bound grows from.
const FIRST_SETTING: &str = "chain.first";
/// The highest confirmed tip. Databases written before the first tip was kept apart store only
/// this one, and it then stands in for the first.
const CONFIRMED_SETTING: &str = "chain.reference";
/// A tip seen once that is too far ahead of the confirmed one to be confirmed by itself.
const PENDING_SETTING: &str = "chain.pending";

/// Node data the wallet refuses to act on. Nothing derived from the answer is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ImplausibleNodeData {
    /// The limit grows with the device clock, so a clock set far behind the real time (for
    /// example after a battery reset) also gives this error until the clock is right.
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
    /// The output MMR cannot have grown this large in the blocks up to the tip.
    #[error("node reported output index {index} above the highest possible {limit} at its tip")]
    IndexAboveTip { index: u64, limit: u64 },
}

/// A tip the wallet confirmed, and when it saw it, for starting a node client from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedTip {
    pub height: Height,
    pub seen_at: Timestamp,
}

/// A tip and when it was seen, in seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainReference {
    height: Height,
    seen_at: i64,
}

impl ChainReference {
    fn new(height: Height, now: Timestamp) -> Self {
        Self {
            height,
            seen_at: now.as_second(),
        }
    }

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

    /// The highest tip plausible at `now` for a chain that was at `self.height` then.
    fn bound(self, now: Timestamp) -> u64 {
        self.height
            .value()
            .saturating_add(TIP_SLACK_BLOCKS)
            .saturating_add(plausible_growth(self.seen_at, now))
    }
}

/// What the wallet stored about the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ChainPosition {
    first: Option<ChainReference>,
    confirmed: Option<ChainReference>,
    pending: Option<ChainReference>,
}

impl ChainPosition {
    fn first(&self) -> Option<ChainReference> {
        self.first.or(self.confirmed)
    }

    /// The height of the highest confirmed tip.
    pub(crate) fn confirmed_height(&self) -> Option<Height> {
        self.confirmed.map(|reference| reference.height)
    }
}

/// A stored reference that does not parse is ignored; the checkpoint bound still applies.
pub(crate) fn position(repos: &dyn Repositories) -> Result<ChainPosition, StoreError> {
    Ok(ChainPosition {
        first: stored_reference(repos, FIRST_SETTING)?,
        confirmed: stored_reference(repos, CONFIRMED_SETTING)?,
        pending: stored_reference(repos, PENDING_SETTING)?,
    })
}

fn stored_reference(
    repos: &dyn Repositories,
    name: &str,
) -> Result<Option<ChainReference>, StoreError> {
    Ok(match repos.setting(name)? {
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

/// Stores what a refresh or scan that applied learnt from `tip`, which passed [`check_tip`].
///
/// A pending tip is confirmed when `tip` is at or above it and plausible from it. `tip` is
/// confirmed itself when it is at most [`TIP_STEP_BLOCKS`] above the highest confirmed height,
/// counting `last_confirmed`; otherwise it becomes the pending tip. Returns the confirmed
/// height when this answer raised it.
pub(crate) fn observe_tip(
    repos: &mut dyn Repositories,
    last_confirmed: Option<Height>,
    tip: Height,
    now: Timestamp,
) -> Result<Option<Height>, StoreError> {
    let stored = position(repos)?;
    let agreed = stored
        .pending
        .filter(|pending| pending.height <= tip && tip.value() <= agreement_bound(*pending, now));
    let base = [
        agreed.map(|reference| reference.height),
        stored.confirmed.map(|reference| reference.height),
        last_confirmed,
    ]
    .into_iter()
    .flatten()
    .max();
    let stepped = base
        .filter(|base| *base <= tip && tip.value() <= base.value().saturating_add(TIP_STEP_BLOCKS))
        .map(|_| ChainReference::new(tip, now));
    let newly = stepped.or(agreed).filter(|reference| {
        stored
            .confirmed
            .is_none_or(|confirmed| reference.height > confirmed.height)
    });
    if let Some(reference) = newly {
        repos.put_setting(CONFIRMED_SETTING, &reference.encode())?;
        if stored.first.is_none() {
            let first = stored.first().unwrap_or(reference);
            repos.put_setting(FIRST_SETTING, &first.encode())?;
        }
    }
    if stepped.is_some() || base.is_some_and(|base| tip <= base) {
        if stored.pending.is_some() {
            repos.delete_setting(PENDING_SETTING)?;
        }
    } else {
        debug!(height = %tip, "tip held until a later answer agrees");
        repos.put_setting(PENDING_SETTING, &ChainReference::new(tip, now).encode())?;
    }
    Ok(newly.map(|reference| reference.height))
}

/// A later tip agrees with a pending one when it is no further ahead than the time between the
/// two allows.
fn agreement_bound(pending: ChainReference, now: Timestamp) -> u64 {
    pending
        .height
        .value()
        .saturating_add(TIP_STEP_BLOCKS)
        .saturating_add(plausible_growth(pending.seen_at, now))
}

pub(crate) fn forget(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    repos.delete_setting(FIRST_SETTING)?;
    repos.delete_setting(CONFIRMED_SETTING)?;
    repos.delete_setting(PENDING_SETTING)
}

/// Blocks the chain can plausibly have grown by between two instants.
fn plausible_growth(from_seconds: i64, now: Timestamp) -> u64 {
    let elapsed = u64::try_from(now.as_second().saturating_sub(from_seconds)).unwrap_or(0);
    let blocks = elapsed / BLOCK_TIME_SECONDS;
    blocks.saturating_add(blocks / BLOCK_RATE_MARGIN_DIVISOR)
}

const fn checkpoint(network: Network) -> ChainReference {
    match network {
        Network::Mainnet => MAINNET_CHECKPOINT,
        Network::Floonet => FLOONET_CHECKPOINT,
    }
}

/// The highest tip accepted at `now`: the lower of the bound from the network's checkpoint and
/// the bound from the first confirmed tip. Nothing confirmed later raises it.
pub(crate) fn plausible_limit(
    network: Network,
    position: &ChainPosition,
    now: Timestamp,
) -> Height {
    let absolute = checkpoint(network).bound(now);
    let limit = position
        .first()
        .map_or(absolute, |first| first.bound(now).min(absolute));
    Height::new(limit)
}

pub(crate) fn check_tip(
    network: Network,
    position: &ChainPosition,
    tip: Height,
    now: Timestamp,
) -> Result<(), ImplausibleNodeData> {
    let limit = plausible_limit(network, position, now);
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

/// Whether a peer's slate height is at most [`SLATE_LEAD_BLOCKS`] above `tip`.
pub(crate) fn slate_height_near(height: Height, tip: Height) -> bool {
    height.value() <= tip.value().saturating_add(SLATE_LEAD_BLOCKS)
}

/// The lowest height to look a kernel up from, for a slate created at `slate_height`, when
/// looking up to `tip`. A slate height can come from the peer, which may be ahead of this
/// wallet by [`SLATE_LEAD_BLOCKS`] or report a height the chain has not reached, so the lookup
/// starts that many blocks lower and never above the tip. A node answers a lookup from above
/// its tip, or from height zero, with an error rather than with no kernel, so the floor is
/// kept between one and the tip.
pub(crate) fn kernel_floor(slate_height: Height, tip: Height) -> Height {
    let lowered = slate_height
        .checked_sub_blocks(SLATE_LEAD_BLOCKS)
        .unwrap_or(Height::ZERO);
    lowered.min(tip).max(Height::new(1))
}

/// An output MMR index is at most the positions every block up to and including the tip can
/// have added.
pub(crate) fn check_output_index(index: u64, tip: Height) -> Result<(), ImplausibleNodeData> {
    let limit = tip
        .value()
        .saturating_add(1)
        .saturating_mul(MAX_MMR_POSITIONS_PER_BLOCK);
    if index > limit {
        return Err(ImplausibleNodeData::IndexAboveTip { index, limit });
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

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The highest tip the wallet confirmed, or `None` before the first one. A host starts its
    /// node client from it, so the client bounds the first tip it sees in a session. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn confirmed_tip(&self) -> Result<Option<ConfirmedTip>, WalletError> {
        let session = self.session()?;
        let stored = session
            .store
            .read(|repos| Ok::<_, WalletError>(position(repos)?))?;
        Ok(stored.confirmed.and_then(|reference| {
            Some(ConfirmedTip {
                height: reference.height,
                seen_at: Timestamp::from_second(reference.seen_at).ok()?,
            })
        }))
    }

    /// Refuses a tip a stage is about to act on when it is not plausible for what the wallet
    /// stored, with [`WalletError::Implausible`].
    pub(crate) async fn check_plausible_tip(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: Height,
    ) -> Result<(), WalletError> {
        let session = Arc::clone(session);
        self.blocking(move |ports, config| {
            let stored = session
                .store
                .read(|repos| Ok::<_, WalletError>(position(repos)?))?;
            check_tip(config.network, &stored, tip, ports.clock.now())?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
// Tests may use plain arithmetic (docs/rules.md).
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use lepic_store::{CONTEXT_KEY_LEN, ContextKey, MemoryStore, WalletStore};

    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    const DAY: i64 = 86_400;
    const HOUR: i64 = 3_600;

    fn reference(height: u64, seen_at: i64) -> ChainReference {
        ChainReference {
            height: Height::new(height),
            seen_at,
        }
    }

    fn store() -> MemoryStore {
        MemoryStore::new(ContextKey::from_bytes([1; CONTEXT_KEY_LEN]))
    }

    fn observe(store: &MemoryStore, last: Option<u64>, tip: u64, now: i64) -> Option<Height> {
        store
            .write(|repos| observe_tip(repos, last.map(Height::new), Height::new(tip), at(now)))
            .unwrap()
    }

    fn stored(store: &MemoryStore) -> ChainPosition {
        store.read(|repos| position(repos)).unwrap()
    }

    #[test]
    fn reference_round_trips_and_rejects_malformed_text() {
        let reference = reference(14, 1_790_000_000);
        assert_eq!(ChainReference::decode(&reference.encode()), Some(reference));
        for text in ["", "14", "14 x", "x 1", "-1 5", "14 5 6"] {
            assert_eq!(ChainReference::decode(text), None, "{text}");
        }
    }

    #[test]
    fn without_a_reference_the_tip_is_bounded_from_the_network_checkpoint() {
        let now = at(MAINNET_CHECKPOINT.seen_at + DAY);
        let limit = MAINNET_CHECKPOINT.height.value() + TIP_SLACK_BLOCKS + 1_440 + 90;
        let none = ChainPosition::default();
        assert_eq!(
            plausible_limit(Network::Mainnet, &none, now),
            Height::new(limit)
        );
        assert!(check_tip(Network::Mainnet, &none, Height::new(limit), now).is_ok());
        assert_eq!(
            check_tip(Network::Mainnet, &none, Height::new(limit + 1), now),
            Err(ImplausibleNodeData::TipTooHigh {
                tip: Height::new(limit + 1),
                limit: Height::new(limit),
            })
        );
    }

    #[test]
    fn the_checkpoint_bound_grows_at_the_block_rate_plus_the_margin() {
        let none = ChainPosition::default();
        let at_checkpoint = at(MAINNET_CHECKPOINT.seen_at);
        assert_eq!(
            plausible_limit(Network::Mainnet, &none, at_checkpoint).value(),
            MAINNET_CHECKPOINT.height.value() + TIP_SLACK_BLOCKS
        );
        let year_later = at(MAINNET_CHECKPOINT.seen_at + 365 * DAY);
        assert_eq!(
            plausible_limit(Network::Mainnet, &none, year_later).value(),
            MAINNET_CHECKPOINT.height.value() + TIP_SLACK_BLOCKS + 525_600 + 32_850
        );
    }

    #[test]
    fn floonet_is_bounded_from_its_genesis_block() {
        let now = at(GENESIS_SECONDS + DAY);
        assert_eq!(
            plausible_limit(Network::Floonet, &ChainPosition::default(), now),
            Height::new(TIP_SLACK_BLOCKS + 1_440 + 90)
        );
    }

    #[test]
    fn the_bound_grows_from_the_first_confirmed_tip_not_the_latest() {
        let seen_at = MAINNET_CHECKPOINT.seen_at - 30 * DAY;
        let first = reference(3_000_000, seen_at);
        let position = ChainPosition {
            first: Some(first),
            confirmed: Some(reference(3_000_000 + 1_440, seen_at + DAY)),
            pending: None,
        };
        let now = at(seen_at + DAY + HOUR);
        // From the first tip: a day and an hour of blocks plus the margin and the slack.
        let from_first = 3_000_000 + TIP_SLACK_BLOCKS + 1_500 + 93;
        assert_eq!(
            plausible_limit(Network::Mainnet, &position, now),
            Height::new(from_first)
        );
    }

    #[test]
    fn a_database_with_only_a_confirmed_tip_keeps_it_as_the_first() {
        let store = store();
        let now = MAINNET_CHECKPOINT.seen_at;
        let old = reference(3_000_000, now - DAY);
        store
            .write(|repos| repos.put_setting(CONFIRMED_SETTING, &old.encode()))
            .unwrap();
        observe(&store, None, 3_000_010, now);
        let position = stored(&store);
        assert_eq!(position.first, Some(old));
        assert_eq!(position.confirmed, Some(reference(3_000_010, now)));
    }

    #[test]
    fn small_steps_cannot_climb_past_the_bound_from_the_first_tip() {
        let store = store();
        let start = MAINNET_CHECKPOINT.seen_at + DAY;
        let first_height = 3_738_000;
        observe(&store, None, first_height, start);
        observe(&store, None, first_height, start + 60);
        let first = reference(first_height, start + 60);
        assert_eq!(stored(&store).first, Some(first));
        let mut tip = first_height;
        let mut now = start + 60;
        for _ in 0..1_000 {
            now += 60;
            let limit = plausible_limit(Network::Mainnet, &stored(&store), at(now)).value();
            tip = (tip + TIP_STEP_BLOCKS).min(limit);
            observe(&store, None, tip, now);
        }
        let climbed = stored(&store).confirmed.unwrap().height.value();
        assert_eq!(climbed, first.bound(at(now)));
        assert!(climbed < first_height + 2 * TIP_SLACK_BLOCKS);
    }

    #[test]
    fn a_clock_behind_the_first_tip_leaves_only_the_slack_above_it() {
        let seen_at = MAINNET_CHECKPOINT.seen_at + DAY;
        let position = ChainPosition {
            first: Some(reference(3_730_000, seen_at)),
            confirmed: Some(reference(3_730_100, seen_at + 2 * HOUR)),
            pending: None,
        };
        assert_eq!(
            plausible_limit(Network::Mainnet, &position, at(seen_at - HOUR)),
            Height::new(3_730_000 + TIP_SLACK_BLOCKS)
        );
    }

    #[test]
    fn a_first_tip_is_held_until_a_later_answer_agrees() {
        let store = store();
        let now = MAINNET_CHECKPOINT.seen_at;
        assert_eq!(observe(&store, None, 3_737_000, now), None);
        assert_eq!(stored(&store).confirmed, None);
        assert_eq!(
            observe(&store, None, 3_737_002, now + 120),
            Some(Height::new(3_737_002))
        );
        let position = stored(&store);
        assert_eq!(position.first, Some(reference(3_737_002, now + 120)));
        assert_eq!(position.pending, None);
    }

    #[test]
    fn a_tip_far_ahead_is_confirmed_only_by_a_later_agreeing_answer() {
        let store = store();
        let now = MAINNET_CHECKPOINT.seen_at;
        observe(&store, Some(100), 100, now);
        assert_eq!(observe(&store, Some(100), 100 + 500, now + 60), None);
        assert_eq!(stored(&store).pending, Some(reference(100 + 500, now + 60)));
        // A lower answer contradicts the pending tip, which is dropped.
        assert_eq!(
            observe(&store, Some(100), 101, now + 120),
            Some(Height::new(101))
        );
        assert_eq!(stored(&store).pending, None);
        observe(&store, Some(101), 101 + 500, now + 180);
        assert_eq!(
            observe(&store, Some(101), 101 + 502, now + 300),
            Some(Height::new(101 + 502))
        );
    }

    #[test]
    fn a_pending_tip_is_not_confirmed_by_an_answer_too_far_above_it() {
        let store = store();
        let now = MAINNET_CHECKPOINT.seen_at;
        observe(&store, Some(100), 100, now);
        observe(&store, Some(100), 1_000, now + 60);
        assert_eq!(observe(&store, Some(100), 5_000, now + 120), None);
        assert_eq!(stored(&store).confirmed, Some(reference(100, now)));
        assert_eq!(stored(&store).pending, Some(reference(5_000, now + 120)));
    }

    #[test]
    fn the_stored_last_confirmed_height_lets_a_close_tip_through_at_once() {
        let store = store();
        assert_eq!(
            observe(&store, Some(9), 10, MAINNET_CHECKPOINT.seen_at),
            Some(Height::new(10))
        );
    }

    #[test]
    fn forgetting_drops_every_reference() {
        let store = store();
        let now = MAINNET_CHECKPOINT.seen_at;
        observe(&store, Some(100), 100, now);
        observe(&store, Some(100), 1_000, now + 60);
        store.write(|repos| forget(repos)).unwrap();
        assert_eq!(stored(&store), ChainPosition::default());
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
    fn slate_heights_may_lead_the_tip_by_a_few_blocks() {
        let tip = Height::new(1_000);
        assert!(slate_height_near(Height::ZERO, tip));
        assert!(slate_height_near(
            Height::new(1_000 + SLATE_LEAD_BLOCKS),
            tip
        ));
        assert!(!slate_height_near(
            Height::new(1_001 + SLATE_LEAD_BLOCKS),
            tip
        ));
        assert!(slate_height_near(
            Height::new(u64::MAX),
            Height::new(u64::MAX)
        ));
    }

    #[test]
    fn kernel_floor_stays_between_one_and_the_tip() {
        let tip = Height::new(1_000);
        let lead = SLATE_LEAD_BLOCKS;
        assert_eq!(kernel_floor(Height::new(500), tip), Height::new(500 - lead));
        assert_eq!(kernel_floor(Height::new(u64::MAX), tip), tip);
        assert_eq!(kernel_floor(Height::ZERO, tip), Height::new(1));
        assert_eq!(kernel_floor(Height::new(lead), tip), Height::new(1));
    }

    #[test]
    fn output_indices_stay_within_what_the_blocks_up_to_the_tip_can_hold() {
        let tip = Height::new(9);
        let limit = 10 * MAX_MMR_POSITIONS_PER_BLOCK;
        assert!(check_output_index(limit, tip).is_ok());
        assert_eq!(
            check_output_index(limit + 1, tip),
            Err(ImplausibleNodeData::IndexAboveTip {
                index: limit + 1,
                limit
            })
        );
        assert!(check_output_index(u64::MAX, Height::new(u64::MAX)).is_ok());
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
