// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic core/src/consensus.rs, core/src/global.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Per-network chain parameters. Each wallet holds its own [`ChainParams`]; nothing here is
//! process-global (ADR 0011).

use crate::amount::{Amount, ArithmeticError, EPIC_BASE, Fee, Height, MILLI_EPIC};
use crate::ser::ProtocolVersion;

/// Block weight of one input.
pub const BLOCK_INPUT_WEIGHT: u64 = 1;

/// Block weight of one output.
pub const BLOCK_OUTPUT_WEIGHT: u64 = 21;

/// Block weight of one kernel.
pub const BLOCK_KERNEL_WEIGHT: u64 = 3;

/// Largest block weight. Mainnet and floonet share it, which is why decoders, which see no
/// network, can enforce it.
pub const MAX_BLOCK_WEIGHT: u64 = 40_000;

/// Weight a block reserves for its coinbase reward: one output and one kernel.
pub const COINBASE_WEIGHT: u64 = BLOCK_OUTPUT_WEIGHT + BLOCK_KERNEL_WEIGHT;

/// Largest weight of a transaction, which must leave room in a block for the coinbase reward.
pub const MAX_TX_WEIGHT: u64 = MAX_BLOCK_WEIGHT - COINBASE_WEIGHT;

/// The chains LEPIC can operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    pub const ALL: [Self; 2] = [Self::Mainnet, Self::Floonet];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Floonet => "floonet",
        }
    }

    pub const fn params(self) -> ChainParams {
        ChainParams::for_network(self)
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Consensus and policy values of one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    network: Network,
    coinbase_maturity: u64,
}

impl ChainParams {
    pub const fn for_network(network: Network) -> Self {
        let coinbase_maturity = match network {
            Network::Mainnet => 1_440,
            Network::Floonet => 30,
        };
        Self {
            network,
            coinbase_maturity,
        }
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    /// Blocks a coinbase output waits before it can be spent.
    pub const fn coinbase_maturity(&self) -> u64 {
        self.coinbase_maturity
    }

    /// Lock height `epic-wallet` records for a coinbase output mined at `height`.
    pub fn coinbase_lock_height(&self, height: Height) -> Result<Height, ArithmeticError> {
        height.checked_add_blocks(self.coinbase_maturity)
    }

    pub const fn max_block_weight(&self) -> u64 {
        MAX_BLOCK_WEIGHT
    }

    pub const fn max_tx_weight(&self) -> u64 {
        MAX_TX_WEIGHT
    }

    /// The protocol version the node uses for its own storage and peers.
    pub const fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::V2
    }

    /// Fee per unit of transaction weight that `epic-wallet` uses unless configured otherwise.
    pub const fn default_base_fee(&self) -> Fee {
        Fee::new(MILLI_EPIC)
    }

    /// Everything a block at `height` creates: the miner's reward plus the foundation levy.
    pub fn block_total_reward(&self, height: Height) -> Amount {
        let height = height.value();
        let epics: u64 = match self.network {
            Network::Floonet if height <= FLOONET_BLOCK_ERA_1 => 16,
            Network::Floonet => 8,
            Network::Mainnet if height <= BLOCK_ERA_1 => 16,
            Network::Mainnet if height <= BLOCK_ERA_2 => 8,
            Network::Mainnet if height <= BLOCK_ERA_3 => 4,
            Network::Mainnet if height <= BLOCK_ERA_4 => 2,
            Network::Mainnet if height <= BLOCK_ERA_5 => 1,
            Network::Mainnet => {
                // Halved every era of `BLOCK_ERA_6_ONWARDS` blocks. Upstream shifts without a
                // check, which overflows some 250 years after era 5; the reward is zero there.
                let halvings = height
                    .saturating_sub(BLOCK_ERA_5 + 1)
                    .checked_div(BLOCK_ERA_6_ONWARDS)
                    .unwrap_or(0);
                let reward = u32::try_from(halvings)
                    .ok()
                    .and_then(|halvings| 1u64.checked_shl(halvings))
                    .and_then(|divisor| BASE_REWARD_ERA_6_ONWARDS.checked_div(divisor))
                    .unwrap_or(0);
                return Amount::new(reward);
            }
        };
        Amount::new(epics.saturating_mul(EPIC_BASE))
    }

    /// The share of the block total at `height` that goes to the foundation output the node
    /// adds itself. Zero at genesis and from the ninth levy era on.
    pub fn foundation_levy(&self, height: Height) -> Amount {
        let index = match height.value() {
            0 => return Amount::ZERO,
            height if height <= FOUNDATION_LEVY_ERA_1 => 0,
            height => height
                .saturating_sub(FOUNDATION_LEVY_ERA_1 + 1)
                .checked_div(FOUNDATION_LEVY_ERA_2_ONWARDS)
                .unwrap_or(0)
                .saturating_add(1),
        };
        let Some(&levy) = usize::try_from(index)
            .ok()
            .and_then(|index| FOUNDATION_LEVY.get(index))
        else {
            return Amount::ZERO;
        };
        // At most 16 EPIC times 888, far inside u64.
        let levy = self
            .block_total_reward(height)
            .value()
            .saturating_mul(levy)
            .checked_div(FOUNDATION_LEVY_RATIO)
            .unwrap_or(0);
        Amount::new(levy)
    }

    /// The miner's reward at `height`, without fees: upstream `reward_at_height`.
    pub fn mining_reward(&self, height: Height) -> Amount {
        let total = self.block_total_reward(height).value();
        Amount::new(total.saturating_sub(self.foundation_levy(height).value()))
    }

    /// The value of the coinbase output of a block at `height` whose transactions pay `fees`:
    /// upstream `reward`, which saturates.
    pub fn coinbase_value(&self, fees: Fee, height: Height) -> Amount {
        Amount::new(
            self.mining_reward(height)
                .value()
                .saturating_add(fees.value()),
        )
    }
}

/// Blocks in a day at the target block time of one minute.
const DAY_HEIGHT: u64 = 1_440;

/// Last heights of mainnet's first five emission eras.
const BLOCK_ERA_1: u64 = DAY_HEIGHT * 334;
const BLOCK_ERA_2: u64 = BLOCK_ERA_1 + DAY_HEIGHT * 470;
const BLOCK_ERA_3: u64 = BLOCK_ERA_2 + DAY_HEIGHT * 601;
const BLOCK_ERA_4: u64 = BLOCK_ERA_3 + DAY_HEIGHT * 800;
const BLOCK_ERA_5: u64 = BLOCK_ERA_4 + DAY_HEIGHT * 1_019;

/// Length of each mainnet era after the fifth.
const BLOCK_ERA_6_ONWARDS: u64 = DAY_HEIGHT * 1_460;

/// The block total of era 6, 0.15625 EPIC.
const BASE_REWARD_ERA_6_ONWARDS: u64 = 15_625_000;

/// Last height of floonet's first emission era.
const FLOONET_BLOCK_ERA_1: u64 = DAY_HEIGHT * 334;

const FOUNDATION_LEVY_ERA_1: u64 = DAY_HEIGHT * 120;
const FOUNDATION_LEVY_ERA_2_ONWARDS: u64 = DAY_HEIGHT * 365;
const FOUNDATION_LEVY_RATIO: u64 = 10_000;
const FOUNDATION_LEVY: [u64; 9] = [888, 777, 666, 555, 444, 333, 222, 111, 111];
