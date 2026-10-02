//! Per-network chain parameters. Each wallet holds its own [`ChainParams`]; nothing here is
//! process-global (ADR 0011).

use crate::amount::{ArithmeticError, Fee, Height, MILLI_EPIC};
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
}
