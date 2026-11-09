// SPDX-License-Identifier: Apache-2.0
//! Native slates over Epicbox (RFC 0003 11.1): what the payments address claims in its marker,
//! and the seal key its native slates open with.
//!
//! With [`crate::WalletConfig::native_direct`] on, every marked slate this wallet sends over
//! Epicbox claims [`NATIVE_SLATES`] and carries, in the marker's `reply`, the public key of the
//! payments address's seal key of kind 03 ([`SealKeyKind::Epicbox`]). That key is not the
//! epic1's (kind 00), so the payments address and the epic1 address are not linkable. With it
//! off, the marker is what it was before.

use lepic_contact::EncSecretKey;
use lepic_keychain::Seed;
use lepic_primitives::params::Network;
use lepic_transport::marker::features::NATIVE_SLATES;
use lepic_transport::method::Sending;
use tracing::warn;

use crate::config::WalletConfig;
use crate::error::WalletError;
use crate::namespace::{self, SealKeyKind};

/// The account whose address is the payments address.
const PAYMENTS_ACCOUNT: u32 = 0;

/// What the marker of a slate this wallet sends over Epicbox claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Claim {
    /// The feature bits of the marker's `f`.
    pub(crate) features: u32,
    /// The public seal key of the marker's `reply`, when the wallet takes native slates there.
    pub(crate) seal_key: Option<[u8; 32]>,
}

impl Claim {
    /// A claim of `features` alone, the marker of a wallet that takes no native slates over
    /// Epicbox.
    pub(crate) const fn plain(features: u32) -> Self {
        Self {
            features,
            seal_key: None,
        }
    }

    /// The claim of the wallet of `seed` under `config`. A seal key that does not derive is
    /// logged and the wallet claims no native slates.
    pub(crate) fn of(config: &WalletConfig, seed: &Seed) -> Self {
        let features = config.claimed_features();
        if !config.native_direct {
            return Self::plain(features);
        }
        match payments_seal_key(seed, config.network) {
            Ok(secret) => Self {
                features: features | NATIVE_SLATES,
                seal_key: Some(*secret.public_key().as_bytes()),
            },
            Err(error) => {
                warn!(%error, "no epicbox seal key, claiming no native slates");
                Self::plain(features)
            }
        }
    }

    /// What a method encoding a slate on `network` needs, with this claim.
    pub(crate) fn sending(&self, network: Network, reply_key: Option<[u8; 32]>) -> Sending {
        let sending = Sending::new(network, self.features, reply_key);
        match self.seal_key {
            Some(key) => sending.with_seal_key(key),
            None => sending,
        }
    }
}

/// The seal key of kind 03 of the payments address on `network`: native slates sent to it over
/// Epicbox open with it.
pub(crate) fn payments_seal_key(
    seed: &Seed,
    network: Network,
) -> Result<EncSecretKey, WalletError> {
    namespace::seal_key(
        seed,
        PAYMENTS_ACCOUNT,
        contact_network(network),
        SealKeyKind::Epicbox,
    )
}

/// The network of the seal layer for `network`.
pub(crate) const fn contact_network(network: Network) -> lepic_contact::Network {
    match network {
        Network::Mainnet => lepic_contact::Network::Mainnet,
        Network::Floonet => lepic_contact::Network::Floonet,
    }
}
