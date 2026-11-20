// SPDX-License-Identifier: Apache-2.0
//! Keys area: mnemonics, BIP32 derivation, commitments, switch commitments, range proofs from both
//! proof builders and their rewinds, Epicbox address keys, payment-proof keys and the encrypted
//! `wallet.seed` file, all computed by the reference node and wallet code.
//!
//! Every case is deterministic except the seed file, whose salt and nonce upstream draws itself.

mod address;
mod commitments;
mod derivation;
mod epic1;
mod mnemonic;
mod namespace;
mod pairing_keys;
mod proofs;
mod seed_file;

use epic_keychain::{ExtKeychain, ExtKeychainPath, Identifier, Keychain, SwitchCommitmentType};
use serde::Serialize;

use crate::{Error, Pins, Rendered, Upstream, git_source};

const AREA: &str = "keys";

// Fixed test-only seeds. Never real wallet material.
const SEED_32: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SEED_16: [u8; 16] = [
    0xa5, 0x5a, 0xc3, 0x3c, 0x96, 0x69, 0xf0, 0x0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
];

/// A named test seed. The name is part of the vector file names.
struct Seed {
    name: &'static str,
    entropy: &'static [u8],
}

const SEEDS: [Seed; 2] = [
    Seed {
        name: "seed32",
        entropy: &SEED_32,
    },
    Seed {
        name: "seed16",
        entropy: &SEED_16,
    },
];

const HARDENED: u32 = 0x8000_0000;

/// Amounts at the edges and in the usual range: zero, one base unit, one milli-epic, one epic, the
/// total supply order of magnitude and the largest `u64`.
const AMOUNTS: [u64; 6] = [0, 1, 100_000, 100_000_000, 2_100_000_000_000_000, u64::MAX];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    const ALL: [Network; 2] = [Network::Mainnet, Network::Floonet];

    fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Floonet => "floonet",
        }
    }

    fn is_floonet(self) -> bool {
        self == Network::Floonet
    }
}

/// A key path as upstream stores it in an `Identifier`: a depth and four components. Components
/// with the top bit set are hardened.
#[derive(Clone, Copy, Serialize)]
struct KeyPath {
    depth: u8,
    components: [u32; 4],
}

impl KeyPath {
    const fn new(depth: u8, components: [u32; 4]) -> KeyPath {
        KeyPath { depth, components }
    }

    fn identifier(self) -> Identifier {
        let [d0, d1, d2, d3] = self.components;
        ExtKeychainPath::new(self.depth, d0, d1, d2, d3).to_identifier()
    }
}

fn switch_name(switch: SwitchCommitmentType) -> &'static str {
    match switch {
        SwitchCommitmentType::None => "none",
        SwitchCommitmentType::Regular => "regular",
    }
}

fn keychain(seed: &[u8], network: Network) -> Result<ExtKeychain, Error> {
    ExtKeychain::from_seed(seed, network.is_floonet())
        .map_err(Error::reference("keychain from seed"))
}

/// The two upstream repositories this area draws from. Key, commitment and proof code is in the
/// node; mnemonic handling as the wallet uses it, addresses and payment-proof keys are in the wallet.
struct KeysPins<'a> {
    node: &'a Upstream,
    wallet: Upstream,
}

/// Raised when the reference code disagrees with itself, for example when two upstream paths
/// that must give the same key do not. A vector is never written from such a run.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Inconsistent(&'static str);

fn ensure(condition: bool, what: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::reference("self-consistency check")(Inconsistent(
            what,
        )))
    }
}

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    let pins = KeysPins {
        node: &pins.node,
        wallet: git_source(crate::LOCKFILE, "epic_wallet_libwallet")?,
    };
    let mut vectors = Vec::new();
    vectors.extend(mnemonic::generate(&pins)?);
    vectors.extend(derivation::generate(&pins)?);
    vectors.extend(commitments::generate(&pins)?);
    vectors.extend(proofs::generate(&pins)?);
    vectors.extend(address::generate(&pins)?);
    vectors.extend(epic1::generate(&pins)?);
    vectors.extend(seed_file::generate(&pins)?);
    vectors.extend(namespace::generate(&pins)?);
    vectors.extend(pairing_keys::generate(&pins)?);
    Ok(vectors)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{DEFAULT_OUT, LOCKFILE};

    #[test]
    fn regenerated_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        for vector in generate(&pins)? {
            let path = Path::new(DEFAULT_OUT)
                .join(AREA)
                .join(format!("{}.json", vector.name));
            assert_eq!(std::fs::read(&path)?, vector.bytes, "{}", path.display());
        }
        Ok(())
    }

    #[test]
    fn generation_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        let first = generate(&pins)?;
        let second = generate(&pins)?;
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(&second) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.bytes, b.bytes, "{}", a.name);
        }
        Ok(())
    }
}
