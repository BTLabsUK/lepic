// SPDX-License-Identifier: Apache-2.0
//! The epic1 address (RFC 0003 §5.13, Appendix B.1): bech32m, human-readable part `epic`
//! (mainnet) or `tepic` (floonet), 65 data bytes: version `01`, the Ed25519 proof key and the
//! X25519 seal key. Nothing else is in the address.

use std::fmt;

use lepic_contact::{EncPublicKey, KeyError, VerifyingKey, verifying_key};
use lepic_epicbox::Network;
use thiserror::Error;

use crate::bech32m::{self, Bech32Error};

/// Address layout version this crate reads and writes.
pub const VERSION: u8 = 0x01;
/// Data bytes: version, proof key, seal key.
pub const DATA_LEN: usize = 65;
/// Characters of a mainnet epic1; a floonet one has one more.
pub const MAINNET_TEXT_LEN: usize = 115;

const KEY_LEN: usize = 32;

/// The human-readable part of `network`.
pub fn hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "epic",
        Network::Floonet => "tepic",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Epic1Error {
    #[error("not a bech32m string: {0}")]
    Bech32(#[source] Bech32Error),
    #[error("address is not a {expected:?} epic1")]
    WrongNetwork { expected: Network },
    #[error("address prefix is not epic or tepic")]
    UnknownPrefix,
    #[error("address data has {actual} bytes, expected 65")]
    Length { actual: usize },
    #[error("address version {version:#04x} is not defined")]
    Version { version: u8 },
    #[error("proof key is not a canonical Ed25519 point of large order")]
    ProofKey(#[source] KeyError),
    #[error("seal key is of small order")]
    SealKey(#[source] KeyError),
}

/// An epic1: who is paid (the proof key) and what to seal to (the seal key), on one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epic1Address {
    network: Network,
    proof_key: VerifyingKey,
    seal_key: EncPublicKey,
}

impl Epic1Address {
    /// An address from keys already checked by their own types.
    pub fn new(network: Network, proof_key: VerifyingKey, seal_key: EncPublicKey) -> Self {
        Self {
            network,
            proof_key,
            seal_key,
        }
    }

    /// An address from raw key bytes, checked as a decoder checks them.
    pub fn from_key_bytes(
        network: Network,
        proof_key: &[u8; KEY_LEN],
        seal_key: [u8; KEY_LEN],
    ) -> Result<Self, Epic1Error> {
        Ok(Self {
            network,
            proof_key: verifying_key(proof_key).map_err(Epic1Error::ProofKey)?,
            seal_key: EncPublicKey::from_bytes(seal_key).map_err(Epic1Error::SealKey)?,
        })
    }

    /// Reads an epic1 of `expected` network: lower case, checksum, prefix, length, version
    /// `01` and both keys are checked, in that order.
    pub fn decode(text: &str, expected: Network) -> Result<Self, Epic1Error> {
        let (prefix, data) = bech32m::decode(text).map_err(Epic1Error::Bech32)?;
        if prefix != hrp(expected) {
            return Err(if prefix == hrp(other(expected)) {
                Epic1Error::WrongNetwork { expected }
            } else {
                Epic1Error::UnknownPrefix
            });
        }
        let (version, rest) = data
            .split_first()
            .filter(|_| data.len() == DATA_LEN)
            .ok_or(Epic1Error::Length { actual: data.len() })?;
        if *version != VERSION {
            return Err(Epic1Error::Version { version: *version });
        }
        let (proof_key, seal_key) = rest
            .split_first_chunk::<KEY_LEN>()
            .and_then(|(proof, seal)| Some((proof, <&[u8; KEY_LEN]>::try_from(seal).ok()?)))
            .ok_or(Epic1Error::Length { actual: data.len() })?;
        Self::from_key_bytes(expected, proof_key, *seal_key)
    }

    /// Reads an epic1 of either network, and says which.
    pub fn decode_any(text: &str) -> Result<Self, Epic1Error> {
        match Self::decode(text, Network::Mainnet) {
            Err(Epic1Error::WrongNetwork { .. }) => Self::decode(text, Network::Floonet),
            other => other,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn proof_key(&self) -> &VerifyingKey {
        &self.proof_key
    }

    pub fn seal_key(&self) -> &EncPublicKey {
        &self.seal_key
    }

    /// The 65 data bytes.
    pub fn data(&self) -> [u8; DATA_LEN] {
        let mut data = [0u8; DATA_LEN];
        let bytes = std::iter::once(&VERSION)
            .chain(self.proof_key.as_bytes())
            .chain(self.seal_key.as_bytes());
        for (slot, byte) in data.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        data
    }

    /// The address as text: 115 characters (`epic1…`) or 116 (`tepic1…`).
    pub fn encode(&self) -> String {
        // The prefix is a constant and the data length is fixed, far below the limit.
        bech32m::encode(hrp(self.network), &self.data()).unwrap_or_default()
    }
}

impl fmt::Display for Epic1Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

fn other(network: Network) -> Network {
    match network {
        Network::Mainnet => Network::Floonet,
        Network::Floonet => Network::Mainnet,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use lepic_contact::EncSecretKey;

    use super::*;

    pub(crate) fn sample(network: Network) -> Epic1Address {
        let proof = lepic_contact::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let seal = EncSecretKey::from_bytes([9; 32]).public_key();
        Epic1Address::new(network, proof, seal)
    }

    fn with_data(prefix: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut data = sample(Network::Mainnet).data().to_vec();
        edit(&mut data);
        bech32m::encode(prefix, &data).unwrap()
    }

    #[test]
    fn round_trips_on_both_networks_with_the_stated_lengths() {
        for (network, length) in [(Network::Mainnet, 115), (Network::Floonet, 116)] {
            let address = sample(network);
            let text = address.encode();
            assert_eq!(text.len(), length);
            assert!(text.starts_with(&format!("{}1", hrp(network))));
            assert_eq!(Epic1Address::decode(&text, network), Ok(address));
            assert_eq!(Epic1Address::decode_any(&text), Ok(address));
        }
    }

    #[test]
    fn refuses_the_other_networks_prefix() {
        let mainnet = sample(Network::Mainnet).encode();
        let floonet = sample(Network::Floonet).encode();
        assert_eq!(
            Epic1Address::decode(&mainnet, Network::Floonet),
            Err(Epic1Error::WrongNetwork {
                expected: Network::Floonet
            })
        );
        assert_eq!(
            Epic1Address::decode(&floonet, Network::Mainnet),
            Err(Epic1Error::WrongNetwork {
                expected: Network::Mainnet
            })
        );
        assert_eq!(
            Epic1Address::decode(&with_data("btc", |_| {}), Network::Mainnet),
            Err(Epic1Error::UnknownPrefix)
        );
    }

    #[test]
    fn refuses_mixed_case_and_a_bad_checksum() {
        let text = sample(Network::Mainnet).encode();
        let mixed = format!("EPIC{}", &text[4..]);
        assert_eq!(
            Epic1Address::decode(&mixed, Network::Mainnet),
            Err(Epic1Error::Bech32(Bech32Error::MixedCase))
        );
        let mut broken = text.into_bytes();
        let last = broken.len() - 1;
        broken[last] = if broken[last] == b'q' { b'p' } else { b'q' };
        assert_eq!(
            Epic1Address::decode(&String::from_utf8(broken).unwrap(), Network::Mainnet),
            Err(Epic1Error::Bech32(Bech32Error::Checksum))
        );
    }

    #[test]
    fn refuses_wrong_lengths_and_versions() {
        for length in [0, 1, 64, 66, 97] {
            let text = with_data("epic", |data| data.resize(length, 1));
            assert_eq!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::Length { actual: length })
            );
        }
        for version in [0x00, 0x02, 0xff] {
            let text = with_data("epic", |data| data[0] = version);
            assert_eq!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::Version { version })
            );
        }
    }

    #[test]
    fn refuses_a_weak_or_undecodable_proof_key() {
        // The identity point, the point of order 2, and a y that is no curve point.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut order_two = [0xff; 32];
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        for key in [identity, order_two, [0u8; 32], off_curve] {
            let text = with_data("epic", |data| data[1..33].copy_from_slice(&key));
            assert!(
                matches!(
                    Epic1Address::decode(&text, Network::Mainnet),
                    Err(Epic1Error::ProofKey(_))
                ),
                "{key:02x?}"
            );
        }
    }

    #[test]
    fn refuses_a_small_order_seal_key() {
        for key in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            let text = with_data("epic", |data| data[33..65].copy_from_slice(&key));
            assert!(matches!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::SealKey(_))
            ));
        }
    }
}
