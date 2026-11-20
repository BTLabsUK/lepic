// SPDX-License-Identifier: Apache-2.0
//! The epic1 address (RFC 0003 §5.13, Appendix B.1): bech32m, human-readable part `epic`
//! (mainnet) or `tepic` (floonet), 66 data bytes: version `01`, the X25519 seal key and the
//! secp256k1 delivery key. Nothing else is in the address.

use std::fmt;

use lepic_contact::{EncPublicKey, KeyError};
use lepic_crypto::{CryptoError, PublicKey};
use lepic_epicbox::Network;
use thiserror::Error;

use crate::bech32m::{self, Bech32Error};

/// Address layout version this crate reads and writes.
pub const VERSION: u8 = 0x01;
/// Data bytes: version, seal key, delivery key.
pub const DATA_LEN: usize = 1 + SEAL_KEY_LEN + PublicKey::LEN;
/// Characters of a mainnet epic1; a floonet one has one more.
pub const MAINNET_TEXT_LEN: usize = 117;

const SEAL_KEY_LEN: usize = 32;

/// Data bytes of the epic1 of earlier releases (0.5 and before): no version byte. Such an
/// address is refused as [`Epic1Error::EarlierAddress`].
const EARLIER_DATA_LEN: usize = SEAL_KEY_LEN + PublicKey::LEN;

/// What the refusal of an earlier address says to use instead.
const EARLIER_TEXT: &str = "epic1 address of an older wallet version (65 data bytes, expected \
    66), which this version cannot read: use the wallet's Epicbox address (the one with an @), \
    or an epic1 address or link from an updated wallet";

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
    #[error("address data has {actual} bytes, expected {DATA_LEN}")]
    Length { actual: usize },
    /// An epic1 of 0.5 and before: 65 data bytes, no version byte. This version cannot read it.
    #[error("{EARLIER_TEXT}")]
    EarlierAddress,
    #[error("address version {version:#04x} is not defined")]
    Version { version: u8 },
    #[error("seal key is of small order")]
    SealKey(#[source] KeyError),
    #[error("delivery key is not a compressed secp256k1 point")]
    DeliveryKey(#[source] CryptoError),
}

/// An epic1: what to seal a payment to (the seal key) and the key its delivery is for (the
/// delivery key), on one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epic1Address {
    network: Network,
    seal_key: EncPublicKey,
    delivery_key: PublicKey,
}

impl Epic1Address {
    /// An address from keys already checked by their own types.
    pub fn new(network: Network, seal_key: EncPublicKey, delivery_key: PublicKey) -> Self {
        Self {
            network,
            seal_key,
            delivery_key,
        }
    }

    /// An address from raw key bytes, checked as a decoder checks them: the seal key first.
    pub fn from_key_bytes(
        network: Network,
        seal_key: [u8; SEAL_KEY_LEN],
        delivery_key: &[u8; PublicKey::LEN],
    ) -> Result<Self, Epic1Error> {
        Ok(Self {
            network,
            seal_key: EncPublicKey::from_bytes(seal_key).map_err(Epic1Error::SealKey)?,
            delivery_key: PublicKey::from_bytes(delivery_key).map_err(Epic1Error::DeliveryKey)?,
        })
    }

    /// Reads an epic1 of `expected` network: case, checksum, prefix, length, version `01` and
    /// both keys are checked, in that order. Text all in upper case reads as the same address.
    pub fn decode(text: &str, expected: Network) -> Result<Self, Epic1Error> {
        let (prefix, data) = bech32m::decode(text).map_err(Epic1Error::Bech32)?;
        if prefix != hrp(expected) {
            return Err(if prefix == hrp(other(expected)) {
                Epic1Error::WrongNetwork { expected }
            } else {
                Epic1Error::UnknownPrefix
            });
        }
        if data.len() == EARLIER_DATA_LEN {
            return Err(Epic1Error::EarlierAddress);
        }
        let (version, rest) = data
            .split_first()
            .filter(|_| data.len() == DATA_LEN)
            .ok_or(Epic1Error::Length { actual: data.len() })?;
        if *version != VERSION {
            return Err(Epic1Error::Version { version: *version });
        }
        let (seal_key, delivery_key) = rest
            .split_first_chunk::<SEAL_KEY_LEN>()
            .and_then(|(seal, delivery)| {
                Some((seal, <&[u8; PublicKey::LEN]>::try_from(delivery).ok()?))
            })
            .ok_or(Epic1Error::Length { actual: data.len() })?;
        Self::from_key_bytes(expected, *seal_key, delivery_key)
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

    pub fn seal_key(&self) -> &EncPublicKey {
        &self.seal_key
    }

    pub fn delivery_key(&self) -> &PublicKey {
        &self.delivery_key
    }

    /// The 66 data bytes.
    pub fn data(&self) -> [u8; DATA_LEN] {
        let mut data = [0u8; DATA_LEN];
        let delivery = self.delivery_key.to_bytes();
        let bytes = std::iter::once(&VERSION)
            .chain(self.seal_key.as_bytes())
            .chain(&delivery);
        for (slot, byte) in data.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        data
    }

    /// The address as text in lower case: 117 characters (`epic1…`) or 118 (`tepic1…`).
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
    use lepic_crypto::SecretKey;

    use super::*;

    pub(crate) fn sample(network: Network) -> Epic1Address {
        let seal = EncSecretKey::from_bytes([9; 32]).public_key();
        let delivery =
            PublicKey::from_secret_key(&SecretKey::from_bytes(&[7; 32]).unwrap()).unwrap();
        Epic1Address::new(network, seal, delivery)
    }

    fn with_data(prefix: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut data = sample(Network::Mainnet).data().to_vec();
        edit(&mut data);
        bech32m::encode(prefix, &data).unwrap()
    }

    #[test]
    fn round_trips_on_both_networks_with_the_stated_lengths() {
        for (network, length) in [(Network::Mainnet, 117), (Network::Floonet, 118)] {
            let address = sample(network);
            let text = address.encode();
            assert_eq!(text.len(), length);
            assert!(text.starts_with(&format!("{}1", hrp(network))));
            assert_eq!(Epic1Address::decode(&text, network), Ok(address));
            assert_eq!(Epic1Address::decode_any(&text), Ok(address));
        }
        assert_eq!(sample(Network::Mainnet).encode().len(), MAINNET_TEXT_LEN);
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
    fn reads_upper_case_and_refuses_mixed_case_and_a_bad_checksum() {
        let address = sample(Network::Floonet);
        let text = address.encode();
        assert_eq!(Epic1Address::decode_any(&text.to_uppercase()), Ok(address));
        let mixed = format!("TEPIC{}", &text[5..]);
        assert_eq!(
            Epic1Address::decode(&mixed, Network::Floonet),
            Err(Epic1Error::Bech32(Bech32Error::MixedCase))
        );
        let mut broken = text.into_bytes();
        let last = broken.len() - 1;
        broken[last] = if broken[last] == b'q' { b'p' } else { b'q' };
        assert_eq!(
            Epic1Address::decode(&String::from_utf8(broken).unwrap(), Network::Floonet),
            Err(Epic1Error::Bech32(Bech32Error::Checksum))
        );
    }

    #[test]
    fn refuses_wrong_lengths_and_versions() {
        for length in [0, 1, 64, 67, 97] {
            let text = with_data("epic", |data| data.resize(length, 1));
            assert_eq!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::Length { actual: length })
            );
        }
        let earlier = with_data("epic", |data| data.resize(65, 1));
        assert_eq!(
            Epic1Address::decode(&earlier, Network::Mainnet),
            Err(Epic1Error::EarlierAddress)
        );
        for version in [0x00, 0x02, 0xff] {
            let text = with_data("epic", |data| data[0] = version);
            assert_eq!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::Version { version })
            );
        }
    }

    #[test]
    fn refuses_a_delivery_key_that_is_no_compressed_point() {
        let good = sample(Network::Mainnet).delivery_key().to_bytes();
        let mut uncompressed = good;
        uncompressed[0] = 0x04;
        let mut no_prefix = good;
        no_prefix[0] = 0x00;
        // x = 5: x^3 + 7 is not a square modulo p.
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 5;
        for key in [uncompressed, no_prefix, off_curve, [0u8; 33]] {
            let text = with_data("epic", |data| data[33..66].copy_from_slice(&key));
            assert_eq!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::DeliveryKey(CryptoError::InvalidPublicKey)),
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
            let text = with_data("epic", |data| data[1..33].copy_from_slice(&key));
            assert!(matches!(
                Epic1Address::decode(&text, Network::Mainnet),
                Err(Epic1Error::SealKey(_))
            ));
        }
    }
}
