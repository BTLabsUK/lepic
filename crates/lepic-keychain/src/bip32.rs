// Portions Copyright 2019 The Grin Developers
// Portions of the Rust Bitcoin Library, written in 2014 by Andrew Poelstra (CC0)
// Ported from EpicCash/epic keychain/src/extkey_bip32.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! BIP32 hierarchical derivation as the Epic keychain does it: the master key comes from
//! HMAC-SHA512 keyed by `"IamVoldemort"`, and the extended-key version bytes are Epic's own.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use lepic_crypto::{CryptoError, PublicKey, SecretKey};
#[cfg(test)]
use lepic_primitives::params::Network;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

/// The HMAC key for the master key. Upstream replaced BIP32's `"Bitcoin seed"` with it.
const MASTER_HMAC_KEY: &[u8] = b"IamVoldemort";

const HARDENED_BIT: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Bip32Error {
    #[error("derived key is zero or not below the curve order")]
    InvalidDerivedKey,
    #[error("derivation is deeper than 255 levels")]
    DepthOverflow,
    #[error("child index {index} does not fit in 31 bits")]
    ChildIndexOutOfRange { index: u32 },
    #[error("key operation failed")]
    Crypto(#[from] CryptoError),
}

/// A BIP32 child number in its `u32` form: hardened children set the top bit. Every `u32` is a
/// valid child number, so the conversions both ways are lossless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChildNumber(u32);

impl ChildNumber {
    /// The normal child `index`, which must be below 2^31.
    pub fn normal(index: u32) -> Result<Self, Bip32Error> {
        if index & HARDENED_BIT == 0 {
            Ok(Self(index))
        } else {
            Err(Bip32Error::ChildIndexOutOfRange { index })
        }
    }

    /// The hardened child `index`, which must be below 2^31.
    pub fn hardened(index: u32) -> Result<Self, Bip32Error> {
        if index & HARDENED_BIT == 0 {
            Ok(Self(index | HARDENED_BIT))
        } else {
            Err(Bip32Error::ChildIndexOutOfRange { index })
        }
    }

    pub fn is_hardened(self) -> bool {
        self.0 & HARDENED_BIT != 0
    }

    /// The index without the hardened bit.
    pub fn index(self) -> u32 {
        self.0 & !HARDENED_BIT
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        Self(number)
    }
}

impl From<ChildNumber> for u32 {
    fn from(child: ChildNumber) -> Self {
        child.0
    }
}

/// Extended-key version bytes. They are the only thing in a keychain that depends on the network.
/// LEPIC never serialises extended keys, so only the vector tests read them.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtKeyVersion {
    pub(crate) private: [u8; 4],
    pub(crate) public: [u8; 4],
}

#[cfg(test)]
impl ExtKeyVersion {
    pub(crate) const MAINNET: Self = Self {
        private: [0x03, 0x3C, 0x04, 0xA4],
        public: [0x03, 0x3C, 0x08, 0xDF],
    };
    /// Used by floonet and every other non-mainnet chain.
    pub(crate) const FLOONET: Self = Self {
        private: [0x03, 0x27, 0x3A, 0x10],
        public: [0x03, 0x27, 0x3E, 0x4B],
    };

    /// `epic-wallet` uses the mainnet bytes on mainnet and the floonet ones elsewhere.
    pub(crate) const fn of(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Floonet => Self::FLOONET,
        }
    }
}

/// A chain code. Together with a public key it derives every normal child, so it is treated as a
/// secret: wiped on drop and never printed.
#[derive(Clone)]
pub struct ChainCode(Zeroizing<[u8; 32]>);

impl ChainCode {
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ChainCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChainCode([redacted])")
    }
}

/// The first four bytes of HASH160 of a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fingerprint(pub [u8; 4]);

impl Fingerprint {
    pub fn of(key: &PublicKey) -> Self {
        let sha = Sha256::digest(key.to_bytes());
        let hash160 = Ripemd160::digest(sha);
        let mut fingerprint = [0u8; 4];
        for (byte, source) in fingerprint.iter_mut().zip(hash160.iter()) {
            *byte = *source;
        }
        Self(fingerprint)
    }
}

/// An extended private key. Wiped on drop and never printed.
#[derive(Clone)]
pub struct ExtendedPrivKey {
    depth: u8,
    parent_fingerprint: Fingerprint,
    child_number: ChildNumber,
    secret_key: SecretKey,
    chain_code: ChainCode,
}

impl ExtendedPrivKey {
    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn parent_fingerprint(&self) -> Fingerprint {
        self.parent_fingerprint
    }

    pub fn child_number(&self) -> ChildNumber {
        self.child_number
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    pub fn new_master(seed: &[u8]) -> Result<Self, Bip32Error> {
        let output = hmac_sha512(MASTER_HMAC_KEY, &[seed])?;
        let (secret_key, chain_code) = split(&output)?;
        Ok(Self {
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber(0),
            secret_key,
            chain_code,
        })
    }

    pub fn public_key(&self) -> Result<PublicKey, Bip32Error> {
        Ok(PublicKey::from_secret_key(&self.secret_key)?)
    }

    pub fn fingerprint(&self) -> Result<Fingerprint, Bip32Error> {
        Ok(Fingerprint::of(&self.public_key()?))
    }

    /// Private to private child derivation.
    pub fn ckd_priv(&self, child: ChildNumber) -> Result<Self, Bip32Error> {
        let depth = self.depth.checked_add(1).ok_or(Bip32Error::DepthOverflow)?;
        let parent_public = self.public_key()?;
        let index = u32::from(child).to_be_bytes();
        let output = if child.is_hardened() {
            hmac_sha512(
                self.chain_code.expose_bytes(),
                &[&[0u8], self.secret_key.expose_bytes(), &index],
            )?
        } else {
            hmac_sha512(
                self.chain_code.expose_bytes(),
                &[&parent_public.to_bytes(), &index],
            )?
        };
        let (tweak, chain_code) = split(&output)?;
        let secret_key = SecretKey::sum(&[tweak, self.secret_key.clone()], &[])
            .map_err(|_| Bip32Error::InvalidDerivedKey)?;
        Ok(Self {
            depth,
            parent_fingerprint: Fingerprint::of(&parent_public),
            child_number: child,
            secret_key,
            chain_code,
        })
    }

    pub fn derive_priv(
        &self,
        path: impl IntoIterator<Item = ChildNumber>,
    ) -> Result<Self, Bip32Error> {
        path.into_iter()
            .try_fold(self.clone(), |key, child| key.ckd_priv(child))
    }
}

impl fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExtendedPrivKey([redacted])")
    }
}

fn hmac_sha512(key: &[u8], data: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>, Bip32Error> {
    let mut mac = <HmacSha512 as KeyInit>::new_from_slice(key)
        .map_err(|_| Bip32Error::Crypto(CryptoError::Backend))?;
    for part in data {
        mac.update(part);
    }
    let mut digest = mac.finalize().into_bytes();
    let mut output = Zeroizing::new([0u8; 64]);
    output.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Ok(output)
}

/// Splits HMAC output into the key (left half) and the chain code (right half).
fn split(output: &[u8; 64]) -> Result<(SecretKey, ChainCode), Bip32Error> {
    let (left, right) = output.split_at(32);
    let secret_key = SecretKey::from_bytes(left).map_err(|_| Bip32Error::InvalidDerivedKey)?;
    let mut chain_code = Zeroizing::new([0u8; 32]);
    chain_code.copy_from_slice(right);
    Ok((secret_key, ChainCode(chain_code)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_number_round_trips_through_u32() {
        for raw in [
            0,
            1,
            HARDENED_BIT - 1,
            HARDENED_BIT,
            HARDENED_BIT | 44,
            u32::MAX,
        ] {
            assert_eq!(u32::from(ChildNumber::from(raw)), raw);
        }
        assert_eq!(
            ChildNumber::from(HARDENED_BIT | 7),
            ChildNumber::hardened(7).unwrap()
        );
        assert_eq!(ChildNumber::from(7), ChildNumber::normal(7).unwrap());
        let hardened = ChildNumber::from(HARDENED_BIT | 7);
        assert!(hardened.is_hardened());
        assert_eq!(hardened.index(), 7);
    }

    #[test]
    fn rejects_child_index_with_the_hardened_bit_set() {
        for index in [HARDENED_BIT, HARDENED_BIT | 5, u32::MAX] {
            let error = Bip32Error::ChildIndexOutOfRange { index };
            assert_eq!(ChildNumber::normal(index), Err(error));
            assert_eq!(ChildNumber::hardened(index), Err(error));
        }
    }

    #[test]
    fn rejects_derivation_past_depth_255() {
        let mut key = ExtendedPrivKey::new_master(&[1u8; 16]).unwrap();
        key.depth = u8::MAX;
        assert_eq!(
            key.ckd_priv(ChildNumber::from(0)).err(),
            Some(Bip32Error::DepthOverflow)
        );
    }

    #[test]
    fn redacts_extended_key_and_chain_code_in_debug() {
        let key = ExtendedPrivKey::new_master(&[1u8; 16]).unwrap();
        assert_eq!(format!("{key:?}"), "ExtendedPrivKey([redacted])");
        assert_eq!(format!("{:?}", key.chain_code), "ChainCode([redacted])");
    }
}
