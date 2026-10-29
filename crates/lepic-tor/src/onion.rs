// SPDX-License-Identifier: Apache-2.0
//! Onion v3 addresses and the key tor publishes them with.
//!
//! The wallet's onion is its payment-proof key in onion form, so it equals what
//! `epic-wallet address` prints and survives a restore from the phrase. The key's 32-byte seed
//! is the wallet's address secret key (`lepic_keychain::Keychain::address_key`, account `m/0/0`,
//! index 0).

use std::fmt;

use ed25519_dalek::SigningKey;
use sha2::Sha512;
use sha3::Sha3_256;
use sha3::digest::Digest;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Characters in an onion v3 name, without `.onion`.
pub const ONION_NAME_LEN: usize = 56;

const VERSION: u8 = 3;
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
// Anything a person pastes as an address fits; longer text is not one.
const MAX_INPUT_LEN: usize = 512;

/// Why a text is not an onion v3 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OnionError {
    #[error("the address is empty")]
    Empty,
    #[error("the text is not an onion v3 address")]
    Format,
    #[error("the onion address has an unknown version")]
    Version,
    #[error("the onion address has a typo")]
    Checksum,
}

/// A checked onion v3 address: 56 lowercase base32 characters whose version and checksum hold.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress {
    name: String,
    public_key: [u8; 32],
}

impl OnionAddress {
    /// The onion of an ed25519 public key.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        let bytes: Vec<u8> = public_key
            .iter()
            .copied()
            .chain(checksum(public_key))
            .chain([VERSION])
            .collect();
        Self {
            name: base32_encode(&bytes),
            public_key: *public_key,
        }
    }

    /// Reads what a person typed or pasted: the bare name, with or without `.onion`, an
    /// `http://` or `https://` prefix, any `:port` and any path, in any case. The port and path
    /// are dropped; the foreign API is always reached at port 80, `/v2/foreign`.
    pub fn parse(text: &str) -> Result<Self, OnionError> {
        if text.len() > MAX_INPUT_LEN {
            return Err(OnionError::Format);
        }
        let lower = text.trim().to_ascii_lowercase();
        if lower.is_empty() {
            return Err(OnionError::Empty);
        }
        let rest = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"))
            .unwrap_or(&lower);
        let authority = rest.split('/').next().unwrap_or_default();
        let host = match authority.rsplit_once(':') {
            Some((host, port)) if is_port(port) => host,
            Some(_) => return Err(OnionError::Format),
            None => authority,
        };
        let name = host.strip_suffix(".onion").unwrap_or(host);
        if name.len() != ONION_NAME_LEN {
            return Err(OnionError::Format);
        }
        let bytes = base32_decode(name).ok_or(OnionError::Format)?;
        let (key, rest) = bytes.split_first_chunk::<32>().ok_or(OnionError::Format)?;
        let [check0, check1, version] =
            <[u8; 3]>::try_from(rest).map_err(|_| OnionError::Format)?;
        if version != VERSION {
            return Err(OnionError::Version);
        }
        if checksum(key) != [check0, check1] {
            return Err(OnionError::Checksum);
        }
        Ok(Self {
            name: name.to_owned(),
            public_key: *key,
        })
    }

    /// The 56-character name, which is also tor's ServiceID.
    pub fn service_id(&self) -> &str {
        &self.name
    }

    /// `<name>.onion`, the host to ask tor for.
    pub fn host(&self) -> String {
        format!("{}.onion", self.name)
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.onion", self.name)
    }
}

impl fmt::Debug for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OnionAddress({self})")
    }
}

/// `<56 characters>.onion` for an ed25519 public key.
pub fn onion_address(public_key: &[u8; 32]) -> String {
    OnionAddress::from_public_key(public_key).host()
}

/// See [`OnionAddress::parse`].
pub fn parse_onion(text: &str) -> Result<OnionAddress, OnionError> {
    OnionAddress::parse(text)
}

/// The ed25519 public key of a 32-byte seed.
pub fn public_key_of_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// The 64-byte expanded secret key tor's `ADD_ONION ED25519-V3:` takes: SHA-512 of the seed
/// with the scalar half clamped, as RFC 8032 key generation does. Tor derives the public key
/// from this, so passing the seed itself, or the seed followed by the public key, publishes a
/// different onion than the wallet's. The key is on the heap, so moving it leaves no copy
/// behind, and is wiped when dropped.
pub fn expanded_secret(seed: &[u8; 32]) -> Box<Zeroizing<[u8; 64]>> {
    let mut hash = Sha512::digest(seed);
    let mut expanded = Box::new(Zeroizing::new([0u8; 64]));
    expanded.copy_from_slice(&hash);
    hash.as_mut_slice().zeroize();
    if let Some(first) = expanded.first_mut() {
        *first &= 248;
    }
    if let Some(last) = expanded.get_mut(31) {
        *last &= 127;
        *last |= 64;
    }
    expanded
}

fn checksum(public_key: &[u8; 32]) -> [u8; 2] {
    let digest = Sha3_256::new()
        .chain_update(CHECKSUM_PREFIX)
        .chain_update(public_key)
        .chain_update([VERSION])
        .finalize();
    let mut out = [0u8; 2];
    out.iter_mut().zip(digest.iter()).for_each(|(o, d)| *o = *d);
    out
}

fn is_port(text: &str) -> bool {
    (1..=5).contains(&text.len()) && text.parse::<u16>().is_ok_and(|port| port > 0)
}

// Unpadded RFC 4648 base32 in lowercase. 35 bytes are exactly 56 characters, so an onion never
// has leftover bits.
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let index = usize::from((buffer >> bits) & 31);
            out.extend(ALPHABET.get(index).map(|&c| char::from(c)));
        }
        buffer &= low_bits(bits);
    }
    if bits > 0 {
        let index = usize::from((buffer << 5u32.saturating_sub(bits)) & 31);
        out.extend(ALPHABET.get(index).map(|&c| char::from(c)));
    }
    out
}

// A mask of the lowest `bits` bits; the base32 buffers never hold more than 12.
const fn low_bits(bits: u32) -> u16 {
    (1u16 << bits).wrapping_sub(1)
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(5) / 8);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)?;
        buffer = (buffer << 5) | u16::try_from(value).ok()?;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
            buffer &= low_bits(bits);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ONION: &str = "mk7ca5rxicc6ps765gdj3irikfzer6ffd2jpysipnnpttl7jynzaluyd";

    #[test]
    fn accepts_every_shape_a_person_pastes() {
        for text in [
            ONION.to_owned(),
            format!("{ONION}.onion"),
            format!("http://{ONION}.onion"),
            format!("http://{ONION}.onion:80/"),
            format!(" {}.ONION ", ONION.to_uppercase()),
            format!("https://{ONION}.onion/"),
            format!("http://{ONION}.onion:3415"),
            format!("{ONION}.onion/v2/foreign"),
            format!("HTTP://{ONION}.onion:3415/v2/foreign"),
            format!("{ONION}:3415"),
        ] {
            assert_eq!(
                OnionAddress::parse(&text).unwrap().service_id(),
                ONION,
                "{text}"
            );
        }
    }

    #[test]
    fn a_typo_is_a_checksum_error() {
        let mut typo = ONION.to_owned().into_bytes();
        typo[10] = if typo[10] == b'a' { b'b' } else { b'a' };
        let typo = String::from_utf8(typo).unwrap();
        assert_eq!(OnionAddress::parse(&typo), Err(OnionError::Checksum));
        assert_eq!(
            OnionAddress::parse(&format!("http://{typo}.onion:3415/v2/foreign")),
            Err(OnionError::Checksum)
        );
    }

    #[test]
    fn rejects_other_shapes() {
        let all_a = "a".repeat(55);
        assert_eq!(
            OnionAddress::parse(&format!("{all_a}d")),
            Err(OnionError::Checksum)
        );
        assert_eq!(
            OnionAddress::parse(&format!("{all_a}e")),
            Err(OnionError::Version)
        );
        assert_eq!(OnionAddress::parse(""), Err(OnionError::Empty));
        assert_eq!(OnionAddress::parse("   "), Err(OnionError::Empty));
        for text in [
            ONION[1..].to_owned(),
            format!("{ONION}.onion:abc"),
            format!("{ONION}.onion:123456"),
            format!("{ONION}.onion:0"),
            format!("{ONION}.onion:"),
            format!("{}1", &ONION[..55]),
            "esXXXXX@relay.example.invalid".to_owned(),
            // An onion v2 host.
            format!("{}.onion", "a".repeat(16)),
            format!("ftp://{ONION}.onion"),
            format!("{ONION}.onion.evil.example"),
            "a".repeat(MAX_INPUT_LEN + 1),
        ] {
            assert_eq!(
                OnionAddress::parse(&text),
                Err(OnionError::Format),
                "{text}"
            );
        }
    }

    #[test]
    fn expansion_is_sha512_clamped() {
        let seed = [7u8; 32];
        let expanded = expanded_secret(&seed);
        let hash = Sha512::digest(seed);
        assert_eq!(expanded[0], hash[0] & 248);
        assert_eq!(expanded[31], (hash[31] & 127) | 64);
        assert_eq!(expanded[1..31], hash[1..31]);
        assert_eq!(expanded[32..], hash[32..]);
    }

    #[test]
    fn display_and_debug_show_the_host() {
        let onion = OnionAddress::parse(ONION).unwrap();
        assert_eq!(onion.to_string(), format!("{ONION}.onion"));
        assert_eq!(onion.host(), format!("{ONION}.onion"));
        assert_eq!(format!("{onion:?}"), format!("OnionAddress({ONION}.onion)"));
    }

    proptest! {
        #[test]
        fn every_public_key_round_trips(key in proptest::array::uniform32(any::<u8>())) {
            let onion = OnionAddress::from_public_key(&key);
            prop_assert_eq!(onion.service_id().len(), ONION_NAME_LEN);
            let parsed = OnionAddress::parse(&onion_address(&key)).unwrap();
            prop_assert_eq!(parsed.public_key(), &key);
            prop_assert_eq!(parsed, onion);
        }

        #[test]
        fn never_panics_on_any_text(text in ".{0,120}") {
            let _ = OnionAddress::parse(&text);
        }

        #[test]
        fn base32_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let encoded = base32_encode(&bytes);
            let decoded = base32_decode(&encoded).unwrap();
            prop_assert_eq!(&decoded[..bytes.len()], &bytes[..]);
        }
    }
}
