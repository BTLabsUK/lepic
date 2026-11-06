// SPDX-License-Identifier: Apache-2.0
//! A domain claim (RFC 0002 section 6.3, ADR 0043): a contact says it speaks for a domain, and
//! proves the claim with a long-lived domain key that signs the pairing's sig key. The claim
//! travels as envelope extension 0x83 in a pairing reply, confirm and contact update. Pure: this
//! module checks signatures and names only. Whether the domain publishes the key is the host's
//! fetch and the wallet's verdict, never decided here.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::network::Network;

/// The first bytes of the signed message; the version of the claim format.
pub const DOMAIN_TAG: &[u8] = b"epic-domain/1";
/// The longest domain name, in bytes, as in DNS.
pub const MAX_DOMAIN_LEN: usize = 253;

const MAX_LABEL_LEN: usize = 63;
const ISSUED_AT_LEN: usize = 8;
const SIGNATURE_LEN: usize = 64;

/// Why a domain name or claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DomainError {
    #[error("not a valid domain name")]
    Name,
    #[error("a domain name is 1 to {MAX_DOMAIN_LEN} bytes and a claim holds its signature")]
    Length,
    #[error("the domain signature does not verify")]
    Signature,
}

/// A normalized domain name: ASCII, lowercase, dot-separated labels of letters, digits and
/// hyphens, at least two labels, no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// Normalizes `text`: lowercases ASCII letters and removes one trailing dot, then checks
    /// each label is 1 to 63 bytes of `[a-z0-9-]`, not starting or ending with a hyphen, that
    /// there is at least one dot and that the whole name is 1 to 253 bytes.
    pub fn new(text: &str) -> Result<Self, DomainError> {
        if !text.is_ascii() {
            return Err(DomainError::Name);
        }
        let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
        if name.is_empty() || name.len() > MAX_DOMAIN_LEN {
            return Err(DomainError::Length);
        }
        let mut labels = 0usize;
        for label in name.split('.') {
            labels = labels.saturating_add(1);
            let valid = (1..=MAX_LABEL_LEN).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
            if !valid {
                return Err(DomainError::Name);
            }
        }
        if labels < 2 {
            return Err(DomainError::Name);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The Ed25519 key that signs domain claims, from a 32-byte seed the wallet derives from the
/// contact root. Its public half is what the domain lists in its well-known file.
pub struct DomainKey(SigningKey);

impl DomainKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl fmt::Debug for DomainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DomainKey(..)")
    }
}

/// A claim that the sender of a pairing speaks for `domain`, signed by the domain key over the
/// network, the pairing's sig key, the time and the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainClaim {
    pub domain: DomainName,
    /// Unix seconds when the claim was signed; informational.
    pub issued_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl DomainClaim {
    /// `epic-domain/1 || net || sig_key || issued_at (u64 BE) || domain`.
    fn message(
        net: Network,
        sig_key: &VerifyingKey,
        issued_at: u64,
        domain: &DomainName,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            DOMAIN_TAG
                .len()
                .saturating_add(33)
                .saturating_add(ISSUED_AT_LEN)
                .saturating_add(domain.as_str().len()),
        );
        message.extend_from_slice(DOMAIN_TAG);
        message.push(net.byte());
        message.extend_from_slice(sig_key.as_bytes());
        message.extend_from_slice(&issued_at.to_be_bytes());
        message.extend_from_slice(domain.as_str().as_bytes());
        message
    }

    /// Signs the claim for the pairing whose sig key is `sig_key`.
    pub fn sign(
        key: &DomainKey,
        net: Network,
        sig_key: &VerifyingKey,
        domain: DomainName,
        issued_at: u64,
    ) -> Self {
        let signature = key
            .0
            .sign(&Self::message(net, sig_key, issued_at, &domain))
            .to_bytes();
        Self {
            domain,
            issued_at,
            signature,
        }
    }

    /// Whether `domain_key` signed this claim for `sig_key` on `net`. Strict: a signature that
    /// is only valid under the lax rules is refused.
    pub fn verify_with(
        &self,
        domain_key: &VerifyingKey,
        net: Network,
        sig_key: &VerifyingKey,
    ) -> bool {
        domain_key
            .verify_strict(
                &Self::message(net, sig_key, self.issued_at, &self.domain),
                &Signature::from_bytes(&self.signature),
            )
            .is_ok()
    }

    /// The value of extension 0x83: `issued_at (8, u64 BE) || signature (64) || domain`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            ISSUED_AT_LEN
                .saturating_add(SIGNATURE_LEN)
                .saturating_add(self.domain.as_str().len()),
        );
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(self.domain.as_str().as_bytes());
        bytes
    }

    /// Reads an extension 0x83 value. The domain is normalized, so a name in capitals or with a
    /// trailing dot parses; its signature only verifies when the sender signed the normalized
    /// name. A value too short or with an invalid name is an error here, and absent to the
    /// envelope reader.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomainError> {
        let (issued_at, rest) = bytes
            .split_first_chunk::<ISSUED_AT_LEN>()
            .ok_or(DomainError::Length)?;
        let (signature, domain) = rest
            .split_first_chunk::<SIGNATURE_LEN>()
            .ok_or(DomainError::Length)?;
        let domain = std::str::from_utf8(domain).map_err(|_| DomainError::Name)?;
        Ok(Self {
            domain: DomainName::new(domain)?,
            issued_at: u64::from_be_bytes(*issued_at),
            signature: *signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (DomainKey, VerifyingKey) {
        (
            DomainKey::from_seed([7; 32]),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
        )
    }

    fn claim() -> DomainClaim {
        let (key, sig_key) = keys();
        DomainClaim::sign(
            &key,
            Network::Floonet,
            &sig_key,
            DomainName::new("btlabs.uk").unwrap(),
            1_762_387_200,
        )
    }

    #[test]
    fn domain_name_normalizes() {
        assert_eq!(DomainName::new("BTLabs.UK.").unwrap().as_str(), "btlabs.uk");
        assert_eq!(
            DomainName::new("a-b.c1.example").unwrap().as_str(),
            "a-b.c1.example"
        );
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), MAX_DOMAIN_LEN);
        assert!(DomainName::new(&longest).is_ok());
    }

    #[test]
    fn domain_name_rejects() {
        let too_long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(too_long.len(), 254);
        for bad in [
            "",
            ".",
            "localhost",
            "localhost.",
            "-a.com",
            "a-.com",
            "a..com",
            ".a.com",
            "a.com..",
            "a b.com",
            "a_b.com",
            "bücher.de",
            "a.com/x",
            &too_long,
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(DomainName::new(bad).is_err(), "{bad:?}");
        }
        assert_eq!(DomainName::new("").err(), Some(DomainError::Length));
        assert_eq!(DomainName::new(&too_long).err(), Some(DomainError::Length));
        assert_eq!(DomainName::new("-a.com").err(), Some(DomainError::Name));
    }

    #[test]
    fn claim_round_trips_bytes() {
        let claim = claim();
        let bytes = claim.to_bytes();
        assert_eq!(bytes.len(), 81);
        assert_eq!(bytes[..8], 1_762_387_200u64.to_be_bytes());
        assert_eq!(bytes[8..72], claim.signature);
        assert_eq!(bytes[72..], *b"btlabs.uk");
        assert_eq!(DomainClaim::from_bytes(&bytes).unwrap(), claim);
    }

    #[test]
    fn claim_from_bytes_normalizes_and_refuses_short_or_bad_names() {
        let mut bytes = claim().to_bytes();
        bytes.truncate(72);
        bytes.extend_from_slice(b"BTLabs.UK.");
        assert_eq!(
            DomainClaim::from_bytes(&bytes).unwrap().domain.as_str(),
            "btlabs.uk"
        );
        assert_eq!(DomainClaim::from_bytes(&[0; 10]), Err(DomainError::Length));
        assert_eq!(DomainClaim::from_bytes(&[0; 72]), Err(DomainError::Length));
        bytes.truncate(72);
        bytes.extend_from_slice(b"nodot");
        assert_eq!(DomainClaim::from_bytes(&bytes), Err(DomainError::Name));
        bytes.truncate(72);
        bytes.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(DomainClaim::from_bytes(&bytes), Err(DomainError::Name));
        bytes.truncate(72);
        bytes.extend_from_slice("a".repeat(254).as_bytes());
        assert!(DomainClaim::from_bytes(&bytes).is_err());
    }

    #[test]
    fn claim_verifies_and_rejects_other_sig_key_or_net() {
        let (key, sig_key) = keys();
        let claim = claim();
        let other_sig_key = SigningKey::from_bytes(&[10; 32]).verifying_key();
        let other_key = DomainKey::from_seed([8; 32]).public();
        assert!(claim.verify_with(&key.public(), Network::Floonet, &sig_key));
        assert!(!claim.verify_with(&key.public(), Network::Mainnet, &sig_key));
        assert!(!claim.verify_with(&key.public(), Network::Floonet, &other_sig_key));
        assert!(!claim.verify_with(&other_key, Network::Floonet, &sig_key));

        let mut later = claim.clone();
        later.issued_at = later.issued_at.wrapping_add(1);
        assert!(!later.verify_with(&key.public(), Network::Floonet, &sig_key));
        let mut other_domain = claim;
        other_domain.domain = DomainName::new("btlabs.example").unwrap();
        assert!(!other_domain.verify_with(&key.public(), Network::Floonet, &sig_key));
    }

    #[test]
    fn the_signed_message_has_the_documented_layout() {
        let (_, sig_key) = keys();
        let message = DomainClaim::message(
            Network::Floonet,
            &sig_key,
            0x0102_0304_0506_0708,
            &DomainName::new("btlabs.uk").unwrap(),
        );
        assert_eq!(&message[..13], b"epic-domain/1");
        assert_eq!(message[13], 1);
        assert_eq!(&message[14..46], sig_key.as_bytes());
        assert_eq!(&message[46..54], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&message[54..], b"btlabs.uk");
    }
}
