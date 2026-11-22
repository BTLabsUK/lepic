// SPDX-License-Identifier: Apache-2.0
//! The signature of a checkout request: a payee that proves a domain (ADR 0043) signs a whole
//! lepic.v1 request code with its domain key, so a payer can show who asks for the payment.
//!
//! The signature sits in the code's last tail record, `F0` (request claim):
//! `key (32) || issued_at (u64 BE) || signature (64) || domain`. It covers
//! `epic-request/1 || net || key || SHA-256(P) || issued_at (u64 BE) || domain`, where P is every
//! byte of the code before the claim record. Pure: this module neither parses the slate nor
//! fetches the domain's well-known file; `lepic-native-slate` reads the record and the wallet
//! decides the verdict.

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use crate::domain::{DomainError, DomainKey, DomainName};
use crate::hash::sha256;
use crate::network::Network;

/// The first bytes of the signed message; the version of the request signature.
pub const REQUEST_TAG: &[u8] = b"epic-request/1";
/// The tail record type that holds the request claim.
pub const REQUEST_CLAIM_TYPE: u8 = 0xF0;

const KEY_LEN: usize = 32;
const ISSUED_AT_LEN: usize = 8;
const SIGNATURE_LEN: usize = 64;

/// `epic-request/1 || net || key || SHA-256(signed) || issued_at (u64 BE) || domain`.
fn message(
    net: Network,
    key: &[u8; KEY_LEN],
    signed: &[u8],
    issued_at: u64,
    domain: &DomainName,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        REQUEST_TAG
            .len()
            .saturating_add(1 + KEY_LEN + 32 + ISSUED_AT_LEN)
            .saturating_add(domain.as_str().len()),
    );
    message.extend_from_slice(REQUEST_TAG);
    message.push(net.byte());
    message.extend_from_slice(key);
    message.extend_from_slice(&sha256(&[signed]));
    message.extend_from_slice(&issued_at.to_be_bytes());
    message.extend_from_slice(domain.as_str().as_bytes());
    message
}

/// Signs `code` and returns it with the request claim record appended.
///
/// `code` is a whole lepic.v1 I1 without a claim; its tail must hold no record above `F0`, so
/// that the claim is the last record. Nothing about the slate is checked here: the caller decodes
/// the result, which refuses a code that breaks those rules.
pub fn sign_request_code(
    code: &[u8],
    key: &DomainKey,
    net: Network,
    domain: &DomainName,
    issued_at: u64,
) -> Vec<u8> {
    let public = key.public().to_bytes();
    let signature = key
        .signing_key()
        .sign(&message(net, &public, code, issued_at, domain))
        .to_bytes();
    let domain = domain.as_str().as_bytes();
    let value_len = (KEY_LEN + ISSUED_AT_LEN + SIGNATURE_LEN).saturating_add(domain.len());
    // A domain is at most 253 bytes, so the value always fits its u16 length.
    let len = u16::try_from(value_len).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(code.len().saturating_add(3).saturating_add(value_len));
    out.extend_from_slice(code);
    out.push(REQUEST_CLAIM_TYPE);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&public);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&signature);
    out.extend_from_slice(domain);
    out
}

/// Checks a request claim's signature over `signed`, the code before its claim record.
///
/// Strict Ed25519: a key that is not a valid point, or a signature that does not verify under
/// it, gives [`DomainError::Signature`].
pub fn check_request_signature(
    signed: &[u8],
    net: Network,
    key: &[u8; KEY_LEN],
    issued_at: u64,
    domain: &DomainName,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), DomainError> {
    let public = VerifyingKey::from_bytes(key).map_err(|_| DomainError::Signature)?;
    public
        .verify_strict(
            &message(net, key, signed, issued_at, domain),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| DomainError::Signature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const CODE: &[u8] = b"lepic.v1 stand-in: any bytes before the claim";

    struct Parts {
        signed: Vec<u8>,
        key: [u8; 32],
        issued_at: u64,
        signature: [u8; 64],
        domain: DomainName,
    }

    fn split(signed_code: &[u8], signed_len: usize) -> Parts {
        let (signed, record) = signed_code.split_at(signed_len);
        assert_eq!(record[0], REQUEST_CLAIM_TYPE);
        let len = usize::from(u16::from_be_bytes([record[1], record[2]]));
        let value = &record[3..];
        assert_eq!(value.len(), len);
        Parts {
            signed: signed.to_vec(),
            key: value[..32].try_into().unwrap(),
            issued_at: u64::from_be_bytes(value[32..40].try_into().unwrap()),
            signature: value[40..104].try_into().unwrap(),
            domain: DomainName::new(std::str::from_utf8(&value[104..]).unwrap()).unwrap(),
        }
    }

    fn check(parts: &Parts, net: Network) -> Result<(), DomainError> {
        check_request_signature(
            &parts.signed,
            net,
            &parts.key,
            parts.issued_at,
            &parts.domain,
            &parts.signature,
        )
    }

    fn signed() -> Parts {
        let key = DomainKey::from_seed([7; 32]);
        let domain = DomainName::new("shop.example.org").unwrap();
        let code = sign_request_code(CODE, &key, Network::Mainnet, &domain, 1_700_000_000);
        assert!(code.starts_with(CODE));
        let parts = split(&code, CODE.len());
        assert_eq!(parts.key, key.public().to_bytes());
        assert_eq!(parts.issued_at, 1_700_000_000);
        assert_eq!(parts.domain, domain);
        parts
    }

    #[test]
    fn a_signed_code_checks() {
        assert_eq!(check(&signed(), Network::Mainnet), Ok(()));
    }

    #[test]
    fn the_signature_covers_every_byte_before_the_claim() {
        let parts = signed();
        for at in 0..parts.signed.len() {
            let mut changed = Parts {
                signed: parts.signed.clone(),
                ..signed()
            };
            changed.signed[at] ^= 0x01;
            assert_eq!(
                check(&changed, Network::Mainnet),
                Err(DomainError::Signature),
                "byte {at}"
            );
        }
        let mut longer = signed();
        longer.signed.push(0);
        assert_eq!(
            check(&longer, Network::Mainnet),
            Err(DomainError::Signature)
        );
    }

    #[test]
    fn the_signature_binds_network_time_domain_and_key() {
        assert_eq!(
            check(&signed(), Network::Floonet),
            Err(DomainError::Signature)
        );
        let mut later = signed();
        later.issued_at += 1;
        assert_eq!(check(&later, Network::Mainnet), Err(DomainError::Signature));
        let mut other = signed();
        other.domain = DomainName::new("shop.example.net").unwrap();
        assert_eq!(check(&other, Network::Mainnet), Err(DomainError::Signature));
        let mut key = signed();
        key.key = DomainKey::from_seed([8; 32]).public().to_bytes();
        assert_eq!(check(&key, Network::Mainnet), Err(DomainError::Signature));
        let mut not_a_point = signed();
        not_a_point.key = [0xff; 32];
        not_a_point.key[31] = 0x7f;
        assert_eq!(
            check(&not_a_point, Network::Mainnet),
            Err(DomainError::Signature)
        );
        let mut signature = signed();
        signature.signature[0] ^= 1;
        assert_eq!(
            check(&signature, Network::Mainnet),
            Err(DomainError::Signature)
        );
    }
}
