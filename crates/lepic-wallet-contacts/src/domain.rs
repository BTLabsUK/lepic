// SPDX-License-Identifier: Apache-2.0
//! The domain proof of a paired contact (RFC 0002 6.3, ADR 0043): the file a domain publishes at
//! `/.well-known/epic-wallet.json` lists the domain keys of its wallets, and a contact's claim is
//! proven when one listed key signed it for the pairing's sig key. Pure: the host fetches the
//! file and hands the bytes over; nothing here reaches a network.
//!
//! ```json
//! {"version":1,"networks":{"mainnet":{"domain_keys":["<hex 32>"]}},"relays":["host:port"]}
//! ```
//!
//! Unknown members are ignored. `relays` is optional and informational.
//!
//! The same file proves a signed checkout request: an I1 whose last tail record is a request
//! claim, signed by the domain key over the whole code (`lepic_seal::sign_request_code`). See
//! [`request_claim`] and [`verify_request`].

use std::collections::BTreeMap;
use std::fmt;

use lepic_contact::{DomainClaim, DomainKey, DomainName, Network, VerifyingKey};
use lepic_native_slate::NativeSlate;
use lepic_slate::stage::Stage;
use serde::Deserialize;
use thiserror::Error;

use crate::hex;

/// The largest well-known file read, in bytes; a longer one is refused unparsed.
pub const DOMAIN_FILE_MAX: usize = 4096;

/// The most keys read from one network's list.
const KEYS_PER_NETWORK: usize = 8;

/// The only version of the file this reads.
const FILE_VERSION: u64 = 1;

const MAINNET: &str = "mainnet";
const FLOONET: &str = "floonet";

/// Why a domain claim was not proven. A host shows these as one word at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRefused {
    /// The file is longer than [`DOMAIN_FILE_MAX`].
    FileTooLarge,
    /// The file is not JSON of the documented shape, or a listed key is not an Ed25519 key.
    FileMalformed,
    /// The file's version is not 1.
    UnsupportedVersion,
    /// The file lists no keys for the wallet's network.
    NetworkAbsent,
    /// The claim names another domain than the one the file was fetched from.
    DomainMismatch,
    /// No key the file lists for the network signed the claim for this pairing.
    NoKeyMatches,
    /// A checkout request's signature does not verify over the code under the key it names.
    BadSignature,
    /// The file does not list the key that signed a checkout request, for the network.
    KeyNotListed,
}

impl DomainRefused {
    /// The reason as a snake_case word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileTooLarge => "file_too_large",
            Self::FileMalformed => "file_malformed",
            Self::UnsupportedVersion => "unsupported_version",
            Self::NetworkAbsent => "network_absent",
            Self::DomainMismatch => "domain_mismatch",
            Self::NoKeyMatches => "no_key_matches",
            Self::BadSignature => "bad_signature",
            Self::KeyNotListed => "key_not_listed",
        }
    }
}

impl fmt::Display for DomainRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainVerdict {
    Proven,
    Refused(DomainRefused),
}

/// A well-known file as read: the domain keys it lists for each network it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainFile {
    /// Keyed by `"mainnet"` and `"floonet"`; a network the file does not list is absent.
    pub networks: BTreeMap<String, Vec<VerifyingKey>>,
    /// The relays the domain names, informational.
    pub relays: Vec<String>,
}

#[derive(Deserialize)]
struct RawFile {
    version: u64,
    networks: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    relays: Vec<String>,
}

#[derive(Deserialize)]
struct RawKeys {
    domain_keys: Vec<String>,
}

impl DomainFile {
    /// Reads a well-known file: version 1, at most [`DOMAIN_FILE_MAX`] bytes, at most 8 keys for
    /// each of `mainnet` and `floonet`, each a 64-digit hex Ed25519 public key. Other networks
    /// and unknown members are ignored.
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainRefused> {
        if bytes.len() > DOMAIN_FILE_MAX {
            return Err(DomainRefused::FileTooLarge);
        }
        let raw: RawFile =
            serde_json::from_slice(bytes).map_err(|_| DomainRefused::FileMalformed)?;
        if raw.version != FILE_VERSION {
            return Err(DomainRefused::UnsupportedVersion);
        }
        let mut networks = BTreeMap::new();
        for (name, value) in raw.networks {
            if name != MAINNET && name != FLOONET {
                continue;
            }
            let RawKeys { domain_keys } =
                serde_json::from_value(value).map_err(|_| DomainRefused::FileMalformed)?;
            if domain_keys.len() > KEYS_PER_NETWORK {
                return Err(DomainRefused::FileMalformed);
            }
            let keys = domain_keys
                .iter()
                .map(|text| {
                    hex::decode_array::<32>(text)
                        .ok()
                        .and_then(|key| VerifyingKey::from_bytes(&key).ok())
                        .ok_or(DomainRefused::FileMalformed)
                })
                .collect::<Result<Vec<_>, _>>()?;
            networks.insert(name, keys);
        }
        Ok(Self {
            networks,
            relays: raw.relays,
        })
    }

    /// The text of a well-known file that lists `keys` for `network` and names `relays`: compact
    /// JSON, `relays` left out when there are none, no other network present.
    pub fn render(network: Network, keys: &[VerifyingKey], relays: &[String]) -> String {
        let keys = keys
            .iter()
            .map(|key| format!("\"{}\"", hex::encode(key.as_bytes())))
            .collect::<Vec<_>>()
            .join(",");
        let relays = if relays.is_empty() {
            String::new()
        } else {
            let list = relays
                .iter()
                .map(|relay| json_string(relay))
                .collect::<Vec<_>>()
                .join(",");
            format!(",\"relays\":[{list}]")
        };
        format!(
            "{{\"version\":{FILE_VERSION},\"networks\":{{\"{}\":{{\"domain_keys\":[{keys}]}}}}{relays}}}",
            network_name(network)
        )
    }

    /// The keys the file lists for `network`, if it names the network.
    pub fn keys(&self, network: Network) -> Option<&[VerifyingKey]> {
        self.networks.get(network_name(network)).map(Vec::as_slice)
    }
}

/// `value` as a JSON string literal.
fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""))
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => MAINNET,
        Network::Floonet => FLOONET,
    }
}

/// Whether the well-known file `file`, fetched from `domain`, proves `claim` for the pairing
/// whose sig key is `sig_key` on `network`. The checks run in this order: size, shape, version,
/// the network is listed, the claim names `domain`, and one listed key signed the claim.
pub fn verify(
    domain: &DomainName,
    file: &[u8],
    claim: &DomainClaim,
    sig_key: &VerifyingKey,
    network: Network,
) -> DomainVerdict {
    let file = match DomainFile::parse(file) {
        Ok(file) => file,
        Err(reason) => return DomainVerdict::Refused(reason),
    };
    let Some(keys) = file.keys(network) else {
        return DomainVerdict::Refused(DomainRefused::NetworkAbsent);
    };
    if claim.domain != *domain {
        return DomainVerdict::Refused(DomainRefused::DomainMismatch);
    }
    if keys
        .iter()
        .any(|key| claim.verify_with(key, network, sig_key))
    {
        DomainVerdict::Proven
    } else {
        DomainVerdict::Refused(DomainRefused::NoKeyMatches)
    }
}

/// What a wallet signs its domain claims with: the domain key and the domain the wallet claims.
pub struct DomainSigner {
    pub key: DomainKey,
    pub domain: DomainName,
}

impl DomainSigner {
    /// The claim for the pairing whose sig key is `sig_key`, signed at `issued_at` (unix
    /// seconds).
    pub fn claim(&self, network: Network, sig_key: &VerifyingKey, issued_at: u64) -> DomainClaim {
        DomainClaim::sign(&self.key, network, sig_key, self.domain.clone(), issued_at)
    }
}

/// The request claim of a checkout request as read: who signed the code, as the code says. Not
/// proven until [`verify_request`] checks it against the domain's well-known file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub domain: DomainName,
    pub key: VerifyingKey,
    /// Unix seconds when the code was signed; informational.
    pub issued_at: u64,
}

/// The outcome of [`verify_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestVerdict {
    /// The code carries no request claim.
    Unsigned,
    /// The domain's file lists the key that signed the code.
    Checked { domain: DomainName },
    /// The code names `domain`, but the claim is not proven.
    Refused {
        domain: DomainName,
        reason: DomainRefused,
    },
}

/// Why a code could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RequestSignError {
    #[error("the code is not a lepic.v1 slate")]
    Malformed,
    #[error("only an I1 invoice request is signed")]
    NotAnInvoice,
    #[error("the code is signed already")]
    AlreadySigned,
    #[error("the code was signed for another network")]
    Network,
}

/// The parts of a code's request claim, when it decodes as lepic.v1 and carries one.
fn read_claim(code: &[u8]) -> Option<(Network, Claim, &[u8], [u8; 64])> {
    let (network, slate) = NativeSlate::decode_any(code).ok()?;
    let claim = slate.tail().request_claim()?;
    let signed = claim.signed_part(code)?;
    let read = Claim {
        domain: DomainName::new(claim.domain()).ok()?,
        key: VerifyingKey::from_bytes(claim.key()).ok()?,
        issued_at: claim.issued_at(),
    };
    Some((seal_network(network), read, signed, *claim.signature()))
}

const fn seal_network(network: lepic_primitives::params::Network) -> Network {
    match network {
        lepic_primitives::params::Network::Mainnet => Network::Mainnet,
        lepic_primitives::params::Network::Floonet => Network::Floonet,
    }
}

/// The request claim of `code`, unchecked. `None` when the code carries none, or does not decode
/// as lepic.v1, or names a key that is not an Ed25519 point (no signature can verify under it).
pub fn request_claim(code: &[u8]) -> Option<Claim> {
    read_claim(code).map(|(_, claim, _, _)| claim)
}

/// Whether the well-known file `file`, fetched from the domain the claim of `code` names, proves
/// the claim on `network`. The checks run in this order: the code carries a claim, the signature
/// covers the code on `network`, then the file's size, shape and version, the network is listed,
/// and the file lists the signing key.
///
/// A code that does not decode as lepic.v1 reads as [`RequestVerdict::Unsigned`]: decode a code,
/// and refuse it if it is malformed, before showing its verdict. A claim with a key that is not
/// an Ed25519 point is [`DomainRefused::BadSignature`]; so is a code of another network, since its
/// signature names that network.
pub fn verify_request(code: &[u8], file: &[u8], network: Network) -> RequestVerdict {
    let Ok((code_network, slate)) = NativeSlate::decode_any(code) else {
        return RequestVerdict::Unsigned;
    };
    let Some(raw) = slate.tail().request_claim() else {
        return RequestVerdict::Unsigned;
    };
    // The codec only reads canonical names, which normalize to themselves.
    let Ok(domain) = DomainName::new(raw.domain()) else {
        return RequestVerdict::Unsigned;
    };
    let refused = |reason| RequestVerdict::Refused {
        domain: domain.clone(),
        reason,
    };
    let signature_ok = seal_network(code_network) == network
        && raw.signed_part(code).is_some_and(|signed| {
            lepic_seal::check_request_signature(
                signed,
                network,
                raw.key(),
                raw.issued_at(),
                &domain,
                raw.signature(),
            )
            .is_ok()
        });
    if !signature_ok {
        return refused(DomainRefused::BadSignature);
    }
    let file = match DomainFile::parse(file) {
        Ok(file) => file,
        Err(reason) => return refused(reason),
    };
    let Some(keys) = file.keys(network) else {
        return refused(DomainRefused::NetworkAbsent);
    };
    if keys.iter().any(|key| key.as_bytes() == raw.key()) {
        RequestVerdict::Checked { domain }
    } else {
        refused(DomainRefused::KeyNotListed)
    }
}

impl DomainSigner {
    /// `code`, an unsigned lepic.v1 I1, with a request claim for this signer's domain appended,
    /// signed at `issued_at` (unix seconds) on `network`. The result decodes: the tail must hold
    /// no record above the claim's type, which the codec refuses otherwise.
    pub fn sign_request(
        &self,
        code: &[u8],
        network: Network,
        issued_at: u64,
    ) -> Result<Vec<u8>, RequestSignError> {
        let (code_network, slate) =
            NativeSlate::decode_any(code).map_err(|_| RequestSignError::Malformed)?;
        if seal_network(code_network) != network {
            return Err(RequestSignError::Network);
        }
        if slate.slate().stage() != Stage::I1 {
            return Err(RequestSignError::NotAnInvoice);
        }
        if slate.tail().request_claim().is_some() {
            return Err(RequestSignError::AlreadySigned);
        }
        let signed =
            lepic_seal::sign_request_code(code, &self.key, network, &self.domain, issued_at);
        // A record above the claim's type would follow it; the codec refuses that.
        NativeSlate::decode_any(&signed).map_err(|_| RequestSignError::Malformed)?;
        Ok(signed)
    }
}

impl fmt::Debug for DomainSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainSigner")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    const ISSUED_AT: u64 = 1_762_387_200;

    fn signer() -> DomainSigner {
        DomainSigner {
            key: DomainKey::from_seed([7; 32]),
            domain: DomainName::new("integration.btlabs.uk").unwrap(),
        }
    }

    fn sig_key() -> VerifyingKey {
        lepic_contact::SigningKey::from_bytes(&[9; 32]).verifying_key()
    }

    fn claim(network: Network) -> DomainClaim {
        signer().claim(network, &sig_key(), ISSUED_AT)
    }

    fn file(network: Network) -> String {
        DomainFile::render(
            network,
            &[
                DomainKey::from_seed([1; 32]).public(),
                signer().key.public(),
            ],
            &[],
        )
    }

    fn check(file: &[u8], claim: &DomainClaim) -> DomainVerdict {
        verify(&signer().domain, file, claim, &sig_key(), Network::Floonet)
    }

    #[test]
    fn verify_proves_listed_key() {
        let verdict = check(file(Network::Floonet).as_bytes(), &claim(Network::Floonet));
        assert_eq!(verdict, DomainVerdict::Proven);
    }

    #[test]
    fn verify_refuses_other_network() {
        // The key is listed, but under mainnet only.
        let verdict = check(file(Network::Mainnet).as_bytes(), &claim(Network::Floonet));
        assert_eq!(
            verdict,
            DomainVerdict::Refused(DomainRefused::NetworkAbsent)
        );
        // Listed under the right network, but the claim was signed for the other one.
        let verdict = check(file(Network::Floonet).as_bytes(), &claim(Network::Mainnet));
        assert_eq!(verdict, DomainVerdict::Refused(DomainRefused::NoKeyMatches));
    }

    #[test]
    fn verify_refuses_domain_mismatch() {
        let other = DomainSigner {
            key: DomainKey::from_seed([7; 32]),
            domain: DomainName::new("other.example").unwrap(),
        };
        let claim = other.claim(Network::Floonet, &sig_key(), ISSUED_AT);
        let verdict = check(file(Network::Floonet).as_bytes(), &claim);
        assert_eq!(
            verdict,
            DomainVerdict::Refused(DomainRefused::DomainMismatch)
        );
    }

    #[test]
    fn verify_refuses_oversize_file() {
        let mut text = file(Network::Floonet);
        text.push_str(&" ".repeat(DOMAIN_FILE_MAX));
        assert!(text.len() > DOMAIN_FILE_MAX);
        let verdict = check(text.as_bytes(), &claim(Network::Floonet));
        assert_eq!(verdict, DomainVerdict::Refused(DomainRefused::FileTooLarge));
    }

    #[test]
    fn verify_refuses_unlisted_key_and_other_sig_key() {
        let unlisted = DomainFile::render(
            Network::Floonet,
            &[DomainKey::from_seed([1; 32]).public()],
            &[],
        );
        let verdict = check(unlisted.as_bytes(), &claim(Network::Floonet));
        assert_eq!(verdict, DomainVerdict::Refused(DomainRefused::NoKeyMatches));
        let other_pairing = lepic_contact::SigningKey::from_bytes(&[10; 32]).verifying_key();
        let verdict = verify(
            &signer().domain,
            file(Network::Floonet).as_bytes(),
            &claim(Network::Floonet),
            &other_pairing,
            Network::Floonet,
        );
        assert_eq!(verdict, DomainVerdict::Refused(DomainRefused::NoKeyMatches));
    }

    #[test]
    fn verify_refuses_malformed_files() {
        let key = hex::encode(signer().key.public().as_bytes());
        let cases = [
            (String::from("not json"), DomainRefused::FileMalformed),
            (
                format!(r#"{{"version":2,"networks":{{"floonet":{{"domain_keys":["{key}"]}}}}}}"#),
                DomainRefused::UnsupportedVersion,
            ),
            (
                String::from(r#"{"version":1,"networks":{"floonet":{"domain_keys":["zz"]}}}"#),
                DomainRefused::FileMalformed,
            ),
            (
                format!(
                    r#"{{"version":1,"networks":{{"floonet":{{"domain_keys":[{}]}}}}}}"#,
                    vec![format!("\"{key}\""); 9].join(",")
                ),
                DomainRefused::FileMalformed,
            ),
        ];
        for (text, reason) in cases {
            let verdict = check(text.as_bytes(), &claim(Network::Floonet));
            assert_eq!(verdict, DomainVerdict::Refused(reason), "{text}");
        }
    }

    #[test]
    fn render_parses_back() {
        let keys = [
            DomainKey::from_seed([1; 32]).public(),
            signer().key.public(),
        ];
        let relays = vec![String::from("relay.example.org:443")];
        let text = DomainFile::render(Network::Mainnet, &keys, &relays);
        assert!(text.len() <= DOMAIN_FILE_MAX);
        assert_eq!(
            text,
            format!(
                r#"{{"version":1,"networks":{{"mainnet":{{"domain_keys":["{}","{}"]}}}},"relays":["relay.example.org:443"]}}"#,
                hex::encode(keys[0].as_bytes()),
                hex::encode(keys[1].as_bytes()),
            )
        );
        let file = DomainFile::parse(text.as_bytes()).unwrap();
        assert_eq!(file.keys(Network::Mainnet), Some(keys.as_slice()));
        assert_eq!(file.keys(Network::Floonet), None);
        assert_eq!(file.relays, relays);
        let plain = DomainFile::render(Network::Floonet, &keys[..1], &[]);
        assert!(!plain.contains("relays"));
        assert!(
            DomainFile::parse(plain.as_bytes())
                .unwrap()
                .relays
                .is_empty()
        );
    }

    #[test]
    fn unknown_members_and_networks_are_ignored() {
        let key = hex::encode(signer().key.public().as_bytes());
        let text = format!(
            r#"{{"version":1,"extra":[1],"networks":{{"testnet":5,"floonet":{{"domain_keys":["{key}"],"note":"x"}}}}}}"#
        );
        let file = DomainFile::parse(text.as_bytes()).unwrap();
        assert_eq!(file.networks.len(), 1);
        assert_eq!(file.keys(Network::Floonet).map(<[_]>::len), Some(1));
    }

    #[test]
    fn refusal_reasons_read_in_snake_case() {
        assert_eq!(DomainRefused::FileTooLarge.to_string(), "file_too_large");
        assert_eq!(DomainRefused::NoKeyMatches.to_string(), "no_key_matches");
        assert_eq!(DomainRefused::BadSignature.to_string(), "bad_signature");
        assert_eq!(DomainRefused::KeyNotListed.to_string(), "key_not_listed");
    }

    /// The lepic.v1 bytes of a conformance vector.
    pub(crate) fn code(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/slates_native")
            .join(format!("{name}.json"));
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        hex::unhex(document["expected"]["lepic_v1"].as_str().unwrap()).unwrap()
    }

    fn invoice() -> Vec<u8> {
        code("invoice_file_plain_i1_mainnet")
    }

    fn signed_invoice() -> Vec<u8> {
        signer()
            .sign_request(&invoice(), Network::Mainnet, ISSUED_AT)
            .unwrap()
    }

    fn checked(code: &[u8], file: &str) -> RequestVerdict {
        verify_request(code, file.as_bytes(), Network::Mainnet)
    }

    fn refused(reason: DomainRefused) -> RequestVerdict {
        RequestVerdict::Refused {
            domain: signer().domain,
            reason,
        }
    }

    #[test]
    fn a_signed_request_reads_and_checks() {
        let code = signed_invoice();
        assert!(code.starts_with(&invoice()));
        assert_eq!(
            request_claim(&code),
            Some(Claim {
                domain: signer().domain,
                key: signer().key.public(),
                issued_at: ISSUED_AT,
            })
        );
        assert_eq!(
            checked(&code, &file(Network::Mainnet)),
            RequestVerdict::Checked {
                domain: signer().domain
            }
        );
    }

    /// The signed conformance vectors come from an independent Ed25519 implementation: each
    /// checks, and signing its unsigned part again gives the same bytes.
    #[test]
    fn the_signed_vectors_check_and_sign_the_same() {
        let vector_signer = DomainSigner {
            key: DomainKey::from_seed([0x5a; 32]),
            domain: DomainName::new("shop.example.com").unwrap(),
        };
        let issued_at = 1_795_000_000;
        let file = DomainFile::render(Network::Mainnet, &[vector_signer.key.public()], &[]);
        for name in [
            "tail_signed_invoice_file_plain_i1_mainnet",
            "tail_signed_direct_route_invoice_file_plain_i1_mainnet",
        ] {
            let signed = code(name);
            assert_eq!(
                checked(&signed, &file),
                RequestVerdict::Checked {
                    domain: vector_signer.domain.clone()
                },
                "{name}"
            );
            assert_eq!(
                request_claim(&signed).unwrap().issued_at,
                issued_at,
                "{name}"
            );
            let record_len = 3 + 32 + 8 + 64 + "shop.example.com".len();
            let unsigned = &signed[..signed.len() - record_len];
            assert_eq!(
                vector_signer
                    .sign_request(unsigned, Network::Mainnet, issued_at)
                    .unwrap(),
                signed,
                "{name}"
            );
        }
        let plain = code("tail_signed_invoice_file_plain_i1_mainnet");
        assert_eq!(plain[..invoice().len()], invoice());
        assert_eq!(plain.len(), invoice().len() + 3 + 32 + 8 + 64 + 16);
    }

    #[test]
    fn an_unsigned_or_unreadable_code_is_unsigned() {
        assert_eq!(request_claim(&invoice()), None);
        assert_eq!(
            checked(&invoice(), &file(Network::Mainnet)),
            RequestVerdict::Unsigned
        );
        assert_eq!(request_claim(b"not a slate"), None);
        assert_eq!(
            checked(b"not a slate", &file(Network::Mainnet)),
            RequestVerdict::Unsigned
        );
    }

    #[test]
    fn a_request_with_a_bad_signature_is_refused() {
        let mut code = signed_invoice();
        let domain = signer().domain.as_str().len();
        let signature_at = code.len() - domain - 64;
        code[signature_at] ^= 0x01;
        assert!(request_claim(&code).is_some());
        assert_eq!(
            checked(&code, &file(Network::Mainnet)),
            refused(DomainRefused::BadSignature)
        );
        // Signed on mainnet, checked as floonet.
        assert_eq!(
            verify_request(
                &signed_invoice(),
                file(Network::Floonet).as_bytes(),
                Network::Floonet
            ),
            refused(DomainRefused::BadSignature)
        );
    }

    #[test]
    fn a_request_is_refused_by_the_file() {
        let code = signed_invoice();
        let unlisted = DomainFile::render(
            Network::Mainnet,
            &[DomainKey::from_seed([1; 32]).public()],
            &[],
        );
        assert_eq!(
            checked(&code, &unlisted),
            refused(DomainRefused::KeyNotListed)
        );
        assert_eq!(
            checked(&code, &file(Network::Floonet)),
            refused(DomainRefused::NetworkAbsent)
        );
        assert_eq!(
            checked(&code, "not json"),
            refused(DomainRefused::FileMalformed)
        );
        let mut large = file(Network::Mainnet);
        large.push_str(&" ".repeat(DOMAIN_FILE_MAX));
        assert_eq!(checked(&code, &large), refused(DomainRefused::FileTooLarge));
        let key = hex::encode(signer().key.public().as_bytes());
        let version =
            format!(r#"{{"version":2,"networks":{{"mainnet":{{"domain_keys":["{key}"]}}}}}}"#);
        assert_eq!(
            checked(&code, &version),
            refused(DomainRefused::UnsupportedVersion)
        );
    }

    #[test]
    fn only_an_unsigned_i1_of_the_network_is_signed() {
        let signer = signer();
        assert_eq!(
            signer.sign_request(b"not a slate", Network::Mainnet, ISSUED_AT),
            Err(RequestSignError::Malformed)
        );
        assert_eq!(
            signer.sign_request(
                &code("send_file_plain_s1_mainnet"),
                Network::Mainnet,
                ISSUED_AT
            ),
            Err(RequestSignError::NotAnInvoice)
        );
        assert_eq!(
            signer.sign_request(&signed_invoice(), Network::Mainnet, ISSUED_AT),
            Err(RequestSignError::AlreadySigned)
        );
        assert_eq!(
            signer.sign_request(&invoice(), Network::Floonet, ISSUED_AT),
            Err(RequestSignError::Network)
        );
    }
}
