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

use std::collections::BTreeMap;
use std::fmt;

use lepic_contact::{DomainClaim, DomainKey, DomainName, Network, VerifyingKey};
use serde::Deserialize;

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

impl fmt::Debug for DomainSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainSigner")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
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
    }
}
