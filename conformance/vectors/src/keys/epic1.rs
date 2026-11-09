// SPDX-License-Identifier: Apache-2.0
//! The epic1 address and the epic1 payment link (RFC 0003 §5.13, §5.14 and Appendix B).
//!
//! The text codes come from the generator's own bech32m and percent-encoding, written here and
//! sharing nothing with the product crate. The keys are published test data (RFC 8032 section 7.1
//! public keys for the proof half, RFC 7748 section 6.1 public keys for the seal half). The
//! Epicbox mailbox keys come from the wallet's address code, which is the reference for their
//! base58 form and version bytes on each network.

// A text codec written for independence, in the plain style of its specification.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]

use epic_keychain::Keychain;
use epic_util::secp::key::{PublicKey, SecretKey};
use serde::Serialize;

use super::address::epicbox_form;
use super::{AREA, KeysPins, Network, SEED_32, keychain};
use crate::{Error, Rendered, render};

/// bech32 alphabet, BIP 173.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The bech32m checksum constant, BIP 350.
const BECH32M: u32 = 0x2bc8_30a3;

const PROOF_KEYS: [(&str, &str); 2] = [
    (
        "rfc8032_1",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "rfc8032_2",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
];
const SEAL_KEYS: [(&str, &str); 2] = [
    (
        "rfc7748_alice",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    ),
    (
        "rfc7748_bob",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ),
];
/// The all-zero u-coordinate, a point of order 4 on Curve25519.
const SMALL_ORDER_SEAL: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Fixed secp256k1 secrets for the mailbox keys.
const MAILBOX_SECRETS: [u8; 3] = [0x11, 0x22, 0x33];

fn hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "epic",
        Network::Floonet => "tepic",
    }
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|at| text.get(at..at + 2))
        .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
        .collect()
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (bit, generator) in GEN.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

/// Regroups 8-bit bytes into 5-bit values, padding the last group with zeros.
fn to_five_bits(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in data {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let values = to_five_bits(data);
    let mut all = hrp_expand(hrp);
    all.extend(&values);
    all.extend([0u8; 6]);
    let checksum = polymod(&all) ^ BECH32M;
    let mut text = format!("{hrp}1");
    for value in &values {
        text.push(char::from(CHARSET[usize::from(*value)]));
    }
    for at in 0..6 {
        let value = (checksum >> (5 * (5 - at))) & 31;
        text.push(char::from(CHARSET[value as usize]));
    }
    text
}

fn address_data(version: u8, proof: &str, seal: &str) -> Vec<u8> {
    let mut data = vec![version];
    data.extend(from_hex(proof));
    data.extend(from_hex(seal));
    data
}

fn address_text(network: Network, version: u8, proof: &str, seal: &str) -> String {
    bech32m_encode(hrp(network), &address_data(version, proof, seal))
}

fn other(network: Network) -> Network {
    match network {
        Network::Mainnet => Network::Floonet,
        Network::Floonet => Network::Mainnet,
    }
}

#[derive(Serialize)]
struct KeyInputs {
    proof_keys: Vec<Named>,
    seal_keys: Vec<Named>,
}

#[derive(Serialize)]
struct Named {
    name: &'static str,
    key: &'static str,
}

#[derive(Serialize)]
struct AddressCase {
    proof_key: &'static str,
    seal_key: &'static str,
    mainnet: String,
    floonet: String,
}

#[derive(Serialize)]
struct AddressExpected {
    cases: Vec<AddressCase>,
}

/// `refusal` is one of `mixed_case`, `checksum`, `version`, `network`, `seal_key`, `length`.
#[derive(Serialize)]
struct Refused {
    name: &'static str,
    text: String,
    network: &'static str,
    refusal: &'static str,
}

#[derive(Serialize)]
struct RefusedInputs {
    note: &'static str,
}

#[derive(Serialize)]
struct RefusedExpected {
    cases: Vec<Refused>,
}

fn named(list: &[(&'static str, &'static str)]) -> Vec<Named> {
    list.iter().map(|(name, key)| Named { name, key }).collect()
}

fn addresses() -> Result<Vec<AddressCase>, Error> {
    let mut cases = Vec::new();
    for (_, proof) in PROOF_KEYS {
        for (_, seal) in SEAL_KEYS {
            cases.push(AddressCase {
                proof_key: proof,
                seal_key: seal,
                mainnet: address_text(Network::Mainnet, 1, proof, seal),
                floonet: address_text(Network::Floonet, 1, proof, seal),
            });
        }
    }
    Ok(cases)
}

fn refused() -> Vec<Refused> {
    let (proof, seal) = (PROOF_KEYS[0].1, SEAL_KEYS[0].1);
    let good = address_text(Network::Mainnet, 1, proof, seal);
    let mixed = {
        let mut text = good.clone();
        text.replace_range(10..11, &text[10..11].to_uppercase());
        text
    };
    let bad_checksum = {
        let mut text = good.clone();
        let last = text.pop().unwrap_or('q');
        text.push(if last == 'q' { 'p' } else { 'q' });
        text
    };
    let mut short = address_data(1, proof, seal);
    short.pop();
    vec![
        Refused {
            name: "mixed_case",
            text: mixed,
            network: "mainnet",
            refusal: "mixed_case",
        },
        Refused {
            name: "bad_checksum",
            text: bad_checksum,
            network: "mainnet",
            refusal: "checksum",
        },
        Refused {
            name: "version_00",
            text: address_text(Network::Mainnet, 0, proof, seal),
            network: "mainnet",
            refusal: "version",
        },
        Refused {
            name: "version_02",
            text: address_text(Network::Mainnet, 2, proof, seal),
            network: "mainnet",
            refusal: "version",
        },
        Refused {
            name: "floonet_read_as_mainnet",
            text: address_text(Network::Floonet, 1, proof, seal),
            network: "mainnet",
            refusal: "network",
        },
        Refused {
            name: "mainnet_read_as_floonet",
            text: good,
            network: "floonet",
            refusal: "network",
        },
        Refused {
            name: "small_order_seal_key",
            text: address_text(Network::Mainnet, 1, proof, SMALL_ORDER_SEAL),
            network: "mainnet",
            refusal: "seal_key",
        },
        Refused {
            name: "one_byte_short",
            text: bech32m_encode("epic", &short),
            network: "mainnet",
            refusal: "length",
        },
    ]
}

// Links.

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02x}"));
        }
    }
    out
}

/// `1`, `1.5` or `.25` in base units, 8 decimals, by string arithmetic.
fn amount_units(text: &str) -> String {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = format!("{whole}{fraction:0<8}");
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

struct Mailbox {
    mainnet: String,
    floonet: String,
}

fn mailboxes(pins: &KeysPins<'_>) -> Result<Vec<Mailbox>, Error> {
    let _ = pins;
    let keychain = keychain(&SEED_32, Network::Mainnet)?;
    let secp = keychain.secp();
    MAILBOX_SECRETS
        .iter()
        .map(|byte| {
            let secret = SecretKey::from_slice(secp, &[*byte; 32])
                .map_err(Error::reference("mailbox secret"))?;
            let public = PublicKey::from_secret_key(secp, &secret)
                .map_err(Error::reference("mailbox public key"))?;
            Ok(Mailbox {
                mainnet: epicbox_form(Network::Mainnet, public)?.public_key,
                floonet: epicbox_form(Network::Floonet, public)?.public_key,
            })
        })
        .collect()
}

#[derive(Serialize)]
struct Hop {
    mailbox: String,
    relay: &'static str,
    port: Option<u16>,
}

/// `outcome` is `link` or `refused`; a refused link has `reason`. `skipped` lists what a read link
/// left out: `transport_network` for a mailbox of the other network, `transports_over_limit` for
/// entries after the third.
#[derive(Serialize)]
struct LinkCase {
    name: &'static str,
    text: String,
    network: &'static str,
    outcome: &'static str,
    reason: Option<&'static str>,
    address: Option<String>,
    transports: Vec<Hop>,
    skipped: Vec<&'static str>,
    amount_units: Option<String>,
    message: Option<&'static str>,
    can_pay: bool,
}

#[derive(Serialize)]
struct LinkExpected {
    cases: Vec<LinkCase>,
}

#[derive(Serialize)]
struct LinkInputs {
    note: &'static str,
}

fn hop_param(hop: &Hop) -> String {
    let port = hop.port.map(|p| format!(":{p}")).unwrap_or_default();
    format!("epicbox={}@{}{port}", hop.mailbox, hop.relay)
}

fn link_cases(boxes: &[Mailbox]) -> Vec<LinkCase> {
    let (proof, seal) = (PROOF_KEYS[0].1, SEAL_KEYS[0].1);
    let mut cases = Vec::new();
    for network in Network::ALL {
        let label = network.name();
        let address = address_text(network, 1, proof, seal);
        let mailbox = |at: usize| -> String {
            match (network, boxes.get(at)) {
                (Network::Mainnet, Some(b)) => b.mainnet.clone(),
                (Network::Floonet, Some(b)) => b.floonet.clone(),
                _ => String::new(),
            }
        };
        let hops = |count: usize| -> Vec<Hop> {
            [
                (0, "relay.example.org", None),
                (1, "relay.example.net", Some(8443)),
                (2, "203.0.113.7", Some(443)),
            ]
            .into_iter()
            .take(count)
            .map(|(at, relay, port)| Hop {
                mailbox: mailbox(at),
                relay,
                port,
            })
            .collect()
        };
        let uri = |hops: &[Hop], tail: &str| -> String {
            let mut text = format!("epic:{address}");
            let mut first = true;
            for hop in hops {
                text.push(if first { '?' } else { '&' });
                first = false;
                text.push_str(&hop_param(hop));
            }
            if !tail.is_empty() {
                text.push(if first { '?' } else { '&' });
                text.push_str(tail);
            }
            text
        };
        let message = "Rent for May & June";
        let tail = format!("amount=1.5&message={}", percent_encode(message));
        let one = hops(1);
        cases.push(LinkCase {
            name: leak(format!("one_transport_{label}")),
            text: uri(&one, &tail),
            network: label,
            outcome: "link",
            reason: None,
            address: Some(address.clone()),
            transports: one,
            skipped: vec![],
            amount_units: Some(amount_units("1.5")),
            message: Some(message),
            can_pay: true,
        });
        let three = hops(3);
        cases.push(LinkCase {
            name: leak(format!("three_transports_{label}")),
            text: uri(&three, ""),
            network: label,
            outcome: "link",
            reason: None,
            address: Some(address.clone()),
            transports: three,
            skipped: vec![],
            amount_units: None,
            message: None,
            can_pay: true,
        });
        // A fourth entry is not read.
        let mut text = uri(&hops(3), "");
        text.push_str(&format!("&epicbox={}@relay.example.com", mailbox(0)));
        cases.push(LinkCase {
            name: leak(format!("fourth_transport_left_out_{label}")),
            text,
            network: label,
            outcome: "link",
            reason: None,
            address: Some(address.clone()),
            transports: hops(3),
            skipped: vec!["transports_over_limit"],
            amount_units: None,
            message: None,
            can_pay: true,
        });
        // A mailbox of the other network is not usable; the link has no transport left.
        let wrong = match (network, boxes.first()) {
            (Network::Mainnet, Some(b)) => b.floonet.clone(),
            (Network::Floonet, Some(b)) => b.mainnet.clone(),
            _ => String::new(),
        };
        cases.push(LinkCase {
            name: leak(format!("mailbox_of_other_network_{label}")),
            text: format!("epic:{address}?epicbox={wrong}@relay.example.org"),
            network: label,
            outcome: "link",
            reason: None,
            address: Some(address.clone()),
            transports: vec![],
            skipped: vec!["transport_network"],
            amount_units: None,
            message: None,
            can_pay: false,
        });
        // An Epicbox link that carries an epic1 parameter is not an epic1 link.
        cases.push(LinkCase {
            name: leak(format!("epicbox_link_with_epic1_{label}")),
            text: format!(
                "epic:{}@relay.example.org?epic1={address}&amount=1",
                mailbox(0)
            ),
            network: label,
            outcome: "refused",
            reason: Some("not_an_epic1_link"),
            address: None,
            transports: vec![],
            skipped: vec![],
            amount_units: None,
            message: None,
            can_pay: false,
        });
    }
    cases
}

/// Vector case names are `&'static str` in the shared shape; the generator is a short-lived
/// process, so leaking a handful of names is harmless.
fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let boxes = mailboxes(pins)?;
    Ok(vec![
        render(
            AREA,
            "epic1_addresses",
            &pins.wallet,
            KeyInputs {
                proof_keys: named(&PROOF_KEYS),
                seal_keys: named(&SEAL_KEYS),
            },
            AddressExpected {
                cases: addresses()?,
            },
        )?,
        render(
            AREA,
            "epic1_addresses_refused",
            &pins.wallet,
            RefusedInputs {
                note: "built from the first proof key and the first seal key",
            },
            RefusedExpected { cases: refused() },
        )?,
        render(
            AREA,
            "epic1_links",
            &pins.wallet,
            LinkInputs {
                note: "address from the first proof key and the first seal key; mailboxes from the secp256k1 secrets 0x11.., 0x22.., 0x33..",
            },
            LinkExpected {
                cases: link_cases(&boxes),
            },
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP 350 valid strings, which the generator's checksum must reproduce.
    #[test]
    fn bech32m_matches_bip_350() {
        assert_eq!(bech32m_encode("a", &[]), "a1lqfn3a");
    }

    #[test]
    fn amounts_in_base_units() {
        assert_eq!(amount_units("1.5"), "150000000");
        assert_eq!(amount_units("0.00000001"), "1");
    }
}
