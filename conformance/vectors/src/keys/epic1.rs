// SPDX-License-Identifier: Apache-2.0
//! The epic1 address and the epic1 payment link (RFC 0003 §5.13, §5.14 and Appendix B).
//!
//! The text codes come from the generator's own bech32m and percent-encoding, written here and
//! sharing nothing with the product crate. The keys are published test data (RFC 7748 section
//! 6.1 public keys for the seal half, the secp256k1 base point G and 2G for the delivery half). The
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
/// Compressed secp256k1 points: the base point G and 2G.
const DELIVERY_KEYS: [(&str, &str); 2] = [
    (
        "secp256k1_g",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    (
        "secp256k1_2g",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    ),
];
/// G's x-coordinate under the uncompressed prefix 04, 33 bytes.
const DELIVERY_PREFIX_04: &str =
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// x = 5: x^3 + 7 is not a square mod p, so no point of secp256k1 has it.
const DELIVERY_OFF_CURVE: &str =
    "020000000000000000000000000000000000000000000000000000000000000005";
/// The all-zero u-coordinate, a point of order 4 on Curve25519.
const SMALL_ORDER_SEAL: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Fixed secp256k1 secrets for the mailbox keys.
const MAILBOX_SECRETS: [u8; 2] = [0x11, 0x22];

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

fn address_data(version: u8, seal: &str, delivery: &str) -> Vec<u8> {
    let mut data = vec![version];
    data.extend(from_hex(seal));
    data.extend(from_hex(delivery));
    data
}

fn address_text(network: Network, version: u8, seal: &str, delivery: &str) -> String {
    bech32m_encode(hrp(network), &address_data(version, seal, delivery))
}

#[derive(Serialize)]
struct KeyInputs {
    seal_keys: Vec<Named>,
    delivery_keys: Vec<Named>,
}

#[derive(Serialize)]
struct Named {
    name: &'static str,
    key: &'static str,
}

#[derive(Serialize)]
struct AddressCase {
    seal_key: &'static str,
    delivery_key: &'static str,
    mainnet: String,
    floonet: String,
}

#[derive(Serialize)]
struct AddressExpected {
    cases: Vec<AddressCase>,
}

/// `refusal` is one of `mixed_case`, `checksum`, `version`, `network`, `seal_key`,
/// `delivery_key`, `length`.
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
    for (_, seal) in SEAL_KEYS {
        for (_, delivery) in DELIVERY_KEYS {
            cases.push(AddressCase {
                seal_key: seal,
                delivery_key: delivery,
                mainnet: address_text(Network::Mainnet, 1, seal, delivery),
                floonet: address_text(Network::Floonet, 1, seal, delivery),
            });
        }
    }
    Ok(cases)
}

fn refused() -> Vec<Refused> {
    let (seal, delivery) = (SEAL_KEYS[0].1, DELIVERY_KEYS[0].1);
    let good = address_text(Network::Mainnet, 1, seal, delivery);
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
    // The version, a seal key and 32 more bytes: the length of an address made by 0.6.0.
    let mut earlier = address_data(1, seal, delivery);
    earlier.pop();
    let mut long = address_data(1, seal, delivery);
    long.push(0);
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
            text: address_text(Network::Mainnet, 0, seal, delivery),
            network: "mainnet",
            refusal: "version",
        },
        Refused {
            name: "version_02",
            text: address_text(Network::Mainnet, 2, seal, delivery),
            network: "mainnet",
            refusal: "version",
        },
        Refused {
            name: "floonet_read_as_mainnet",
            text: address_text(Network::Floonet, 1, seal, delivery),
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
            text: address_text(Network::Mainnet, 1, SMALL_ORDER_SEAL, delivery),
            network: "mainnet",
            refusal: "seal_key",
        },
        Refused {
            name: "delivery_key_prefix_04",
            text: address_text(Network::Mainnet, 1, seal, DELIVERY_PREFIX_04),
            network: "mainnet",
            refusal: "delivery_key",
        },
        Refused {
            name: "delivery_key_off_curve",
            text: address_text(Network::Mainnet, 1, seal, DELIVERY_OFF_CURVE),
            network: "mainnet",
            refusal: "delivery_key",
        },
        Refused {
            name: "earlier_length",
            text: bech32m_encode("epic", &earlier),
            network: "mainnet",
            refusal: "length",
        },
        Refused {
            name: "one_byte_long",
            text: bech32m_encode("epic", &long),
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
struct Route {
    method: &'static str,
    value: String,
}

/// `outcome` is `link` or `refused`; a refused link has `reason`: `not_an_epic1_link`, or
/// `too_many_entries` for more than three `http` and `tor` entries, usable or not. `routes` are
/// the route entries read, in link order, with canonical values. `skipped` lists what a read link
/// left out, in link order: `epicbox` for each `epicbox` entry, which a link no longer carries
/// (the address's delivery key is its mailbox), and `transport_http` and `transport_onion` for an
/// `http` or `tor` value out of form.
#[derive(Serialize)]
struct LinkCase {
    name: &'static str,
    text: String,
    network: &'static str,
    outcome: &'static str,
    reason: Option<&'static str>,
    address: Option<String>,
    routes: Vec<Route>,
    skipped: Vec<&'static str>,
    amount_units: Option<String>,
    message: Option<&'static str>,
}

#[derive(Serialize)]
struct LinkExpected {
    cases: Vec<LinkCase>,
}

#[derive(Serialize)]
struct LinkInputs {
    note: &'static str,
}

fn route(method: &'static str, value: &str) -> Route {
    Route {
        method,
        value: value.to_owned(),
    }
}

/// A v3 onion name with a valid checksum, and the same name with one checksum character changed.
const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
const ONION_WRONG_CHECKSUM: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4psaryd.onion";

fn link_cases(boxes: &[Mailbox]) -> Vec<LinkCase> {
    let (seal, delivery) = (SEAL_KEYS[0].1, DELIVERY_KEYS[0].1);
    let mut cases = Vec::new();
    for network in Network::ALL {
        let label = network.name();
        let address = address_text(network, 1, seal, delivery);
        let mailbox = |at: usize| -> String {
            match (network, boxes.get(at)) {
                (Network::Mainnet, Some(b)) => b.mainnet.clone(),
                (Network::Floonet, Some(b)) => b.floonet.clone(),
                _ => String::new(),
            }
        };
        // An `epicbox` entry as an earlier release wrote it: `<mailbox>@<relay>[:<port>]`.
        let epicbox = |at: usize, relay: &str| format!("epicbox={}@{relay}", mailbox(at));
        let link = |name: String,
                    text: String,
                    routes: Vec<Route>,
                    skipped: Vec<&'static str>,
                    amount: Option<&str>,
                    message: Option<&'static str>| LinkCase {
            name: leak(format!("{name}_{label}")),
            text,
            network: label,
            outcome: "link",
            reason: None,
            address: Some(address.clone()),
            routes,
            skipped,
            amount_units: amount.map(amount_units),
            message,
        };
        let refused = |name: String, text: String, reason: &'static str| LinkCase {
            name: leak(format!("{name}_{label}")),
            text,
            network: label,
            outcome: "refused",
            reason: Some(reason),
            address: None,
            routes: vec![],
            skipped: vec![],
            amount_units: None,
            message: None,
        };
        let message = "Rent for May & June";
        cases.push(link(
            "one_route".into(),
            format!(
                "epic:{address}?http=pay.example.org&amount=1.5&message={}",
                percent_encode(message)
            ),
            vec![route("http", "pay.example.org")],
            vec![],
            Some("1.5"),
            Some(message),
        ));
        cases.push(link(
            "three_routes".into(),
            format!("epic:{address}?http=pay.example.org&tor={ONION}:8080&http=203.0.113.7:443"),
            vec![
                route("http", "pay.example.org"),
                route("tor", &format!("{ONION}:8080")),
                route("http", "203.0.113.7:443"),
            ],
            vec![],
            None,
            None,
        ));
        cases.push(refused(
            "fourth_entry_refused".into(),
            format!(
                "epic:{address}?http=pay.example.org&tor={ONION}&http=pay.example.net&tor={ONION}:8080"
            ),
            "too_many_entries",
        ));
        // The bound counts entries out of form too.
        cases.push(refused(
            "fourth_entry_out_of_form_refused".into(),
            format!(
                "epic:{address}?http=pay.example.org&tor={ONION}&http=pay.example.net&tor=pay.example.com"
            ),
            "too_many_entries",
        ));
        // A link of an earlier release: its `epicbox` entries are left out and reported.
        cases.push(link(
            "epicbox_entries_left_out".into(),
            format!(
                "epic:{address}?{}&{}&amount=1.5",
                epicbox(0, "relay.example.org"),
                epicbox(1, "relay.example.net:8443")
            ),
            vec![],
            vec!["epicbox", "epicbox"],
            Some("1.5"),
            None,
        ));
        cases.push(link(
            "http_beside_epicbox".into(),
            format!(
                "epic:{address}?http=Pay.Example.org&{}&amount=1.5",
                epicbox(0, "relay.example.org")
            ),
            vec![route("http", "pay.example.org")],
            vec!["epicbox"],
            Some("1.5"),
            None,
        ));
        cases.push(link(
            "tor_beside_epicbox".into(),
            format!(
                "epic:{address}?{}&tor={ONION}:8080",
                epicbox(1, "relay.example.net:8443")
            ),
            vec![route("tor", &format!("{ONION}:8080"))],
            vec!["epicbox"],
            None,
            None,
        ));
        cases.push(link(
            "http_alone".into(),
            format!("epic:{address}?http=pay.example.org:8443&amount=.25"),
            vec![route("http", "pay.example.org:8443")],
            vec![],
            Some(".25"),
            None,
        ));
        cases.push(link(
            "tor_alone".into(),
            format!("epic:{address}?tor={ONION}"),
            vec![route("tor", ONION)],
            vec![],
            None,
            None,
        ));
        // The reader checks the form of a tor value only; the poster checks the checksum.
        cases.push(link(
            "tor_wrong_checksum_read_as_the_checksum_is_the_posters_check".into(),
            format!("epic:{address}?tor={ONION_WRONG_CHECKSUM}"),
            vec![route("tor", ONION_WRONG_CHECKSUM)],
            vec![],
            None,
            None,
        ));
        cases.push(link(
            "http_and_tor_values_out_of_form".into(),
            format!(
                "epic:{address}?http={}&tor={}&{}",
                percent_encode("https://pay.example.org"),
                ONION.to_ascii_uppercase(),
                epicbox(0, "relay.example.org")
            ),
            vec![],
            vec!["transport_http", "transport_onion", "epicbox"],
            None,
            None,
        ));
        cases.push(link(
            "tor_and_http_values_out_of_form_only".into(),
            format!(
                "epic:{address}?tor={ONION}/inbox&http={}",
                percent_encode("pay.example.org:0")
            ),
            vec![],
            vec!["transport_onion", "transport_http"],
            None,
            None,
        ));
        // The bound of three counts `http` and `tor` entries; `epicbox` entries do not count.
        cases.push(link(
            "route_bound_leaves_out_epicbox".into(),
            format!(
                "epic:{address}?http=pay.example.org&{}&tor={ONION}&{}&http=pay.example.net",
                epicbox(0, "relay.example.org"),
                epicbox(1, "relay.example.net")
            ),
            vec![
                route("http", "pay.example.org"),
                route("tor", ONION),
                route("http", "pay.example.net"),
            ],
            vec!["epicbox", "epicbox"],
            None,
            None,
        ));
        // An Epicbox link that carries an epic1 parameter is not an epic1 link.
        cases.push(refused(
            "epicbox_link_with_epic1".into(),
            format!(
                "epic:{}@relay.example.org?epic1={address}&amount=1",
                mailbox(0)
            ),
            "not_an_epic1_link",
        ));
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
                seal_keys: named(&SEAL_KEYS),
                delivery_keys: named(&DELIVERY_KEYS),
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
                note: "built from the first seal key and the first delivery key",
            },
            RefusedExpected { cases: refused() },
        )?,
        render(
            AREA,
            "epic1_links",
            &pins.wallet,
            LinkInputs {
                note: "address from the first seal key and the first delivery key; the epicbox entries name mailboxes from the secp256k1 secrets 0x11.., 0x22..",
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
