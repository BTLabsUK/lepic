// SPDX-License-Identifier: Apache-2.0
//! Replays the epic1 address and link vectors in `testdata/vectors/keys`, written by the
//! generator's own bech32m and percent-encoding (RFC 0003 §5.13, §5.14, Appendix B).

// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use lepic_crypto::PublicKey;
use lepic_epic1::{
    Delivery, Epic1Address, Epic1Error, Epic1Link, LinkError, Network, Skipped, TransportFault,
    bech32m::Bech32Error,
};
use lepic_epicbox::EpicboxAddress;
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/keys")
        .join(format!("{name}.json"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(document["area"], "keys", "{name}: area");
    assert_eq!(document["name"], name, "{name}: name");
    document["expected"]["cases"].clone()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is text"))
}

fn network(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "floonet" => Network::Floonet,
        other => panic!("unknown network {other}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn addresses_encode_and_decode_as_the_vectors_say() {
    let cases = vectors("epic1_addresses");
    assert!(!cases.as_array().unwrap().is_empty());
    for case in cases.as_array().unwrap() {
        for (name, net) in [("mainnet", Network::Mainnet), ("floonet", Network::Floonet)] {
            let address = Epic1Address::decode(text(case, name), net).unwrap();
            assert_eq!(hex(address.proof_key().as_bytes()), text(case, "proof_key"));
            assert_eq!(hex(address.seal_key().as_bytes()), text(case, "seal_key"));
            assert_eq!(address.network(), net);
            assert_eq!(address.encode(), text(case, name));
            assert_eq!(Epic1Address::decode_any(text(case, name)).unwrap(), address);
        }
    }
}

#[test]
fn malformed_addresses_give_the_named_refusal() {
    let cases = vectors("epic1_addresses_refused");
    assert!(!cases.as_array().unwrap().is_empty());
    for case in cases.as_array().unwrap() {
        let name = text(case, "name");
        let error = Epic1Address::decode(text(case, "text"), network(text(case, "network")))
            .expect_err(name);
        let matched = match text(case, "refusal") {
            "mixed_case" => matches!(error, Epic1Error::Bech32(Bech32Error::MixedCase)),
            "checksum" => matches!(error, Epic1Error::Bech32(Bech32Error::Checksum)),
            "version" => matches!(error, Epic1Error::Version { .. }),
            "network" => matches!(error, Epic1Error::WrongNetwork { .. }),
            "seal_key" => matches!(error, Epic1Error::SealKey(_)),
            "length" => matches!(error, Epic1Error::Length { .. }),
            other => panic!("unknown refusal {other}"),
        };
        assert!(matched, "{name}: {error:?}");
    }
}

#[test]
fn links_read_as_the_vectors_say() {
    let cases = vectors("epic1_links");
    assert!(!cases.as_array().unwrap().is_empty());
    for case in cases.as_array().unwrap() {
        let name = text(case, "name");
        let net = network(text(case, "network"));
        let parsed = Epic1Link::parse(text(case, "text"));
        if text(case, "outcome") == "refused" {
            assert!(
                matches!(parsed, Err(LinkError::NotAnEpic1Link)),
                "{name}: {parsed:?}"
            );
            assert_eq!(text(case, "reason"), "not_an_epic1_link");
            continue;
        }
        let link = parsed.expect(name);
        assert_eq!(
            link.address.encode(),
            text(case, "address"),
            "{name}: address"
        );
        assert_eq!(link.address.network(), net, "{name}: network");

        let expected = case["transports"].as_array().unwrap();
        assert_eq!(link.transports.len(), expected.len(), "{name}: transports");
        for (read, want) in link.transports.iter().zip(expected) {
            let mailbox: PublicKey = EpicboxAddress::parse_key(text(want, "mailbox"), net).unwrap();
            assert_eq!(read.mailbox(), &mailbox, "{name}: mailbox");
            assert_eq!(read.relay().as_str(), text(want, "relay"), "{name}: relay");
            assert_eq!(
                read.port(),
                want["port"]
                    .as_u64()
                    .map(|port| u16::try_from(port).unwrap()),
                "{name}: port"
            );
        }

        let skipped: Vec<&str> = link
            .ignored
            .iter()
            .filter_map(|skip| match skip {
                Skipped::Transport {
                    fault: TransportFault::Network,
                    ..
                } => Some("transport_network"),
                Skipped::TransportsOverLimit { .. } => Some("transports_over_limit"),
                _ => None,
            })
            .collect();
        let want_skipped: Vec<&str> = case["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|reason| reason.as_str().unwrap())
            .collect();
        assert_eq!(skipped, want_skipped, "{name}: skipped");

        assert_eq!(
            link.amount.map(|amount| amount.value().to_string()),
            case["amount_units"].as_str().map(str::to_owned),
            "{name}: amount"
        );
        assert_eq!(
            link.message.as_deref(),
            case["message"].as_str(),
            "{name}: message"
        );
        let can_pay = matches!(link.delivery(), Delivery::Usable(_));
        assert_eq!(
            can_pay,
            case["can_pay"].as_bool().unwrap(),
            "{name}: can pay"
        );
    }
}
