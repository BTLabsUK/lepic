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

use lepic_epic1::{
    Epic1Address, Epic1Error, Epic1Link, LinkError, MAX_TRANSPORTS, Network, Skipped,
    TransportFault, bech32m::Bech32Error, parse_host_port, receipt,
};
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

/// Each address case on `net`: decoded, its keys and length as the vector says, written back.
fn addresses_on(name: &str, net: Network, length: usize) {
    let cases = vectors("epic1_addresses");
    assert!(!cases.as_array().unwrap().is_empty());
    for case in cases.as_array().unwrap() {
        let written = text(case, name);
        assert_eq!(written.len(), length, "{written}");
        let address = Epic1Address::decode(written, net).unwrap();
        assert_eq!(hex(address.seal_key().as_bytes()), text(case, "seal_key"));
        assert_eq!(
            hex(&address.delivery_key().to_bytes()),
            text(case, "delivery_key")
        );
        assert_eq!(address.network(), net);
        assert_eq!(address.encode(), written);
        assert_eq!(Epic1Address::decode_any(written).unwrap(), address);
    }
}

#[test]
fn address_mainnet() {
    addresses_on("mainnet", Network::Mainnet, 117);
}

#[test]
fn address_floonet() {
    addresses_on("floonet", Network::Floonet, 118);
}

/// The refused case `name`, read on its network.
fn refused(name: &str) -> Epic1Error {
    let cases = vectors("epic1_addresses_refused");
    let case = cases
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"));
    match Epic1Address::decode(text(case, "text"), network(text(case, "network"))) {
        Ok(_) => panic!("case {name} was read"),
        Err(error) => error,
    }
}

#[test]
fn an_address_of_the_earlier_length_is_refused() {
    let error = refused("earlier_length");
    assert_eq!(error, Epic1Error::EarlierAddress);
    let text = error.to_string();
    assert!(text.contains("expected 66"), "{text}");
    assert!(text.contains("older wallet version"), "{text}");
    assert!(text.contains("Epicbox address"), "{text}");
}

#[test]
fn address_with_a_bad_delivery_key() {
    for name in ["delivery_key_prefix_04", "delivery_key_off_curve"] {
        let error = refused(name);
        assert!(
            matches!(error, Epic1Error::DeliveryKey(_)),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn upper_case_reads_as_lower_case() {
    let cases = vectors("epic1_addresses");
    for case in cases.as_array().unwrap() {
        for (name, net) in [("mainnet", Network::Mainnet), ("floonet", Network::Floonet)] {
            let lower = text(case, name);
            let upper = Epic1Address::decode(&lower.to_uppercase(), net).unwrap();
            assert_eq!(upper, Epic1Address::decode(lower, net).unwrap());
            assert_eq!(upper.encode(), lower);
            assert_eq!(
                Epic1Address::decode_any(&upper.to_string().to_uppercase()).unwrap(),
                upper
            );
        }
    }
}

#[test]
fn mixed_case_is_refused() {
    assert_eq!(
        refused("mixed_case"),
        Epic1Error::Bech32(Bech32Error::MixedCase)
    );
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
            "delivery_key" => matches!(error, Epic1Error::DeliveryKey(_)),
            // The earlier release's length has a refusal of its own.
            "length" => matches!(
                error,
                Epic1Error::Length { .. } | Epic1Error::EarlierAddress
            ),
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
            let matched = match text(case, "reason") {
                "not_an_epic1_link" => matches!(parsed, Err(LinkError::NotAnEpic1Link)),
                "too_many_entries" => matches!(
                    parsed,
                    Err(LinkError::TooManyEntries {
                        max: MAX_TRANSPORTS,
                        ..
                    })
                ),
                other => panic!("unknown refusal {other}"),
            };
            assert!(matched, "{name}: {parsed:?}");
            continue;
        }
        let link = parsed.expect(name);
        assert_eq!(
            link.address.encode(),
            text(case, "address"),
            "{name}: address"
        );
        assert_eq!(link.address.network(), net, "{name}: network");

        let routes: Vec<(&str, &str)> = link
            .routes
            .iter()
            .map(|entry| (entry.method.as_str(), entry.value.as_str()))
            .collect();
        let want_routes: Vec<(&str, &str)> = case["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| (text(entry, "method"), text(entry, "value")))
            .collect();
        assert_eq!(routes, want_routes, "{name}: routes");

        let skipped: Vec<&str> = link
            .ignored
            .iter()
            .filter_map(|skip| match skip {
                Skipped::Epicbox => Some("epicbox"),
                Skipped::Transport {
                    fault: TransportFault::Http(_),
                    ..
                } => Some("transport_http"),
                Skipped::Transport {
                    fault: TransportFault::Onion,
                    ..
                } => Some("transport_onion"),
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
    }
}

/// The relay hosts every LEPIC parser shares, from the epic-pairing-kit generator. epic1 keeps
/// the host lower-cased.
#[test]
fn relay_hosts_match_the_shared_cases() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/pairing/epictx_relay_hosts.json");
    let document: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let cases = document["vectors"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let relay = text(case, "relay");
        let parsed = parse_host_port(relay);
        assert_eq!(
            parsed.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            text(case, "name")
        );
        if let Ok((host, _)) = parsed {
            let name = relay.split(':').next().unwrap();
            assert_eq!(host.as_str(), name.to_ascii_lowercase());
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "{text}");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn array<const N: usize>(value: &Value, key: &str) -> [u8; N] {
    unhex(text(value, key)).try_into().unwrap()
}

fn public_key(value: &Value, key: &str) -> lepic_crypto::PublicKey {
    lepic_crypto::PublicKey::from_bytes(&unhex(text(value, key))).unwrap()
}

fn receipt_facts(case: &Value) -> receipt::ReceiptFacts {
    receipt::ReceiptFacts {
        network: network(text(case, "network")),
        delivery_key: public_key(case, "delivery_key"),
        amount: case["amount"].as_u64().unwrap(),
        kernel_excess: array(case, "kernel_excess"),
        slate_id: array(case, "slate_id"),
        payer_key: public_key(case, "payer_key"),
    }
}

/// Each receipt case, from the delivery secret and the facts: the tweak, the receipt key and
/// secret, the message and its digest, and the signature byte for byte; the address carries the
/// delivery key; and the signature verifies.
#[test]
fn epic1_receipts_match_the_vectors() {
    let document = {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/keys/epic1_receipts.json");
        serde_json::from_str::<Value>(&std::fs::read_to_string(&path).unwrap()).unwrap()
    };
    let cases = vectors("epic1_receipts");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let facts = receipt_facts(case);
        let net = facts.network;
        assert_eq!(
            case["net"].as_u64().unwrap(),
            u64::from(receipt::net_byte(net))
        );
        let address = Epic1Address::decode(text(case, "address"), net).unwrap();
        assert_eq!(address.delivery_key(), &facts.delivery_key);
        let delivery = lepic_crypto::SecretKey::from_array(array(case, "delivery_secret")).unwrap();
        assert_eq!(
            hex(receipt::tweak(&facts.delivery_key).unwrap().expose_bytes()),
            text(case, "tweak")
        );
        assert_eq!(
            hex(receipt::receipt_secret(&delivery).unwrap().expose_bytes()),
            text(case, "receipt_secret")
        );
        assert_eq!(
            hex(&receipt::receipt_key(&facts.delivery_key)
                .unwrap()
                .to_bytes()),
            text(case, "receipt_key")
        );
        assert_eq!(hex(&receipt::message(&facts)), text(case, "message"));
        assert_eq!(hex(&receipt::digest(&facts)), text(case, "digest"));
        let signature = receipt::sign(&facts, &delivery).unwrap();
        assert_eq!(hex(&signature), text(case, "signature"));
        receipt::verify(&facts, &signature).unwrap();
    }
    let refused = document["expected"]["refused"].as_array().unwrap();
    let names: Vec<&str> = refused.iter().map(|case| text(case, "name")).collect();
    assert_eq!(
        names,
        [
            "flipped_bit",
            "amount_changed",
            "untweaked_delivery_key",
            "key_not_in_challenge"
        ]
    );
    for case in refused {
        assert_eq!(
            receipt::verify(&receipt_facts(case), &array(case, "signature")),
            Err(receipt::ReceiptError::BadSignature),
            "{}",
            text(case, "name")
        );
    }
}
