// SPDX-License-Identifier: Apache-2.0
// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{AddressError, Domain, EpicboxAddress, Network};
use proptest::prelude::*;

const MAINNET_KEY: &str = "esYTimgooNuxKXdEEXJk3fbXoy2HWyyY2CaRXYU8Z8B7fSPyz6YL";
const FLOONET_KEY: &str = "zzQDUih9cHWequRhSpzCKLTmf4M13trQAHJ9dKb1LCfuxTXQoB7b";

fn mainnet(text: &str) -> Result<EpicboxAddress, AddressError> {
    EpicboxAddress::parse(text, Network::Mainnet)
}

#[test]
fn rejects_empty_text() {
    assert_eq!(mainnet(""), Err(AddressError::KeyLength { actual: 0 }));
}

#[test]
fn rejects_key_of_the_wrong_length() {
    assert_eq!(
        mainnet(&MAINNET_KEY[..51]),
        Err(AddressError::KeyLength { actual: 51 })
    );
    assert_eq!(
        mainnet(&format!("{MAINNET_KEY}1")),
        Err(AddressError::KeyLength { actual: 53 })
    );
}

#[test]
fn rejects_hex_public_key() {
    assert_eq!(
        mainnet("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"),
        Err(AddressError::KeyLength { actual: 66 })
    );
}

#[test]
fn rejects_surrounding_whitespace() {
    assert_eq!(
        mainnet(&format!(" {MAINNET_KEY}")),
        Err(AddressError::KeyLength { actual: 53 })
    );
    assert_eq!(
        mainnet(&format!("{MAINNET_KEY}\n")),
        Err(AddressError::KeyLength { actual: 53 })
    );
}

#[test]
fn rejects_other_scheme() {
    assert_eq!(
        mainnet(&format!("https://{MAINNET_KEY}")),
        Err(AddressError::KeyLength { actual: 60 })
    );
}

#[test]
fn rejects_character_outside_the_base58_alphabet() {
    let key = MAINNET_KEY.replacen('u', "0", 1);
    assert_eq!(mainnet(&key), Err(AddressError::NotBase58));
}

#[test]
fn rejects_wrong_checksum() {
    let key = format!("{}1", &MAINNET_KEY[..51]);
    assert_eq!(mainnet(&key), Err(AddressError::Checksum));
}

#[test]
fn rejects_key_of_the_other_network() {
    assert_eq!(
        mainnet(FLOONET_KEY),
        Err(AddressError::WrongNetwork {
            expected: Network::Mainnet
        })
    );
    assert_eq!(
        EpicboxAddress::parse(MAINNET_KEY, Network::Floonet),
        Err(AddressError::WrongNetwork {
            expected: Network::Floonet
        })
    );
}

#[test]
fn rejects_invalid_domain() {
    for domain in [
        "",
        "relay-1.example.org",
        "relay_1",
        "relay example",
        "réseau",
    ] {
        assert_eq!(
            mainnet(&format!("{MAINNET_KEY}@{domain}")),
            Err(AddressError::InvalidDomain),
            "{domain:?}"
        );
    }
}

#[test]
fn rejects_invalid_port() {
    for port in ["", "https", "65536", "99999999999999999999", "-1", " 80"] {
        assert_eq!(
            mainnet(&format!("{MAINNET_KEY}@relay.example.org:{port}")),
            Err(AddressError::InvalidPort),
            "{port:?}"
        );
    }
}

#[test]
fn rejects_port_without_domain() {
    assert_eq!(
        mainnet(&format!("{MAINNET_KEY}@:443")),
        Err(AddressError::InvalidDomain)
    );
}

#[test]
fn rejects_second_at_sign() {
    assert_eq!(
        mainnet(&format!("{MAINNET_KEY}@a@b")),
        Err(AddressError::InvalidDomain)
    );
}

#[test]
fn applies_the_given_default_domain_without_at_sign() {
    assert_eq!(mainnet(MAINNET_KEY), Err(AddressError::MissingDomain));
    let relay = Domain::parse("relay.example.org").unwrap();
    let address =
        EpicboxAddress::parse_with_default(MAINNET_KEY, Network::Mainnet, &relay).unwrap();
    assert_eq!(address.domain(), &relay);
    assert_eq!(address.port(), None);
    assert_eq!(address.key_text(), MAINNET_KEY);
}

#[test]
fn accepts_highest_port() {
    let address = mainnet(&format!("{MAINNET_KEY}@relay:65535")).unwrap();
    assert_eq!(address.port(), Some(65535));
}

#[test]
fn domain_parse_applies_the_same_rules() {
    assert_eq!(
        Domain::parse("Relay.Example.ORG").unwrap().as_str(),
        "Relay.Example.ORG"
    );
    assert_eq!(Domain::parse("a-b"), Err(AddressError::InvalidDomain));
}

fn address() -> impl Strategy<Value = EpicboxAddress> {
    (
        any::<[u8; 32]>().prop_filter_map("not a valid secret key", |bytes| {
            SecretKey::from_array(bytes).ok()
        }),
        prop_oneof![Just(Network::Mainnet), Just(Network::Floonet)],
        "[a-zA-Z0-9.]{1,64}",
        proptest::option::of(any::<u16>()),
    )
        .prop_map(|(secret, network, domain, port)| {
            EpicboxAddress::new(
                PublicKey::from_secret_key(&secret).unwrap(),
                network,
                Domain::parse(&domain).unwrap(),
                port,
            )
        })
}

proptest! {
    #[test]
    fn display_parses_back_to_the_same_address(address in address()) {
        let parsed = EpicboxAddress::parse(&address.to_string(), address.network()).unwrap();
        prop_assert_eq!(parsed.public_key(), address.public_key());
        prop_assert_eq!(parsed.domain(), address.domain());
        let shown_port = address.port().filter(|port| *port != 443);
        prop_assert_eq!(parsed.port(), shown_port);
        prop_assert_eq!(parsed.to_string(), address.to_string());
    }

    #[test]
    fn key_text_parses_back_to_the_same_key(address in address()) {
        let parsed = EpicboxAddress::parse_key(&address.key_text(), address.network()).unwrap();
        prop_assert_eq!(&parsed, address.public_key());
    }

    #[test]
    fn parser_never_panics(text in any::<String>()) {
        let _ = mainnet(&text);
    }

    #[test]
    fn parser_never_panics_on_near_addresses(suffix in "[@:a-z0-9.]{0,24}") {
        let _ = mainnet(&format!("{MAINNET_KEY}{suffix}"));
    }
}
