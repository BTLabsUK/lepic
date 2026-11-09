#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::*;
use crate::address::tests::sample;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn key() -> PublicKey {
    let bytes: Vec<u8> = (0..G.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&G[i..i + 2], 16).unwrap())
        .collect();
    PublicKey::from_bytes(&bytes).unwrap()
}

fn entry(network: Network, relay: &str) -> String {
    format!("{}@{relay}", EpicboxAddress::key_text_of(&key(), network))
}

fn link_text(network: Network, query: &str) -> String {
    format!("epic:{}?{query}", sample(network).encode())
}

#[test]
fn reads_one_transport_amount_and_message() {
    let text = link_text(
        Network::Mainnet,
        &format!(
            "epicbox={}&amount=1.5&message=Dinner%20for%20two",
            entry(Network::Mainnet, "relay.example.com:2100")
        ),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.address, sample(Network::Mainnet));
    assert_eq!(link.transports.len(), 1);
    assert_eq!(link.transports[0].relay().as_str(), "relay.example.com");
    assert_eq!(link.transports[0].port(), Some(2100));
    assert_eq!(link.transports[0].port_or_default(), 2100);
    assert_eq!(link.amount, Some(parse_amount("1.5").unwrap()));
    assert_eq!(link.message.as_deref(), Some("Dinner for two"));
    assert!(link.ignored.is_empty());
    assert!(matches!(link.delivery(), Delivery::Usable(list) if list.len() == 1));
}

#[test]
fn reads_only_three_transports_and_reports_the_rest() {
    let entries: Vec<String> = (1..=5)
        .map(|n| {
            format!(
                "epicbox={}",
                entry(Network::Floonet, &format!("r{n}.example.com"))
            )
        })
        .collect();
    let link = Epic1Link::parse(&link_text(Network::Floonet, &entries.join("&"))).unwrap();
    let relays: Vec<&str> = link.transports.iter().map(|t| t.relay().as_str()).collect();
    assert_eq!(
        relays,
        ["r1.example.com", "r2.example.com", "r3.example.com"]
    );
    assert_eq!(link.ignored, [Skipped::TransportsOverLimit { count: 2 }]);
    assert_eq!(link.transports[0].port_or_default(), DEFAULT_PORT);
}

#[test]
fn skips_a_mailbox_of_the_other_network_and_reports_it() {
    let text = link_text(
        Network::Mainnet,
        &format!(
            "epicbox={}&epicbox={}",
            entry(Network::Floonet, "a.example.com"),
            entry(Network::Mainnet, "b.example.com")
        ),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.transports.len(), 1);
    assert_eq!(link.transports[0].relay().as_str(), "b.example.com");
    assert_eq!(
        link.ignored,
        [Skipped::Transport {
            index: 0,
            fault: TransportFault::Network
        }]
    );
}

#[test]
fn a_link_without_a_usable_transport_cannot_pay() {
    for query in [
        "amount=1",
        "epicbox=nothing",
        "epicbox=%zz",
        "epicbox=abc@relay.example.com",
    ] {
        let link = Epic1Link::parse(&link_text(Network::Mainnet, query)).unwrap();
        assert_eq!(link.delivery(), Delivery::CannotPay, "{query}");
    }
    let bare = format!("epic:{}", sample(Network::Mainnet).encode());
    let link = Epic1Link::parse(&bare).unwrap();
    assert_eq!(link.delivery(), Delivery::CannotPay);
    assert!(link.ignored.is_empty());
}

#[test]
fn bad_relay_and_port_make_the_entry_unusable() {
    for relay in ["-bad.example.com", "host:0", "host:65536", "host:x", "a b"] {
        let text = link_text(
            Network::Mainnet,
            &format!("epicbox={}", entry(Network::Mainnet, relay)),
        );
        let link = Epic1Link::parse(&text).unwrap();
        assert!(link.transports.is_empty(), "{relay}");
        assert_eq!(link.ignored.len(), 1, "{relay}");
    }
}

#[test]
fn ignores_method_direct_require_min_and_unknown_keys() {
    let text = link_text(
        Network::Mainnet,
        &format!(
            "method=epicbox&direct=1&require=x&min=2&unknown=3&epicbox={}&noequals",
            entry(Network::Mainnet, "relay.example.com")
        ),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.transports.len(), 1);
    assert!(link.ignored.is_empty());
    assert_eq!(link.amount, None);
}

#[test]
fn message_aliases_and_bounds() {
    for key in ["message", "note", "memo"] {
        let link = Epic1Link::parse(&link_text(Network::Mainnet, &format!("{key}=hi"))).unwrap();
        assert_eq!(link.message.as_deref(), Some("hi"));
    }
    let long = "a".repeat(MAX_VALUE_LEN + 1);
    let link = Epic1Link::parse(&link_text(Network::Mainnet, &format!("label={long}"))).unwrap();
    assert_eq!(link.label, None);
    assert_eq!(link.ignored, [Skipped::Value { key: "label" }]);
    let link = Epic1Link::parse(&link_text(Network::Mainnet, "message=a%0Ab")).unwrap();
    assert_eq!(link.message, None);
    let link = Epic1Link::parse(&link_text(Network::Mainnet, "message=%ff")).unwrap();
    assert_eq!(link.message, None);
}

#[test]
fn refuses_bad_amounts() {
    for amount in ["0", "-1", "1.123456789", "abc", "", "1e3", "%zz"] {
        let result = Epic1Link::parse(&link_text(Network::Mainnet, &format!("amount={amount}")));
        assert!(result.is_err(), "{amount:?}");
    }
}

#[test]
fn an_epicbox_link_is_not_an_epic1_link() {
    let epicbox = EpicboxAddress::key_text_of(&key(), Network::Mainnet);
    let epic1 = sample(Network::Mainnet).encode();
    for text in [
        format!("epic:{epicbox}@relay.example.com?amount=1"),
        format!("epic:{epicbox}@relay.example.com?native={epic1}"),
        format!("epic:{epicbox}@relay.example.com?epic1={epic1}"),
        format!("epic:epicbox://{epicbox}@relay.example.com"),
        format!("epicbox://{epicbox}@relay.example.com"),
        epic1.clone(),
        String::new(),
    ] {
        assert_eq!(
            Epic1Link::parse(&text),
            Err(LinkError::NotAnEpic1Link),
            "{text}"
        );
    }
}

#[test]
fn an_epic1_inside_a_parameter_is_never_read_as_the_address() {
    let other = sample(Network::Mainnet).encode();
    let text = link_text(Network::Floonet, &format!("native={other}&address={other}"));
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.address.network(), Network::Floonet);
    assert!(link.transports.is_empty());
}

#[test]
fn refuses_a_bad_address_and_long_text() {
    let mut text = link_text(Network::Mainnet, "amount=1");
    let at = text.find("epic1").unwrap() + 20;
    text.replace_range(at..=at, "q");
    assert!(matches!(
        Epic1Link::parse(&text),
        Err(LinkError::Address(_))
    ));
    let long = link_text(
        Network::Mainnet,
        &format!("message={}", "a".repeat(MAX_LINK_LEN)),
    );
    assert!(matches!(
        Epic1Link::parse(&long),
        Err(LinkError::TooLong { .. })
    ));
}

#[test]
fn builder_round_trips_with_a_lower_case_address() {
    for network in [Network::Mainnet, Network::Floonet] {
        let mut link = Epic1Link::new(sample(network));
        for relay in [
            "a.example.com",
            "b.example.com",
            "c.example.com",
            "d.example.com",
        ] {
            link.transports.push(EpicboxTransport::new(
                key(),
                RelayHost::parse(relay).unwrap(),
                Some(2100),
            ));
        }
        link.amount = Some(parse_amount("12.5").unwrap());
        link.message = Some("Dinner & drinks, 50%".to_owned());
        link.label = Some("Café".to_owned());
        let text = link.to_uri();
        let address_part = text.split('?').next().unwrap();
        assert_eq!(address_part, address_part.to_ascii_lowercase());
        assert!(text.contains("epicbox="));
        assert_eq!(text.matches("epicbox=").count(), MAX_TRANSPORTS);
        let back = Epic1Link::parse(&text).unwrap();
        link.transports.truncate(MAX_TRANSPORTS);
        assert_eq!(back, link);
        assert_eq!(back.to_uri(), text);
    }
}

#[test]
fn builder_without_extras_is_the_bare_address() {
    let link = Epic1Link::new(sample(Network::Mainnet));
    assert_eq!(
        link.to_uri(),
        format!("epic:{}", sample(Network::Mainnet).encode())
    );
}

#[test]
fn an_ipv4_relay_is_kept_as_a_literal() {
    let text = link_text(
        Network::Mainnet,
        &format!("epicbox={}", entry(Network::Mainnet, "192.168.1.5:2100")),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(
        link.transports[0].relay().ipv4(),
        Some("192.168.1.5".parse().unwrap())
    );
}
