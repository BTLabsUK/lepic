#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use lepic_crypto::PublicKey;
use lepic_epicbox::{EpicboxAddress, Network};

use super::*;
use crate::address::tests::sample;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

fn key() -> PublicKey {
    let bytes: Vec<u8> = (0..G.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&G[i..i + 2], 16).unwrap())
        .collect();
    PublicKey::from_bytes(&bytes).unwrap()
}

/// The value an `epicbox=` entry of an earlier link held: `<mailbox>@<relay>`.
fn mailbox_entry(network: Network, relay: &str) -> String {
    format!("{}@{relay}", EpicboxAddress::key_text_of(&key(), network))
}

fn link_text(network: Network, query: &str) -> String {
    format!("epic:{}?{query}", sample(network).encode())
}

fn route(method: MethodId, value: &str) -> RouteEntry {
    RouteEntry {
        method,
        value: value.to_owned(),
    }
}

#[test]
fn reads_one_route_amount_and_message() {
    let text = link_text(
        Network::Mainnet,
        "http=pay.example.com:2100&amount=1.5&message=Dinner%20for%20two",
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.address, sample(Network::Mainnet));
    assert_eq!(link.routes, [route(MethodId::Http, "pay.example.com:2100")]);
    assert_eq!(link.amount, Some(parse_amount("1.5").unwrap()));
    assert_eq!(link.message.as_deref(), Some("Dinner for two"));
    assert!(link.ignored.is_empty());
}

#[test]
fn reads_a_link_written_in_upper_case() {
    let text = link_text(Network::Floonet, "amount=1.5&message=order-7").to_ascii_uppercase();
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.address, sample(Network::Floonet));
    assert_eq!(link.amount, Some(parse_amount("1.5").unwrap()));
    assert_eq!(link.message.as_deref(), Some("ORDER-7"));
}

#[test]
fn a_link_with_epicbox_is_read_with_epicbox_ignored() {
    let first = mailbox_entry(Network::Mainnet, "relay.example.com:2100");
    let second = mailbox_entry(Network::Floonet, "other.example.com");
    let text = link_text(
        Network::Mainnet,
        &format!("epicbox={first}&http=pay.example.com&EPICBOX={second}&amount=2&tor={ONION}"),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(
        link.routes,
        [
            route(MethodId::Http, "pay.example.com"),
            route(MethodId::Tor, ONION)
        ]
    );
    assert_eq!(link.ignored, [Skipped::Epicbox, Skipped::Epicbox]);
    assert_eq!(link.amount, Some(parse_amount("2").unwrap()));
    assert!(!link.to_uri().contains("epicbox"));

    // A link of the earlier release with only `epicbox=` entries reads as the bare address.
    let earlier = link_text(Network::Mainnet, &format!("epicbox={first}&amount=1"));
    let link = Epic1Link::parse(&earlier).unwrap();
    assert!(link.routes.is_empty());
    assert_eq!(link.ignored, [Skipped::Epicbox]);
    assert_eq!(
        link.to_uri(),
        link_text(Network::Mainnet, "amount=1"),
        "the entry is not written back"
    );
}

#[test]
fn a_link_with_a_mailbox_is_read_with_the_mailbox_ignored() {
    let text = link_text(
        Network::Mainnet,
        "mailbox=relay.example.com&amount=1&MAILBOX=other.example.com:2100",
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert!(link.routes.is_empty());
    assert_eq!(link.ignored, [Skipped::Mailbox, Skipped::Mailbox]);
    assert_eq!(link.to_uri(), link_text(Network::Mainnet, "amount=1"));
}

#[test]
fn an_epicbox_route_set_by_hand_is_not_written() {
    let mut link = Epic1Link::new(sample(Network::Mainnet));
    link.routes.push(route(
        MethodId::Epicbox,
        &mailbox_entry(Network::Mainnet, "relay.example.com"),
    ));
    link.routes.push(route(MethodId::Http, "pay.example.com"));
    let expected = link_text(Network::Mainnet, "http=pay.example.com");
    assert_eq!(link.to_uri(), expected);
    assert_eq!(link.to_qr(), expected);
}

#[test]
fn a_link_with_four_entries_is_refused() {
    let four = format!("http=a.example.com&tor={ONION}&http=b.example.com&tor={ONION}:8080");
    assert_eq!(
        Epic1Link::parse(&link_text(Network::Floonet, &four)),
        Err(LinkError::TooManyEntries { count: 4, max: 3 })
    );
    // Every `http=` and `tor=` counts, usable or not; `epicbox=` entries do not.
    let unusable = format!("http=-bad&tor={ONION}&http=%zz&tor=pay.example.com&amount=1");
    assert_eq!(
        Epic1Link::parse(&link_text(Network::Floonet, &unusable)),
        Err(LinkError::TooManyEntries { count: 4, max: 3 })
    );
    let mailbox = mailbox_entry(Network::Floonet, "relay.example.com");
    let three =
        format!("epicbox={mailbox}&http=-bad&tor={ONION}&epicbox={mailbox}&http=pay.example.com");
    let link = Epic1Link::parse(&link_text(Network::Floonet, &three)).unwrap();
    let methods: Vec<MethodId> = link.routes.iter().map(|route| route.method).collect();
    assert_eq!(methods, [MethodId::Tor, MethodId::Http]);
    assert_eq!(
        link.ignored,
        [
            Skipped::Epicbox,
            Skipped::Transport {
                index: 0,
                fault: TransportFault::Http(RelayHostError::Label)
            },
            Skipped::Epicbox,
        ]
    );
}

#[test]
fn a_link_without_a_usable_route_has_none() {
    for query in ["amount=1", "http=%zz", "tor=nothing", "http=-bad"] {
        let link = Epic1Link::parse(&link_text(Network::Mainnet, query)).unwrap();
        assert!(link.routes.is_empty(), "{query}");
    }
    let bare = format!("epic:{}", sample(Network::Mainnet).encode());
    let link = Epic1Link::parse(&bare).unwrap();
    assert!(link.routes.is_empty());
    assert!(link.ignored.is_empty());
}

#[test]
fn bad_hosts_and_ports_make_the_entry_unusable() {
    for host in [
        "-bad.example.com",
        "host:0",
        "host:65536",
        "host:x",
        "a%20b",
    ] {
        let link = Epic1Link::parse(&link_text(Network::Mainnet, &format!("http={host}"))).unwrap();
        assert!(link.routes.is_empty(), "{host}");
        assert_eq!(link.ignored.len(), 1, "{host}");
    }
}

#[test]
fn ignores_method_direct_require_min_and_unknown_keys() {
    let text = link_text(
        Network::Mainnet,
        "method=epicbox&direct=1&require=x&min=2&unknown=3&http=pay.example.com&noequals",
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.routes.len(), 1);
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
    assert!(link.routes.is_empty());
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
        link.routes = vec![
            route(MethodId::Http, "a.example.com:2100"),
            route(MethodId::Tor, ONION),
            route(MethodId::Http, "b.example.com"),
            route(MethodId::Http, "c.example.com"),
        ];
        link.amount = Some(parse_amount("12.5").unwrap());
        link.message = Some("Dinner & drinks, 50%".to_owned());
        link.label = Some("Café".to_owned());
        let text = link.to_uri();
        let address_part = text.split('?').next().unwrap();
        assert_eq!(address_part, address_part.to_ascii_lowercase());
        assert_eq!(
            text.matches("http=").count() + text.matches("tor=").count(),
            MAX_TRANSPORTS
        );
        let back = Epic1Link::parse(&text).unwrap();
        link.routes.truncate(MAX_TRANSPORTS);
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
fn an_ipv4_http_host_is_kept_as_a_literal() {
    let link = Epic1Link::parse(&link_text(Network::Mainnet, "http=192.168.1.5:2100")).unwrap();
    assert_eq!(link.routes, [route(MethodId::Http, "192.168.1.5:2100")]);
    assert_eq!(
        link.routes[0].host_port(),
        Some(("192.168.1.5".to_owned(), 2100))
    );
}

#[test]
fn each_route_key_is_read_in_link_order_and_round_trips() {
    let text = link_text(
        Network::Mainnet,
        &format!("tor={ONION}:8080&http=Pay.Example.com&amount=2"),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(
        link.routes,
        [
            route(MethodId::Tor, &format!("{ONION}:8080")),
            route(MethodId::Http, "pay.example.com"),
        ]
    );
    assert!(link.ignored.is_empty());
    let written = link.to_uri();
    assert_eq!(
        written,
        link_text(
            Network::Mainnet,
            &format!(
                "tor={}&http=pay.example.com&amount=2",
                ONION.to_owned() + "%3a8080"
            )
        )
    );
    assert_eq!(Epic1Link::parse(&written).unwrap(), link);
}

#[test]
fn http_and_tor_values_are_canonical_with_their_default_ports() {
    let text = link_text(
        Network::Floonet,
        &format!("http=pay.example.com:00443&tor={ONION}"),
    );
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.routes[0].value, "pay.example.com:443");
    assert_eq!(
        link.routes[0].host_port(),
        Some(("pay.example.com".to_owned(), 443))
    );
    assert_eq!(link.routes[1].host_port(), Some((ONION.to_owned(), 80)));
    let http = route(MethodId::Http, "pay.example.com");
    assert_eq!(http.host_port(), Some(("pay.example.com".to_owned(), 443)));
}

#[test]
fn a_bad_http_or_tor_value_is_skipped_with_its_index() {
    let upper = ONION.to_ascii_uppercase();
    let short = &ONION[1..];
    let cases: [(&str, TransportFault); 12] = [
        (
            "http=https%3a%2f%2fpay.example.com",
            TransportFault::Http(RelayHostError::Port),
        ),
        (
            "http=pay.example.com%2fpath",
            TransportFault::Http(RelayHostError::Label),
        ),
        (
            "http=pay-me.example.com",
            TransportFault::Http(RelayHostError::Label),
        ),
        (
            "http=pay.example.com:0",
            TransportFault::Http(RelayHostError::Port),
        ),
        (
            "http=1.2.3.04",
            TransportFault::Http(RelayHostError::NotAnAddress),
        ),
        ("http=%zz", TransportFault::Encoding),
        (&format!("tor={upper}"), TransportFault::Onion),
        (&format!("tor={short}"), TransportFault::Onion),
        (&format!("tor=http%3a%2f%2f{ONION}"), TransportFault::Onion),
        (&format!("tor={ONION}%2fpath"), TransportFault::Onion),
        (&format!("tor={ONION}:65536"), TransportFault::Onion),
        ("tor=pay.example.com", TransportFault::Onion),
    ];
    for (bad, fault) in cases {
        let text = link_text(Network::Mainnet, &format!("http=pay.example.com&{bad}"));
        let link = Epic1Link::parse(&text).unwrap();
        assert_eq!(link.routes.len(), 1, "{bad}");
        assert_eq!(
            link.ignored,
            [Skipped::Transport { index: 1, fault }],
            "{bad}"
        );
    }
}

#[test]
fn the_qr_form_has_the_address_the_first_entry_and_the_amount() {
    let text = link_text(
        Network::Mainnet,
        &format!("http=pay.example.com&tor={ONION}&amount=3&message=hi&label=shop"),
    );
    let link = Epic1Link::parse(&text).unwrap();
    let qr = link.to_qr();
    assert_eq!(
        qr,
        link_text(Network::Mainnet, "http=pay.example.com&amount=3")
    );
    assert_eq!(qr, qr.to_ascii_lowercase());
    let read = Epic1Link::parse(&qr).unwrap();
    assert_eq!(read.routes, link.routes[..1]);
    assert_eq!(read.amount, link.amount);
    assert_eq!(read.message, None);
    let bare = Epic1Link::new(sample(Network::Floonet));
    let qr = bare.to_qr();
    assert_eq!(qr, bare.to_uri().to_ascii_uppercase());
    assert_eq!(Epic1Link::parse(&qr).unwrap().address, bare.address);
    let mixed = qr.replacen("EPIC:TEPIC1", "EPIC:tEPIC1", 1);
    assert!(Epic1Link::parse(&mixed).is_err(), "{mixed}");
}

#[test]
fn an_upper_case_scheme_address_and_keys_still_read_routes() {
    let address = sample(Network::Mainnet).encode().to_ascii_uppercase();
    let text = format!("EPIC:{address}?HTTP=PAY.EXAMPLE.COM&Tor={ONION}");
    let link = Epic1Link::parse(&text).unwrap();
    assert_eq!(link.address, sample(Network::Mainnet));
    assert_eq!(
        link.routes,
        [
            route(MethodId::Http, "pay.example.com"),
            route(MethodId::Tor, ONION)
        ]
    );
}

fn earlier_address(prefix: &str) -> String {
    crate::bech32m::encode(prefix, &[7u8; 65]).unwrap()
}

#[test]
fn a_link_of_an_earlier_release_is_refused_and_names_its_mailbox() {
    let mailbox = mailbox_entry(Network::Mainnet, "Relay.Example.org:8443");
    for (query, expected) in [
        (
            format!("epicbox={mailbox}&amount=1"),
            Some("relay.example.org:8443"),
        ),
        (
            format!(
                "amount=1&EPICBOX={}",
                mailbox_entry(Network::Mainnet, "relay.test")
            ),
            Some("relay.test"),
        ),
        ("epicbox=nobody&amount=1".to_owned(), None),
        ("epicbox=key@bad_host".to_owned(), None),
        ("http=pay.example.com".to_owned(), None),
    ] {
        let text = format!("epic:{}?{query}", earlier_address("epic"));
        let error = Epic1Link::parse(&text).unwrap_err();
        assert_eq!(
            error,
            LinkError::EarlierAddress {
                mailbox: expected.map(str::to_owned)
            },
            "{query}"
        );
        assert!(error.is_earlier_address());
        let shown = error.to_string();
        assert!(shown.contains("older wallet version"), "{shown}");
        assert!(shown.contains("Epicbox address"), "{shown}");
        assert_eq!(shown.contains("mailbox "), expected.is_some(), "{shown}");
        if let Some(host) = expected {
            assert!(shown.contains(host), "{shown}");
        }
    }
}

#[test]
fn a_bare_earlier_address_and_a_floonet_one_are_refused_without_a_mailbox() {
    for prefix in ["epic", "tepic"] {
        let error = Epic1Link::parse(&format!("epic:{}", earlier_address(prefix))).unwrap_err();
        assert_eq!(error, LinkError::EarlierAddress { mailbox: None });
    }
    assert!(!LinkError::NotAnEpic1Link.is_earlier_address());
    assert!(
        LinkError::Address(Epic1Error::EarlierAddress).is_earlier_address(),
        "the address error alone counts too"
    );
    let other = Epic1Link::parse(&format!(
        "epic:{}",
        crate::bech32m::encode("epic", &[7u8; 64]).unwrap()
    ))
    .unwrap_err();
    assert!(!other.is_earlier_address(), "{other}");
}
