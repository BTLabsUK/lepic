#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

#[test]
fn mailbox_address_follows_the_relay_domain_grammar() {
    for good in [
        "epicbox.epiccash.com",
        "relay1.example.org:443",
        "a",
        "10.0.0.1:1",
        "x.y:65535",
        "Ab.C9",
    ] {
        assert!(is_mailbox_address(good), "{good}");
    }
    for bad in [
        "",
        "relay-1.example.org",
        "a..org",
        ".org",
        "org.",
        "a.org:",
        "a.org:0",
        "a.org:65536",
        "a.org:123456",
        "a.org:+1",
        "a_b.org",
        "a.org:1:2",
        "é.org",
        "127.1",
        "10.0.0.256",
        "a.1b",
    ] {
        assert!(!is_mailbox_address(bad), "{bad}");
    }
    let label = "a".repeat(63);
    assert!(is_mailbox_address(&format!("{label}.{label}")));
    assert!(!is_mailbox_address(&"a".repeat(64)));
    assert!(!is_mailbox_address(&format!("{label}.{label}.a")));
}

/// The relay hosts every LEPIC parser shares, from the epic-pairing-kit generator.
#[test]
fn mailbox_address_matches_the_shared_relay_hosts() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/pairing/epictx_relay_hosts.json");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let relay = vector["relay"].as_str().unwrap();
        assert_eq!(
            is_mailbox_address(relay),
            vector["valid"].as_bool().unwrap(),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn unknown_records_must_be_ignorable_and_increasing() {
    assert_eq!(
        UnknownRecord::new(0x7f, Vec::new()),
        Err(TailError::UnknownRequired { record_type: 0x7f })
    );
    let a = UnknownRecord::new(0x90, vec![1]).unwrap();
    let b = UnknownRecord::new(0x82, vec![2]).unwrap();
    assert_eq!(
        Tail::new(None, None, vec![a, b]),
        Err(TailError::Order {
            previous: 0x90,
            found: 0x82
        })
    );
}

#[test]
fn tail_round_trips_through_its_bytes() {
    let tail = Tail::new(
        Some(ReplyKey::from_bytes([7; 32])),
        None,
        vec![
            UnknownRecord::new(0x80, Vec::new()).unwrap(),
            UnknownRecord::new(0xff, vec![1, 2, 3]).unwrap(),
        ],
    )
    .unwrap();
    let mut bytes = Vec::new();
    tail.encode(&mut bytes);
    assert_eq!(Tail::decode(&bytes, Stage::S1), Ok(tail));
    assert_eq!(
        Tail::decode(&bytes, Stage::S2),
        Err(TailError::NotAllowed {
            record_type: REPLY_KEY,
            stage: Stage::S2
        })
    );
    assert_eq!(
        Tail::decode(&bytes[..bytes.len() - 1], Stage::S1),
        Err(TailError::Truncated)
    );
}

const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

fn route() -> DirectRoute {
    DirectRoute::new(vec![
        DirectEntry::new(DirectMethod::Http, "pay.example.org".to_owned()).unwrap(),
        DirectEntry::new(DirectMethod::Tor, format!("{ONION}:8080")).unwrap(),
    ])
    .unwrap()
}

fn claim() -> RequestClaim {
    RequestClaim::new(
        [3; 32],
        1_700_000_000,
        [9; 64],
        "shop.example.org".to_owned(),
    )
    .unwrap()
}

fn request_tail() -> Tail {
    Tail::new(
        Some(ReplyKey::from_bytes([7; 32])),
        None,
        vec![
            UnknownRecord::new(0x80, Vec::new()).unwrap(),
            UnknownRecord::new(0x90, vec![1]).unwrap(),
        ],
    )
    .unwrap()
    .with_direct_route(route())
    .with_request_claim(claim())
    .unwrap()
}

fn bytes_of(tail: &Tail) -> Vec<u8> {
    let mut bytes = Vec::new();
    tail.encode(&mut bytes);
    bytes
}

#[test]
fn request_records_round_trip_in_type_order() {
    let tail = request_tail();
    let bytes = bytes_of(&tail);
    let types: Vec<u8> = {
        let mut types = Vec::new();
        let mut rest = bytes.as_slice();
        while let [record_type, high, low, after @ ..] = rest {
            types.push(*record_type);
            rest = &after[usize::from(u16::from_be_bytes([*high, *low]))..];
        }
        types
    };
    assert_eq!(types, [REPLY_KEY, 0x80, DIRECT_ROUTE, 0x90, REQUEST_CLAIM]);
    let decoded = Tail::decode(&bytes, Stage::I1).unwrap();
    assert_eq!(decoded, tail);
    assert_eq!(decoded.direct_route(), Some(&route()));
    assert_eq!(decoded.request_claim(), Some(&claim()));
    assert!(bytes.ends_with(&claim().record()));
    assert_eq!(
        claim().signed_part(&bytes),
        Some(&bytes[..bytes.len() - claim().record().len()])
    );
    assert_eq!(claim().signed_part(&bytes[..bytes.len() - 1]), None);
}

#[test]
fn request_records_are_allowed_on_an_i1_only() {
    let route_only = Tail::empty().with_direct_route(route());
    let claim_only = Tail::empty().with_request_claim(claim()).unwrap();
    for stage in [Stage::S1, Stage::S2, Stage::S3, Stage::I2, Stage::I3] {
        assert_eq!(
            route_only.check_stage(stage),
            Err(TailError::NotAllowed {
                record_type: DIRECT_ROUTE,
                stage
            })
        );
        assert_eq!(
            claim_only.check_stage(stage),
            Err(TailError::NotAllowed {
                record_type: REQUEST_CLAIM,
                stage
            })
        );
        assert!(Tail::decode(&bytes_of(&claim_only), stage).is_err());
    }
    assert_eq!(route_only.check_stage(Stage::I1), Ok(()));
    assert_eq!(claim_only.check_stage(Stage::I1), Ok(()));
}

#[test]
fn a_record_after_the_claim_is_refused() {
    let mut bytes = bytes_of(&Tail::empty().with_request_claim(claim()).unwrap());
    bytes.extend_from_slice(&[0xf1, 0, 0]);
    assert_eq!(
        Tail::decode(&bytes, Stage::I1),
        Err(TailError::ClaimNotLast)
    );
    let mut lower = bytes_of(&Tail::empty().with_request_claim(claim()).unwrap());
    lower.extend_from_slice(&[0x01, 0, 0]);
    assert_eq!(
        Tail::decode(&lower, Stage::I1),
        Err(TailError::ClaimNotLast)
    );
    let after = Tail::new(
        None,
        None,
        vec![UnknownRecord::new(0xf1, Vec::new()).unwrap()],
    )
    .unwrap();
    assert_eq!(
        after.with_request_claim(claim()),
        Err(TailError::ClaimNotLast)
    );
}

#[test]
fn known_types_are_not_unknown_records() {
    for record_type in [DIRECT_ROUTE, REQUEST_CLAIM] {
        assert_eq!(
            UnknownRecord::new(record_type, Vec::new()),
            Err(TailError::KnownType { record_type })
        );
    }
}

#[test]
fn direct_entries_follow_their_method() {
    for good in [
        "pay.example.org",
        "pay.example.org:8443",
        "my-shop.example",
        "my-shop.pay-1.example:443",
        "10.0.0.1:1",
        "a",
    ] {
        assert!(
            DirectEntry::new(DirectMethod::Http, good.to_owned()).is_ok(),
            "{good}"
        );
    }
    for bad in [
        "",
        "Pay.example.org",
        "-shop.example",
        "shop-.example",
        "shop..example",
        "shop.example.",
        "my_shop.example",
        "10.0.0.256",
        "a.org:0",
        ONION,
        "a.org/x",
    ] {
        assert_eq!(
            DirectEntry::new(DirectMethod::Http, bad.to_owned()),
            Err(TailError::DirectAddress),
            "{bad}"
        );
    }
    let longest = format!("{}.{}.org", "a".repeat(63), "b-c".repeat(20));
    assert_eq!(longest.len(), MAX_DIRECT_ADDRESS_LEN);
    assert!(DirectEntry::new(DirectMethod::Http, longest.clone()).is_ok());
    assert_eq!(
        DirectEntry::new(DirectMethod::Http, format!("x{longest}")),
        Err(TailError::DirectAddress)
    );
    for good in [ONION.to_owned(), format!("{ONION}:80")] {
        assert!(
            DirectEntry::new(DirectMethod::Tor, good.clone()).is_ok(),
            "{good}"
        );
    }
    let short = &ONION[1..];
    for bad in [
        short.to_owned(),
        ONION.to_uppercase(),
        ONION.replace('p', "1"),
        format!("{ONION}:0"),
        "pay.example.org".to_owned(),
        format!("x.{ONION}"),
    ] {
        assert_eq!(
            DirectEntry::new(DirectMethod::Tor, bad.clone()),
            Err(TailError::DirectAddress),
            "{bad}"
        );
    }
}

#[test]
fn direct_route_holds_one_to_four_distinct_entries() {
    let entry = |n: u8| DirectEntry::new(DirectMethod::Http, format!("a{n}.org")).unwrap();
    assert_eq!(
        DirectRoute::new(Vec::new()),
        Err(TailError::DirectEntryCount { count: 0 })
    );
    assert!(DirectRoute::new((0..4).map(entry).collect()).is_ok());
    assert_eq!(
        DirectRoute::new((0..5).map(entry).collect()),
        Err(TailError::DirectEntryCount { count: 5 })
    );
    assert_eq!(
        DirectRoute::new(vec![entry(1), entry(1)]),
        Err(TailError::DirectDuplicate)
    );
}

fn direct_record(value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![DIRECT_ROUTE];
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

#[test]
fn direct_route_decoding_refuses_bad_values() {
    let decode = |value: &[u8]| Tail::decode(&direct_record(value), Stage::I1);
    assert_eq!(decode(b""), Err(TailError::DirectEntryCount { count: 0 }));
    assert_eq!(
        decode(b"\x03\x01a"),
        Err(TailError::DirectMethod { byte: 3 })
    );
    assert_eq!(decode(b"\x01\x05a.org\x01"), Err(TailError::Truncated));
    assert_eq!(decode(b"\x01\x06a.org"), Err(TailError::Truncated));
    assert_eq!(decode(b"\x01\x02\xff\xfe"), Err(TailError::DirectAddress));
    assert_eq!(decode(b"\x02\x05a.org"), Err(TailError::DirectAddress));
    assert_eq!(
        decode(b"\x01\x01a\x01\x01a"),
        Err(TailError::DirectDuplicate)
    );
    let five: Vec<u8> = (b'a'..=b'e').flat_map(|c| [1, 1, c]).collect();
    assert_eq!(decode(&five), Err(TailError::DirectEntryCount { count: 5 }));
    assert_eq!(
        decode(b"\x01\x05a.org")
            .unwrap()
            .direct_route()
            .unwrap()
            .entries()[0]
            .address(),
        "a.org"
    );
}

#[test]
fn request_claim_decoding_refuses_bad_values() {
    let value = claim().value();
    let decode = |value: &[u8]| {
        let mut bytes = vec![REQUEST_CLAIM];
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(value);
        Tail::decode(&bytes, Stage::I1)
    };
    assert_eq!(decode(&value).unwrap().request_claim(), Some(&claim()));
    for len in [0, 31, 104] {
        assert_eq!(
            decode(&value[..len]),
            Err(TailError::Length {
                record_type: REQUEST_CLAIM,
                len
            })
        );
    }
    let mut long = value[..104].to_vec();
    long.extend(std::iter::repeat_n(b'a', 254));
    assert_eq!(
        decode(&long),
        Err(TailError::Length {
            record_type: REQUEST_CLAIM,
            len: 358
        })
    );
    for domain in [
        "Shop.example.org",
        "shop",
        "shop.example.org.",
        "-shop.org",
        "shop-.org",
        "a..org",
        "shop_1.org",
    ] {
        let mut bad = value[..104].to_vec();
        bad.extend_from_slice(domain.as_bytes());
        assert_eq!(decode(&bad), Err(TailError::ClaimDomain), "{domain}");
    }
    let mut utf8 = value[..104].to_vec();
    utf8.extend_from_slice(b"\xffa.org");
    assert_eq!(decode(&utf8), Err(TailError::ClaimDomain));
}

#[test]
fn claim_domain_takes_labels_up_to_dns_limits() {
    let label = "a".repeat(63);
    let longest = format!("{label}.{label}.{label}.{}", "b".repeat(61));
    assert_eq!(longest.len(), 253);
    assert!(RequestClaim::new([0; 32], 0, [0; 64], longest.clone()).is_ok());
    assert_eq!(
        RequestClaim::new([0; 32], 0, [0; 64], format!("{longest}b")),
        Err(TailError::ClaimDomain)
    );
    assert_eq!(
        RequestClaim::new([0; 32], 0, [0; 64], format!("{}.org", "a".repeat(64))),
        Err(TailError::ClaimDomain)
    );
}

mod round_trip {
    use proptest::prelude::*;

    use super::*;

    fn entry() -> impl Strategy<Value = DirectEntry> {
        prop_oneof![
            (
                "[a-z][a-z0-9]{0,19}(\\.[a-z][a-z0-9]{0,10}){0,3}",
                proptest::option::of(1u16..)
            )
                .prop_map(|(host, port)| {
                    let address = port.map_or(host.clone(), |port| format!("{host}:{port}"));
                    DirectEntry::new(DirectMethod::Http, address).unwrap()
                }),
            ("[a-z2-7]{56}", proptest::option::of(1u16..)).prop_map(|(name, port)| {
                let host = format!("{name}.onion");
                let address = port.map_or(host.clone(), |port| format!("{host}:{port}"));
                DirectEntry::new(DirectMethod::Tor, address).unwrap()
            }),
        ]
    }

    fn tail() -> impl Strategy<Value = Tail> {
        (
            proptest::option::of(any::<[u8; 32]>()),
            proptest::option::of(proptest::collection::vec(entry(), 1..=4)),
            proptest::option::of((
                any::<[u8; 32]>(),
                any::<u64>(),
                proptest::collection::vec(any::<u8>(), 64),
                "[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){1,3}",
            )),
            proptest::collection::btree_map(
                0x82u8..0xf0,
                proptest::collection::vec(any::<u8>(), 0..8),
                0..3,
            ),
        )
            .prop_filter_map("distinct entries", |(key, entries, claim, unknown)| {
                let unknown = unknown
                    .into_iter()
                    .map(|(record_type, value)| UnknownRecord::new(record_type, value).unwrap())
                    .collect();
                let mut tail = Tail::new(key.map(ReplyKey::from_bytes), None, unknown).unwrap();
                if let Some(entries) = entries {
                    tail = tail.with_direct_route(DirectRoute::new(entries).ok()?);
                }
                if let Some((key, issued_at, signature, domain)) = claim {
                    let signature: [u8; 64] = signature.try_into().unwrap();
                    let claim = RequestClaim::new(key, issued_at, signature, domain).unwrap();
                    tail = tail.with_request_claim(claim).unwrap();
                }
                Some(tail)
            })
    }

    proptest! {
        #[test]
        fn request_tails_round_trip(tail in tail()) {
            let bytes = bytes_of(&tail);
            prop_assert_eq!(Tail::decode(&bytes, Stage::I1), Ok(tail));
        }
    }
}
