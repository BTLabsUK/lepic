#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

#[test]
fn mailbox_address_follows_the_relay_domain_grammar() {
    for good in [
        "epicbox.epiccash.com",
        "relay-1.example.org:443",
        "a",
        "10.0.0.1:1",
        "x.y:65535",
        "A-b.C9",
    ] {
        assert!(is_mailbox_address(good), "{good}");
    }
    for bad in [
        "",
        "-a.org",
        "a-.org",
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
    ] {
        assert!(!is_mailbox_address(bad), "{bad}");
    }
    assert!(is_mailbox_address(&"a".repeat(128)));
    assert!(!is_mailbox_address(&"a".repeat(129)));
}

#[test]
fn unknown_records_must_be_ignorable_and_increasing() {
    assert_eq!(
        UnknownRecord::new(0x7f, Vec::new()),
        Err(TailError::UnknownRequired { record_type: 0x7f })
    );
    let a = UnknownRecord::new(0x90, vec![1]).unwrap();
    let b = UnknownRecord::new(0x81, vec![2]).unwrap();
    assert_eq!(
        Tail::new(None, None, vec![a, b]),
        Err(TailError::Order {
            previous: 0x90,
            found: 0x81
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
