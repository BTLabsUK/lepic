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
