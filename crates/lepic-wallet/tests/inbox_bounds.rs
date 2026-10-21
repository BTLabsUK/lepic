//! The Epicbox inbox stays bounded: a reply the relay will not deliver does not stop the
//! messages behind it, a slate expired by a stale tip is settled after one refresh, and
//! unsolicited payments are capped per sender key and in total.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod send_support;
mod support;
#[path = "inbox/world.rs"]
mod world;

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork, Nonce, Salt, SignedMessage};
use lepic_primitives::amount::Height;
use lepic_store::{AccountIndex, TxDirection, TxState, WalletStore};
use lepic_wallet::Event;
use lepic_wallet::inbox::{
    InboxSummary, ListenHandle, MAX_OPEN_RECEIPTS, MAX_OPEN_RECEIPTS_PER_SENDER,
};
use world::World;

const VECTOR_SLATE_ID: &str = "0436430c-2b02-624c-2032-570501212b03";

/// The upstream S1 vector with its TTL cutoff height.
fn vector_s1() -> (String, u64) {
    let path = format!(
        "{}/../../testdata/vectors/slates/send_file_ttl_s1_v3.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s1 = support::vector_text(&vector, "/expected/json");
    let slate: serde_json::Value = serde_json::from_str(&s1).unwrap();
    let cutoff = slate["ttl_cutoff_height"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    (s1, cutoff)
}

/// The vector S1 under slate id number `n`, so each is a new payment.
fn s1_numbered(n: u32) -> String {
    let (s1, _) = vector_s1();
    assert!(s1.contains(VECTOR_SLATE_ID));
    s1.replace(
        VECTOR_SLATE_ID,
        &format!("00000000-0000-4000-8000-{n:012x}"),
    )
}

fn sender_key(n: u32) -> SecretKey {
    let mut bytes = [0x11_u8; 32];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_array(bytes).unwrap()
}

fn sender_address(n: u32) -> EpicboxAddress {
    EpicboxAddress::new(
        PublicKey::from_secret_key(&sender_key(n)).unwrap(),
        RelayNetwork::Floonet,
        Domain::parse("relay.test").unwrap(),
        Some(80),
    )
}

/// Stores `plaintext` for the receiver as sender number `n` posted it.
fn post_from(world: &World, n: u32, plaintext: &str) -> String {
    let message = SignedMessage::seal(
        plaintext,
        &world.receiver_address,
        &sender_key(n),
        Salt::from([4; 8]),
        Nonce::from([5; 12]),
    )
    .unwrap();
    world
        .relay
        .store(&sender_address(n), &world.receiver_address, &message)
}

/// The receiver's incoming transactions by state.
fn incoming(world: &World, state: TxState) -> usize {
    world
        .receiver
        .store()
        .read(|repos| repos.transactions(AccountIndex(0)))
        .unwrap()
        .iter()
        .filter(|tx| tx.entry.direction == TxDirection::Incoming && tx.entry.state == state)
        .count()
}

#[test]
fn a_reply_the_relay_refuses_does_not_stop_the_payment_behind_it_in_a_drain() {
    let world = World::new();
    world.relay.set_unroutable(&sender_address(1));
    post_from(&world, 1, &s1_numbered(1));
    world.block_on(world.send());

    let mut events = world.receiver_wallet.subscribe();

    let summary = world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            received: 2,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(incoming(&world, TxState::Received), 2);
    let undelivered: Vec<_> = std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::ReplyUndelivered(undelivered) => Some(undelivered),
            _ => None,
        })
        .collect();
    assert_eq!(undelivered.len(), 1);
    assert_eq!(
        undelivered[0].slate_id.to_string(),
        "00000000-0000-4000-8000-000000000001"
    );
    // The second payment's S2 reached its sender.
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

#[test]
fn a_reply_the_relay_refuses_does_not_stop_the_payment_behind_it_in_a_listen() {
    let world = World::new();
    world.relay.set_unroutable(&sender_address(1));
    post_from(&world, 1, &s1_numbered(1));
    world.block_on(world.send());
    let handle = ListenHandle::new();

    let summary = world.block_on(async {
        let listen = world
            .receiver_wallet
            .epicbox_listen(&world.receiver_epicbox, &handle);
        let script = async {
            world.until_acknowledged(&world.receiver_address).await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(summary.unwrap().received, 2);
    assert_eq!(incoming(&world, TxState::Received), 2);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

#[test]
fn a_drain_refreshes_the_tip_once_and_refuses_an_s1_expired_at_its_stale_tip() {
    let world = World::new();
    let (s1, cutoff) = vector_s1();
    post_from(&world, 1, &s1);
    world.block_on(world.send());
    world.receiver.harness.node.update_chain(|chain| {
        chain.tip.height = Height::new(cutoff);
    });

    let summary = world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            received: 1,
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(incoming(&world, TxState::Received), 1);
}

#[test]
fn open_receipts_from_one_sender_key_are_capped() {
    let world = World::new();
    let sent = 1_000;
    for n in 0..sent {
        post_from(&world, 1, &s1_numbered(n));
    }

    let summary = world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();

    let cap = u32::try_from(MAX_OPEN_RECEIPTS_PER_SENDER).unwrap();
    assert_eq!(
        summary,
        InboxSummary {
            received: cap,
            rejected: sent - cap,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.receiver.transactions(), MAX_OPEN_RECEIPTS_PER_SENDER);

    // Another sender is still received.
    post_from(&world, 2, &s1_numbered(sent));
    let summary = world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();
    assert_eq!(summary.received, 1);
}

#[test]
fn open_receipts_over_all_senders_are_capped_by_cancelling_the_oldest() {
    let world = World::new();
    let sent = 1_000;
    for n in 0..sent {
        post_from(&world, n, &s1_numbered(n));
    }

    let summary = world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            received: sent,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(incoming(&world, TxState::Received), MAX_OPEN_RECEIPTS);
    assert_eq!(
        incoming(&world, TxState::Cancelled),
        usize::try_from(sent).unwrap() - MAX_OPEN_RECEIPTS
    );
    // The newest payment is among the open ones, so receiving never stopped.
    let newest = world
        .receiver
        .store()
        .read(|repos| {
            repos.transaction_by_slate(
                uuid::Uuid::parse_str(&format!("00000000-0000-4000-8000-{:012x}", sent - 1))
                    .unwrap(),
                TxDirection::Incoming,
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(newest.entry.state, TxState::Received);
}
