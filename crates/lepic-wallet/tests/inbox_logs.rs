//! Inbox logs in their own binary, for the reason `lifecycle_logs.rs` gives.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;
#[path = "inbox/world.rs"]
mod world;

use lepic_keychain::{Identifier, Keychain, Seed};
use lepic_primitives::params::Network;
use lepic_store::{SlateStage, WalletStore};
use lepic_telemetry::{assert_no_secrets, capture};
use world::{RECEIVER_MNEMONIC, World};

#[test]
fn a_drain_never_logs_keys_or_slates() {
    let world = World::new();
    world.block_on(world.send());

    let (summary, captured) = capture(|| {
        world
            .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
            .unwrap()
    });
    assert_eq!(summary.received, 1);

    let seed = Seed::from_mnemonic(RECEIVER_MNEMONIC).unwrap();
    let keychain = Keychain::from_seed(&seed, Network::Floonet).unwrap();
    let address_key = keychain
        .address_key(&Identifier::new(2, [0, 0, 0, 0]).unwrap(), 0)
        .unwrap();
    let s2 = world
        .receiver
        .store()
        .read(|repos| {
            let transaction = &repos.transactions(lepic_store::AccountIndex(0))?[0];
            repos.slate(transaction.entry.slate_id.unwrap(), SlateStage::Standard2)
        })
        .unwrap()
        .unwrap();
    let words: Vec<&str> = RECEIVER_MNEMONIC.split(' ').collect();
    let pairs: Vec<String> = words.windows(2).map(|pair| pair.join(" ")).collect();
    let mut secrets: Vec<&[u8]> = vec![
        seed.expose_bytes(),
        address_key.expose_bytes(),
        // The decrypted payload and the reply, whole.
        &s2.bytes,
    ];
    secrets.extend(pairs.iter().map(String::as_bytes));
    assert_no_secrets(&captured.records, &secrets).unwrap();

    let record = captured
        .records
        .iter()
        .find(|record| record.message == "slate received" && record.spans.contains(&"receive"))
        .unwrap_or_else(|| panic!("no \"slate received\": {:?}", captured.records));
    assert!(record.spans.contains(&"epicbox_drain"), "{record}");
    assert_eq!(record.field("transport"), Some("epicbox"), "{record}");
}
