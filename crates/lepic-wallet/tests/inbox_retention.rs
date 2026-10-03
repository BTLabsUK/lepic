//! The Epicbox inbox forgets relay message ids the relay can no longer deliver, when a drain or
//! listen starts and as messages settle during a listen.

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

use std::time::Duration;

use lepic_epicbox::RELAY_RETENTION;
use lepic_store::{InboxEntry, InboxStatus, WalletStore};
use lepic_wallet::event::TransportState;
use lepic_wallet::inbox::ListenHandle;
use world::{World, transport_reaches, until};

const ONE_HOUR: Duration = Duration::from_secs(60 * 60);

/// Stores one entry received just past the relay retention and one just within it.
fn store_expired_and_recent_entries(world: &World) {
    let now = support::fixed_time();
    let expired = now.checked_sub(RELAY_RETENTION + ONE_HOUR).unwrap();
    let recent = now.checked_sub(RELAY_RETENTION - ONE_HOUR).unwrap();
    world
        .receiver
        .store()
        .write(|repos| {
            for (msg_id, received_at) in [("expired", expired), ("recent", recent)] {
                repos.put_inbox(&InboxEntry {
                    msg_id: msg_id.to_owned(),
                    status: InboxStatus::Acknowledged,
                    received_at,
                    updated_at: received_at,
                })?;
            }
            Ok::<_, lepic_store::StoreError>(())
        })
        .unwrap();
}

#[test]
fn a_drain_prunes_inbox_entries_older_than_the_relay_retention() {
    let world = World::new();
    store_expired_and_recent_entries(&world);

    world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();

    assert_eq!(world.receiver.inbox("expired"), None);
    assert!(world.receiver.inbox("recent").is_some());
}

/// Entries that expire while a listen is open are pruned when the next message settles, not
/// only when a listen starts.
#[test]
fn a_long_listen_prunes_inbox_entries_as_messages_settle() {
    let world = World::new();
    let handle = ListenHandle::new();

    let summary = world.block_on(async {
        let listen = world
            .receiver_wallet
            .epicbox_listen(&world.receiver_epicbox, &handle);
        let script = async {
            let mut events = world.receiver_wallet.subscribe();
            transport_reaches(&mut events, TransportState::Connected).await;
            store_expired_and_recent_entries(&world);
            world.send().await;
            until(|| world.relay.pending(&world.receiver_address) == 0).await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(summary.unwrap().received, 1);
    assert_eq!(world.receiver.inbox("expired"), None);
    assert!(world.receiver.inbox("recent").is_some());
}
