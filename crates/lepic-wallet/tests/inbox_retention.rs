//! The Epicbox inbox forgets relay message ids the relay can no longer deliver.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod send_support;
mod support;
#[path = "inbox/world.rs"]
mod world;

use std::time::Duration;

use lepic_epicbox::RELAY_RETENTION;
use lepic_store::{InboxEntry, InboxStatus, WalletStore};
use world::World;

const ONE_HOUR: Duration = Duration::from_secs(60 * 60);

#[test]
fn a_drain_prunes_inbox_entries_older_than_the_relay_retention() {
    let world = World::new();
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

    world
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
        .unwrap();

    assert_eq!(world.receiver.inbox("expired"), None);
    assert!(world.receiver.inbox("recent").is_some());
}
