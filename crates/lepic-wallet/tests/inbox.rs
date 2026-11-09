// SPDX-License-Identifier: Apache-2.0
//! The Epicbox inbox: two LEPIC wallets transact through the mock relay; redeliveries after a
//! crash produce no second S2; messages that cannot be used are recorded and acknowledged; a
//! transient failure leaves the message on the relay.

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

use lepic_crypto::PublicKey;
use lepic_epicbox::{Network as RelayNetwork, RELAY_RETENTION, TRANSPORT_ID};
use lepic_methods::epicbox::Epicbox;
use lepic_node::mock::MockFailure;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{AccountIndex, InboxEntry, InboxStatus, TxDirection, TxState, WalletStore};
use lepic_transport::transport::{Destination, Inbound, Location, Transport};
use lepic_wallet::details::{SlateMessage, TxFlow};
use lepic_wallet::event::{Connection, TransportState, TransportStatus};
use lepic_wallet::inbox::{Handled, InboxError, InboxSummary, ListenHandle};
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::slate::Role;
use lepic_wallet::{Event, ReceiveRequest, WalletError};
use world::{
    RECEIVER_MNEMONIC, World, request, settings, transport_reaches, transport_states, within,
};

#[test]
fn two_wallets_transact_through_the_relay_across_a_relay_restart() {
    let world = World::new();
    let mut sender_events = world.sender.wallet.subscribe();
    let handle = ListenHandle::new();

    let (listened, received) = world.block_on(async {
        let listen = world.sender_epicbox.listen(&world.sender.wallet, &handle);
        let script = async {
            let mut events = world.sender.wallet.subscribe();
            transport_reaches(&mut events, TransportState::Connected).await;
            world.send().await;
            assert_eq!(world.relay.pending(&world.receiver_address), 1);

            world.relay.disconnect_all();
            transport_reaches(&mut events, TransportState::Disconnected).await;
            transport_reaches(&mut events, TransportState::Connected).await;

            let received = world
                .receiver_epicbox
                .drain(&world.receiver_wallet)
                .await
                .unwrap();
            // The listen acknowledges S2 only after posting and recording it; a stop before
            // then would abandon S2 in hand and count it as held.
            world.until_acknowledged(&world.sender_address).await;
            assert_eq!(world.sender_state(), TxState::Posted);
            handle.stop();
            received
        };
        tokio::join!(listen, script)
    });

    assert_eq!(
        received,
        InboxSummary {
            received: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        listened.unwrap(),
        InboxSummary {
            finalized: 1,
            ..InboxSummary::default()
        }
    );
    // Both wallets run LEPIC, so the sender told the receiver it posted the payment.
    assert_eq!(world.relay.pending(&world.receiver_address), 1);
    assert_eq!(
        world
            .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
            .unwrap(),
        InboxSummary {
            notices: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.sender_address), 0);
    assert_eq!(world.sender.harness.node.pushed_transactions().len(), 1);
    assert_eq!(world.receiver.transactions(), 1);
    let states = transport_states(&mut sender_events);
    assert_eq!(states.first(), Some(&TransportState::Connecting));
    assert_eq!(states.last(), Some(&TransportState::Stopped));
    // The watch channel may skip the short `Connecting` between the two.
    let dropped = states
        .iter()
        .position(|state| *state == TransportState::Disconnected)
        .unwrap();
    assert!(
        states[dropped..].contains(&TransportState::Connected),
        "{states:?}"
    );
}

#[test]
fn each_side_records_the_others_epicbox_address() {
    let world = World::new();
    world.block_on(async {
        world.send().await;
        world
            .receiver_epicbox
            .drain(&world.receiver_wallet)
            .await
            .unwrap();
    });

    let counterparty = |wallet: &support::TestWallet| {
        let transactions = world
            .block_on(wallet.transactions(AccountIndex(0)))
            .unwrap();
        assert_eq!(transactions.len(), 1);
        transactions[0]
            .counterparty
            .as_ref()
            .map(|address| address.as_str().to_owned())
    };
    assert_eq!(
        counterparty(&world.receiver_wallet),
        Some(world.sender_address.to_string())
    );
    assert_eq!(
        counterparty(&world.sender.wallet),
        Some(world.receiver_address.to_string())
    );
}

#[test]
fn a_send_and_its_receive_are_payments() {
    let world = World::new();
    world.block_on(async {
        world.send().await;
        world
            .receiver_epicbox
            .drain(&world.receiver_wallet)
            .await
            .unwrap();
    });

    let only = |wallet: &support::TestWallet| {
        let transactions = world
            .block_on(wallet.transactions(AccountIndex(0)))
            .unwrap();
        assert_eq!(transactions.len(), 1);
        let details = &transactions[0];
        (details.transaction.entry.direction, details.flow)
    };
    assert_eq!(
        only(&world.sender.wallet),
        (TxDirection::Outgoing, TxFlow::Payment)
    );
    assert_eq!(
        only(&world.receiver_wallet),
        (TxDirection::Incoming, TxFlow::Payment)
    );
}

/// The receiver stores S2 and stops before replying or acknowledging, as an app suspended at the
/// worst moment does. After a restart the relay delivers S1 again and the stored S2 goes out.
#[test]
fn a_crash_between_storing_s2_and_acknowledging_gives_exactly_one_s2() {
    let world = World::new();
    world.block_on(async {
        world.send().await;
        let client = world.receiver_epicbox.client().unwrap();
        let subscription = client.drain().unwrap();
        let envelope = within(subscription.next_envelope()).await.unwrap().unwrap();
        world
            .receiver_wallet
            .receive(
                &world.receiver_method,
                envelope.wire(),
                ReceiveRequest::default(),
            )
            .await
            .unwrap();
        drop(subscription);
    });
    assert_eq!(world.receiver.transactions(), 1);
    assert_eq!(world.relay.pending(&world.sender_address), 0);

    let (restarted, epicbox) = world.restart_receiver();
    let summary = world.block_on(epicbox.drain(&restarted)).unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
    assert_eq!(world.receiver.transactions(), 1);
    let finalized = world
        .block_on(world.sender_epicbox.drain(&world.sender.wallet))
        .unwrap();
    assert_eq!(finalized.finalized, 1);
    assert_eq!(world.sender_state(), TxState::Posted);
    assert_eq!(world.sender.harness.node.pushed_transactions().len(), 1);
}

/// Receives the pending S1 outside the inbox and delivers the S2 reply, then drops the
/// subscription without acknowledging, as a crash right after replying does. With
/// `record_processed` the crash comes after the inbox recorded the message as processed.
fn reply_then_crash(world: &World, record_processed: bool) {
    world.block_on(async {
        world.send().await;
        let client = world.receiver_epicbox.client().unwrap();
        let subscription = client.drain().unwrap();
        let envelope = within(subscription.next_envelope()).await.unwrap().unwrap();
        let received = world
            .receiver_wallet
            .receive(
                &world.receiver_method,
                envelope.wire(),
                ReceiveRequest::default(),
            )
            .await
            .unwrap();
        world
            .receiver_epicbox
            .outbound()
            .unwrap()
            .deliver(envelope.reply_to().unwrap(), &received.reply)
            .await
            .unwrap();
        if record_processed {
            let at = support::fixed_time();
            world
                .receiver
                .store()
                .write(|repos| {
                    repos.put_inbox(&InboxEntry {
                        msg_id: envelope.ack_token().as_str().to_owned(),
                        status: InboxStatus::Processed,
                        received_at: at,
                        updated_at: at,
                    })
                })
                .unwrap();
        }
        drop(subscription);
    });
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

/// The crash comes after the inbox recorded the message as processed and before the relay
/// heard `Made`. The redelivery is acknowledged without another reply.
#[test]
fn a_crash_after_recording_processed_and_before_acknowledging_sends_no_second_s2() {
    let world = World::new();
    reply_then_crash(&world, true);

    let (restarted, epicbox) = world.restart_receiver();
    let summary = world.block_on(epicbox.drain(&restarted)).unwrap();

    assert_eq!(summary.repeated, 1);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
    assert_eq!(world.receiver.transactions(), 1);
}

/// A copy under a relay id the inbox recorded as settled is acknowledged without an answer, so
/// it announces nothing: neither a payment nor an answer given again.
#[test]
fn a_settled_copy_of_an_s1_emits_no_receipt_event() {
    let world = World::new();
    reply_then_crash(&world, true);

    let (restarted, epicbox) = world.restart_receiver();
    let mut events = restarted.subscribe();
    let summary = world.block_on(epicbox.drain(&restarted)).unwrap();

    assert_eq!(summary.repeated, 1);
    let receipts: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::Received(_) | Event::AnsweredAgain(_)))
        .collect();
    assert_eq!(receipts, []);
}

/// The crash comes between delivering S2 and recording the message, so the redelivered S1 is
/// answered again with the same stored S2. The sender finalizes once, posts once, and counts
/// the copy as repeated.
#[test]
fn a_crash_right_after_replying_sends_the_same_s2_again_and_the_sender_posts_once() {
    let world = World::new();
    reply_then_crash(&world, false);

    let (restarted, epicbox) = world.restart_receiver();
    let summary = world.block_on(epicbox.drain(&restarted)).unwrap();

    assert_eq!(summary.repeated, 1);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 2);
    assert_eq!(world.receiver.transactions(), 1);

    let sender = world
        .block_on(world.sender_epicbox.drain(&world.sender.wallet))
        .unwrap();
    assert_eq!(
        sender,
        InboxSummary {
            finalized: 1,
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.sender_address), 0);
    assert_eq!(world.sender_state(), TxState::Posted);
    assert_eq!(world.sender.harness.node.pushed_transactions().len(), 1);
}

#[test]
fn messages_that_cannot_be_used_are_recorded_and_acknowledged_and_the_next_one_is_handled() {
    let world = World::new();
    let forged = world.post_to_receiver(7, 8, "{}");
    let undecodable = world.post_to_receiver(7, 7, "not a slate");
    world.block_on(world.send());

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            received: 1,
            rejected: 2,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    for msg_id in [&forged, &undecodable] {
        assert_eq!(
            world.receiver.inbox(msg_id).unwrap().status,
            InboxStatus::Rejected
        );
    }
    assert_eq!(world.receiver.transactions(), 1);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

/// A slate exported as a file can be answered by anyone holding a copy, so an answer to it that
/// a relay delivers is refused, and the send waits for the user to import the real answer.
#[test]
fn an_answer_over_epicbox_to_an_s1_exported_as_a_file_is_not_finalized() {
    let world = World::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send.slate");
    world
        .block_on(world.sender.wallet.send(
            &crate::support::file(),
            request(),
            Delivery::Export {
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
    let s1 = WireSlate::text(MediaType::JSON, std::fs::read_to_string(&path).unwrap());
    let answer = world
        .block_on(world.receiver_wallet.receive(
            &world.receiver_method,
            &s1,
            ReceiveRequest::default(),
        ))
        .unwrap();
    let posted = world.post_to_sender(9, answer.reply.as_text().unwrap());

    let summary = world
        .block_on(world.sender_epicbox.drain(&world.sender.wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    let entry = world
        .sender
        .store
        .read(|repos| repos.inbox(&posted))
        .unwrap()
        .unwrap();
    assert_eq!(entry.status, InboxStatus::Rejected);
    assert_eq!(world.sender_state(), TxState::Sent);
    assert!(world.sender.harness.node.pushed_transactions().is_empty());
}

/// An S1 sent over Epicbox is finalized only from the key it went to: an answer posted from
/// another key is refused, and the intended receiver's own answer still goes through.
#[test]
fn an_answer_from_another_key_than_the_receivers_is_not_finalized() {
    let world = World::new();
    world.block_on(world.send());
    let s1 = WireSlate::text(MediaType::JSON, peek_s1(&world));
    let answer = world
        .block_on(world.receiver_wallet.receive(
            &world.receiver_method,
            &s1,
            ReceiveRequest::default(),
        ))
        .unwrap();
    world.post_to_sender(9, answer.reply.as_text().unwrap());

    let refused = world
        .block_on(world.sender_epicbox.drain(&world.sender.wallet))
        .unwrap();
    assert_eq!(
        refused,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.sender_state(), TxState::Sent);

    world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();
    let finalized = world
        .block_on(world.sender_epicbox.drain(&world.sender.wallet))
        .unwrap();
    assert_eq!(finalized.finalized, 1);
    assert_eq!(world.sender_state(), TxState::Posted);
    assert_eq!(world.sender.harness.node.pushed_transactions().len(), 1);
}

/// The S1 the sender posted, read without acknowledging it, so the relay delivers it again.
fn peek_s1(world: &World) -> String {
    world.block_on(async {
        let client = world.receiver_epicbox.client().unwrap();
        let subscription = client.drain().unwrap();
        let envelope = within(subscription.next_envelope()).await.unwrap().unwrap();
        envelope.wire().as_text().unwrap().to_owned()
    })
}

/// Another S1 under the slate id of one the receiver answered is rejected for good: no S2 goes
/// to anyone and nothing is stored.
#[test]
fn a_changed_s1_under_a_received_slate_id_is_rejected() {
    let world = World::new();
    world.block_on(world.send());
    let mut changed: serde_json::Value = serde_json::from_str(&peek_s1(&world)).unwrap();
    changed["amount"] = match &changed["amount"] {
        serde_json::Value::String(_) => serde_json::Value::String("1".to_owned()),
        _ => serde_json::Value::from(1),
    };
    let first = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();
    assert_eq!(first.received, 1, "{first:?}");
    let msg_id = world.post_to_receiver(7, 7, &changed.to_string());

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        world.receiver.inbox(&msg_id).unwrap().status,
        InboxStatus::Rejected
    );
    assert_eq!(world.relay.pending(&World::address_of(7)), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
    assert_eq!(world.receiver.transactions(), 1);
}

/// The same S1 under a second relay message id, as a sender that sent it twice posts it: the
/// first copy is announced as received, the second only as answered again.
#[test]
fn an_s1_delivered_twice_is_announced_as_received_then_as_answered_again() {
    let world = World::new();
    world.block_on(world.send());
    let s1 = peek_s1(&world);
    world.post_to_receiver(7, 7, &s1);
    let mut events = world.receiver_wallet.subscribe();

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            received: 1,
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    let receipts: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::Received(_) | Event::AnsweredAgain(_)))
        .collect();
    let [Event::Received(received), Event::AnsweredAgain(again)] = receipts.as_slice() else {
        panic!("{receipts:?}");
    };
    assert_eq!(again.tx_id, received.tx_id);
    assert_eq!(again.transport, TRANSPORT_ID);
    assert_eq!(world.receiver.transactions(), 1);
}

/// The receiver stored S2 and cancelled before replying; the redelivered S1 is rejected, not
/// answered with the S2 whose output the cancel released.
#[test]
fn an_s1_redelivered_after_its_receive_was_cancelled_is_rejected() {
    let world = World::new();
    let (tx_id, msg_id) = world.block_on(async {
        world.send().await;
        let client = world.receiver_epicbox.client().unwrap();
        let subscription = client.drain().unwrap();
        let envelope = within(subscription.next_envelope()).await.unwrap().unwrap();
        let received = world
            .receiver_wallet
            .receive(
                &world.receiver_method,
                envelope.wire(),
                ReceiveRequest::default(),
            )
            .await
            .unwrap();
        (received.tx_id, envelope.ack_token().as_str().to_owned())
    });
    world.block_on(world.receiver_wallet.cancel(tx_id)).unwrap();

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        world.receiver.inbox(&msg_id).unwrap().status,
        InboxStatus::Rejected
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 0);
    assert_eq!(world.receiver.transactions(), 1);
}

#[test]
fn an_s1_expired_by_the_tip_alone_stays_on_the_relay_while_no_refresh_confirms_the_height() {
    let world = World::new();
    let path = format!(
        "{}/../../testdata/vectors/slates/send_file_ttl_s1_v3.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s1 = support::vector_text(&vector, "/expected/json");
    let slate: serde_json::Value = serde_json::from_str(&s1).unwrap();
    let cutoff: u64 = slate["ttl_cutoff_height"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let msg_id = world.post_to_receiver(7, 7, &s1);
    // Further ahead than one node answer may move the confirmed height, so the refresh the
    // drain makes before holding the slate keeps this tip pending.
    world.receiver.harness.node.update_chain(|chain| {
        chain.tip.height = lepic_primitives::amount::Height::new(
            cutoff + lepic_wallet::chain::TIP_STEP_BLOCKS + 1,
        );
    });

    let held = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        held,
        InboxSummary {
            held: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 1);
    assert_ne!(
        world.receiver.inbox(&msg_id).map(|entry| entry.status),
        Some(InboxStatus::Rejected)
    );

    world.block_on(world.receiver_wallet.refresh()).unwrap();
    let rejected = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(rejected.rejected, 1);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.receiver.transactions(), 0);
}

#[test]
fn a_transient_failure_leaves_the_message_on_the_relay_for_the_next_drain() {
    let world = World::new();
    world.block_on(world.send());
    world
        .receiver
        .harness
        .node
        .fail_next("get_tip", MockFailure::Unreachable);

    let held = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        held,
        InboxSummary {
            held: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 1);
    assert_eq!(world.receiver.transactions(), 0);

    let retried = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();
    assert_eq!(retried.received, 1);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
}

#[test]
fn a_listener_retries_a_held_message_until_it_settles() {
    let world = World::new();
    world.block_on(world.send());
    world
        .receiver
        .harness
        .node
        .fail_next("get_tip", MockFailure::Unreachable);
    let handle = ListenHandle::new();

    let summary = world.block_on(async {
        let listen = world
            .receiver_epicbox
            .listen(&world.receiver_wallet, &handle);
        let script = async {
            world.until_acknowledged(&world.receiver_address).await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(summary.unwrap().received, 1);
    assert_eq!(world.receiver.transactions(), 1);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

#[test]
fn the_receiver_sees_the_senders_message_after_a_listener_receive() {
    let world = World::new();
    world
        .block_on(world.sender.wallet.send(
            &world.sender_method,
            SendRequest {
                message: Some("for the pizza".to_owned()),
                ..world::request()
            },
            Delivery::Deliver {
                to: Destination::new(world.receiver_address.to_string()),
            },
        ))
        .unwrap();
    let handle = ListenHandle::new();

    world.block_on(async {
        let listen = world
            .receiver_epicbox
            .listen(&world.receiver_wallet, &handle);
        let script = async {
            world.until_acknowledged(&world.receiver_address).await;
            handle.stop();
        };
        tokio::join!(listen, script).0.unwrap();
    });

    let transactions = world
        .block_on(world.receiver_wallet.transactions(AccountIndex(0)))
        .unwrap();
    let [received] = transactions.as_slice() else {
        panic!("{transactions:?}");
    };
    assert_eq!(
        received.messages,
        [SlateMessage {
            role: Role::Sender,
            text: "for the pizza".to_owned(),
        }]
    );
}

#[test]
fn stopping_a_listener_returns_promptly_and_reports_the_transport_stopped() {
    let world = World::new();
    let mut events = world.receiver_wallet.subscribe();
    let handle = ListenHandle::new();

    world.block_on(async {
        let listen = world
            .receiver_epicbox
            .listen(&world.receiver_wallet, &handle);
        let script = async {
            let mut events = world.receiver_wallet.subscribe();
            transport_reaches(&mut events, TransportState::Connected).await;
            handle.stop();
            tokio::time::Instant::now()
        };
        let (listened, stopped_at) = tokio::join!(listen, script);
        assert_eq!(listened.unwrap(), InboxSummary::default());
        assert!(stopped_at.elapsed() < Duration::from_secs(1));
    });

    assert_eq!(
        transport_states(&mut events).last(),
        Some(&TransportState::Stopped)
    );
}

#[test]
fn finishing_an_idle_listener_returns_promptly_and_reports_the_transport_stopped() {
    let world = World::new();
    let mut events = world.receiver_wallet.subscribe();
    let handle = ListenHandle::new();

    world.block_on(async {
        let listen = world
            .receiver_epicbox
            .listen(&world.receiver_wallet, &handle);
        let script = async {
            let mut events = world.receiver_wallet.subscribe();
            transport_reaches(&mut events, TransportState::Connected).await;
            handle.finish();
            tokio::time::Instant::now()
        };
        let (listened, finished_at) = tokio::join!(listen, script);
        assert_eq!(listened.unwrap(), InboxSummary::default());
        assert!(finished_at.elapsed() < Duration::from_secs(1));
    });

    assert!(handle.is_stopped());
    assert_eq!(world.relay.connections(), 0);
    assert_eq!(
        transport_states(&mut events).last(),
        Some(&TransportState::Stopped)
    );
}

#[test]
fn a_drain_beside_a_listener_reports_its_connection_as_its_own() {
    let world = World::new();
    let mut events = world.receiver_wallet.subscribe();
    let handle = ListenHandle::new();

    world.block_on(async {
        let listen = world
            .receiver_epicbox
            .listen(&world.receiver_wallet, &handle);
        let script = async {
            let mut events = world.receiver_wallet.subscribe();
            transport_reaches(&mut events, TransportState::Connected).await;
            world.relay.set_refusing(true);
            let refused = world.receiver_epicbox.drain(&world.receiver_wallet).await;
            assert!(
                matches!(refused, Err(InboxError::Subscription(_))),
                "{refused:?}"
            );
            world.relay.set_refusing(false);
            within(world.receiver_epicbox.drain(&world.receiver_wallet))
                .await
                .unwrap();
            handle.stop();
        };
        let (listened, ()) = tokio::join!(listen, script);
        listened.unwrap();
    });

    let mut listener = Vec::new();
    let mut drains = Vec::new();
    let mut disconnects = Vec::new();
    while let Ok(event) = events.try_recv() {
        match event {
            Event::Transport(TransportStatus {
                connection, state, ..
            }) => match connection {
                Connection::Listener => listener.push(state),
                Connection::PaymentsDrain => drains.push((connection, state)),
            },
            Event::TransportDisconnected(disconnect) => disconnects.push(disconnect.connection),
            _ => {}
        }
    }
    assert_eq!(
        listener
            .iter()
            .filter(|state| **state == TransportState::Connected)
            .count(),
        1,
        "{listener:?}"
    );
    assert!(
        !listener.contains(&TransportState::Disconnected),
        "{listener:?}"
    );
    assert_eq!(listener.last(), Some(&TransportState::Stopped));
    assert!(drains.contains(&(Connection::PaymentsDrain, TransportState::Disconnected)));
    assert!(
        drains
            .iter()
            .all(|(connection, _)| *connection == Connection::PaymentsDrain)
    );
    assert!(!disconnects.is_empty());
    assert!(
        disconnects
            .iter()
            .all(|connection| *connection == Connection::PaymentsDrain)
    );
}

#[test]
fn a_locked_wallet_neither_attaches_nor_drains() {
    let world = World::new();
    world.receiver_wallet.lock();
    assert!(matches!(
        world.receiver_epicbox.attach_wallet(&world.receiver_wallet),
        Err(InboxError::Wallet(WalletError::Locked))
    ));
    assert!(matches!(
        world.block_on(world.receiver_epicbox.drain(&world.receiver_wallet)),
        Err(InboxError::Wallet(WalletError::Locked))
    ));
}

#[test]
fn a_transport_for_the_other_network_is_refused() {
    let world = World::new();
    let mainnet = Epicbox::new(settings(), RelayNetwork::Mainnet, world.relay.connector());
    assert!(matches!(
        mainnet.attach_wallet(&world.receiver_wallet),
        Err(InboxError::NetworkMismatch)
    ));
}

#[test]
fn the_address_is_the_default_accounts_key_at_index_zero_at_the_relay() {
    let world = World::new();
    let seed = lepic_keychain::Seed::from_mnemonic(RECEIVER_MNEMONIC).unwrap();
    let keychain =
        lepic_keychain::Keychain::from_seed(&seed, lepic_primitives::params::Network::Floonet)
            .unwrap();
    let parent = lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap();
    let key = keychain.address_key(&parent, 0).unwrap();
    assert_eq!(
        world.receiver_address.public_key(),
        &PublicKey::from_secret_key(&key).unwrap()
    );
    assert_eq!(world.receiver_address.domain().as_str(), "relay.test");
    assert_eq!(world.receiver_address.port(), Some(80));
    assert_eq!(
        world.receiver_address.to_string(),
        world
            .receiver_epicbox
            .client()
            .unwrap()
            .address()
            .to_string()
    );
}

mod policy {
    //! The Epicbox format policy against the G-03 Epicbox payloads: what upstream's Epicbox
    //! sender and receiver put on the wire.

    use lepic_legacy_slate::v2_json::LEGACY_V2_JSON;
    use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
    use lepic_methods::epicbox::EpicboxPolicy;
    use lepic_slate::codec::{EncodeContext, MediaType, WireSlate};
    use lepic_slate::model::Slate;
    use lepic_slate::origin::{LegacyHeader, WireOrigin};
    use lepic_transport::policy::FormatPolicy;
    use serde_json::Value;

    use crate::send_support::legacy_codecs;
    use crate::support::vector_text;

    const CASES: [&str; 2] = ["send_epicbox_message", "send_epicbox_header_7"];

    fn payload(name: &str) -> String {
        let path = format!(
            "{}/../../testdata/vectors/slates/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        vector_text(&vector, "/expected/json")
    }

    fn decode(json: &str) -> Slate {
        EpicboxPolicy
            .decode(
                &legacy_codecs(),
                &WireSlate::text(MediaType::JSON, json.to_owned()),
            )
            .unwrap()
    }

    fn header(slate: &Slate) -> LegacyHeader {
        slate.origin().and_then(WireOrigin::legacy_header).unwrap()
    }

    #[test]
    fn a_new_slate_goes_out_as_upstreams_epicbox_sender_writes_it() {
        for case in CASES {
            let expected = payload(&format!("{case}_s1_epicbox"));
            let slate = decode(&expected);
            let context = EncodeContext {
                block_header_version: header(&slate).block_header_version,
            };
            let wire = EpicboxPolicy
                .encode_new_slate(&legacy_codecs(), &slate.with_origin(None), &context)
                .unwrap();
            assert_eq!(wire.as_text().unwrap(), expected, "{case}");
        }
    }

    #[test]
    fn a_reply_keeps_the_shape_and_header_it_answers() {
        for case in CASES {
            let s1 = decode(&payload(&format!("{case}_s1_epicbox")));
            let expected = payload(&format!("{case}_s2_epicbox"));
            let s2 = decode(&expected);
            assert_eq!(s2.origin().unwrap().codec(), LEGACY_V2_JSON, "{case}");
            assert_eq!(header(&s2), header(&s1), "{case}");
            // A header other than the chain's shows that the reply echoes rather than derives.
            let context = EncodeContext {
                block_header_version: 1,
            };
            let wire = EpicboxPolicy
                .encode_reply(&legacy_codecs(), &s2, &context)
                .unwrap();
            assert_eq!(wire.as_text().unwrap(), expected, "{case}");
        }
    }

    #[test]
    fn a_v3_shaped_slate_is_read_as_v3_and_answered_in_v3() {
        let slate = decode(&payload("send_epicbox_message_s1_v3"));
        assert_eq!(slate.origin().unwrap().codec(), LEGACY_V3_JSON);
        let encoding = EpicboxPolicy.for_reply(
            &slate,
            &EncodeContext {
                block_header_version: 7,
            },
        );
        assert_eq!(encoding.codec, LEGACY_V3_JSON);
        assert_eq!(encoding.legacy_header, Some(header(&slate)));
    }

    #[test]
    fn a_new_slate_is_never_v3_so_a_ttl_is_refused_rather_than_dropped() {
        let slate = decode(&payload("send_file_ttl_payment_proof_messages_s1_v3"));
        let context = EncodeContext {
            block_header_version: 7,
        };
        assert_eq!(
            EpicboxPolicy.for_new_slate(&slate, &context).codec,
            LEGACY_V2_JSON
        );
        assert!(
            EpicboxPolicy
                .encode_new_slate(&legacy_codecs(), &slate.with_origin(None), &context)
                .is_err()
        );
    }
}

/// A pair-request hook whose store always fails, counting its tries.
struct FailingPairRequests(std::sync::Arc<std::sync::atomic::AtomicU32>);

impl<N, S: lepic_wallet::StoreOpener, V> lepic_wallet::extension::PairRequests<N, S, V>
    for FailingPairRequests
{
    fn take<'a>(
        &'a self,
        _wallet: &'a lepic_wallet::Wallet<N, S, V>,
        _sender: &'a str,
        _invite_link: String,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send
                + 'a,
        >,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err("store unavailable".into()) })
    }
}

#[test]
fn a_pair_request_the_store_keeps_refusing_is_acknowledged_after_three_tries() {
    let world = World::new();
    let tries = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    assert!(
        world
            .receiver_wallet
            .set_pair_requests(std::sync::Arc::new(FailingPairRequests(tries.clone())))
    );
    let request = lepic_wallet::notice::pair_request_to("epiccash://pair/1/x", &[512], 512);
    world.post_to_receiver(7, 7, &request);
    let handle = ListenHandle::new();

    world.block_on(async {
        let listen = world
            .receiver_epicbox
            .listen(&world.receiver_wallet, &handle);
        let script = async {
            world.until_acknowledged(&world.receiver_address).await;
            handle.stop();
        };
        tokio::join!(listen, script).0.unwrap();
    });

    assert_eq!(tries.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
}

#[test]
fn an_acknowledgement_recorded_before_the_settlement_gives_way_to_it() {
    let world = World::new();
    let wallet = &world.receiver_wallet;

    world.block_on(wallet.arrival_acknowledged("early", Handled::Received));
    let acknowledged = world.receiver.inbox("early").unwrap();
    assert_eq!(acknowledged.status, InboxStatus::Acknowledged);
    world
        .block_on(wallet.arrival_settled("early", Handled::Received, None, RELAY_RETENTION))
        .unwrap();

    let settled = world.receiver.inbox("early").unwrap();
    assert_eq!(settled.status, InboxStatus::Processed);
    assert_eq!(settled.received_at, acknowledged.received_at);
}

#[test]
fn a_settlement_of_an_id_never_seen_records_it() {
    let world = World::new();
    let wallet = &world.receiver_wallet;
    assert_eq!(world.receiver.inbox("unseen"), None);

    world
        .block_on(wallet.arrival_settled("unseen", Handled::Rejected, None, RELAY_RETENTION))
        .unwrap();

    let entry = world.receiver.inbox("unseen").unwrap();
    assert_eq!(entry.status, InboxStatus::Rejected);
    assert_eq!(entry.received_at, entry.updated_at);
}
