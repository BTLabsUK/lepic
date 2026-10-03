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
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{Network as RelayNetwork, TRANSPORT_ID};
use lepic_node::mock::MockFailure;
use lepic_store::{InboxEntry, InboxStatus, TxState, WalletStore};
use lepic_transport::transport::{Inbound, Transport};
use lepic_wallet::event::TransportState;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet::{ReceiveRequest, WalletError};
use world::{
    RECEIVER_MNEMONIC, World, settings, transport_reaches, transport_states, until, within,
};

#[test]
fn two_wallets_transact_through_the_relay_across_a_relay_restart() {
    let world = World::new();
    let mut sender_events = world.sender.wallet.subscribe();
    let handle = ListenHandle::new();

    let (listened, received) = world.block_on(async {
        let listen = world
            .sender
            .wallet
            .epicbox_listen(&world.sender_epicbox, &handle);
        let script = async {
            let mut events = world.sender.wallet.subscribe();
            transport_reaches(&mut events, TransportState::Connected).await;
            world.send().await;
            assert_eq!(world.relay.pending(&world.receiver_address), 1);

            world.relay.disconnect_all();
            transport_reaches(&mut events, TransportState::Disconnected).await;
            transport_reaches(&mut events, TransportState::Connected).await;

            let received = world
                .receiver_wallet
                .epicbox_drain(&world.receiver_epicbox)
                .await
                .unwrap();
            until(|| world.sender_state() == TxState::Posted).await;
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
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
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
            .receive(TRANSPORT_ID, envelope.wire(), ReceiveRequest::default())
            .await
            .unwrap();
        drop(subscription);
    });
    assert_eq!(world.receiver.transactions(), 1);
    assert_eq!(world.relay.pending(&world.sender_address), 0);

    let (restarted, epicbox) = world.restart_receiver();
    let summary = world.block_on(restarted.epicbox_drain(&epicbox)).unwrap();

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
        .block_on(world.sender.wallet.epicbox_drain(&world.sender_epicbox))
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
            .receive(TRANSPORT_ID, envelope.wire(), ReceiveRequest::default())
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
    let summary = world.block_on(restarted.epicbox_drain(&epicbox)).unwrap();

    assert_eq!(summary.repeated, 1);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
    assert_eq!(world.receiver.transactions(), 1);
}

/// The crash comes between delivering S2 and recording the message, so the redelivered S1 is
/// answered again with the same stored S2. The sender finalizes once, posts once, and counts
/// the copy as repeated.
#[test]
fn a_crash_right_after_replying_sends_the_same_s2_again_and_the_sender_posts_once() {
    let world = World::new();
    reply_then_crash(&world, false);

    let (restarted, epicbox) = world.restart_receiver();
    let summary = world.block_on(restarted.epicbox_drain(&epicbox)).unwrap();

    assert_eq!(summary.repeated, 1);
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.relay.pending(&world.sender_address), 2);
    assert_eq!(world.receiver.transactions(), 1);

    let sender = world
        .block_on(world.sender.wallet.epicbox_drain(&world.sender_epicbox))
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
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
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
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
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
        .block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox))
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
            .receiver_wallet
            .epicbox_listen(&world.receiver_epicbox, &handle);
        let script = async {
            until(|| world.relay.pending(&world.receiver_address) == 0).await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(summary.unwrap().received, 1);
    assert_eq!(world.receiver.transactions(), 1);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

#[test]
fn stopping_a_listener_returns_promptly_and_reports_the_transport_stopped() {
    let world = World::new();
    let mut events = world.receiver_wallet.subscribe();
    let handle = ListenHandle::new();

    world.block_on(async {
        let listen = world
            .receiver_wallet
            .epicbox_listen(&world.receiver_epicbox, &handle);
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
fn a_locked_wallet_neither_attaches_nor_drains() {
    let world = World::new();
    world.receiver_wallet.lock();
    assert!(matches!(
        world
            .receiver_wallet
            .epicbox_attach(&world.receiver_epicbox),
        Err(InboxError::Wallet(WalletError::Locked))
    ));
    assert!(matches!(
        world.block_on(world.receiver_wallet.epicbox_drain(&world.receiver_epicbox)),
        Err(InboxError::Wallet(WalletError::Locked))
    ));
}

#[test]
fn a_transport_for_the_other_network_is_refused() {
    let world = World::new();
    let mainnet = EpicboxTransport::new(settings(), RelayNetwork::Mainnet, world.relay.connector());
    assert!(matches!(
        world.receiver_wallet.epicbox_attach(&mainnet),
        Err(InboxError::NetworkMismatch)
    ));
}

#[test]
fn the_address_is_the_default_accounts_key_at_index_zero_at_the_relay() {
    let world = World::new();
    let seed = lepic_keychain::Seed::from_mnemonic(RECEIVER_MNEMONIC).unwrap();
    let keychain =
        lepic_keychain::Keychain::from_seed(&seed, lepic_keychain::ExtKeyVersion::FLOONET).unwrap();
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

    use lepic_epicbox::transport::EpicboxPolicy;
    use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
    use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
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
