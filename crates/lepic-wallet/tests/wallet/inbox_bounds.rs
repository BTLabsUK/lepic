// SPDX-License-Identifier: Apache-2.0
//! The Epicbox inbox stays bounded: a reply the relay refuses or never answers does not stop the
//! messages behind it, a slate expired by a stale tip is settled after one refresh, and
//! unsolicited payments are capped per sender key and in total: at a cap a new S1 is refused
//! and no open receipt is cancelled.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::inbox_world as world;
use crate::send_support;
use crate::support;

use lepic_crypto::aggsig;
use lepic_crypto::{Commitment, PublicKey, RangeProof, SecretKey};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork, Nonce, Salt, SignedMessage};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_node::LocatedKernel;
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_primitives::amount::Height;
use lepic_primitives::committed::sum_commitments;
use lepic_primitives::kernel::TxKernel;
use lepic_primitives::params::Network;
use lepic_primitives::tx::TransactionBody;
use lepic_slate::codec::{MediaType, WireSlate};
use std::time::Duration;

use lepic_store::{
    AccountIndex, InboxEntry, InboxStatus, OutputRecord, SlateStage, TxDirection, TxId, TxState,
    WalletStore,
};
use lepic_wallet::event::{ReceiptCap, RefusedPayment};
use lepic_wallet::inbox::{InboxSummary, ListenHandle};
use lepic_wallet::{Event, WalletPolicy};
use world::World;

const MAX_OPEN_RECEIPTS: usize = WalletPolicy::DEFAULT.max_open_receipts;
const MAX_OPEN_RECEIPTS_PER_SENDER: usize = WalletPolicy::DEFAULT.max_open_receipts_per_sender;

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
    world.relay.set_post_refused(&sender_address(1));
    post_from(&world, 1, &s1_numbered(1));
    world.block_on(world.send());

    let mut events = world.receiver_wallet.subscribe();

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
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
    world.relay.set_post_refused(&sender_address(1));
    post_from(&world, 1, &s1_numbered(1));
    world.block_on(world.send());
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
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
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
    let sent = 100;
    for n in 0..sent {
        post_from(&world, 1, &s1_numbered(n));
    }
    let mut events = world.receiver_wallet.subscribe();

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    let cap = u32::try_from(MAX_OPEN_RECEIPTS_PER_SENDER).unwrap();
    // Each refusal is raised, with the cap that refused it and the sender's key.
    let refused = refusals(&mut events);
    assert_eq!(refused.len(), usize::try_from(sent - cap).unwrap());
    let sender = refused[0].sender.clone();
    assert!(sender.is_some());
    for refusal in &refused {
        assert_eq!(refusal.cap, ReceiptCap::PerSender);
        assert_eq!(refusal.transport.as_str(), "epicbox");
        assert_eq!(refusal.sender, sender);
    }
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
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();
    assert_eq!(summary.received, 1);
}

#[test]
fn open_receipts_over_all_senders_are_capped_and_none_is_cancelled() {
    let world = World::new();
    let cap = u32::try_from(MAX_OPEN_RECEIPTS).unwrap();
    let sent = cap + 20;
    for n in 0..sent {
        post_from(&world, n, &s1_numbered(n));
    }
    let mut events = world.receiver_wallet.subscribe();

    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            received: cap,
            rejected: sent - cap,
            ..InboxSummary::default()
        }
    );
    let refused = refusals(&mut events);
    assert_eq!(refused.len(), usize::try_from(sent - cap).unwrap());
    assert!(
        refused
            .iter()
            .all(|refusal| refusal.cap == ReceiptCap::Total)
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(incoming(&world, TxState::Received), MAX_OPEN_RECEIPTS);
    assert_eq!(incoming(&world, TxState::Cancelled), 0);
    assert_eq!(world.receiver.transactions(), MAX_OPEN_RECEIPTS);
}

/// The payments refused at an open receipt cap, as raised.
fn refusals(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<RefusedPayment> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::PaymentRefused(refused) => Some(refused),
            _ => None,
        })
        .collect()
}

/// Tries of a held message in one listen, as the inbox bounds them.
const MAX_HOLD_ATTEMPTS: usize = 3;

/// The receiver's client waits briefly for answers, so an unanswered post fails fast.
fn quick_receiver() -> World {
    let mut settings = world::settings();
    settings.response_timeout = Duration::from_secs(1);
    World::with_receiver_settings(settings)
}

fn undelivered_replies(events: &mut tokio::sync::broadcast::Receiver<Event>) -> usize {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::ReplyUndelivered(_)))
        .count()
}

#[test]
fn a_reply_the_relay_never_answers_is_given_up_after_bounded_tries_in_a_listen() {
    let world = quick_receiver();
    world.relay.set_unroutable(&sender_address(1));
    post_from(&world, 1, &s1_numbered(1));
    world.block_on(world.send());
    let mut events = world.receiver_wallet.subscribe();
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

    // The first payment was stored on its first try, so the try that settles it is a repeat.
    assert_eq!(
        summary.unwrap(),
        InboxSummary {
            received: 1,
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(incoming(&world, TxState::Received), 2);
    assert_eq!(undelivered_replies(&mut events), 1);
    // The sender's S1, the bounded tries of the unanswered reply, and the second reply.
    assert_eq!(world.relay.received("PostSlate"), 1 + MAX_HOLD_ATTEMPTS + 1);
    assert_eq!(world.relay.pending(&world.sender_address), 1);
}

#[test]
fn a_drain_gives_up_an_unanswered_reply_once_its_message_waited_the_hold_bound() {
    let world = quick_receiver();
    world.relay.set_unroutable(&sender_address(1));
    let msg_id = post_from(&world, 1, &s1_numbered(1));
    world.block_on(world.send());
    let mut events = world.receiver_wallet.subscribe();

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
    assert_eq!(world.relay.pending(&world.receiver_address), 2);

    let arrived = support::fixed_time()
        .checked_sub(Duration::from_secs(3 * 60))
        .unwrap();
    world
        .receiver
        .store()
        .write(|repos| {
            repos.put_inbox(&InboxEntry {
                msg_id: msg_id.clone(),
                status: InboxStatus::Received,
                received_at: arrived,
                updated_at: arrived,
            })
        })
        .unwrap();
    let settled = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();

    assert_eq!(
        settled,
        InboxSummary {
            received: 1,
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(incoming(&world, TxState::Received), 2);
    assert_eq!(undelivered_replies(&mut events), 1);
}

/// The receiver's open receipts, oldest first, with the slate id each answers.
fn open_receipts(world: &World) -> Vec<TxId> {
    world
        .receiver
        .store()
        .read(|repos| repos.open_receipts("epicbox"))
        .unwrap()
        .into_iter()
        .map(|receipt| receipt.id)
        .collect()
}

fn receiver_outputs(world: &World) -> Vec<OutputRecord> {
    world
        .receiver
        .store()
        .read(|repos| repos.outputs(AccountIndex(0), None))
        .unwrap()
}

/// The kernel the sender of the receipt `tx_id` would post: the S2 kernel with the excess the
/// finalized transaction carries, signed with that excess as a finalized kernel is. `output` is
/// the receiver's output of the receipt.
fn receipt_kernel(world: &World, tx_id: TxId, output: &OutputRecord) -> (TxKernel, Height) {
    let stored = world
        .receiver
        .store()
        .read(|repos| {
            let slate_id = repos.transaction(tx_id)?.unwrap().slate_id.unwrap();
            repos.slate(slate_id, SlateStage::Standard2)
        })
        .unwrap()
        .unwrap();
    let slate = send_support::legacy_codecs()
        .decode(&WireSlate::binary(MediaType::JSON, stored.bytes))
        .unwrap();
    let body =
        TransactionBody::from_parts(slate.inputs().to_vec(), slate.outputs().to_vec(), vec![]);
    let total = sum_commitments(&body, slate.fee().value()).unwrap();
    let offset = slate.offset().to_secret_key().unwrap();
    let excess = if slate.offset().is_zero() {
        total
    } else {
        Commitment::sum(&[total], &[Commitment::commit(0, &offset).unwrap()]).unwrap()
    };
    let secret = receipt_excess_key(output, &offset, slate.offset().is_zero());
    assert_eq!(Commitment::commit(0, &secret).unwrap(), excess);
    let features = slate.kernel_features();
    let public = PublicKey::from_secret_key(&secret).unwrap();
    let nonce = SecretKey::from_array([0x51; 32]).unwrap();
    let signature = aggsig::sign_single(
        &features.signature_message(),
        &secret,
        &nonce,
        Some(&public),
    )
    .unwrap();
    (TxKernel::new(features, excess, signature), slate.height())
}

/// The key of a receipt's kernel excess: the receiver's `output` and the vector sender's change,
/// less the sender's input and the slate `offset`. The sender's keys are in the S1 vector.
fn receipt_excess_key(output: &OutputRecord, offset: &SecretKey, no_offset: bool) -> SecretKey {
    let path = format!(
        "{}/../../testdata/vectors/slates/send_file_ttl_s1_v3.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let wallet = &vector["inputs"]["wallets"][0];
    let keychain = |mnemonic: &str| {
        Keychain::from_seed(&Seed::from_mnemonic(mnemonic).unwrap(), Network::Floonet).unwrap()
    };
    let key = |keychain: &Keychain, entry: &serde_json::Value| {
        let id = Identifier::from_hex(entry["key_id"].as_str().unwrap()).unwrap();
        let value = entry["value"].as_str().unwrap().parse().unwrap();
        keychain
            .derive_key(value, &id, SwitchCommitment::Regular)
            .unwrap()
    };
    let sender = keychain(wallet["mnemonic"].as_str().unwrap());
    let receiver = keychain(world::RECEIVER_MNEMONIC);
    let received = receiver
        .derive_key(
            output.amount.value(),
            &Identifier::from_bytes(&output.key_id.0).unwrap(),
            SwitchCommitment::Regular,
        )
        .unwrap();
    let change = key(&sender, &wallet["outputs"][0]);
    let spent = key(&sender, &wallet["inputs"][0]);
    let mut negative = vec![spent];
    if !no_offset {
        negative.push(offset.clone());
    }
    SecretKey::sum(&[received, change], &negative).unwrap()
}

/// The world's chain tip.
const WORLD_TIP: u64 = 10;

/// The output the receiver stored for the receipt `tx_id`.
fn receipt_output(world: &World, tx_id: TxId) -> OutputRecord {
    let mut outputs = world
        .receiver
        .store()
        .read(|repos| repos.outputs_of_transaction(tx_id))
        .unwrap();
    assert_eq!(outputs.len(), 1);
    outputs.remove(0)
}

/// The kernel of the receipt `tx_id` is on chain at the tip, and `output` too.
fn mine(world: &World, tx_id: TxId, mmr_index: u64, output: Option<OutputRecord>) {
    let received = output
        .clone()
        .unwrap_or_else(|| receipt_output(world, tx_id));
    let (kernel, _) = receipt_kernel(world, tx_id, &received);
    world.receiver.harness.node.update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel,
            height: Height::new(WORLD_TIP),
            mmr_index,
        });
        if let Some(output) = output {
            crate::support::mine_output(
                chain,
                ChainOutput {
                    commitment: output.id.commitment,
                    features: output.id.features,
                    // `get_outputs` answers do not carry proofs, so any proof bytes do.
                    proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
                    height: Height::new(WORLD_TIP),
                    mmr_index,
                    spent: false,
                },
            );
        }
    });
}

/// Fills the open receipts to the cap with one payment from each of senders `0..cap`.
fn fill_to_cap(world: &World) {
    let cap = u32::try_from(MAX_OPEN_RECEIPTS).unwrap();
    for n in 0..cap {
        post_from(world, n, &s1_numbered(n));
    }
    let summary = world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap();
    assert_eq!(summary.received, cap);
    assert_eq!(open_receipts(world).len(), MAX_OPEN_RECEIPTS);
}

fn drain(world: &World) -> InboxSummary {
    world
        .block_on(world.receiver_epicbox.drain(&world.receiver_wallet))
        .unwrap()
}

/// Backdates the arrival of `msg_id` to the hold bound, as if it had waited that long.
fn waited_the_hold_bound(world: &World, msg_id: &str) {
    let arrived = support::fixed_time()
        .checked_sub(Duration::from_secs(3 * 60))
        .unwrap();
    arrived_at(world, msg_id, arrived);
}

fn arrived_at(world: &World, msg_id: &str, arrived: jiff::Timestamp) {
    world
        .receiver
        .store()
        .write(|repos| {
            repos.put_inbox(&InboxEntry {
                msg_id: msg_id.to_owned(),
                status: InboxStatus::Received,
                received_at: arrived,
                updated_at: arrived,
            })
        })
        .unwrap();
}

#[test]
fn at_the_open_receipt_cap_receipts_already_mined_are_confirmed_not_cancelled() {
    let world = World::new();
    fill_to_cap(&world);
    for (index, tx_id) in open_receipts(&world).into_iter().enumerate() {
        let output = receipt_output(&world, tx_id);
        mine(&world, tx_id, 10 + index as u64, Some(output));
    }
    post_from(&world, 1_000, &s1_numbered(1_000));

    let summary = drain(&world);

    assert_eq!(
        summary,
        InboxSummary {
            received: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(incoming(&world, TxState::Cancelled), 0);
    assert_eq!(incoming(&world, TxState::Confirmed), MAX_OPEN_RECEIPTS);
    assert_eq!(incoming(&world, TxState::Received), 1);
    assert_eq!(receiver_outputs(&world).len(), MAX_OPEN_RECEIPTS + 1);
}

#[test]
fn at_the_open_receipt_cap_a_new_s1_is_refused_and_no_receipt_is_cancelled() {
    let world = World::new();
    fill_to_cap(&world);
    let msg_id = post_from(&world, 1_000, &s1_numbered(1_000));

    let summary = drain(&world);

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(
        world.receiver.inbox(&msg_id).unwrap().status,
        InboxStatus::Rejected
    );
    assert_eq!(incoming(&world, TxState::Received), MAX_OPEN_RECEIPTS);
    assert_eq!(incoming(&world, TxState::Cancelled), 0);
    assert_eq!(world.receiver.transactions(), MAX_OPEN_RECEIPTS);
    assert_eq!(receiver_outputs(&world).len(), MAX_OPEN_RECEIPTS);
}

/// The refresh made at the cap is only a chance to confirm receipts: a node that cannot be
/// asked does not hold the new S1, which is refused at once.
#[test]
fn at_the_open_receipt_cap_an_unreachable_node_refuses_the_new_s1_at_once() {
    let world = World::new();
    fill_to_cap(&world);
    post_from(&world, 1_000, &s1_numbered(1_000));
    world
        .receiver
        .harness
        .node
        .fail_next("get_tip", MockFailure::Unreachable);

    let refused = drain(&world);

    assert_eq!(
        refused,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.receiver.transactions(), MAX_OPEN_RECEIPTS);
    assert_eq!(incoming(&world, TxState::Received), MAX_OPEN_RECEIPTS);
    assert_eq!(receiver_outputs(&world).len(), MAX_OPEN_RECEIPTS);
}

#[test]
fn a_redelivered_s1_whose_slate_is_known_is_answered_again_at_the_open_receipt_caps() {
    let world = World::new();
    let per_sender = u32::try_from(MAX_OPEN_RECEIPTS_PER_SENDER).unwrap();
    let senders = u32::try_from(MAX_OPEN_RECEIPTS).unwrap() / per_sender;
    for n in 0..senders * per_sender {
        post_from(&world, n / per_sender, &s1_numbered(n));
    }
    assert_eq!(drain(&world).received, senders * per_sender);
    let replies = world.relay.pending(&sender_address(0));
    post_from(&world, 0, &s1_numbered(0));

    let summary = drain(&world);

    assert_eq!(
        summary,
        InboxSummary {
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&sender_address(0)), replies + 1);
    assert_eq!(incoming(&world, TxState::Cancelled), 0);
    assert_eq!(incoming(&world, TxState::Received), MAX_OPEN_RECEIPTS);
}

#[test]
fn a_held_message_that_first_arrived_after_the_wallet_clock_is_at_its_hold_bound() {
    let world = quick_receiver();
    world.relay.set_unroutable(&sender_address(1));
    let msg_id = post_from(&world, 1, &s1_numbered(1));
    assert_eq!(drain(&world).held, 1);
    // The clock moved back since the message arrived.
    let arrived = support::fixed_time()
        .checked_add(Duration::from_secs(60 * 60))
        .unwrap();
    arrived_at(&world, &msg_id, arrived);

    let settled = drain(&world);

    assert_eq!(
        settled,
        InboxSummary {
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(incoming(&world, TxState::Received), 1);
}

/// The vector S1 with a tip further past its cutoff than one refresh may confirm, so the
/// node's tip alone says it expired.
fn s1_expired_by_the_tip_alone(world: &World) -> String {
    let (s1, cutoff) = vector_s1();
    let msg_id = post_from(world, 1, &s1);
    world.receiver.harness.node.update_chain(|chain| {
        chain.tip.height = Height::new(cutoff + lepic_wallet::chain::TIP_STEP_BLOCKS + 1);
    });
    msg_id
}

fn tip_requests(world: &World) -> usize {
    world
        .receiver
        .harness
        .node
        .calls()
        .iter()
        .filter(|method| *method == "get_tip")
        .count()
}

#[test]
fn an_s1_expired_by_the_tip_alone_is_refused_at_the_hold_bound() {
    let world = World::new();
    let msg_id = s1_expired_by_the_tip_alone(&world);

    assert_eq!(drain(&world).held, 1);
    waited_the_hold_bound(&world, &msg_id);
    let refused = drain(&world);

    assert_eq!(
        refused,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.receiver.transactions(), 0);
}

#[test]
fn an_s1_expired_by_the_tip_alone_refreshes_the_tip_at_most_once_a_minute() {
    let world = World::new();
    s1_expired_by_the_tip_alone(&world);
    let before = tip_requests(&world);
    assert_eq!(drain(&world).held, 1);
    let first = tip_requests(&world) - before;

    // The wallet clock has not moved, so no refresh is due.
    assert_eq!(drain(&world).held, 1);
    let second = tip_requests(&world) - before - first;

    assert!(second < first, "first drain {first}, second drain {second}");
    let refreshes = first - second;
    assert_eq!(drain(&world).held, 1);
    assert_eq!(tip_requests(&world) - before - first - second, second);
    assert!(refreshes >= 1);
}

#[test]
fn a_held_message_that_first_arrived_less_than_a_minute_after_the_wallet_clock_stays_held() {
    let world = quick_receiver();
    world.relay.set_unroutable(&sender_address(1));
    let msg_id = post_from(&world, 1, &s1_numbered(1));
    assert_eq!(drain(&world).held, 1);
    // A small step back of the clock, as time synchronisation makes.
    let arrived = support::fixed_time()
        .checked_add(Duration::from_secs(30))
        .unwrap();
    arrived_at(&world, &msg_id, arrived);

    let held = drain(&world);

    assert_eq!(
        held,
        InboxSummary {
            held: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 1);
}

#[test]
fn at_the_open_receipt_cap_an_implausible_node_tip_refuses_the_new_s1_at_once() {
    let world = World::new();
    // The wallet stores the tip it first saw, which bounds the tips it believes later.
    world.block_on(world.receiver_wallet.refresh()).unwrap();
    // The node client then accepts a tip a day of blocks above this one, while the wallet's
    // bound is lower.
    world.receiver.harness.node.update_chain(|chain| {
        chain.tip.height = Height::new(30);
    });
    fill_to_cap(&world);
    world.receiver.harness.node.update_chain(|chain| {
        chain.tip.height = Height::new(WORLD_TIP + lepic_wallet::chain::TIP_SLACK_BLOCKS + 10);
    });
    post_from(&world, 1_000, &s1_numbered(1_000));

    let refused = drain(&world);

    assert_eq!(
        refused,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.receiver_address), 0);
    assert_eq!(world.receiver.transactions(), MAX_OPEN_RECEIPTS);
    assert_eq!(incoming(&world, TxState::Received), MAX_OPEN_RECEIPTS);
}

#[test]
fn a_sender_at_its_open_receipt_cap_is_received_once_a_refresh_confirms_its_payments() {
    let world = World::new();
    let cap = u32::try_from(MAX_OPEN_RECEIPTS_PER_SENDER).unwrap();
    for n in 0..cap {
        post_from(&world, 1, &s1_numbered(n));
    }
    assert_eq!(drain(&world).received, cap);
    // The sender finalized every payment and the chain mined them; no refresh saw it yet.
    for (index, tx_id) in open_receipts(&world).into_iter().enumerate() {
        let output = receipt_output(&world, tx_id);
        mine(&world, tx_id, 10 + index as u64, Some(output));
    }
    post_from(&world, 1, &s1_numbered(cap));

    let summary = drain(&world);

    assert_eq!(
        summary,
        InboxSummary {
            received: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        incoming(&world, TxState::Confirmed),
        MAX_OPEN_RECEIPTS_PER_SENDER
    );
    assert_eq!(incoming(&world, TxState::Received), 1);
}
