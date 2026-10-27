//! Two installs of one wallet, restored from one recovery phrase, on one Epicbox address of the
//! mock relay and one mock node: an answer that one install cannot use is left for the other,
//! and a payment that both answered ends on the install whose answer the sender did not
//! finalize.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use lepic_epicbox::TRANSPORT_ID;
use lepic_node::LocatedKernel;
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::{Amount, Height};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::stage::Stage;
use lepic_store::{OutputStatus, SlateStage, StoreError, TxDirection, TxId, TxState, WalletStore};
use lepic_transport::transport::Destination;
use lepic_wallet::event::SupersededReceive;
use lepic_wallet::inbox::{
    InboxSummary, ListenHandle, MAX_TWIN_ANSWERS, TWIN_HOLD, TWIN_REQUEUE_WINDOW,
};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{Event, ReceiveRequest};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, TIP, World, pay_request};

fn send_request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

/// The payer sends to the issuer's payments address over Epicbox.
fn send(world: &World) -> SentSlate {
    world
        .block_on(world.payer.wallet.send(
            send_request(),
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(world.issuer.address.to_string()),
            },
        ))
        .unwrap()
}

fn drain(world: &World, party: &Party) -> InboxSummary {
    world
        .block_on(party.wallet.epicbox_drain(&party.epicbox))
        .unwrap()
}

/// Puts every unspent output of `party` on the mock chain, so the node holds the inputs of its
/// sends as unspent.
fn on_chain(world: &World, party: &Party) {
    let outputs = party.read(|repos| repos.outputs(ACCOUNT, None));
    world.node.update_chain(|chain| {
        for output in outputs
            .iter()
            .filter(|output| output.status != OutputStatus::Unconfirmed)
        {
            let mmr_index = u64::try_from(chain.outputs.len()).unwrap() + 1;
            chain.outputs.push(ChainOutput {
                commitment: output.id.commitment,
                features: output.id.features,
                proof: support::some_proof(),
                height: output.height,
                mmr_index,
                spent: false,
            });
        }
    });
}

/// Marks every output on the mock chain spent, as a transaction spending them was mined.
fn spend_everything(world: &World) {
    world.node.update_chain(|chain| {
        for output in &mut chain.outputs {
            output.spent = true;
        }
    });
}

fn state(party: &Party, tx_id: TxId) -> TxState {
    party.read(|repos| repos.transaction(tx_id)).unwrap().state
}

fn unknown_slates(events: &mut Receiver<Event>) -> Vec<lepic_wallet::event::UnknownSlate> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::UnknownSlate(unknown) => Some(unknown),
            _ => None,
        })
        .collect()
}

#[test]
fn an_answer_the_other_install_reads_first_is_left_for_the_sending_install() {
    let world = World::new();
    let twin = world.payer_twin();
    assert_eq!(twin.address, world.payer.address, "one phrase, one address");
    let sent = send(&world);
    let received = drain(&world, &world.issuer);
    assert_eq!(received.received, 1, "{received:?}");
    let mut twin_events = twin.wallet.subscribe();

    // The install that did not make the send reads the S2 first.
    let held = drain(&world, &twin);

    assert_eq!(
        held,
        InboxSummary {
            held: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 1);
    let unknown = unknown_slates(&mut twin_events);
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0].slate_id, sent.slate_id);
    assert_eq!(unknown[0].stage, Stage::S2);

    // The sending install still finalizes it.
    let finalized = drain(&world, &world.payer);
    assert_eq!(finalized.finalized, 1, "{finalized:?}");
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(
        state(&world.payer, sent.tx_id),
        TxState::Posted,
        "the send is no longer waiting for its recipient"
    );
}

#[test]
fn an_answer_still_unclaimed_after_a_relay_round_is_requeued_for_the_sending_install() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.payer_twin();
    let sent = send(&world);
    drain(&world, &world.issuer);
    let mut twin_events = twin.wallet.subscribe();
    assert_eq!(drain(&world, &twin).held, 1);

    // The sending install is away for the whole hold.
    twin.clock.advance(TWIN_HOLD);
    let requeued = drain(&world, &twin);

    // The original is acknowledged once its copy is on the relay; the copy comes straight back
    // to the twin, which holds it in turn.
    assert_eq!(
        requeued,
        InboxSummary {
            requeued: 1,
            held: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 1);
    assert_eq!(world.relay.received("PostSlate"), 3, "S1, S2 and the copy");
    assert_eq!(
        unknown_slates(&mut twin_events).len(),
        1,
        "one event per slate"
    );
    assert!(world.node.pushed_transactions().is_empty());

    // The sending install comes back and finalizes the copy.
    let finalized = drain(&world, &world.payer);
    assert_eq!(finalized.finalized, 1, "{finalized:?}");
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(state(&world.payer, sent.tx_id), TxState::Posted);
}

#[test]
fn a_copy_of_an_answer_the_sending_install_settled_is_acknowledged_there_as_repeated() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.payer_twin();
    send(&world);
    drain(&world, &world.issuer);
    let handle = ListenHandle::new();
    let mut twin_events = twin.wallet.subscribe();

    let (listened, settled) = world.block_on(async {
        let listen = twin.wallet.epicbox_listen(&twin.epicbox, &handle);
        let script = async {
            // The twin holds the S2 in hand, and the relay hands it to the sending install too.
            world
                .within(async {
                    while !matches!(twin_events.recv().await, Ok(Event::UnknownSlate(_))) {}
                })
                .await;
            let first = world
                .payer
                .wallet
                .epicbox_drain(&world.payer.epicbox)
                .await
                .unwrap();
            assert_eq!(first.finalized, 1, "{first:?}");
            // The twin cannot tell, and requeues its delivery at the bound. Posts so far: the
            // S1, the S2, the sending install's `posted` notice, then the requeued copy.
            twin.clock.advance(TWIN_HOLD);
            world
                .within(
                    world
                        .relay
                        .wait_until(|relay| relay.received("PostSlate") == 4),
                )
                .await;
            world
                .within(world.relay.wait_until(|relay| relay.received("Made") == 2))
                .await;
            let second = world
                .payer
                .wallet
                .epicbox_drain(&world.payer.epicbox)
                .await
                .unwrap();
            handle.stop();
            second
        };
        tokio::join!(listen, script)
    });

    assert_eq!(
        settled,
        InboxSummary {
            repeated: 1,
            ..InboxSummary::default()
        }
    );
    let listened = listened.unwrap();
    assert_eq!(
        (listened.requeued, listened.rejected),
        (1, 0),
        "{listened:?}"
    );
    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(world.relay.pending(&world.payer.address), 0);
}

#[test]
fn an_answer_whose_inputs_are_spent_is_refused_at_the_bound() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.payer_twin();
    send(&world);
    drain(&world, &world.issuer);
    assert_eq!(drain(&world, &twin).held, 1);
    spend_everything(&world);

    twin.clock.advance(TWIN_HOLD);
    let refused = drain(&world, &twin);

    assert_eq!(
        refused,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert_eq!(world.relay.received("PostSlate"), 2, "no copy was posted");
}

#[test]
fn an_answer_first_seen_a_day_ago_is_refused_and_acknowledged() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.payer_twin();
    send(&world);
    drain(&world, &world.issuer);
    let mut twin_events = twin.wallet.subscribe();
    assert_eq!(drain(&world, &twin).held, 1);

    twin.clock.advance(TWIN_REQUEUE_WINDOW);
    let refused = drain(&world, &twin);

    assert_eq!(
        refused,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert_eq!(unknown_slates(&mut twin_events).len(), 1);
    assert_eq!(drain(&world, &world.payer), InboxSummary::default());
}

#[test]
fn only_a_few_unknown_answers_cycle_at_once_and_the_rest_are_refused() {
    let world = World::new();
    let sends = MAX_TWIN_ANSWERS + 1;
    for child in 1..u32::try_from(sends).unwrap() {
        world.payer.fund(child, FUNDING);
    }
    on_chain(&world, &world.payer);
    let twin = world.payer_twin();
    for _ in 0..sends {
        send(&world);
    }
    assert_eq!(
        drain(&world, &world.issuer).received,
        u32::try_from(sends).unwrap()
    );
    let mut twin_events = twin.wallet.subscribe();

    // Each drain requeues the answer held by the one before and holds the next.
    assert_eq!(drain(&world, &twin).held, 1);
    for _ in 1..MAX_TWIN_ANSWERS {
        twin.clock.advance(TWIN_HOLD);
        let summary = drain(&world, &twin);
        assert_eq!((summary.requeued, summary.held), (1, 1), "{summary:?}");
    }
    twin.clock.advance(TWIN_HOLD);
    let crowded = drain(&world, &twin);

    // The last answer finds the others cycling and is refused; the copy of the first is held.
    assert_eq!(
        crowded,
        InboxSummary {
            requeued: 1,
            rejected: 1,
            held: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(unknown_slates(&mut twin_events).len(), sends);
    let finalized = drain(&world, &world.payer);
    assert_eq!(
        finalized.finalized,
        u32::try_from(MAX_TWIN_ANSWERS).unwrap()
    );
}

#[test]
fn a_payment_the_other_install_reads_first_is_left_for_the_issuing_install() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    assert_eq!(
        twin.address, world.issuer.address,
        "one phrase, one address"
    );
    let issued = world.issue(None);
    world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    let mut twin_events = twin.wallet.subscribe();

    assert_eq!(drain(&world, &twin).held, 1);
    let unknown = unknown_slates(&mut twin_events);
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0].slate_id, issued.slate_id);
    assert_eq!(unknown[0].stage, Stage::I2);
    twin.clock.advance(TWIN_HOLD);
    assert_eq!(drain(&world, &twin).requeued, 1);

    let finalized = drain(&world, &world.issuer);
    assert_eq!(finalized.finalized, 1, "{finalized:?}");
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn hold_and_window_fit_the_relay() {
    // Held past one challenge round of a minute, well inside the three rounds of three
    // subscribes after which the relay discards the queue.
    assert!(TWIN_HOLD > Duration::from_secs(60));
    assert!(TWIN_HOLD < Duration::from_secs(3 * 60));
    assert!(TWIN_REQUEUE_WINDOW <= Duration::from_secs(24 * 60 * 60));
}

/// The payment `sent` as the sender stored its S1, as the relay hands it to either install.
fn proposal(world: &World, sent: &SentSlate) -> WireSlate {
    let slate_id = Uuid::from_bytes(*sent.slate_id.as_bytes());
    let stored = world
        .payer
        .read(|repos| repos.slate(slate_id, SlateStage::Standard1))
        .unwrap();
    WireSlate::text(MediaType::JSON, String::from_utf8(stored.bytes).unwrap())
}

/// Moves the next receive key of `party` past the other install's, as an install with a
/// history of its own has.
fn skip_keys(party: &Party) {
    party
        .store()
        .write(|repos| {
            let mut account = repos.account(ACCOUNT)?.unwrap();
            account.next_child += 7;
            repos.put_account(&account)
        })
        .map_err(|error: StoreError| error)
        .unwrap();
}

/// Mines the transaction the node accepted, in a block above the tip: its inputs are spent,
/// its kernel is on chain, and so are its outputs unless `with_outputs` is false.
fn mine_pushed(world: &World, with_outputs: bool) {
    let pushed = world.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    let transaction = &pushed[0];
    let height = Height::new(TIP + 1);
    world.node.update_chain(|chain| {
        chain.tip.height = height;
        for input in transaction.inputs() {
            for output in &mut chain.outputs {
                if output.commitment == input.commitment {
                    output.spent = true;
                }
            }
        }
        let mut mmr_index = u64::try_from(chain.outputs.len()).unwrap() + 1;
        if with_outputs {
            for output in transaction.outputs() {
                chain.outputs.push(ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height,
                    mmr_index,
                    spent: false,
                });
                mmr_index += 1;
            }
        }
        for kernel in transaction.kernels() {
            chain.kernels.push(LocatedKernel {
                kernel: *kernel,
                height,
                mmr_index,
            });
        }
    });
}

fn superseded(events: &mut Receiver<Event>) -> Vec<SupersededReceive> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::ReceiveSuperseded(superseded) => Some(superseded),
            _ => None,
        })
        .collect()
}

fn incoming(party: &Party) -> (TxId, TxState) {
    let transactions = party.read(|repos| repos.transactions(ACCOUNT));
    let incoming: Vec<_> = transactions
        .iter()
        .filter(|stored| stored.entry.direction == TxDirection::Incoming)
        .collect();
    assert_eq!(incoming.len(), 1, "{transactions:?}");
    (incoming[0].id, incoming[0].entry.state)
}

fn unconfirmed_outputs(party: &Party) -> usize {
    party
        .read(|repos| repos.outputs(ACCOUNT, None))
        .iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .count()
}

fn refresh(world: &World, party: &Party) {
    world.block_on(party.wallet.refresh()).unwrap();
}

/// Both installs of the issuer answer one S1; the issuer's answer reaches the sender first.
/// Each install refreshes once while the sender's inputs are unspent, as a running app does.
fn answered_twice(world: &World, twin: &Party) -> SentSlate {
    let sent = send(world);
    let twin_answer = world
        .block_on(twin.wallet.receive(
            TRANSPORT_ID,
            &proposal(world, &sent),
            ReceiveRequest::default(),
        ))
        .unwrap();
    assert!(!twin_answer.repeated);
    assert_eq!(drain(world, &world.issuer).received, 1);
    refresh(world, twin);
    refresh(world, &world.issuer);
    sent
}

#[test]
fn the_receive_whose_answer_the_sender_did_not_finalize_is_superseded() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    skip_keys(&twin);
    let sent = answered_twice(&world, &twin);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    mine_pushed(&world, true);
    let mut twin_events = twin.wallet.subscribe();

    world.block_on(twin.wallet.refresh()).unwrap();

    let (tx_id, state) = incoming(&twin);
    assert_eq!(state, TxState::Cancelled);
    assert_eq!(unconfirmed_outputs(&twin), 0, "its output was dropped");
    assert_eq!(
        superseded(&mut twin_events),
        vec![SupersededReceive {
            tx_id,
            slate_id: sent.slate_id,
        }]
    );
    // The install whose answer was finalized confirms it by its output.
    let mut issuer_events = world.issuer.wallet.subscribe();
    world.block_on(world.issuer.wallet.refresh()).unwrap();
    assert_eq!(incoming(&world.issuer).1, TxState::Confirmed);
    assert!(superseded(&mut issuer_events).is_empty());
}

#[test]
fn a_receive_whose_own_output_is_on_chain_is_confirmed_not_superseded() {
    let world = World::new();
    on_chain(&world, &world.payer);
    // Installs whose key counters stand at the same point derive the same key, so the
    // sender's transaction pays the twin's output too.
    let twin = world.issuer_twin();
    same_counter(&world.issuer, &twin);
    answered_twice(&world, &twin);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    mine_pushed(&world, true);
    let mut twin_events = twin.wallet.subscribe();

    world.block_on(twin.wallet.refresh()).unwrap();

    assert_eq!(incoming(&twin).1, TxState::Confirmed);
    assert!(superseded(&mut twin_events).is_empty());
}

#[test]
fn a_receive_whose_kernel_is_on_chain_is_confirmed_not_superseded() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    skip_keys(&twin);
    answered_twice(&world, &twin);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    // The node reports the kernel and the spent inputs, but not yet the output.
    mine_pushed(&world, false);
    let mut issuer_events = world.issuer.wallet.subscribe();

    world.block_on(world.issuer.wallet.refresh()).unwrap();

    assert_eq!(incoming(&world.issuer).1, TxState::Confirmed);
    assert!(superseded(&mut issuer_events).is_empty());
}

#[test]
fn a_receive_whose_inputs_are_unspent_waits_and_costs_no_kernel_lookup() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    skip_keys(&twin);
    answered_twice(&world, &twin);
    let mut twin_events = twin.wallet.subscribe();
    let kernel_lookups = || {
        world
            .node
            .calls()
            .iter()
            .filter(|call| call.as_str() == "get_kernel")
            .count()
    };
    let before = kernel_lookups();

    world.block_on(twin.wallet.refresh()).unwrap();

    assert_eq!(incoming(&twin).1, TxState::Received);
    assert!(superseded(&mut twin_events).is_empty());
    assert_eq!(kernel_lookups(), before);
}

#[test]
fn a_receive_whose_inputs_no_refresh_saw_unspent_is_not_superseded() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    skip_keys(&twin);
    let sent = send(&world);
    world
        .block_on(twin.wallet.receive(
            TRANSPORT_ID,
            &proposal(&world, &sent),
            ReceiveRequest::default(),
        ))
        .unwrap();
    assert_eq!(drain(&world, &world.issuer).received, 1);
    assert_eq!(drain(&world, &world.payer).finalized, 1);
    // Mined before the twin looked: its inputs might as well never have been on chain.
    mine_pushed(&world, true);
    let mut twin_events = twin.wallet.subscribe();

    refresh(&world, &twin);

    assert_eq!(incoming(&twin).1, TxState::Received);
    assert!(superseded(&mut twin_events).is_empty());
}

#[test]
fn a_node_whose_tip_is_not_past_the_slate_supersedes_nothing() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    skip_keys(&twin);
    answered_twice(&world, &twin);
    // A node still syncing below the sender's tip does not hold the inputs yet.
    spend_everything(&world);
    let mut twin_events = twin.wallet.subscribe();

    refresh(&world, &twin);

    assert_eq!(incoming(&twin).1, TxState::Received);
    assert!(superseded(&mut twin_events).is_empty());
}

/// Puts `twin`'s key counter where `install`'s stands, as two installs whose random starts met.
fn same_counter(install: &Party, twin: &Party) {
    let counter = install
        .read(|repos| repos.account(ACCOUNT))
        .unwrap()
        .next_child;
    twin.store()
        .write(|repos| {
            let mut account = repos.account(ACCOUNT)?.unwrap();
            account.next_child = counter;
            repos.put_account(&account)
        })
        .unwrap();
}

/// The next output key the install hands out, and the commitment it makes for `value`.
fn next_commitment(party: &Party, value: u64) -> (String, lepic_crypto::Commitment) {
    let key_id = party
        .store()
        .write(|repos| lepic_wallet::account::next_output_key(repos, ACCOUNT))
        .unwrap();
    let commitment = party
        .keychain()
        .commit(value, &key_id, lepic_keychain::SwitchCommitment::Regular)
        .unwrap();
    (key_id.to_bip32_path(), commitment)
}

#[test]
fn two_installs_of_one_phrase_make_different_output_keys_for_the_same_value() {
    let world = World::new();
    let twin = world.issuer_twin();
    let (key, commitment) = next_commitment(&world.issuer, AMOUNT);
    let (twin_key, twin_commitment) = next_commitment(&twin, AMOUNT);
    assert_ne!(key, twin_key, "each install starts its key counter apart");
    assert_ne!(
        commitment, twin_commitment,
        "the same key and value would make one commitment, which the chain holds once"
    );
}

/// Stores every output of `party` as a plain output: a coinbase one is not spendable by
/// anyone before it matures, so the chain check never takes it for a spend elsewhere.
fn plain_outputs(party: &Party) {
    party
        .store()
        .write(|repos| {
            for mut output in repos.outputs(ACCOUNT, None)? {
                output.id = lepic_primitives::output::OutputIdentifier::new(
                    lepic_primitives::output::OutputFeatures::Plain,
                    output.id.commitment,
                );
                repos.put_output(&output)?;
            }
            Ok::<_, StoreError>(())
        })
        .unwrap();
}

/// A refresh and the update scan that follows it on the app's refresh path.
fn refresh_and_scan(world: &World, party: &Party) {
    refresh(world, party);
    world.block_on(party.wallet.refresh_scan()).unwrap();
}

/// The payer pays the issuer over Epicbox and the payment is mined with its outputs.
fn paid_and_mined(world: &World) {
    send(world);
    assert_eq!(drain(world, &world.issuer).received, 1);
    assert_eq!(drain(world, &world.payer).finalized, 1);
    mine_pushed(world, true);
}

fn other_wallet_entries(
    world: &World,
    party: &Party,
) -> Vec<lepic_wallet::details::TransactionDetails> {
    world
        .block_on(party.wallet.transactions(ACCOUNT))
        .unwrap()
        .into_iter()
        .filter(|details| details.origin == lepic_wallet::legacy_history::TxOrigin::OtherWallet)
        .collect()
}

fn transaction_events(events: &mut Receiver<Event>) -> Vec<TxId> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::Transaction(change) => Some(change.tx_id),
            _ => None,
        })
        .collect()
}

#[test]
fn a_spend_by_the_other_install_shows_as_sent_from_another_wallet_with_its_change() {
    let world = World::new();
    plain_outputs(&world.payer);
    on_chain(&world, &world.payer);
    let twin = world.payer_twin();
    // The same key and value as the payer's funding: the twin holds the same output.
    twin.fund(0, FUNDING);
    plain_outputs(&twin);
    refresh_and_scan(&world, &twin);
    assert!(other_wallet_entries(&world, &twin).is_empty());

    paid_and_mined(&world);
    let mut events = twin.wallet.subscribe();
    refresh_and_scan(&world, &twin);

    let entries = other_wallet_entries(&world, &twin);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let spent = &entries[0];
    let entry = &spent.transaction.entry;
    assert_eq!(
        (entry.direction, entry.state, entry.fee),
        (TxDirection::Outgoing, TxState::Confirmed, None)
    );
    assert_eq!(entry.amount_debited, Amount::new(FUNDING));
    let payer_change: Vec<Amount> = world
        .payer
        .read(|repos| repos.outputs(ACCOUNT, None))
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .map(|output| output.amount)
        .collect();
    assert_eq!(payer_change.len(), 1);
    assert_eq!(
        entry.amount_credited, payer_change[0],
        "the change goes to the spend"
    );
    assert_eq!(spent.spent_commits.len(), 1);
    assert!(transaction_events(&mut events).contains(&spent.transaction.id));
    // The change is the spend's, not a receive of its own.
    let incoming = twin
        .read(|repos| repos.transactions(ACCOUNT))
        .into_iter()
        .filter(|stored| stored.entry.direction == TxDirection::Incoming)
        .count();
    assert_eq!(incoming, 0);

    // A later refresh records nothing more.
    refresh_and_scan(&world, &twin);
    assert_eq!(other_wallet_entries(&world, &twin).len(), 1);
}

#[test]
fn a_payment_the_other_install_received_shows_as_received_by_another_wallet() {
    let world = World::new();
    on_chain(&world, &world.payer);
    let twin = world.issuer_twin();
    paid_and_mined(&world);
    let mut events = twin.wallet.subscribe();

    refresh_and_scan(&world, &twin);

    let entries = other_wallet_entries(&world, &twin);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0].transaction.entry;
    assert_eq!(
        (entry.direction, entry.state, entry.amount_credited),
        (
            TxDirection::Incoming,
            TxState::Confirmed,
            Amount::new(AMOUNT)
        )
    );
    assert!(entries[0].found.is_none());
    assert!(transaction_events(&mut events).contains(&entries[0].transaction.id));
}
