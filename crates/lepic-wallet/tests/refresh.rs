//! Refresh: outputs follow the node's UTXO set, transactions are confirmed by their outputs or
//! their kernel, unposted transactions expire at their TTL cutoff, and a node behind the last
//! refresh changes nothing.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;

use lepic_crypto::RangeProof;
use lepic_node::LocatedKernel;
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::WalletStore;
use lepic_store::{
    OutboxStatus, OutputRecord, OutputStatus, SlateStage, StoredSlate, TransactionEntry,
    TxDirection, TxId, TxState,
};
use lepic_transport::transport::Destination;
use lepic_wallet::WalletError;
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::event::{Event, TransactionState};
use lepic_wallet::refresh::{RefreshError, RefreshOutcome, RefreshSummary};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP, legacy_codecs};
use support::{LOOPBACK, fixed_time};
use uuid::Uuid;

const AMOUNT: u64 = 100_000_000;
const TTL_BLOCKS: u64 = 5;

/// The G-03 `send_file_plain` S3 as upstream's sender finalized it.
const SEND_FILE_PLAIN_S3: &str =
    include_str!("../../../testdata/vectors/slates/send_file_plain_s3_v3.json");

/// The G-03 `send_file_ttl` S2 as upstream's receiver returned it.
const SEND_FILE_TTL_S2: &str =
    include_str!("../../../testdata/vectors/slates/send_file_ttl_s2_v3.json");

fn request(ttl_blocks: Option<u64>) -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ttl_blocks,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

fn to_peer() -> Delivery {
    Delivery::Deliver {
        transport: LOOPBACK,
        to: Destination::new(PEER.to_owned()),
    }
}

fn on_chain(output: &OutputRecord, height: u64, mmr_index: u64) -> ChainOutput {
    ChainOutput {
        commitment: output.id.commitment,
        features: output.id.features,
        // `get_outputs` answers do not carry proofs, so any proof bytes do.
        proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
        height: Height::new(height),
        mmr_index,
        spent: false,
    }
}

/// The funded sender, with its funding output on the node's chain.
fn funded() -> (Sender, OutputRecord) {
    let sender = Sender::new();
    let funding = sender.outputs().remove(0);
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&funding, 1, 1));
    });
    (sender, funding)
}

fn set_tip(sender: &Sender, height: u64) {
    sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(height));
}

fn refresh(sender: &Sender) -> RefreshSummary {
    match sender.harness.block_on(sender.wallet.refresh()).unwrap() {
        RefreshOutcome::Refreshed(summary) => summary,
        other @ RefreshOutcome::NodeBehind { .. } => panic!("refresh did not apply: {other:?}"),
    }
}

fn state(sender: &Sender, tx_id: TxId) -> TxState {
    sender.read(|repos| repos.transaction(tx_id)).unwrap().state
}

fn output(sender: &Sender, record: &OutputRecord) -> Option<OutputRecord> {
    sender.read(|repos| repos.output(record.commitment()))
}

/// The change output of the only send.
fn change(sender: &Sender, funding: &OutputRecord) -> OutputRecord {
    sender
        .outputs()
        .into_iter()
        .find(|output| output.id != funding.id)
        .unwrap()
}

fn events(receiver: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok()).collect()
}

#[test]
fn expires_an_unposted_send_at_its_ttl_cutoff_and_releases_its_inputs() {
    let (sender, funding) = funded();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(Some(TTL_BLOCKS)), to_peer()))
        .unwrap();
    let change = change(&sender, &funding);
    let slate_id = Uuid::from_bytes(*sent.slate_id.as_bytes());

    set_tip(&sender, TIP + TTL_BLOCKS - 1);
    let summary = refresh(&sender);
    assert_eq!(summary.expired_transactions, 0);
    assert_eq!(state(&sender, sent.tx_id), TxState::Sent);
    assert_eq!(
        output(&sender, &funding).unwrap().status,
        OutputStatus::Locked
    );

    set_tip(&sender, TIP + TTL_BLOCKS);
    let mut receiver = sender.wallet.subscribe();
    let summary = refresh(&sender);

    assert_eq!(summary.expired_transactions, 1);
    assert_eq!(state(&sender, sent.tx_id), TxState::Expired);
    assert_eq!(
        output(&sender, &funding).unwrap().status,
        OutputStatus::Unspent
    );
    assert_eq!(output(&sender, &change), None);
    assert!(!sender.has_sender_context(slate_id));
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
    assert!(
        events(&mut receiver).contains(&Event::Transaction(TransactionState {
            tx_id: sent.tx_id,
            from: TxState::Sent,
            to: TxState::Expired,
        }))
    );

    let again = refresh(&sender);
    assert_eq!(again.expired_transactions, 0);
}

#[test]
fn expires_a_received_transaction_and_drops_its_output() {
    let (sender, _) = funded();
    let vector: serde_json::Value = serde_json::from_str(SEND_FILE_TTL_S2).unwrap();
    let json = vector["expected"]["json"].as_str().unwrap().to_owned();
    let slate = legacy_codecs()
        .decode(&WireSlate::binary(
            MediaType::JSON,
            json.clone().into_bytes(),
        ))
        .unwrap();
    let cutoff = slate.ttl_cutoff_height().unwrap();
    let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
    let received = OutputRecord {
        status: OutputStatus::Unconfirmed,
        ..send_support::output(
            &sender.keychain,
            7,
            slate.amount().value(),
            OutputFeatures::Plain,
        )
    };
    let tx_id = sender
        .store
        .write(|repos| {
            let tx_id = repos.insert_transaction(&TransactionEntry {
                account: ACCOUNT,
                direction: TxDirection::Incoming,
                state: TxState::Received,
                slate_id: Some(slate_id),
                transport: None,
                amount_credited: slate.amount(),
                amount_debited: Amount::ZERO,
                fee: None,
                created_at: fixed_time(),
                updated_at: fixed_time(),
            })?;
            repos.put_output(&OutputRecord {
                tx: Some(tx_id),
                ..received.clone()
            })?;
            repos.insert_slate(&StoredSlate {
                slate_id,
                stage: SlateStage::Standard2,
                codec: LEGACY_V3_JSON.as_str().to_owned(),
                bytes: json.into_bytes(),
            })?;
            Ok::<_, lepic_store::StoreError>(tx_id)
        })
        .unwrap();

    set_tip(&sender, cutoff.value() - 1);
    refresh(&sender);
    assert_eq!(state(&sender, tx_id), TxState::Received);
    assert!(output(&sender, &received).is_some());

    set_tip(&sender, cutoff.value());
    let summary = refresh(&sender);

    assert_eq!(summary.expired_transactions, 1);
    assert_eq!(state(&sender, tx_id), TxState::Expired);
    assert_eq!(output(&sender, &received), None);
}

#[test]
fn never_expires_a_send_without_a_ttl_or_one_already_posted() {
    let (sender, funding) = funded();
    let without_ttl = sender
        .harness
        .block_on(sender.wallet.send(request(None), to_peer()))
        .unwrap();
    sender.fund(9, FUNDING);
    let funding_9 = sender
        .outputs()
        .into_iter()
        .find(|output| output.key_id != funding.key_id && output.status == OutputStatus::Unspent)
        .unwrap();
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&funding_9, 1, 2));
    });
    let posted = sender
        .harness
        .block_on(sender.wallet.send(request(Some(TTL_BLOCKS)), to_peer()))
        .unwrap();
    sender
        .store
        .write(|repos| {
            let mut entry = repos.transaction(posted.tx_id)?.unwrap();
            entry.state = TxState::Posted;
            repos.update_transaction(posted.tx_id, &entry)
        })
        .unwrap();

    set_tip(&sender, TIP + 50);
    let summary = refresh(&sender);

    assert_eq!(summary.expired_transactions, 0);
    assert_eq!(state(&sender, without_ttl.tx_id), TxState::Sent);
    assert_eq!(state(&sender, posted.tx_id), TxState::Posted);
    assert_eq!(
        output(&sender, &funding).unwrap().status,
        OutputStatus::Locked
    );
    assert_eq!(
        output(&sender, &funding_9).unwrap().status,
        OutputStatus::Locked
    );
}

#[test]
fn confirms_a_send_once_its_change_is_on_chain_and_reports_the_balance() {
    let (sender, funding) = funded();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(None), to_peer()))
        .unwrap();
    let change = change(&sender, &funding);
    sender.harness.node.update_chain(|chain| {
        chain.outputs[0].spent = true;
        chain.outputs.push(on_chain(&change, TIP + 1, 3));
        chain.tip.height = Height::new(TIP + 1);
    });
    let mut receiver = sender.wallet.subscribe();

    let summary = refresh(&sender);

    assert_eq!(
        summary,
        RefreshSummary {
            height: Height::new(TIP + 1),
            confirmed_outputs: 1,
            spent_outputs: 1,
            confirmed_transactions: 1,
            expired_transactions: 0,
        }
    );
    assert_eq!(state(&sender, sent.tx_id), TxState::Confirmed);
    assert_eq!(
        output(&sender, &funding).unwrap().status,
        OutputStatus::Spent
    );
    let confirmed = output(&sender, &change).unwrap();
    assert_eq!(confirmed.status, OutputStatus::Unspent);
    assert_eq!(confirmed.height, Height::new(TIP + 1));
    assert_eq!(confirmed.mmr_index, Some(3));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + 1))
    );

    let events = events(&mut receiver);
    assert!(events.contains(&Event::Transaction(TransactionState {
        tx_id: sent.tx_id,
        from: TxState::Sent,
        to: TxState::Confirmed,
    })));
    let Some(Event::Balance(balance)) = events
        .iter()
        .find(|event| matches!(event, Event::Balance(_)))
    else {
        panic!("no balance event in {events:?}");
    };
    assert_eq!(balance.account, ACCOUNT);
    assert_eq!(balance.height, Height::new(TIP + 1));
    // One confirmation is short of the three the balance counts as spendable.
    assert_eq!(balance.awaiting_confirmation, change.amount);
    assert_eq!(balance.total, change.amount);
    assert_eq!(balance.spendable, Amount::ZERO);
    assert_eq!(balance.locked, Amount::ZERO);
}

/// A posted send with its final slate stored, as a sender that finalized `send_file_plain` keeps
/// it, crediting `change` back to the sender.
fn posted_with_final_slate(sender: &Sender, change: Amount) -> (TxId, LocatedKernel) {
    let vector: serde_json::Value = serde_json::from_str(SEND_FILE_PLAIN_S3).unwrap();
    let json = vector["expected"]["json"].as_str().unwrap().to_owned();
    let slate = legacy_codecs()
        .decode(&WireSlate::binary(
            MediaType::JSON,
            json.clone().into_bytes(),
        ))
        .unwrap();
    let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
    let tx_id = sender
        .store
        .write(|repos| {
            let tx_id = repos.insert_transaction(&TransactionEntry {
                account: ACCOUNT,
                direction: TxDirection::Outgoing,
                state: TxState::Posted,
                slate_id: Some(slate_id),
                transport: None,
                amount_credited: change,
                amount_debited: Amount::new(AMOUNT),
                fee: Some(Fee::new(800_000)),
                created_at: fixed_time(),
                updated_at: fixed_time(),
            })?;
            repos.insert_slate(&StoredSlate {
                slate_id,
                stage: SlateStage::Standard3,
                codec: LEGACY_V3_JSON.as_str().to_owned(),
                bytes: json.into_bytes(),
            })?;
            Ok::<_, lepic_store::StoreError>(tx_id)
        })
        .unwrap();
    let kernel = LocatedKernel {
        kernel: slate.kernel().unwrap(),
        height: slate.height().checked_add_blocks(1).unwrap(),
        mmr_index: 1,
    };
    (tx_id, kernel)
}

#[test]
fn confirms_a_send_without_change_once_its_kernel_is_on_chain() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_with_final_slate(&sender, Amount::ZERO);
    set_tip(&sender, kernel.height.value());

    let summary = refresh(&sender);
    assert_eq!(summary.confirmed_transactions, 0);
    assert_eq!(state(&sender, tx_id), TxState::Posted);
    assert!(
        sender
            .harness
            .node
            .calls()
            .contains(&"get_kernel".to_owned())
    );

    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    let summary = refresh(&sender);

    assert_eq!(summary.confirmed_transactions, 1);
    assert_eq!(state(&sender, tx_id), TxState::Confirmed);
    assert_eq!(sender.harness.node.violations(), []);
}

#[test]
fn leaves_a_send_with_change_to_its_change_output_instead_of_its_kernel() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_with_final_slate(&sender, Amount::new(1));
    sender.harness.node.update_chain(|chain| {
        chain.kernels.push(kernel);
        chain.tip.height = kernel.height;
    });

    let summary = refresh(&sender);

    assert_eq!(summary.confirmed_transactions, 0);
    assert_eq!(state(&sender, tx_id), TxState::Posted);
    assert!(
        !sender
            .harness
            .node
            .calls()
            .contains(&"get_kernel".to_owned())
    );
}

#[test]
fn keeps_a_cancelled_send_cancelled_when_its_change_appears_on_chain() {
    let (sender, funding) = funded();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(None), to_peer()))
        .unwrap();
    let change = change(&sender, &funding);
    // Cancel deletes the change, so the state is set directly: an ended transaction whose
    // output is still stored, which the peer completed anyway.
    sender
        .store
        .write(|repos| {
            let mut entry = repos.transaction(sent.tx_id)?.unwrap();
            entry.state = TxState::Cancelled;
            repos.update_transaction(sent.tx_id, &entry)
        })
        .unwrap();
    sender.harness.node.update_chain(|chain| {
        chain.outputs[0].spent = true;
        chain.outputs.push(on_chain(&change, TIP + 1, 3));
        chain.tip.height = Height::new(TIP + 1);
    });

    let summary = refresh(&sender);

    assert_eq!(summary.confirmed_outputs, 1);
    assert_eq!(summary.confirmed_transactions, 0);
    assert_eq!(state(&sender, sent.tx_id), TxState::Cancelled);
    assert_eq!(
        output(&sender, &change).unwrap().status,
        OutputStatus::Unspent
    );
}

#[test]
fn reports_the_balance_in_every_category() {
    const TIP_HEIGHT: u64 = 30;
    let (sender, funding) = funded();
    let stored = |child, value, features, status, lock_height| OutputRecord {
        status,
        lock_height: Height::new(lock_height),
        ..send_support::output(&sender.keychain, child, value, features)
    };
    let immature = stored(
        1,
        2,
        OutputFeatures::Coinbase,
        OutputStatus::Unspent,
        TIP_HEIGHT + 1,
    );
    let young = stored(2, 30, OutputFeatures::Plain, OutputStatus::Unspent, 0);
    let locked = stored(3, 400, OutputFeatures::Plain, OutputStatus::Locked, 0);
    let unconfirmed = stored(
        4,
        5_000,
        OutputFeatures::Plain,
        OutputStatus::Unconfirmed,
        0,
    );
    let unconfirmed_coinbase = stored(
        5,
        60_000,
        OutputFeatures::Coinbase,
        OutputStatus::Unconfirmed,
        0,
    );
    sender
        .store
        .write(|repos| {
            for output in [
                &immature,
                &young,
                &locked,
                &unconfirmed,
                &unconfirmed_coinbase,
            ] {
                repos.put_output(output)?;
            }
            Ok::<_, lepic_store::StoreError>(())
        })
        .unwrap();
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&immature, TIP_HEIGHT - 2, 2));
        // Two confirmations, one short of spendable.
        chain.outputs.push(on_chain(&young, TIP_HEIGHT - 1, 3));
        chain.outputs.push(on_chain(&locked, 2, 4));
        chain.tip.height = Height::new(TIP_HEIGHT);
    });
    let mut receiver = sender.wallet.subscribe();

    refresh(&sender);

    let events = events(&mut receiver);
    let Some(Event::Balance(balance)) = events
        .iter()
        .find(|event| matches!(event, Event::Balance(_)))
    else {
        panic!("no balance event in {events:?}");
    };
    assert_eq!(balance.height, Height::new(TIP_HEIGHT));
    assert_eq!(balance.spendable, funding.amount);
    assert_eq!(balance.immature, immature.amount);
    assert_eq!(balance.awaiting_confirmation, young.amount);
    assert_eq!(balance.locked, locked.amount);
    assert_eq!(balance.awaiting_finalization, unconfirmed.amount);
    assert_eq!(
        balance.total.value(),
        funding.amount.value()
            + immature.amount.value()
            + young.amount.value()
            + locked.amount.value()
    );
}

#[test]
fn changes_nothing_while_the_node_is_behind_the_last_refresh() {
    let (sender, funding) = funded();
    set_tip(&sender, TIP + 6);
    refresh(&sender);
    sender.harness.node.update_chain(|chain| {
        chain.outputs.clear();
        chain.tip.height = Height::new(TIP + 5);
    });

    let outcome = sender.harness.block_on(sender.wallet.refresh()).unwrap();

    assert_eq!(
        outcome,
        RefreshOutcome::NodeBehind {
            tip: Height::new(TIP + 5),
            last_confirmed: Height::new(TIP + 6),
        }
    );
    assert_eq!(
        output(&sender, &funding).unwrap().status,
        OutputStatus::Unspent
    );
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + 6))
    );
}

#[test]
fn a_failed_node_request_changes_nothing() {
    let (sender, funding) = funded();
    sender
        .harness
        .node
        .update_chain(|chain| chain.outputs.clear());
    sender
        .harness
        .node
        .fail_next("get_outputs", MockFailure::Unreachable);

    let result = sender.harness.block_on(sender.wallet.refresh());

    assert!(matches!(result, Err(RefreshError::Node(_))), "{result:?}");
    assert_eq!(
        output(&sender, &funding).unwrap().status,
        OutputStatus::Unspent
    );
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

#[test]
fn refresh_needs_an_unlocked_wallet() {
    let (sender, _) = funded();
    sender.wallet.lock();

    let result = sender.harness.block_on(sender.wallet.refresh());

    assert!(
        matches!(result, Err(RefreshError::Wallet(WalletError::Locked))),
        "{result:?}"
    );
}

fn details(sender: &Sender, tx_id: TxId) -> TransactionDetails {
    sender
        .harness
        .block_on(sender.wallet.transaction_details(tx_id))
        .unwrap()
}

#[test]
fn details_of_a_send_show_its_kernel_and_the_height_its_kernel_confirmed_it_at() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_with_final_slate(&sender, Amount::ZERO);
    set_tip(&sender, kernel.height.value());

    refresh(&sender);
    let unconfirmed = details(&sender, tx_id);
    assert_eq!(unconfirmed.transaction.id, tx_id);
    assert_eq!(unconfirmed.transaction.entry.state, TxState::Posted);
    assert_eq!(unconfirmed.kernel_excess, Some(kernel.kernel.excess));
    assert_eq!(unconfirmed.confirmed_height, None);

    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    refresh(&sender);
    let confirmed = details(&sender, tx_id);
    assert_eq!(confirmed.transaction.entry.state, TxState::Confirmed);
    assert_eq!(confirmed.kernel_excess, Some(kernel.kernel.excess));
    assert_eq!(confirmed.confirmed_height, Some(kernel.height));
}

#[test]
fn details_of_a_send_confirmed_by_its_change_show_the_change_height() {
    let (sender, funding) = funded();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(None), to_peer()))
        .unwrap();
    let change = change(&sender, &funding);
    let unconfirmed = details(&sender, sent.tx_id);
    assert_eq!(unconfirmed.transaction.entry.state, TxState::Sent);
    // Nothing is finalized here yet, so no final slate holds a kernel.
    assert_eq!(unconfirmed.kernel_excess, None);
    assert_eq!(unconfirmed.confirmed_height, None);

    sender.harness.node.update_chain(|chain| {
        chain.outputs[0].spent = true;
        chain.outputs.push(on_chain(&change, TIP + 1, 3));
        chain.tip.height = Height::new(TIP + 2);
    });
    refresh(&sender);
    // A second refresh finds nothing new to confirm and keeps the recorded height.
    set_tip(&sender, TIP + 3);
    refresh(&sender);

    let confirmed = details(&sender, sent.tx_id);
    assert_eq!(confirmed.transaction.entry.state, TxState::Confirmed);
    assert_eq!(confirmed.confirmed_height, Some(Height::new(TIP + 1)));
}

#[test]
fn a_reorganisation_that_moves_the_confirming_change_moves_the_confirmation_height() {
    let (sender, funding) = funded();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(None), to_peer()))
        .unwrap();
    let change = change(&sender, &funding);
    sender.harness.node.update_chain(|chain| {
        chain.outputs[0].spent = true;
        chain.outputs.push(on_chain(&change, TIP + 1, 3));
        chain.tip.height = Height::new(TIP + 1);
    });
    refresh(&sender);
    assert_eq!(
        details(&sender, sent.tx_id).confirmed_height,
        Some(Height::new(TIP + 1))
    );

    // The block holding the change is replaced; the change is mined again two blocks later.
    sender.harness.node.update_chain(|chain| {
        let moved = chain
            .outputs
            .iter_mut()
            .find(|output| output.commitment == change.id.commitment)
            .unwrap();
        moved.height = Height::new(TIP + 3);
        chain.tip.height = Height::new(TIP + 3);
    });
    refresh(&sender);

    assert_eq!(
        output(&sender, &change).unwrap().height,
        Height::new(TIP + 3)
    );
    let moved = details(&sender, sent.tx_id);
    assert_eq!(moved.transaction.entry.state, TxState::Confirmed);
    assert_eq!(moved.confirmed_height, Some(Height::new(TIP + 3)));
}

#[test]
fn a_kernel_confirmation_keeps_its_first_height_after_a_reorganisation() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_with_final_slate(&sender, Amount::ZERO);
    sender.harness.node.update_chain(|chain| {
        chain.kernels.push(kernel);
        chain.tip.height = kernel.height;
    });
    refresh(&sender);
    assert_eq!(
        details(&sender, tx_id).confirmed_height,
        Some(kernel.height)
    );

    let moved = kernel.height.checked_add_blocks(2).unwrap();
    sender.harness.node.update_chain(|chain| {
        chain.kernels[0].height = moved;
        chain.tip.height = moved;
    });
    refresh(&sender);

    // A confirmed transaction leaves the kernel lookups, so the move is not seen.
    assert_eq!(
        details(&sender, tx_id).confirmed_height,
        Some(kernel.height)
    );
}

#[test]
fn details_of_an_unknown_transaction_fail() {
    let (sender, _) = funded();
    let result = sender
        .harness
        .block_on(sender.wallet.transaction_details(TxId(99)));
    assert!(
        matches!(result, Err(WalletError::UnknownTransaction(TxId(99)))),
        "{result:?}"
    );
    sender.wallet.lock();
    let result = sender
        .harness
        .block_on(sender.wallet.transaction_details(TxId(1)));
    assert!(matches!(result, Err(WalletError::Locked)), "{result:?}");
}
