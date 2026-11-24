// SPDX-License-Identifier: Apache-2.0
//! The coinbase a mining node asks for: built from the wallet's keys, stored as a candidate,
//! replaced when the node passes its key back, recorded as an incoming transaction once a
//! block confirms it, and deleted when no block did.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::send_support;
use crate::support;

use lepic_crypto::Commitment;
use lepic_crypto::aggsig::verify_single_from_commit;
use lepic_keychain::proof::OutputRewinder;
use lepic_keychain::{Identifier, SwitchCommitment};
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, RejectionKind};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, KeyId, OtherWalletSpend, OutputRecord, OutputStatus, TxDirection, TxId, TxState,
    WalletStore,
};
use lepic_wallet::WalletError;
use lepic_wallet::coinbase::{
    Coinbase, CoinbaseError, CoinbaseRequest, MAX_CANDIDATES, REORG_WINDOW, STALE_AFTER,
};
use lepic_wallet::details::ExpiredReason;
use lepic_wallet::event::{Event, TransactionState};
use lepic_wallet::refresh::{CONFIRMATION_RECHECK_BLOCKS, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use send_support::{NEXT_CHILD, Sender};
use support::both_stores;

const FEES: u64 = 7_000_000;

/// The hash of the block at 5 on the chain these tests start from. Pinned, as on a real chain:
/// the mock otherwise gives the tip a hash of its own.
const BLOCK_5: [u8; 32] = [0xb5; 32];

/// The sender, with its funding output on the node's chain.
fn wallet() -> Sender {
    let sender = Sender::new();
    let funding = sender.outputs().remove(0);
    sender.harness.node.update_chain(|chain| {
        crate::support::mine_output(
            chain,
            ChainOutput {
                commitment: funding.id.commitment,
                features: funding.id.features,
                proof: support::some_proof(),
                height: Height::new(1),
                mmr_index: 1,
                spent: false,
            },
        );
        chain
            .header_hashes
            .insert(Height::new(5), Hash::from_bytes(BLOCK_5));
    });
    sender
}

fn build(sender: &Sender, height: u64, key_id: Option<Identifier>) -> Coinbase {
    sender
        .harness
        .block_on(sender.wallet.build_coinbase(CoinbaseRequest {
            fees: Fee::new(FEES),
            height: Height::new(height),
            key_id,
        }))
        .unwrap()
}

fn candidates(sender: &Sender) -> Vec<OutputRecord> {
    sender
        .outputs()
        .into_iter()
        .filter(|output| output.tx.is_none() && output.status == OutputStatus::Unconfirmed)
        .collect()
}

fn mined(coinbase: &Coinbase, height: u64, mmr_index: u64) -> ChainOutput {
    ChainOutput {
        commitment: coinbase.output.commitment,
        features: OutputFeatures::Coinbase,
        proof: support::some_proof(),
        height: Height::new(height),
        mmr_index,
        spent: false,
    }
}

fn refresh_at(sender: &Sender, tip: u64) {
    sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(tip));
    let outcome = sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert!(
        matches!(outcome, RefreshOutcome::Refreshed(_)),
        "{outcome:?}"
    );
}

both_stores!(builds_a_coinbase_the_node_accepts_and_a_restore_finds);
fn builds_a_coinbase_the_node_accepts_and_a_restore_finds() {
    let sender = wallet();
    let params = Network::Floonet.params();
    let value = params.coinbase_value(Fee::new(FEES), Height::new(5));

    let coinbase = build(&sender, 5, None);

    let key_id = Identifier::new(3, [0, 0, NEXT_CHILD, 0]).unwrap();
    assert_eq!(coinbase.key_id, key_id);
    assert_eq!(coinbase.output.features, OutputFeatures::Coinbase);
    assert_eq!(
        coinbase.output.commitment,
        sender
            .keychain
            .commit(value.value(), &key_id, SwitchCommitment::Regular)
            .unwrap()
    );
    coinbase
        .output
        .proof
        .verify(&coinbase.output.commitment)
        .unwrap();
    let rewound = OutputRewinder::new(&sender.keychain)
        .unwrap()
        .rewind(&coinbase.output.commitment, &coinbase.output.proof)
        .unwrap()
        .unwrap();
    assert_eq!(rewound.identifier, key_id);
    assert_eq!(rewound.amount, value.value());
    assert_eq!(coinbase.kernel.features, KernelFeatures::Coinbase);
    verify_single_from_commit(
        &coinbase.kernel.excess_sig,
        &coinbase.kernel.signature_message(),
        &coinbase.kernel.excess,
    )
    .unwrap();

    let stored = candidates(&sender);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, coinbase.output.identifier());
    assert_eq!(stored[0].key_id, KeyId(key_id.to_bytes()));
    assert_eq!(stored[0].amount, value);
    assert_eq!(stored[0].height, Height::new(5));
    assert_eq!(
        stored[0].lock_height,
        Height::new(5 + params.coinbase_maturity())
    );
    assert_eq!(sender.next_child(), NEXT_CHILD + 1);
    assert!(sender.transactions().is_empty());
}

both_stores!(keeps_the_candidate_whose_key_the_node_passes_back);
fn keeps_the_candidate_whose_key_the_node_passes_back() {
    let sender = wallet();
    let first = build(&sender, 5, None);

    // A new transaction in the template changes the fees, and so the output.
    let again = sender
        .harness
        .block_on(sender.wallet.build_coinbase(CoinbaseRequest {
            fees: Fee::new(FEES + 1),
            height: Height::new(5),
            key_id: Some(first.key_id),
        }))
        .unwrap();

    assert_eq!(again.key_id, first.key_id);
    assert_ne!(again.output.commitment, first.output.commitment);
    let stored = candidates(&sender);
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .any(|output| output.id == first.output.identifier())
    );
    assert!(
        stored
            .iter()
            .any(|output| output.id == again.output.identifier())
    );
    assert_eq!(sender.next_child(), NEXT_CHILD + 1);
}

both_stores!(a_block_found_on_the_older_template_still_pays_the_wallet);
fn a_block_found_on_the_older_template_still_pays_the_wallet() {
    let sender = wallet();
    let first = build(&sender, 5, None);
    let _newer = sender
        .harness
        .block_on(sender.wallet.build_coinbase(CoinbaseRequest {
            fees: Fee::new(FEES + 1),
            height: Height::new(5),
            key_id: Some(first.key_id),
        }))
        .unwrap();

    sender
        .harness
        .node
        .update_chain(|chain| crate::support::mine_output(chain, mined(&first, 5, 7)));
    refresh_at(&sender, 6);

    let output = sender
        .read(|repos| repos.output(first.output.commitment.as_bytes()))
        .unwrap();
    assert_eq!(output.status, OutputStatus::Unspent);
    assert_eq!(sender.transactions().len(), 1);
    // The mined key blinds a spendable output now, so the node gets a new one.
    let next = build(&sender, 7, Some(first.key_id));
    assert_ne!(next.key_id, first.key_id);
}

both_stores!(takes_a_new_key_for_a_key_that_blinds_anything_else);
fn takes_a_new_key_for_a_key_that_blinds_anything_else() {
    let sender = wallet();
    let funding = sender.outputs().remove(0);
    let funding_key = Identifier::from_bytes(&funding.key_id.0).unwrap();
    let unknown = Identifier::new(3, [0, 0, 900, 0]).unwrap();

    let over_funding = build(&sender, 5, Some(funding_key));
    let over_unknown = build(&sender, 6, Some(unknown));

    assert_eq!(
        over_funding.key_id,
        Identifier::new(3, [0, 0, NEXT_CHILD, 0]).unwrap()
    );
    assert_eq!(
        over_unknown.key_id,
        Identifier::new(3, [0, 0, NEXT_CHILD + 1, 0]).unwrap()
    );
    assert_eq!(
        sender.read(|repos| repos.output(funding.commitment())),
        Some(funding)
    );
    assert_eq!(candidates(&sender).len(), 2);
}

both_stores!(records_a_mined_coinbase_as_an_incoming_transaction);
fn records_a_mined_coinbase_as_an_incoming_transaction() {
    let sender = wallet();
    let coinbase = build(&sender, 5, None);
    sender
        .harness
        .node
        .update_chain(|chain| crate::support::mine_output(chain, mined(&coinbase, 5, 7)));

    refresh_at(&sender, 6);

    let output = sender
        .read(|repos| repos.output(coinbase.output.commitment.as_bytes()))
        .unwrap();
    assert_eq!(output.status, OutputStatus::Unspent);
    assert_eq!(output.mmr_index, Some(7));
    assert_eq!(
        output.lock_height,
        Height::new(5 + Network::Floonet.params().coinbase_maturity())
    );
    let tx_id = output.tx.unwrap();
    let entry = sender.read(|repos| repos.transaction(tx_id)).unwrap();
    assert_eq!(entry.direction, TxDirection::Incoming);
    assert_eq!(entry.state, TxState::Confirmed);
    assert_eq!(entry.amount_credited, output.amount);
    assert_eq!(
        sender.read(|repos| repos.confirmed_height(tx_id)),
        Some(Height::new(5))
    );
    let details = sender
        .harness
        .block_on(sender.wallet.transaction_details(tx_id))
        .unwrap();
    assert!(details.coinbase);
    assert_eq!(details.output_commits, vec![coinbase.output.commitment]);

    // A second refresh records nothing more.
    let before = sender.transactions().len();
    refresh_at(&sender, 7);
    assert_eq!(sender.transactions().len(), before);
}

both_stores!(deletes_candidates_no_block_confirmed);
fn deletes_candidates_no_block_confirmed() {
    let sender = wallet();
    let stale = build(&sender, 5, None);
    let tip = 6 + STALE_AFTER;
    let recent = build(&sender, tip, None);

    refresh_at(&sender, tip);

    assert_eq!(
        sender.read(|repos| repos.output(stale.output.commitment.as_bytes())),
        None
    );
    let left = candidates(&sender);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, recent.output.identifier());
    assert!(sender.transactions().is_empty());
}

both_stores!(past_the_cap_the_candidate_touched_longest_ago_goes);
fn past_the_cap_the_candidate_touched_longest_ago_goes() {
    let sender = wallet();
    let oldest = build(&sender, 5, None);
    let live = build(&sender, 5, None);
    let template = candidates(&sender)
        .into_iter()
        .find(|output| output.id == live.output.identifier())
        .unwrap();
    let fill = MAX_CANDIDATES - 3;
    sender
        .store
        .write(|repos| {
            for n in 1..=fill {
                let mut output = template.clone();
                output.id.commitment = Commitment::commit_value(n as u64).unwrap();
                repos.put_output(&output)?;
                repos.touch_output(output.commitment())?;
            }
            Ok::<_, lepic_store::StoreError>(())
        })
        .unwrap();
    // The node's next template touches its row, here with the same fees and key.
    let again = build(&sender, 5, Some(live.key_id));
    assert_eq!(again.output.identifier(), live.output.identifier());
    assert_eq!(candidates(&sender).len(), MAX_CANDIDATES - 1);

    // At the cap a build is answered as ever.
    let first = build(&sender, 6, None);
    assert_eq!(candidates(&sender).len(), MAX_CANDIDATES);
    let second = build(&sender, 6, None);
    let left = candidates(&sender);
    assert_eq!(left.len(), MAX_CANDIDATES);

    let holds = |coinbase: &Coinbase| {
        left.iter()
            .any(|output| output.id == coinbase.output.identifier())
    };
    assert!(!holds(&oldest));
    assert!(holds(&live));
    assert!(holds(&first));
    assert!(holds(&second));
}

both_stores!(deletes_candidates_at_height_zero_or_far_above_the_tip);
fn deletes_candidates_at_height_zero_or_far_above_the_tip() {
    let sender = wallet();
    let tip = 10;
    let at_zero = build(&sender, 0, None);
    let far_above = build(&sender, tip + STALE_AFTER + 1, None);
    let in_reach = build(&sender, tip + STALE_AFTER, None);
    let next = build(&sender, tip + 1, None);

    refresh_at(&sender, tip);

    for gone in [&at_zero, &far_above] {
        assert_eq!(
            sender.read(|repos| repos.output(gone.output.commitment.as_bytes())),
            None
        );
    }
    let left = candidates(&sender);
    assert_eq!(left.len(), 2);
    for kept in [&in_reach, &next] {
        assert!(
            left.iter()
                .any(|output| output.id == kept.output.identifier())
        );
    }
}

/// Whether the node was asked for `coinbase`'s output by commitment, which it logs as a miss
/// when it does not hold it.
fn asked_for(sender: &Sender, coinbase: &Coinbase) -> usize {
    let hex = coinbase.output.commitment.to_hex().to_ascii_lowercase();
    sender
        .harness
        .node
        .outputs_asked()
        .iter()
        .filter(|asked| **asked == hex)
        .count()
}

fn stored(sender: &Sender, coinbase: &Coinbase) -> Option<OutputRecord> {
    sender.read(|repos| repos.output(coinbase.output.commitment.as_bytes()))
}

both_stores!(finds_a_candidate_in_its_block_without_asking_for_it);
fn finds_a_candidate_in_its_block_without_asking_for_it() {
    let sender = wallet();
    let winner = build(&sender, 5, None);
    let loser = sender
        .harness
        .block_on(sender.wallet.build_coinbase(CoinbaseRequest {
            fees: Fee::new(FEES + 1),
            height: Height::new(5),
            key_id: Some(winner.key_id),
        }))
        .unwrap();
    sender
        .harness
        .node
        .update_chain(|chain| crate::support::mine_output(chain, mined(&winner, 5, 7)));

    refresh_at(&sender, 6);

    let output = stored(&sender, &winner).unwrap();
    assert_eq!(output.status, OutputStatus::Unspent);
    assert_eq!(output.mmr_index, Some(7));
    assert_eq!(sender.transactions().len(), 1);
    assert_eq!(asked_for(&sender, &winner), 0);
    assert_eq!(asked_for(&sender, &loser), 0);
    let calls = sender.harness.node.calls();
    assert!(calls.iter().any(|call| call == "get_header"));
    // The block may still be replaced, so the candidate it did not hold stays.
    refresh_at(&sender, 5 + REORG_WINDOW);
    assert!(stored(&sender, &loser).is_some());
}

both_stores!(drops_candidates_their_block_did_not_hold_past_the_window_unasked);
fn drops_candidates_their_block_did_not_hold_past_the_window_unasked() {
    let sender = wallet();
    let first = build(&sender, 5, None);
    let second = build(&sender, 5, None);
    let before = sender.harness.node.calls().len();

    for tip in 5..=5 + REORG_WINDOW {
        refresh_at(&sender, tip);
        assert!(stored(&sender, &first).is_some(), "tip {tip}");
        assert!(stored(&sender, &second).is_some(), "tip {tip}");
    }
    let reads = |sender: &Sender| {
        sender
            .harness
            .node
            .calls()
            .iter()
            .skip(before)
            .filter(|call| *call == "get_pmmr_indices")
            .count()
    };
    // The block's hash did not change, so it was read once.
    assert_eq!(reads(&sender), 1);
    refresh_at(&sender, 6 + REORG_WINDOW);

    assert_eq!(stored(&sender, &first), None);
    assert_eq!(stored(&sender, &second), None);
    assert_eq!(asked_for(&sender, &first), 0);
    assert_eq!(asked_for(&sender, &second), 0);
    assert!(sender.transactions().is_empty());
}

both_stores!(looks_up_no_candidate_above_the_tip);
fn looks_up_no_candidate_above_the_tip() {
    let sender = wallet();
    let tip = 10;
    let next = build(&sender, tip + 1, None);
    let later = build(&sender, tip + STALE_AFTER, None);
    let before = sender.harness.node.calls().len();

    refresh_at(&sender, tip);

    let calls = sender.harness.node.calls().split_off(before);
    assert!(
        !calls.iter().any(|call| call == "get_pmmr_indices"),
        "{calls:?}"
    );
    assert!(
        !calls.iter().any(|call| call == "get_unspent_outputs"),
        "{calls:?}"
    );
    assert_eq!(asked_for(&sender, &next), 0);
    assert_eq!(asked_for(&sender, &later), 0);
    assert_eq!(candidates(&sender).len(), 2);
}

both_stores!(a_refresh_at_tip_zero_reads_no_block);
fn a_refresh_at_tip_zero_reads_no_block() {
    let sender = wallet();
    // The funding output, mined at 1, would make a tip of 0 implausible.
    let mut funding = sender.outputs().remove(0);
    funding.status = OutputStatus::Spent;
    sender
        .store
        .write(|repos| repos.put_output(&funding))
        .unwrap();
    let next = build(&sender, 1, None);
    let before = sender.harness.node.calls().len();

    refresh_at(&sender, 0);

    let calls = sender.harness.node.calls().split_off(before);
    assert!(
        !calls.iter().any(|call| call == "get_pmmr_indices"),
        "{calls:?}"
    );
    assert_eq!(asked_for(&sender, &next), 0);
    assert_eq!(candidates(&sender).len(), 1);
}

both_stores!(reads_a_block_again_when_a_reorganisation_replaces_it);
fn reads_a_block_again_when_a_reorganisation_replaces_it() {
    let sender = wallet();
    let coinbase = build(&sender, 5, None);
    refresh_at(&sender, 8);
    assert_eq!(candidates(&sender).len(), 1);

    // The block another miner found at 5 is replaced by ours.
    sender.harness.node.update_chain(|chain| {
        chain
            .header_hashes
            .insert(Height::new(5), Hash::from_bytes([0xee; 32]));
        crate::support::mine_output(chain, mined(&coinbase, 5, 7));
    });
    refresh_at(&sender, 9);

    let output = stored(&sender, &coinbase).unwrap();
    assert_eq!(output.status, OutputStatus::Unspent);
    let tx_id = output.tx.unwrap();
    assert_eq!(
        sender.read(|repos| repos.transaction(tx_id)).unwrap().state,
        TxState::Confirmed
    );
    assert_eq!(asked_for(&sender, &coinbase), 0);
}

/// A reward the wallet holds: built and mined at 5, with its kernel, and recorded by a refresh
/// at 6.
fn confirmed_reward(sender: &Sender) -> (Coinbase, TxId) {
    let coinbase = build(sender, 5, None);
    sender.harness.node.update_chain(|chain| {
        crate::support::mine_output(chain, mined(&coinbase, 5, 7));
        chain.kernels.push(LocatedKernel {
            kernel: coinbase.kernel,
            height: Height::new(5),
            mmr_index: 3,
        });
    });
    refresh_at(sender, 6);
    let tx_id = stored(sender, &coinbase).unwrap().tx.unwrap();
    (coinbase, tx_id)
}

/// A reorganisation replaces the block at 5 with one that holds neither the reward's output
/// nor its kernel.
fn replace_block(sender: &Sender, coinbase: &Coinbase) {
    sender.harness.node.update_chain(|chain| {
        chain
            .outputs
            .retain(|output| output.commitment != coinbase.output.commitment);
        chain
            .kernels
            .retain(|located| located.kernel.excess != coinbase.kernel.excess);
        chain
            .header_hashes
            .insert(Height::new(5), Hash::from_bytes([0xee; 32]));
    });
}

/// The block at 5 holds the reward again.
fn restore_block(sender: &Sender, coinbase: &Coinbase) {
    sender.harness.node.update_chain(|chain| {
        chain
            .header_hashes
            .insert(Height::new(5), Hash::from_bytes(BLOCK_5));
        crate::support::mine_output(chain, mined(coinbase, 5, 7));
        chain.kernels.push(LocatedKernel {
            kernel: coinbase.kernel,
            height: Height::new(5),
            mmr_index: 3,
        });
    });
}

fn state_of(sender: &Sender, tx_id: TxId) -> TxState {
    sender.read(|repos| repos.transaction(tx_id)).unwrap().state
}

fn transitions(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<TransactionState> {
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(state) = event {
            seen.push(state);
        }
    }
    seen
}

both_stores!(a_reward_whose_block_was_replaced_expires_and_leaves_the_balance);
fn a_reward_whose_block_was_replaced_expires_and_leaves_the_balance() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);
    let amount = stored(&sender, &coinbase).unwrap().amount;
    let before = sender.wallet.balance(AccountIndex(0)).unwrap();
    assert_eq!(before.immature, amount);
    let mut events = sender.wallet.subscribe();

    replace_block(&sender, &coinbase);
    refresh_at(&sender, 7);

    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
    assert_eq!(
        transitions(&mut events),
        vec![TransactionState {
            tx_id,
            from: TxState::Confirmed,
            to: TxState::Expired,
        }]
    );
    let output = stored(&sender, &coinbase).unwrap();
    assert_eq!(output.status, OutputStatus::Unconfirmed);
    assert_eq!(output.tx, Some(tx_id));
    assert_eq!(output.mmr_index, None);
    assert_eq!(sender.read(|repos| repos.confirmed_height(tx_id)), None);
    let after = sender.wallet.balance(AccountIndex(0)).unwrap();
    assert_eq!(after.immature, Amount::ZERO);
    assert_eq!(after.total, before.total.checked_sub(amount).unwrap());
    let details = sender
        .harness
        .block_on(sender.wallet.transaction_details(tx_id))
        .unwrap();
    assert!(details.coinbase);
    assert_eq!(details.expired_reason, Some(ExpiredReason::Orphaned));

    // Later refreshes neither ask for it nor delete it.
    let asked = asked_for(&sender, &coinbase);
    refresh_at(&sender, 8);
    refresh_at(&sender, 6 + REORG_WINDOW);
    refresh_at(&sender, 40);
    assert_eq!(asked_for(&sender, &coinbase), asked);
    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
    assert_eq!(
        stored(&sender, &coinbase).unwrap().status,
        OutputStatus::Unconfirmed
    );
    assert!(transitions(&mut events).is_empty());
}

both_stores!(a_replaced_reward_whose_block_comes_back_confirms_again);
fn a_replaced_reward_whose_block_comes_back_confirms_again() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);
    replace_block(&sender, &coinbase);
    refresh_at(&sender, 7);
    // A refresh reads the replacing block, which does not hold the reward.
    refresh_at(&sender, 8);
    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
    let mut events = sender.wallet.subscribe();

    restore_block(&sender, &coinbase);
    refresh_at(&sender, 9);

    assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);
    assert_eq!(
        transitions(&mut events),
        vec![TransactionState {
            tx_id,
            from: TxState::Expired,
            to: TxState::Confirmed,
        }]
    );
    let output = stored(&sender, &coinbase).unwrap();
    assert_eq!(output.status, OutputStatus::Unspent);
    assert_eq!(output.mmr_index, Some(7));
    assert_eq!(
        output.lock_height,
        Height::new(5 + Network::Floonet.params().coinbase_maturity())
    );
    assert_eq!(
        sender.read(|repos| repos.confirmed_height(tx_id)),
        Some(Height::new(5))
    );
    let details = sender
        .harness
        .block_on(sender.wallet.transaction_details(tx_id))
        .unwrap();
    assert_eq!(details.expired_reason, None);
}

both_stores!(a_reward_a_lagging_node_showed_gone_confirms_again_past_the_reorg_window);
fn a_reward_a_lagging_node_showed_gone_confirms_again_past_the_reorg_window() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);
    replace_block(&sender, &coinbase);
    refresh_at(&sender, 7);
    let asked = asked_for(&sender, &coinbase);
    refresh_at(&sender, 6 + REORG_WINDOW);
    assert_eq!(state_of(&sender, tx_id), TxState::Expired);

    // A node that had the block all along answers again, deeper than REORG_WINDOW.
    restore_block(&sender, &coinbase);
    refresh_at(&sender, 30);

    assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);
    assert_eq!(
        stored(&sender, &coinbase).unwrap().status,
        OutputStatus::Unspent
    );
    assert_eq!(asked_for(&sender, &coinbase), asked);
}

both_stores!(past_the_recheck_window_only_a_scan_confirms_an_orphaned_reward);
fn past_the_recheck_window_only_a_scan_confirms_an_orphaned_reward() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);
    replace_block(&sender, &coinbase);
    refresh_at(&sender, 7);
    restore_block(&sender, &coinbase);
    let before = sender.harness.node.calls().len();

    refresh_at(&sender, 6 + CONFIRMATION_RECHECK_BLOCKS);

    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
    let calls = sender.harness.node.calls().split_off(before);
    assert!(
        !calls.iter().any(|call| call == "get_pmmr_indices"),
        "{calls:?}"
    );
    // A scan rewinds the output's own proof.
    sender.harness.node.update_chain(|chain| {
        for output in &mut chain.outputs {
            if output.commitment == coinbase.output.commitment {
                output.proof = coinbase.output.proof.clone();
            }
        }
    });
    scan(&sender, false);
    assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);
    let output = stored(&sender, &coinbase).unwrap();
    assert_eq!(output.status, OutputStatus::Unspent);
    assert_eq!(
        sender.read(|repos| repos.confirmed_height(tx_id)),
        Some(Height::new(5))
    );
}

/// Stores the reward's output as spent, as a refresh before this change left one whose block
/// was replaced.
fn mark_spent(sender: &Sender, coinbase: &Coinbase) {
    let mut output = stored(sender, coinbase).unwrap();
    output.status = OutputStatus::Spent;
    sender
        .store
        .write(|repos| repos.put_output(&output))
        .unwrap();
}

fn scan(sender: &Sender, delete_unconfirmed: bool) {
    sender
        .harness
        .block_on(sender.wallet.scan(
            ScanOptions {
                delete_unconfirmed,
                ..ScanOptions::update(Network::Floonet)
            },
            &ScanCancel::new(),
        ))
        .unwrap();
}

both_stores!(a_scan_expires_a_reward_stored_as_spent_whose_block_was_replaced);
fn a_scan_expires_a_reward_stored_as_spent_whose_block_was_replaced() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);
    replace_block(&sender, &coinbase);
    mark_spent(&sender, &coinbase);
    let tip = 6 + CONFIRMATION_RECHECK_BLOCKS;
    // Too deep for a refresh to look at again.
    refresh_at(&sender, tip);
    assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);
    let mut events = sender.wallet.subscribe();

    scan(&sender, false);

    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
    assert_eq!(
        transitions(&mut events),
        vec![TransactionState {
            tx_id,
            from: TxState::Confirmed,
            to: TxState::Expired,
        }]
    );
    let output = stored(&sender, &coinbase).unwrap();
    assert_eq!(output.status, OutputStatus::Unconfirmed);
    assert_eq!(output.tx, Some(tx_id));

    // The repair keeps it with its entry.
    scan(&sender, true);
    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
    assert_eq!(
        stored(&sender, &coinbase).unwrap().status,
        OutputStatus::Unconfirmed
    );
}

both_stores!(a_scan_keeps_a_reward_on_chain_or_spent_by_another_wallet);
fn a_scan_keeps_a_reward_on_chain_or_spent_by_another_wallet() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);

    // Spent, its kernel still on chain.
    mark_spent(&sender, &coinbase);
    sender.harness.node.update_chain(|chain| {
        chain
            .outputs
            .retain(|output| output.commitment != coinbase.output.commitment);
    });
    scan(&sender, false);
    assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);

    // Spent by another wallet on the same phrase, so not looked up.
    replace_block(&sender, &coinbase);
    mark_spent(&sender, &coinbase);
    sender
        .store
        .write(|repos| {
            repos.put_other_wallet_spend(
                tx_id,
                &OtherWalletSpend {
                    after: Height::new(5),
                    to: Height::new(6),
                    open: false,
                    spent: vec![*coinbase.output.commitment.as_bytes()],
                    change: Vec::new(),
                },
            )
        })
        .unwrap();
    let lookups = |sender: &Sender| {
        sender
            .harness
            .node
            .calls()
            .iter()
            .filter(|call| *call == "get_kernel")
            .count()
    };
    let before = lookups(&sender);
    scan(&sender, false);
    assert_eq!(lookups(&sender), before);
    assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);
}

both_stores!(a_scan_whose_kernel_lookup_fails_keeps_the_reward_and_completes);
fn a_scan_whose_kernel_lookup_fails_keeps_the_reward_and_completes() {
    let sender = wallet();
    let (coinbase, tx_id) = confirmed_reward(&sender);
    replace_block(&sender, &coinbase);
    mark_spent(&sender, &coinbase);
    refresh_at(&sender, 6 + CONFIRMATION_RECHECK_BLOCKS);
    for failure in [
        MockFailure::Unreachable,
        MockFailure::Rejected(RejectionKind::Internal),
    ] {
        sender.harness.node.fail_every("get_kernel", failure);
        scan(&sender, false);
        assert_eq!(state_of(&sender, tx_id), TxState::Confirmed);
        sender.harness.node.stop_failing("get_kernel");
    }

    scan(&sender, false);
    assert_eq!(state_of(&sender, tx_id), TxState::Expired);
}

#[test]
fn a_locked_wallet_builds_no_coinbase() {
    let sender = wallet();
    sender.wallet.lock();

    let result = sender
        .harness
        .block_on(sender.wallet.build_coinbase(CoinbaseRequest {
            fees: Fee::ZERO,
            height: Height::new(5),
            key_id: None,
        }));

    assert!(
        matches!(result, Err(CoinbaseError::Wallet(WalletError::Locked))),
        "{result:?}"
    );
}
