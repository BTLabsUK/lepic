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

mod send_support;
mod support;

use lepic_crypto::aggsig::verify_single_from_commit;
use lepic_crypto::{Commitment, RangeProof};
use lepic_keychain::proof::OutputRewinder;
use lepic_keychain::{Identifier, SwitchCommitment};
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_store::{KeyId, OutputRecord, OutputStatus, TxDirection, TxState, WalletStore};
use lepic_wallet::WalletError;
use lepic_wallet::coinbase::{
    Coinbase, CoinbaseError, CoinbaseRequest, MAX_CANDIDATES, STALE_AFTER,
};
use lepic_wallet::refresh::RefreshOutcome;
use send_support::{NEXT_CHILD, Sender};
use support::both_stores;

const FEES: u64 = 7_000_000;

/// The sender, with its funding output on the node's chain.
fn wallet() -> Sender {
    let sender = Sender::new();
    let funding = sender.outputs().remove(0);
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(ChainOutput {
            commitment: funding.id.commitment,
            features: funding.id.features,
            proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
            height: Height::new(1),
            mmr_index: 1,
            spent: false,
        });
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
        proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
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
        .update_chain(|chain| chain.outputs.push(mined(&first, 5, 7)));
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
        .update_chain(|chain| chain.outputs.push(mined(&coinbase, 5, 7)));

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
