// SPDX-License-Identifier: Apache-2.0
//! A send whose input a chain reorganisation took (ADR 0071): the change of an earlier send of
//! the wallet, or a block reward, whose block another branch replaced. The send is not ended for
//! it at once: it waits, its coin held, until the earlier send is mined again, and then goes
//! through, or ends `expired` 60 blocks later. A coin another wallet spent, while the earlier
//! send's kernel stays on chain, still ends the send. A confirmed transaction whose block was
//! replaced is reopened and confirms again.
//!
//! Each case names its id in the reorganisation test plan (RO-01 to RO-06). The own-transaction
//! case, a coin this wallet's own cancelled payment spent, is
//! `spend_back::a_move_back_refused_because_the_cancelled_payment_was_mined_names_the_payment`.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::post_retry::{PUSH, Retrying, answered_send, finalize};
use crate::receive_harness::Receiver;
use crate::send_support::{ACCOUNT, FUNDING, Sender, TIP};
use crate::support::{both_stores, fixed_time};

use lepic_crypto::{Commitment, Signature};
use lepic_node::mock::{ChainOutput, MockFailure, MockNode};
use lepic_node::{LocatedKernel, Propagation};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::tx::Transaction;
use lepic_store::{
    OutputRecord, OutputStatus, StoreError, TransactionEntry, TxDirection, TxId, TxState,
    WalletStore as _,
};
use lepic_wallet::details::{ChainReplaced, ExpiredReason, TransactionDetails};
use lepic_wallet::finalize::{FinalizeError, Posted};
use lepic_wallet::refresh::RefreshOutcome;

/// The wallet that answers the second send. The first send's receiver would make the same
/// output again, for the same amount under the same key.
const OTHER_RECEIVER_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo zoo vote";

/// The first send of the wallet, mined at `TIP + 1` and confirmed, and a second send that
/// spends its change.
struct Chained {
    /// The first send.
    retrying: Retrying,
    first: Transaction,
    second: TxId,
    /// The first send's change, the second send's input.
    change: Commitment,
}

/// The second send is posted, or with `failure` on every push, left finalized.
fn chained(failure: Option<MockFailure>) -> Chained {
    let retrying = Retrying::posted();
    let first = retrying.final_transaction();
    mine(retrying.node(), &first, TIP + 1);
    retrying.at(TIP + 1);
    assert_eq!(retrying.state(), TxState::Confirmed);
    let sender = &retrying.sender;
    let own = sender.outputs();
    let change = first
        .outputs()
        .iter()
        .map(|output| output.commitment)
        .find(|commitment| own.iter().any(|coin| coin.id.commitment == *commitment))
        .unwrap();

    let receiver = Receiver::new(OTHER_RECEIVER_MNEMONIC, TIP + 1);
    let (second, s2) = answered_send(&sender.harness, &sender.wallet, &sender.peer, &receiver);
    if let Some(failure) = failure {
        retrying.node().fail_every(PUSH, failure);
        let error = finalize(&sender.harness, &sender.wallet, &s2).unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        retrying.node().stop_failing(PUSH);
    } else {
        finalize(&sender.harness, &sender.wallet, &s2).unwrap();
    }
    let chained = Chained {
        retrying,
        first,
        second,
        change,
    };
    let coin = chained.change();
    assert_eq!(coin.status, OutputStatus::Locked);
    assert_eq!(coin.tx, Some(second));
    chained
}

impl Chained {
    fn change(&self) -> OutputRecord {
        self.retrying
            .sender
            .outputs()
            .into_iter()
            .find(|coin| coin.id.commitment == self.change)
            .unwrap()
    }

    fn second_state(&self) -> TxState {
        self.retrying
            .sender
            .read(|repos| repos.transaction(self.second))
            .unwrap()
            .state
    }

    fn second_details(&self) -> TransactionDetails {
        let sender = &self.retrying.sender;
        sender
            .harness
            .block_on(sender.wallet.transaction_details(self.second))
            .unwrap()
    }

    fn post_second(&self) -> Result<Posted, FinalizeError> {
        let sender = &self.retrying.sender;
        sender
            .harness
            .block_on(sender.wallet.post(self.second, Propagation::Stem))
    }

    fn entries(&self) -> usize {
        self.retrying.sender.transactions().len()
    }

    /// Pushes of the second send the node accepted so far.
    fn second_pushes(&self) -> usize {
        let second = self.retrying.final_transaction_of(self.second);
        self.retrying
            .node()
            .pushed_transactions()
            .iter()
            .filter(|pushed| pushed.kernels() == second.kernels())
            .count()
    }

    /// Another branch replaces the block at `TIP + 1` and grows to `tip`: the first send's
    /// outputs and kernel are gone and its input is unspent again.
    fn reorganised(&self, tip: u64) {
        unmine(self.retrying.node(), &self.first, tip);
    }

    /// Another wallet on the same recovery phrase spent the change, at `tip`; the first send
    /// stays on chain.
    fn change_spent_elsewhere(&self, tip: u64) {
        let change = self.change;
        self.retrying.node().update_chain(|chain| {
            chain.outputs.retain(|held| held.commitment != change);
            chain.tip.height = Height::new(tip);
        });
    }
}

/// Another branch replaces the block that held `transaction` and grows to `tip`: its outputs
/// and kernel are gone and its inputs are unspent again.
fn unmine(node: &MockNode, transaction: &Transaction, tip: u64) {
    node.update_chain(|chain| {
        chain.outputs.retain(|held| {
            !transaction
                .outputs()
                .iter()
                .any(|output| output.commitment == held.commitment)
        });
        for held in &mut chain.outputs {
            if transaction
                .inputs()
                .iter()
                .any(|input| input.commitment == held.commitment)
            {
                held.spent = false;
            }
        }
        chain
            .kernels
            .retain(|located| located.kernel.excess != transaction.kernels()[0].excess);
        chain.tip.height = Height::new(tip);
    });
}

/// A miner includes `transaction` at `height`: its inputs are spent, and its outputs and kernel
/// are on chain under MMR indices past the ones there.
fn mine(node: &MockNode, transaction: &Transaction, height: u64) {
    node.update_chain(|chain| {
        for held in &mut chain.outputs {
            if transaction
                .inputs()
                .iter()
                .any(|input| input.commitment == held.commitment)
            {
                held.spent = true;
            }
        }
        let next_index = chain
            .outputs
            .iter()
            .map(|held| held.mmr_index)
            .max()
            .unwrap_or(0)
            + 1;
        for (mmr_index, output) in (next_index..).zip(transaction.outputs()) {
            crate::support::mine_output(
                chain,
                ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height: Height::new(height),
                    mmr_index,
                    spent: false,
                },
            );
        }
        let kernel_index = chain
            .kernels
            .iter()
            .map(|located| located.mmr_index)
            .max()
            .unwrap_or(0)
            + 1;
        chain.kernels.push(LocatedKernel {
            kernel: transaction.kernels()[0],
            height: Height::new(height),
            mmr_index: kernel_index,
        });
        if chain.tip.height < Height::new(height) {
            chain.tip.height = Height::new(height);
        }
    });
}

// RO-02: the reorganisation comes after the post.
both_stores!(a_posted_send_whose_input_a_reorganisation_took_waits_and_goes_through);
fn a_posted_send_whose_input_a_reorganisation_took_waits_and_goes_through() {
    let chained = chained(None);
    let retrying = &chained.retrying;
    assert_eq!(chained.second_state(), TxState::Posted);
    let entries = chained.entries();

    chained.reorganised(TIP + 3);
    retrying.at(TIP + 3);

    // The first send is reopened, and the second keeps its coin, off chain for now.
    assert_eq!(retrying.state(), TxState::Posted);
    assert_eq!(chained.second_state(), TxState::Posted);
    let coin = chained.change();
    assert_eq!(coin.status, OutputStatus::Locked);
    assert_eq!(coin.tx, Some(chained.second));
    assert_eq!(coin.mmr_index, None);
    // No spend of another wallet is recorded.
    assert_eq!(chained.entries(), entries);

    retrying.at(TIP + 8);
    assert_eq!(chained.second_state(), TxState::Posted);

    // The first send is mined again on the new branch: the coin is back, still held.
    mine(retrying.node(), &chained.first, TIP + 9);
    retrying.at(TIP + 9);
    assert_eq!(retrying.state(), TxState::Confirmed);
    let coin = chained.change();
    assert_eq!(coin.status, OutputStatus::Locked);
    assert_eq!(coin.tx, Some(chained.second));
    assert!(coin.mmr_index.is_some(), "{coin:?}");

    // The second send, missing from the pool, is pushed again and mined.
    let pushes = chained.second_pushes();
    for height in TIP + 10..=TIP + 12 {
        retrying.at(height);
    }
    assert!(
        chained.second_pushes() > pushes,
        "the second send is pushed again"
    );
    let second = retrying.final_transaction_of(chained.second);
    mine(retrying.node(), &second, TIP + 13);
    retrying.at(TIP + 13);
    assert_eq!(chained.second_state(), TxState::Confirmed);
    assert_eq!(chained.change().status, OutputStatus::Spent);
    assert_eq!(chained.entries(), entries);
}

// RO-01: the reorganisation comes before the post; the send completes once its input is
// mined again.
both_stores!(a_post_refused_for_an_input_a_reorganisation_took_keeps_the_send);
fn a_post_refused_for_an_input_a_reorganisation_took_keeps_the_send() {
    let chained = chained(Some(MockFailure::HttpStatus(502)));
    let retrying = &chained.retrying;
    retrying.node().expect_invalid_pushes();
    assert_eq!(chained.second_state(), TxState::Finalized);
    let entries = chained.entries();

    // No refresh has seen the reorganisation: the first send is still held confirmed, and the
    // chain no longer holds its kernel.
    chained.reorganised(TIP + 3);
    let error = chained.post_second().unwrap_err();

    assert!(
        matches!(error, FinalizeError::InputsReorged { tx_id, .. } if tx_id == chained.second),
        "{error:?}"
    );
    assert_eq!(chained.second_state(), TxState::Finalized);
    assert_eq!(chained.change().status, OutputStatus::Locked);
    assert_eq!(chained.entries(), entries);
    assert_eq!(
        chained.second_details().chain_replaced,
        Some(ChainReplaced::InputsReplaced)
    );

    // Refreshes push it again with their backoff, the node refuses, and the send is kept.
    let pushes = retrying.pushes();
    for height in TIP + 4..=TIP + 12 {
        retrying.at(height);
        assert_eq!(chained.second_state(), TxState::Finalized, "at {height}");
    }
    assert!(
        retrying.pushes() > pushes,
        "the second send is pushed again"
    );
    assert_eq!(chained.change().status, OutputStatus::Locked);
    assert_eq!(chained.entries(), entries);
    assert_eq!(
        chained.second_details().chain_replaced,
        Some(ChainReplaced::InputsReplaced)
    );

    // Once the first send is mined again, the post goes through.
    mine(retrying.node(), &chained.first, TIP + 13);
    retrying.at(TIP + 13);
    chained.post_second().unwrap();
    assert_eq!(chained.second_state(), TxState::Posted);
    assert_eq!(chained.second_details().chain_replaced, None);
    let second = retrying.final_transaction_of(chained.second);
    mine(retrying.node(), &second, TIP + 14);
    retrying.at(TIP + 14);
    assert_eq!(chained.second_state(), TxState::Confirmed);
    assert_eq!(chained.change().status, OutputStatus::Spent);
    assert_eq!(chained.entries(), entries);
}

// RO-06: a true spend by another wallet, refused at the post.
both_stores!(a_post_refused_for_an_input_another_wallet_spent_still_ends_the_send);
fn a_post_refused_for_an_input_another_wallet_spent_still_ends_the_send() {
    let chained = chained(Some(MockFailure::HttpStatus(502)));
    chained.retrying.node().expect_invalid_pushes();

    chained.change_spent_elsewhere(TIP + 3);
    let error = chained.post_second().unwrap_err();

    assert!(
        matches!(error, FinalizeError::InputsSpentElsewhere { tx_id, .. } if tx_id == chained.second),
        "{error:?}"
    );
    assert_eq!(chained.second_state(), TxState::Cancelled);
}

// RO-06: a true spend by another wallet, found by a refresh.
both_stores!(a_refresh_still_ends_a_posted_send_whose_input_another_wallet_spent);
fn a_refresh_still_ends_a_posted_send_whose_input_another_wallet_spent() {
    let chained = chained(None);

    chained.change_spent_elsewhere(TIP + 3);
    chained.retrying.at(TIP + 3);

    assert_eq!(chained.retrying.state(), TxState::Confirmed);
    assert_eq!(chained.second_state(), TxState::Cancelled);
}

both_stores!(a_send_cancelled_while_its_input_is_reorged_gives_the_coin_back_to_its_maker);
fn a_send_cancelled_while_its_input_is_reorged_gives_the_coin_back_to_its_maker() {
    let chained = chained(Some(MockFailure::HttpStatus(502)));
    let retrying = &chained.retrying;
    retrying.node().expect_invalid_pushes();
    let entries = chained.entries();
    chained.reorganised(TIP + 3);
    retrying.at(TIP + 3);
    assert_eq!(chained.second_state(), TxState::Finalized);

    let sender = &retrying.sender;
    sender
        .harness
        .block_on(sender.wallet.cancel(chained.second))
        .unwrap();
    retrying.at(TIP + 4);

    // The coin waits on the first send, which made it, and is not taken for another wallet's
    // spend.
    assert_eq!(chained.second_state(), TxState::Cancelled);
    let coin = chained.change();
    assert_eq!(coin.status, OutputStatus::Unconfirmed);
    assert_eq!(coin.tx, Some(retrying.tx_id));
    assert_eq!(chained.entries(), entries);

    mine(retrying.node(), &chained.first, TIP + 5);
    retrying.at(TIP + 5);
    assert_eq!(retrying.state(), TxState::Confirmed);
    assert_eq!(chained.change().status, OutputStatus::Unspent);
    assert_eq!(chained.entries(), entries);
}

// RO-01, across a restart: the wait's mark is in the store, so a wallet opened again still
// reads the send as waiting for its inputs.
both_stores!(a_reopened_wallet_still_reads_the_wait_for_reorged_inputs);
fn a_reopened_wallet_still_reads_the_wait_for_reorged_inputs() {
    let chained = chained(Some(MockFailure::HttpStatus(502)));
    chained.retrying.node().expect_invalid_pushes();
    chained.reorganised(TIP + 3);
    chained.post_second().unwrap_err();

    let sender = &chained.retrying.sender;
    let (wallet, _peer) = crate::post_retry::reopened(sender, false);

    let details = sender
        .harness
        .block_on(wallet.transaction_details(chained.second))
        .unwrap();
    assert_eq!(details.chain_replaced, Some(ChainReplaced::InputsReplaced));
}

// The maker never comes back: 60 blocks after the wallet first saw the inputs gone, the send
// ends expired, its coin goes back to the first send, unconfirmed, and no spend of another
// wallet is recorded.
both_stores!(a_send_whose_reorged_input_never_comes_back_expires_after_sixty_blocks);
fn a_send_whose_reorged_input_never_comes_back_expires_after_sixty_blocks() {
    let chained = chained(None);
    let retrying = &chained.retrying;
    retrying.node().expect_invalid_pushes();
    let entries = chained.entries();

    chained.reorganised(TIP + 3);
    retrying.at(TIP + 3);
    assert_eq!(
        chained.second_details().chain_replaced,
        Some(ChainReplaced::InputsReplaced)
    );

    for height in (TIP + 4..TIP + 63).step_by(5) {
        retrying.at(height);
        assert_eq!(chained.second_state(), TxState::Posted, "at {height}");
    }
    retrying.at(TIP + 62);
    assert_eq!(chained.second_state(), TxState::Posted);

    retrying.at(TIP + 63);
    assert_eq!(chained.second_state(), TxState::Expired);
    let details = chained.second_details();
    assert_eq!(details.expired_reason, Some(ExpiredReason::InputsReorged));
    assert_eq!(details.chain_replaced, None);
    let coin = chained.change();
    assert_eq!(coin.status, OutputStatus::Unconfirmed);
    assert_eq!(coin.tx, Some(retrying.tx_id));
    assert_eq!(retrying.state(), TxState::Posted);
    assert_eq!(chained.entries(), entries);

    // The reason stays once later refreshes swept the marks.
    retrying.at(TIP + 70);
    assert_eq!(
        chained.second_details().expired_reason,
        Some(ExpiredReason::InputsReorged)
    );
}

/// A block reward of `FUNDING` at height 1 that paid the sender's funding coin, its kernel on
/// chain.
fn reward_of_the_funding(sender: &Sender) -> (TxId, TxKernel) {
    let coin = sender.outputs()[0].clone();
    let value = Commitment::commit_value(FUNDING).unwrap();
    let excess = Commitment::sum(&[coin.id.commitment], &[value]).unwrap();
    let kernel = TxKernel::new(
        KernelFeatures::Coinbase,
        excess,
        Signature::from_compact(&[1; 64]).unwrap(),
    );
    let reward = sender
        .store
        .write(|repos| {
            let reward = repos.insert_transaction(&TransactionEntry {
                account: ACCOUNT,
                direction: TxDirection::Incoming,
                state: TxState::Confirmed,
                slate_id: None,
                transport: None,
                amount_credited: Amount::new(FUNDING),
                amount_debited: Amount::ZERO,
                fee: None,
                created_at: fixed_time(),
                updated_at: fixed_time(),
            })?;
            repos.set_confirmed_height(reward, Height::new(1))?;
            let mut coin = coin.clone();
            coin.tx = Some(reward);
            repos.put_output(&coin)?;
            Ok::<_, StoreError>(reward)
        })
        .unwrap();
    sender.harness.node.update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel,
            height: Height::new(1),
            mmr_index: 1,
        });
    });
    let outcome = sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert!(
        matches!(outcome, RefreshOutcome::Refreshed(_)),
        "{outcome:?}"
    );
    (reward, kernel)
}

// RO-03: a send of a block reward whose block another branch replaced. The refusal names the
// reorganisation, not another wallet's spend; the send waits the same 60 blocks, then ends
// expired and the coin goes back to the reward, which ends orphaned.
both_stores!(a_send_of_a_reward_whose_block_was_replaced_waits_and_gives_the_coin_back);
fn a_send_of_a_reward_whose_block_was_replaced_waits_and_gives_the_coin_back() {
    let mut reward = None;
    let (retrying, _receiver) = Retrying::answered_with(|sender| {
        reward = Some(reward_of_the_funding(sender));
    });
    let (reward, kernel) = reward.unwrap();
    retrying
        .node()
        .fail_every(PUSH, MockFailure::HttpStatus(502));
    retrying.finalize().unwrap_err();
    retrying.node().stop_failing(PUSH);
    retrying.node().expect_invalid_pushes();
    let entries = retrying.sender.transactions().len();

    let funding = retrying.funding;
    retrying.node().update_chain(|chain| {
        chain.outputs.retain(|held| held.commitment != funding);
        chain
            .kernels
            .retain(|located| located.kernel.excess != kernel.excess);
        chain.tip.height = Height::new(TIP + 1);
    });
    let error = retrying.post().unwrap_err();

    assert!(
        matches!(error, FinalizeError::InputsReorged { tx_id, .. } if tx_id == retrying.tx_id),
        "{error:?}"
    );
    assert_eq!(retrying.state(), TxState::Finalized);
    assert_eq!(retrying.funding_status(), OutputStatus::Locked);
    assert_eq!(
        retrying.details().chain_replaced,
        Some(ChainReplaced::InputsReplaced)
    );

    for height in (TIP + 2..TIP + 61).step_by(5) {
        retrying.at(height);
        assert_eq!(retrying.state(), TxState::Finalized, "at {height}");
    }
    retrying.at(TIP + 61);

    assert_eq!(retrying.state(), TxState::Expired);
    assert_eq!(
        retrying.details().expired_reason,
        Some(ExpiredReason::InputsReorged)
    );
    let coin = retrying
        .sender
        .outputs()
        .into_iter()
        .find(|output| output.id.commitment == funding)
        .unwrap();
    assert_eq!(coin.status, OutputStatus::Unconfirmed);
    assert_eq!(coin.tx, Some(reward));
    let state = retrying
        .sender
        .read(|repos| repos.transaction(reward))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Expired);
    let reward_details = retrying
        .sender
        .harness
        .block_on(retrying.sender.wallet.transaction_details(reward))
        .unwrap();
    assert_eq!(reward_details.expired_reason, Some(ExpiredReason::Orphaned));
    assert_eq!(retrying.sender.transactions().len(), entries);
}

// RO-04: the receiver's confirmed receive, whose block another branch replaced, is reopened,
// its output unconfirmed, and confirms again once the payment is mined again.
both_stores!(a_confirmed_receive_whose_block_was_replaced_is_reopened_and_confirms_again);
fn a_confirmed_receive_whose_block_was_replaced_is_reopened_and_confirms_again() {
    let (retrying, receiver) = Retrying::answered_with(|_| ());
    retrying.finalize().unwrap();
    let payment = retrying.final_transaction();
    mine(&receiver.node, &payment, TIP + 1);
    receiver.refresh_at(TIP + 1);
    let receive = received(&receiver);
    assert_eq!(receive.1, TxState::Confirmed);

    unmine(&receiver.node, &payment, TIP + 3);
    receiver.refresh_at(TIP + 3);

    let (tx_id, state) = received(&receiver);
    assert!(!matches!(state, TxState::Confirmed), "{state:?}");
    let details = receiver
        .block_on(receiver.wallet.transaction_details(tx_id))
        .unwrap();
    assert_eq!(details.chain_replaced, Some(ChainReplaced::Reopened));
    let outputs = receiver
        .store()
        .read(|repos| repos.outputs(ACCOUNT, None))
        .unwrap();
    let output = outputs
        .iter()
        .find(|output| output.tx == Some(tx_id))
        .unwrap();
    assert_eq!(output.status, OutputStatus::Unconfirmed);

    mine(&receiver.node, &payment, TIP + 5);
    receiver.refresh_at(TIP + 5);
    assert_eq!(received(&receiver).1, TxState::Confirmed);
    let details = receiver
        .block_on(receiver.wallet.transaction_details(tx_id))
        .unwrap();
    assert_eq!(details.chain_replaced, None);
}

/// The receiver's one transaction: its id and state.
fn received(receiver: &Receiver) -> (TxId, TxState) {
    let transactions = receiver
        .store()
        .read(|repos| repos.transactions(ACCOUNT))
        .unwrap();
    assert_eq!(transactions.len(), 1);
    (transactions[0].id, transactions[0].entry.state)
}

// RO-05: a confirmed send whose block another branch replaced is posted again, pushed again,
// and confirms once mined again.
both_stores!(a_confirmed_send_whose_block_was_replaced_is_pushed_again_and_confirms);
fn a_confirmed_send_whose_block_was_replaced_is_pushed_again_and_confirms() {
    let retrying = Retrying::posted();
    let payment = retrying.final_transaction();
    mine(retrying.node(), &payment, TIP + 1);
    retrying.at(TIP + 1);
    assert_eq!(retrying.state(), TxState::Confirmed);

    unmine(retrying.node(), &payment, TIP + 3);
    retrying.at(TIP + 3);

    assert_eq!(retrying.state(), TxState::Posted);
    assert_eq!(
        retrying.details().chain_replaced,
        Some(ChainReplaced::Reopened)
    );
    let pushes = retrying.pushes();
    let pushed_at = retrying.walk(TIP + 4..=TIP + 20);
    assert!(!pushed_at.is_empty(), "the send is not pushed again");
    assert!(retrying.pushes() > pushes);

    mine(retrying.node(), &payment, TIP + 21);
    retrying.at(TIP + 21);
    assert_eq!(retrying.state(), TxState::Confirmed);
    assert_eq!(retrying.details().chain_replaced, None);
}
