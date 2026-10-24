//! The read API a host shows history, balances and send previews from: the transaction list
//! with its details, the balance without the node, and fee estimates that equal the fee of the
//! send that follows them.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;

use lepic_crypto::RangeProof;
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_store::WalletStore;
use lepic_store::{AccountIndex, OutputRecord, OutputStatus, TxState};
use lepic_transport::file::{FILE, FileTransport};
use lepic_transport::transport::{Destination, Location};
use lepic_wallet::chain::TIP_STEP_BLOCKS;
use lepic_wallet::event::Event;
use lepic_wallet::refresh::{BalanceCategory, RefreshOutcome};
use lepic_wallet::selection::{Selection, SelectionError, SelectionOptions, SelectionStrategy};
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use lepic_wallet::{AccountError, WalletError};
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP, output};
use support::{LOOPBACK, fixed_time};

const AMOUNT: u64 = 100_000_000;
const TTL_BLOCKS: u64 = 5;
const STRATEGIES: [SelectionStrategy; 2] = [SelectionStrategy::Smallest, SelectionStrategy::All];

fn options(strategy: SelectionStrategy) -> SelectionOptions {
    SelectionOptions {
        minimum_confirmations: 1,
        strategy,
        ..SelectionOptions::new(ACCOUNT)
    }
}

fn request(amount: Amount, strategy: SelectionStrategy) -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy,
        ..SendRequest::new(ACCOUNT, amount)
    }
}

fn to_peer() -> Delivery {
    Delivery::Deliver {
        transport: LOOPBACK,
        to: Destination::new(PEER.to_owned()),
    }
}

/// The sender with a second, larger coinbase output, so the strategies choose differently.
fn funded_twice() -> Sender {
    let sender = Sender::new();
    sender.fund(1, 2 * FUNDING);
    sender
}

fn commitments(outputs: &[OutputRecord]) -> Vec<[u8; 33]> {
    let mut commitments: Vec<[u8; 33]> =
        outputs.iter().map(|output| *output.commitment()).collect();
    commitments.sort_unstable();
    commitments
}

/// Sends what `estimate` selected and checks the send took the same inputs, change and fee.
fn send_matches(sender: &Sender, estimate: &Selection, strategy: SelectionStrategy) {
    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(request(estimate.amount, strategy), to_peer()),
        )
        .unwrap();
    assert_eq!(sent.fee, estimate.fee, "{strategy:?}");
    let locked: Vec<OutputRecord> = sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .collect();
    assert_eq!(commitments(&locked), commitments(&estimate.inputs));
    let mut change: Vec<Amount> = sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .map(|output| output.amount)
        .collect();
    change.sort_unstable();
    let mut estimated_change = estimate.change.clone();
    estimated_change.sort_unstable();
    assert_eq!(change, estimated_change, "{strategy:?}");
}

#[test]
fn a_fee_estimate_with_change_equals_the_fee_of_the_send_that_follows() {
    let mut fees = Vec::new();
    for strategy in STRATEGIES {
        let sender = funded_twice();
        let estimate = sender
            .harness
            .block_on(
                sender
                    .wallet
                    .estimate_fee(Amount::new(AMOUNT), options(strategy)),
            )
            .unwrap();
        assert_eq!(estimate.amount, Amount::new(AMOUNT));
        assert_eq!(estimate.change.len(), 1, "{strategy:?}");
        send_matches(&sender, &estimate, strategy);
        fees.push((estimate.inputs.len(), estimate.fee));
    }
    // Smallest spends the one output that covers the amount, All spends both.
    assert_eq!(fees[0].0, 1);
    assert_eq!(fees[1].0, 2);
    assert_ne!(fees[0].1, fees[1].1);
}

#[test]
fn a_fee_estimate_without_change_equals_the_fee_of_the_send_that_follows() {
    for strategy in STRATEGIES {
        let sender = funded_twice();
        // Both outputs less the fee of spending them into one output leave no change.
        let fee = 3 * 100_000;
        let amount = Amount::new(3 * FUNDING - fee);
        let estimate = sender
            .harness
            .block_on(sender.wallet.estimate_fee(amount, options(strategy)))
            .unwrap();
        assert!(estimate.change.is_empty(), "{strategy:?}");
        assert_eq!(estimate.fee.value(), fee);
        send_matches(&sender, &estimate, strategy);
        assert_eq!(sender.transactions()[0].entry.amount_credited, Amount::ZERO);
    }
}

#[test]
fn the_largest_send_spends_every_output_and_pays_the_estimated_fee() {
    for strategy in STRATEGIES {
        let sender = funded_twice();
        let max = sender
            .harness
            .block_on(sender.wallet.estimate_max(options(strategy)))
            .unwrap();
        assert_eq!(max.amount, Amount::new(3 * FUNDING - 3 * 100_000));
        assert_eq!(max.inputs.len(), 2);
        assert!(max.change.is_empty());
        let one_more = Amount::new(max.amount.value() + 1);
        let refused = sender
            .harness
            .block_on(sender.wallet.estimate_fee(one_more, options(strategy)));
        assert!(
            matches!(
                refused,
                Err(SendError::Selection(SelectionError::NotEnoughFunds { .. }))
            ),
            "{refused:?}"
        );
        send_matches(&sender, &max, strategy);
    }
}

#[test]
fn an_estimate_locks_derives_and_stores_nothing() {
    let sender = funded_twice();
    let outputs = sender.outputs();
    let next_child = sender.next_child();
    for strategy in STRATEGIES {
        sender
            .harness
            .block_on(
                sender
                    .wallet
                    .estimate_fee(Amount::new(AMOUNT), options(strategy)),
            )
            .unwrap();
        sender
            .harness
            .block_on(sender.wallet.estimate_max(options(strategy)))
            .unwrap();
    }
    assert_eq!(sender.outputs(), outputs);
    assert_eq!(sender.next_child(), next_child);
    assert!(sender.transactions().is_empty());
}

#[test]
fn estimates_fail_as_the_send_would() {
    let sender = Sender::new();
    let too_much = sender.harness.block_on(
        sender
            .wallet
            .estimate_fee(Amount::new(FUNDING), options(SelectionStrategy::All)),
    );
    assert!(
        matches!(
            too_much,
            Err(SendError::Selection(SelectionError::NotEnoughFunds { .. }))
        ),
        "{too_much:?}"
    );
    // The funding output has four confirmations at the tip, fewer than asked for.
    let unconfirmed = SelectionOptions {
        minimum_confirmations: TIP + 1,
        ..options(SelectionStrategy::All)
    };
    let nothing = sender
        .harness
        .block_on(sender.wallet.estimate_max(unconfirmed));
    assert!(
        matches!(
            nothing,
            Err(SendError::Selection(SelectionError::NotEnoughFunds { .. }))
        ),
        "{nothing:?}"
    );
    let unknown = sender.harness.block_on(
        sender
            .wallet
            .estimate_max(SelectionOptions::new(AccountIndex(7))),
    );
    assert!(
        matches!(
            unknown,
            Err(SendError::Wallet(WalletError::Account(
                AccountError::UnknownAccount(AccountIndex(7))
            )))
        ),
        "{unknown:?}"
    );
}

#[test]
fn the_balance_is_read_from_the_store_without_the_node() {
    let sender = Sender::new();
    let calls = sender.harness.node.calls().len();
    let before = sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(sender.harness.node.calls().len(), calls);
    assert_eq!(before.account, ACCOUNT);
    assert_eq!(before.total, Amount::new(FUNDING));

    let funding = sender.outputs().remove(0);
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&funding, 1));
    });
    let mut events = sender.wallet.subscribe();
    let outcome = sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert!(matches!(outcome, RefreshOutcome::Refreshed(_)));
    let refreshed = std::iter::from_fn(|| events.try_recv().ok())
        .find_map(|event| match event {
            Event::Balance(balance) if balance.account == ACCOUNT => Some(balance),
            _ => None,
        })
        .unwrap();

    let calls = sender.harness.node.calls().len();
    assert_eq!(sender.wallet.balance(ACCOUNT).unwrap(), refreshed);
    assert_eq!(sender.harness.node.calls().len(), calls);
    assert!(matches!(
        sender.wallet.balance(AccountIndex(7)),
        Err(WalletError::Account(AccountError::UnknownAccount(
            AccountIndex(7)
        )))
    ));
    sender.wallet.lock();
    assert!(matches!(
        sender.wallet.balance(ACCOUNT),
        Err(WalletError::Locked)
    ));
}

fn on_chain(output: &OutputRecord, height: u64) -> ChainOutput {
    ChainOutput {
        commitment: output.id.commitment,
        features: output.id.features,
        // `get_outputs` answers do not carry proofs, so any proof bytes do.
        proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
        height: Height::new(height),
        mmr_index: height,
        spent: false,
    }
}

#[test]
fn transactions_are_listed_newest_first_with_counterparty_ttl_and_confirmation() {
    let sender = Sender::with_transports(vec![Box::new(FileTransport::new())]);
    sender.fund(1, FUNDING);
    let delivered = sender
        .harness
        .block_on(sender.wallet.send(
            SendRequest {
                ttl_blocks: Some(TTL_BLOCKS),
                ..request(Amount::new(AMOUNT), SelectionStrategy::Smallest)
            },
            to_peer(),
        ))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let exported = sender
        .harness
        .block_on(sender.wallet.send(
            request(Amount::new(AMOUNT), SelectionStrategy::Smallest),
            Delivery::Export {
                transport: FILE,
                to: Location::File(dir.path().join("send.slate")),
            },
        ))
        .unwrap();

    let listed = sender
        .harness
        .block_on(sender.wallet.transactions(ACCOUNT))
        .unwrap();
    let ids: Vec<_> = listed
        .iter()
        .map(|details| details.transaction.id)
        .collect();
    assert_eq!(ids, vec![exported.tx_id, delivered.tx_id]);
    let (file, epicbox) = (&listed[0], &listed[1]);
    assert_eq!(file.counterparty, None);
    assert_eq!(file.ttl_cutoff_height, None);
    assert_eq!(
        epicbox.counterparty,
        Some(Destination::new(PEER.to_owned()))
    );
    assert_eq!(
        epicbox.ttl_cutoff_height,
        Some(Height::new(TIP + TTL_BLOCKS))
    );
    assert_eq!(epicbox.transaction.entry.fee, Some(delivered.fee));
    for details in &listed {
        assert_eq!(details.confirmed_at, None);
        assert_eq!(details.confirmed_height, None);
        let single = sender
            .harness
            .block_on(sender.wallet.transaction_details(details.transaction.id))
            .unwrap();
        assert_eq!(&single, details);
    }

    // Mining the delivered send's change confirms it.
    let change = sender
        .outputs()
        .into_iter()
        .find(|output| {
            output.status == OutputStatus::Unconfirmed && output.tx == Some(delivered.tx_id)
        })
        .unwrap();
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&change, TIP + 1));
        chain.tip.height = Height::new(TIP + 1);
    });
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    let confirmed = sender
        .harness
        .block_on(sender.wallet.transaction_details(delivered.tx_id))
        .unwrap();
    assert_eq!(confirmed.transaction.entry.state, TxState::Confirmed);
    assert_eq!(confirmed.confirmed_at, Some(fixed_time()));
    assert_eq!(confirmed.confirmed_height, Some(Height::new(TIP + 1)));
    assert_eq!(
        confirmed.counterparty,
        Some(Destination::new(PEER.to_owned()))
    );

    let unknown = sender
        .harness
        .block_on(sender.wallet.transactions(AccountIndex(7)));
    assert!(matches!(
        unknown,
        Err(WalletError::Account(AccountError::UnknownAccount(
            AccountIndex(7)
        )))
    ));
}

#[test]
fn a_send_lists_its_change_in_its_details_also_once_another_send_spends_it() {
    let sender = Sender::new();
    let request = request(Amount::new(AMOUNT), SelectionStrategy::Smallest);
    let first = sender
        .harness
        .block_on(sender.wallet.send(request.clone(), to_peer()))
        .unwrap();
    let change = sender
        .outputs()
        .into_iter()
        .find(|output| output.status == OutputStatus::Unconfirmed)
        .unwrap();
    let commits = |tx_id| {
        sender
            .harness
            .block_on(sender.wallet.transaction_details(tx_id))
            .unwrap()
            .output_commits
    };
    assert_eq!(commits(first.tx_id), vec![change.id.commitment]);

    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&change, TIP + 1));
        chain.tip.height = Height::new(TIP + 1);
    });
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    let second = sender
        .harness
        .block_on(sender.wallet.send(request, to_peer()))
        .unwrap();

    let spent = sender
        .outputs()
        .into_iter()
        .find(|output| output.id.commitment == change.id.commitment)
        .unwrap();
    assert_eq!(
        (spent.status, spent.tx),
        (OutputStatus::Locked, Some(second.tx_id))
    );
    assert_eq!(commits(first.tx_id), vec![change.id.commitment]);
    let second_change: Vec<_> = sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .map(|output| output.id.commitment)
        .collect();
    assert_eq!(second_change.len(), 1);
    assert_eq!(commits(second.tx_id), second_change);
}

#[test]
fn a_refresh_whose_tip_is_held_reports_the_balance_that_balance_reads() {
    let sender = Sender::new();
    let funding = sender.outputs().remove(0);
    // Two confirmations at the tip: one short of the three the balance counts as spendable.
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&funding, TIP - 1));
    });
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    let confirmed = sender.wallet.balance(ACCOUNT).unwrap().height;
    assert_eq!(confirmed, Height::new(TIP));

    // Too far ahead to be confirmed by one answer, so the tip is held as pending.
    let ahead = TIP + TIP_STEP_BLOCKS + 1;
    sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(ahead));
    let mut events = sender.wallet.subscribe();
    let outcome = sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert!(matches!(outcome, RefreshOutcome::Refreshed(_)));
    let reported = std::iter::from_fn(|| events.try_recv().ok())
        .find_map(|event| match event {
            Event::Balance(balance) if balance.account == ACCOUNT => Some(balance),
            _ => None,
        })
        .unwrap();

    assert_eq!(reported, sender.wallet.balance(ACCOUNT).unwrap());
    assert_eq!(reported.height, confirmed);
    // At the held tip the funding output would count as spendable; at the confirmed one it
    // still awaits confirmation.
    assert_eq!(reported.spendable, Amount::ZERO);
    assert_eq!(reported.awaiting_confirmation, Amount::new(FUNDING));
}

#[test]
fn an_estimate_leaves_out_what_minimum_confirmations_excludes_as_the_send_does() {
    let sender = Sender::new();
    // A second output mined at the tip has one confirmation, fewer than asked for.
    let mut recent = output(&sender.keychain, 1, 2 * FUNDING, OutputFeatures::Coinbase);
    recent.height = Height::new(TIP);
    sender
        .store
        .write(|repos| repos.put_output(&recent))
        .unwrap();
    let strategy = SelectionStrategy::All;
    let options = SelectionOptions {
        minimum_confirmations: 2,
        ..options(strategy)
    };
    let estimate = sender
        .harness
        .block_on(sender.wallet.estimate_fee(Amount::new(AMOUNT), options))
        .unwrap();
    assert_eq!(values(&estimate.inputs), [FUNDING]);
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            SendRequest {
                minimum_confirmations: 2,
                ..request(Amount::new(AMOUNT), strategy)
            },
            to_peer(),
        ))
        .unwrap();
    assert_eq!(sent.fee, estimate.fee);
    let locked: Vec<OutputRecord> = sender
        .outputs()
        .into_iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .collect();
    assert_eq!(commitments(&locked), commitments(&estimate.inputs));
}

fn values(outputs: &[OutputRecord]) -> Vec<u64> {
    outputs.iter().map(|output| output.amount.value()).collect()
}

#[test]
fn outputs_add_up_to_the_balance_in_each_category() {
    let sender = funded_twice();
    sender
        .harness
        .block_on(sender.wallet.send(
            request(Amount::new(AMOUNT), SelectionStrategy::Smallest),
            to_peer(),
        ))
        .unwrap();

    let outputs = sender.wallet.outputs(ACCOUNT).unwrap();
    let balance = sender.wallet.balance(ACCOUNT).unwrap();

    let sum = |category| {
        outputs
            .iter()
            .filter(|details| details.category == Some(category))
            .map(|details| details.output.amount.value())
            .sum::<u64>()
    };
    assert_eq!(sum(BalanceCategory::Spendable), balance.spendable.value());
    assert_eq!(
        sum(BalanceCategory::AwaitingConfirmation),
        balance.awaiting_confirmation.value()
    );
    assert_eq!(
        sum(BalanceCategory::AwaitingFinalization),
        balance.awaiting_finalization.value()
    );
    assert_eq!(sum(BalanceCategory::Immature), balance.immature.value());
    assert_eq!(sum(BalanceCategory::Locked), balance.locked.value());
    let statuses: Vec<_> = outputs
        .iter()
        .map(|details| details.output.status)
        .collect();
    assert_eq!(statuses.len(), 3, "two funding outputs and the change");
    assert!(statuses.contains(&OutputStatus::Locked));
    assert!(statuses.contains(&OutputStatus::Unconfirmed));
    for details in &outputs {
        if details.output.status == OutputStatus::Unconfirmed {
            assert_eq!(details.confirmations, 0);
        } else {
            assert_eq!(
                details.confirmations,
                (balance.height.value() + 1).saturating_sub(details.output.height.value()),
                "none above the balance height"
            );
        }
    }
    assert!(matches!(
        sender.wallet.outputs(AccountIndex(7)),
        Err(WalletError::Account(AccountError::UnknownAccount(
            AccountIndex(7)
        )))
    ));
}
