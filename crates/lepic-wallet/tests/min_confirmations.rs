//! The wallet's minimum confirmations: the stored setting, its range, and the balance split
//! following it (ADR 0027).

// Tests may unwrap, index and panic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;

use lepic_primitives::amount::Amount;
use lepic_store::WalletStore;
use lepic_wallet::WalletError;
use lepic_wallet::event::Event;
use lepic_wallet::refresh::{
    BalanceCategory, DEFAULT_MINIMUM_CONFIRMATIONS, MINIMUM_CONFIRMATIONS_RANGE,
};
use lepic_wallet::selection::{SelectionError, SelectionOptions};
use lepic_wallet::send::SendError;
use send_support::{ACCOUNT, FUNDING, Sender, TIP};

#[test]
fn a_wallet_that_never_set_it_reads_the_default() {
    let sender = Sender::new();
    assert_eq!(DEFAULT_MINIMUM_CONFIRMATIONS, 6);
    assert_eq!(sender.wallet.minimum_confirmations().unwrap(), 6);
    assert_eq!(
        sender
            .wallet
            .balance(ACCOUNT)
            .unwrap()
            .minimum_confirmations,
        6
    );
}

#[test]
fn the_setting_round_trips_and_is_bounded() {
    let sender = Sender::new();
    for count in [1, 3, 10, 30] {
        sender.wallet.set_minimum_confirmations(count).unwrap();
        assert_eq!(sender.wallet.minimum_confirmations().unwrap(), count);
    }
    assert_eq!(MINIMUM_CONFIRMATIONS_RANGE, 1..=30);
    for count in [0, 31, u64::MAX] {
        assert!(matches!(
            sender.wallet.set_minimum_confirmations(count),
            Err(WalletError::MinimumConfirmationsOutOfRange { count: c }) if c == count
        ));
    }
    assert_eq!(sender.wallet.minimum_confirmations().unwrap(), 30);
    sender.wallet.lock();
    assert!(matches!(
        sender.wallet.minimum_confirmations(),
        Err(WalletError::Locked)
    ));
    assert!(matches!(
        sender.wallet.set_minimum_confirmations(5),
        Err(WalletError::Locked)
    ));
}

#[test]
fn the_balance_split_follows_the_setting_and_a_change_is_announced() {
    // The funding output, mined at height 1, has 4 confirmations at the tip.
    let sender = Sender::new();
    sender
        .store
        .write(|repos| repos.put_setting("refresh.last_confirmed_height", &TIP.to_string()))
        .unwrap();
    let at_default = sender.wallet.balance(ACCOUNT).unwrap();
    assert_eq!(at_default.awaiting_confirmation, Amount::new(FUNDING));
    assert_eq!(at_default.spendable, Amount::ZERO);

    let mut events = sender.wallet.subscribe();
    sender.wallet.set_minimum_confirmations(3).unwrap();
    let announced = std::iter::from_fn(|| events.try_recv().ok())
        .find_map(|event| match event {
            Event::Balance(balance) if balance.account == ACCOUNT => Some(balance),
            _ => None,
        })
        .unwrap();
    assert_eq!(announced.minimum_confirmations, 3);
    assert_eq!(announced.spendable, Amount::new(FUNDING));
    assert_eq!(announced.awaiting_confirmation, Amount::ZERO);
    assert_eq!(sender.wallet.balance(ACCOUNT).unwrap(), announced);

    let outputs = sender.wallet.outputs(ACCOUNT).unwrap();
    assert!(
        outputs
            .iter()
            .all(|output| output.category == Some(BalanceCategory::Spendable))
    );
    sender.wallet.set_minimum_confirmations(6).unwrap();
    let outputs = sender.wallet.outputs(ACCOUNT).unwrap();
    assert!(
        outputs
            .iter()
            .all(|output| output.category == Some(BalanceCategory::AwaitingConfirmation))
    );
}

/// A spend never takes fewer confirmations than the user stored, whatever the caller asks for:
/// the funding output, with 4 confirmations at the tip, pays a send asking for 1 until the
/// setting asks for 5.
#[test]
fn a_spend_takes_at_least_the_stored_setting() {
    let sender = Sender::new();
    let options = SelectionOptions {
        minimum_confirmations: 1,
        ..SelectionOptions::new(ACCOUNT)
    };
    let estimate = |sender: &Sender| {
        sender.harness.block_on(
            sender
                .wallet
                .estimate_fee(Amount::new(100_000_000), options.clone()),
        )
    };
    sender.wallet.set_minimum_confirmations(4).unwrap();
    assert!(estimate(&sender).is_ok());

    sender.wallet.set_minimum_confirmations(5).unwrap();

    assert!(matches!(
        estimate(&sender),
        Err(SendError::Selection(SelectionError::NotEnoughFunds { .. }))
    ));
}
