// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use jiff::Timestamp;
use lepic_primitives::amount::Amount;
use lepic_store::{
    AccountIndex, AccountRecord, CONTEXT_KEY_LEN, ContextKey, MemoryStore, TransactionEntry,
    TxDirection, TxId, TxState, WalletStore,
};
use lepic_wallet::state::{
    InvalidTransition, StateChange, apply_transition, check_transition, is_allowed, is_final,
};
use lepic_wallet::{Event, WalletError};

use TxState::{Cancelled, Confirmed, Expired, Finalized, Posted, Received, Sent};

const ALL: [TxState; 7] = [
    Sent, Received, Finalized, Posted, Confirmed, Cancelled, Expired,
];

/// The transitions `docs/compat/states.md` documents, besides staying in the same state.
const ALLOWED: [(TxState, TxState); 13] = [
    (Sent, Finalized),
    (Sent, Confirmed),
    (Sent, Cancelled),
    (Sent, Expired),
    (Received, Finalized),
    (Received, Confirmed),
    (Received, Cancelled),
    (Received, Expired),
    (Finalized, Posted),
    (Finalized, Confirmed),
    (Finalized, Cancelled),
    (Posted, Confirmed),
    (Posted, Cancelled),
];

fn created_at() -> Timestamp {
    Timestamp::from_second(1_790_000_000).unwrap()
}

fn changed_at() -> Timestamp {
    Timestamp::from_second(1_790_000_600).unwrap()
}

fn store_with(state: TxState) -> (MemoryStore, TxId) {
    let store = MemoryStore::new(ContextKey::from_bytes([3; CONTEXT_KEY_LEN]));
    let tx_id = store
        .write(|repos| {
            repos.put_account(&AccountRecord {
                index: AccountIndex(0),
                label: "default".to_owned(),
                next_child: 0,
            })?;
            repos.insert_transaction(&TransactionEntry {
                account: AccountIndex(0),
                direction: TxDirection::Outgoing,
                state,
                slate_id: None,
                transport: None,
                amount_credited: Amount::ZERO,
                amount_debited: Amount::ZERO,
                fee: None,
                created_at: created_at(),
                updated_at: created_at(),
            })
        })
        .unwrap();
    (store, tx_id)
}

fn stored(store: &MemoryStore, tx_id: TxId) -> TransactionEntry {
    store
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .unwrap()
}

#[test]
fn allowed_transitions_are_exactly_the_documented_ones() {
    for from in ALL {
        for to in ALL {
            let expected = from == to || ALLOWED.contains(&(from, to));
            assert_eq!(is_allowed(from, to), expected, "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn every_allowed_transition_is_persisted_with_its_time() {
    for (from, to) in ALLOWED {
        let (store, tx_id) = store_with(from);

        let change = store
            .write(|repos| apply_transition(repos, tx_id, to, changed_at()))
            .unwrap();

        assert_eq!(
            change,
            Some(StateChange { tx_id, from, to }),
            "{from:?} -> {to:?}"
        );
        let entry = stored(&store, tx_id);
        assert_eq!(entry.state, to);
        assert_eq!(entry.updated_at, changed_at());
        assert_eq!(entry.created_at, created_at());
    }
}

#[test]
fn every_other_transition_is_a_typed_error_and_changes_nothing() {
    for from in ALL {
        for to in ALL {
            if from == to || ALLOWED.contains(&(from, to)) {
                continue;
            }
            let (store, tx_id) = store_with(from);

            let result = store.write(|repos| apply_transition(repos, tx_id, to, changed_at()));

            assert!(
                matches!(
                    result,
                    Err(WalletError::Transition(InvalidTransition { from: f, to: t }))
                        if f == from && t == to
                ),
                "{from:?} -> {to:?}"
            );
            assert_eq!(stored(&store, tx_id).state, from);
            assert_eq!(stored(&store, tx_id).updated_at, created_at());
        }
    }
}

#[test]
fn repeating_a_transition_succeeds_without_a_change() {
    for (from, to) in ALLOWED {
        let (store, tx_id) = store_with(from);
        store
            .write(|repos| apply_transition(repos, tx_id, to, changed_at()))
            .unwrap();

        let later = Timestamp::from_second(1_790_001_200).unwrap();
        let repeated = store
            .write(|repos| apply_transition(repos, tx_id, to, later))
            .unwrap();

        assert_eq!(repeated, None, "{from:?} -> {to:?}");
        assert_eq!(stored(&store, tx_id).updated_at, changed_at());
    }
}

#[test]
fn final_states_are_left_by_no_transition() {
    for from in ALL {
        let leaves = ALL.iter().any(|&to| to != from && is_allowed(from, to));
        assert_eq!(is_final(from), !leaves, "{from:?}");
    }
    assert!(is_final(Confirmed) && is_final(Cancelled) && is_final(Expired));
}

#[test]
fn transition_of_an_unknown_transaction_is_a_typed_error() {
    let (store, _) = store_with(Sent);
    let result = store.write(|repos| apply_transition(repos, TxId(99), Finalized, changed_at()));
    assert!(matches!(
        result,
        Err(WalletError::UnknownTransaction(TxId(99)))
    ));
}

#[test]
fn a_transition_rolled_back_with_its_store_transaction_is_not_stored() {
    let (store, tx_id) = store_with(Finalized);

    let result: Result<(), WalletError> = store.write(|repos| {
        apply_transition(repos, tx_id, Posted, changed_at())?;
        Err(WalletError::Locked)
    });

    assert!(matches!(result, Err(WalletError::Locked)));
    assert_eq!(stored(&store, tx_id).state, Finalized);
}

#[test]
fn a_stored_change_becomes_a_transaction_event() {
    let change = check_transition(TxId(4), Posted, Confirmed)
        .unwrap()
        .unwrap();
    let Event::Transaction(event) = Event::from(change) else {
        panic!("not a transaction event");
    };
    assert_eq!(
        (event.tx_id, event.from, event.to),
        (TxId(4), Posted, Confirmed)
    );
}

#[test]
fn invalid_transition_names_both_states() {
    let error = check_transition(TxId(1), Confirmed, Sent).unwrap_err();
    assert_eq!(
        error.to_string(),
        "transaction cannot move from confirmed to sent"
    );
}
