// SPDX-License-Identifier: Apache-2.0
//! The transaction state machine. `docs/compat/states.md` maps these states to the transaction log
//! types and confirmation flag `epic-wallet` stores.
//!
//! ```text
//! Sent ─────┬─> Finalized ─> Posted ─┬─> Confirmed
//! Received ─┘      │                 └─> Cancelled, Expired
//!   │              └─> Confirmed, Cancelled, Expired
//!   └─> Confirmed, Cancelled, Expired
//! ```
//!
//! A transaction that ended unconfirmed while its kernel could still be mined (a released send,
//! a cancel or expiry after the peer could complete it) leaves `cancelled` or `expired` for
//! `confirmed` when the chain mines it after all (`confirm_released`); outside that step the
//! final states are final.
//!
//! Moving a transaction to the state it is already in succeeds without a change, so a repeated
//! step (a slate delivered twice, a second post) is harmless.
//!
//! The table ignores direction: it allows every step either side could take. Which side may take
//! a step, for example that only an invoice issuer finalizes an incoming transaction, is checked
//! by the stage that takes it.

use jiff::Timestamp;
use lepic_store::{Repositories, TxId, TxState};
use thiserror::Error;

use crate::error::WalletError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("transaction cannot move from {} to {}", state_name(*from), state_name(*to))]
pub struct InvalidTransition {
    pub from: TxState,
    pub to: TxState,
}

/// A state change that was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateChange {
    pub tx_id: TxId,
    pub from: TxState,
    pub to: TxState,
}

/// The lowercase name used in logs and errors.
pub const fn state_name(state: TxState) -> &'static str {
    match state {
        TxState::Sent => "sent",
        TxState::Received => "received",
        TxState::Finalized => "finalized",
        TxState::Posted => "posted",
        TxState::Confirmed => "confirmed",
        TxState::Cancelled => "cancelled",
        TxState::Expired => "expired",
    }
}

/// A state no transition leaves.
pub const fn is_final(state: TxState) -> bool {
    matches!(
        state,
        TxState::Confirmed | TxState::Cancelled | TxState::Expired
    )
}

/// Whether a transaction may move from `from` to `to` in one step. Every state may "move" to
/// itself.
pub const fn is_allowed(from: TxState, to: TxState) -> bool {
    use TxState::{Cancelled, Confirmed, Expired, Finalized, Posted, Received, Sent};
    match (from, to) {
        (Sent, Sent)
        | (Received, Received)
        | (Finalized, Finalized)
        | (Posted, Posted)
        | (Confirmed, Confirmed)
        | (Cancelled, Cancelled)
        | (Expired, Expired) => true,
        (Sent | Received, Finalized | Confirmed | Cancelled | Expired)
        // A finalized or posted transaction may still be mined after its TTL. Only an invoice
        // issuer's, which it no longer posts from its cutoff, expires, and its kernel stays
        // watched.
        | (Finalized, Posted | Confirmed | Cancelled | Expired)
        | (Posted, Confirmed | Cancelled | Expired) => true,
        _ => false,
    }
}

/// Checks a transition without storing anything. `Ok(None)` when `to` is the current state.
pub fn check_transition(
    tx_id: TxId,
    from: TxState,
    to: TxState,
) -> Result<Option<StateChange>, InvalidTransition> {
    if !is_allowed(from, to) {
        return Err(InvalidTransition { from, to });
    }
    Ok((from != to).then_some(StateChange { tx_id, from, to }))
}

/// Moves the stored transaction to `to` and stamps it with `at`. Run it inside the store
/// transaction that stores the effect causing the change, so the two persist together.
/// Returns `Ok(None)`, and writes nothing, when the transaction is already in `to`.
pub fn apply_transition(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    to: TxState,
    at: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let mut entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let Some(change) = check_transition(tx_id, entry.state, to)? else {
        return Ok(None);
    };
    entry.state = to;
    entry.updated_at = at;
    repos.update_transaction(tx_id, &entry)?;
    Ok(Some(change))
}

/// Moves a watched transaction the chain mined after all from `cancelled` or `expired` to
/// `confirmed`, the one step out of a final state (`docs/compat/states.md`): the chain is the
/// authority, and a kernel on chain means the transaction happened. Only a refresh that found
/// the kernel of a transaction it watches takes this step; every other cancelled or expired
/// transaction stays final. Returns `Ok(None)` when it is already confirmed.
pub(crate) fn confirm_released(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    at: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let mut entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    match entry.state {
        TxState::Confirmed => return Ok(None),
        TxState::Cancelled | TxState::Expired => {}
        from => {
            return Err(InvalidTransition {
                from,
                to: TxState::Confirmed,
            }
            .into());
        }
    }
    let change = StateChange {
        tx_id,
        from: entry.state,
        to: TxState::Confirmed,
    };
    entry.state = TxState::Confirmed;
    entry.updated_at = at;
    repos.update_transaction(tx_id, &entry)?;
    Ok(Some(change))
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Amount;
    use lepic_store::{
        AccountIndex, AccountRecord, CONTEXT_KEY_LEN, MemoryStore, StoreKeys, TransactionEntry,
        TxDirection, WalletStore,
    };

    use super::*;

    fn at() -> Timestamp {
        Timestamp::from_second(1_790_000_000).unwrap()
    }

    fn store_with(state: TxState) -> (MemoryStore, TxId) {
        let store = MemoryStore::new(StoreKeys::from_bytes(
            [2; CONTEXT_KEY_LEN],
            [2; CONTEXT_KEY_LEN],
        ));
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
                    created_at: at(),
                    updated_at: at(),
                })
            })
            .unwrap();
        (store, tx_id)
    }

    #[test]
    fn confirms_a_cancelled_or_expired_transaction_once() {
        for state in [TxState::Cancelled, TxState::Expired] {
            let (store, tx_id) = store_with(state);

            let first = store.write(|repos| confirm_released(repos, tx_id, at()));
            let second = store.write(|repos| confirm_released(repos, tx_id, at()));

            assert_eq!(
                first.unwrap(),
                Some(StateChange {
                    tx_id,
                    from: state,
                    to: TxState::Confirmed,
                })
            );
            assert_eq!(second.unwrap(), None);
        }
    }

    #[test]
    fn confirms_no_other_state_out_of_turn() {
        for state in [TxState::Received, TxState::Sent, TxState::Posted] {
            let (store, tx_id) = store_with(state);

            let result = store.write(|repos| confirm_released(repos, tx_id, at()));

            assert!(
                matches!(
                    result,
                    Err(WalletError::Transition(InvalidTransition { from, .. })) if from == state
                ),
                "{state:?}: {result:?}"
            );
        }
    }
}
