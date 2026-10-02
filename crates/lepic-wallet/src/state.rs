//! The transaction state machine. `docs/compat/states.md` maps these states to the transaction log
//! types and confirmation flag `epic-wallet` stores.
//!
//! ```text
//! Sent ─────┬─> Finalized ─> Posted ─┬─> Confirmed
//! Received ─┘      │                 └─> Cancelled
//!   │              └─> Confirmed, Cancelled, Expired
//!   └─> Confirmed, Cancelled, Expired
//! ```
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
        | (Finalized, Posted | Confirmed | Cancelled | Expired)
        // A posted transaction may still be mined after its TTL, so only the owner's explicit
        // cancel ends it before confirmation.
        | (Posted, Confirmed | Cancelled) => true,
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
