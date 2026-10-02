//! Output selection and fee estimation for a send, with the results `epic-wallet` reaches in
//! `libwallet/src/internal/selection.rs`: the same inputs, the same fee and the same change.
//!
//! Selection is pure. It reads the outputs it is given and changes nothing, so an estimate is
//! the same computation as a send and has no side effects. Locking the chosen inputs and
//! deriving keys for the change outputs belong to the caller.

use std::num::NonZeroUsize;

use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::MAX_TX_WEIGHT;
use lepic_store::{AccountIndex, OutputRecord, OutputStatus};
use thiserror::Error;

/// How inputs are chosen from the eligible outputs, sorted by increasing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// As few of the smallest outputs as cover the amount.
    Smallest,
    /// Every eligible output, up to the maximum number of inputs.
    All,
}

/// What a send asks selection for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRequest {
    pub account: AccountIndex,
    /// The amount the receiver gets, without the fee.
    pub amount: Amount,
    /// The chain tip the send is built at.
    pub tip: Height,
    /// Blocks, counting the one that holds the output, an unspent output needs before it is
    /// spent. Zero also admits unconfirmed outputs that are not coinbase.
    pub minimum_confirmations: u64,
    /// A soft limit: it is exceeded when no set within it covers the amount.
    pub max_outputs: NonZeroUsize,
    pub change_outputs: NonZeroUsize,
    pub strategy: SelectionStrategy,
    /// Fee per unit of transaction weight.
    pub base_fee: Fee,
}

/// The inputs, fee and change of a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// In increasing value, the order the transaction adds them in.
    pub inputs: Vec<OutputRecord>,
    /// Values of the change outputs. Empty when the inputs cover amount and fee exactly.
    pub change: Vec<Amount>,
    pub amount: Amount,
    pub fee: Fee,
    /// Sum of the input values.
    pub total: Amount,
}

/// What a send would lock and pay, without choosing change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    /// Sum of the values of the inputs the send would lock.
    pub total: Amount,
    pub fee: Fee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SelectionError {
    /// `available` is the value of the best set selection found, `needed` the amount plus the
    /// fee that set would pay.
    #[error("not enough funds: {available} available, {needed} needed")]
    NotEnoughFunds { available: Amount, needed: Amount },
    #[error("change of {change} cannot be split into {outputs} outputs")]
    ChangeTooSmall { change: Amount, outputs: usize },
    #[error("transaction with {inputs} inputs and {outputs} outputs exceeds the weight limit")]
    TooHeavy { inputs: usize, outputs: usize },
    #[error("selection arithmetic failed")]
    Arithmetic(#[from] ArithmeticError),
}

/// Chooses inputs and splits the change for a send of `request.amount` from `outputs`.
///
/// Outputs of other accounts and outputs not yet spendable at `request.tip` are ignored.
/// Outputs of equal value are taken in the order they are given.
pub fn select(
    outputs: &[OutputRecord],
    request: &SelectionRequest,
) -> Result<Selection, SelectionError> {
    let chosen = select_coins_and_fee(outputs, request)?;
    let change = split_change(&chosen, request)?;
    Ok(Selection {
        inputs: chosen.coins.into_iter().cloned().collect(),
        change,
        amount: request.amount,
        fee: chosen.fee,
        total: chosen.total,
    })
}

/// The total and fee [`select`] would choose, without splitting change.
pub fn estimate(
    outputs: &[OutputRecord],
    request: &SelectionRequest,
) -> Result<Estimate, SelectionError> {
    let chosen = select_coins_and_fee(outputs, request)?;
    Ok(Estimate {
        total: chosen.total,
        fee: chosen.fee,
    })
}

/// Whether `output` may be spent at `tip`, by `epic-wallet`'s `OutputData::eligible_to_spend`.
pub fn eligible_to_spend(output: &OutputRecord, tip: Height, minimum_confirmations: u64) -> bool {
    let is_coinbase = output.id.features == OutputFeatures::Coinbase;
    match output.status {
        OutputStatus::Spent | OutputStatus::Locked => false,
        OutputStatus::Unconfirmed if is_coinbase => false,
        _ if output.lock_height > tip => false,
        OutputStatus::Unspent => confirmations(output, tip) >= minimum_confirmations,
        OutputStatus::Unconfirmed => minimum_confirmations == 0,
    }
}

/// An output at height `n` has one confirmation at tip `n`.
fn confirmations(output: &OutputRecord, tip: Height) -> u64 {
    if output.status == OutputStatus::Unconfirmed {
        return 0;
    }
    tip.value()
        .checked_sub(output.height.value())
        .map_or(0, |blocks| blocks.saturating_add(1))
}

struct Chosen<'a> {
    coins: Vec<&'a OutputRecord>,
    total: Amount,
    fee: Fee,
}

/// `select_coins_and_fee`: try without change first, then with change, widening the selection
/// until the inputs cover the amount and the fee those inputs imply.
fn select_coins_and_fee<'a>(
    outputs: &'a [OutputRecord],
    request: &SelectionRequest,
) -> Result<Chosen<'a>, SelectionError> {
    let mut eligible: Vec<&OutputRecord> = outputs
        .iter()
        .filter(|output| {
            output.account == request.account
                && eligible_to_spend(output, request.tip, request.minimum_confirmations)
        })
        .collect();
    // Stable, so equal values keep the order they were given in.
    eligible.sort_by_key(|output| output.amount);
    let max_outputs = request.max_outputs.get();

    let mut coins = select_coins(&eligible, request.amount, max_outputs, request.strategy)?;
    let mut total = sum(&coins)?;
    let mut fee = tx_fee(coins.len(), 1, request.base_fee)?;
    let mut needed = request.amount.checked_add(fee.to_amount())?;
    let not_enough = |available, needed| SelectionError::NotEnoughFunds { available, needed };

    if total == Amount::ZERO {
        return Err(not_enough(Amount::ZERO, needed));
    }
    // `epic-wallet` compares with the number of eligible outputs here, not with `max_outputs`:
    // only when every eligible output is already selected is there nothing left to add.
    if total < needed && coins.len() == eligible.len() {
        return Err(not_enough(total, needed));
    }
    if total == needed {
        return Ok(Chosen { coins, total, fee });
    }

    let outputs_with_change = request
        .change_outputs
        .get()
        .checked_add(1)
        .ok_or(ArithmeticError::Overflow)?;
    fee = tx_fee(coins.len(), outputs_with_change, request.base_fee)?;
    needed = request.amount.checked_add(fee.to_amount())?;
    // The next selection depends only on how many inputs the last one had, so a selection
    // that has not succeeded after one pass per possible input count never will. Upstream
    // loops forever there; LEPIC reports the shortfall.
    let mut passes_left = eligible.len().saturating_add(1);
    while total < needed {
        if coins.len() == eligible.len() || passes_left == 0 {
            return Err(not_enough(total, needed));
        }
        passes_left = passes_left.saturating_sub(1);
        coins = select_coins(&eligible, needed, max_outputs, request.strategy)?;
        total = sum(&coins)?;
        fee = tx_fee(coins.len(), outputs_with_change, request.base_fee)?;
        needed = request.amount.checked_add(fee.to_amount())?;
    }
    Ok(Chosen { coins, total, fee })
}

/// `select_coins`: within `max_outputs`, the first window of consecutive outputs by value that
/// covers `target`; past it, the smallest outputs that cover `target`; failing both, the
/// largest `max_outputs` outputs, largest first, so the caller can report what is available.
fn select_coins<'a>(
    eligible: &[&'a OutputRecord],
    target: Amount,
    max_outputs: usize,
    strategy: SelectionStrategy,
) -> Result<Vec<&'a OutputRecord>, SelectionError> {
    if eligible.len() > max_outputs {
        if let Some(window) = first_covering_window(eligible, target, max_outputs)? {
            return select_from(window, target, strategy);
        }
        if sum(eligible)? >= target {
            return select_from(eligible, target, SelectionStrategy::Smallest);
        }
    } else if sum(eligible)? >= target {
        return select_from(eligible, target, strategy);
    }
    Ok(eligible.iter().rev().take(max_outputs).copied().collect())
}

/// The first run of `len` consecutive outputs whose values add up to at least `target`.
fn first_covering_window<'a, 'b>(
    eligible: &'b [&'a OutputRecord],
    target: Amount,
    len: usize,
) -> Result<Option<&'b [&'a OutputRecord]>, SelectionError> {
    let mut window_total = Amount::ZERO;
    for (end, output) in eligible.iter().enumerate() {
        window_total = window_total.checked_add(output.amount)?;
        let Some(start) = end.checked_add(1).and_then(|count| count.checked_sub(len)) else {
            continue;
        };
        if window_total >= target {
            return Ok(eligible.get(start..=end));
        }
        if let Some(leaving) = eligible.get(start) {
            window_total = window_total.checked_sub(leaving.amount)?;
        }
    }
    Ok(None)
}

/// `select_from` for a set known to cover `target`.
fn select_from<'a>(
    outputs: &[&'a OutputRecord],
    target: Amount,
    strategy: SelectionStrategy,
) -> Result<Vec<&'a OutputRecord>, SelectionError> {
    if strategy == SelectionStrategy::All {
        return Ok(outputs.to_vec());
    }
    let mut selected = Vec::new();
    let mut selected_total = Amount::ZERO;
    for output in outputs {
        if selected_total >= target {
            break;
        }
        selected_total = selected_total.checked_add(output.amount)?;
        selected.push(*output);
    }
    Ok(selected)
}

/// `inputs_and_change`: equal parts, the last one also taking the remainder.
fn split_change(
    chosen: &Chosen<'_>,
    request: &SelectionRequest,
) -> Result<Vec<Amount>, SelectionError> {
    let change = chosen
        .total
        .checked_sub(request.amount)?
        .checked_sub(chosen.fee.to_amount())?;
    let count = if change == Amount::ZERO {
        0
    } else {
        request.change_outputs.get()
    };
    let outputs = count.checked_add(1).ok_or(ArithmeticError::Overflow)?;
    let weight = body(chosen.coins.len(), outputs)?.weight_as_block();
    if weight > MAX_TX_WEIGHT {
        return Err(SelectionError::TooHeavy {
            inputs: chosen.coins.len(),
            outputs,
        });
    }
    let Some(parts) = NonZeroUsize::new(count) else {
        return Ok(Vec::new());
    };
    let parts_u64 = u64::try_from(parts.get()).map_err(|_| ArithmeticError::Overflow)?;
    let too_small = SelectionError::ChangeTooSmall {
        change,
        outputs: parts.get(),
    };
    let part = change
        .value()
        .checked_div(parts_u64)
        .filter(|part| *part > 0)
        .ok_or(too_small)?;
    // Upstream takes the remainder modulo the part, which equals the true remainder whenever
    // its change adds up. LEPIC always uses the true remainder.
    let remainder = change.value().checked_rem(parts_u64).ok_or(too_small)?;
    let mut amounts = vec![Amount::new(part); parts.get()];
    if let Some(last) = amounts.last_mut() {
        *last = last.checked_add(Amount::new(remainder))?;
    }
    Ok(amounts)
}

fn tx_fee(inputs: usize, outputs: usize, base_fee: Fee) -> Result<Fee, SelectionError> {
    Ok(body(inputs, outputs)?.tx_fee(base_fee)?)
}

/// The send's body: the inputs, `outputs` including the receiver's, and one kernel.
fn body(inputs: usize, outputs: usize) -> Result<BodyCounts, SelectionError> {
    let count = |n: usize| u64::try_from(n).map_err(|_| ArithmeticError::Overflow);
    Ok(BodyCounts::new(count(inputs)?, count(outputs)?, 1))
}

fn sum(outputs: &[&OutputRecord]) -> Result<Amount, SelectionError> {
    outputs
        .iter()
        .try_fold(Amount::ZERO, |total, output| {
            total.checked_add(output.amount)
        })
        .map_err(SelectionError::from)
}
