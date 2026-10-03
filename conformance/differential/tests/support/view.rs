//! What each wallet reports at a checkpoint, in upstream's terms, and how two reports are
//! compared. LEPIC states are mapped to upstream's through `docs/compat/states.md`.

use lepic_store::{OutputStatus, TxDirection, TxState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceView {
    pub total: u64,
    pub spendable: u64,
    pub awaiting_confirmation: u64,
    pub awaiting_finalization: u64,
    pub immature: u64,
    pub locked: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputView {
    pub commit: String,
    pub value: u64,
    pub status: &'static str,
}

/// One transaction log entry. Fields a wallet does not record are `None` and not compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxView {
    /// The upstream `(tx_type, confirmed)` pairs this entry corresponds to: exactly one for an
    /// upstream wallet, every pair `states.md` maps the LEPIC state to for a LEPIC wallet.
    pub upstream_states: Vec<(String, bool)>,
    pub amount_credited: u64,
    pub amount_debited: u64,
    pub fee: Option<u64>,
    pub ttl_cutoff_height: Option<Option<u64>>,
    pub stored_tx: Option<bool>,
    pub messages: Option<Vec<String>>,
    /// Differs between runs, since blinding factors are random; used within a run only.
    pub kernel_excess: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyView {
    pub balance: BalanceView,
    /// Commitments match between runs because both wallets derive the same keys.
    pub outputs: Vec<OutputView>,
    pub tx: Option<TxView>,
}

/// The upstream states of a LEPIC transaction, from the transaction state table of
/// `docs/compat/states.md`.
pub fn upstream_states(direction: TxDirection, state: TxState) -> Vec<(String, bool)> {
    let pairs: &[(&str, bool)] = match (direction, state) {
        (TxDirection::Outgoing, TxState::Sent | TxState::Finalized) => &[("TxSentCreated", false)],
        (TxDirection::Outgoing, TxState::Posted) => {
            &[("TxSentCreated", false), ("TxSentMempool", false)]
        }
        (TxDirection::Outgoing, TxState::Confirmed) => &[("TxSent", true)],
        (TxDirection::Outgoing, TxState::Cancelled | TxState::Expired) => {
            &[("TxSentCancelled", false)]
        }
        (TxDirection::Incoming, TxState::Received | TxState::Finalized) => &[("TxReceived", false)],
        (TxDirection::Incoming, TxState::Posted) => {
            &[("TxReceived", false), ("TxReceivedMempool", false)]
        }
        (TxDirection::Incoming, TxState::Confirmed) => &[
            ("TxReceived", true),
            ("TxReceivedMempool", true),
            ("ConfirmedCoinbase", true),
        ],
        (TxDirection::Incoming, TxState::Cancelled | TxState::Expired) => {
            &[("TxReceivedCancelled", false)]
        }
        // The store has no other directions or states; a new one must be added to states.md
        // and here before it can be compared.
        _ => &[],
    };
    pairs.iter().map(|(t, c)| ((*t).to_owned(), *c)).collect()
}

/// The upstream output status of a LEPIC output, from the output state table of `states.md`.
pub fn upstream_output_status(status: OutputStatus) -> &'static str {
    match status {
        OutputStatus::Unconfirmed => "Unconfirmed",
        OutputStatus::Unspent => "Unspent",
        OutputStatus::Locked => "Locked",
        OutputStatus::Spent => "Spent",
    }
}

/// Every difference between a wallet's view in the LEPIC run and the same wallet's view in the
/// reference run.
pub fn differences(observed: &PartyView, reference: &PartyView) -> Vec<String> {
    let mut found = Vec::new();
    if observed.balance != reference.balance {
        found.push(format!(
            "balance {:?}, reference {:?}",
            observed.balance, reference.balance
        ));
    }
    if observed.outputs != reference.outputs {
        found.push(format!(
            "outputs {:?}, reference {:?}",
            observed.outputs, reference.outputs
        ));
    }
    match (&observed.tx, &reference.tx) {
        (None, None) => {}
        (Some(observed), Some(reference)) => tx_differences(observed, reference, &mut found),
        (observed, reference) => {
            found.push(format!("transaction {observed:?}, reference {reference:?}"));
        }
    }
    found
}

fn tx_differences(observed: &TxView, reference: &TxView, found: &mut Vec<String>) {
    let shared = reference
        .upstream_states
        .iter()
        .any(|state| observed.upstream_states.contains(state));
    if !shared {
        found.push(format!(
            "state {:?}, reference {:?}",
            observed.upstream_states, reference.upstream_states
        ));
    }
    let amounts = (
        observed.amount_credited,
        observed.amount_debited,
        observed.fee,
    );
    let reference_amounts = (
        reference.amount_credited,
        reference.amount_debited,
        reference.fee,
    );
    if amounts != reference_amounts {
        found.push(format!(
            "credited, debited and fee {amounts:?}, reference {reference_amounts:?}"
        ));
    }
    compare_known(
        "ttl cutoff",
        &observed.ttl_cutoff_height,
        &reference.ttl_cutoff_height,
        found,
    );
    compare_known(
        "stored transaction",
        &observed.stored_tx,
        &reference.stored_tx,
        found,
    );
    compare_known("messages", &observed.messages, &reference.messages, found);
}

fn compare_known<T: PartialEq + std::fmt::Debug>(
    what: &str,
    observed: &Option<T>,
    reference: &Option<T>,
    found: &mut Vec<String>,
) {
    if let (Some(observed), Some(reference)) = (observed, reference)
        && observed != reference
    {
        found.push(format!("{what} {observed:?}, reference {reference:?}"));
    }
}
