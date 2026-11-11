// SPDX-License-Identifier: Apache-2.0
//! Payments as the API shows them: built from the wallet's transactions, the invoices that wait
//! for approval, and the notes the API keeps beside them.

use std::collections::BTreeMap;

use lepic_store::{AccountIndex, TxDirection, TxState, WalletStore as _};
use lepic_wallet::details::{TransactionDetails, TxFlow};
use lepic_wallet::legacy_history::TxOrigin;
use lepic_wallet::slate::Role as MoneyRole;
use lepic_wallet_contacts::WalletContacts as _;
use serde::{Deserialize, Serialize};

use super::super::super::Service;
use crate::amount::format_units;
use crate::api::model::{Delivery, Handoff, Payment};
use crate::exit::CliError;
use crate::host::Host;

/// The settings key prefix of a payment's note.
const NOTE: &str = "api.payment.";
/// The settings key prefix of an invoice opened by hand and held for approval (D5).
const HELD: &str = "api.held.";
/// The settings key prefix of an invoice declined before it was paid: the payment as it was.
const DECLINED: &str = "api.declined.";
/// The settings key prefix that maps a caller's invoice id to the slate id the engine drew.
const ALIAS: &str = "api.alias.";

/// What the API keeps about a payment beside the wallet's own records. Never sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in super::super) struct Note {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) purpose: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in super::super) metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) handoff: Option<Handoff>,
}

/// An invoice slate opened by hand, held until approved or declined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in super::super) struct Held {
    /// The I1 as it was handed over.
    pub(in super::super) wire: String,
    pub(in super::super) amount: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) expires_at_height: Option<u64>,
    pub(in super::super) received_at: String,
}

/// Where an invoice that waits for approval came from, and so how it is paid or declined.
#[derive(Debug, Clone)]
pub(in super::super) enum Waiting {
    /// Opened by hand: paid with a reply handed back.
    Held(Held),
    /// Parked on the payments address by an Epicbox sender.
    Parked,
    /// Sent by a paired contact.
    Contact,
}

fn store<H: Host>(service: &Service<'_, H>) -> Result<crate::stores::SharedStore, CliError> {
    service.held.store()
}

fn setting<H: Host>(service: &Service<'_, H>, key: &str) -> Result<Option<String>, CliError> {
    store(service)?.read(|repos| Ok::<_, CliError>(repos.setting(key)?))
}

fn put_setting<H: Host>(service: &Service<'_, H>, key: &str, value: &str) -> Result<(), CliError> {
    store(service)?.write(|repos| Ok::<_, CliError>(repos.put_setting(key, value)?))
}

fn delete_setting<H: Host>(service: &Service<'_, H>, key: &str) -> Result<(), CliError> {
    store(service)?.write(|repos| Ok::<_, CliError>(repos.delete_setting(key)?))
}

/// The note of payment `id`; empty when it has none, or when it cannot be read.
pub(in super::super) fn note<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Note, CliError> {
    Ok(setting(service, &format!("{NOTE}{id}"))?
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default())
}

pub(in super::super) fn put_note<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    note: &Note,
) -> Result<(), CliError> {
    let text = serde_json::to_string(note)
        .map_err(|error| CliError::io("a payment note")(error.into()))?;
    put_setting(service, &format!("{NOTE}{id}"), &text)
}

pub(in super::super) fn put_held<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    held: &Held,
) -> Result<(), CliError> {
    let text = serde_json::to_string(held)
        .map_err(|error| CliError::io("a payment note")(error.into()))?;
    put_setting(service, &format!("{HELD}{id}"), &text)
}

pub(in super::super) fn delete_held<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<(), CliError> {
    delete_setting(service, &format!("{HELD}{id}"))
}

fn all_held<H: Host>(service: &Service<'_, H>) -> Result<Vec<(String, Held)>, CliError> {
    let rows =
        store(service)?.read(|repos| Ok::<_, CliError>(repos.settings_with_prefix(HELD)?))?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, text)| {
            let id = key.strip_prefix(HELD)?.to_owned();
            serde_json::from_str(&text).ok().map(|held| (id, held))
        })
        .collect())
}

/// Keeps `payment`, declined before it was paid, so it can still be read.
pub(in super::super) fn put_declined<H: Host>(
    service: &Service<'_, H>,
    payment: &Payment,
) -> Result<(), CliError> {
    let text = serde_json::to_string(payment)
        .map_err(|error| CliError::io("a payment note")(error.into()))?;
    put_setting(service, &format!("{DECLINED}{}", payment.id), &text)
}

fn all_declined<H: Host>(service: &Service<'_, H>) -> Result<Vec<Payment>, CliError> {
    let rows =
        store(service)?.read(|repos| Ok::<_, CliError>(repos.settings_with_prefix(DECLINED)?))?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, text)| serde_json::from_str(&text).ok())
        .collect())
}

/// Records that the caller's id `alias` stands for the slate `id`.
pub(in super::super) fn put_alias<H: Host>(
    service: &Service<'_, H>,
    alias: &str,
    id: &str,
) -> Result<(), CliError> {
    put_setting(service, &format!("{ALIAS}{alias}"), id)
}

/// The slate id a caller's id stands for: itself when a payment, a declined invoice or a
/// waiting invoice has that id (a real slate id wins over an alias), else the alias if one is
/// stored, else itself.
pub(in super::super) fn resolve<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    known: impl Fn(&str) -> bool,
) -> Result<String, CliError> {
    let id = id.to_ascii_lowercase();
    if known(&id) {
        return Ok(id);
    }
    Ok(setting(service, &format!("{ALIAS}{id}"))?.unwrap_or(id))
}

/// The id of the payment a transaction belongs to: its slate id, or for a transaction without
/// one (found by a scan, a coinbase) an id made from its number.
pub(in super::super) fn payment_id(details: &TransactionDetails) -> String {
    match details.transaction.entry.slate_id {
        Some(slate) => slate.to_string(),
        None => format!("00000000-0000-0000-0000-{:012x}", details.transaction.id.0),
    }
}

fn is_self(details: &TransactionDetails) -> bool {
    details.transaction.entry.transport.as_deref() == Some("self")
}

/// The other half of a send to self: the incoming entry, which the payment of the outgoing
/// one stands for.
fn is_self_half(details: &TransactionDetails) -> bool {
    is_self(details) && details.transaction.entry.direction == TxDirection::Incoming
}

/// The wallet's transactions and accounts, read once for one answer.
pub(in super::super) struct Book {
    labels: Vec<(AccountIndex, String)>,
    tip: Option<u64>,
    /// Every account's transactions, newest first.
    pub(in super::super) transactions: Vec<TransactionDetails>,
}

impl Book {
    pub(in super::super) async fn load<H: Host>(
        service: &Service<'_, H>,
    ) -> Result<Self, CliError> {
        let wallet = &service.held.wallet;
        let mut labels = Vec::new();
        let mut transactions = Vec::new();
        for account in wallet.accounts()? {
            transactions.extend(wallet.transactions(account.index).await?);
            labels.push((account.index, account.label));
        }
        transactions.sort_by(|a, b| {
            b.transaction
                .entry
                .created_at
                .cmp(&a.transaction.entry.created_at)
                .then(b.transaction.id.0.cmp(&a.transaction.id.0))
        });
        let tip = wallet
            .last_confirmed_height()?
            .map(lepic_primitives::amount::Height::value);
        Ok(Self {
            labels,
            tip,
            transactions,
        })
    }

    pub(in super::super) fn label(&self, index: AccountIndex) -> String {
        self.labels
            .iter()
            .find(|(each, _)| *each == index)
            .map_or_else(|| index.to_string(), |(_, label)| label.clone())
    }

    /// The transaction payment `id` stands for: the outgoing entry first, so a send to self
    /// is its sending half.
    pub(in super::super) fn find(&self, id: &str) -> Option<&TransactionDetails> {
        let matching = |details: &&TransactionDetails| payment_id(details) == id;
        self.transactions
            .iter()
            .filter(matching)
            .find(|details| details.transaction.entry.direction == TxDirection::Outgoing)
            .or_else(|| self.transactions.iter().find(matching))
    }

    /// The transactions that are payments of their own: all but the receiving half of each
    /// send to self.
    pub(in super::super) fn payments(&self) -> impl Iterator<Item = &TransactionDetails> {
        self.transactions
            .iter()
            .filter(|details| !is_self_half(details))
    }

    /// The payment of `details`, with its note and contact.
    pub(in super::super) async fn payment<H: Host>(
        &self,
        service: &Service<'_, H>,
        details: &TransactionDetails,
    ) -> Result<Payment, CliError> {
        let mut payment = self.base(details);
        let contact =
            crate::commands::contact::contact_of(&service.held, details.transaction.id).await?;
        if let Some(contact) = contact {
            payment.via = "contact".to_owned();
            payment.counterparty_mut().contact_id = Some(contact.to_string());
        }
        let note = note(service, &payment.id)?;
        payment.purpose = note.purpose;
        payment.metadata = note.metadata;
        Ok(payment)
    }

    /// The payment of `details` as the wallet's records alone show it.
    #[allow(clippy::too_many_lines)] // One field per Payment property.
    fn base(&self, details: &TransactionDetails) -> Payment {
        let entry = &details.transaction.entry;
        let outgoing = entry.direction == TxDirection::Outgoing;
        let self_send = is_self(details);
        let id = payment_id(details);
        let (state, state_reason) = state(details);
        let ended = matches!(state, "cancelled" | "declined" | "expired");
        let amount = if outgoing {
            crate::commands::amount_sent(details).unwrap_or(0)
        } else {
            entry
                .amount_credited
                .value()
                .saturating_sub(entry.amount_debited.value())
        };
        let fee = (outgoing || self_send)
            .then_some(entry.fee.map(lepic_primitives::amount::Fee::value))
            .flatten();
        let balance_change = if ended {
            format_units(0)
        } else if self_send {
            signed(fee.unwrap_or(0), true)
        } else if outgoing {
            signed(
                entry
                    .amount_debited
                    .value()
                    .saturating_sub(entry.amount_credited.value()),
                true,
            )
        } else {
            signed(amount, false)
        };
        let to_account = self_send
            .then(|| {
                self.transactions
                    .iter()
                    .find(|other| is_self_half(other) && payment_id(other) == id)
                    .map(|other| self.label(other.transaction.entry.account))
            })
            .flatten();
        // The sender of the money writes as the sender, whoever started the slate.
        let ours = if outgoing {
            MoneyRole::Sender
        } else {
            MoneyRole::Receiver
        };
        let message = details
            .messages
            .iter()
            .find(|each| each.role == ours)
            .map(|each| each.text.clone());
        let their_message = details
            .messages
            .iter()
            .find(|each| each.role != ours)
            .map(|each| each.text.clone());
        let mut payment = Payment {
            id,
            kind: kind(details).to_owned(),
            direction: if self_send {
                "self"
            } else if outgoing {
                "out"
            } else {
                "in"
            }
            .to_owned(),
            state: state.to_owned(),
            state_reason: state_reason.map(str::to_owned),
            account: self.label(entry.account),
            to_account,
            amount: format_units(amount),
            fee: fee.map(format_units),
            balance_change,
            via: via(details).to_owned(),
            counterparty: None,
            our_address: None,
            link_id: None,
            purpose: None,
            message,
            their_message,
            delivery: delivery(details),
            answers: Vec::new(),
            check_code: None,
            their_notices: None,
            actions: actions(details, state),
            cancellable_from_height: matches!(state, "finalized" | "posted")
                .then_some(
                    details
                        .releasable_from
                        .map(lepic_primitives::amount::Height::value),
                )
                .flatten(),
            expires_at_height: details
                .ttl_cutoff_height
                .map(lepic_primitives::amount::Height::value),
            confirmations: None,
            confirmed_height: details
                .confirmed_height
                .map(lepic_primitives::amount::Height::value),
            kernel_excess: details
                .kernel_excess
                .as_ref()
                .map(lepic_wallet::selection::Commitment::to_hex),
            source: match details.origin {
                TxOrigin::Imported => "imported",
                TxOrigin::FoundByScan => "scan",
                TxOrigin::Wallet | TxOrigin::OtherWallet => "wallet",
            }
            .to_owned(),
            metadata: BTreeMap::new(),
            created_at: entry.created_at.to_string(),
            updated_at: entry.updated_at.to_string(),
            handoff: None,
        };
        if let (Some(tip), Some(confirmed)) = (self.tip, payment.confirmed_height) {
            payment.confirmations = Some(tip.saturating_sub(confirmed).saturating_add(1));
        }
        if let Some(address) = &details.counterparty {
            payment.counterparty_mut().address = Some(address.as_str().to_owned());
        }
        if !outgoing && !self_send {
            if details.receive_listing.is_some() {
                payment.set_our_address("listing", None);
            } else if let Some(index) = details.epic1_index {
                payment.set_our_address("epic1", Some(index));
            } else if entry.transport.as_deref() == Some("epicbox") {
                payment.set_our_address("epicbox", None);
            }
        }
        let notices = payment.their_notices_mut();
        notices.posted_at = details.sender_reported_posted_at.map(|at| at.to_string());
        notices.cancelled_at = details
            .sender_reported_cancelled_at
            .map(|at| at.to_string());
        notices.declined_at = details
            .receiver_declined_at
            .or(details.payer_declined_at)
            .map(|at| at.to_string());
        payment.drop_empty_notices();
        payment
    }
}

/// `-` before `units` when they leave the wallet.
fn signed(units: u64, leaves: bool) -> String {
    let text = format_units(units);
    if leaves && units != 0 {
        format!("-{text}")
    } else {
        text
    }
}

fn kind(details: &TransactionDetails) -> &'static str {
    if details.coinbase {
        "coinbase"
    } else if matches!(details.origin, TxOrigin::FoundByScan) {
        "unknown"
    } else if details.flow == TxFlow::Invoice {
        "invoice"
    } else {
        "send"
    }
}

fn via(details: &TransactionDetails) -> &'static str {
    if details.coinbase {
        return "chain";
    }
    match details.transaction.entry.transport.as_deref() {
        Some("epicbox") => "epicbox",
        Some("http") => "http",
        Some("tor") => "tor",
        Some("file") => "file",
        Some(other) if other.contains("epic1") || other.contains("in_person") => "in_person",
        // A send to self, or a transaction known only from the chain.
        _ => "chain",
    }
}

/// The payment's state and why it ended.
fn state(details: &TransactionDetails) -> (&'static str, Option<&'static str>) {
    let declined = details.receiver_declined_at.or(details.payer_declined_at);
    match details.transaction.entry.state {
        TxState::Sent | TxState::Received if declined.is_some() => ("declined", Some("by_them")),
        TxState::Sent | TxState::Received => ("awaiting_answer", None),
        TxState::Finalized => ("finalized", None),
        TxState::Posted => ("posted", None),
        TxState::Confirmed => ("confirmed", None),
        TxState::Expired => ("expired", None),
        TxState::Cancelled if declined.is_some() => ("declined", Some("by_them")),
        TxState::Cancelled if details.sender_reported_cancelled_at.is_some() => {
            ("cancelled", Some("by_them"))
        }
        TxState::Cancelled => ("cancelled", Some("by_us")),
    }
}

/// The calls that work on the payment now, as `tx cancel`, `tx release`, `tx post` and
/// `tx resend` take them.
fn actions(details: &TransactionDetails, state: &str) -> Vec<String> {
    let entry = &details.transaction.entry;
    let mut actions = Vec::new();
    match state {
        "awaiting_answer" => {
            if entry.direction == TxDirection::Outgoing && details.undelivered && !is_self(details)
            {
                actions.push("deliver");
            }
            actions.push("cancel");
        }
        "finalized" => actions.extend(["post", "cancel"]),
        "posted" => {
            actions.push("post");
            if details.releasable {
                actions.push("cancel");
            }
        }
        _ => {}
    }
    actions.into_iter().map(str::to_owned).collect()
}

/// How the slate this wallet started is getting to the other wallet; none for slates it
/// answered, sends to self and transactions it did not make.
fn delivery(details: &TransactionDetails) -> Option<Delivery> {
    let entry = &details.transaction.entry;
    let started = match details.flow {
        TxFlow::Payment => entry.direction == TxDirection::Outgoing,
        TxFlow::Invoice => entry.direction == TxDirection::Incoming,
    };
    if !started
        || is_self(details)
        || details.coinbase
        || !matches!(details.origin, TxOrigin::Wallet)
    {
        return None;
    }
    let (state, attempts) = if entry.transport.as_deref() == Some("file") {
        ("by_hand", 0)
    } else if details.undelivered {
        ("uncertain", 1)
    } else {
        ("sent", 1)
    };
    Some(Delivery {
        state: state.to_owned(),
        to: details
            .counterparty
            .as_ref()
            .map(|address| address.as_str().to_owned()),
        relays_left: None,
        attempts,
        updated_at: entry.updated_at.to_string(),
        error: None,
    })
}

/// An invoice that waits for approval, as a payment.
fn waiting_payment(id: String, amount: u64, via: &str, received_at: String) -> Payment {
    Payment {
        id,
        kind: "invoice".to_owned(),
        direction: "out".to_owned(),
        state: "needs_approval".to_owned(),
        state_reason: None,
        account: lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned(),
        to_account: None,
        amount: format_units(amount),
        fee: None,
        balance_change: signed(amount, true),
        via: via.to_owned(),
        counterparty: None,
        our_address: None,
        link_id: None,
        purpose: None,
        message: None,
        their_message: None,
        delivery: None,
        answers: Vec::new(),
        check_code: None,
        their_notices: None,
        actions: vec!["approve".to_owned(), "decline".to_owned()],
        cancellable_from_height: None,
        expires_at_height: None,
        confirmations: None,
        confirmed_height: None,
        kernel_excess: None,
        source: "wallet".to_owned(),
        metadata: BTreeMap::new(),
        updated_at: received_at.clone(),
        created_at: received_at,
        handoff: None,
    }
}

/// Every invoice that waits for approval, with where it came from.
pub(in super::super) async fn waiting<H: Host>(
    service: &Service<'_, H>,
) -> Result<Vec<(Payment, Waiting)>, CliError> {
    let opened = &*service.held;
    let mut all = Vec::new();
    for (id, held) in all_held(service)? {
        let mut payment = waiting_payment(id, held.amount, "file", held.received_at.clone());
        payment.their_message.clone_from(&held.message);
        payment.expires_at_height = held.expires_at_height;
        all.push((payment, Waiting::Held(held)));
    }
    for invoice in opened
        .wallet
        .pending_invoices(service.settings.invoice_expiry)?
    {
        let mut payment = waiting_payment(
            invoice.slate_id.to_string(),
            invoice.amount.value(),
            "epicbox",
            invoice.received_at.to_string(),
        );
        payment.their_message = invoice.message;
        payment.counterparty_mut().address = Some(invoice.sender);
        all.push((payment, Waiting::Parked));
    }
    for invoice in opened.wallet.contact_book().contact_invoices().await? {
        let mut payment = waiting_payment(
            invoice.slate_id.to_string(),
            invoice.amount.value(),
            "contact",
            invoice.received_at.to_string(),
        );
        payment.their_message = invoice.message;
        payment.purpose = invoice
            .purpose
            .map(|purpose| crate::commands::contact::purpose_name(purpose).to_owned());
        payment.counterparty_mut().contact_id = Some(invoice.contact_id.to_string());
        all.push((payment, Waiting::Contact));
    }
    for (payment, _) in &mut all {
        let note = note(service, &payment.id)?;
        payment.metadata = note.metadata;
        if payment.purpose.is_none() {
            payment.purpose = note.purpose;
        }
    }
    Ok(all)
}

/// Every invoice declined before it was paid, without those that wait again.
pub(in super::super) fn declined<H: Host>(
    service: &Service<'_, H>,
    waiting: &[(Payment, Waiting)],
) -> Result<Vec<Payment>, CliError> {
    Ok(all_declined(service)?
        .into_iter()
        .filter(|payment| waiting.iter().all(|(each, _)| each.id != payment.id))
        .collect())
}

/// The payment `id` and, when it waits for approval, where it came from.
pub(in super::super) async fn find<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<(Payment, Option<Waiting>)>, CliError> {
    let book = Book::load(service).await?;
    let waiting = waiting(service).await?;
    let declined = declined(service, &waiting)?;
    let id = resolve(service, id, |id| {
        book.find(id).is_some()
            || declined.iter().any(|payment| payment.id == id)
            || waiting.iter().any(|(payment, _)| payment.id == id)
    })?;
    if let Some(details) = book.find(&id) {
        return Ok(Some((book.payment(service, details).await?, None)));
    }
    if let Some(found) = declined.into_iter().find(|payment| payment.id == id) {
        return Ok(Some((found, None)));
    }
    Ok(waiting
        .into_iter()
        .find(|(payment, _)| payment.id == id)
        .map(|(payment, waiting)| (payment, Some(waiting))))
}
