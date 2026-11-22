// SPDX-License-Identifier: Apache-2.0
//! Payments as the API shows them: built from the wallet's transactions, the invoices that wait
//! for approval, and the notes the API keeps beside them.

use std::collections::BTreeMap;

use lepic_store::{
    AccountIndex, NodeOutcome, OutboxState, PaymentDelivery, StoreError, TxDirection, TxId,
    TxState, WalletStore as _,
};
use lepic_wallet::details::{CancelledReason, ExpiredReason, TransactionDetails, TxFlow};
use lepic_wallet::error_text::node_text;
use lepic_wallet::legacy_history::TxOrigin;
use lepic_wallet::slate::Role as MoneyRole;
use lepic_wallet_contacts::WalletContacts as _;
use serde::{Deserialize, Serialize};

use super::super::super::Service;
use crate::amount::format_units;
use crate::api::model::{
    Delivery, Handoff, OldestPayment, OpenPayments, Payment, PaymentRecovery, PaymentsStatus, Post,
};
use crate::exit::CliError;
use crate::host::Host;

/// The settings key prefix of a payment's note.
const NOTE: &str = "api.payment.";
/// The settings key prefix of an invoice opened by hand and held for approval (D5).
const HELD: &str = "api.held.";
/// The settings key prefix of an invoice declined before it was paid: the payment as it was.
const DECLINED: &str = "api.declined.";
/// The settings key prefix of the error a send's first delivery failed with, kept until a
/// delivery goes through: the wallet keeps no row of it once the payment is cancelled.
const UNDELIVERED: &str = "api.undelivered.";
/// How many failed first deliveries are kept. Past it the oldest are dropped, so the keys do
/// not build up for the payments that ended another way than a delivery.
const MAX_UNDELIVERED: usize = 256;
/// The settings key of the tip up to which confirmations were checked.
const CONFIRMED_TIP: &str = "api.confirmations.tip";

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
    /// The I1 as it was handed over: the armour text when `sealed`.
    pub(in super::super) wire: String,
    /// The invoice came sealed by a contact and is paid sealed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(in super::super) sealed: bool,
    /// The contact that sealed it, when it was signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) contact_id: Option<String>,
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
    /// Sent by a paired contact.
    Contact,
}

pub(super) fn store<H: Host>(
    service: &Service<'_, H>,
) -> Result<crate::stores::SharedStore, CliError> {
    service.held.store()
}

pub(super) fn setting<H: Host>(
    service: &Service<'_, H>,
    key: &str,
) -> Result<Option<String>, CliError> {
    store(service)?.read(|repos| Ok::<_, CliError>(repos.setting(key)?))
}

pub(super) fn put_setting<H: Host>(
    service: &Service<'_, H>,
    key: &str,
    value: &str,
) -> Result<(), CliError> {
    store(service)?.write(|repos| Ok::<_, CliError>(repos.put_setting(key, value)?))
}

pub(super) fn delete_setting<H: Host>(service: &Service<'_, H>, key: &str) -> Result<(), CliError> {
    store(service)?.write(|repos| Ok::<_, CliError>(repos.delete_setting(key)?))
}

/// The settings whose keys start with `prefix`, as `(key, value)`.
pub(super) fn settings_with_prefix<H: Host>(
    service: &Service<'_, H>,
    prefix: &str,
) -> Result<Vec<(String, String)>, CliError> {
    store(service)?.read(|repos| Ok::<_, CliError>(repos.settings_with_prefix(prefix)?))
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

/// Records that the first delivery of payment `id` failed with `error`, and drops the oldest
/// records past `MAX_UNDELIVERED`. A record is `<unix seconds>\t<error>`; one without the time
/// (an older one) counts as the oldest.
pub(in super::super) fn put_undelivered<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    error: &str,
) -> Result<(), CliError> {
    let now = jiff::Timestamp::now().as_second();
    store(service)?.write(|repos| {
        repos.put_setting(&format!("{UNDELIVERED}{id}"), &format!("{now}\t{error}"))?;
        let kept = repos.settings_with_prefix(UNDELIVERED)?;
        let written = format!("{UNDELIVERED}{id}");
        for key in oldest_past(kept, MAX_UNDELIVERED, &written) {
            repos.delete_setting(&key)?;
        }
        Ok::<_, CliError>(())
    })
}

/// The keys of the oldest records of `kept` past `max`, oldest first. The record `keep` (the one
/// just written) is never among them, even when it ties with older ones on the second.
fn oldest_past(mut kept: Vec<(String, String)>, max: usize, keep: &str) -> Vec<String> {
    kept.sort_by(|a, b| (undelivered_at(&a.1), &a.0).cmp(&(undelivered_at(&b.1), &b.0)));
    let excess = kept.len().saturating_sub(max);
    kept.into_iter()
        .filter(|(key, _)| key != keep)
        .take(excess)
        .map(|(key, _)| key)
        .collect()
}

/// When a stored failed delivery was recorded, in unix seconds; 0 for a record without a time.
fn undelivered_at(text: &str) -> i64 {
    text.split_once('\t')
        .and_then(|(at, _)| at.parse().ok())
        .unwrap_or(0)
}

/// The error of a stored failed delivery.
fn undelivered_error(text: String) -> String {
    match text.split_once('\t') {
        Some((at, error)) if at.parse::<i64>().is_ok() => error.to_owned(),
        _ => text,
    }
}

/// Forgets the failed delivery of payment `id`, once a delivery went through.
pub(in super::super) fn delete_undelivered<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<(), CliError> {
    delete_setting(service, &format!("{UNDELIVERED}{id}"))
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

/// The invoices held for approval, after dropping each whose `expires_at_height` is below the
/// wallet's last known tip. The node is not asked; with no known tip every invoice is kept.
pub(in super::super) fn live_held<H: Host>(
    service: &Service<'_, H>,
) -> Result<Vec<(String, Held)>, CliError> {
    let tip = known_tip(service)?;
    let mut live = Vec::new();
    for (id, held) in all_held(service)? {
        if past(held.expires_at_height, tip) {
            delete_held(service, &id)?;
        } else {
            live.push((id, held));
        }
    }
    Ok(live)
}

/// Whether an invoice that expires at `expires_at_height` is past it at the wallet's last
/// known tip, as [`live_held`] judges it. The node is not asked.
pub(in super::super) fn held_expired<H: Host>(
    service: &Service<'_, H>,
    expires_at_height: Option<u64>,
) -> Result<bool, CliError> {
    Ok(past(expires_at_height, known_tip(service)?))
}

/// The wallet's last known tip; the node is not asked.
pub(super) fn known_tip<H: Host>(service: &Service<'_, H>) -> Result<Option<u64>, CliError> {
    Ok(service
        .held
        .wallet
        .last_confirmed_height()?
        .map(lepic_primitives::amount::Height::value))
}

const fn past(expires_at_height: Option<u64>, tip: Option<u64>) -> bool {
    matches!((expires_at_height, tip), (Some(expires), Some(tip)) if expires < tip)
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

/// Records that the caller's id `alias` stands for the slate `id`, on the payment's delivery
/// row. A row the outbox already keeps keeps its state.
pub(in super::super) fn put_alias<H: Host>(
    service: &Service<'_, H>,
    alias: &str,
    id: &str,
) -> Result<(), CliError> {
    let payment_id = id.parse().map_err(|_| CliError::SlateId)?;
    let now = jiff::Timestamp::now();
    store(service)?.write(|repos| {
        let row = match repos.payment_delivery(payment_id)? {
            Some(row) => PaymentDelivery {
                alias: Some(alias.to_owned()),
                ..row
            },
            None => PaymentDelivery {
                payment_id,
                alias: Some(alias.to_owned()),
                state: None,
                state_reason: None,
                updated_at: now,
            },
        };
        Ok::<_, CliError>(repos.put_payment_delivery(&row)?)
    })
}

/// The slate id the caller's id `alias` stands for, if one is stored.
pub(in super::super) fn alias<H: Host>(
    service: &Service<'_, H>,
    alias: &str,
) -> Result<Option<String>, CliError> {
    let row =
        store(service)?.read(|repos| Ok::<_, CliError>(repos.payment_delivery_by_alias(alias)?))?;
    Ok(row.map(|row| row.payment_id.to_string()))
}

/// The id of the payment a transaction belongs to: its slate id, or for a transaction without
/// one (found by a scan, a coinbase) an id made from its number.
pub(in super::super) fn payment_id(details: &TransactionDetails) -> String {
    id_of(details.transaction.entry.slate_id, details.transaction.id)
}

/// The payment id of the wallet's transaction `tx`, read from the store; `None` when it has
/// none.
pub(in super::super) fn payment_id_of_tx<H: Host>(
    service: &Service<'_, H>,
    tx: TxId,
) -> Result<Option<String>, CliError> {
    let entry = store(service)?.read(|repos| Ok::<_, CliError>(repos.transaction(tx)?))?;
    Ok(entry.map(|entry| id_of(entry.slate_id, tx)))
}

/// The prefix of the payment id of a transaction without a slate id.
const NUMBERED: &str = "00000000-0000-0000-0000-";

/// The transaction a payment id made by [`id_of`] from a transaction number stands for.
fn numbered(id: &str) -> Option<TxId> {
    let hex = id.strip_prefix(NUMBERED)?;
    let number = u64::from_str_radix(hex, 16).ok()?;
    let tx_id = TxId(u32::try_from(number).ok()?);
    (id_of(None::<String>, tx_id) == id).then_some(tx_id)
}

/// The payment id of transaction `id` with slate `slate`, as [`payment_id`] gives it.
fn id_of(slate: Option<impl std::fmt::Display>, id: TxId) -> String {
    match slate {
        Some(slate) => slate.to_string(),
        None => format!("{NUMBERED}{:012x}", id.0),
    }
}

/// Whether the stored entry is the receiving half of a send to self, which has no payment of
/// its own: [`is_self_half`] on the row alone.
pub(in super::super) fn is_self_row(entry: &lepic_store::TransactionEntry) -> bool {
    entry.transport.as_deref() == Some("self") && entry.direction == TxDirection::Incoming
}

/// The payment id of a stored transaction, as [`payment_id`] gives it.
pub(in super::super) fn row_id(row: &lepic_store::StoredTransaction) -> String {
    id_of(row.entry.slate_id, row.id)
}

/// Milliseconds since the epoch of `at`, 0 before it: the time part of a list key.
pub(in super::super) fn milli(at: jiff::Timestamp) -> u64 {
    u64::try_from(at.as_millisecond()).unwrap_or(0)
}

/// Whether a transaction that is a payment of its own has the payment id `id`.
pub(in super::super) fn has_transaction<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<bool, CliError> {
    store(service)?.read(|repos| {
        if let Ok(slate) = id.parse() {
            for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                if let Some(found) = repos.transaction_by_slate(slate, direction)?
                    && !is_self_row(&found.entry)
                {
                    return Ok::<_, CliError>(true);
                }
            }
            return Ok(false);
        }
        Ok(numbered(id).is_some_and(|tx_id| {
            repos
                .transaction(tx_id)
                .ok()
                .flatten()
                .is_some_and(|entry| entry.slate_id.is_none() && !is_self_row(&entry))
        }))
    })
}

fn is_self(details: &TransactionDetails) -> bool {
    details.transaction.entry.transport.as_deref() == Some("self")
}

/// The other half of a send to self: the incoming entry, which the payment of the outgoing
/// one stands for.
fn is_self_half(details: &TransactionDetails) -> bool {
    is_self(details) && details.transaction.entry.direction == TxDirection::Incoming
}

/// The payments whose `needed`-th confirmation came since the tip of the last call, oldest
/// first, and keeps the tip. The first call finds none; a tip below the kept one finds none and
/// leaves it, so a reorg reports no payment twice.
pub(in super::super) async fn reached<H: Host>(
    service: &Service<'_, H>,
    needed: u64,
) -> Result<Vec<Payment>, CliError> {
    let checked = setting(service, CONFIRMED_TIP)?.and_then(|text| text.parse::<u64>().ok());
    let tip = known_tip(service)?;
    if tip.is_none() || tip <= checked {
        return Ok(Vec::new());
    }
    let book = Book::load(service).await?;
    let Some(tip) = book.tip else {
        return Ok(Vec::new());
    };
    let mut reached = Vec::new();
    if let Some(checked) = checked.filter(|checked| *checked < tip) {
        let at = |details: &TransactionDetails| {
            details
                .confirmed_height
                .map(|height| height.value().saturating_add(needed.saturating_sub(1)))
        };
        let due: Vec<_> = book
            .payments()
            .filter(|details| at(details).is_some_and(|at| at > checked && at <= tip))
            .collect();
        for details in due.into_iter().rev() {
            reached.push(book.payment(service, details).await?);
        }
    }
    let kept = checked.map_or(tip, |checked| checked.max(tip));
    put_setting(service, CONFIRMED_TIP, &kept.to_string())?;
    Ok(reached)
}

/// The wallet's transactions and accounts, read once for one answer.
pub(in super::super) struct Book {
    labels: Vec<(AccountIndex, String)>,
    tip: Option<u64>,
    /// The confirmations after which a payment is final (the `final_confirmations` setting).
    final_confirmations: u64,
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
            final_confirmations: service.settings.final_confirmations,
            transactions,
        })
    }

    /// The transactions of payment `id` alone, with the self-send of its recovery: both halves
    /// of a send to self, or the one transaction of any other payment. `None` when no
    /// transaction has the id.
    pub(in super::super) async fn of<H: Host>(
        service: &Service<'_, H>,
        id: &str,
    ) -> Result<Option<Self>, CliError> {
        let ids = store(service)?.read(|repos| {
            let mut ids = Vec::new();
            if let Ok(slate) = id.parse() {
                for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                    if let Some(found) = repos.transaction_by_slate(slate, direction)? {
                        ids.push(found.id);
                    }
                }
            }
            if ids.is_empty()
                && let Some(tx_id) = numbered(id)
                && repos
                    .transaction(tx_id)?
                    .is_some_and(|entry| entry.slate_id.is_none())
            {
                ids.push(tx_id);
            }
            Ok::<_, CliError>(ids)
        })?;
        if ids.is_empty() {
            return Ok(None);
        }
        let wallet = &service.held.wallet;
        let mut transactions = Vec::new();
        for tx_id in ids {
            let details = wallet.transaction_details(tx_id).await?;
            if let Some(recovery) = &details.recovery {
                match wallet.transaction_details(recovery.sent_tx).await {
                    Ok(sent) => transactions.push(sent),
                    Err(lepic_wallet::WalletError::UnknownTransaction(_)) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            transactions.push(details);
        }
        let labels = wallet
            .accounts()?
            .into_iter()
            .map(|account| (account.index, account.label))
            .collect();
        let tip = wallet
            .last_confirmed_height()?
            .map(lepic_primitives::amount::Height::value);
        Ok(Some(Self {
            labels,
            tip,
            final_confirmations: service.settings.final_confirmations,
            transactions,
        }))
    }

    /// The accounts' labels and the tip, with no transactions: what a list reads once and
    /// builds its [`Self::row`]s on.
    pub(in super::super) fn bare<H: Host>(service: &Service<'_, H>) -> Result<Self, CliError> {
        let wallet = &service.held.wallet;
        let labels = wallet
            .accounts()?
            .into_iter()
            .map(|account| (account.index, account.label))
            .collect();
        let tip = wallet
            .last_confirmed_height()?
            .map(lepic_primitives::amount::Height::value);
        Ok(Self {
            labels,
            tip,
            final_confirmations: service.settings.final_confirmations,
            transactions: Vec::new(),
        })
    }

    /// A book of the transaction `details` alone, with what [`Self::base`] reads of the others:
    /// the receiving half of a send to self and the self-send of a recovery. The list builds
    /// its payments one by one from these, so it never reads the whole history.
    pub(in super::super) async fn row<H: Host>(
        &self,
        service: &Service<'_, H>,
        details: TransactionDetails,
    ) -> Result<Self, CliError> {
        let wallet = &service.held.wallet;
        let mut transactions = Vec::new();
        if let Some(recovery) = &details.recovery {
            match wallet.transaction_details(recovery.sent_tx).await {
                Ok(sent) => transactions.push(sent),
                Err(lepic_wallet::WalletError::UnknownTransaction(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if is_self(&details)
            && details.transaction.entry.direction == TxDirection::Outgoing
            && let Some(slate) = details.transaction.entry.slate_id
        {
            let half = store(service)?.read(|repos| {
                Ok::<_, CliError>(repos.transaction_by_slate(slate, TxDirection::Incoming)?)
            })?;
            if let Some(half) = half {
                transactions.push(wallet.transaction_details(half.id).await?);
            }
        }
        transactions.push(details);
        Ok(Self {
            labels: self.labels.clone(),
            tip: self.tip,
            final_confirmations: self.final_confirmations,
            transactions,
        })
    }

    /// The details of the transaction `tx` this book was made for with [`Self::row`].
    pub(in super::super) fn of_row(&self, tx: TxId) -> Option<&TransactionDetails> {
        self.transactions
            .iter()
            .find(|details| details.transaction.id == tx)
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
        self.complete(service, details, self.base(details)).await
    }

    /// `payment`, the [`Self::base`] of `details`, with what the store keeps beside the
    /// transaction: its contact, its pushes to the node, the outbox's delivery and its note.
    /// Leaves the account, state, kind, direction, id and times as they are.
    pub(in super::super) async fn complete<H: Host>(
        &self,
        service: &Service<'_, H>,
        details: &TransactionDetails,
        mut payment: Payment,
    ) -> Result<Payment, CliError> {
        let tx = details.transaction.id;
        let wants_post = !matches!(
            details.transaction.entry.state,
            TxState::Sent | TxState::Received
        );
        let delivery_id = payment
            .delivery
            .as_ref()
            .and_then(|_| payment.id.parse().ok());
        let note_key = format!("{NOTE}{}", payment.id);
        // One read of the store for what a payment keeps beside its transaction.
        let undelivered_key = format!("{UNDELIVERED}{}", payment.id);
        let (contact, record, row, note, undelivered, reposts) = store(service)?.read(|repos| {
            let contact = lepic_wallet::contact_link::tx_contact(repos, tx)?;
            let record = if wants_post {
                repos.node_post(tx)?
            } else {
                None
            };
            let row = match delivery_id {
                Some(id) => repos.payment_delivery(id)?,
                None => None,
            };
            let note: Note = repos
                .setting(&note_key)?
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default();
            let undelivered = match delivery_id {
                Some(_) => repos.setting(&undelivered_key)?.map(undelivered_error),
                None => None,
            };
            // The classic send's posts over Epicbox, each counted on its outbox row.
            let mut reposts = 0u32;
            if let Some(id) = delivery_id {
                for stored in repos.outbox_of_slate(id)? {
                    reposts = reposts.saturating_add(stored.entry.attempts);
                }
            }
            Ok::<_, CliError>((contact, record, row, note, undelivered, reposts))
        })?;
        if let Some(contact) = contact {
            payment.via = "contact".to_owned();
            payment.counterparty_mut().contact_id = Some(contact.to_string());
        }
        if contact.is_none()
            && let Some(paid) = self
                .epic1_paid(service, &payment, delivery_id.is_some())
                .await?
        {
            // A payment through an epic1 address is stored as a file send; the record of
            // the pay says where it went, for payments made before this too.
            payment.via = "link".to_owned();
            payment.counterparty_mut().address = Some(paid);
        }
        if let Some(delivery) = payment.delivery.as_mut() {
            // The wallet's own posts of a classic send: one more for each re-post.
            delivery.attempts = delivery.attempts.max(reposts);
        }
        if wants_post {
            payment.post = record.map(|record| post_from(&record, &payment.state));
        }
        let row_state = row.as_ref().and_then(|row| row.state);
        outbox_delivery(
            service,
            &mut payment,
            row,
            delivery_id.is_some(),
            contact.is_some(),
        )
        .await?;
        if let (Some(error), None, false, Some(delivery)) = (
            undelivered,
            row_state,
            contact.is_some(),
            payment.delivery.as_mut(),
        ) && matches!(payment.state.as_str(), "awaiting_answer" | "cancelled")
        {
            // The first delivery failed and nothing has got the slate across since: the
            // wallet forgets that once the payment is cancelled.
            delivery.state = "uncertain".to_owned();
            delivery.error = Some(error);
            delivery.undelivered = true;
        }
        if let Some(request) = super::checkout::request_note(service, &payment.id)? {
            super::checkout::fill(service, details, &mut payment, &request, self.tip).await;
        }
        payment.purpose = note.purpose;
        payment.metadata = note.metadata;
        Ok(payment)
    }

    /// The epic1 address `payment` was paid to, when the wallet paid it through one. Only a
    /// payment this wallet started (`started`) can be one.
    async fn epic1_paid<H: Host>(
        &self,
        service: &Service<'_, H>,
        payment: &Payment,
        started: bool,
    ) -> Result<Option<String>, CliError> {
        let Ok(slate_id) = lepic_wallet::event::SlateId::parse(&payment.id) else {
            return Ok(None);
        };
        if !started || payment.kind != "send" {
            return Ok(None);
        }
        let paid = service
            .held
            .wallet
            .contact_book()
            .epic1_payment(slate_id)
            .await?;
        Ok(paid.map(|paid| paid.address))
    }

    /// The payment of `details` as the wallet's records alone show it.
    #[allow(clippy::too_many_lines)] // One field per Payment property.
    pub(in super::super) fn base(&self, details: &TransactionDetails) -> Payment {
        let entry = &details.transaction.entry;
        let outgoing = entry.direction == TxDirection::Outgoing;
        let self_send = is_self(details);
        let id = payment_id(details);
        let (state, state_reason) = state(details);
        let ended = matches!(state, "cancelled" | "declined" | "expired");
        let amount = if self_send && outgoing {
            // The outgoing half holds the change: the other outputs of the same spend. The
            // amount of a self-send is all the outputs it makes: what it spent, less the fee.
            entry
                .amount_debited
                .value()
                .saturating_sub(entry.fee.map_or(0, lepic_primitives::amount::Fee::value))
        } else if outgoing {
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
            purpose: None,
            message,
            their_message,
            delivery: delivery(details),
            answers: Vec::new(),
            check_code: None,
            request: None,
            their_notices: None,
            recovery: self.recovery(details),
            post: None,
            actions: actions(details, state, self.tip),
            expires_at_height: details
                .ttl_cutoff_height
                .map(lepic_primitives::amount::Height::value),
            confirmations: None,
            r#final: None,
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
            slate_bytes: None,
            slate_limit: None,
        };
        if let (Some(tip), Some(confirmed)) = (self.tip, payment.confirmed_height) {
            let confirmations = tip.saturating_sub(confirmed).saturating_add(1);
            payment.confirmations = Some(confirmations);
            payment.r#final = Some(confirmations >= self.final_confirmations);
        }
        if let Some(address) = &details.counterparty {
            payment.counterparty_mut().address = Some(address.as_str().to_owned());
        }
        if !outgoing && !self_send {
            if details.receive_listing.is_some() {
                payment.set_our_address("listing", None);
            } else if let Some(index) = details.epic1_index {
                // An epic1 payment is received as a file exchange: the record of the address
                // it came to makes it a link payment, for payments received before this too.
                // Its payer has no address, so `counterparty` stays empty.
                payment.via = "link".to_owned();
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

    /// The `recovery` object of `details`: its `tx_id` is the payment id of the recovery's
    /// self-send.
    fn recovery(&self, details: &TransactionDetails) -> Option<PaymentRecovery> {
        let recovery = details.recovery.as_ref()?;
        let sent = self
            .transactions
            .iter()
            .find(|other| other.transaction.id == recovery.sent_tx)?;
        Some(PaymentRecovery {
            tx_id: payment_id(sent),
            state: crate::output::recovery_state_name(recovery.state).to_owned(),
            confirmations: recovery.confirmations,
            needed: recovery.needed,
            fee: recovery
                .fee
                .map(|fee| format_units(lepic_primitives::amount::Fee::value(fee))),
            error: recovery.error.as_deref().map(node_text),
        })
    }
}

/// The `post` object of transaction `tx_id`, from the store's record of its pushes to the
/// node. Only a finalized transaction is pushed, so a payment that waits for its answer has
/// none. The next attempt is shown only while the wallet still pushes: `finalized` or `posted`.
fn post_from(record: &lepic_store::NodePost, state: &str) -> Post {
    Post {
        attempts: record.attempts,
        last_outcome: match record.last_outcome {
            NodeOutcome::Accepted => "accepted",
            NodeOutcome::Refused => "refused",
            NodeOutcome::Unreachable => "unreachable",
        }
        .to_owned(),
        last_attempt_at: record.last_at.to_string(),
        last_error: record.last_error.as_deref().map(node_text),
        next_attempt_height: matches!(state, "finalized" | "posted")
            .then(|| lepic_wallet::next_attempt_height(record).value()),
        accepted_once: record.accepted_once,
    }
}

/// The delivery of `payment` as the outbox keeps it, when the outbox posted for it: its state,
/// time and reason replace what the wallet's records show. A slate the outbox could not get
/// across, or may not have, can go to its next route: `deliver` is offered while the payment
/// waits for its answer. The outbox's rows also say whether any route took the slate, the
/// stuck mark and the next post (`undelivered`, `stuck`, `stuck_at`, `next_attempt_at`); a
/// payment to a contact has no other record of its delivery.
async fn outbox_delivery<H: Host>(
    service: &Service<'_, H>,
    payment: &mut Payment,
    row: Option<lepic_store::PaymentDelivery>,
    has_delivery: bool,
    to_contact: bool,
) -> Result<(), CliError> {
    if !has_delivery {
        return Ok(());
    }
    let state = row.as_ref().and_then(|row| row.state);
    if let (Some(state), Some(row), Some(delivery)) =
        (state, row.as_ref(), payment.delivery.as_mut())
    {
        delivery.state = match state {
            OutboxState::Queued => "queued",
            OutboxState::Posted => "sent",
            OutboxState::Uncertain => "uncertain",
            OutboxState::Failed => "failed",
        }
        .to_owned();
        delivery.updated_at = row.updated_at.to_string();
        delivery.error = row.state_reason.as_deref().map(node_text);
    }
    let stuck = matches!(state, Some(OutboxState::Uncertain | OutboxState::Failed));
    let post = match lepic_wallet::event::SlateId::parse(&payment.id) {
        Ok(slate_id) if state.is_some() || to_contact => {
            service
                .held
                .wallet
                .contact_book()
                .payment_post(slate_id)
                .await?
        }
        _ => None,
    };
    if let (Some(post), Some(delivery)) = (post, payment.delivery.as_mut()) {
        if to_contact && state.is_none() {
            delivery.state = if post.delivered {
                "sent"
            } else if post.waiting {
                "queued"
            } else {
                "failed"
            }
            .to_owned();
            delivery.error = post.reason.as_deref().map(node_text);
        }
        delivery.attempts = post.attempts;
        delivery.undelivered = !post.delivered;
        delivery.stuck = post.stuck;
        delivery.stuck_at = post.stuck_at.map(|at| at.to_string());
        delivery.next_attempt_at = post.next_at.map(|at| at.to_string());
    }
    let deliver = "deliver".to_owned();
    if stuck
        && payment.state == "awaiting_answer"
        && payment.actions.iter().any(|action| action == "cancel")
        && !payment.actions.contains(&deliver)
    {
        payment.actions.insert(0, deliver);
    }
    Ok(())
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
        TxState::Expired => match details.expired_reason {
            Some(ExpiredReason::RejectedByNode) => ("expired", Some("expired_rejected_by_node")),
            Some(ExpiredReason::NoAnswer) => ("expired", Some("expired_no_answer")),
            Some(ExpiredReason::NotMined) => ("expired", Some("expired_not_mined")),
            _ => ("expired", None),
        },
        TxState::Cancelled if declined.is_some() => ("declined", Some("by_them")),
        TxState::Cancelled if details.cancelled_reason == Some(CancelledReason::Recovered) => {
            ("cancelled", Some("recovered"))
        }
        TxState::Cancelled if details.sender_reported_cancelled_at.is_some() => {
            ("cancelled", Some("by_them"))
        }
        TxState::Cancelled => ("cancelled", Some("by_us")),
    }
}

/// The calls that work on the payment now, as `tx cancel`, `tx post`, `tx resend` and
/// `tx recover` take them. From its post cutoff at the wallet's last known
/// `tip`, the wallet no longer posts a transaction. While a recovery is open, neither the
/// payment nor an entry of the recovery's pair is posted or cancelled.
fn actions(details: &TransactionDetails, state: &str, tip: Option<u64>) -> Vec<String> {
    let entry = &details.transaction.entry;
    let postable = !matches!(
        (details.post_cutoff_height, tip),
        (Some(cutoff), Some(tip)) if tip >= cutoff.value()
    );
    let recovering = details.recovery_of.is_some()
        || details
            .recovery
            .as_ref()
            .is_some_and(|recovery| recovery.state.is_open());
    let mut actions = Vec::new();
    match state {
        _ if recovering => {}
        "awaiting_answer" => {
            if entry.direction == TxDirection::Outgoing && details.undelivered && !is_self(details)
            {
                actions.push("deliver");
            }
            actions.push("cancel");
        }
        "finalized" => {
            if postable {
                actions.push("post");
            }
            actions.push("cancel");
        }
        "posted" if postable => actions.push("post"),
        _ => {}
    }
    if details.recoverable {
        actions.push("recover");
    }
    actions.into_iter().map(str::to_owned).collect()
}

/// The error of a send over stock Epicbox its receiver left unanswered for a day.
const UNANSWERED: &str = "no answer from the receiver for a day: it may be offline, or at its \
     limit of open receipts, which this route cannot report; cancel the payment to free its \
     funds, or keep waiting";

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
    } else if details.undelivered || details.unanswered_at.is_some() {
        ("uncertain", 1)
    } else {
        ("sent", 1)
    };
    // A stock Epicbox receiver cannot say that it refused the payment, so a send it left
    // unanswered for a day is marked with the likely reasons.
    let unanswered = details.unanswered_at;
    Some(Delivery {
        state: state.to_owned(),
        to: details
            .counterparty
            .as_ref()
            .map(|address| address.as_str().to_owned()),
        relays_left: None,
        attempts,
        updated_at: entry.updated_at.to_string(),
        error: unanswered.map(|_| UNANSWERED.to_owned()),
        undelivered: state != "by_hand" && details.undelivered,
        stuck: unanswered.is_some(),
        stuck_at: unanswered.map(|at| at.to_string()),
        next_attempt_at: None,
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
        purpose: None,
        message: None,
        their_message: None,
        delivery: None,
        answers: Vec::new(),
        check_code: None,
        request: None,
        their_notices: None,
        recovery: None,
        post: None,
        actions: vec!["approve".to_owned(), "decline".to_owned()],
        expires_at_height: None,
        confirmations: None,
        r#final: None,
        confirmed_height: None,
        kernel_excess: None,
        source: "wallet".to_owned(),
        metadata: BTreeMap::new(),
        updated_at: received_at.clone(),
        created_at: received_at,
        handoff: None,
        slate_bytes: None,
        slate_limit: None,
    }
}

/// Every invoice that waits for approval, with where it came from. An invoice parked from an
/// Epicbox sender is listed without actions until it expires: nothing pays or declines it.
pub(in super::super) async fn waiting<H: Host>(
    service: &Service<'_, H>,
) -> Result<Vec<(Payment, Option<Waiting>)>, CliError> {
    let opened = &*service.held;
    let mut all = Vec::new();
    for (id, held) in live_held(service)? {
        let mut payment = waiting_payment(id, held.amount, "file", held.received_at.clone());
        payment.their_message.clone_from(&held.message);
        payment.expires_at_height = held.expires_at_height;
        if let Some(contact) = &held.contact_id {
            payment.counterparty_mut().contact_id = Some(contact.clone());
        }
        all.push((payment, Some(Waiting::Held(held))));
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
        payment.actions.clear();
        all.push((payment, None));
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
        all.push((payment, Some(Waiting::Contact)));
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
    waiting: &[(Payment, Option<Waiting>)],
) -> Result<Vec<Payment>, CliError> {
    Ok(all_declined(service)?
        .into_iter()
        .filter(|payment| waiting.iter().all(|(each, _)| each.id != payment.id))
        .collect())
}

/// The payment `id` and, when it waits for approval, where it came from. A payment, a declined
/// invoice or a waiting invoice with that id wins over a caller's id stored for another one.
/// Reads the payment's own transactions, never the whole history.
pub(in super::super) async fn find<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<(Payment, Option<Waiting>)>, CliError> {
    let id = id.to_ascii_lowercase();
    if let Some(found) = found_by_id(service, &id).await? {
        return Ok(Some(found));
    }
    match alias(service, &id)? {
        Some(slate) if slate != id => found_by_id(service, &slate).await,
        _ => Ok(None),
    }
}

/// The payment whose own id is `id`, without looking at aliases.
async fn found_by_id<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<(Payment, Option<Waiting>)>, CliError> {
    if let Some(book) = Book::of(service, id).await?
        && let Some(details) = book.find(id)
    {
        return Ok(Some((book.payment(service, details).await?, None)));
    }
    let waiting = waiting(service).await?;
    if let Some(found) = declined(service, &waiting)?
        .into_iter()
        .find(|payment| payment.id == id)
    {
        return Ok(Some((found, None)));
    }
    Ok(waiting.into_iter().find(|(payment, _)| payment.id == id))
}

/// The settings key prefix of the payer's decline of an invoice this wallet issued. A copy of
/// the wallet's own `DECLINED_PREFIX` in `crates/lepic-wallet/src/notices.rs`, which it keeps
/// to itself; the two must stay the same.
const PAYER_DECLINED: &str = "notice.declined.";
/// The settings key prefix of the receiver's decline of a send this wallet made; a copy of
/// `SEND_DECLINED_PREFIX` in `crates/lepic-wallet/src/notices.rs`.
const RECEIVER_DECLINED: &str = "notice.send_declined.";
/// The transport of both halves of a payment to self.
const SELF_TRANSPORT: &str = "self";

/// The payments that are not over yet, counted as `GET /payments` lists them over every
/// account, from the store alone: no node request and no load of the wallet's transactions.
/// `needs_approval` counts every parked invoice, so it can exceed the listing by one whose
/// slate does not decode or one from a contact without its note.
pub(in super::super) fn status<H: Host>(
    service: &Service<'_, H>,
) -> Result<PaymentsStatus, CliError> {
    let tip = known_tip(service)?;
    let held = all_held(service)?
        .into_iter()
        .filter(|(_, held)| !past(held.expires_at_height, tip))
        .count();
    store(service)?.read(|repos| {
        let parked = repos.parked_invoice_count()?;
        let declined = declined_open(repos)?;
        // Each state's first payment not declined is among its first `declined + 1`.
        let enough = u32::try_from(declined.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let sent = repos.transactions_in_state(TxState::Sent, SELF_TRANSPORT, enough)?;
        let received = repos.transactions_in_state(TxState::Received, SELF_TRANSPORT, enough)?;
        let finalized = repos.transactions_in_state(TxState::Finalized, SELF_TRANSPORT, 1)?;
        let posted = repos.transactions_in_state(TxState::Posted, SELF_TRANSPORT, 0)?;
        let oldest_awaiting = sent
            .oldest
            .iter()
            .chain(&received.oldest)
            .filter(|(id, _)| !declined.contains(id))
            .min_by_key(|(id, at)| (*at, *id))
            .copied();
        let as_count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        Ok::<_, CliError>(PaymentsStatus {
            open: OpenPayments {
                needs_approval: as_count(held).saturating_add(as_count(parked)),
                awaiting_answer: sent
                    .count
                    .saturating_add(received.count)
                    .saturating_sub(as_count(declined.len())),
                finalized: finalized.count,
                posted: posted.count,
            },
            oldest_awaiting_answer: oldest_payment(repos, oldest_awaiting)?,
            oldest_finalized: oldest_payment(repos, finalized.oldest.first().copied())?,
        })
    })
}

/// What the deliveries of the payments that are not over show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct OpenDeliveries {
    /// Payments whose `delivery.state` is `queued`.
    pub queued: u64,
    /// Payments whose `delivery.stuck` is set or whose `delivery.state` is `uncertain` or
    /// `failed`.
    pub stuck: u64,
}

/// The deliveries of the payments [`status`] counts as open, counted from the payments as
/// `GET /payments` builds them, so the two cannot differ. It reads each open payment's
/// transaction, but not the rest of the history and not the node.
pub(in super::super) async fn open_deliveries<H: Host>(
    service: &Service<'_, H>,
) -> Result<OpenDeliveries, CliError> {
    let ids = store(service)?.read(|repos| {
        let declined = declined_open(repos)?;
        let mut ids = Vec::new();
        for state in [
            TxState::Sent,
            TxState::Received,
            TxState::Finalized,
            TxState::Posted,
        ] {
            let tally = repos.transactions_in_state(state, SELF_TRANSPORT, u32::MAX)?;
            ids.extend(
                tally
                    .oldest
                    .into_iter()
                    .map(|(id, _)| id)
                    .filter(|id| !declined.contains(id)),
            );
        }
        Ok::<_, CliError>(ids)
    })?;
    let bare = Book::bare(service)?;
    let mut open = OpenDeliveries {
        queued: 0,
        stuck: 0,
    };
    for id in ids {
        let details = service.held.wallet.transaction_details(id).await?;
        let book = bare.row(service, details).await?;
        let Some(details) = book.of_row(id) else {
            continue;
        };
        let payment = book.payment(service, details).await?;
        if !matches!(
            payment.state.as_str(),
            "awaiting_answer" | "finalized" | "posted"
        ) {
            continue;
        }
        let Some(delivery) = &payment.delivery else {
            continue;
        };
        if delivery.state == "queued" {
            open.queued = open.queued.saturating_add(1);
        }
        if delivery.stuck || matches!(delivery.state.as_str(), "uncertain" | "failed") {
            open.stuck = open.stuck.saturating_add(1);
        }
    }
    Ok(open)
}

/// The transactions still awaiting an answer that the other side declined, which the listing
/// shows as `declined`. A mark counts, as there, only for a transaction of its direction and
/// only when it holds a time; marks of older versions (`1`) do not.
fn declined_open(
    repos: &dyn lepic_store::Repositories,
) -> Result<std::collections::BTreeSet<TxId>, StoreError> {
    let mut open = std::collections::BTreeSet::new();
    for (prefix, direction) in [
        (RECEIVER_DECLINED, TxDirection::Outgoing),
        (PAYER_DECLINED, TxDirection::Incoming),
    ] {
        for (key, at) in repos.settings_with_prefix(prefix)? {
            let Some(text) = key.strip_prefix(prefix) else {
                continue;
            };
            // Only the form the wallet writes, so a key it never reads is never counted.
            let Ok(slate) = lepic_wallet::event::SlateId::parse(text) else {
                continue;
            };
            if slate.to_string() != text || at.parse::<jiff::Timestamp>().is_err() {
                continue;
            }
            let Ok(uuid) = text.parse() else {
                continue;
            };
            let Some(found) = repos.transaction_by_slate(uuid, direction)? else {
                continue;
            };
            let entry = &found.entry;
            let self_half = direction == TxDirection::Incoming
                && entry.transport.as_deref() == Some(SELF_TRANSPORT);
            if matches!(entry.state, TxState::Sent | TxState::Received) && !self_half {
                open.insert(found.id);
            }
        }
    }
    Ok(open)
}

/// The payment of transaction `oldest`, by the id the listing gives it.
fn oldest_payment(
    repos: &dyn lepic_store::Repositories,
    oldest: Option<(TxId, jiff::Timestamp)>,
) -> Result<Option<OldestPayment>, StoreError> {
    let Some((id, since)) = oldest else {
        return Ok(None);
    };
    let Some(entry) = repos.transaction(id)? else {
        return Ok(None);
    };
    Ok(Some(OldestPayment {
        id: id_of(entry.slate_id, id),
        since: since.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use jiff::Timestamp;
    use lepic_primitives::amount::Amount;
    use lepic_store::{StoredTransaction, TransactionEntry};
    use lepic_transport::transport::Destination;

    use super::*;

    const ROUTE: &str = "zzRMBr82zhzvz6hAxJMecEchV4ohxJkrNtDKLqwJMq7EQ4y2ibhQ@epicbox.example:443";

    /// A send over stock Epicbox that waits for its answer, marked unanswered at `unanswered_at`.
    fn epicbox_send(unanswered_at: Option<Timestamp>) -> TransactionDetails {
        let created = Timestamp::from_second(1_790_000_000).unwrap();
        TransactionDetails {
            transaction: StoredTransaction {
                id: TxId(1),
                entry: TransactionEntry {
                    account: AccountIndex(0),
                    direction: TxDirection::Outgoing,
                    state: TxState::Sent,
                    slate_id: Some("0436430c-2b02-624c-2032-570501212b0e".parse().unwrap()),
                    transport: Some("epicbox".to_owned()),
                    amount_credited: Amount::new(0),
                    amount_debited: Amount::new(1_000),
                    fee: None,
                    created_at: created,
                    updated_at: created,
                },
            },
            kernel_excess: None,
            confirmed_height: None,
            counterparty: Some(Destination::new(ROUTE.to_owned())),
            receive_listing: None,
            epic1_index: None,
            ttl_cutoff_height: None,
            post_cutoff_height: None,
            confirmed_at: None,
            messages: Vec::new(),
            flow: TxFlow::Payment,
            origin: TxOrigin::Wallet,
            imported: None,
            found: None,
            undelivered: false,
            output_commits: Vec::new(),
            spent_commits: Vec::new(),
            unverified: false,
            sender_reported_posted_at: None,
            sender_reported_cancelled_at: None,
            receiver_declined_at: None,
            unanswered_at,
            payer_declined_at: None,
            relay_cancellable: false,
            coinbase: false,
            expired_reason: None,
            cancelled_reason: None,
            recovery: None,
            recovery_of: None,
            recoverable: false,
        }
    }

    #[test]
    fn a_send_marked_unanswered_is_uncertain_and_stuck_since_the_mark() {
        let at = Timestamp::from_second(1_790_086_400).unwrap();
        let delivery = delivery(&epicbox_send(Some(at))).unwrap();
        assert_eq!(delivery.state, "uncertain");
        assert!(delivery.stuck);
        assert_eq!(delivery.stuck_at, Some(at.to_string()));
        assert_eq!(delivery.error.as_deref(), Some(UNANSWERED));
        assert!(!delivery.undelivered);
        assert_eq!(delivery.to.as_deref(), Some(ROUTE));
    }

    #[test]
    fn a_send_that_waits_unmarked_is_sent_and_not_stuck() {
        let delivery = delivery(&epicbox_send(None)).unwrap();
        assert_eq!(delivery.state, "sent");
        assert!(!delivery.stuck);
        assert_eq!(delivery.stuck_at, None);
        assert_eq!(delivery.error, None);
    }

    #[test]
    fn the_oldest_failed_deliveries_past_the_cap_are_the_ones_dropped() {
        let record = |id: &str, text: &str| (format!("{UNDELIVERED}{id}"), text.to_owned());
        let kept = vec![
            record("c", "300\tnewest"),
            record("a", "100\toldest with a time"),
            record("b", "no time at all"),
            record("d", "200\tmiddle"),
        ];
        assert_eq!(
            oldest_past(kept.clone(), 2, &format!("{UNDELIVERED}c")),
            vec![format!("{UNDELIVERED}b"), format!("{UNDELIVERED}a")]
        );
        assert!(oldest_past(kept.clone(), 4, &format!("{UNDELIVERED}c")).is_empty());
        // The record just written survives, even when it sorts among the oldest.
        assert_eq!(
            oldest_past(kept, 2, &format!("{UNDELIVERED}b")),
            vec![format!("{UNDELIVERED}a"), format!("{UNDELIVERED}d")]
        );
        assert_eq!(
            undelivered_error("100\tconnection refused".to_owned()),
            "connection refused"
        );
        assert_eq!(
            undelivered_error("an older text".to_owned()),
            "an older text"
        );
    }
}
