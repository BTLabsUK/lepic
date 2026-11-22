// SPDX-License-Identifier: Apache-2.0
//! Payments: `/payments` and the actions on one.

mod checkout;
mod create;
pub(super) mod view;

use std::collections::BTreeMap;

use lepic_methods::http::{ListenerUrl, PlainHttp};
use lepic_store::{TxId, WalletStore as _};
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::send::SendError;
use lepic_wallet::slate::{MediaType, WireSlate};
use lepic_wallet_contacts::WalletContacts as _;
use serde::Deserialize;

pub(in super::super) use checkout::{
    Locks as CheckoutLocks, driver as checkout_driver, public_routes,
};
pub(in super::super) use create::{Creates, Work, failed, make_queued, uuid, with_coins, with_id};
pub(super) use create::{create, estimate};

use super::super::Service;
use super::events::{self, Change};
use super::{Reply, check_message};
use crate::api::list::{ListQuery, Order, Page, number_key};
use crate::api::model::{Handoff, Payment};
use crate::api::{Category, Context, Listener, Problem, Request, ok};
use crate::api_clients::Role;
use crate::cli::{
    AccountArg, Command, ContactArgs, ContactCommand, ContactPayArgs, ContactSlateIdArg,
    DEFAULT_CHANGE_OUTPUTS, DestinationArgs, Epic1Args, Epic1Command, Epic1PostNextArgs, FluffArg,
    MessageArg, PlainHttpArg, PostArgs, ResendArgs, SelectionArg, SpendArgs, TxCommand, TxIdArgs,
};
use crate::exit::CliError;
use crate::host::Host;
use view::{Book, Held, Waiting};

/// The most metadata keys a payment keeps, and the longest key and value.
const METADATA_KEYS: usize = 50;
const METADATA_KEY_LEN: usize = 40;
const METADATA_VALUE_LEN: usize = 500;

const STATES: &[&str] = &[
    "needs_approval",
    "awaiting_answer",
    "awaiting_post",
    "finalized",
    "posted",
    "confirmed",
    "cancelled",
    "declined",
    "expired",
];
const KINDS: &[&str] = &["send", "invoice", "coinbase", "unknown"];
const DIRECTIONS: &[&str] = &["in", "out", "self"];
const VIAS: &[&str] = &[
    "epicbox",
    "http",
    "tor",
    "contact",
    "link",
    "in_person",
    "file",
    "peer",
    "chain",
];
const DELIVERIES: &[&str] = &[
    "queued",
    "sent",
    "uncertain",
    "held",
    "failed",
    "refused",
    "by_hand",
];
const HANDOFF_FORMATS: &[&str] = &["slate", "epictx", "sealed", "plain", "in_person_code"];

/// Runs `command` as `lepic` runs it. Boxed: the CLI's dispatch is too large a future to keep
/// on a handler's stack.
async fn run<H: Host>(
    service: &Service<'_, H>,
    command: Command,
) -> Result<crate::output::Report, CliError> {
    Box::pin(service.command(command)).await
}

/// 404 for payment `id`. `payment_id` is in the body only when `id` is a UUID, the format the
/// problem document gives it: a path that is no UUID names no payment.
fn unknown(id: &str) -> Problem {
    let problem = Problem::not_found(format!("this wallet has no payment {id}"));
    if lepic_wallet::event::SlateId::parse(id).is_ok() {
        problem.with_payment(id)
    } else {
        problem
    }
}

/// The payment `id` and where it waits, or 404: `payment_declined` with `declined_at` when the
/// receiver of a send this wallet made declined it unanswered (the wallet erased that send, so
/// nothing else of it is left), `not_found` otherwise.
async fn found<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<(Payment, Option<Waiting>), Problem> {
    if let Some(found) = view::find(service, id).await? {
        return Ok(found);
    }
    Err(match declined_at(service, id).await? {
        Some(at) => Problem::payment_declined(id, at),
        None => unknown(id),
    })
}

/// When the receiver declined the send under the payment id `id`, if it did.
async fn declined_at<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<String>, CliError> {
    let Ok(slate) = lepic_wallet::event::SlateId::parse(id) else {
        return Ok(None);
    };
    let at = service.held.wallet.send_declined_at(slate).await?;
    Ok(at.map(|at| at.to_string()))
}

/// 409 `action_not_available` unless `payment` lists `action`.
fn allowed(payment: &Payment, action: &str) -> Result<(), Problem> {
    if payment.actions.iter().any(|each| each == action) {
        Ok(())
    } else {
        Err(Problem::action_not_available(action).with_payment(payment.id.clone()))
    }
}

/// 400 at `/metadata` unless `metadata` keeps the bounds.
fn check_metadata(metadata: &BTreeMap<String, String>) -> Result<(), Problem> {
    if metadata.len() > METADATA_KEYS {
        return Err(Problem::invalid(
            "/metadata",
            format!("metadata holds at most {METADATA_KEYS} keys"),
        ));
    }
    for (key, value) in metadata {
        if key.is_empty() || key.chars().count() > METADATA_KEY_LEN {
            return Err(Problem::invalid(
                "/metadata",
                format!("a metadata key has 1 to {METADATA_KEY_LEN} characters"),
            ));
        }
        if value.chars().count() > METADATA_VALUE_LEN {
            return Err(Problem::invalid(
                &format!("/metadata/{key}"),
                format!("a metadata value has at most {METADATA_VALUE_LEN} characters"),
            ));
        }
    }
    Ok(())
}

/// The query parameter `name` when it is one of `allowed`; 400 at `/name` otherwise.
fn one_of(request: &Request, name: &str, allowed: &[&str]) -> Result<Option<String>, Problem> {
    match request.query().get(name) {
        None => Ok(None),
        Some(value) if allowed.contains(&value) => Ok(Some(value.to_owned())),
        Some(value) => Err(Problem::invalid(
            &format!("/{name}"),
            format!("{name}: {value} is not one of {}", allowed.join(", ")),
        )),
    }
}

/// Milliseconds since the epoch of an RFC 3339 time; 0 when it does not parse.
fn millis(at: &str) -> u64 {
    at.parse::<jiff::Timestamp>()
        .ok()
        .and_then(|at| u64::try_from(at.as_millisecond()).ok())
        .unwrap_or(0)
}

/// The list key of `payment`: newest first, then by id.
fn list_key(payment: &Payment) -> String {
    format!("{}{}", number_key(millis(&payment.created_at)), payment.id)
}

/// The query parameters a payment list is filtered by.
struct Filters {
    account: Option<String>,
    state: Option<String>,
    kind: Option<String>,
    direction: Option<String>,
    via: Option<String>,
    delivery: Option<String>,
    contact: Option<String>,
    updated_after: Option<u64>,
}

impl Filters {
    fn parse(request: &Request) -> Result<Self, Problem> {
        Ok(Self {
            account: request.query().get("account").map(str::to_owned),
            state: one_of(request, "state", STATES)?,
            kind: one_of(request, "kind", KINDS)?,
            direction: one_of(request, "direction", DIRECTIONS)?,
            via: one_of(request, "via", VIAS)?,
            delivery: one_of(request, "delivery", DELIVERIES)?,
            contact: request.query().get("contact_id").map(str::to_owned),
            updated_after: request
                .query()
                .parsed::<jiff::Timestamp>("updated_after")?
                .and_then(|at| u64::try_from(at.as_millisecond()).ok()),
        })
    }

    /// Whether `payment` passes the filters that building it in full leaves alone: its account,
    /// state, kind, direction and update time come from the wallet's records alone.
    fn keeps_base(&self, payment: &Payment) -> bool {
        same(&self.account, Some(&payment.account))
            && same(&self.state, Some(&payment.state))
            && same(&self.kind, Some(&payment.kind))
            && same(&self.direction, Some(&payment.direction))
            && self
                .updated_after
                .is_none_or(|after| millis(&payment.updated_at) > after)
    }

    /// Whether `payment`, built in full, passes every filter.
    fn keeps(&self, payment: &Payment) -> bool {
        self.keeps_base(payment)
            && same(&self.via, Some(&payment.via))
            && same(
                &self.delivery,
                payment.delivery.as_ref().map(|each| each.state.as_str()),
            )
            && same(
                &self.contact,
                payment
                    .counterparty
                    .as_ref()
                    .and_then(|each| each.contact_id.as_deref()),
            )
    }
}

/// Whether `got` is what the filter `want` asks for; no filter keeps everything.
fn same(want: &Option<String>, got: Option<&str>) -> bool {
    want.as_deref().is_none_or(|want| Some(want) == got)
}

/// The width of a list key's time part, as [`number_key`] writes it.
const NUMBER_WIDTH: usize = 20;

/// The least entries one step of the list's walk through the store reads.
const STEP: u32 = 256;

/// A payment a list may show, before it is built in full.
enum Candidate {
    /// A transaction of the wallet, read from its row alone.
    Transaction(TxId),
    /// An invoice declined, or one that waits, already built.
    Built(Box<Payment>),
}

/// The payments a list may show, newest first, produced a step at a time: each step reads the
/// next entries of the store by creation time, never more than the page needs, and merges in
/// the invoices declined and those that wait, which are few and already built. The order is
/// the list's key: millisecond, then payment id. A payment id comes once, the first time it
/// does.
struct Walk {
    /// Entries created before this are still to read; `None` until the first step.
    before: Option<jiff::Timestamp>,
    done: bool,
    /// Built payments not yet merged, newest first.
    extras: Vec<Payment>,
    seen: std::collections::BTreeSet<String>,
    /// The current step, oldest last: what is left of it is taken from the end.
    step: Vec<(String, Candidate)>,
    /// The details of the step's transactions, read together.
    details: std::collections::BTreeMap<TxId, TransactionDetails>,
}

impl Walk {
    fn new(after: Option<&str>, declined: Vec<Payment>, waiting: Vec<Payment>) -> Self {
        let mut extras: Vec<Payment> = declined.into_iter().chain(waiting).collect();
        extras.sort_by_cached_key(|payment| std::cmp::Reverse(list_key(payment)));
        // Entries made in the cursor's millisecond are kept, and told apart by their key.
        let before = after.and_then(|after| {
            let milli: i64 = after.get(..NUMBER_WIDTH)?.parse().ok()?;
            jiff::Timestamp::from_millisecond(milli.checked_add(1)?).ok()
        });
        Self {
            before,
            done: false,
            extras,
            seen: std::collections::BTreeSet::new(),
            step: Vec::new(),
            details: std::collections::BTreeMap::new(),
        }
    }

    /// The next candidate, newest first, with its list key; `None` at the end.
    async fn next<H: Host>(
        &mut self,
        service: &Service<'_, H>,
    ) -> Result<Option<(String, Candidate)>, CliError> {
        loop {
            while let Some((key, candidate)) = self.step.pop() {
                let id = match &candidate {
                    Candidate::Transaction(_) => key.get(NUMBER_WIDTH..).unwrap_or_default(),
                    Candidate::Built(payment) => payment.id.as_str(),
                };
                if self.seen.insert(id.to_owned()) {
                    return Ok(Some((key, candidate)));
                }
            }
            if self.done {
                return Ok(None);
            }
            self.read_step(service).await?;
        }
    }

    async fn read_step<H: Host>(&mut self, service: &Service<'_, H>) -> Result<(), CliError> {
        let before = self.before;
        // A payment id is one payment, shown at its newest row. A row whose slate has another
        // payment row with a newer key is left out, so the older one never shows again below a
        // cursor that passed the newer one.
        let (rows, superseded) = service.held.store()?.read(|repos| {
            let rows = repos.transactions_before(before, STEP)?;
            let mut superseded = std::collections::BTreeSet::new();
            for row in &rows {
                let Some(slate) = row.entry.slate_id else {
                    continue;
                };
                let other = match row.entry.direction {
                    lepic_store::TxDirection::Outgoing => lepic_store::TxDirection::Incoming,
                    lepic_store::TxDirection::Incoming => lepic_store::TxDirection::Outgoing,
                };
                if let Some(other) = repos.transaction_by_slate(slate, other)?
                    && !view::is_self_row(&other.entry)
                    && view::milli(other.entry.created_at) > view::milli(row.entry.created_at)
                {
                    superseded.insert(row.id);
                }
            }
            Ok::<_, CliError>((rows, superseded))
        })?;
        let mut step: Vec<(String, Candidate)> = rows
            .iter()
            .filter(|row| !view::is_self_row(&row.entry) && !superseded.contains(&row.id))
            .map(|row| {
                let id = view::row_id(row);
                let key = format!("{}{id}", number_key(view::milli(row.entry.created_at)));
                (key, Candidate::Transaction(row.id))
            })
            .collect();
        // The step reaches back to the millisecond of its last row; further back there is more.
        let floor = rows.last().map(|last| view::milli(last.entry.created_at));
        let exhausted = rows.len() < usize::try_from(STEP).unwrap_or(usize::MAX);
        self.done = exhausted;
        self.before = rows.last().and_then(|last| {
            jiff::Timestamp::from_millisecond(
                i64::try_from(view::milli(last.entry.created_at)).ok()?,
            )
            .ok()
        });
        let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.extras)
            .into_iter()
            .partition(|payment| {
                exhausted || floor.is_some_and(|floor| millis(&payment.created_at) >= floor)
            });
        self.extras = later;
        for payment in now {
            // A transaction of the same id is the payment, wherever its time puts it.
            if view::has_transaction(service, &payment.id)? {
                continue;
            }
            step.push((list_key(&payment), Candidate::Built(Box::new(payment))));
        }
        // Newest first is taken from the end.
        step.sort_by(|a, b| a.0.cmp(&b.0));
        // The step's details in one read of the store, not one read per row.
        let ids = step
            .iter()
            .filter_map(|(_, candidate)| match candidate {
                Candidate::Transaction(tx) => Some(*tx),
                Candidate::Built(_) => None,
            })
            .collect();
        self.details = service
            .held
            .wallet
            .transactions_details(ids)
            .await?
            .into_iter()
            .map(|details| (details.transaction.id, details))
            .collect();
        self.step = step;
        Ok(())
    }
}

/// Lists payments newest first. The store is read a step at a time from the newest entry, the
/// cursor and the filters the wallet's records decide are applied before a payment is built in
/// full, and the walk stops once the page and one payment past it are found: a long history
/// costs the page, not the history.
pub(super) async fn list<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let page = ListQuery::parse(request.query())?;
    let filters = Filters::parse(&request)?;
    let waiting = view::waiting(service).await?;
    let declined = view::declined(service, &waiting)?;
    let waiting = waiting.into_iter().map(|(payment, _)| payment).collect();
    let mut walk = Walk::new(page.after.as_deref(), declined, waiting);
    let bare = Book::bare(service)?;
    let mut shown = Vec::new();
    while let Some((key, candidate)) = walk.next(service).await? {
        if page
            .after
            .as_ref()
            .is_some_and(|after| key.as_str() >= after.as_str())
        {
            continue;
        }
        let payment = match candidate {
            Candidate::Built(payment) => {
                if !filters.keeps_base(&payment) {
                    continue;
                }
                *payment
            }
            Candidate::Transaction(tx) => {
                let Some(details) = walk.details.remove(&tx) else {
                    continue;
                };
                let book = bare.row(service, details).await?;
                let Some(details) = book.of_row(tx) else {
                    continue;
                };
                let payment = book.base(details);
                if !filters.keeps_base(&payment) {
                    continue;
                }
                book.complete(service, details, payment).await?
            }
        };
        if filters.keeps(&payment) {
            shown.push(payment);
            if shown.len() > page.limit {
                break;
            }
        }
    }
    ok(&Page::of(shown, &page, Order::Descending, list_key))
}

pub(super) async fn get<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let (payment, _) = found(service, request.param("id")?).await?;
    ok(&payment)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchBody {
    #[serde(default)]
    metadata: Option<BTreeMap<String, String>>,
}

pub(super) async fn update<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: PatchBody = request.json()?;
    let (payment, _) = found(service, request.param("id")?).await?;
    let Some(changes) = body.metadata else {
        return ok(&payment);
    };
    let mut note = view::note(service, &payment.id)?;
    for (key, value) in changes {
        if value.is_empty() {
            note.metadata.remove(&key);
        } else {
            note.metadata.insert(key, value);
        }
    }
    check_metadata(&note.metadata)?;
    view::put_note(service, &payment.id, &note)?;
    events::payment(service, &payment.id, Change::Updated(&["metadata"])).await;
    let (payment, _) = found(service, &payment.id).await?;
    ok(&payment)
}

/// What `tx send`, `invoice pay` and `contact pay-invoice` spend with when the call names nothing:
/// the cutoff is the service's `send_ttl_blocks`.
const fn default_spend(send_ttl_blocks: u64) -> SpendArgs {
    SpendArgs {
        min_confirmations: lepic_wallet::selection::SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS,
        change_outputs: DEFAULT_CHANGE_OUTPUTS,
        selection: SelectionArg::Smallest,
        ttl_blocks: Some(send_ttl_blocks),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    amount: String,
    /// Only `true` is taken: the answer is handed back. `false` is refused.
    #[serde(default)]
    deliver: Option<bool>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

pub(super) async fn approve<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    request.require(Role::Full)?;
    let body: ApproveBody = request.json()?;
    check_message(body.message.as_deref())?;
    if body.deliver == Some(false) {
        return Err(Problem::invalid(
            "/deliver",
            "deliver: false is not supported yet; the answer is handed back",
        ));
    }
    let (payment, waiting) = found(service, request.param("id")?).await?;
    let Some(waiting) = waiting else {
        return Err(Problem::action_not_available("approve").with_payment(payment.id));
    };
    let retyped = crate::amount::parse_amount(&body.amount)
        .map_err(|error| Problem::invalid("/amount", format!("amount: {error}")))?;
    let asked = crate::amount::parse_amount(&payment.amount).map_err(CliError::from)?;
    if retyped != asked {
        return Err(Problem::invalid(
            "/amount",
            format!("the invoice asks for {}", payment.amount),
        )
        .with_payment(payment.id));
    }
    let account = body
        .account
        .unwrap_or_else(|| lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned());
    let id = payment.id.clone();
    let handoff = match waiting {
        Waiting::Held(held) => {
            Some(pay_held(service, &id, held, &account, retyped, body.message).await?)
        }
        Waiting::Contact => {
            run(
                service,
                Command::Contact(ContactArgs {
                    command: ContactCommand::PayInvoice(ContactPayArgs {
                        slate_id: id.clone(),
                        amount: body.amount,
                        account: AccountArg { account },
                        message: MessageArg {
                            message: body.message,
                        },
                        spend: default_spend(service.settings.send_ttl_blocks),
                    }),
                    offline: false,
                }),
            )
            .await?;
            None
        }
    };
    events::payment(service, &id, Change::State(None)).await;
    let (mut payment, _) = found(service, &id).await?;
    payment.handoff = handoff;
    ok(&payment)
}

/// Pays the invoice `held`, opened by hand, and keeps the reply to hand back.
async fn pay_held<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    held: Held,
    account: &str,
    amount: lepic_primitives::amount::Amount,
    message: Option<String>,
) -> Result<Handoff, Problem> {
    let opened = &*service.held;
    let index = opened
        .wallet
        .account(account)
        .map_err(CliError::from)?
        .index;
    let spend =
        crate::commands::Spend::from_args(&default_spend(service.settings.send_ttl_blocks))?;
    let pay = spend.pay_request(index, amount, message);
    let handoff = if held.sealed {
        // Paid as `contact open-sealed` pays it, answered sealed on the channel it came by.
        let paid = Box::pin(opened.wallet.contact_book().sealed_pay(&held.wire, pay))
            .await
            .map_err(CliError::from)?;
        super::handed::answer_handoff(id, paid.answer, false)
    } else {
        let incoming = WireSlate::text(MediaType::JSON, held.wire);
        let paid = Box::pin(opened.wallet.pay_invoice(&opened.file, &incoming, pay))
            .await
            .map_err(CliError::from)?;
        super::handed::plain_answer_handoff(id, &paid.reply, false)
    };
    view::delete_held(service, id)?;
    let mut note = view::note(service, id)?;
    note.handoff = Some(handoff.clone());
    view::put_note(service, id, &note)?;
    Ok(handoff)
}

pub(super) async fn decline<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let (mut payment, waiting) = found(service, request.param("id")?).await?;
    let Some(waiting) = waiting else {
        return Err(Problem::action_not_available("decline").with_payment(payment.id));
    };
    let id = payment.id.clone();
    match waiting {
        Waiting::Held(_) => view::delete_held(service, &id)?,
        Waiting::Contact => {
            run(
                service,
                Command::Contact(ContactArgs {
                    command: ContactCommand::Decline(ContactSlateIdArg {
                        slate_id: id.clone(),
                    }),
                    offline: false,
                }),
            )
            .await?;
        }
    }
    payment.state = "declined".to_owned();
    payment.state_reason = Some("by_us".to_owned());
    payment.actions.clear();
    payment.balance_change = crate::amount::format_units(0);
    payment.updated_at = jiff::Timestamp::now().to_string();
    view::put_declined(service, &payment)?;
    events::payment(service, &id, Change::State(Some("by_us".to_owned()))).await;
    ok(&payment)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverBody {
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    to: Option<String>,
}

/// 400 when the owner TLS listener would send to `to`, an address of this computer.
fn guard_tls(request: &Request, to: &str) -> Result<(), Problem> {
    if request.listener() == Listener::Tls
        && to.contains("://")
        && ListenerUrl::parse(to, PlainHttp::Allowed).is_ok_and(|url| url.names_this_computer())
    {
        return Err(Problem::usage(
            "the owner TLS listener does not send to this computer's own addresses",
        ));
    }
    Ok(())
}

/// The wallet's transaction of payment `id`.
async fn tx_of<H: Host>(service: &Service<'_, H>, id: &str) -> Result<TxId, Problem> {
    Book::of(service, id)
        .await?
        .and_then(|book| book.find(id).map(|details| details.transaction.id))
        .ok_or_else(|| unknown(id))
}

/// Posts epic1 payment `id` by its next route, as `lepic epic1 post-next` does: 409
/// `no_more_routes` when none is left.
async fn next_route<H: Host>(service: &Service<'_, H>, id: &str) -> Reply {
    let command = Command::Epic1(Epic1Args {
        command: Epic1Command::PostNext(Epic1PostNextArgs {
            slate_id: id.to_owned(),
        }),
        offline: false,
    });
    if let Err(error) = run(service, command).await {
        let problem = Problem::from(error);
        let refused = if problem.code() == "epic1_no_more_relays" {
            Problem::conflict("no_more_routes", "every route of the payment was tried")
        } else {
            problem
        };
        return Err(refused.with_payment(id.to_owned()));
    }
    events::payment(service, id, Change::Updated(&["delivery"])).await;
    let (payment, _) = found(service, id).await?;
    ok(&payment)
}

pub(super) async fn deliver<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: DeliverBody = request.json()?;
    let (payment, _) = found(service, request.param("id")?).await?;
    allowed(&payment, "deliver")?;
    if body.relay.is_some() {
        return Err(Problem::invalid(
            "/relay",
            "a delivery goes to the payment's own address; choosing a relay is not supported",
        ));
    }
    if body.to.is_some() {
        return Err(Problem::invalid(
            "/to",
            "a delivery goes to the payment's own address; another destination is not supported",
        ));
    }
    if let Ok(slate) = lepic_wallet::event::SlateId::parse(&payment.id)
        && service
            .held
            .wallet
            .contact_book()
            .epic1_payment(slate)
            .await
            .map_err(CliError::from)?
            .is_some()
    {
        return next_route(service, &payment.id).await;
    }
    let to = payment
        .counterparty
        .as_ref()
        .and_then(|each| each.address.clone())
        .ok_or_else(|| Problem::action_not_available("deliver").with_payment(payment.id.clone()))?;
    guard_tls(&request, &to)?;
    let tx = tx_of(service, &payment.id).await?;
    run(
        service,
        Command::Tx(TxCommand::Resend(ResendArgs {
            tx: TxIdArgs { tx_id: tx.0 },
            plain_http: PlainHttpArg {
                allow_plain_http: to.starts_with("http://")
                    && !lepic_transport::epicbox_link::is_epicbox_link(&to),
            },
            destination: DestinationArgs {
                to: Some(to),
                to_file: None,
            },
            tor: create::tor_of(&service.settings.relay_tor),
            fluff: FluffArg { fluff: false },
        })),
    )
    .await?;
    view::delete_undelivered(service, &payment.id)?;
    events::payment(service, &payment.id, Change::Updated(&["delivery"])).await;
    let (payment, _) = found(service, &payment.id).await?;
    ok(&payment)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostBody {
    #[serde(default)]
    fluff: bool,
    /// For an open in-person request: the answer to finalize, by its id or check code.
    #[serde(default)]
    answer: Option<String>,
}

pub(super) async fn post<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let (payment, _) = found(service, request.param("id")?).await?;
    if !own_invoice(&payment) {
        request.require(Role::Full)?;
    }
    let body: PostBody = request.json()?;
    // The answer of a paid request again: the same one finalized is answered as it is, another
    // is refused and changes nothing.
    if body.answer.is_some()
        && payment
            .request
            .as_ref()
            .is_some_and(|paid| paid.state == "paid")
    {
        let answer = checkout::chosen_answer(&payment.answers, body.answer.as_deref())?;
        checkout::finalize(
            service,
            &payment.id,
            answer,
            crate::commands::propagation(body.fluff),
        )
        .await?;
        let (payment, _) = found(service, &payment.id).await?;
        return ok(&payment);
    }
    allowed(&payment, "post")?;
    if let Some(open) = payment.request.as_ref().filter(|open| open.state == "open") {
        if open.finalize != checkout::MANUAL {
            return Err(Problem::conflict(
                "action_not_available",
                "serve finalizes this request's first answer itself",
            )
            .with_payment(payment.id));
        }
        let answer = checkout::chosen_answer(&payment.answers, body.answer.as_deref())?;
        checkout::finalize(
            service,
            &payment.id,
            answer,
            crate::commands::propagation(body.fluff),
        )
        .await?;
        events::payment(service, &payment.id, Change::State(None)).await;
        let (payment, _) = found(service, &payment.id).await?;
        return ok(&payment);
    }
    if body.answer.is_some() {
        return Err(Problem::invalid(
            "/answer",
            "answer goes only to an open in-person request",
        ));
    }
    let tx = tx_of(service, &payment.id).await?;
    run(
        service,
        Command::Tx(TxCommand::Post(PostArgs {
            tx: TxIdArgs { tx_id: tx.0 },
            fluff: FluffArg { fluff: body.fluff },
        })),
    )
    .await?;
    events::payment(service, &payment.id, Change::State(None)).await;
    let (payment, _) = found(service, &payment.id).await?;
    ok(&payment)
}

/// Recovers a payment's coins: a send to this wallet that spends the payment's inputs, so the
/// payment can never be mined once the recovery is. Answers 202 with the payment, whose
/// `recovery` shows how the push went, a refused one included; refusals before anything is
/// stored are 409s with the wallet's codes.
pub(super) async fn recover<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let (payment, _) = found(service, request.param("id")?).await?;
    request.require(Role::Full)?;
    // A failed load keeps its own answer. An invoice that waits for approval has no
    // transaction yet: nothing holds coins for it.
    let tx = Book::of(service, &payment.id)
        .await?
        .and_then(|book| book.find(&payment.id).map(|details| details.transaction.id))
        .ok_or_else(|| {
            Problem::conflict("not_recoverable", "this payment holds no coins to recover")
                .with_payment(payment.id.clone())
        })?;
    service
        .held
        .wallet
        .recover(tx)
        .await
        .map_err(|error| Problem::from(CliError::from(error)).with_payment(payment.id.clone()))?;
    let (payment, _) = found(service, &payment.id).await?;
    crate::api::accepted(&payment)
}

/// Whether `payment` is an invoice this wallet issued: finishing it moves no coin of ours, so
/// `receive` may post it, and cancel it while it awaits its answer.
fn own_invoice(payment: &Payment) -> bool {
    payment.kind == "invoice" && payment.direction == "in"
}

/// Cancels a payment. A payment already cancelled is answered as it is; a posted send is
/// refused with `use_recover`, as only a recovery spends its inputs again. Any other posted
/// payment falls to the `actions` rule.
pub(super) async fn cancel<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let (payment, _) = found(service, request.param("id")?).await?;
    if !(own_invoice(&payment) && matches!(payment.state.as_str(), "awaiting_answer" | "cancelled"))
    {
        request.require(Role::Full)?;
    }
    if payment.state == "cancelled" {
        return ok(&payment);
    }
    // A recovery's pair are self payments, so `out` leaves them to the `actions` rule.
    if payment.state == "posted" && payment.direction == "out" {
        return Err(Problem::conflict(
            "use_recover",
            "the node took this payment, so it is not cancelled: a send is recovered instead",
        )
        .with_payment(payment.id));
    }
    allowed(&payment, "cancel")?;
    let tx_id = tx_of(service, &payment.id).await?;
    let opened = &*service.held;
    // Cancelling an invoice issued to a paired contact tells that contact it is withdrawn.
    opened
        .epicbox
        .attach_wallet(&opened.wallet)
        .map_err(CliError::from)?;
    // The wallet's own state event fires during the cancel and reads the request's note, so the
    // shop's mark goes first or that event says `expired`. The mark counts only once the
    // payment is `Cancelled`, so the request stays open meanwhile; a failed cancel clears it.
    let requested = payment.request.is_some();
    if requested {
        checkout::mark_cancelled(service, &payment.id).await?;
    }
    if let Err(error) = opened.wallet.cancel_with_relay(tx_id).await {
        if requested {
            checkout::unmark_cancelled(service, &payment.id).await?;
        }
        return Err(CliError::from(error).into());
    }
    events::payment(
        service,
        &payment.id,
        Change::State(Some("by_us".to_owned())),
    )
    .await;
    let (payment, _) = found(service, &payment.id).await?;
    ok(&payment)
}

pub(super) async fn handoff<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let format = one_of(&request, "format", HANDOFF_FORMATS)?;
    let qr = request.query().flag("qr")?.unwrap_or(false);
    let (payment, _) = found(service, request.param("id")?).await?;
    let Some(mut handoff) = handoff_of(service, &payment).await? else {
        return Err(Problem::conflict(
            "no_handoff",
            "this payment has nothing to hand over: it was delivered, or it came in",
        )
        .with_payment(payment.id));
    };
    if format
        .as_ref()
        .is_some_and(|format| *format != handoff.format)
    {
        return Err(Problem::conflict(
            "format_not_available",
            format!("this payment's handoff is a {}", handoff.format),
        )
        .with_param("/format")
        .with_payment(payment.id));
    }
    // An in-person code keeps its own frames: they carry the code's bytes, not its text.
    if qr && handoff.format != "in_person_code" {
        handoff.qr_frames = Some(qr_frames(&handoff.text)?);
    }
    ok(&handoff)
}

/// The handoff of `payment`: the one stored with it; else, for a payment this wallet handed over
/// by hand as a plain slate, that slate made again from the store, the text the create returned.
async fn handoff_of<H: Host>(
    service: &Service<'_, H>,
    payment: &Payment,
) -> Result<Option<Handoff>, Problem> {
    if let Some(handoff) = view::note(service, &payment.id)?.handoff {
        return Ok(Some(handoff));
    }
    if payment
        .delivery
        .as_ref()
        .is_none_or(|delivery| delivery.state != "by_hand")
    {
        return Ok(None);
    }
    let tx = tx_of(service, &payment.id).await?;
    let method = service
        .held
        .send_method(lepic_transport::file::FILE)
        .map_err(CliError::from)?;
    // A slate the wallet no longer gives, as the transaction has ended, is no handoff.
    let wire = if payment.kind == "invoice" {
        match service.held.wallet.issued_invoice(method, tx).await {
            Err(InvoiceError::NotFinalizable { .. }) => return Ok(None),
            wire => wire.map_err(CliError::from)?,
        }
    } else {
        match service.held.wallet.sent_slate(method, tx).await {
            Err(SendError::NotResendable { .. }) => return Ok(None),
            wire => wire.map_err(CliError::from)?,
        }
    };
    let text = String::from_utf8(wire.as_bytes().to_vec()).map_err(|_| {
        Problem::of(
            Category::Internal,
            "internal",
            "the payment slate is not text",
        )
    })?;
    Ok(Some(Handoff {
        format: "slate".to_owned(),
        text,
        file_name: Some(format!("{}.slate", payment.id)),
        qr_frames: None,
        link: None,
    }))
}

/// `text` as animated QR frames (UR).
fn qr_frames(text: &str) -> Result<Vec<String>, Problem> {
    lepic_wallet::slate::ur_slate::encode_ur_slate(
        text,
        lepic_wallet::slate::ur_slate::MAX_FRAGMENT_LEN,
    )
    .map_err(|error| {
        Problem::conflict(
            "format_not_available",
            format!("this handoff does not fit QR frames: {error}"),
        )
    })
}

/// The payment with slate id `id`, for `GET /payments/{id}` and the `payment.*` events; `None` when this wallet has none.
pub(super) async fn object<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<Payment>, Problem> {
    Ok(view::find(service, id).await?.map(|(payment, _)| payment))
}

/// The payment of the wallet's transaction `tx`, for the `payment.*` events the engine reports
/// by transaction; `None` when it has none.
pub(super) async fn object_of_tx<H: Host>(
    service: &Service<'_, H>,
    tx: TxId,
) -> Result<Option<Payment>, Problem> {
    let Some(id) = view::payment_id_of_tx(service, tx)? else {
        return Ok(None);
    };
    let Some(book) = Book::of(service, &id).await? else {
        return Ok(None);
    };
    let Some(details) = book.find(&id) else {
        return Ok(None);
    };
    Ok(Some(book.payment(service, details).await?))
}
