// SPDX-License-Identifier: Apache-2.0
//! Payments: `/payments` and the actions on one.

mod create;
pub(super) mod view;

use std::collections::BTreeMap;

use lepic_methods::http::{ListenerUrl, PlainHttp};
use lepic_store::TxId;
use lepic_wallet::slate::{MediaType, WireSlate};
use lepic_wallet_contacts::WalletContacts as _;
use serde::Deserialize;

pub(super) use create::{create, estimate};

use super::super::Service;
use super::Reply;
use super::events::{self, Change};
use crate::api::list::{ListQuery, Order, Page, number_key};
use crate::api::model::{Handoff, Payment};
use crate::api::{Context, Listener, Problem, Request, ok};
use crate::api_clients::Role;
use crate::cli::{
    AccountArg, Command, ContactArgs, ContactCommand, ContactPayArgs, ContactSlateIdArg,
    DEFAULT_CHANGE_OUTPUTS, DestinationArgs, FluffArg, InvoiceCommand, LegacyArg, MessageArg,
    PayArgs, PlainHttpArg, PostArgs, ReplyFileArg, ResendArgs, SelectionArg, SlateIdArg, SpendArgs,
    TorBinaryArgs, TxCommand, TxIdArgs,
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

/// 404 for payment `id`.
fn unknown(id: &str) -> Problem {
    Problem::not_found(format!("this wallet has no payment {id}")).with_payment(id)
}

/// The payment `id` and where it waits, or 404.
async fn found<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<(Payment, Option<Waiting>), Problem> {
    view::find(service, id).await?.ok_or_else(|| unknown(id))
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

/// Every payment: the wallet's transactions, the invoices that wait, those declined.
async fn all<H: Host>(service: &Service<'_, H>) -> Result<Vec<Payment>, CliError> {
    let book = Book::load(service).await?;
    let mut payments = Vec::new();
    for details in book.payments() {
        payments.push(book.payment(service, details).await?);
    }
    let waiting = view::waiting(service).await?;
    payments.extend(view::declined(service, &waiting)?);
    payments.extend(waiting.into_iter().map(|(payment, _)| payment));
    let mut seen = std::collections::BTreeSet::new();
    payments.retain(|payment| seen.insert(payment.id.clone()));
    Ok(payments)
}

pub(super) async fn list<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let page = ListQuery::parse(request.query())?;
    let account = request.query().get("account").map(str::to_owned);
    let state = one_of(&request, "state", STATES)?;
    let kind = one_of(&request, "kind", KINDS)?;
    let direction = one_of(&request, "direction", DIRECTIONS)?;
    let via = one_of(&request, "via", VIAS)?;
    let delivery = one_of(&request, "delivery", DELIVERIES)?;
    let contact = request.query().get("contact_id").map(str::to_owned);
    let link = request.query().get("link_id").map(str::to_owned);
    let updated_after = request
        .query()
        .parsed::<jiff::Timestamp>("updated_after")?
        .and_then(|at| u64::try_from(at.as_millisecond()).ok());
    let same = |want: &Option<String>, got: Option<&str>| {
        want.as_deref().is_none_or(|want| Some(want) == got)
    };
    let mut payments: Vec<Payment> = all(service)
        .await?
        .into_iter()
        .filter(|payment| {
            same(&account, Some(&payment.account))
                && same(&state, Some(&payment.state))
                && same(&kind, Some(&payment.kind))
                && same(&direction, Some(&payment.direction))
                && same(&via, Some(&payment.via))
                && same(
                    &delivery,
                    payment.delivery.as_ref().map(|each| each.state.as_str()),
                )
                && same(
                    &contact,
                    payment
                        .counterparty
                        .as_ref()
                        .and_then(|each| each.contact_id.as_deref()),
                )
                && same(&link, payment.link_id.as_deref())
                && updated_after.is_none_or(|after| millis(&payment.updated_at) > after)
        })
        .collect();
    payments.sort_by_key(|payment| std::cmp::Reverse(list_key(payment)));
    ok(&Page::of(payments, &page, Order::Descending, list_key))
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

/// What `tx send`, `invoice pay` and `contact pay-invoice` spend with when the call names nothing.
const fn default_spend() -> SpendArgs {
    SpendArgs {
        min_confirmations: lepic_wallet::selection::SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS,
        change_outputs: DEFAULT_CHANGE_OUTPUTS,
        selection: SelectionArg::Smallest,
        ttl_blocks: None,
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
        Waiting::Parked => {
            run(
                service,
                Command::Invoice(InvoiceCommand::Pay(PayArgs {
                    invoice: id.clone(),
                    amount: body.amount,
                    reply: ReplyFileArg { reply_file: None },
                    account: AccountArg { account },
                    message: MessageArg {
                        message: body.message,
                    },
                    spend: default_spend(),
                })),
            )
            .await?;
            None
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
                        spend: default_spend(),
                    }),
                    offline: false,
                    epicbox_off: false,
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
    let spend = crate::commands::Spend::from_args(&default_spend())?;
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
        super::handed::plain_answer_handoff(service, id, &incoming, &paid.reply, false)?
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
        Waiting::Parked => {
            run(
                service,
                Command::Invoice(InvoiceCommand::Decline(SlateIdArg {
                    slate_id: id.clone(),
                })),
            )
            .await?;
        }
        Waiting::Contact => {
            run(
                service,
                Command::Contact(ContactArgs {
                    command: ContactCommand::Decline(ContactSlateIdArg {
                        slate_id: id.clone(),
                    }),
                    offline: false,
                    epicbox_off: false,
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
struct FinalizeBody {
    #[serde(default)]
    answer_id: Option<String>,
}

/// Finishing a payment by one of its answers. Only in-person payments collect answers, and
/// this wallet starts none yet, so no payment lists `finalize`.
pub(super) async fn finalize<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: FinalizeBody = request.json()?;
    let (payment, _) = found(service, request.param("id")?).await?;
    if body.answer_id.is_none() {
        return Err(Problem::invalid("/answer_id", "answer_id is required"));
    }
    allowed(&payment, "finalize")?;
    Err(Problem::action_not_available("finalize").with_payment(payment.id))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverBody {
    /// Taken, not used yet.
    #[serde(default, rename = "relay_ok")]
    _relay_ok: Option<bool>,
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
    let book = Book::load(service).await?;
    book.find(id)
        .map(|details| details.transaction.id)
        .ok_or_else(|| unknown(id))
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
                allow_plain_http: to.starts_with("http://"),
            },
            destination: DestinationArgs {
                to: Some(to),
                to_file: None,
            },
            tor: TorBinaryArgs {
                tor_binary: None,
                lib_dir: None,
            },
            fluff: FluffArg { fluff: false },
            legacy: LegacyArg { legacy: false },
        })),
    )
    .await?;
    events::payment(service, &payment.id, Change::Updated(&["delivery"])).await;
    let (payment, _) = found(service, &payment.id).await?;
    ok(&payment)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostBody {
    #[serde(default)]
    fluff: bool,
}

pub(super) async fn post<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: PostBody = request.json()?;
    let (payment, _) = found(service, request.param("id")?).await?;
    allowed(&payment, "post")?;
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

/// Cancels a payment, or releases the coins of a posted one the chain never took. A payment
/// already cancelled is answered as it is.
pub(super) async fn cancel<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let (payment, _) = found(service, request.param("id")?).await?;
    if payment.state == "cancelled" {
        return ok(&payment);
    }
    allowed(&payment, "cancel")?;
    let tx = TxIdArgs {
        tx_id: tx_of(service, &payment.id).await?.0,
    };
    let command = if payment.state == "posted" {
        TxCommand::Release(tx)
    } else {
        TxCommand::Cancel(tx)
    };
    run(service, Command::Tx(command)).await?;
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
    let Some(mut handoff) = view::note(service, &payment.id)?.handoff else {
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
    if qr {
        handoff.qr_frames = Some(qr_frames(&handoff.text)?);
    }
    ok(&handoff)
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
    let book = Book::load(service).await?;
    let Some(details) = book
        .transactions
        .iter()
        .find(|details| details.transaction.id == tx)
    else {
        return Ok(None);
    };
    let id = view::payment_id(details);
    let Some(details) = book.find(&id) else {
        return Ok(None);
    };
    Ok(Some(book.payment(service, details).await?))
}
