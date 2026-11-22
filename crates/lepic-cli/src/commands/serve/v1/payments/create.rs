// SPDX-License-Identifier: Apache-2.0
//! `POST /payments` and `POST /payments/estimate`.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lepic_epicbox::TRANSPORT_ID;
use lepic_methods::http::{ListenerUrl, PlainHttp};
use lepic_store::OutputRecord;
use lepic_transport::method::Method;
use lepic_transport::transport::PostedSize;
use lepic_wallet::selection::{SelectionOptions, SelectionStrategy};
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet_contacts::parse_mailbox;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{Notify, oneshot};

use super::super::super::Service;
use super::super::events::{self, Change};
use super::super::handed;
use super::super::{Create, Reply, check_message};
use super::checkout;
use super::view::{self, Note};
use super::{check_metadata, default_spend};
use crate::amount::{format_units, parse_amount};
use crate::api::model::{Estimate, Handoff};
use crate::api::{Category, Context, Listener, Problem, Request, created, idempotency, ok};
use crate::api_clients::Role;
use crate::cli::{
    AccountArg, Command, ContactArgs, ContactCommand, ContactIdArg, ContactInvoiceArgs,
    DestinationArgs, Epic1Args, Epic1Command, Epic1LinkArg, Epic1PayArgs, FluffArg, HttpReach,
    InvoiceCommand, IssueArgs, MessageArg, PayMailboxesArg, PlainHttpArg, PurposeArg, SelectionArg,
    SendArgs, SendDestinationArgs, SendSlateIdArg, SpendArgs, TorBinaryArgs, TxCommand,
};
use crate::commands::contact::SlateFile;
use crate::commands::{caller_slate_id, drawn_slate_id};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::Report;
use crate::recipient;
use crate::settings::RelayTor;

/// The body of `POST /payments` and `POST /payments/estimate`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    via: Option<String>,
    #[serde(default)]
    account: Option<String>,
    /// Empty when left out: an `epic:` link may name the amount.
    #[serde(default)]
    amount: String,
    /// Left out, the link's message; empty or only spaces, none.
    #[serde(default)]
    message: Option<String>,
    /// For an epic1 payment: the mailboxes it goes through in place of the wallet's list.
    #[serde(default)]
    mailboxes: Vec<String>,
    #[serde(default)]
    min_confirmations: Option<u64>,
    #[serde(default)]
    selection: Option<String>,
    #[serde(default)]
    change_outputs: Option<usize>,
    #[serde(default)]
    ttl_blocks: Option<u64>,
    #[serde(default)]
    fluff: bool,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    allow_plain_http: bool,
    #[serde(default = "yes")]
    deliver: bool,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    /// For an in-person request: `first` or `manual`.
    #[serde(default)]
    finalize: Option<String>,
    /// For an in-person request: whether its code names serve's direct routes.
    #[serde(default)]
    direct: Option<bool>,
}

const fn yes() -> bool {
    true
}

/// The amount `max` stands for: everything the account can send.
const MAX: &str = "max";

impl CreateBody {
    /// The body, and the body as it came for the idempotency check.
    fn read(request: &Request) -> Result<(Self, Value), Problem> {
        let value: Value = request.json()?;
        let body = serde_json::from_value(value.clone())
            .map_err(|error| Problem::bad_request("invalid_body", error.to_string()))?;
        Ok((body, value))
    }

    fn is_invoice(&self) -> Result<bool, Problem> {
        match self.kind.as_deref() {
            None | Some("send") => Ok(false),
            Some("invoice") => Ok(true),
            Some(other) => Err(Problem::invalid(
                "/kind",
                format!("kind: {other} is not send or invoice"),
            )),
        }
    }

    fn account(&self) -> String {
        self.account
            .clone()
            .unwrap_or_else(|| lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned())
    }

    /// The spending options of the call: what it names, else the defaults. A cutoff it does not
    /// name is left to the send, which applies `send_ttl_blocks`.
    fn spend(&self, send_ttl_blocks: u64) -> Result<SpendArgs, Problem> {
        let defaults = default_spend(send_ttl_blocks);
        let selection = match self.selection.as_deref() {
            None | Some("smallest") => SelectionArg::Smallest,
            Some("all") => SelectionArg::All,
            Some(other) => {
                return Err(Problem::invalid(
                    "/selection",
                    format!("selection: {other} is not all or smallest"),
                ));
            }
        };
        if self.change_outputs == Some(0) {
            return Err(Problem::invalid(
                "/change_outputs",
                "change_outputs is at least 1",
            ));
        }
        Ok(SpendArgs {
            min_confirmations: self.min_confirmations.unwrap_or(defaults.min_confirmations),
            change_outputs: self.change_outputs.unwrap_or(defaults.change_outputs),
            selection,
            ttl_blocks: self.ttl_blocks,
        })
    }

    fn purpose(&self) -> Result<Option<PurposeArg>, Problem> {
        Ok(match self.purpose.as_deref() {
            None => None,
            Some("payment") => Some(PurposeArg::Payment),
            Some("deposit") => Some(PurposeArg::Deposit),
            Some("withdrawal") => Some(PurposeArg::Withdrawal),
            Some("refund") => Some(PurposeArg::Refund),
            Some("request") => Some(PurposeArg::Request),
            Some(other) => {
                return Err(Problem::invalid(
                    "/purpose",
                    format!("purpose: {other} is not a purpose"),
                ));
            }
        })
    }
}

/// Where a create sends its slate.
enum Route {
    /// Nowhere: the slate is handed back.
    File,
    /// A paired contact's mailbox.
    Contact(String),
    /// An Epicbox, http(s):// or onion address.
    Address(String),
    /// An epic1 link, paid as `lepic epic1 pay` pays it.
    Epic1(String),
    /// An in-person request: a code shown to the payer.
    InPerson,
}

/// The values of `via`.
const VIAS: [&str; 9] = [
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

/// The `via` a send to `to` takes, by the form of the address: the same split `lepic tx send`
/// makes.
fn address_via(to: &str) -> &'static str {
    let to = lepic_transport::epicbox_link::epicbox_of_link(to).unwrap_or(to);
    if crate::commands::is_onion(to) {
        "tor"
    } else if to.contains("://") {
        "http"
    } else {
        "epicbox"
    }
}

/// 400 `via_mismatch` unless `via` is left out or is the route the payment takes, `takes`.
fn agree_via(via: Option<&str>, takes: &str) -> Result<(), Problem> {
    match via {
        Some(via) if via != takes => Err(Problem::bad_request(
            "via_mismatch",
            format!("via: {via} does not match the route of to, which is {takes}"),
        )
        .with_param("/via")),
        _ => Ok(()),
    }
}

/// The route of `body`, or 400 for one this wallet cannot take yet. A classic `epic:` link is
/// settled into the body's amount and message and routed as its address. A `via` is checked
/// against its values and against the route `to` takes: it pins the route, it never changes it.
fn route(body: &mut CreateBody) -> Result<Route, Problem> {
    let via = body.via.as_deref();
    if let Some(via) = via
        && !VIAS.contains(&via)
    {
        return Err(Problem::invalid(
            "/via",
            format!("via: {via} is not one of {}", VIAS.join(", ")),
        ));
    }
    if via == Some("in_person") {
        if body.to.as_deref().is_some_and(|to| !to.trim().is_empty()) {
            return Err(Problem::invalid(
                "/to",
                "an in-person request goes to no one: the payer reads its code",
            ));
        }
        return Ok(Route::InPerson);
    }
    if !body.deliver || via == Some("file") {
        return Ok(Route::File);
    }
    if let Some(via @ ("peer" | "chain")) = via {
        return Err(Problem::invalid(
            "/via",
            format!("via: {via} payments are not supported yet"),
        ));
    }
    let Some(to) = body
        .to
        .as_deref()
        .map(str::trim)
        .filter(|to| !to.is_empty())
    else {
        return Err(Problem::invalid(
            "/to",
            "to is required unless via is file or deliver is false",
        ));
    };
    if let Some(contact) = to.strip_prefix("contact:") {
        agree_via(via, "contact")?;
        return Ok(Route::Contact(contact.to_owned()));
    }
    if via == Some("contact") {
        return Ok(Route::Contact(to.to_owned()));
    }
    if to.starts_with("account:") {
        return Err(Problem::invalid(
            "/to",
            "a payment to one of this wallet's own accounts is not supported yet",
        ));
    }
    if let Some(link) = recipient::epic1_link(to) {
        agree_via(via, "link")?;
        return Ok(Route::Epic1(link));
    }
    if recipient::after_scheme(to).is_some() {
        let link = handed::classic(to)
            .ok_or_else(|| Problem::invalid("/to", "to is not an epic: link with an address"))?;
        agree_via(via, address_via(&link.address))?;
        agree(&mut body.amount, link.amount.as_deref())?;
        if body.message.is_none() {
            body.message = link.message;
        }
        return Ok(Route::Address(link.address));
    }
    agree_via(via, address_via(to))?;
    Ok(Route::Address(to.to_owned()))
}

/// [`route`], with what an epic1 link asks filled into the body where the body names nothing.
async fn settle<H: Host>(
    service: &Service<'_, H>,
    body: &mut CreateBody,
    invoice: bool,
) -> Result<Route, Problem> {
    let route = route(body)?;
    if matches!(route, Route::InPerson) {
        if !invoice {
            return Err(Problem::invalid(
                "/via",
                "via: in_person sends are not supported yet",
            ));
        }
        checkout::finalize_mode(body.finalize.as_deref())?;
        checkout::direct_mode(service, body.direct)?;
    } else if body.finalize.is_some() {
        return Err(Problem::invalid(
            "/finalize",
            "finalize goes only to an in-person request",
        ));
    } else if body.direct.is_some() {
        return Err(Problem::invalid(
            "/direct",
            "direct goes only to an in-person request",
        ));
    }
    if !body.mailboxes.is_empty() {
        if !matches!(route, Route::Epic1(_)) {
            return Err(Problem::invalid(
                "/mailboxes",
                "mailboxes go only to a payment to an epic1 address",
            ));
        }
        if let Some(error) = body
            .mailboxes
            .iter()
            .find_map(|host| parse_mailbox(host).err())
        {
            return Err(Problem::invalid(
                "/mailboxes",
                format!("mailboxes: {error}"),
            ));
        }
    }
    if invoice && matches!(route, Route::Address(_)) {
        return Err(Problem::bad_request(
            "invoice_to_address",
            "an invoice is not sent to an address: hand it back as a file or send it to a \
             paired contact",
        )
        .with_param("/to"));
    }
    if let Route::Epic1(link) = &route {
        if invoice {
            return Err(Problem::invalid(
                "/to",
                "an invoice is not sent to an epic1 link",
            ));
        }
        // The payer may pay another amount than the link asks, as `lepic epic1 pay` does.
        let (asked, asked_message) = handed::epic1_terms(service, link).await?;
        if body.amount.is_empty() {
            body.amount = asked.ok_or_else(|| {
                Problem::invalid("/amount", "amount is required: the link names none")
            })?;
        }
        if body.message.is_none() {
            body.message = asked_message;
        }
    }
    Ok(route)
}

/// Settles `amount` with what a classic `epic:` link `asked`: the body's amount when it names
/// one, else the link's, else 400 at `/amount`. The payer may pay another amount than the link
/// asks, as with an epic1 link.
fn agree(amount: &mut String, asked: Option<&str>) -> Result<(), Problem> {
    if amount.is_empty() {
        match asked {
            Some(asked) => asked.clone_into(amount),
            None => {
                return Err(Problem::invalid(
                    "/amount",
                    "amount is required: the link names none",
                ));
            }
        }
    }
    Ok(())
}

/// `id` as a lowercase UUID, or 400 at `/id`.
pub(in crate::commands::serve) fn uuid(id: &str) -> Result<String, Problem> {
    let id = id.to_ascii_lowercase();
    let shaped = id.len() == 36
        && id.char_indices().all(|(at, each)| match at {
            8 | 13 | 18 | 23 => each == '-',
            _ => each.is_ascii_hexdigit(),
        });
    if shaped {
        Ok(id)
    } else {
        Err(Problem::invalid("/id", "id is a UUID"))
    }
}

/// How far the listener the call came in on may send over HTTP.
fn reach(request: &Request) -> HttpReach {
    if request.listener() == Listener::Tls {
        HttpReach::OtherComputers
    } else {
        HttpReach::Any
    }
}

/// 400 when the owner TLS listener would send to `to`, an address of this computer.
fn guard(reach: HttpReach, to: &str) -> Result<(), Problem> {
    if reach == HttpReach::OtherComputers
        && to.contains("://")
        && ListenerUrl::parse(to, PlainHttp::Allowed).is_ok_and(|url| url.names_this_computer())
    {
        return Err(Problem::usage(
            "the owner TLS listener does not send to this computer's own addresses",
        ));
    }
    Ok(())
}

/// A string field of `report`.
fn field(report: &Report, name: &str) -> Option<String> {
    serde_json::to_value(report)
        .ok()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}

pub(in super::super) async fn create<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
    let reply = attempt(service, request, context).await;
    service.counters.created(&reply);
    reply
}

async fn attempt<H: Host>(service: &Service<'_, H>, request: Request, context: &Context) -> Reply {
    let (mut body, value) = CreateBody::read(&request)?;
    let invoice = body.is_invoice()?;
    request.require(if invoice { Role::Receive } else { Role::Full })?;
    let id = match body.id.as_deref() {
        Some(id) => Some(uuid(id)?),
        None if request.listener() == Listener::Tls => {
            return Err(Problem::invalid(
                "/id",
                "id is required over the owner TLS listener, so a retry cannot pay twice",
            ));
        }
        None => None,
    };
    let route = settle(service, &mut body, invoice).await?;
    if body.amount == MAX {
        return Err(Problem::invalid(
            "/amount",
            "max is for an estimate; a payment names its amount",
        ));
    }
    parse_amount(&body.amount)
        .map_err(|error| Problem::invalid("/amount", format!("amount: {error}")))?;
    check_message(body.message.as_deref())?;
    check_metadata(&body.metadata)?;
    let purpose = body.purpose()?;
    let spend = body.spend(service.settings.send_ttl_blocks)?;
    let reach = reach(&request);
    if let Route::Address(to) = &route {
        guard(reach, to)?;
    }
    let order = Order {
        body,
        route,
        id,
        invoice,
        purpose,
        spend,
        reach,
    };
    let Some(id) = order.id.clone() else {
        return make(service, order).await;
    };
    with_id(
        service,
        context,
        &id,
        &value,
        Work::Payment(Box::new(order)),
    )
    .await
}

/// A create with the caller's `id` and body `value`: it answers the payment a repeat made, else
/// queues `work` for serve to make and answers once it is made. When `api.max_connections`
/// creates are made or wait already it makes and keeps nothing: a new id's record is deleted
/// and the answer is 503 `busy`.
pub(in crate::commands::serve) async fn with_id<H: Host>(
    service: &Service<'_, H>,
    context: &Context,
    id: &str,
    value: &Value,
    work: Work,
) -> Reply {
    // A new id must not name a payment or an alias already: the call would take that payment
    // over. A repeat (its record exists) is checked by `record` as before.
    if service
        .held
        .wallet
        .api_request(idempotency::PAYMENT, id)
        .map_err(CliError::from)?
        .is_none()
        && view::find(service, id).await?.is_some()
    {
        return Err(
            Problem::conflict("idempotency_mismatch", "this id already names a payment")
                .with_param("/id"),
        );
    }
    let started = context.in_progress().start(idempotency::PAYMENT, id)?;
    let create = super::super::record(service, started, idempotency::PAYMENT, id, value)?;
    if create.repeat {
        if let Some(mut payment) = super::object(service, id).await? {
            payment.handoff = super::handoff_of(service, &payment).await?;
            return ok(&payment);
        }
        // The receiver declined the send and the wallet erased it: a repeat must not make it
        // again (its slate id is spent, so a send under it is refused).
        if let Some(at) = super::declined_at(service, id).await? {
            return Err(Problem::payment_declined(id, at));
        }
    }
    match service
        .creates
        .queue(work, create, context.limits().max_connections)
    {
        Ok(answered) => answered
            .await
            .unwrap_or_else(|_| Err(CliError::Interrupted.into())),
        Err(create) => {
            if !create.repeat {
                let _ = service
                    .held
                    .wallet
                    .delete_api_request(idempotency::PAYMENT, id);
            }
            drop(create);
            context.refuse();
            Err(Problem::busy())
        }
    }
}

/// A payment create, checked: what [`make`] makes.
pub(in crate::commands::serve) struct Order {
    body: CreateBody,
    route: Route,
    id: Option<String>,
    invoice: bool,
    purpose: Option<PurposeArg>,
    spend: SpendArgs,
    reach: HttpReach,
}

/// What a create with an id makes.
pub(in crate::commands::serve) enum Work {
    Payment(Box<Order>),
    Consolidation(super::super::consolidate::Consolidation),
}

/// A payment create with an id, made by serve whether or not its caller still waits.
pub(in crate::commands::serve) struct Job {
    work: Work,
    create: Create,
    answer: oneshot::Sender<Reply>,
}

/// The payment creates with an id: those that wait for serve to take them up, and how many are
/// made or wait.
#[derive(Default)]
pub(in crate::commands::serve) struct Creates {
    waiting: RefCell<Vec<Job>>,
    held: Cell<usize>,
    queued: Notify,
}

impl Creates {
    pub(in crate::commands::serve) fn idle(&self) -> bool {
        self.held.get() == 0
    }

    /// Queues `work` for serve to make under `create`; its answer comes once it is made. Gives
    /// `create` back when `bound` creates are made or wait already.
    fn queue(
        &self,
        work: Work,
        create: Create,
        bound: usize,
    ) -> Result<oneshot::Receiver<Reply>, Create> {
        if self.held.get() >= bound {
            return Err(create);
        }
        let (answer, answered) = oneshot::channel();
        self.waiting.borrow_mut().push(Job {
            work,
            create,
            answer,
        });
        self.held.set(self.held.get().saturating_add(1));
        self.queued.notify_one();
        Ok(answered)
    }

    /// The creates queued since the last call, once there is one.
    pub(in crate::commands::serve) async fn next(&self) -> Vec<Job> {
        loop {
            let jobs = std::mem::take(&mut *self.waiting.borrow_mut());
            if !jobs.is_empty() {
                return jobs;
            }
            self.queued.notified().await;
        }
    }
}

/// Makes the payment of `job` and answers its caller if it still waits. An error answer that
/// made nothing removes the record of a new id, so the id can be used again.
pub(in crate::commands::serve) async fn make_queued<H: Host>(service: &Service<'_, H>, job: Job) {
    let Job {
        work,
        create,
        answer,
    } = job;
    let (id, reply) = match work {
        Work::Payment(order) => (order.id.clone(), make(service, *order).await),
        Work::Consolidation(consolidation) => (
            consolidation.id(),
            super::super::consolidate::make(service, consolidation).await,
        ),
    };
    if let (Err(problem), Some(id)) = (&reply, id)
        && !create.repeat
        && idempotency::made_nothing(problem)
    {
        let _ = service
            .held
            .wallet
            .delete_api_request(idempotency::PAYMENT, &id);
    }
    drop(create);
    let creates = &service.creates;
    creates.held.set(creates.held.get().saturating_sub(1));
    let _ = answer.send(reply);
}

/// Issues the in-person request `body` asks for, under the payment id `id` when it has one.
async fn in_person<H: Host>(
    service: &Service<'_, H>,
    body: CreateBody,
    id: Option<String>,
) -> Reply {
    let issue = checkout::Issue {
        account: body.account(),
        finalize: checkout::finalize_mode(body.finalize.as_deref())?,
        direct: checkout::direct_mode(service, body.direct)?,
        note: Note {
            purpose: body.purpose,
            metadata: body.metadata,
            handoff: None,
        },
        // Settled before the code is issued, so a repeat after a crash issues under the
        // same slate id and the wallet returns the stored code.
        slate_id: id
            .as_deref()
            .map(|id| invoice_slate_id(service, id))
            .transpose()?,
        id,
        amount: body.amount,
        message: body.message,
        ttl_blocks: body.ttl_blocks,
    };
    checkout::make(service, issue).await
}

/// Makes the payment `order` names and answers 201 with it.
async fn make<H: Host>(service: &Service<'_, H>, order: Order) -> Reply {
    let Order {
        body,
        route,
        id,
        invoice,
        purpose,
        spend,
        reach,
    } = order;
    if matches!(route, Route::InPerson) {
        return in_person(service, body, id).await;
    }
    let file = match route {
        Route::File => Some(SlateFile::new(&service.settings.data_dir)?),
        _ => None,
    };
    let epic1 = match &route {
        Route::Epic1(link) => Some(link.clone()),
        _ => None,
    };
    let destination = destination(route, file.as_ref());
    // The slate id is settled and noted before the payment is made, so a call cut short after
    // the payment was stored leaves nothing for its repeat to add.
    let slate = match (&id, invoice) {
        (Some(id), true) => Some(invoice_slate_id(service, id)?),
        (Some(id), false) => Some(id.clone()),
        (None, _) => None,
    };
    let mut note = Note {
        purpose: body.purpose.clone(),
        metadata: body.metadata.clone(),
        handoff: None,
    };
    if let Some(slate) = slate.as_deref() {
        view::put_note(service, slate, &note)?;
    }
    let command = if let Some(link) = epic1 {
        epic1_command(&body, link, spend, slate.clone())
    } else if invoice {
        invoice_command(&body, destination, purpose, slate.clone())
    } else {
        send_command(
            &body,
            destination,
            purpose,
            spend,
            id.clone(),
            (reach, tor_of(&service.settings.relay_tor)),
        )
    };
    // Whether a payment had the id before this call: if so, this call made nothing.
    let existed = match id.as_deref() {
        Some(id) => super::object(service, id).await?.is_some(),
        None => false,
    };
    let report = match super::run(service, command).await {
        Ok(report) => report,
        Err(error) => return failed(service, id.as_deref(), existed, error).await,
    };
    let slate_id = field(&report, "slate_id").ok_or_else(|| {
        Problem::of(
            Category::Internal,
            "internal",
            "the wallet reported no slate id",
        )
    })?;
    if let Some(id) = id.as_deref().filter(|id| *id != slate_id) {
        view::put_alias(service, id, &slate_id)?;
    }
    let handoff = match &file {
        Some(file) => Some(Handoff {
            format: "slate".to_owned(),
            text: std::fs::read_to_string(&file.path).map_err(CliError::io("the payment slate"))?,
            file_name: Some(format!("{slate_id}.slate")),
            qr_frames: None,
            link: None,
        }),
        None => None,
    };
    drop(file);
    if handoff.is_some() || slate.as_deref() != Some(slate_id.as_str()) {
        note.handoff.clone_from(&handoff);
        view::put_note(service, &slate_id, &note)?;
    }
    events::payment(service, &slate_id, Change::Created).await;
    let mut payment = super::object(service, &slate_id)
        .await?
        .ok_or_else(|| super::unknown(&slate_id))?;
    payment.handoff = handoff;
    if let Report::Send(sent) = &report {
        payment.slate_bytes = sent.slate_bytes.and_then(|bytes| u64::try_from(bytes).ok());
        payment.slate_limit = sent.slate_limit.and_then(|limit| u64::try_from(limit).ok());
    }
    created(&payment)
}

/// Where the command sends the slate: an address, a contact, or the file handed back.
fn destination(route: Route, file: Option<&SlateFile>) -> SendDestinationArgs {
    let (to, to_contact) = match route {
        Route::File | Route::InPerson => (None, None),
        Route::Contact(contact) => (None, Some(contact)),
        Route::Address(to) | Route::Epic1(to) => (Some(to), None),
    };
    SendDestinationArgs {
        to,
        to_file: file.map(|file| file.path.clone()),
        to_contact,
    }
}

/// The slate id of the invoice the caller's `id` asks for: `id` itself when it is a random
/// version-4 UUID, else the slate id stored for it, else a new one, stored before the invoice is
/// made so that a repeat issues under the same slate id.
fn invoice_slate_id<H: Host>(service: &Service<'_, H>, id: &str) -> Result<String, Problem> {
    if caller_slate_id(id).is_ok() {
        return Ok(id.to_owned());
    }
    if let Some(slate_id) = view::alias(service, id)? {
        return Ok(slate_id);
    }
    let slate_id = drawn_slate_id()?.to_string();
    view::put_alias(service, id, &slate_id)?;
    Ok(slate_id)
}

/// The command that issues the invoice `body` asks for, under `slate_id` when given.
fn invoice_command(
    body: &CreateBody,
    destination: SendDestinationArgs,
    purpose: Option<PurposeArg>,
    slate_id: Option<String>,
) -> Command {
    let account = AccountArg {
        account: body.account(),
    };
    match destination.to_contact {
        Some(contact) => Command::Contact(ContactArgs {
            command: ContactCommand::Invoice(ContactInvoiceArgs {
                contact: ContactIdArg { contact },
                amount: body.amount.clone(),
                purpose: purpose.unwrap_or(PurposeArg::Request),
                reference: None,
                message: MessageArg {
                    message: body.message.clone(),
                },
                ttl_blocks: body.ttl_blocks,
                account,
                slate_id: SendSlateIdArg { slate_id },
            }),
            offline: false,
        }),
        None => Command::Invoice(InvoiceCommand::Issue(IssueArgs {
            amount: body.amount.clone(),
            destination: DestinationArgs {
                to: destination.to,
                to_file: destination.to_file,
            },
            account,
            message: MessageArg {
                message: body.message.clone(),
            },
            ttl_blocks: body.ttl_blocks,
            slate_id: SendSlateIdArg { slate_id },
        })),
    }
}

/// The command that pays the epic1 `link` as `lepic epic1 pay` does.
fn epic1_command(
    body: &CreateBody,
    link: String,
    spend: SpendArgs,
    slate_id: Option<String>,
) -> Command {
    Command::Epic1(Epic1Args {
        command: Epic1Command::Pay(Epic1PayArgs {
            link: Epic1LinkArg { link },
            amount: Some(body.amount.clone()),
            account: AccountArg {
                account: body.account(),
            },
            message: MessageArg {
                message: body.message.clone(),
            },
            spend,
            slate_id: SendSlateIdArg { slate_id },
            mailboxes: PayMailboxesArg {
                mailboxes: body.mailboxes.clone(),
            },
        }),
        offline: false,
    })
}

/// The tor binary a send over tor runs: the one the settings name for the relay's tor, which
/// the CLI takes from `--tor-binary`. A tor that runs already (`epicbox_tor_socks`) or none
/// leaves a send to an onion address without a binary, which it refuses.
pub(super) fn tor_of(relay_tor: &RelayTor) -> TorBinaryArgs {
    match relay_tor {
        RelayTor::Binary { binary, lib_dir } => TorBinaryArgs {
            tor_binary: Some(binary.clone()),
            lib_dir: lib_dir.clone(),
        },
        RelayTor::Off | RelayTor::Socks(_) => TorBinaryArgs {
            tor_binary: None,
            lib_dir: None,
        },
    }
}

/// The command that makes the send `body` asks for. A purpose goes only to a contact.
fn send_command(
    body: &CreateBody,
    destination: SendDestinationArgs,
    purpose: Option<PurposeArg>,
    spend: SpendArgs,
    slate_id: Option<String>,
    (reach, tor): (HttpReach, TorBinaryArgs),
) -> Command {
    let to_contact = destination.to_contact.is_some();
    Command::Tx(TxCommand::Send(SendArgs {
        amount: Some(body.amount.clone()),
        purpose: purpose.filter(|_| to_contact),
        destination,
        plain_http: PlainHttpArg {
            allow_plain_http: body.allow_plain_http,
        },
        tor,
        fluff: FluffArg { fluff: body.fluff },
        account: AccountArg {
            account: body.account(),
        },
        message: MessageArg {
            message: body.message.clone(),
        },
        spend,
        slate_id: SendSlateIdArg { slate_id },
        reach,
        mailboxes: PayMailboxesArg::default(),
    }))
}

/// The answer to a send that failed: when the payment was made but its delivery failed, 201
/// with the delivery `uncertain`; otherwise the failure.
pub(in crate::commands::serve) async fn failed<H: Host>(
    service: &Service<'_, H>,
    id: Option<&str>,
    existed: bool,
    error: CliError,
) -> Reply {
    let Some(id) = id.filter(|_| !existed) else {
        return Err(error.into());
    };
    let Some(mut payment) = super::object(service, id).await? else {
        return Err(error.into());
    };
    let detail = error.to_string();
    let delivery = payment
        .delivery
        .get_or_insert_with(|| crate::api::model::Delivery {
            state: "uncertain".to_owned(),
            to: None,
            relays_left: None,
            attempts: 1,
            updated_at: payment.updated_at.clone(),
            error: None,
            undelivered: true,
            stuck: false,
            stuck_at: None,
            next_attempt_at: None,
        });
    delivery.state = "uncertain".to_owned();
    // Kept, so a later read shows the error and a cancel does not turn the send into one that
    // was delivered.
    view::put_undelivered(service, &payment.id, &detail)?;
    delivery.error = Some(detail);
    events::payment(service, id, Change::Created).await;
    created(&payment)
}

/// The size on the relay of the slate a send of `request` to the address `to` would post, or
/// of the answer to it, whichever is longer. `None` for an address the send does not post
/// through the relay, resolved as the send resolves it.
async fn slate_size<H: Host>(
    service: &Service<'_, H>,
    request: SendRequest,
    to: String,
) -> Result<Option<PostedSize>, CliError> {
    let destination = DestinationArgs {
        to: Some(to),
        to_file: None,
    };
    let Ok((TRANSPORT_ID, Delivery::Deliver { to }, _)) =
        crate::commands::delivery_to(service.settings, destination, false)
    else {
        return Ok(None);
    };
    let wallet = &service.held.wallet;
    service.held.epicbox.attach_wallet(wallet)?;
    let epicbox: Arc<dyn Method> = service.held.epicbox.clone();
    Ok(wallet
        .estimate_slate_size(&epicbox, request, Some(to))
        .await?)
}

pub(in super::super) async fn estimate<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    request.require(Role::Read)?;
    let (mut body, _) = CreateBody::read(&request)?;
    let invoice = body.is_invoice()?;
    // An `epic:` link may name the amount, as for a create.
    let routed = if body.to.as_deref().is_some_and(|to| {
        recipient::after_scheme(to.trim()).is_some() || recipient::epic1_link(to.trim()).is_some()
    }) {
        Some(settle(service, &mut body, invoice).await?)
    } else {
        route(&mut body).ok()
    };
    let amount = if body.amount == MAX {
        None
    } else {
        Some(
            parse_amount(&body.amount)
                .map_err(|error| Problem::invalid("/amount", format!("amount: {error}")))?,
        )
    };
    check_message(body.message.as_deref())?;
    let spend = body.spend(service.settings.send_ttl_blocks)?;
    let label = body.account();
    let wallet = &service.held.wallet;
    let index = wallet.account(&label).map_err(CliError::from)?.index;
    let options = SelectionOptions {
        minimum_confirmations: spend.min_confirmations,
        change_outputs: NonZeroUsize::new(spend.change_outputs).unwrap_or(NonZeroUsize::MIN),
        strategy: match spend.selection {
            SelectionArg::All => SelectionStrategy::All,
            SelectionArg::Smallest => SelectionStrategy::Smallest,
        },
        ..SelectionOptions::new(index)
    };
    let measured = options.clone();
    let (selection, max_amount) = match amount {
        None => {
            let most = wallet.estimate_max(options).await.map_err(CliError::from)?;
            let max_amount = most.amount.value();
            (most, max_amount)
        }
        Some(amount) => {
            let max_amount = wallet
                .estimate_max(options.clone())
                .await
                .map_or(0, |most| most.amount.value());
            let selection = wallet
                .estimate_fee(amount, options)
                .await
                .map_err(CliError::from)?;
            (selection, max_amount)
        }
    };
    let size = match routed {
        Some(Route::Address(to)) if !invoice && body.via.is_none() => {
            let mut request = SendRequest::new(index, amount.unwrap_or(selection.amount));
            request.minimum_confirmations = measured.minimum_confirmations;
            request.change_outputs = measured.change_outputs;
            request.strategy = measured.strategy;
            request.ttl_blocks = spend.ttl_blocks;
            request.message.clone_from(&body.message);
            slate_size(service, request, to).await?
        }
        _ => None,
    };
    let mut estimate = Estimate::new(
        format_units(selection.fee.value()),
        format_units(max_amount),
    );
    estimate.slate_bytes = size.and_then(|size| u64::try_from(size.bytes).ok());
    estimate.slate_limit = size.and_then(|size| u64::try_from(size.limit).ok());
    with_coins(service, estimate, &label, selection.inputs)
}

/// `estimate`, given the coins `inputs` of the account `label`, as the answer.
pub(in crate::commands::serve) fn with_coins<H: Host>(
    service: &Service<'_, H>,
    mut estimate: Estimate,
    label: &str,
    inputs: Vec<OutputRecord>,
) -> Reply {
    let tip = service
        .held
        .wallet
        .last_confirmed_height()
        .map_err(CliError::from)?
        .map_or(0, lepic_primitives::amount::Height::value);
    for coin in inputs {
        let height = coin.height.value();
        let confirmations = if height == 0 {
            0
        } else {
            tip.checked_sub(height)
                .map_or(0, |gap| gap.saturating_add(1))
        };
        estimate.push_coin(
            coin.id.commitment.to_hex(),
            label.to_owned(),
            format_units(coin.amount.value()),
            crate::commands::status_name(coin.status),
            confirmations,
            coin.id.features.is_coinbase(),
            (
                Some(height).filter(|height| *height != 0),
                Some(coin.lock_height.value()).filter(|height| *height != 0),
            ),
        );
    }
    ok(&estimate)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{tor_of, uuid};
    use crate::settings::RelayTor;

    #[test]
    fn the_tor_binary_of_the_settings_goes_to_a_send_and_a_resend() {
        let binary = RelayTor::Binary {
            binary: PathBuf::from("/opt/tor/tor"),
            lib_dir: Some(PathBuf::from("/opt/tor/lib")),
        };
        let args = tor_of(&binary);
        assert_eq!(args.tor_binary.as_deref(), Some("/opt/tor/tor".as_ref()));
        assert_eq!(args.lib_dir.as_deref(), Some("/opt/tor/lib".as_ref()));
        for none in [
            RelayTor::Off,
            RelayTor::Socks("127.0.0.1:9050".parse().unwrap()),
        ] {
            let args = tor_of(&none);
            assert!(args.tor_binary.is_none() && args.lib_dir.is_none());
        }
    }

    #[test]
    fn ids_are_lowercase_uuids() {
        assert_eq!(
            uuid("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0").ok().as_deref(),
            Some("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
        );
        assert!(uuid("0f1e2d3c4b5a69788796a5b4c3d2e1f0").is_err());
        assert!(uuid("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1fg").is_err());
    }
}
