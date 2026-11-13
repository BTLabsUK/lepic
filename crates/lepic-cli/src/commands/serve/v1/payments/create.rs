// SPDX-License-Identifier: Apache-2.0
//! `POST /payments` and `POST /payments/estimate`.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use lepic_methods::http::{ListenerUrl, PlainHttp};
use lepic_wallet::selection::{SelectionOptions, SelectionStrategy};
use serde::Deserialize;
use serde_json::Value;

use super::super::super::Service;
use super::super::Reply;
use super::super::events::{self, Change};
use super::super::handed;
use super::view::{self, Note};
use super::{check_metadata, default_spend};
use crate::amount::{format_units, parse_amount};
use crate::api::model::{Estimate, Handoff};
use crate::api::{Category, Context, Listener, Problem, Request, created, idempotency, ok};
use crate::api_clients::Role;
use crate::cli::{
    AccountArg, Command, ContactArgs, ContactCommand, ContactIdArg, ContactInvoiceArgs,
    DestinationArgs, Epic1Args, Epic1Command, Epic1LinkArg, Epic1PayArgs, FluffArg, HttpReach,
    InvoiceCommand, IssueArgs, LegacyArg, MessageArg, PlainHttpArg, PurposeArg, SelectionArg,
    SendArgs, SendDestinationArgs, SendSlateIdArg, SpendArgs, TorBinaryArgs, TxCommand,
};
use crate::commands::contact::SlateFile;
use crate::commands::{caller_slate_id, drawn_slate_id};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::Report;

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
    #[serde(default)]
    message: Option<String>,
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
    /// Taken, not used yet: a send goes to the relay the address names.
    #[serde(default, rename = "relay_ok")]
    _relay_ok: Option<bool>,
    #[serde(default)]
    legacy: bool,
    #[serde(default = "yes")]
    deliver: bool,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
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

    fn spend(&self) -> Result<SpendArgs, Problem> {
        let defaults = default_spend();
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
}

/// The route of `body`, or 400 for one this wallet cannot take yet. A classic `epic:` link is
/// settled into the body's amount and message and routed as its address.
fn route(body: &mut CreateBody) -> Result<Route, Problem> {
    let via = body.via.as_deref();
    if !body.deliver || via == Some("file") {
        return Ok(Route::File);
    }
    if let Some(via @ ("in_person" | "link" | "peer" | "chain")) = via {
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
    if handed::is_epic1(to) {
        return Ok(Route::Epic1(to.to_owned()));
    }
    if to.starts_with("epic:") {
        let link = handed::classic(to)
            .ok_or_else(|| Problem::invalid("/to", "to is not an epic: link with an address"))?;
        agree(&mut body.amount, link.amount.as_deref())?;
        if body.message.is_none() {
            body.message = link.message;
        }
        return Ok(Route::Address(link.address));
    }
    Ok(Route::Address(to.to_owned()))
}

/// [`route`], with the amount an epic1 link asks settled into the body as well.
async fn settle<H: Host>(
    service: &Service<'_, H>,
    body: &mut CreateBody,
    invoice: bool,
) -> Result<Route, Problem> {
    let route = route(body)?;
    if let Route::Epic1(link) = &route {
        if invoice {
            return Err(Problem::invalid(
                "/to",
                "an invoice is not sent to an epic1 link",
            ));
        }
        let (asked, _) = handed::epic1_terms(service, link).await?;
        agree(&mut body.amount, asked.as_deref())?;
    }
    Ok(route)
}

/// Settles `amount` with what an `epic:` link `asked`: taken from the link when left out, else
/// the same, or 400 at `/amount`.
fn agree(amount: &mut String, asked: Option<&str>) -> Result<(), Problem> {
    let parse = |text: &str| {
        parse_amount(text).map_err(|error| Problem::invalid("/amount", format!("amount: {error}")))
    };
    match (amount.is_empty(), asked) {
        (true, Some(asked)) => asked.clone_into(amount),
        (true, None) => {
            return Err(Problem::invalid(
                "/amount",
                "amount is required: the link names none",
            ));
        }
        (false, Some(asked)) if parse(amount)? != parse(asked)? => {
            return Err(Problem::invalid(
                "/amount",
                "amount is not the amount the link asks",
            ));
        }
        _ => {}
    }
    Ok(())
}

/// `id` as a lowercase UUID, or 400 at `/id`.
fn uuid(id: &str) -> Result<String, Problem> {
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

#[allow(clippy::too_many_lines)] // validate, record, run and answer in one pass
pub(in super::super) async fn create<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
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
    check_metadata(&body.metadata)?;
    let purpose = body.purpose()?;
    let spend = body.spend()?;
    let reach = reach(&request);
    if let Route::Address(to) = &route {
        guard(reach, to)?;
    }
    let _create = match &id {
        Some(id) => {
            // A new id must not name a payment or an alias already: the call would take that
            // payment over. A repeat (its record exists) is checked by `begin` as before.
            if service
                .held
                .wallet
                .api_request(idempotency::PAYMENT, id)
                .map_err(CliError::from)?
                .is_none()
                && view::find(service, id).await?.is_some()
            {
                return Err(Problem::conflict(
                    "idempotency_mismatch",
                    "this id already names a payment",
                )
                .with_param("/id"));
            }
            let create = super::super::begin(service, context, idempotency::PAYMENT, id, &value)?;
            if create.repeat
                && let Some(payment) = super::object(service, id).await?
            {
                return ok(&payment);
            }
            Some(create)
        }
        None => None,
    };
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
        send_command(&body, destination, purpose, spend, id.clone(), reach)
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
    created(&payment)
}

/// Where the command sends the slate: an address, a contact, or the file handed back.
fn destination(route: Route, file: Option<&SlateFile>) -> SendDestinationArgs {
    let (to, to_contact) = match route {
        Route::File => (None, None),
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
            epicbox_off: false,
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
            hosts_ok: false,
            slate_id: SendSlateIdArg { slate_id },
        }),
        offline: false,
        epicbox_off: false,
    })
}

/// The command that makes the send `body` asks for. A purpose goes only to a contact.
fn send_command(
    body: &CreateBody,
    destination: SendDestinationArgs,
    purpose: Option<PurposeArg>,
    spend: SpendArgs,
    slate_id: Option<String>,
    reach: HttpReach,
) -> Command {
    let to_contact = destination.to_contact.is_some();
    Command::Tx(TxCommand::Send(SendArgs {
        amount: body.amount.clone(),
        purpose: purpose.filter(|_| to_contact),
        destination,
        plain_http: PlainHttpArg {
            allow_plain_http: body.allow_plain_http,
        },
        tor: TorBinaryArgs {
            tor_binary: None,
            lib_dir: None,
        },
        fluff: FluffArg { fluff: body.fluff },
        account: AccountArg {
            account: body.account(),
        },
        message: MessageArg {
            message: body.message.clone(),
        },
        spend,
        slate_id: SendSlateIdArg { slate_id },
        legacy: LegacyArg {
            legacy: body.legacy,
        },
        reach,
    }))
}

/// The answer to a send that failed: when the payment was made but its delivery failed, 201
/// with the delivery `uncertain`; otherwise the failure.
async fn failed<H: Host>(
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
        });
    delivery.state = "uncertain".to_owned();
    delivery.error = Some(detail);
    events::payment(service, id, Change::Created).await;
    created(&payment)
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
    if body
        .to
        .as_deref()
        .is_some_and(|to| to.trim().starts_with("epic:"))
    {
        settle(service, &mut body, invoice).await?;
    }
    let amount = if body.amount == MAX {
        None
    } else {
        Some(
            parse_amount(&body.amount)
                .map_err(|error| Problem::invalid("/amount", format!("amount: {error}")))?,
        )
    };
    let spend = body.spend()?;
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
    let tip = wallet
        .last_confirmed_height()
        .map_err(CliError::from)?
        .map_or(0, lepic_primitives::amount::Height::value);
    let mut estimate = Estimate::new(
        format_units(selection.fee.value()),
        format_units(max_amount),
    );
    for coin in selection.inputs {
        let height = coin.height.value();
        let confirmations = if height == 0 {
            0
        } else {
            tip.checked_sub(height)
                .map_or(0, |gap| gap.saturating_add(1))
        };
        estimate.push_coin(
            coin.id.commitment.to_hex(),
            label.clone(),
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
    use super::uuid;

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
