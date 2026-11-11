// SPDX-License-Identifier: Apache-2.0
//! Coins and being paid: `/outputs`, `/addresses`, `/links`.
//!
//! The addresses are the epic1 addresses of each account and the wallet's Epicbox address; the
//! links are the epic1 links. The wallet keeps neither the text of a link nor what it asks, so
//! serve keeps them beside the link in the wallet's settings, under `api.`, and a link made with
//! the CLI is listed without them.

use lepic_store::{AccountIndex, WalletStore as _};
use lepic_wallet_contacts::{Epic1LinkKind, Epic1LinkRequest, Epic1LinkView, WalletContacts as _};
use serde::{Deserialize, Serialize};

use super::super::Service;
use super::wallet::resolve;
use super::{Reply, begin};
use crate::amount::{format_amount, parse_amount};
use crate::api::list::{ListQuery, Order, Page, number_key};
use crate::api::model::{Address, Link, Output};
use crate::api::{Context, Problem, Request, created, idempotency, ok};
use crate::exit::CliError;
use crate::host::Host;

const STATES: [&str; 4] = ["unspent", "unconfirmed", "locked", "spent"];
const ADDRESS_TYPES: [&str; 4] = ["epicbox", "epic1", "onion", "http"];

pub(super) async fn list_outputs<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let query = request.query();
    let list = ListQuery::parse(query)?;
    let state = query.get("state");
    if let Some(state) = state
        && !STATES.contains(&state)
    {
        return Err(Problem::invalid("/state", "not an output state"));
    }
    let only = match query.get("account") {
        Some(label) => Some(resolve(service, Some(label), "/account")?.index),
        None => None,
    };
    let wallet = &service.held.wallet;
    let mut items = Vec::new();
    for account in wallet.accounts().map_err(CliError::from)? {
        if only.is_some_and(|index| index != account.index) {
            continue;
        }
        for details in wallet.outputs(account.index).map_err(CliError::from)? {
            let record = &details.output;
            let name = state_name(record.status);
            if state.is_some_and(|wanted| wanted != name) {
                continue;
            }
            let commitment = record.id.commitment.to_hex();
            items.push((
                format!("{}{commitment}", number_key(record.height.value())),
                Output {
                    commitment,
                    account: account.label.clone(),
                    amount: format_amount(record.amount),
                    state: name.to_owned(),
                    confirmations: details.confirmations,
                    height: Some(record.height.value()),
                    lock_height: Some(record.lock_height.value()).filter(|height| *height != 0),
                    coinbase: record.id.features.is_coinbase(),
                },
            ));
        }
    }
    items.sort_by(|one, other| one.0.cmp(&other.0));
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page.items.into_iter().map(|(_, output)| output).collect(),
        next_cursor: page.next_cursor,
    })
}

const fn state_name(status: lepic_store::OutputStatus) -> &'static str {
    match status {
        lepic_store::OutputStatus::Unconfirmed => "unconfirmed",
        lepic_store::OutputStatus::Unspent => "unspent",
        lepic_store::OutputStatus::Locked => "locked",
        lepic_store::OutputStatus::Spent => "spent",
    }
}

pub(super) async fn list_addresses<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let query = request.query();
    let list = ListQuery::parse(query)?;
    let kind = query.get("type");
    if let Some(kind) = kind
        && !ADDRESS_TYPES.contains(&kind)
    {
        return Err(Problem::invalid("/type", "not an address type"));
    }
    let index: Option<u32> = query.parsed("index")?;
    let only = match query.get("account") {
        Some(label) => Some(resolve(service, Some(label), "/account")?.index),
        None => None,
    };
    let wallet = &service.held.wallet;
    let book = wallet.contact_book();
    let mut items: Vec<(String, Address)> = Vec::new();
    if kind.is_none_or(|kind| kind == "epicbox") && index.is_none() {
        let default = resolve(service, None, "/account")?;
        if only.is_none_or(|only| only == default.index) {
            let text = service
                .held
                .epicbox
                .attach_wallet(wallet)
                .map_err(CliError::from)?
                .to_string();
            items.push((
                "0".to_owned(),
                Address {
                    kind: "epicbox".to_owned(),
                    text,
                    account: default.label,
                    index: None,
                    issued_at: None,
                    used: false,
                },
            ));
        }
    }
    if kind.is_none_or(|kind| kind == "epic1") {
        for account in wallet.accounts().map_err(CliError::from)? {
            if only.is_some_and(|only| only != account.index) {
                continue;
            }
            let (from, limit) = match index {
                Some(index) => (index, 1),
                None => (0, u32::MAX),
            };
            let page = book
                .epic1_addresses(account.index, from, limit)
                .await
                .map_err(CliError::from)?;
            for view in page.addresses {
                items.push((
                    format!(
                        "1{}{}",
                        number_key(u64::from(account.index.0)),
                        number_key(u64::from(view.index))
                    ),
                    epic1_address(&account.label, view.index, view.address),
                ));
            }
        }
    }
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page.items.into_iter().map(|(_, address)| address).collect(),
        next_cursor: page.next_cursor,
    })
}

fn epic1_address(label: &str, index: u32, text: String) -> Address {
    Address {
        kind: "epic1".to_owned(),
        text,
        account: label.to_owned(),
        index: Some(index),
        issued_at: None,
        used: false,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAddressBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    account: Option<String>,
}

pub(super) async fn create_address<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
    let body: CreateAddressBody = request.json()?;
    let account = resolve(service, body.account.as_deref(), "/account")?;
    let wallet = &service.held.wallet;
    let book = wallet.contact_book();
    let create = match &body.id {
        Some(id) => {
            let value = serde_json::json!({"id": id, "account": body.account});
            Some(begin(service, context, idempotency::ADDRESS, id, &value)?)
        }
        None => None,
    };
    if let (Some(id), Some(create)) = (&body.id, &create)
        && create.repeat
        && let Some(recorded) = read(service, &created_key("address", id))?
        && let Some(index) = recorded.parse::<u32>().ok()
    {
        let page = book
            .epic1_addresses(account.index, index, 1)
            .await
            .map_err(CliError::from)?;
        if let Some(view) = page.addresses.into_iter().next() {
            return ok(&epic1_address(&account.label, view.index, view.address));
        }
    }
    let (index, address) = book
        .epic1_new_address(account.index)
        .await
        .map_err(CliError::from)?;
    if let Some(id) = &body.id {
        write(service, &created_key("address", id), &index.to_string())?;
    }
    created(&epic1_address(&account.label, index, address.encode()))
}

/// What serve keeps of a link beside the wallet's own record of its mailbox.
#[derive(Debug, Serialize, Deserialize)]
struct Kept {
    text: String,
    address_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

const fn kind_part(kind: Epic1LinkKind) -> &'static str {
    match kind {
        Epic1LinkKind::OnScreen => "screen",
        Epic1LinkKind::Printed => "printed",
    }
}

const fn kind_name(kind: Epic1LinkKind) -> &'static str {
    match kind {
        Epic1LinkKind::OnScreen => "on_screen",
        Epic1LinkKind::Printed => "printed",
    }
}

fn link_id(account: AccountIndex, kind: Epic1LinkKind, n: u32) -> String {
    format!("{}.{}.{n}", account.0, kind_part(kind))
}

fn parse_link_id(id: &str) -> Option<(AccountIndex, Epic1LinkKind, u32)> {
    let mut parts = id.split('.');
    let account = parts.next()?.parse().ok()?;
    let kind = match parts.next()? {
        "screen" => Epic1LinkKind::OnScreen,
        "printed" => Epic1LinkKind::Printed,
        _ => return None,
    };
    let n = parts.next()?.parse().ok()?;
    parts
        .next()
        .is_none()
        .then_some((AccountIndex(account), kind, n))
}

fn kept_key(id: &str) -> String {
    format!("api.link.{id}")
}

fn created_key(scope: &str, id: &str) -> String {
    format!("api.created.{scope}.{id}")
}

fn read<H: Host>(service: &Service<'_, H>, key: &str) -> Result<Option<String>, Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    session
        .store
        .read(|repos| repos.setting(key))
        .map_err(|error| Problem::from(CliError::from(error)))
}

fn write<H: Host>(service: &Service<'_, H>, key: &str, value: &str) -> Result<(), Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    session
        .store
        .write(|repos| repos.put_setting(key, value))
        .map_err(|error| Problem::from(CliError::from(error)))
}

fn forget<H: Host>(service: &Service<'_, H>, key: &str) -> Result<(), Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    session
        .store
        .write(|repos| repos.delete_setting(key))
        .map_err(|error| Problem::from(CliError::from(error)))
}

fn kept<H: Host>(service: &Service<'_, H>, id: &str) -> Result<Option<Kept>, Problem> {
    Ok(read(service, &kept_key(id))?.and_then(|text| serde_json::from_str(&text).ok()))
}

fn link_object<H: Host>(
    service: &Service<'_, H>,
    labels: &[(AccountIndex, String)],
    view: &Epic1LinkView,
) -> Result<Link, Problem> {
    let id = link_id(view.account, view.kind, view.n);
    let kept = kept(service, &id)?;
    let account = labels
        .iter()
        .find(|(index, _)| *index == view.account)
        .map(|(_, label)| label.clone())
        .unwrap_or_default();
    Ok(Link {
        id,
        text: kept
            .as_ref()
            .map(|kept| kept.text.clone())
            .unwrap_or_default(),
        kind: kind_name(view.kind).to_owned(),
        account,
        address_index: view
            .index
            .or_else(|| kept.as_ref().map(|kept| kept.address_index))
            .unwrap_or(0),
        amount: kept.as_ref().and_then(|kept| kept.amount.clone()),
        message: kept.as_ref().and_then(|kept| kept.message.clone()),
        relays: view.relays.clone(),
        issued_at: view.issued_at.to_string(),
        last_paid_at: view.used_at.map(|at| at.to_string()),
        retired_at: None,
        metadata: std::collections::BTreeMap::new(),
    })
}

fn labels<H: Host>(service: &Service<'_, H>) -> Result<Vec<(AccountIndex, String)>, Problem> {
    Ok(service
        .held
        .wallet
        .accounts()
        .map_err(CliError::from)?
        .into_iter()
        .map(|account| (account.index, account.label))
        .collect())
}

pub(super) async fn list_links<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let list = ListQuery::parse(request.query())?;
    let labels = labels(service)?;
    let views = service
        .held
        .wallet
        .contact_book()
        .epic1_links()
        .await
        .map_err(CliError::from)?;
    let mut items = Vec::new();
    for view in &views {
        items.push((
            format!(
                "{}{}{}",
                number_key(u64::from(view.account.0)),
                kind_part(view.kind),
                number_key(u64::from(view.n))
            ),
            link_object(service, &labels, view)?,
        ));
    }
    items.sort_by(|one, other| one.0.cmp(&other.0));
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page.items.into_iter().map(|(_, link)| link).collect(),
        next_cursor: page.next_cursor,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateLinkBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    address_index: Option<u32>,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    relays: Vec<String>,
}

#[allow(clippy::too_many_lines)] // Checks, a repeated create, the issue, then the stored record.
pub(super) async fn create_link<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
    let body: CreateLinkBody = request.json()?;
    let kind = match body.kind.as_deref() {
        None | Some("on_screen") => Epic1LinkKind::OnScreen,
        Some("printed") => Epic1LinkKind::Printed,
        Some(_) => return Err(Problem::invalid("/kind", "on_screen or printed")),
    };
    if body.relays.len() > 3 {
        return Err(Problem::invalid("/relays", "at most three relays"));
    }
    let amount = body
        .amount
        .as_deref()
        .map(parse_amount)
        .transpose()
        .map_err(|error| Problem::invalid("/amount", error.to_string()))?;
    let account = resolve(service, body.account.as_deref(), "/account")?;
    let wallet = &service.held.wallet;
    let book = wallet.contact_book();
    let create = match &body.id {
        Some(id) => {
            let value = serde_json::json!({
                "id": id,
                "account": body.account,
                "address_index": body.address_index,
                "amount": body.amount,
                "message": body.message,
                "kind": body.kind,
                "relays": body.relays,
            });
            Some(begin(service, context, idempotency::LINK, id, &value)?)
        }
        None => None,
    };
    if let (Some(id), Some(create)) = (&body.id, &create)
        && create.repeat
        && let Some(link) = read(service, &created_key("link", id))?
        && let Some((index, link_kind, n)) = parse_link_id(&link)
    {
        let labels = labels(service)?;
        let views = book.epic1_links().await.map_err(CliError::from)?;
        if let Some(view) = views
            .iter()
            .find(|view| view.account == index && view.kind == link_kind && view.n == n)
        {
            return ok(&link_object(service, &labels, view)?);
        }
    }
    let address_index = match body.address_index {
        Some(index) => index,
        None => {
            book.epic1_addresses(account.index, 0, 1)
                .await
                .map_err(CliError::from)?
                .highest
        }
    };
    let relays = super::super::super::contact::relays_in_mode(
        &service.held,
        false,
        false,
        &service.settings.servers.meeting_relays,
    );
    let issued = book
        .epic1_link(
            &relays,
            Epic1LinkRequest {
                account: account.index,
                index: address_index,
                amount,
                message: body.message.clone(),
                kind,
                relays: body.relays.clone(),
            },
        )
        .await
        .map_err(CliError::from)?;
    let id = link_id(account.index, issued.kind, issued.n);
    let record = Kept {
        text: issued.link,
        address_index: issued.index,
        amount: body.amount.clone(),
        message: body.message.clone(),
    };
    write(
        service,
        &kept_key(&id),
        &serde_json::to_string(&record).map_err(|error| Problem::usage(error.to_string()))?,
    )?;
    if let Some(caller) = &body.id {
        write(service, &created_key("link", caller), &id)?;
    }
    let views = book.epic1_links().await.map_err(CliError::from)?;
    let labels = labels(service)?;
    let view = views
        .iter()
        .find(|view| {
            view.account == account.index && view.kind == issued.kind && view.n == issued.n
        })
        .ok_or_else(|| Problem::not_found("the link was not stored"))?;
    created(&link_object(service, &labels, view)?)
}

pub(super) async fn retire_link<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let id = request.param("id")?;
    let Some((account, Epic1LinkKind::Printed, n)) = parse_link_id(id) else {
        return Err(Problem::not_found("no printed link has this id"));
    };
    let book = service.held.wallet.contact_book();
    let labels = labels(service)?;
    let views = book.epic1_links().await.map_err(CliError::from)?;
    let Some(view) = views
        .iter()
        .find(|view| view.account == account && view.kind == Epic1LinkKind::Printed && view.n == n)
    else {
        return Err(Problem::not_found("no printed link has this id"));
    };
    let mut link = link_object(service, &labels, view)?;
    book.epic1_retire(account, n)
        .await
        .map_err(CliError::from)?;
    forget(service, &kept_key(id))?;
    link.retired_at = Some(service.held.wallet.ports().clock.now().to_string());
    ok(&link)
}
