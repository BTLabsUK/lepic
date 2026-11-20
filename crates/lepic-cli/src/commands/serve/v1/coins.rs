// SPDX-License-Identifier: Apache-2.0
//! Coins and being paid: `/outputs`, `/addresses`, `/links`.
//!
//! The addresses are the epic1 address of each account and the wallet's legacy Epicbox address.
//! A link is the account's epic1 address with what it asks; the wallet stores nothing for it.

use lepic_wallet_contacts::{Epic1LinkRequest, WalletContacts as _};
use serde::Deserialize;

use super::super::Service;
use super::Reply;
use super::wallet::resolve;
use crate::amount::{format_amount, parse_amount};
use crate::api::list::{ListQuery, Order, Page, number_key};
use crate::api::model::{Address, Link, Output};
use crate::api::{Context, Problem, Request, ok};
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

/// The epic1 address of each account and the legacy Epicbox address, which is the default
/// account's: the Epicbox identity is that account's key.
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
    let only = match query.get("account") {
        Some(label) => Some(resolve(service, Some(label), "/account")?.index),
        None => None,
    };
    let wallet = &service.held.wallet;
    let book = wallet.contact_book();
    let mut items: Vec<(String, Address)> = Vec::new();
    if kind.is_none_or(|kind| kind == "epicbox") {
        let default = resolve(service, None, "/account")?;
        if only.is_none_or(|only| only == default.index) {
            let text = service
                .held
                .epicbox
                .attach_wallet(wallet)
                .map_err(CliError::from)?
                .to_string();
            items.push(("0".to_owned(), address("epicbox", default.label, text)));
        }
    }
    if kind.is_none_or(|kind| kind == "epic1") {
        for account in wallet.accounts().map_err(CliError::from)? {
            if only.is_some_and(|only| only != account.index) {
                continue;
            }
            let text = book
                .epic1_address(account.index)
                .map_err(CliError::from)?
                .encode();
            items.push((
                format!("1{}", number_key(u64::from(account.index.0))),
                address("epic1", account.label, text),
            ));
        }
    }
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page.items.into_iter().map(|(_, address)| address).collect(),
        next_cursor: page.next_cursor,
    })
}

fn address(kind: &str, account: String, text: String) -> Address {
    Address {
        kind: kind.to_owned(),
        text,
        account,
        used: false,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateLinkBody {
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// Makes the link: the account's epic1 address with what the body asks. Nothing is stored, so
/// the same body gives the same link again.
pub(super) async fn create_link<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    if !request.has_body() {
        return Err(Problem::bad_request(
            "invalid_body",
            "the request body must be a JSON object: send {} for a link without an amount",
        ));
    }
    let body: CreateLinkBody = request.json()?;
    let amount = body
        .amount
        .as_deref()
        .map(parse_amount)
        .transpose()
        .map_err(|error| Problem::invalid("/amount", error.to_string()))?;
    let account = resolve(service, body.account.as_deref(), "/account")?;
    let relays = super::super::super::contact::relays_in_mode(
        &service.held,
        false,
        &service.settings.servers.mailboxes.current(),
    );
    let issued = service
        .held
        .wallet
        .contact_book()
        .epic1_link(
            &relays,
            Epic1LinkRequest {
                account: account.index,
                amount,
                message: body.message.clone(),
                entries: Vec::new(),
            },
        )
        .map_err(CliError::from)?;
    ok(&Link {
        text: issued.link,
        account: account.label,
        amount: body.amount,
        message: body.message,
    })
}
