// SPDX-License-Identifier: Apache-2.0
//! The owner routes. Each one builds the arguments of the CLI command it stands for; the
//! command runs as `lepic` runs it and its JSON report is the response body.

use hyper::Response;
use lepic_wallet::selection::SelectionOptions;
use lepic_wallet::slate::{MediaType, WireSlate};
use serde::Deserialize;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::events::{self, EventReport};
use super::{Api, Body, Call, InFlight, Problem, Request, report, response};
use crate::cli::{
    AccountArg, Command, DEFAULT_CHANGE_OUTPUTS, FluffArg, ListArgs, MessageArg, NodeCommand,
    PlainHttpArg, SelectionArg, SendArgs, SendDestinationArgs, SendSlateIdArg, SpendArgs,
    TorBinaryArgs, TxCommand, TxShowArgs, WalletCommand,
};
use crate::commands::is_onion;
use crate::output::{
    AddressReport, FinalizeReport, InfoReport, NodeStatusReport, OutputsReport, PasswordReport,
    SendReport, ServeStatusReport, SlateReceiveReport, TxListReport, TxReport,
};

type Answer = Result<Response<Body>, Problem>;

/// The account a listing covers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountQuery {
    account: Option<String>,
}

/// An Epicbox send.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendBody {
    /// EPIC, as a decimal string, for example `"1.5"`.
    amount: String,
    /// The Epicbox address the slate goes to.
    to: String,
    /// A random version-4 UUID the caller stores before sending. A send made again under it
    /// sends nothing and reports the first send with `repeated: true`.
    slate_id: Option<String>,
    /// The account label; the default account when absent.
    account: Option<String>,
    /// A message to the receiver, signed with the slate.
    message: Option<String>,
    /// Confirmations an output needs before it is spent.
    min_confirmations: Option<u64>,
    /// Outputs the change is split into.
    change_outputs: Option<usize>,
}

/// A slate a sender gave this wallet.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiveBody {
    /// The slate, V2 or V3 slate JSON.
    slate: String,
    /// The account the payment goes to; the default account when absent.
    account: Option<String>,
    /// A message to the sender, signed with the reply.
    message: Option<String>,
}

/// The receiver's answer to a send, or the payer's answer to an invoice.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizeBody {
    /// The answer slate, V2 or V3 slate JSON.
    slate: String,
    /// Broadcast to all peers at once instead of through the stem phase.
    #[serde(default)]
    fluff: bool,
}

/// The vault's password, and the one it is re-encrypted under.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordBody {
    #[serde(deserialize_with = "secret")]
    #[schema(value_type = String, format = Password)]
    current_password: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    #[schema(value_type = String, format = Password)]
    new_password: Zeroizing<String>,
}

fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// This document
#[utoipa::path(
    get,
    path = "/v1/openapi.json",
    tag = "service",
    responses((status = 200, description = "The OpenAPI document", content_type = "application/json")),
)]
pub(crate) async fn openapi_document(api: &Api<'_>, _request: Request) -> Answer {
    Ok(response(
        hyper::StatusCode::OK,
        "application/json",
        api.document.clone(),
    ))
}

/// The running serve
///
/// Uptime, the API's request counts, the listeners, the wallet's height and the node's tip,
/// and the maintenance results. Facts only: thresholds belong to the monitor.
#[utoipa::path(
    get,
    path = "/v1/status",
    tag = "service",
    responses((status = 200, body = ServeStatusReport)),
)]
pub(crate) async fn status(api: &Api<'_>, _request: Request) -> Answer {
    Ok(report(&api.owner.status(api.requests())?))
}

/// The wallet's events
///
/// A server-sent event stream: each event's `event` field is its `kind` and its `data` line
/// is the event as JSON. A client that falls behind gets a `lagged` event saying how many it
/// missed, and the stream goes on.
#[utoipa::path(
    get,
    path = "/v1/events",
    tag = "service",
    responses((status = 200, content_type = "text/event-stream", body = EventReport)),
)]
pub(crate) async fn events(api: &Api<'_>, _request: Request) -> Answer {
    let stream = events::stream(
        api.owner.events(),
        api.stop.clone(),
        InFlight::new(&api.in_flight),
    );
    let mut response = Response::new(stream);
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

/// The wallet's balances, after a refresh
#[utoipa::path(
    get,
    path = "/v1/wallet",
    tag = "wallet",
    responses((status = 200, body = InfoReport)),
)]
pub(crate) async fn wallet_info(api: &Api<'_>, _request: Request) -> Answer {
    api.run(Call::Command(Command::Wallet(WalletCommand::Info)))
        .await
}

/// The wallet's Epicbox address
#[utoipa::path(
    get,
    path = "/v1/wallet/address",
    tag = "wallet",
    responses((status = 200, body = AddressReport)),
)]
pub(crate) async fn wallet_address(api: &Api<'_>, _request: Request) -> Answer {
    api.run(Call::Command(Command::Wallet(WalletCommand::Address)))
        .await
}

/// Change the wallet's password
///
/// Re-encrypts the vault under the new password.
#[utoipa::path(
    put,
    path = "/v1/wallet/password",
    tag = "wallet",
    request_body = PasswordBody,
    responses((status = 200, body = PasswordReport)),
)]
pub(crate) async fn change_password(api: &Api<'_>, request: Request) -> Answer {
    let body: PasswordBody = request.json()?;
    api.run(Call::Password {
        current: body.current_password,
        new: body.new_password,
    })
    .await
}

/// The wallet's outputs, spent ones included
#[utoipa::path(
    get,
    path = "/v1/outputs",
    tag = "wallet",
    params(("account" = Option<String>, Query, description = "Account label; the default account when absent")),
    responses((status = 200, body = OutputsReport)),
)]
pub(crate) async fn outputs(api: &Api<'_>, request: Request) -> Answer {
    let query: AccountQuery = request.query()?;
    let account = account(query.account);
    api.run(Call::Command(Command::Wallet(WalletCommand::Outputs(
        account,
    ))))
    .await
}

/// The node's version and chain tip
#[utoipa::path(
    get,
    path = "/v1/node",
    tag = "node",
    responses((status = 200, body = NodeStatusReport)),
)]
pub(crate) async fn node_status(api: &Api<'_>, _request: Request) -> Answer {
    api.run(Call::Command(Command::Node(NodeCommand::Status)))
        .await
}

/// The account's transactions
#[utoipa::path(
    get,
    path = "/v1/transactions",
    tag = "transactions",
    params(("account" = Option<String>, Query, description = "Account label; the default account when absent")),
    responses((status = 200, body = TxListReport)),
)]
pub(crate) async fn transactions(api: &Api<'_>, request: Request) -> Answer {
    let query: AccountQuery = request.query()?;
    let args = ListArgs {
        account: account(query.account),
    };
    api.run(Call::Command(Command::Tx(TxCommand::List(args))))
        .await
}

/// One transaction
#[utoipa::path(
    get,
    path = "/v1/transactions/{tx_id}",
    tag = "transactions",
    params(("tx_id" = u32, Path, description = "Local transaction id, as the list shows it")),
    responses((status = 200, body = TxReport)),
)]
pub(crate) async fn transaction(api: &Api<'_>, request: Request) -> Answer {
    let tx_id = request
        .param("tx_id")?
        .parse()
        .map_err(|_| Problem::usage("tx_id is not a transaction id"))?;
    let args = TxShowArgs {
        tx_id: Some(tx_id),
        slate_id: SendSlateIdArg { slate_id: None },
    };
    api.run(Call::Command(Command::Tx(TxCommand::Show(args))))
        .await
}

/// Send over Epicbox
///
/// With a `slate_id`, a repeated request is safe: it reports the first send.
#[utoipa::path(
    post,
    path = "/v1/transactions",
    tag = "transactions",
    request_body = SendBody,
    responses((status = 200, body = SendReport)),
)]
pub(crate) async fn send(api: &Api<'_>, request: Request) -> Answer {
    let body: SendBody = request.json()?;
    if is_onion(&body.to) || body.to.contains("://") {
        return Err(Problem::usage("the API sends over Epicbox only"));
    }
    let args = SendArgs {
        amount: body.amount,
        destination: SendDestinationArgs {
            to: Some(body.to),
            to_file: None,
            to_contact: None,
        },
        purpose: None,
        plain_http: PlainHttpArg {
            allow_plain_http: false,
        },
        tor: TorBinaryArgs {
            tor_binary: None,
            lib_dir: None,
        },
        fluff: FluffArg { fluff: false },
        account: account(body.account),
        message: MessageArg {
            message: body.message,
        },
        spend: SpendArgs {
            min_confirmations: body
                .min_confirmations
                .unwrap_or(SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS),
            change_outputs: body.change_outputs.unwrap_or(DEFAULT_CHANGE_OUTPUTS),
            selection: SelectionArg::Smallest,
            ttl_blocks: None,
        },
        slate_id: SendSlateIdArg {
            slate_id: body.slate_id,
        },
    };
    api.run(Call::Command(Command::Tx(TxCommand::Send(args))))
        .await
}

/// Receive a slate
///
/// The reply slate for the sender is in the response.
#[utoipa::path(
    post,
    path = "/v1/slates/receive",
    tag = "slates",
    request_body = ReceiveBody,
    responses((status = 200, body = SlateReceiveReport)),
)]
pub(crate) async fn receive(api: &Api<'_>, request: Request) -> Answer {
    let body: ReceiveBody = request.json()?;
    api.run(Call::Receive {
        wire: WireSlate::text(MediaType::JSON, body.slate),
        account: account(body.account).account,
        message: body.message,
    })
    .await
}

/// Finalize and post a slate
#[utoipa::path(
    post,
    path = "/v1/slates/finalize",
    tag = "slates",
    request_body = FinalizeBody,
    responses((status = 200, body = FinalizeReport)),
)]
pub(crate) async fn finalize(api: &Api<'_>, request: Request) -> Answer {
    let body: FinalizeBody = request.json()?;
    api.run(Call::Finalize {
        wire: WireSlate::text(MediaType::JSON, body.slate),
        fluff: body.fluff,
    })
    .await
}

fn account(label: Option<String>) -> AccountArg {
    AccountArg {
        account: label.unwrap_or_else(|| lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned()),
    }
}
