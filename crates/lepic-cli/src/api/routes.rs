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
use super::{Api, Body, Call, InFlight, Listener, Problem, Request, report, response};
use crate::cli::{
    AccountArg, Command, ContactAcceptArgs, ContactArgs, ContactCardArgs, ContactCommand,
    ContactEnterArgs, ContactIdArg, ContactInviteArgs, ContactKeyCheckArgs, ContactKeysArgs,
    ContactLabelArgs, ContactLinkArg, ContactMoveArgs, ContactMoveHomeArgs, ContactNameArg,
    ContactPayloadAckArgs, ContactPayloadArgs, ContactPayloadCommand, ContactPayloadPostArgs,
    ContactRequestArgs, ContactSasArgs, ContactScanArgs, ContactSwitchArgs, DEFAULT_CHANGE_OUTPUTS,
    DEFAULT_CONTACT_NAME, DomainArgs, DomainCommand, EpicboxCommand, FluffArg, InviteExpiryArg,
    KeysArg, ListArgs, ListingArgs, MAX_DRAIN_DAYS, MessageArg, NodeCommand, OnOffArg, PeerArgs,
    PlainHttpArg, PostArgs, ProfileCommand, ProfileSetArgs, SasArg, SelectionArg, SendArgs,
    SendDestinationArgs, SendSlateIdArg, SpendArgs, TorBinaryArgs, TxCommand, TxIdArgs, TxShowArgs,
    WalletCommand, WalletScanArgs,
};
use crate::commands::is_onion;
use crate::output::{
    AddressReport, ContactAcceptReport, ContactBackupReport, ContactCardReport, ContactCheckReport,
    ContactCollectReport, ContactImportReport, ContactInviteReport, ContactInvoiceListReport,
    ContactKeyCheckReport, ContactLinkReport, ContactListReport, ContactMoveHomeReport,
    ContactPayloadAckReport, ContactPayloadListReport, ContactPayloadPostReport,
    ContactPreviewReport, ContactQuarantineReport, ContactRemoveReport, ContactReport,
    EpicboxStatusReport, FinalizeReport, InfoReport, MethodsReport, NodeStatusReport,
    OutputsReport, PasswordReport, PeerReport, PostReport, ProfileDomainAttachReport,
    ProfileDomainDocumentReport, ProfileDomainShowReport, ProfileSetReport, ProfileShowReport,
    Report, SendReport, ServeStatusReport, SlateReceiveReport, TxListReport, TxReport,
    TxStateReport, WalletScanReport,
};

type Answer = Result<Response<Body>, Problem>;

/// The account a listing covers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountQuery {
    account: Option<String>,
}

/// A send over one of the registered methods.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendBody {
    /// EPIC, as a decimal string, for example `"1.5"`.
    amount: String,
    /// The address or URL the slate goes to; the method decides which it is.
    to: String,
    /// The method the slate goes over: one of `GET /v1/methods`. Epicbox when absent.
    method: Option<String>,
    /// A random version-4 UUID the caller stores before sending. A send made again under it
    /// sends nothing and reports the first send with `repeated: true`. Required on the owner
    /// TLS listener.
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

/// Whether a posted transaction goes out at once.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostBody {
    /// Broadcast to all peers at once instead of through the stem phase.
    #[serde(default)]
    fluff: bool,
}

/// How far a wallet scan reaches.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanBody {
    /// Start at this height; 0 scans the whole chain. Not with `reset_chain`.
    start_height: Option<u64>,
    /// Also unlock locked outputs found on chain and delete unconfirmed outputs not found,
    /// cancelling their transactions.
    #[serde(default)]
    delete_unconfirmed: bool,
    /// Forget the chain heights the wallet stored and scan from genesis.
    #[serde(default)]
    reset_chain: bool,
}

/// The profile this wallet tells its contacts: exactly one of the two fields.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileBody {
    /// Bit names, `no-payments` and `automated`; empty clears the profile.
    names: Option<String>,
    /// The profile as a number 0 to 65535 or 0x hex.
    bits: Option<String>,
}

/// The relays a domain file names.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainFileBody {
    /// Relays as `host:port`.
    #[serde(default)]
    relays: Vec<String>,
}

/// A change to a contact; at least one field.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactUpdateBody {
    /// Your name for the contact.
    label: Option<String>,
    /// Whether the contact may send invoices; it has to be verified.
    allow_invoices: Option<bool>,
}

/// An invite to pair.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InviteBody {
    /// The name this wallet gives itself in the invite; `LEPIC` when absent.
    name: Option<String>,
    /// How long the invite may be answered; one day when absent.
    expiry: Option<InviteExpiryArg>,
    /// Also offer five pairing words that find the invite.
    #[serde(default)]
    pairing_words: bool,
}

/// A pairing request to a wallet's payments address.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestBody {
    /// The wallet's Epicbox address.
    address: String,
    /// The name this wallet gives itself; `LEPIC` when absent.
    name: Option<String>,
}

/// A pairing link.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkBody {
    /// The `epiccash://` link.
    link: String,
}

/// An invite answered.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptBody {
    /// The invite's `epiccash://` link.
    link: String,
    /// The name this wallet gives itself in the reply; `LEPIC` when absent.
    name: Option<String>,
    /// Answer with a reply link to send by hand instead of posting it.
    #[serde(default)]
    by_hand: bool,
}

/// A link or the five pairing words of an invite.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnterBody {
    /// One link, or the five pairing words.
    input: Vec<String>,
}

/// The name a card carries.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CardBody {
    /// The name this wallet gives itself; `LEPIC` when absent.
    name: Option<String>,
}

/// The other phone's card.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanCardBody {
    /// The id the card route answered on this wallet.
    contact: String,
    /// The other phone's `epiccash://contact/` link.
    link: String,
}

/// The verdict on the four SAS words.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SasBody {
    result: SasArg,
}

/// The older pairing with the same contact.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyCheckBody {
    /// The older pairing's id.
    old: String,
}

/// What to do with a pairing in keys-changed.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeysBody {
    choice: KeysArg,
}

/// The relay a contact asked for.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MoveBody {
    /// The relay host, as the contact shows it.
    host: String,
}

/// The relay this wallet moves home to.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MoveHomeBody {
    /// The relay, `domain[:port]`.
    host: String,
    /// Days to keep reading the old mailboxes, up to `MAX_DRAIN_DAYS`; 0 when absent.
    drain_days: Option<u16>,
}

/// Pairing records from a contact backup.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportBody {
    /// The document the export route answered.
    backup: String,
}

/// Bytes for a contact.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadBody {
    /// The payload as hex digits.
    payload: String,
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

/// The methods serve offers
///
/// Each registered method, in registry order, and what it can do: deliver a slate, listen for
/// slates, exchange a slate with the caller, send notices, and what its slates may carry. A
/// send names one of these ids in its `method` field.
#[utoipa::path(
    get,
    path = "/v1/methods",
    tag = "service",
    responses((status = 200, body = MethodsReport)),
)]
pub(crate) async fn methods(api: &Api<'_>, _request: Request) -> Answer {
    api.run(Call::Methods).await
}

/// The wallet's events
///
/// A server-sent event stream: each event's `event` field is its `kind` and its `data` line
/// is the event as JSON. A client that falls behind gets a `lagged` event saying how many it
/// missed, and the stream goes on. A stream over the owner TLS listener ends at the
/// connection age limit, and the client opens it again.
#[utoipa::path(
    get,
    path = "/v1/events",
    tag = "service",
    responses((status = 200, content_type = "text/event-stream", body = EventReport)),
)]
pub(crate) async fn events(api: &Api<'_>, request: Request) -> Answer {
    let stream = events::stream(
        api.owner.events(),
        request.closing,
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
/// Re-encrypts the vault under the new password. Answered on the socket only: the TLS listener
/// refuses it with a 403 `usage` problem.
#[utoipa::path(
    put,
    path = "/v1/wallet/password",
    tag = "wallet",
    request_body = PasswordBody,
    responses((status = 200, body = PasswordReport)),
    extensions(("x-socket-only" = json!(true))),
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
    let args = TxShowArgs {
        tx_id: Some(tx_id(&request)?.tx_id),
        slate_id: SendSlateIdArg { slate_id: None },
    };
    api.run(Call::Command(Command::Tx(TxCommand::Show(args))))
        .await
}

/// Send a slate
///
/// The slate goes to the address or URL in `to` over the method named in `method`, Epicbox
/// when absent. The API sends over `epicbox` and `http`. With a `slate_id`, a repeated request is safe: it reports the first send.
#[utoipa::path(
    post,
    path = "/v1/transactions",
    tag = "transactions",
    request_body = SendBody,
    responses((status = 200, body = SendReport)),
)]
pub(crate) async fn send(api: &Api<'_>, request: Request) -> Answer {
    let body: SendBody = request.json()?;
    if request.listener == Listener::Tls && body.slate_id.is_none() {
        return Err(Problem::usage(
            "a send over the owner TLS listener needs a slate_id, so a repeated request is safe",
        ));
    }
    match body.method.as_deref() {
        None => {
            if is_onion(&body.to) || body.to.contains("://") {
                return Err(Problem::usage("the API sends over Epicbox only"));
            }
        }
        Some(id) => send_method(api, id, &body.to).await?,
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

/// Checks that `id` names a registered method the API sends over, and that `to` is a
/// destination it delivers to.
async fn send_method(api: &Api<'_>, id: &str, to: &str) -> Result<(), Problem> {
    let Report::Methods(offered) = api.owner.call(Call::Methods).await? else {
        return Err(Problem::usage("serve did not list its methods"));
    };
    if !offered.methods.iter().any(|method| method.id == id) {
        let ids: Vec<&str> = offered
            .methods
            .iter()
            .map(|method| method.id.as_str())
            .collect();
        return Err(Problem::usage(format!(
            "unknown method {id}; serve offers: {}",
            ids.join(", ")
        )));
    }
    match id {
        "epicbox" if is_onion(to) || to.contains("://") => Err(Problem::usage(
            "an Epicbox send goes to an Epicbox address, not an onion or a URL",
        )),
        "epicbox" => Ok(()),
        "http" if to.contains("://") => Ok(()),
        "http" => Err(Problem::usage("an HTTP send goes to a URL")),
        other => Err(Problem::usage(format!(
            "the API does not send over {other} today"
        ))),
    }
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

/// Cancel a transaction that is not posted
#[utoipa::path(
    post,
    path = "/v1/transactions/{tx_id}/cancel",
    tag = "transactions",
    params(("tx_id" = u32, Path, description = "Local transaction id, as the list shows it")),
    responses((status = 200, body = TxStateReport)),
)]
pub(crate) async fn transaction_cancel(api: &Api<'_>, request: Request) -> Answer {
    let tx = tx_id(&request)?;
    api.run(Call::Command(Command::Tx(TxCommand::Cancel(tx))))
        .await
}

/// Release the inputs of a send the network never took
///
/// Refused until a refresh a day of blocks after the finalize still finds the transaction
/// nowhere on chain.
#[utoipa::path(
    post,
    path = "/v1/transactions/{tx_id}/release",
    tag = "transactions",
    params(("tx_id" = u32, Path, description = "Local transaction id, as the list shows it")),
    responses((status = 200, body = TxStateReport)),
)]
pub(crate) async fn transaction_release(api: &Api<'_>, request: Request) -> Answer {
    let tx = tx_id(&request)?;
    api.run(Call::Command(Command::Tx(TxCommand::Release(tx))))
        .await
}

/// Post a finalized transaction again
#[utoipa::path(
    post,
    path = "/v1/transactions/{tx_id}/post",
    tag = "transactions",
    params(("tx_id" = u32, Path, description = "Local transaction id, as the list shows it")),
    request_body = PostBody,
    responses((status = 200, body = PostReport)),
)]
pub(crate) async fn transaction_post(api: &Api<'_>, request: Request) -> Answer {
    let tx = tx_id(&request)?;
    let body: PostBody = request.json()?;
    let args = PostArgs {
        tx,
        fluff: FluffArg { fluff: body.fluff },
    };
    api.run(Call::Command(Command::Tx(TxCommand::Post(args))))
        .await
}

/// Scan the chain for the wallet's outputs
///
/// Brings the wallet in line with the chain; a long scan holds the request open.
#[utoipa::path(
    post,
    path = "/v1/wallet/scan",
    tag = "wallet",
    request_body = ScanBody,
    responses((status = 200, body = WalletScanReport)),
)]
pub(crate) async fn wallet_scan(api: &Api<'_>, request: Request) -> Answer {
    let body: ScanBody = request.json()?;
    if body.start_height.is_some() && body.reset_chain {
        return Err(Problem::usage(
            "start_height and reset_chain cannot be given together",
        ));
    }
    let args = WalletScanArgs {
        start_height: body.start_height,
        delete_unconfirmed: body.delete_unconfirmed,
        reset_chain: body.reset_chain,
    };
    api.run(Call::Command(Command::Wallet(WalletCommand::Scan(args))))
        .await
}

/// The relay, the address and the deliveries still pending
#[utoipa::path(
    get,
    path = "/v1/epicbox",
    tag = "epicbox",
    responses((status = 200, body = EpicboxStatusReport)),
)]
pub(crate) async fn epicbox_status(api: &Api<'_>, _request: Request) -> Answer {
    let args = ListingArgs {
        listing: None,
        generation: 0,
    };
    api.run(Call::Command(Command::Epicbox(EpicboxCommand::Status(
        args,
    ))))
    .await
}

/// Whether a peer is known to pay invoices
///
/// What this wallet learned from the peer's own messages over Epicbox. Nothing is sent.
#[utoipa::path(
    get,
    path = "/v1/epicbox/peers/{address}",
    tag = "epicbox",
    params(("address" = String, Path, description = "The peer's full Epicbox address")),
    responses((status = 200, body = PeerReport)),
)]
pub(crate) async fn epicbox_peer(api: &Api<'_>, request: Request) -> Answer {
    let args = PeerArgs {
        address: request.param("address")?.to_owned(),
    };
    api.run(Call::Command(Command::Epicbox(EpicboxCommand::Peer(args))))
        .await
}

/// The profile this wallet tells its contacts
#[utoipa::path(
    get,
    path = "/v1/profile",
    tag = "profile",
    responses((status = 200, body = ProfileShowReport)),
)]
pub(crate) async fn profile_show(api: &Api<'_>, _request: Request) -> Answer {
    api.run(Call::Command(Command::Profile(ProfileCommand::Show)))
        .await
}

/// Tell every paired contact a new profile
///
/// Exactly one of `names` and `bits`. The `profile` setting keeps its value; set it too, or
/// later updates tell the configured one again.
#[utoipa::path(
    patch,
    path = "/v1/profile",
    tag = "profile",
    request_body = ProfileBody,
    responses((status = 200, body = ProfileSetReport)),
)]
pub(crate) async fn profile_set(api: &Api<'_>, request: Request) -> Answer {
    let body: ProfileBody = request.json()?;
    if body.names.is_some() == body.bits.is_some() {
        return Err(Problem::usage("give exactly one of names and bits"));
    }
    let args = ProfileSetArgs {
        names: body.names,
        bits: body.bits,
    };
    api.run(Call::Command(Command::Profile(ProfileCommand::Set(args))))
        .await
}

/// The proof of this wallet's domain
#[utoipa::path(
    get,
    path = "/v1/profile/domain",
    tag = "profile",
    responses((status = 200, body = ProfileDomainShowReport)),
)]
pub(crate) async fn profile_domain(api: &Api<'_>, _request: Request) -> Answer {
    api.run(domain(DomainCommand::Show)).await
}

/// The well-known file that proves the domain
///
/// The file's text is in the response; the caller serves it at the `url` it names.
#[utoipa::path(
    post,
    path = "/v1/profile/domain/file",
    tag = "profile",
    request_body = DomainFileBody,
    responses((status = 200, body = ProfileDomainDocumentReport)),
)]
pub(crate) async fn profile_domain_file(api: &Api<'_>, request: Request) -> Answer {
    let body: DomainFileBody = request.json()?;
    api.run(Call::DomainFile {
        relays: body.relays,
    })
    .await
}

/// Tell every paired contact the domain
///
/// Needs the `domain` setting.
#[utoipa::path(
    post,
    path = "/v1/profile/domain/attach",
    tag = "profile",
    responses((status = 200, body = ProfileDomainAttachReport)),
)]
pub(crate) async fn profile_domain_attach(api: &Api<'_>, _request: Request) -> Answer {
    api.run(domain(DomainCommand::Attach)).await
}

/// The paired contacts
#[utoipa::path(
    get,
    path = "/v1/contacts",
    tag = "contacts",
    responses((status = 200, body = ContactListReport)),
)]
pub(crate) async fn contacts(api: &Api<'_>, _request: Request) -> Answer {
    api.run(contact(ContactCommand::List)).await
}

/// Remove a pairing
///
/// The contact is not told.
#[utoipa::path(
    delete,
    path = "/v1/contacts/{id}",
    tag = "contacts",
    params(("id" = String, Path, description = "The contact's id, as the list shows it")),
    responses((status = 200, body = ContactRemoveReport)),
)]
pub(crate) async fn contact_remove(api: &Api<'_>, request: Request) -> Answer {
    let id = contact_arg(&request)?;
    api.run(contact(ContactCommand::Remove(id))).await
}

/// Change a contact's label or whether it may send invoices
///
/// The label is set first. The response is the contact as it is after the last change.
#[utoipa::path(
    patch,
    path = "/v1/contacts/{id}",
    tag = "contacts",
    params(("id" = String, Path, description = "The contact's id, as the list shows it")),
    request_body = ContactUpdateBody,
    responses((status = 200, body = ContactReport)),
)]
pub(crate) async fn contact_update(api: &Api<'_>, request: Request) -> Answer {
    let body: ContactUpdateBody = request.json()?;
    let id = request.param("id")?;
    let mut answer = None;
    if let Some(label) = body.label {
        let args = ContactLabelArgs {
            contact: contact_id(id),
            label,
        };
        answer = Some(api.run(contact(ContactCommand::Label(args))).await?);
    }
    if let Some(allow) = body.allow_invoices {
        let args = ContactSwitchArgs {
            contact: contact_id(id),
            state: if allow { OnOffArg::On } else { OnOffArg::Off },
        };
        answer = Some(
            api.run(contact(ContactCommand::AllowInvoices(args)))
                .await?,
        );
    }
    answer.ok_or_else(|| Problem::usage("give label, allow_invoices or both"))
}

/// Make an invite to pair
///
/// The invite is a link to share; the collect route takes the answer.
#[utoipa::path(
    post,
    path = "/v1/contacts/invites",
    tag = "contacts",
    request_body = InviteBody,
    responses((status = 200, body = ContactInviteReport)),
)]
pub(crate) async fn contact_invite(api: &Api<'_>, request: Request) -> Answer {
    let body: InviteBody = request.json()?;
    let args = ContactInviteArgs {
        name: contact_name(body.name),
        expiry: body.expiry.unwrap_or_default(),
        kind: None,
        pairing_words: body.pairing_words,
    };
    api.run(contact(ContactCommand::Invite(args))).await
}

/// Ask a wallet to pair, at its payments address
///
/// Sent only to a key that ran LEPIC lately. The collect route takes the answer.
#[utoipa::path(
    post,
    path = "/v1/contacts/requests",
    tag = "contacts",
    request_body = RequestBody,
    responses((status = 200, body = ContactInviteReport)),
)]
pub(crate) async fn contact_request(api: &Api<'_>, request: Request) -> Answer {
    let body: RequestBody = request.json()?;
    let args = ContactRequestArgs {
        address: body.address,
        name: contact_name(body.name),
    };
    api.run(contact(ContactCommand::Request(args))).await
}

/// Show what an invite link says, before answering it
#[utoipa::path(
    post,
    path = "/v1/contacts/preview",
    tag = "contacts",
    request_body = LinkBody,
    responses((status = 200, body = ContactPreviewReport)),
)]
pub(crate) async fn contact_preview(api: &Api<'_>, request: Request) -> Answer {
    let body: LinkBody = request.json()?;
    let args = ContactLinkArg { link: body.link };
    api.run(contact(ContactCommand::Open(args))).await
}

/// Answer an invite
///
/// The reply goes to the inviter's relay unless `by_hand`.
#[utoipa::path(
    post,
    path = "/v1/contacts/accept",
    tag = "contacts",
    request_body = AcceptBody,
    responses((status = 200, body = ContactAcceptReport)),
)]
pub(crate) async fn contact_accept(api: &Api<'_>, request: Request) -> Answer {
    let body: AcceptBody = request.json()?;
    let args = ContactAcceptArgs {
        link: ContactLinkArg { link: body.link },
        name: contact_name(body.name),
        by_hand: body.by_hand,
    };
    api.run(contact(ContactCommand::Accept(args))).await
}

/// Take a pair-reply or pair-confirm link sent by hand, or find an invite by its pairing words
#[utoipa::path(
    post,
    path = "/v1/contacts/enter",
    tag = "contacts",
    request_body = EnterBody,
    responses((status = 200, body = ContactLinkReport)),
)]
pub(crate) async fn contact_enter(api: &Api<'_>, request: Request) -> Answer {
    let body: EnterBody = request.json()?;
    if !(1..=5).contains(&body.input.len()) {
        return Err(Problem::usage(
            "input is one link or the five pairing words",
        ));
    }
    let args = ContactEnterArgs { input: body.input };
    api.run(contact(ContactCommand::Enter(args))).await
}

/// Fetch pairing and contact messages from the home relays once, and send what waits
#[utoipa::path(
    post,
    path = "/v1/contacts/collect",
    tag = "contacts",
    responses((status = 200, body = ContactCollectReport)),
)]
pub(crate) async fn contact_collect(api: &Api<'_>, _request: Request) -> Answer {
    api.run(contact(ContactCommand::Collect)).await
}

/// Record the check of the four SAS words against the other screen
///
/// A mismatch ends the pairing and answers the removal instead of the contact.
#[utoipa::path(
    post,
    path = "/v1/contacts/{id}/sas",
    tag = "contacts",
    params(("id" = String, Path, description = "The contact's id, as the list shows it")),
    request_body = SasBody,
    responses((status = 200, body = ContactReport)),
)]
pub(crate) async fn contact_sas(api: &Api<'_>, request: Request) -> Answer {
    let body: SasBody = request.json()?;
    let args = ContactSasArgs {
        contact: contact_arg(&request)?,
        result: body.result,
    };
    api.run(contact(ContactCommand::Sas(args))).await
}

/// Ask a paired contact to answer with its current card
///
/// The collect route takes the answer.
#[utoipa::path(
    post,
    path = "/v1/contacts/{id}/check",
    tag = "contacts",
    params(("id" = String, Path, description = "The contact's id, as the list shows it")),
    responses((status = 200, body = ContactCheckReport)),
)]
pub(crate) async fn contact_check(api: &Api<'_>, request: Request) -> Answer {
    let id = contact_arg(&request)?.contact;
    api.run(contact(ContactCommand::Check(contact_id(&id))))
        .await
}

/// Ask whether a new pairing's contact still holds the keys of an older pairing
///
/// The path names the new pairing. The collect route takes the answer.
#[utoipa::path(
    post,
    path = "/v1/contacts/{id}/key-check",
    tag = "contacts",
    params(("id" = String, Path, description = "The new pairing's id")),
    request_body = KeyCheckBody,
    responses((status = 200, body = ContactKeyCheckReport)),
)]
pub(crate) async fn contact_key_check(api: &Api<'_>, request: Request) -> Answer {
    let body: KeyCheckBody = request.json()?;
    let args = ContactKeyCheckArgs {
        new: request.param("id")?.to_owned(),
        old: body.old,
    };
    api.run(contact(ContactCommand::KeyCheck(args))).await
}

/// Keep the old keys or use the new ones for a pairing in keys-changed
///
/// Keeping the old keys deletes the new pairing and answers the removal instead of the contact.
#[utoipa::path(
    post,
    path = "/v1/contacts/{id}/keys",
    tag = "contacts",
    params(("id" = String, Path, description = "The new pairing's id, in keys-changed")),
    request_body = KeysBody,
    responses((status = 200, body = ContactReport)),
)]
pub(crate) async fn contact_keys(api: &Api<'_>, request: Request) -> Answer {
    let body: KeysBody = request.json()?;
    let args = ContactKeysArgs {
        new: request.param("id")?.to_owned(),
        choice: body.choice,
    };
    api.run(contact(ContactCommand::Keys(args))).await
}

/// Move to the relay a contact asked for
#[utoipa::path(
    post,
    path = "/v1/contacts/{id}/move",
    tag = "contacts",
    params(("id" = String, Path, description = "The contact's id, as the list shows it")),
    request_body = MoveBody,
    responses((status = 200, body = ContactReport)),
)]
pub(crate) async fn contact_move(api: &Api<'_>, request: Request) -> Answer {
    let body: MoveBody = request.json()?;
    let args = ContactMoveArgs {
        contact: contact_arg(&request)?,
        apply: body.host,
    };
    api.run(contact(ContactCommand::Move(args))).await
}

/// Move this wallet's home relay for every paired contact
///
/// Each contact is told once. The old mailboxes are read for `drain_days`.
#[utoipa::path(
    post,
    path = "/v1/contacts/move-home",
    tag = "contacts",
    request_body = MoveHomeBody,
    responses((status = 200, body = ContactMoveHomeReport)),
)]
pub(crate) async fn contact_move_home(api: &Api<'_>, request: Request) -> Answer {
    let body: MoveHomeBody = request.json()?;
    let drain_days = body.drain_days.unwrap_or(0);
    if i64::from(drain_days) > MAX_DRAIN_DAYS {
        return Err(Problem::usage(format!(
            "drain_days is at most {MAX_DRAIN_DAYS}"
        )));
    }
    let args = ContactMoveHomeArgs {
        host: body.host,
        drain_days,
    };
    api.run(contact(ContactCommand::MoveHome(args))).await
}

/// Show a card to pair in person
///
/// Makes a pairing; the other phone scans the card.
#[utoipa::path(
    post,
    path = "/v1/contacts/card",
    tag = "contacts",
    request_body = CardBody,
    responses((status = 200, body = ContactCardReport)),
)]
pub(crate) async fn contact_card(api: &Api<'_>, request: Request) -> Answer {
    let body: CardBody = request.json()?;
    let args = ContactCardArgs {
        name: contact_name(body.name),
        kind: None,
    };
    api.run(contact(ContactCommand::ShowCard(args))).await
}

/// Pair in person with the card the other phone shows
#[utoipa::path(
    post,
    path = "/v1/contacts/cards/scan",
    tag = "contacts",
    request_body = ScanCardBody,
    responses((status = 200, body = ContactReport)),
)]
pub(crate) async fn contact_scan_card(api: &Api<'_>, request: Request) -> Answer {
    let body: ScanCardBody = request.json()?;
    let args = ContactScanArgs {
        contact: ContactIdArg {
            contact: body.contact,
        },
        link: body.link,
    };
    api.run(contact(ContactCommand::ScanCard(args))).await
}

/// The contact messages kept in quarantine
#[utoipa::path(
    get,
    path = "/v1/contacts/quarantine",
    tag = "contacts",
    responses((status = 200, body = ContactQuarantineReport)),
)]
pub(crate) async fn contact_quarantine(api: &Api<'_>, _request: Request) -> Answer {
    api.run(contact(ContactCommand::Quarantine)).await
}

/// The invoices parked from contacts
///
/// Read only: paying or declining one is not part of this API.
#[utoipa::path(
    get,
    path = "/v1/contact-invoices",
    tag = "contacts",
    responses((status = 200, body = ContactInvoiceListReport)),
)]
pub(crate) async fn contact_invoices(api: &Api<'_>, _request: Request) -> Answer {
    api.run(contact(ContactCommand::Invoices)).await
}

/// The pairing records, as a backup document
#[utoipa::path(
    post,
    path = "/v1/contacts/export",
    tag = "contacts",
    responses((status = 200, body = ContactBackupReport)),
)]
pub(crate) async fn contact_export(api: &Api<'_>, _request: Request) -> Answer {
    api.run(Call::ContactExport).await
}

/// Restore pairing records from a backup document
#[utoipa::path(
    post,
    path = "/v1/contacts/import",
    tag = "contacts",
    request_body = ImportBody,
    responses((status = 200, body = ContactImportReport)),
)]
pub(crate) async fn contact_import(api: &Api<'_>, request: Request) -> Answer {
    let body: ImportBody = request.json()?;
    api.run(Call::ContactImport {
        document: body.backup,
    })
    .await
}

/// Send bytes to a paired contact through its mailbox
///
/// LEPIC never reads the bytes. The response holds the payload's id.
#[utoipa::path(
    post,
    path = "/v1/contacts/{id}/payloads",
    tag = "payloads",
    params(("id" = String, Path, description = "The contact's id, as the list shows it")),
    request_body = PayloadBody,
    responses((status = 200, body = ContactPayloadPostReport)),
)]
pub(crate) async fn payload_post(api: &Api<'_>, request: Request) -> Answer {
    let body: PayloadBody = request.json()?;
    let args = ContactPayloadPostArgs {
        contact: contact_arg(&request)?,
        hex: Some(body.payload),
        file: None,
    };
    api.run(payload(ContactPayloadCommand::Post(args))).await
}

/// The payloads that arrived and are not acknowledged, oldest first
#[utoipa::path(
    get,
    path = "/v1/payloads",
    tag = "payloads",
    responses((status = 200, body = ContactPayloadListReport)),
)]
pub(crate) async fn payloads(api: &Api<'_>, _request: Request) -> Answer {
    api.run(payload(ContactPayloadCommand::List)).await
}

/// Forget a payload once its bytes are kept elsewhere
#[utoipa::path(
    post,
    path = "/v1/payloads/{id}/ack",
    tag = "payloads",
    params(("id" = String, Path, description = "The payload's id, as the list shows it")),
    responses((status = 200, body = ContactPayloadAckReport)),
)]
pub(crate) async fn payload_ack(api: &Api<'_>, request: Request) -> Answer {
    let args = ContactPayloadAckArgs {
        ids: vec![request.param("id")?.to_owned()],
    };
    api.run(payload(ContactPayloadCommand::Ack(args))).await
}

fn tx_id(request: &Request) -> Result<TxIdArgs, Problem> {
    let tx_id = request
        .param("tx_id")?
        .parse()
        .map_err(|_| Problem::usage("tx_id is not a transaction id"))?;
    Ok(TxIdArgs { tx_id })
}

fn contact_id(id: &str) -> ContactIdArg {
    ContactIdArg {
        contact: id.to_owned(),
    }
}

fn contact_arg(request: &Request) -> Result<ContactIdArg, Problem> {
    request.param("id").map(contact_id)
}

fn contact_name(name: Option<String>) -> ContactNameArg {
    ContactNameArg {
        name: name.unwrap_or_else(|| DEFAULT_CONTACT_NAME.to_owned()),
    }
}

fn contact(command: ContactCommand) -> Call {
    Call::Command(Command::Contact(ContactArgs {
        command,
        offline: false,
        epicbox_off: false,
    }))
}

fn payload(command: ContactPayloadCommand) -> Call {
    contact(ContactCommand::Payload(ContactPayloadArgs { command }))
}

fn domain(command: DomainCommand) -> Call {
    Call::Command(Command::Profile(ProfileCommand::Domain(DomainArgs {
        command,
    })))
}

fn account(label: Option<String>) -> AccountArg {
    AccountArg {
        account: label.unwrap_or_else(|| lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned()),
    }
}
