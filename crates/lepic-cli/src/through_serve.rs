// SPDX-License-Identifier: Apache-2.0
//! Commands that run on the wallet a running `lepic serve` holds (ADR 0053).
//!
//! serve holds the data directory lock for as long as it runs. A command that has a route in the
//! wallet API is sent to serve's socket as that route's request (the socket the data directory's
//! `serve-socket` pointer names, else the default one). The answer is printed as the command
//! prints it when it runs on its own: the JSON report as it comes, the text serve renders for
//! `Accept: text/plain`, or the problem as the CLI error with the same kind, exit code, causes,
//! hint and transaction.
//!
//! The wallet, transaction, Epicbox and profile commands map here; `families` maps the contact,
//! in-person, epic1, `epictx open` and `profile domain` commands. A file a command reads is read
//! after the connection is made and goes in the request body; a file it writes is written from the
//! answer (`Finish`), through the same helpers a direct run uses. A command with no route, or with
//! an option the route has no field for, runs here and meets the lock.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use crate::api::{Caller, VERSION, VERSION_HEADER};
use crate::cli::{
    AccountArg, Command, EpicboxCommand, FluffArg, LegacyArg, ListArgs, ListingArgs, MessageArg,
    NodeCommand, PeerCommand, PlainHttpArg, PostArgs, ProfileCommand, SelectionArg, SendArgs,
    SendDestinationArgs, SendSlateIdArg, SpendArgs, TorBinaryArgs, TxCommand, TxShowArgs,
    WalletCommand,
};
use crate::commands::files;
use crate::commands::is_onion;
use crate::exit::{CliError, ErrorKind, ServedCause};
use crate::output;
use crate::service;
use crate::settings::{OutputFormat, Settings};

mod families;

/// Far above any report serve answers with.
const MAX_ANSWER: usize = 64 * 1024 * 1024;

/// The route request a command stands for.
struct Call {
    method: Method,
    /// Path and query.
    target: String,
    body: Body,
    finish: Finish,
    /// The call moves money: its JSON body carries a `slate_id`, drawn here when the command
    /// gave none, so the payment can be looked up, and made again safely, when no answer comes.
    pays: bool,
}

/// What the request carries.
enum Body {
    None,
    Json(Value),
    /// A body made from a file or standard input, read once serve has answered the connection:
    /// a command that runs here reads its own files.
    Read(Box<dyn FnOnce() -> Result<Value, CliError> + Send>),
}

/// What the command does with the answer.
enum Finish {
    /// Print it as the command prints it.
    Print,
    /// The answer holds the contact backup; write it to the file and report the file.
    ContactBackup(PathBuf),
    /// The answer holds the domain file; write it and report the file.
    DomainFile { path: Option<PathBuf>, force: bool },
}

impl Call {
    fn new(method: Method, target: String) -> Self {
        Self {
            method,
            target,
            body: Body::None,
            finish: Finish::Print,
            pays: false,
        }
    }

    fn pays(mut self) -> Self {
        self.pays = true;
        self
    }

    /// The slate id of a call that moves money, drawn into its body when the command gave none.
    fn slate_id(&mut self) -> Result<Option<String>, CliError> {
        if !self.pays {
            return Ok(None);
        }
        let Body::Json(Value::Object(body)) = &mut self.body else {
            return Ok(None);
        };
        let slate_id = match body.get("slate_id") {
            Some(Value::String(given)) => given.clone(),
            _ => crate::commands::drawn_slate_id()?.to_string(),
        };
        body.insert("slate_id".to_owned(), Value::String(slate_id.clone()));
        Ok(Some(slate_id))
    }

    fn json(mut self, body: Value) -> Self {
        self.body = Body::Json(body);
        self
    }

    fn read(mut self, read: impl FnOnce() -> Result<Value, CliError> + Send + 'static) -> Self {
        self.body = Body::Read(Box::new(read));
        self
    }

    fn finish(mut self, finish: Finish) -> Self {
        self.finish = finish;
        self
    }
}

/// Runs `command` on the wallet serve holds and returns what the command prints, when serve
/// answers on a socket of the data directory and the command has a route. `None` when the command
/// runs here.
pub(crate) async fn run(
    command: &Command,
    settings: &Settings,
) -> Result<Option<Zeroizing<String>>, CliError> {
    let Some(call) = call(command) else {
        return Ok(None);
    };
    let Some((stream, socket)) = service::connect(&settings.data_dir).await else {
        return Ok(None);
    };
    exchange(
        stream,
        &socket,
        call,
        settings.output,
        &Caller::of(settings),
    )
    .await
    .map(Some)
}

/// The socket serve answers on in `data_dir`, when it runs there: the one its pointer file
/// names, or the default.
pub(crate) async fn serving(data_dir: &Path) -> Option<PathBuf> {
    service::connect(data_dir).await.map(|(_, socket)| socket)
}

/// Sends `call` and reads the answer. A call that moves money and gets no answer fails with
/// [`CliError::PaymentUnanswered`], naming its slate id: the payment may have been made.
async fn exchange(
    stream: UnixStream,
    socket: &Path,
    mut call: Call,
    format: OutputFormat,
    caller: &Caller,
) -> Result<Zeroizing<String>, CliError> {
    let slate_id = call.slate_id()?;
    let unanswered = |source: Box<dyn std::error::Error + Send + Sync>| match &slate_id {
        Some(slate_id) => CliError::PaymentUnanswered {
            socket: socket.to_owned(),
            slate_id: slate_id.clone(),
            source,
        },
        None => CliError::ServeUnanswered {
            socket: socket.to_owned(),
            source,
        },
    };
    let body = match call.body {
        Body::None => None,
        Body::Json(body) => Some(body),
        Body::Read(read) => Some(read()?),
    };
    let has_body = body.is_some();
    let body = match body {
        Some(body) => Zeroizing::new(serde_json::to_vec(&body).map_err(|e| unanswered(e.into()))?),
        None => Zeroizing::new(Vec::new()),
    };
    // A file the answer is written to is made from the JSON report; the rest is printed as it is.
    let accept = match (&call.finish, format) {
        (Finish::Print, OutputFormat::Human) => "text/plain",
        _ => "application/json",
    };
    let mut request = Request::builder()
        .method(call.method)
        .uri(call.target)
        .header(header::HOST, "lepic")
        .header(header::ACCEPT, accept);
    for (name, value) in caller.headers() {
        request = request.header(name, value);
    }
    if has_body {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request
        .body(Full::new(Bytes::from(body.to_vec())))
        .map_err(|e| unanswered(e.into()))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| unanswered(e.into()))?;
    let connection = tokio::spawn(connection);
    let answered = async {
        let response = sender.send_request(request).await?;
        let status = response.status();
        let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
        let version = response.headers().get(VERSION_HEADER).cloned();
        let body = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await?
            .to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, content_type, version, body))
    }
    .await;
    connection.abort();
    let (status, content_type, version, body) = answered.map_err(unanswered)?;
    let text = Zeroizing::new(String::from_utf8(body.to_vec()).map_err(|e| unanswered(e.into()))?);
    if status.is_success() {
        return finish(call.finish, text, format, &unanswered);
    }
    // A serve of another version may not know the route or a field: say so, not what it says.
    if version.as_ref().is_none_or(|version| version != VERSION) {
        return Err(CliError::ServeVersion {
            socket: socket.to_owned(),
            serve: version.map_or_else(
                || "an older version".to_owned(),
                |version| format!("version {}", String::from_utf8_lossy(version.as_bytes())),
            ),
            cli: VERSION,
        });
    }
    if content_type != Some(HeaderValue::from_static("application/problem+json")) {
        return Err(unanswered(
            format!("serve answered {status} without a problem document").into(),
        ));
    }
    let problem: Problem = serde_json::from_str(&text).map_err(|e| unanswered(e.into()))?;
    Err(problem.into_error())
}

/// Prints `text`, or writes the file it holds and prints the report of that.
fn finish(
    finish: Finish,
    text: Zeroizing<String>,
    format: OutputFormat,
    unanswered: &dyn Fn(Box<dyn std::error::Error + Send + Sync>) -> CliError,
) -> Result<Zeroizing<String>, CliError> {
    let report = match finish {
        Finish::Print => return Ok(text),
        Finish::ContactBackup(file) => {
            let answer: Backup = serde_json::from_str(&text).map_err(|e| unanswered(e.into()))?;
            files::save_backup(&file, &answer.backup)?
        }
        Finish::DomainFile { path, force } => {
            let answer: DomainDocument =
                serde_json::from_str(&text).map_err(|e| unanswered(e.into()))?;
            files::save_domain_file(path.as_deref(), force, &answer.document, answer.url)?
        }
    };
    Ok(output::render(&report, format))
}

/// `POST /v1/contacts/export`.
#[derive(Deserialize)]
struct Backup {
    #[serde(deserialize_with = "secret")]
    backup: Zeroizing<String>,
}

/// `POST /v1/profile/domain/file`.
#[derive(Deserialize)]
struct DomainDocument {
    document: String,
    url: Option<String>,
}

fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// The fields of a problem document the CLI error is built from.
#[derive(Deserialize)]
struct Problem {
    code: String,
    detail: String,
    #[serde(default)]
    causes: Vec<String>,
    tx_id: Option<u32>,
    #[serde(default)]
    recovery: Vec<String>,
    hint: Option<String>,
}

impl Problem {
    /// The CLI error the command reports when it runs on its own: `detail` is the message and
    /// its causes joined by `: `.
    fn into_error(self) -> CliError {
        let kind = ErrorKind::from_name(&self.code).unwrap_or(ErrorKind::Internal);
        let suffix = self.causes.iter().fold(String::new(), |mut suffix, cause| {
            let _ = write!(suffix, ": {cause}");
            suffix
        });
        let (message, causes) = match self.detail.strip_suffix(&suffix) {
            Some(message) => (message.to_owned(), self.causes),
            None => (self.detail, Vec::new()),
        };
        CliError::Served {
            kind,
            message,
            causes: ServedCause::chain(causes),
            tx_id: self.tx_id,
            recovery: self.recovery.into(),
            hint: self.hint,
        }
    }
}

/// The route request `command` stands for, when it has a route that takes every option given.
/// Each argument struct is taken apart field by field, so a new option is a compile error here
/// until it is mapped or refused.
fn call(command: &Command) -> Option<Call> {
    match command {
        Command::Wallet(WalletCommand::Info) => get("/v1/wallet".to_owned()),
        Command::Wallet(WalletCommand::Address) => get("/v1/wallet/address".to_owned()),
        Command::Wallet(WalletCommand::Outputs(account)) => get(accounted("/v1/outputs", account)),
        Command::Wallet(WalletCommand::Scan(args)) => {
            let crate::cli::WalletScanArgs {
                start_height,
                delete_unconfirmed,
                reset_chain,
            } = args;
            with_body(
                Method::POST,
                "/v1/wallet/scan".to_owned(),
                json!({
                    "start_height": start_height,
                    "delete_unconfirmed": delete_unconfirmed,
                    "reset_chain": reset_chain,
                }),
            )
        }
        Command::Node(NodeCommand::Status) => get("/v1/node".to_owned()),
        Command::Tx(TxCommand::List(ListArgs { account, refresh })) => get(format!(
            "{}&refresh={}",
            accounted("/v1/transactions", account),
            refresh.refresh
        )),
        Command::Tx(TxCommand::Show(TxShowArgs {
            tx_id: Some(tx_id),
            slate_id: SendSlateIdArg { slate_id: None },
            refresh,
        })) => get(format!(
            "/v1/transactions/{tx_id}?refresh={}",
            refresh.refresh
        )),
        Command::Tx(TxCommand::Cancel(tx)) => Some(Call::new(
            Method::POST,
            format!("/v1/transactions/{}/cancel", tx.tx_id),
        )),
        Command::Tx(TxCommand::Release(tx)) => Some(Call::new(
            Method::POST,
            format!("/v1/transactions/{}/release", tx.tx_id),
        )),
        Command::Tx(TxCommand::Post(PostArgs {
            tx,
            fluff: FluffArg { fluff },
        })) => with_body(
            Method::POST,
            format!("/v1/transactions/{}/post", tx.tx_id),
            json!({ "fluff": fluff }),
        ),
        Command::Tx(TxCommand::Send(args)) => send(args),
        Command::Epicbox(EpicboxCommand::Status(ListingArgs {
            listing: None,
            generation: _,
        })) => get("/v1/epicbox".to_owned()),
        Command::Epicbox(EpicboxCommand::Peer(args)) => {
            get(format!("/v1/epicbox/peers/{}", encode(&args.address)))
        }
        Command::Profile(ProfileCommand::Show) => get("/v1/profile".to_owned()),
        Command::Profile(ProfileCommand::Set(args)) => with_body(
            Method::PATCH,
            "/v1/profile".to_owned(),
            json!({ "names": args.names, "bits": args.bits }),
        ),
        Command::Peer(PeerCommand::Pins(account)) => get(accounted("/v1/peer-pins", account)),
        Command::Peer(PeerCommand::Forget(args)) => Some(Call::new(
            Method::DELETE,
            format!(
                "/v1/peer-pins?origin={}&account={}",
                encode(&args.origin),
                encode(&args.account.account)
            ),
        )),
        Command::Profile(ProfileCommand::Domain(args)) => families::domain(&args.command),
        Command::Contact(args) => families::contact(args),
        Command::InPerson(args) => families::in_person(args),
        Command::Epic1(args) => families::epic1(args),
        Command::Epictx(command) => families::epictx(command),
        _ => None,
    }
}

/// `POST /v1/transactions`: an Epicbox address, or an HTTP listener's URL, with the options its
/// body has.
fn send(args: &SendArgs) -> Option<Call> {
    let SendArgs {
        amount,
        destination:
            SendDestinationArgs {
                to,
                to_file,
                to_contact,
            },
        purpose,
        plain_http: PlainHttpArg { allow_plain_http },
        tor: TorBinaryArgs {
            tor_binary,
            lib_dir,
        },
        fluff: FluffArg { fluff },
        account: AccountArg { account },
        message: MessageArg { message },
        spend:
            SpendArgs {
                min_confirmations,
                change_outputs,
                selection,
                ttl_blocks,
            },
        slate_id: SendSlateIdArg { slate_id },
        legacy: LegacyArg { legacy },
        reach: _,
    } = args;
    let to = to.as_ref()?;
    let routed = to_file.is_none()
        && to_contact.is_none()
        && purpose.is_none()
        && !allow_plain_http
        && tor_binary.is_none()
        && lib_dir.is_none()
        && !fluff
        && ttl_blocks.is_none()
        && matches!(selection, SelectionArg::Smallest)
        && !is_onion(to);
    if !routed {
        return None;
    }
    let method = to.contains("://").then_some("http");
    pays(
        Method::POST,
        "/v1/transactions".to_owned(),
        json!({
            "amount": amount,
            "to": to,
            "method": method,
            "slate_id": slate_id,
            "account": account,
            "message": message,
            "min_confirmations": min_confirmations,
            "change_outputs": change_outputs,
            "legacy": legacy,
        }),
    )
}

fn get(target: String) -> Option<Call> {
    Some(Call::new(Method::GET, target))
}

fn with_body(method: Method, target: String, body: Value) -> Option<Call> {
    Some(Call::new(method, target).json(body))
}

/// A call that moves money; see [`Call::pays`].
fn pays(method: Method, target: String, body: Value) -> Option<Call> {
    Some(Call::new(method, target).json(body).pays())
}

fn accounted(path: &str, account: &AccountArg) -> String {
    format!("{path}?account={}", encode(&account.account))
}

/// Percent-encodes a path segment or a query value.
fn encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_problem_becomes_the_error_with_its_causes() {
        let problem = Problem {
            code: "insufficient_funds".to_owned(),
            detail: "send failed: not enough: 1 short".to_owned(),
            causes: vec!["not enough".to_owned(), "1 short".to_owned()],
            tx_id: Some(4),
            recovery: vec!["lepic tx post 4".to_owned(), "lepic tx cancel 4".to_owned()],
            hint: Some("fund the wallet".to_owned()),
        };
        let error = problem.into_error();
        assert_eq!(error.kind(), ErrorKind::InsufficientFunds);
        assert_eq!(error.chain(), ["send failed", "not enough", "1 short"]);
        assert_eq!(error.tx_id(), Some(4));
        assert_eq!(
            crate::hint::hint(&error, None).as_deref(),
            Some("fund the wallet")
        );
        assert_eq!(
            crate::hint::recovery(&error),
            ["lepic tx post 4", "lepic tx cancel 4"]
        );
    }

    #[test]
    fn a_problem_without_causes_keeps_its_detail() {
        let problem = Problem {
            code: "no_such_kind".to_owned(),
            detail: "a: b".to_owned(),
            causes: Vec::new(),
            tx_id: None,
            recovery: Vec::new(),
            hint: None,
        };
        let error = problem.into_error();
        assert_eq!(error.kind(), ErrorKind::Internal);
        assert_eq!(error.chain(), ["a: b"]);
    }

    /// The request the arguments stand for: method, target and the body when it needs no file.
    fn request(arguments: &[&str]) -> Option<(String, String, Option<Value>)> {
        use clap::Parser as _;
        let mut line = vec!["lepic"];
        line.extend_from_slice(arguments);
        let cli = crate::cli::Cli::try_parse_from(line).unwrap();
        let call = call(&cli.command)?;
        let body = match call.body {
            Body::None => None,
            Body::Json(body) => Some(body),
            Body::Read(read) => Some(read().unwrap()),
        };
        Some((call.method.to_string(), call.target, body))
    }

    #[test]
    fn contact_commands_stand_for_their_routes() {
        let table: &[(&[&str], &str, &str, Option<Value>)] = &[
            (
                &["contact", "invite", "--expiry", "1h", "--pairing-words"],
                "POST",
                "/v1/contacts/invites",
                Some(json!({"name": "LEPIC", "expiry": "1h", "pairing_words": true})),
            ),
            (&["contact", "list"], "GET", "/v1/contacts", None),
            (
                &["contact", "collect"],
                "POST",
                "/v1/contacts/collect",
                None,
            ),
            (
                &["contact", "remove", "a b"],
                "DELETE",
                "/v1/contacts/a%20b",
                None,
            ),
            (
                &["contact", "allow-invoices", "c1", "on"],
                "PATCH",
                "/v1/contacts/c1",
                Some(json!({"allow_invoices": true})),
            ),
            (
                &["contact", "sas", "c1", "mismatch"],
                "POST",
                "/v1/contacts/c1/sas",
                Some(json!({"result": "mismatch"})),
            ),
            (
                &["contact", "keys", "n1", "keep-old"],
                "POST",
                "/v1/contacts/n1/keys",
                Some(json!({"choice": "keep-old"})),
            ),
            (
                &[
                    "contact",
                    "move-home",
                    "relay.example:443",
                    "--drain-days",
                    "3",
                ],
                "POST",
                "/v1/contacts/move-home",
                Some(json!({"host": "relay.example:443", "drain_days": 3})),
            ),
            (
                &["contact", "payload", "post", "c1", "--hex", "00ff"],
                "POST",
                "/v1/contacts/c1/payloads",
                Some(json!({"payload": "00ff"})),
            ),
            (
                &["contact", "payload", "ack", "p1"],
                "POST",
                "/v1/payloads/p1/ack",
                None,
            ),
            (&["contact", "payload", "list"], "GET", "/v1/payloads", None),
        ];
        for (arguments, method, target, body) in table {
            assert_eq!(
                request(arguments),
                Some(((*method).to_owned(), (*target).to_owned(), body.clone())),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn in_person_and_epic1_commands_stand_for_their_routes() {
        let table: &[(&[&str], &str, &str, Option<Value>)] = &[
            (
                &["in-person", "invoice", "1.5", "--ttl-blocks", "20"],
                "POST",
                "/v1/in-person/invoices",
                Some(
                    json!({"amount": "1.5", "account": "default", "message": null, "ttl_blocks": 20}),
                ),
            ),
            (
                &["in-person", "receive", "--hex", "ab"],
                "POST",
                "/v1/in-person/receive",
                Some(json!({"code": "ab", "account": "default", "message": null})),
            ),
            (
                &["in-person", "take", "ab", "cd"],
                "POST",
                "/v1/in-person/take",
                Some(json!({"answer": ["ab", "cd"]})),
            ),
            (
                &["in-person", "finalize", "s1", "2", "--fluff"],
                "POST",
                "/v1/in-person/s1/finalize",
                Some(json!({"answer": 2, "fluff": true})),
            ),
            (
                &["in-person", "answers", "s1"],
                "GET",
                "/v1/in-person/s1/answers",
                None,
            ),
            (
                &["epic1", "address"],
                "GET",
                "/v1/epic1/address?account=default&index=0",
                None,
            ),
            (
                &["epic1", "address", "--index", "7"],
                "GET",
                "/v1/epic1/address?account=default&index=7",
                None,
            ),
            (
                &["epic1", "new-address"],
                "POST",
                "/v1/epic1/addresses",
                Some(json!({"account": "default"})),
            ),
            (
                &["epic1", "addresses", "--from", "2", "--limit", "5"],
                "GET",
                "/v1/epic1/addresses?account=default&from=2&limit=5",
                None,
            ),
            (&["epic1", "links"], "GET", "/v1/epic1/links", None),
            (
                &["epic1", "retire", "3"],
                "POST",
                "/v1/epic1/links/3/retire",
                Some(json!({"account": "default"})),
            ),
            (
                &["epic1", "post-next", "s1", "--hosts-ok"],
                "POST",
                "/v1/epic1/s1/post-next",
                Some(json!({"hosts_ok": true})),
            ),
            (&["epic1", "restore"], "POST", "/v1/epic1/restore", None),
            (
                &["epic1", "issue-here"],
                "POST",
                "/v1/epic1/issue-here",
                None,
            ),
        ];
        for (arguments, method, target, body) in table {
            assert_eq!(
                request(arguments),
                Some(((*method).to_owned(), (*target).to_owned(), body.clone())),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn profile_commands_stand_for_their_routes() {
        let table: &[(&[&str], &str, &str, Option<Value>)] = &[
            (
                &["profile", "domain", "show"],
                "GET",
                "/v1/profile/domain",
                None,
            ),
            (
                &["profile", "domain", "attach"],
                "POST",
                "/v1/profile/domain/attach",
                None,
            ),
            (
                &["profile", "domain", "file", "--relay", "r.example:443"],
                "POST",
                "/v1/profile/domain/file",
                Some(json!({"relays": ["r.example:443"]})),
            ),
        ];
        for (arguments, method, target, body) in table {
            assert_eq!(
                request(arguments),
                Some(((*method).to_owned(), (*target).to_owned(), body.clone())),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn a_command_with_an_option_its_route_lacks_runs_here() {
        let local: &[&[&str]] = &[
            &["contact", "--offline", "list"],
            &["contact", "--epicbox-off", "collect"],
            &["contact", "invite", "--kind", "shop"],
            &["contact", "payload", "ack", "p1", "p2"],
            &["contact", "seal", "c1", "4"],
            &["contact", "decline", "s1"],
            &["in-person", "invoice", "1", "--out", "code.txt"],
            &["in-person", "send", "1", "--selection", "all"],
            &["in-person", "pay", "1", "--hex", "ab", "--ttl-blocks", "5"],
            &["in-person", "read", "--hex", "ab", "--selection", "all"],
            &["epic1", "--offline", "links"],
            &["epic1", "pay", "epic:epic1x", "--ttl-blocks", "5"],
        ];
        for arguments in local {
            assert!(request(arguments).is_none(), "{arguments:?}");
        }
    }

    #[test]
    fn a_payment_carries_a_slate_id_drawn_when_none_is_given() {
        let given = "8a6e2f0c-4b1d-4c3e-9f2a-7d5b6c8e9f01";
        let payments: &[&[&str]] = &[
            &["tx", "send", "1", "--to", "a@relay.example"],
            &["epic1", "pay", "epic:epic1x"],
        ];
        for arguments in payments {
            let parse = |arguments: &[&str]| {
                use clap::Parser as _;
                let mut line = vec!["lepic"];
                line.extend_from_slice(arguments);
                let cli = crate::cli::Cli::try_parse_from(line).unwrap();
                let mut call = call(&cli.command).unwrap();
                let slate_id = call.slate_id().unwrap().unwrap();
                let Body::Json(body) = call.body else {
                    panic!("{arguments:?}")
                };
                (slate_id, body)
            };
            let (drawn, body) = parse(arguments);
            assert_eq!(body["slate_id"], drawn.as_str(), "{arguments:?}");
            crate::commands::caller_slate_id(&drawn).unwrap();
            let mut with_given = arguments.to_vec();
            with_given.extend(["--slate-id", given]);
            let (kept, body) = parse(&with_given);
            assert_eq!(kept, given, "{arguments:?}");
            assert_eq!(body["slate_id"], given, "{arguments:?}");
        }
        let mut other = call(&Command::Wallet(WalletCommand::Info)).unwrap();
        assert_eq!(other.slate_id().unwrap(), None);
    }

    #[tokio::test]
    async fn a_payment_serve_does_not_answer_names_its_slate_id() {
        let (client, server) = UnixStream::pair().unwrap();
        drop(server);
        let call = Call::new(Method::POST, "/v1/epic1/pay".to_owned())
            .json(json!({ "link": "epic:epic1x", "slate_id": null }))
            .pays();
        let error = exchange(
            client,
            Path::new("lepic.sock"),
            call,
            OutputFormat::Json,
            &caller(),
        )
        .await
        .unwrap_err();
        let CliError::PaymentUnanswered { slate_id, .. } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(error.kind(), ErrorKind::Incomplete);
        assert_eq!(
            crate::hint::recovery(&error),
            [format!("lepic tx show --slate-id {slate_id}")]
        );
        let (client, server) = UnixStream::pair().unwrap();
        drop(server);
        let error = exchange(
            client,
            Path::new("lepic.sock"),
            Call::new(Method::GET, "/v1/wallet".to_owned()),
            OutputFormat::Json,
            &caller(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Transport, "{error:?}");
    }

    fn caller() -> Caller {
        let env = crate::settings::Env::new([
            ("HOME".to_owned(), "/home/u".to_owned()),
            ("LEPIC_NETWORK".to_owned(), "floonet".to_owned()),
            ("LEPIC_DATA_DIR".to_owned(), "/w".to_owned()),
        ]);
        Caller::of(&Settings::resolve(&crate::cli::GlobalArgs::default(), &env).unwrap())
    }

    /// Answers one request on `server` with `answer`, and returns the request's head.
    async fn answer_once(server: UnixStream, answer: String) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut server = server;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            server.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        server.write_all(answer.as_bytes()).await.unwrap();
        server.shutdown().await.unwrap();
        String::from_utf8(head).unwrap()
    }

    fn problem_answer(version: Option<&str>) -> String {
        let body = r#"{"type":"about:blank","title":"Not Found","status":404,"detail":"no such route","code":"not_found"}"#;
        let version = version.map_or_else(String::new, |version| {
            format!("x-lepic-version: {version}\r\n")
        });
        format!(
            "HTTP/1.1 404 Not Found\r\ncontent-type: application/problem+json\r\n{version}\
             content-length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn a_command_tells_serve_its_run_and_an_older_serve_is_named() {
        for (version, older) in [(None, true), (Some("0.0.1"), true), (Some(VERSION), false)] {
            let (client, server) = UnixStream::pair().unwrap();
            let served = tokio::spawn(answer_once(server, problem_answer(version)));
            let error = exchange(
                client,
                Path::new("lepic.sock"),
                Call::new(Method::GET, "/v1/epic1/addresses".to_owned()),
                OutputFormat::Json,
                &caller(),
            )
            .await
            .unwrap_err();
            let head = served.await.unwrap().to_ascii_lowercase();
            for (name, value) in caller().headers() {
                assert!(
                    head.contains(&format!("{name}: {}", value.to_ascii_lowercase())),
                    "{name}"
                );
            }
            if older {
                assert!(matches!(error, CliError::ServeVersion { .. }), "{error:?}");
                assert_eq!(error.kind(), ErrorKind::Config);
                let expected =
                    version.map_or("an older version".to_owned(), |v| format!("version {v}"));
                assert!(error.to_string().contains(&expected), "{error}");
            } else {
                assert_eq!(error.kind(), ErrorKind::NotFound, "{error:?}");
            }
        }
    }

    #[test]
    fn values_are_percent_encoded() {
        assert_eq!(encode("a b@c:1/x~"), "a%20b%40c%3A1%2Fx~");
    }
}
