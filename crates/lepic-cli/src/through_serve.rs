// SPDX-License-Identifier: Apache-2.0
//! Commands that run on the wallet a running `lepic serve` holds (ADR 0053).
//!
//! serve holds the data directory lock for as long as it runs. A command that has a route in the
//! wallet API is sent to serve's socket in the data directory as that route's request, and the
//! answer is printed as the command prints it when it runs on its own: the JSON report as it
//! comes, the text serve renders for `Accept: text/plain`, or the problem as the CLI error with
//! the same kind, exit code, causes and transaction. A command with no route, or with an option
//! the route has no field for, runs here and meets the lock.

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

use crate::cli::{
    AccountArg, Command, EpicboxCommand, FluffArg, LegacyArg, ListArgs, ListingArgs, MessageArg,
    NodeCommand, PeerCommand, PlainHttpArg, PostArgs, ProfileCommand, SelectionArg, SendArgs,
    SendDestinationArgs, SendSlateIdArg, SpendArgs, TorBinaryArgs, TxCommand, TxShowArgs,
    WalletCommand,
};
use crate::commands::is_onion;
use crate::exit::{CliError, ErrorKind, ServedCause};
use crate::service;
use crate::settings::{OutputFormat, Settings};

/// Far above any report serve answers with.
const MAX_ANSWER: usize = 64 * 1024 * 1024;

/// The route request a command stands for.
struct Call {
    method: Method,
    /// Path and query.
    target: String,
    body: Option<Value>,
}

/// Runs `command` on the wallet serve holds and returns what the command prints, when serve
/// answers on the data directory's socket and the command has a route. `None` when the command
/// runs here.
pub(crate) async fn run(
    command: &Command,
    settings: &Settings,
) -> Result<Option<Zeroizing<String>>, CliError> {
    let Some(call) = call(command) else {
        return Ok(None);
    };
    let socket = service::default_socket(&settings.data_dir);
    let Ok(stream) = UnixStream::connect(&socket).await else {
        return Ok(None);
    };
    exchange(stream, &socket, call, settings.output)
        .await
        .map(Some)
}

/// The socket serve answers on in `data_dir`, when it runs there.
pub(crate) async fn serving(data_dir: &Path) -> Option<PathBuf> {
    let socket = service::default_socket(data_dir);
    UnixStream::connect(&socket).await.ok().map(|_| socket)
}

async fn exchange(
    stream: UnixStream,
    socket: &Path,
    call: Call,
    format: OutputFormat,
) -> Result<Zeroizing<String>, CliError> {
    let unanswered = |source: Box<dyn std::error::Error + Send + Sync>| CliError::ServeUnanswered {
        socket: socket.to_owned(),
        source,
    };
    let body = match &call.body {
        Some(body) => Bytes::from(serde_json::to_vec(body).map_err(|e| unanswered(e.into()))?),
        None => Bytes::new(),
    };
    let accept = match format {
        OutputFormat::Json => "application/json",
        OutputFormat::Human => "text/plain",
    };
    let mut request = Request::builder()
        .method(call.method)
        .uri(call.target)
        .header(header::HOST, "lepic")
        .header(header::ACCEPT, accept);
    if call.body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request
        .body(Full::new(body))
        .map_err(|e| unanswered(e.into()))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| unanswered(e.into()))?;
    let connection = tokio::spawn(connection);
    let answered = async {
        let response = sender.send_request(request).await?;
        let status = response.status();
        let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
        let body = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await?
            .to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, content_type, body))
    }
    .await;
    connection.abort();
    let (status, content_type, body) = answered.map_err(unanswered)?;
    let text = Zeroizing::new(String::from_utf8(body.to_vec()).map_err(|e| unanswered(e.into()))?);
    if status.is_success() {
        return Ok(text);
    }
    if content_type != Some(HeaderValue::from_static("application/problem+json")) {
        return Err(unanswered(
            format!("serve answered {status} without a problem document").into(),
        ));
    }
    let problem: Problem = serde_json::from_str(&text).map_err(|e| unanswered(e.into()))?;
    Err(problem.into_error())
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
        Command::Tx(TxCommand::Cancel(tx)) => Some(Call {
            method: Method::POST,
            target: format!("/v1/transactions/{}/cancel", tx.tx_id),
            body: None,
        }),
        Command::Tx(TxCommand::Release(tx)) => Some(Call {
            method: Method::POST,
            target: format!("/v1/transactions/{}/release", tx.tx_id),
            body: None,
        }),
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
        Command::Peer(PeerCommand::Forget(args)) => Some(Call {
            method: Method::DELETE,
            target: format!(
                "/v1/peer-pins?origin={}&account={}",
                encode(&args.origin),
                encode(&args.account.account)
            ),
            body: None,
        }),
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
    with_body(
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
    Some(Call {
        method: Method::GET,
        target,
        body: None,
    })
}

fn with_body(method: Method, target: String, body: Value) -> Option<Call> {
    Some(Call {
        method,
        target,
        body: Some(body),
    })
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
        };
        let error = problem.into_error();
        assert_eq!(error.kind(), ErrorKind::InsufficientFunds);
        assert_eq!(error.chain(), ["send failed", "not enough", "1 short"]);
        assert_eq!(error.tx_id(), Some(4));
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
        };
        let error = problem.into_error();
        assert_eq!(error.kind(), ErrorKind::Internal);
        assert_eq!(error.chain(), ["a: b"]);
    }

    #[test]
    fn values_are_percent_encoded() {
        assert_eq!(encode("a b@c:1/x~"), "a%20b%40c%3A1%2Fx~");
    }
}
