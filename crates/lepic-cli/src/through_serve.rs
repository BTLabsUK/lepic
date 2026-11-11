// SPDX-License-Identifier: Apache-2.0
//! Commands that run on the wallet a running `lepic serve` holds (ADR 0053).
//!
//! serve holds the data directory lock for as long as it runs. A command that serve can run is
//! sent to serve's Unix socket as it was parsed, in `POST /cli/run` (the socket the data
//! directory's `serve-socket` pointer names, else the default one). serve runs it on the wallet it
//! holds. The answer is printed as the command prints it when it runs on its own: the JSON report
//! as it comes, the text serve renders for `Accept: text/plain`, or the failure as the CLI error
//! with the same kind, exit code, causes, hint and transaction.
//!
//! The wallet, transaction, Epicbox and profile commands map here; `families` maps the contact,
//! in-person, epic1, `epictx open` and `profile domain` commands. A file a command reads is read
//! here and goes in the request as the command's inline form (`--hex`, the text); a file it writes
//! is written from the answer (`Finish`), through the same helpers a direct run uses. serve never
//! opens a path the client named. A command serve cannot run, or one with an option it cannot
//! take, runs here and meets the lock.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper::header;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use crate::api::{Caller, VERSION, VERSION_HEADER};
use crate::cli::{
    Command, Epic1Args, Epic1Command, Epic1PayArgs, EpicboxCommand, FluffArg, ListingArgs,
    NodeCommand, PeerCommand, PlainHttpArg, ProfileCommand, SelectionArg, SendArgs,
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

/// What `POST /cli/run` carries: the command serve runs for the CLI. A file the command reads is
/// inline already, and a file it writes is not named.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CliCall {
    /// A command, as parsed.
    Command(Box<Command>),
    /// `contact export`: the answer holds the backup, which the CLI writes to its file.
    ContactExport,
    /// `contact import`: the backup the CLI read from its file.
    ContactImport { document: String },
    /// `profile domain file`: the answer holds the document, which the CLI writes to its file.
    DomainFile { relays: Vec<String> },
}

impl CliCall {
    /// A call to run `command`.
    fn of(command: Command) -> Self {
        Self::Command(Box::new(command))
    }

    /// The slate id of a call that moves money, drawn here when the command gave none, so the
    /// payment can be looked up, and made again safely, when no answer comes.
    fn slate_id(&mut self) -> Result<Option<String>, CliError> {
        let Self::Command(command) = self else {
            return Ok(None);
        };
        let (Command::Tx(TxCommand::Send(SendArgs {
            slate_id: SendSlateIdArg { slate_id: slate },
            ..
        }))
        | Command::Epic1(Epic1Args {
            command:
                Epic1Command::Pay(Epic1PayArgs {
                    slate_id: SendSlateIdArg { slate_id: slate },
                    ..
                }),
            ..
        })) = &mut **command
        else {
            return Ok(None);
        };
        let id = match slate {
            Some(given) => given.clone(),
            None => crate::commands::drawn_slate_id()?.to_string(),
        };
        *slate = Some(id.clone());
        Ok(Some(id))
    }
}

/// Whether `command` is one the CLI sends as it is: serve refuses any other, so the channel runs
/// what the client would send and no more. A command that names a file to read is not.
pub(crate) fn forwarded(command: &Command) -> bool {
    matches!(
        call(command),
        Some(Call {
            send: Body::Ready(CliCall::Command(_)),
            ..
        })
    )
}

/// The request a command stands for.
struct Call {
    send: Body,
    finish: Finish,
}

/// What is sent.
enum Body {
    Ready(CliCall),
    /// Made from a file or standard input, read once serve has answered the connection: a command
    /// that runs here reads its own files.
    Read(Box<dyn FnOnce() -> Result<CliCall, CliError> + Send>),
}

/// What the command does with the answer.
enum Finish {
    /// Print it as the command prints it.
    Print,
    /// Hand back the JSON report, which the CLI prints and draws a QR code from (`--qr`).
    Report,
    /// The answer holds the contact backup; write it to the file and report the file.
    ContactBackup(PathBuf),
    /// The answer holds the domain file; write it and report the file.
    DomainFile { path: Option<PathBuf>, force: bool },
}

impl Call {
    /// `command`, sent as it is.
    fn command(command: &Command) -> Option<Self> {
        Some(Self::ready(CliCall::of(command.clone())))
    }

    const fn ready(call: CliCall) -> Self {
        Self {
            send: Body::Ready(call),
            finish: Finish::Print,
        }
    }

    fn read(read: impl FnOnce() -> Result<CliCall, CliError> + Send + 'static) -> Self {
        Self {
            send: Body::Read(Box::new(read)),
            finish: Finish::Print,
        }
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

/// Runs `command` on the wallet serve holds, as [`run`] does, and returns its report rather than
/// its text: for `--qr`, which draws the code from the report.
pub(crate) async fn run_report(
    command: &Command,
    settings: &Settings,
) -> Result<Option<output::Report>, CliError> {
    let Some(call) = call(command) else {
        return Ok(None);
    };
    if !matches!(call.finish, Finish::Print) {
        return Ok(None);
    }
    let Some((stream, socket)) = service::connect(&settings.data_dir).await else {
        return Ok(None);
    };
    let json = exchange(
        stream,
        &socket,
        call.finish(Finish::Report),
        settings.output,
        &Caller::of(settings),
    )
    .await?;
    crate::qr::report_from_json(command, &json)
        .map(Some)
        .map_err(|e| CliError::ServeUnanswered {
            socket,
            source: e.into(),
        })
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
    call: Call,
    format: OutputFormat,
    caller: &Caller,
) -> Result<Zeroizing<String>, CliError> {
    let mut sent = match call.send {
        Body::Ready(sent) => sent,
        Body::Read(read) => read()?,
    };
    let slate_id = sent.slate_id()?;
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
    let body = Zeroizing::new(serde_json::to_vec(&sent).map_err(|e| unanswered(e.into()))?);
    // A file the answer is written to is made from the JSON report; the rest is printed as it is.
    let accept = match (&call.finish, format) {
        (Finish::Print, OutputFormat::Human) => "text/plain",
        _ => "application/json",
    };
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/cli/run")
        .header(header::HOST, "lepic")
        .header(header::ACCEPT, accept)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in caller.headers() {
        request = request.header(name, value);
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
    // A serve of another version may not know the channel or a field: say so, not what it says.
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
    // The channel's own failure is plain JSON; the router's refusals are problem documents.
    if !matches!(
        content_type.as_ref().and_then(|value| value.to_str().ok()),
        Some("application/json" | "application/problem+json")
    ) {
        return Err(unanswered(
            format!("serve answered {status} without an error document").into(),
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
        Finish::Print | Finish::Report => return Ok(text),
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

/// The report of [`CliCall::ContactExport`].
#[derive(Deserialize)]
struct Backup {
    #[serde(deserialize_with = "secret")]
    backup: Zeroizing<String>,
}

/// The report of [`CliCall::DomainFile`].
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

/// The fields of an error document the CLI error is built from: serve's failure of a command, or
/// a problem document of the router.
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

/// The request `command` stands for, when serve can run it with every option given. Each
/// argument struct is taken apart field by field where a field decides, so a new option is a
/// compile error here until it is mapped or refused.
fn call(command: &Command) -> Option<Call> {
    match command {
        Command::Wallet(
            WalletCommand::Info
            | WalletCommand::Address(_)
            | WalletCommand::Outputs(_)
            | WalletCommand::Scan(_),
        )
        | Command::Node(NodeCommand::Status)
        | Command::Tx(
            TxCommand::List(_) | TxCommand::Cancel(_) | TxCommand::Release(_) | TxCommand::Post(_),
        )
        | Command::Epicbox(EpicboxCommand::Peer(_))
        | Command::Profile(ProfileCommand::Show | ProfileCommand::Set(_))
        | Command::Peer(PeerCommand::Pins(_) | PeerCommand::Forget(_)) => Call::command(command),
        Command::Tx(TxCommand::Show(TxShowArgs {
            tx_id: Some(_),
            slate_id: SendSlateIdArg { slate_id: None },
            refresh: _,
        })) => Call::command(command),
        Command::Tx(TxCommand::Send(args)) => send(command, args),
        Command::Epicbox(EpicboxCommand::Status(ListingArgs {
            listing: None,
            generation: _,
        })) => Call::command(command),
        Command::Profile(ProfileCommand::Domain(args)) => families::domain(command, &args.command),
        Command::Contact(args) => families::contact(command, args),
        Command::InPerson(args) => families::in_person(command, args),
        Command::Epic1(args) => families::epic1(command, args),
        Command::Epictx(args) => families::epictx(command, args),
        _ => None,
    }
}

/// `tx send` to an Epicbox address, or an HTTP listener's URL, with the options serve takes.
fn send(command: &Command, args: &SendArgs) -> Option<Call> {
    let SendArgs {
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
        spend: SpendArgs {
            selection,
            ttl_blocks,
            ..
        },
        ..
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
    Call::command(command)
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

    use clap::Parser as _;

    fn parse(arguments: &[&str]) -> Command {
        let mut line = vec!["lepic"];
        line.extend_from_slice(arguments);
        crate::cli::Cli::try_parse_from(line).unwrap().command
    }

    /// The call the arguments stand for, with the files it reads read.
    fn sent(arguments: &[&str]) -> Option<CliCall> {
        match call(&parse(arguments))?.send {
            Body::Ready(call) => Some(call),
            Body::Read(read) => Some(read().unwrap()),
        }
    }

    /// The command sent for `arguments`.
    fn sent_command(arguments: &[&str]) -> Command {
        match sent(arguments) {
            Some(CliCall::Command(command)) => *command,
            other => panic!("{arguments:?}: {other:?}"),
        }
    }

    #[test]
    fn the_commands_serve_runs_are_sent_as_they_were_parsed() {
        let forwarded_lines: &[&[&str]] = &[
            &["wallet", "info"],
            &["wallet", "address"],
            &["wallet", "outputs", "--account", "a"],
            &["wallet", "scan", "--start-height", "5"],
            &["node", "status"],
            &["tx", "list", "--refresh"],
            &["tx", "show", "7"],
            &["tx", "cancel", "7"],
            &["tx", "release", "7"],
            &["tx", "post", "7", "--fluff"],
            &["tx", "send", "1", "--to", "a@relay.example"],
            &[
                "tx",
                "send",
                "1",
                "--to",
                "https://h.example/x",
                "--message",
                "m",
            ],
            &["epicbox", "status"],
            &["epicbox", "peer", "a@relay.example"],
            &["profile", "show"],
            &["profile", "set", "automated"],
            &["peer", "pins"],
            &["peer", "forget", "o", "--account", "a"],
            &["profile", "domain", "show"],
            &["profile", "domain", "attach"],
            &["contact", "invite", "--expiry", "1h"],
            &["contact", "list"],
            &["contact", "collect"],
            &["contact", "remove", "a b"],
            &["contact", "allow-invoices", "c1", "on"],
            &["contact", "sas", "c1", "mismatch"],
            &["contact", "keys", "n1", "keep-old"],
            &[
                "contact",
                "move-home",
                "relay.example:443",
                "--drain-days",
                "3",
            ],
            &["contact", "payload", "post", "c1", "--hex", "00ff"],
            &["contact", "payload", "ack", "p1"],
            &["contact", "payload", "list"],
            &["in-person", "invoice", "1.5", "--ttl-blocks", "20"],
            &["in-person", "send", "1", "--ttl-blocks", "20"],
            &["in-person", "receive", "--hex", "ab"],
            &["in-person", "read", "--hex", "ab"],
            &["in-person", "pay", "1", "--hex", "ab"],
            &["in-person", "take", "ab", "cd"],
            &["in-person", "finalize", "s1", "2", "--fluff"],
            &["in-person", "answers", "s1"],
            &["epic1", "address", "--index", "7"],
            &["epic1", "new-address"],
            &["epic1", "addresses", "--from", "2", "--limit", "5"],
            &["epic1", "links"],
            &["epic1", "retire", "3"],
            &["epic1", "pay", "epic:epic1x"],
            &["epic1", "post-next", "s1", "--hosts-ok"],
            &["epic1", "restore"],
            &["epic1", "issue-here"],
        ];
        for arguments in forwarded_lines {
            let command = parse(arguments);
            assert!(forwarded(&command), "{arguments:?}");
            let CliCall::Command(sent) = sent(arguments).unwrap() else {
                panic!("{arguments:?}")
            };
            // What serve reads back is the command that was parsed.
            let wire = serde_json::to_string(&CliCall::Command(sent)).unwrap();
            let CliCall::Command(read) = serde_json::from_str(&wire).unwrap() else {
                panic!("{arguments:?}")
            };
            assert_eq!(
                serde_json::to_value(&read).unwrap(),
                serde_json::to_value(&command).unwrap(),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn a_command_with_an_option_serve_lacks_runs_here() {
        let local: &[&[&str]] = &[
            &["wallet", "init"],
            &[
                "tx",
                "show",
                "--slate-id",
                "8a6e2f0c-4b1d-4c3e-9f2a-7d5b6c8e9f01",
            ],
            &["tx", "send", "1", "--to", "a@relay.example", "--fluff"],
            &[
                "tx",
                "send",
                "1",
                "--to",
                "a@relay.example",
                "--ttl-blocks",
                "5",
            ],
            &[
                "tx",
                "send",
                "1",
                "--to",
                "a@relay.example",
                "--selection",
                "all",
            ],
            &["tx", "send", "1", "--to-contact", "c1"],
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
            assert!(sent(arguments).is_none(), "{arguments:?}");
        }
    }

    #[test]
    fn the_files_a_command_writes_or_reads_stay_on_this_side() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();

        // A file read here is sent as the command's inline form, and serve refuses the path form.
        let payload = path("payload.bin");
        std::fs::write(&payload, [0x00, 0xff, 0x10]).unwrap();
        let arguments = [
            "contact",
            "payload",
            "post",
            "c1",
            "--file",
            payload.as_str(),
        ];
        assert!(!forwarded(&parse(&arguments)));
        let Command::Contact(crate::cli::ContactArgs {
            command:
                crate::cli::ContactCommand::Payload(crate::cli::ContactPayloadArgs {
                    command: crate::cli::ContactPayloadCommand::Post(post),
                }),
            ..
        }) = sent_command(&arguments)
        else {
            panic!("not a payload post")
        };
        assert_eq!((post.hex.as_deref(), post.file), (Some("00ff10"), None));

        let code = path("code.bin");
        std::fs::write(&code, [0xab, 0xcd]).unwrap();
        for command in ["read", "receive"] {
            let arguments = ["in-person", command, "--file", code.as_str()];
            assert!(!forwarded(&parse(&arguments)), "{command}");
            let Command::InPerson(crate::cli::InPersonArgs { command: sent, .. }) =
                sent_command(&arguments)
            else {
                panic!("{command}")
            };
            let (crate::cli::InPersonCommand::Read(crate::cli::InPersonReadArgs { code, .. })
            | crate::cli::InPersonCommand::Receive(crate::cli::InPersonReceiveArgs {
                code,
                ..
            })) = sent
            else {
                panic!("{command}")
            };
            assert_eq!((code.hex.as_deref(), code.file), (Some("abcd"), None));
        }
        let arguments = ["in-person", "take", "--file", code.as_str()];
        assert!(!forwarded(&parse(&arguments)));
        let Command::InPerson(crate::cli::InPersonArgs {
            command: crate::cli::InPersonCommand::Take(take),
            ..
        }) = sent_command(&arguments)
        else {
            panic!("not a take")
        };
        assert_eq!((take.input, take.file), (vec!["abcd".to_owned()], None));

        // The sealed text is read here; serve is given the text.
        let sealed = path("slate.epictx");
        std::fs::write(&sealed, "not a sealed slate").unwrap();
        let arguments = ["epictx", "open", sealed.as_str()];
        assert!(!forwarded(&parse(&arguments)));
        let error = call(&parse(&arguments));
        assert!(matches!(
            error,
            Some(Call {
                send: Body::Read(_),
                ..
            })
        ));

        // A file a command writes is not sent: serve answers with the content.
        let out = path("contacts.backup");
        let export = call(&parse(&["contact", "export", out.as_str()])).unwrap();
        assert!(matches!(export.send, Body::Ready(CliCall::ContactExport)));
        assert!(
            matches!(export.finish, Finish::ContactBackup(file) if file.ends_with("contacts.backup"))
        );
        let domain = call(&parse(&[
            "profile",
            "domain",
            "file",
            "--relay",
            "r.example:443",
            "--force",
        ]))
        .unwrap();
        let Body::Ready(CliCall::DomainFile { relays }) = domain.send else {
            panic!("not a domain file call")
        };
        assert_eq!(relays, ["r.example:443"]);
        assert!(matches!(
            domain.finish,
            Finish::DomainFile {
                path: None,
                force: true
            }
        ));
    }

    #[test]
    fn a_backup_is_read_here_and_sent_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.backup");
        let Some(Call {
            send: Body::Read(read),
            ..
        }) = call(&parse(&["contact", "import", missing.to_str().unwrap()]))
        else {
            panic!("import is read here")
        };
        // The file is read once the connection is made, and a file that is not there fails here.
        assert!(read().is_err());
    }

    #[test]
    fn every_call_survives_the_wire() {
        for call in [
            CliCall::ContactExport,
            CliCall::ContactImport {
                document: "text".to_owned(),
            },
            CliCall::DomainFile {
                relays: vec!["r.example:443".to_owned()],
            },
        ] {
            let wire = serde_json::to_string(&call).unwrap();
            let back: CliCall = serde_json::from_str(&wire).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
        }
        assert!(serde_json::from_str::<CliCall>(r#"{"command":"nothing"}"#).is_err());
        assert!(serde_json::from_str::<CliCall>("{}").is_err());
    }

    #[test]
    fn a_payment_carries_a_slate_id_drawn_when_none_is_given() {
        let given = "8a6e2f0c-4b1d-4c3e-9f2a-7d5b6c8e9f01";
        let payments: &[&[&str]] = &[
            &["tx", "send", "1", "--to", "a@relay.example"],
            &["epic1", "pay", "epic:epic1x"],
        ];
        let slate_of = |command: &Command| match command {
            Command::Tx(TxCommand::Send(args)) => args.slate_id.slate_id.clone(),
            Command::Epic1(Epic1Args {
                command: Epic1Command::Pay(args),
                ..
            }) => args.slate_id.slate_id.clone(),
            other => panic!("{other:?}"),
        };
        for arguments in payments {
            let draw = |arguments: &[&str]| {
                let mut sent = sent(arguments).unwrap();
                let slate_id = sent.slate_id().unwrap().unwrap();
                let CliCall::Command(command) = sent else {
                    panic!("{arguments:?}")
                };
                (slate_id, slate_of(&command))
            };
            let (drawn, in_command) = draw(arguments);
            assert_eq!(in_command.as_deref(), Some(drawn.as_str()), "{arguments:?}");
            crate::commands::caller_slate_id(&drawn).unwrap();
            let mut with_given = arguments.to_vec();
            with_given.extend(["--slate-id", given]);
            let (kept, in_command) = draw(&with_given);
            assert_eq!(kept, given, "{arguments:?}");
            assert_eq!(in_command.as_deref(), Some(given), "{arguments:?}");
        }
        let mut other = CliCall::Command(Box::new(Command::Wallet(WalletCommand::Info)));
        assert_eq!(other.slate_id().unwrap(), None);
        assert_eq!(CliCall::ContactExport.slate_id().unwrap(), None);
    }

    #[tokio::test]
    async fn a_payment_serve_does_not_answer_names_its_slate_id() {
        let (client, server) = UnixStream::pair().unwrap();
        drop(server);
        let call = call(&parse(&["epic1", "pay", "epic:epic1x"])).unwrap();
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
            call_of(&["wallet", "info"]),
            OutputFormat::Json,
            &caller(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Transport, "{error:?}");
    }

    fn call_of(arguments: &[&str]) -> Call {
        call(&parse(arguments)).unwrap()
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
                call_of(&["epic1", "addresses"]),
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
}
