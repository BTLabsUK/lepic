// SPDX-License-Identifier: Apache-2.0
//! `POST /cli/run`: the private channel through which the CLI has serve run a command on the
//! wallet it holds (ADR 0053). It exists on the Unix socket only, is not part of the wallet API's
//! document, and answers what the command prints when it runs on its own.

use hyper::body::Bytes;
use hyper::header;
use hyper::{Response, StatusCode};
use serde::Serialize;

use super::Service;
use crate::api::{Body, Category, Problem, Request, response};
use crate::commands::{contact, profile};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{self, ContactBackupReport, Report};
use crate::settings::OutputFormat;
use crate::through_serve::{CliCall, forwarded};

/// What the CLI is answered when its command fails: the fields it prints the same error from.
/// The names are those of the wallet API's problem documents, so one reader serves both.
#[derive(Serialize)]
struct Failure {
    code: &'static str,
    detail: String,
    causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_id: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recovery: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// Runs the call in `request` and answers with its report, or with the failure of the command.
/// A body that is not a call, or a command serve does not run for the CLI, is a 400.
pub(super) async fn run<H: Host>(
    service: &Service<'_, H>,
    request: Request,
) -> Result<Response<Body>, Problem> {
    let call: CliCall = request.json()?;
    let people = request
        .header(header::ACCEPT.as_str())
        .is_some_and(|accept| accept.starts_with("text/plain"));
    let answered = match call {
        CliCall::Command(command) if !forwarded(&command) => {
            return Err(Problem::usage("this command does not run through serve"));
        }
        CliCall::Command(command) => service.command(*command).await,
        CliCall::ContactExport => contact::export_document(&service.held)
            .await
            .map(|backup| Report::ContactBackup(ContactBackupReport { backup })),
        CliCall::ContactImport { document } => contact::import_document(&service.held, document)
            .await
            .map(Report::ContactImport),
        CliCall::DomainFile { relays } => {
            profile::domain_document(&service.held, service.settings, &relays)
        }
    };
    Ok(match answered {
        Ok(report) if people => text(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            output::render(&report, OutputFormat::Human).as_str(),
        ),
        Ok(report) => text(
            StatusCode::OK,
            "application/json",
            output::render(&report, OutputFormat::Json).as_str(),
        ),
        Err(error) => failure(service, &error),
    })
}

/// The answer to a failed command: the status of the error's category and the document the CLI
/// builds the error from.
fn failure<H: Host>(service: &Service<'_, H>, error: &CliError) -> Response<Body> {
    let kind = error.kind();
    let chain = error.chain();
    let document = Failure {
        code: kind.name(),
        detail: chain.join(": "),
        causes: chain.get(1..).unwrap_or_default().into(),
        tx_id: error.tx_id(),
        recovery: crate::hint::recovery(error),
        hint: crate::hint::hint(error, Some(service.settings)),
    };
    let body = serde_json::to_string(&document).unwrap_or_else(|_| {
        // Every field is a string, a number or a list of strings; this keeps the status anyway.
        r#"{"code":"internal","detail":"the failure could not be written","causes":[]}"#.to_owned()
    });
    text(
        Category::of(kind).status(),
        "application/json",
        &format!("{body}\n"),
    )
}

/// `text`, as it is, with `status` and `content_type`.
fn text(status: StatusCode, content_type: &'static str, text: &str) -> Response<Body> {
    response(status, content_type, Bytes::copy_from_slice(text.as_bytes()))
}
