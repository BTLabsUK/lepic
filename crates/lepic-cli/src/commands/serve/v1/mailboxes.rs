// SPDX-License-Identifier: Apache-2.0
//! The mailbox list native mail goes to: `/mailboxes`. Each call runs the `lepic mailbox`
//! command, so a change is written to the settings file and serve's sessions follow it at once.

use serde::Deserialize;

use super::super::Service;
use super::Reply;
use crate::api::model::{Mailbox, MailboxAdded, MailboxProbe, Mailboxes, ProbeStep};
use crate::api::{Category, Context, Problem, Request, created, ok};
use crate::cli::{Command, MailboxAddArgs, MailboxCommand, MailboxHostArg};
use crate::host::Host;
use crate::output::{MailboxEntryReport, MailboxProbeReport, ProbeStepReport, Report};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddBody {
    host: String,
    #[serde(default)]
    anyway: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    host: String,
}

pub(super) async fn list<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    ok(&listed(service).await?)
}

/// Tests the mailbox and adds it when the test passed or `anyway` is set: 201 when it was
/// added, 200 when it was in the list already.
pub(super) async fn add<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: AddBody = request.json()?;
    let command = MailboxCommand::Add(MailboxAddArgs {
        host: MailboxHostArg { host: body.host },
        anyway: body.anyway,
    });
    let Report::MailboxAdd(report) = run(service, command).await? else {
        return Err(unexpected());
    };
    let answer = MailboxAdded {
        added: report.added,
        probe: probe(report.probe),
        mailboxes: listed(service).await?.mailboxes,
    };
    if answer.added {
        created(&answer)
    } else {
        ok(&answer)
    }
}

/// Removes the mailbox: a shipped one is marked removed, an added one leaves the list. 404 when
/// it is not in the list.
pub(super) async fn remove<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let host = request.param("host")?.to_owned();
    let command = MailboxCommand::Remove(MailboxHostArg { host });
    let Report::MailboxRemove(report) = run(service, command).await? else {
        return Err(unexpected());
    };
    if !report.removed {
        return Err(Problem::not_found("no such mailbox in the list"));
    }
    ok(&listed(service).await?)
}

/// One test of a mailbox; changes nothing.
pub(super) async fn probe_one<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: ProbeBody = request.json()?;
    let command = MailboxCommand::Probe(MailboxHostArg { host: body.host });
    let Report::MailboxProbe(report) = run(service, command).await? else {
        return Err(unexpected());
    };
    ok(&probe(report))
}

pub(super) async fn listed<H: Host>(service: &Service<'_, H>) -> Result<Mailboxes, Problem> {
    let Report::MailboxList(report) = run(service, MailboxCommand::List).await? else {
        return Err(unexpected());
    };
    Ok(Mailboxes {
        mailboxes: report.mailboxes.into_iter().map(mailbox).collect(),
        left_out: report.left_out,
    })
}

/// Runs the mailbox command; a refused host is a problem at `/host`.
async fn run<H: Host>(
    service: &Service<'_, H>,
    command: MailboxCommand,
) -> Result<Report, Problem> {
    let names_host = matches!(command, MailboxCommand::Add(_) | MailboxCommand::Probe(_));
    service
        .command(Command::Mailbox(command))
        .await
        .map_err(|error| {
            let problem = Problem::from(error);
            match problem.code() {
                "mailbox_invalid" | "mailbox_not_public" if names_host => {
                    problem.with_param("/host")
                }
                _ => problem,
            }
        })
}

fn unexpected() -> Problem {
    Problem::of(
        Category::Internal,
        "internal",
        "the mailbox command answered another report",
    )
}

fn mailbox(entry: MailboxEntryReport) -> Mailbox {
    Mailbox {
        host: entry.host,
        origin: entry.origin.to_owned(),
        push: entry.push,
        no_mux: entry.no_mux,
        last_success_at: entry.last_success,
        failures: entry.failures,
        last_error: entry.last_error,
    }
}

fn probe(report: MailboxProbeReport) -> MailboxProbe {
    MailboxProbe {
        host: report.host,
        tls: step(report.tls),
        greeting: step(report.greeting),
        push: step(report.push),
        passed: report.passed,
    }
}

fn step(step: ProbeStepReport) -> ProbeStep {
    ProbeStep {
        result: step.result.to_owned(),
        error: step.error,
    }
}
