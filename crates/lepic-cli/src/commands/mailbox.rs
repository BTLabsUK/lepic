// SPDX-License-Identifier: Apache-2.0
//! `lepic mailbox`: the list of mailboxes native mail goes to, and a test of one mailbox.

use lepic_epicbox::{ClientSettings, MailboxProbe, ProbeStep, RelayEndpoint, probe_mailbox};
use lepic_wallet_contacts::{
    ContactError, MailboxList, MailboxOrigin, MailboxStatus, mailbox_host, parse_mailbox,
};

use super::Run;
use super::contact::relays_in_mode;
use crate::cli::{MailboxAddArgs, MailboxCommand, MailboxHostArg};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    MailboxAddReport, MailboxEntryReport, MailboxListReport, MailboxProbeReport,
    MailboxRemoveReport, ProbeStepReport, Report, probe_lines,
};

impl<H: Host> Run<'_, H> {
    pub(super) async fn mailbox(&mut self, command: MailboxCommand) -> Result<Report, CliError> {
        if matches!(command, MailboxCommand::Add(_) | MailboxCommand::Remove(_)) {
            self.settings.servers.mailboxes.editable()?;
        }
        match command {
            MailboxCommand::List => Ok(self.mailbox_list()),
            MailboxCommand::Add(args) => self.mailbox_add(args).await,
            MailboxCommand::Remove(MailboxHostArg { host }) => {
                let endpoint = parse_mailbox(&host).map_err(ContactError::Mailboxes)?;
                let removed = self.settings.servers.mailboxes.remove(&endpoint)?;
                Ok(Report::MailboxRemove(MailboxRemoveReport {
                    host: mailbox_host(&endpoint),
                    removed,
                }))
            }
            MailboxCommand::Probe(MailboxHostArg { host }) => {
                let endpoint = parse_mailbox(&host).map_err(ContactError::Mailboxes)?;
                Ok(Report::MailboxProbe(self.probe(&endpoint).await?))
            }
        }
    }

    /// The list with each mailbox's health as the wallet `lepic serve` holds saw it; a command
    /// on its own saw nothing, so every mailbox reads not tried.
    fn mailbox_list(&self) -> Report {
        let list = self.settings.servers.mailboxes.current();
        let health = self.held.as_ref().map(|opened| {
            relays_in_mode(opened, false, &list)
                .mailbox_status()
                .into_iter()
        });
        let mut health = health.into_iter().flatten();
        let mailboxes = list
            .listed()
            .into_iter()
            .map(|listed| {
                let status = health.next();
                entry(&listed.endpoint, listed.origin, status)
            })
            .collect();
        Report::MailboxList(MailboxListReport {
            mailboxes,
            left_out: left_out(&list),
        })
    }

    /// Tests the mailbox, then adds it when the test passed or `anyway` is given.
    async fn mailbox_add(&mut self, args: MailboxAddArgs) -> Result<Report, CliError> {
        let MailboxAddArgs {
            host: MailboxHostArg { host },
            anyway,
        } = args;
        let endpoint = parse_mailbox(&host).map_err(ContactError::Mailboxes)?;
        let probe = self.probe(&endpoint).await?;
        if !probe.passed && !anyway {
            return Err(CliError::MailboxUntested {
                host: probe.host.clone(),
                probe: probe_lines(&probe),
            });
        }
        let added = self.settings.servers.mailboxes.add(endpoint)?;
        Ok(Report::MailboxAdd(MailboxAddReport {
            host: probe.host.clone(),
            added,
            probe,
        }))
    }

    /// One connection to `endpoint` over the wallet's relay route (tor when the wallet uses it),
    /// greeted and closed. Opens no wallet.
    async fn probe(&self, endpoint: &RelayEndpoint) -> Result<MailboxProbeReport, CliError> {
        let settings = ClientSettings::new(endpoint.clone(), self.settings.tuning.relay);
        let connector = self.host.relay(self.settings)?;
        let probe = probe_mailbox(&settings, connector.as_ref()).await;
        Ok(probe_report(mailbox_host(endpoint), &probe))
    }
}

/// The mailboxes the list names that `listed()` cuts at the limit: shipped ones the user did not
/// remove, then added ones, each once, that are not among the listed.
fn left_out(list: &MailboxList) -> Vec<String> {
    let listed: Vec<String> = list
        .listed()
        .iter()
        .map(|listed| mailbox_host(&listed.endpoint))
        .collect();
    let removed: Vec<String> = list.removed().iter().map(mailbox_host).collect();
    let shipped = list
        .shipped()
        .iter()
        .map(mailbox_host)
        .filter(|host| !removed.contains(host));
    let mut seen = listed;
    let mut out = Vec::new();
    for host in shipped.chain(list.added().iter().map(mailbox_host)) {
        if !seen.contains(&host) {
            seen.push(host.clone());
            out.push(host);
        }
    }
    out
}

fn entry(
    endpoint: &RelayEndpoint,
    origin: MailboxOrigin,
    status: Option<MailboxStatus>,
) -> MailboxEntryReport {
    let origin = match origin {
        MailboxOrigin::Shipped => "shipped",
        MailboxOrigin::Added => "added",
    };
    let last_success = status
        .as_ref()
        .and_then(|status| status.last_success)
        .and_then(|time| jiff::Timestamp::try_from(time).ok())
        .map(|time| time.to_string());
    MailboxEntryReport {
        host: mailbox_host(endpoint),
        origin,
        push: status.as_ref().and_then(|status| status.push),
        no_mux: status.as_ref().is_some_and(|status| status.no_mux),
        last_success,
        failures: status.as_ref().map_or(0, |status| status.failures),
        last_error: status.and_then(|status| status.last_error),
    }
}

fn probe_report(host: String, probe: &MailboxProbe) -> MailboxProbeReport {
    MailboxProbeReport {
        host,
        tls: step(&probe.tls),
        greeting: step(&probe.greeting),
        push: step(&probe.push),
        passed: probe.passed(),
    }
}

fn step(step: &ProbeStep) -> ProbeStepReport {
    match step {
        ProbeStep::Passed => ProbeStepReport {
            result: "passed",
            error: None,
        },
        ProbeStep::Failed(error) => ProbeStepReport {
            result: "failed",
            error: Some(error.clone()),
        },
        _ => ProbeStepReport {
            result: "not_reached",
            error: None,
        },
    }
}
