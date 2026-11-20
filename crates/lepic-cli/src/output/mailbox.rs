// SPDX-License-Identifier: Apache-2.0
//! Reports of `lepic mailbox`.

use std::io::Write as _;

use serde::Serialize;

use super::{Report, printable, short_time};

/// One mailbox of the list, from `mailbox list`.
#[derive(Debug, Serialize)]
pub struct MailboxEntryReport {
    /// `domain` or `domain:port`; the port is left out when it is the default one.
    pub host: String,
    /// `shipped` or `added`.
    pub origin: &'static str,
    /// Whether the mailbox offered push (mux/1) at its last greeting; `null` before any answer.
    pub push: Option<bool>,
    /// The mailbox is known to lack mux/1: it answered without it, and the wallet neither reads
    /// it nor posts to it. Not the same as unreachable, which is `failures` and `last_error`.
    pub no_mux: bool,
    /// When a session last attached to it, RFC 3339; `null` when none has yet.
    pub last_success: Option<String>,
    /// Sessions lost since the last success.
    pub failures: u32,
    pub last_error: Option<String>,
}

/// The mailbox list, from `mailbox list`.
#[derive(Debug, Serialize)]
pub struct MailboxListReport {
    pub mailboxes: Vec<MailboxEntryReport>,
    /// Mailboxes the settings name that the wallet does not use, because the list holds at most
    /// 16. Left out of the report when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub left_out: Vec<String>,
}

/// One step of a mailbox test.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeStepReport {
    /// `passed`, `failed` or `not_reached`.
    pub result: &'static str,
    /// Why the step failed.
    pub error: Option<String>,
}

/// What a test of one mailbox found, from `mailbox probe` and `mailbox add`.
#[derive(Debug, Clone, Serialize)]
pub struct MailboxProbeReport {
    pub host: String,
    /// The connection, its TLS handshake and the websocket upgrade.
    pub tls: ProbeStepReport,
    /// The mailbox answered the greeting.
    pub greeting: ProbeStepReport,
    /// The mailbox offers push (mux/1), which the wallet reads by.
    pub push: ProbeStepReport,
    /// Every step passed.
    pub passed: bool,
}

/// A mailbox added, from `mailbox add`.
#[derive(Debug, Serialize)]
pub struct MailboxAddReport {
    pub host: String,
    /// False when the mailbox was in the list already; nothing was written.
    pub added: bool,
    pub probe: MailboxProbeReport,
}

/// A mailbox removed, from `mailbox remove`.
#[derive(Debug, Serialize)]
pub struct MailboxRemoveReport {
    pub host: String,
    /// False when the mailbox was not in the list; nothing was written.
    pub removed: bool,
}

/// The three lines of a test.
pub(crate) fn probe_lines(report: &MailboxProbeReport) -> String {
    [
        ("tls", &report.tls),
        ("greeting", &report.greeting),
        ("push", &report.push),
    ]
    .iter()
    .map(|(name, step)| match &step.error {
        Some(error) => format!("{name}: {} ({})", step.result, printable(error)),
        None => format!("{name}: {}", step.result),
    })
    .collect::<Vec<_>>()
    .join("\n")
}

/// A mailbox report. Writes nothing for any other.
pub(super) fn write_mailbox_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::MailboxList(r) => {
            r.mailboxes.iter().try_for_each(|entry| {
                let push = match (entry.push, entry.no_mux) {
                    (_, true) => "no mux/1",
                    (Some(true), _) => "yes",
                    (Some(false), _) => "no",
                    (None, _) => "not known",
                };
                let last = entry
                    .last_success
                    .as_deref()
                    .map_or_else(|| "not tried".to_owned(), short_time);
                write!(
                    out,
                    "{}  {}  push: {push}  last success: {last}  failures: {}",
                    entry.host, entry.origin, entry.failures
                )?;
                match &entry.last_error {
                    Some(error) => writeln!(out, "  last error: {}", printable(error)),
                    None => writeln!(out),
                }
            })?;
            if r.left_out.is_empty() {
                return Ok(());
            }
            writeln!(
                out,
                "Not used, the list holds at most {} mailboxes: {}",
                lepic_wallet_contacts::MAX_MAILBOXES,
                r.left_out.join(", ")
            )
        }
        Report::MailboxProbe(r) => writeln!(out, "{}\n{}", r.host, probe_lines(r)),
        Report::MailboxAdd(r) => {
            writeln!(out, "{}", probe_lines(&r.probe))?;
            if r.added {
                writeln!(out, "Mailbox {} added.", r.host)
            } else {
                writeln!(out, "Mailbox {} is in the list already.", r.host)
            }
        }
        Report::MailboxRemove(r) if r.removed => writeln!(out, "Mailbox {} removed.", r.host),
        Report::MailboxRemove(r) => writeln!(out, "Mailbox {} is not in the list.", r.host),
        _ => Ok(()),
    }
}
