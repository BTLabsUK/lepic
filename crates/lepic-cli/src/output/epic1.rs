// SPDX-License-Identifier: Apache-2.0
//! Reports of `lepic epic1` and `lepic epictx`.

use std::io::Write as _;

use serde::{Deserialize, Deserializer, Serialize};

use super::{InPersonHostReport, Report, printable, short_time};

/// The epic1 address of an account, from `epic1 address`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Epic1AddressReport {
    pub account: String,
    /// The address's number in the account; 0 is its first address.
    pub index: u32,
    pub address: String,
}

/// The epic1 addresses an account issued, from `epic1 addresses`.
#[derive(Debug, Serialize)]
pub struct Epic1AddressesReport {
    pub account: String,
    /// The highest number issued or paid; every number up to it is issued.
    pub highest: u32,
    /// The addresses of the page, from the lowest number.
    pub addresses: Vec<Epic1AddressEntryReport>,
}

/// One address of `epic1 addresses`.
#[derive(Debug, Serialize)]
pub struct Epic1AddressEntryReport {
    pub index: u32,
    pub address: String,
}

/// A link issued, from `epic1 link`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Epic1LinkReport {
    /// The link text, `epic:epic1…?epicbox=…`.
    pub link: String,
    pub address: String,
    /// The number of the address in its account.
    pub index: u32,
    /// `on_screen` or `printed`.
    #[serde(deserialize_with = "link_kind")]
    pub kind: &'static str,
    pub n: u32,
}

/// The `kind` of an [`Epic1LinkReport`] serve answered.
fn link_kind<'de, D: Deserializer<'de>>(deserializer: D) -> Result<&'static str, D::Error> {
    super::known_word(deserializer, &["on_screen", "printed"])
}

/// A printed link freed, from `epic1 retire`.
#[derive(Debug, Serialize)]
pub struct Epic1RetireReport {
    pub account: String,
    pub n: u32,
    pub retired: bool,
}

/// A link mailbox in use.
#[derive(Debug, Serialize)]
pub struct Epic1LinkEntryReport {
    /// The account's index.
    pub account: u32,
    /// The number of the epic1 address the link pays; absent for a link from before numbers.
    pub index: Option<u32>,
    pub kind: &'static str,
    pub n: u32,
    pub issued_at: String,
    /// When a payment last arrived at the mailbox.
    pub used_at: Option<String>,
    pub relays: Vec<String>,
}

/// The link mailboxes in use, from `epic1 links`.
#[derive(Debug, Serialize)]
pub struct Epic1LinksReport {
    pub links: Vec<Epic1LinkEntryReport>,
}

/// What an epic1 link asks, from `epic1 read`.
#[derive(Debug, Serialize)]
pub struct Epic1ReadReport {
    /// The payee: the epic1 address, never a mailbox.
    pub address: String,
    pub amount: Option<String>,
    pub message: Option<String>,
    pub label: Option<String>,
    /// The relays a payment is posted to, in the order they are tried.
    pub hosts: Vec<InPersonHostReport>,
}

/// One post of a payment to a relay of its link.
#[derive(Debug, Serialize)]
pub struct Epic1AttemptReport {
    pub host: String,
    /// Why the post failed; absent when it went through.
    pub error: Option<String>,
    /// The post failed after the payment was sent: the relay may hold it.
    pub uncertain: bool,
}

/// A payment to an epic1 link, from `epic1 pay` and `epic1 post-next`.
#[derive(Debug, Serialize)]
pub struct Epic1PaidReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub address: String,
    pub attempts: Vec<Epic1AttemptReport>,
    /// The relay of the link, from 0, the payment was posted to; absent when every post failed.
    pub posted: Option<usize>,
    /// Whether the payment was posted to any relay; false when every post failed.
    pub posted_ok: bool,
    /// The payment was made before under the same `slate_id`; this run posted nothing, and
    /// `attempts` is empty.
    pub repeated: bool,
    /// The first relay of the link, from 0, that may hold the payment though its post failed;
    /// the payee may still take it from there.
    pub uncertain: Option<usize>,
}

/// An answer this wallet made for a payment taken at a link mailbox.
#[derive(Debug, Serialize)]
pub struct Epic1AnswerReport {
    pub tx_id: u32,
    pub slate_id: String,
    /// The relay of the payer's reply mailbox, as written.
    pub mailbox: String,
    /// The relay as it is shown before posting; absent when it cannot be posted to.
    pub host: Option<InPersonHostReport>,
    pub posted: bool,
}

/// The answers to payments taken at link mailboxes, from `epic1 answers`.
#[derive(Debug, Serialize)]
pub struct Epic1AnswersReport {
    pub answers: Vec<Epic1AnswerReport>,
}

/// An answer posted, from `epic1 post-answer`.
#[derive(Debug, Serialize)]
pub struct Epic1PostReport {
    pub slate_id: String,
    pub posted: bool,
}

/// This install made the one that issues new epic1 addresses, from `epic1 issue-here`.
#[derive(Debug, Serialize)]
pub struct Epic1IssuerReport {
    pub issuing: bool,
}

/// The link mailboxes read after a restore, from `epic1 restore`.
#[derive(Debug, Serialize)]
pub struct Epic1RestoreReport {
    /// Payments taken and answers finalized.
    pub taken: usize,
}

/// A slate in an .epictx file as it arrived, from `epictx open`.
#[derive(Debug, Serialize)]
pub struct EpictxOpenReport {
    /// The contact whose key signed the envelope; absent for an anonymous one.
    pub contact_id: Option<String>,
    /// The body is a `lepic.v1` slate.
    pub native: bool,
    /// `payment`, `deposit`, `withdrawal`, `refund` or `request`.
    pub purpose: Option<&'static str>,
    /// The sender's own reference, never trusted for crediting.
    pub reference: Option<String>,
    /// When the sender stops honouring the slate, in unix seconds; advisory.
    pub expires: Option<u64>,
    /// Every field of a `lepic.v1` slate, with its network, kernel features, header version
    /// and tail; for another slate its V3 JSON.
    pub slate: serde_json::Value,
}

/// A payment made before under the same slate id, which this run did not post again.
fn write_repeated(out: &mut Vec<u8>, r: &Epic1PaidReport) -> std::io::Result<()> {
    match r.posted {
        Some(_) => writeln!(
            out,
            "Payment {} was made before as transaction {} and posted; nothing was posted now.",
            r.slate_id, r.tx_id
        ),
        None => writeln!(
            out,
            "Payment {} was made before as transaction {} and is not posted; `lepic epic1 \
             post-next` tries the next relay.",
            r.slate_id, r.tx_id
        ),
    }
}

/// An epic1 or epictx report. Writes nothing for any other.
pub(super) fn write_epic1_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Epic1Address(r) => writeln!(out, "{}", r.address),
        Report::Epic1Addresses(r) => r
            .addresses
            .iter()
            .try_for_each(|entry| writeln!(out, "{}  {}", entry.index, entry.address)),
        Report::Epic1Link(r) => writeln!(out, "{}\n{} link {}.", r.link, kind_name(r.kind), r.n),
        Report::Epic1Retire(r) => writeln!(out, "Printed link {} retired.", r.n),
        Report::Epic1Links(r) if r.links.is_empty() => writeln!(out, "No links."),
        Report::Epic1Links(r) => r.links.iter().try_for_each(|link| {
            writeln!(
                out,
                "{}  {} {}  issued {}{}  {}",
                link.account,
                kind_name(link.kind),
                link.n,
                short_time(&link.issued_at),
                link.used_at
                    .as_deref()
                    .map(|used| format!("  used {}", short_time(used)))
                    .unwrap_or_default(),
                link.relays.join(" ")
            )
        }),
        Report::Epic1Read(r) => {
            writeln!(out, "Pays {}.", r.address)?;
            if let Some(amount) = &r.amount {
                writeln!(out, "Asks {amount}.")?;
            }
            if let Some(label) = &r.label {
                writeln!(out, "Label: {}", printable(label))?;
            }
            if let Some(message) = &r.message {
                writeln!(out, "Message: {}", printable(message))?;
            }
            r.hosts.iter().try_for_each(|host| {
                writeln!(
                    out,
                    "Posted to {}:{} ({}{}).",
                    host.host,
                    host.port,
                    host.host_rule,
                    if host.in_relay_list {
                        ", a known relay"
                    } else {
                        ""
                    }
                )
            })
        }
        Report::Epic1Paid(r) if r.repeated => write_repeated(out, r),
        Report::Epic1Paid(r) => {
            r.attempts
                .iter()
                .filter_map(|attempt| attempt.error.as_ref().map(|error| (&attempt.host, error)))
                .try_for_each(|(host, error)| writeln!(out, "{host}: {error}"))?;
            match r
                .posted
                .and_then(|n| r.attempts.last().map(|last| (n, last)))
            {
                Some((_, last)) => writeln!(
                    out,
                    "Payment {} posted to {}; transaction {}.",
                    r.slate_id, last.host, r.tx_id
                ),
                None => match r.uncertain.and_then(|n| r.attempts.get(n)) {
                    Some(attempt) => writeln!(
                        out,
                        "Payment {} may have reached {}: it did not answer. Do not pay again; \
                         `lepic epic1 post-next` posts the same payment to the next relay.",
                        r.slate_id, attempt.host
                    ),
                    None => writeln!(
                        out,
                        "Payment {} not posted; `lepic epic1 post-next` tries the next relay.",
                        r.slate_id
                    ),
                },
            }
        }
        Report::Epic1Answers(r) if r.answers.is_empty() => writeln!(out, "No answers."),
        Report::Epic1Answers(r) => r.answers.iter().try_for_each(|answer| {
            writeln!(
                out,
                "{}  {}  {}{}",
                answer.slate_id,
                answer.tx_id,
                answer.mailbox,
                if answer.posted { "  posted" } else { "" }
            )
        }),
        Report::Epic1Post(r) => writeln!(out, "Answer to {} posted.", r.slate_id),
        Report::Epic1Restore(r) => writeln!(out, "{} payment(s) taken or finalized.", r.taken),
        Report::Epic1Issuer(_) => writeln!(out, "This install issues new epic1 addresses."),
        Report::EpictxOpen(r) => {
            let text = serde_json::to_string_pretty(&r.slate).map_err(std::io::Error::other)?;
            writeln!(out, "{text}")
        }
        _ => Ok(()),
    }
}

fn kind_name(kind: &str) -> &'static str {
    if kind == "printed" {
        "Printed"
    } else {
        "On-screen"
    }
}
