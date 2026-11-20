// SPDX-License-Identifier: Apache-2.0
//! Reports of `lepic epic1` and `lepic epictx`.

use std::io::Write as _;

use serde::{Deserialize, Serialize};

use super::{Report, printable};

/// The epic1 address of an account, from `epic1 address`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Epic1AddressReport {
    pub account: String,
    pub address: String,
}

/// A link made, from `epic1 link`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Epic1LinkReport {
    /// The link text, `epic:epic1…`.
    pub link: String,
    pub address: String,
}

/// What an epic1 link asks, from `epic1 read`.
#[derive(Debug, Serialize)]
pub struct Epic1ReadReport {
    /// The payee: the epic1 address, never a mailbox.
    pub address: String,
    pub amount: Option<String>,
    pub message: Option<String>,
    pub label: Option<String>,
    /// The host of the `http` or `tor` entry a payment is posted to first; absent when it is
    /// posted to the payee's mailbox on the relays of the list.
    pub http_host: Option<String>,
    /// How many `mailbox=` entries the link holds, which a payment does not use: it goes through
    /// the payer's own mailbox list.
    pub ignored_mailboxes: usize,
}

/// One post of a payment to a relay of its link.
#[derive(Debug, Serialize)]
pub struct Epic1AttemptReport {
    pub host: String,
    /// Why the post failed; absent when it went through.
    pub error: Option<String>,
    /// The post failed after the payment was sent: the relay may hold it.
    pub uncertain: bool,
    /// The mailbox refused the post: its words, the wait it asked for and whether the post goes
    /// again. Absent when no mailbox refused it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<super::MailboxRefusalReport>,
}

/// A payment to an epic1 link, from `epic1 pay` and `epic1 post-next`.
#[derive(Debug, Serialize)]
pub struct Epic1PaidReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub address: String,
    /// What the payment paid the payee, as `tx send` reports it to any address.
    pub amount: Option<String>,
    /// The fee of the payment.
    pub fee: Option<String>,
    /// The transaction's state now, as `tx send` names it.
    pub state: Option<&'static str>,
    /// Always `epic1`.
    pub transport: &'static str,
    /// The epic1 address paid; the same as `address`.
    pub destination: String,
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

/// An answer this wallet made for a payment taken at the delivery mailbox of an open address.
#[derive(Debug, Serialize)]
pub struct Epic1AnswerReport {
    pub tx_id: u32,
    pub slate_id: String,
    /// The relay of the payer's reply mailbox, as written.
    pub mailbox: String,
    pub posted: bool,
}

/// The answers to payments taken at delivery mailboxes, from `epic1 answers`.
#[derive(Debug, Serialize)]
pub struct Epic1AnswersReport {
    pub answers: Vec<Epic1AnswerReport>,
}

/// The delivery mailboxes read after a restore, from `epic1 restore`.
#[derive(Debug, Serialize)]
pub struct Epic1RestoreReport {
    /// Payments taken and answers finalized.
    pub taken: usize,
    /// The mailboxes of the list that were not read, each with why.
    pub not_read: Vec<Epic1NotReadReport>,
}

/// A mailbox a restore did not read.
#[derive(Debug, Serialize)]
pub struct Epic1NotReadReport {
    pub host: String,
    pub reason: String,
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
        Report::Epic1Link(r) => writeln!(out, "{}", r.link),
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
            if r.ignored_mailboxes > 0 {
                writeln!(
                    out,
                    "The link names {} mailbox(es); they are not used.",
                    r.ignored_mailboxes
                )?;
            }
            match &r.http_host {
                Some(host) => writeln!(out, "Posted to {}.", printable(host)),
                None => writeln!(out, "Posted to the payee's slot on the wallet's mailboxes."),
            }
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
        Report::Epic1Restore(r) => {
            r.not_read
                .iter()
                .try_for_each(|entry| writeln!(out, "{} not read: {}", entry.host, entry.reason))?;
            writeln!(out, "{} payment(s) taken or finalized.", r.taken)
        }
        Report::EpictxOpen(r) => {
            let text = serde_json::to_string_pretty(&r.slate).map_err(std::io::Error::other)?;
            writeln!(out, "{text}")
        }
        _ => Ok(()),
    }
}
