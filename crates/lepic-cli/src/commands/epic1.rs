// SPDX-License-Identifier: Apache-2.0
//! `lepic epic1`: payments taken at an epic1 address through links, and epic1 links paid
//! (RFC 0003 §5.19); `lepic epictx open`: an `.epictx` file shown as JSON (§5.10).

use lepic_primitives::amount::Amount;
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::send::{SendError, SendRequest};
use lepic_wallet::state::state_name;
use lepic_wallet_contacts::{
    ContactError, ContactRelays, Epic1AnswerView, Epic1LinkRequest, Epic1Paid, Epic1PayRequest,
    MethodId, RouteEntry, WalletContacts, parse_mailbox,
};

use super::contact::{SlateFile, purpose_name, read_sealed, relays_in_mode};
use super::in_person::slate_id;
use super::{Opened, Run, Spend, amount_sent, caller_slate_id, drawn_slate_id};
use crate::amount::{format_amount, format_units, parse_amount};
use crate::cli::{Epic1Args, Epic1Command, Epic1LinkArgs, Epic1PayArgs, EpictxCommand};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    Epic1AddressReport, Epic1AnswerReport, Epic1AnswersReport, Epic1AttemptReport, Epic1LinkReport,
    Epic1NotReadReport, Epic1PaidReport, Epic1ReadReport, Epic1RestoreReport, EpictxOpenReport,
    Report,
};

impl<H: Host> Run<'_, H> {
    pub(super) async fn epic1(&mut self, args: Epic1Args) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let wallet = &opened.wallet;
        let relays = relays_in_mode(
            &opened,
            args.offline,
            &self.settings.servers.mailboxes.current(),
        );
        let book = wallet.contact_book();
        Ok(match args.command {
            Epic1Command::Address(args) => {
                let account = wallet.account(&args.account.account)?.index;
                let address = book.epic1_address(account)?;
                Report::Epic1Address(Epic1AddressReport {
                    account: args.account.account,
                    address: address.encode(),
                })
            }
            Epic1Command::Link(args) => link(&opened, &relays, args)?,
            Epic1Command::Read(args) => {
                let read = book.epic1_read(&relays, &args.link)?;
                Report::Epic1Read(Epic1ReadReport {
                    address: read.address,
                    amount: read.amount.map(format_amount),
                    message: read.message,
                    label: read.label,
                    http_host: read.http_host,
                    ignored_mailboxes: read.ignored_mailboxes,
                })
            }
            Epic1Command::Pay(args) => {
                let data_dir = self.settings.data_dir.clone();
                let ttl = self.settings.send_ttl_blocks;
                let (paid, repeated) = pay(&opened, &relays, args, &data_dir, ttl).await?;
                paid_report(&opened, paid, repeated).await?
            }
            Epic1Command::PostNext(args) => {
                let paid = book
                    .epic1_post_next(&relays, slate_id(&args.slate_id)?)
                    .await?;
                paid_report(&opened, paid, false).await?
            }
            Epic1Command::Answers => Report::Epic1Answers(Epic1AnswersReport {
                answers: book
                    .epic1_answers()
                    .await?
                    .into_iter()
                    .map(answer_entry)
                    .collect(),
            }),
            Epic1Command::Restore => {
                let restored = book.epic1_restore(&relays).await?;
                Report::Epic1Restore(Epic1RestoreReport {
                    taken: restored.taken,
                    not_read: restored
                        .not_read
                        .into_iter()
                        .map(|entry| Epic1NotReadReport {
                            host: entry.host,
                            reason: entry.reason.to_string(),
                        })
                        .collect(),
                })
            }
        })
    }

    pub(super) async fn epictx(&mut self, command: EpictxCommand) -> Result<Report, CliError> {
        let EpictxCommand::Open(args) = command;
        let text = match args.text {
            Some(text) => {
                lepic_wallet_contacts::payment_file(text.as_bytes())?;
                text
            }
            None => read_sealed(&args.input)?,
        };
        let opened = self.open().await?;
        let view = opened.wallet.contact_book().epictx_open(&text).await?;
        Ok(Report::EpictxOpen(EpictxOpenReport {
            contact_id: view.contact_id.map(|id| id.to_string()),
            native: view.native,
            purpose: view.purpose.map(purpose_name),
            reference: view.reference,
            expires: view.expires,
            slate: view.slate,
        }))
    }
}

/// Makes a link: the account's epic1 address, with what the link asks.
fn link<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: Epic1LinkArgs,
) -> Result<Report, CliError> {
    let Epic1LinkArgs {
        account,
        amount,
        message,
        http,
        tor,
        qr: _,
    } = args;
    let wallet = &opened.wallet;
    let account = wallet.account(&account.account)?.index;
    let entries = http
        .into_iter()
        .map(|value| RouteEntry {
            method: MethodId::Http,
            value,
        })
        .chain(tor.into_iter().map(|value| RouteEntry {
            method: MethodId::Tor,
            value,
        }))
        .collect();
    let request = Epic1LinkRequest {
        account,
        amount: amount.as_deref().map(parse_amount).transpose()?,
        message: message.message,
        entries,
    };
    let issued = wallet.contact_book().epic1_link(relays, request)?;
    Ok(Report::Epic1Link(Epic1LinkReport {
        link: issued.link,
        address: issued.address,
    }))
}

/// Pays an epic1 link: the amount and message given, or those the link asks. Returns the payment
/// and whether it was made before under the caller's slate id, in which case nothing is sent.
async fn pay<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: Epic1PayArgs,
    data_dir: &std::path::Path,
    default_ttl_blocks: u64,
) -> Result<(Epic1Paid, bool), CliError> {
    let Epic1PayArgs {
        link,
        amount,
        account,
        message,
        spend,
        slate_id,
        mailboxes,
    } = args;
    let mailboxes = mailboxes
        .mailboxes
        .iter()
        .map(|host| parse_mailbox(host).map_err(ContactError::Mailboxes))
        .collect::<Result<Vec<_>, _>>()?;
    let wallet = &opened.wallet;
    let book = wallet.contact_book();
    let caller_slate = slate_id
        .slate_id
        .as_deref()
        .map(caller_slate_id)
        .transpose()?;
    let account = wallet.account(&account.account)?.index;
    // The link is read only for what the payer left out, and after a payment made again under
    // its slate id is found: that one is told without reading the link.
    let mut read = None;
    let amount: Amount = match amount {
        Some(amount) => parse_amount(&amount)?,
        None => {
            let asked = book.epic1_read(relays, &link.link)?;
            let amount = asked.amount.ok_or(CliError::Epic1Amount)?;
            read = Some(asked);
            amount
        }
    };
    let first = FirstPayment {
        relays,
        link: &link.link,
        account,
        amount,
    };
    if let Some(slate_id) = caller_slate
        && let Some(paid) = first.find(opened, slate_id).await?
    {
        return Ok((paid, true));
    }
    let asked_message = match (read, &message.message) {
        (_, Some(_)) => None,
        (Some(read), None) => read.message,
        (None, None) => book.epic1_read(relays, &link.link)?.message,
    };
    let message = chosen_message(message.message, asked_message);
    let spend = Spend::from_args(&spend)?.with_default_ttl(default_ttl_blocks);
    let send = SendRequest {
        minimum_confirmations: spend.minimum_confirmations,
        change_outputs: spend.change_outputs,
        strategy: spend.strategy,
        ttl_blocks: spend.ttl_blocks,
        message,
        slate_id: Some(caller_slate.map_or_else(drawn_slate_id, Ok)?),
        ..SendRequest::new(account, amount)
    };
    let slate_file = SlateFile::new(data_dir)?;
    let paid = book
        .epic1_pay(
            relays,
            Epic1PayRequest {
                link: link.link.clone(),
                send,
                slate_file: slate_file.path.clone(),
                mailboxes,
            },
        )
        .await;
    match (paid, caller_slate) {
        (Ok(paid), _) => Ok((paid, false)),
        // A payment under the same id that ran at the same time stored its transaction first.
        (
            Err(error @ ContactError::Send(SendError::SlateIdTaken { sent: Some(_), .. })),
            Some(slate_id),
        ) => match first.find(opened, slate_id).await {
            Ok(Some(paid)) => Ok((paid, true)),
            _ => Err(error.into()),
        },
        (Err(error), _) => Err(error.into()),
    }
}

/// The message a payment carries: the link's when none is given, none when the one given is
/// empty or only spaces.
pub(crate) fn chosen_message(given: Option<String>, asked: Option<String>) -> Option<String> {
    match given {
        None => asked,
        Some(given) if given.trim().is_empty() => None,
        Some(given) => Some(given),
    }
}

/// The payment a caller asks for, to compare with one made before under its slate id.
struct FirstPayment<'a> {
    relays: &'a ContactRelays,
    link: &'a str,
    account: lepic_store::AccountIndex,
    amount: Amount,
}

impl FirstPayment<'_> {
    /// The payment made before under `slate_id`, if there was one. A send under it that was
    /// not this payment (another account, amount or address, or no epic1 payment at all) is
    /// refused, since the caller asked for a payment that was not made.
    async fn find<N: lepic_node::NodeApi + 'static>(
        &self,
        opened: &Opened<N>,
        slate_id: lepic_wallet::event::SlateId,
    ) -> Result<Option<Epic1Paid>, CliError> {
        let Some(first) = opened.wallet.sent_with_slate(slate_id).await? else {
            return Ok(None);
        };
        let reused = CliError::SlateIdReused {
            tx_id: first.transaction.id.0,
        };
        let book = opened.wallet.contact_book();
        let Some(paid) = book.epic1_payment(slate_id).await? else {
            return Err(reused);
        };
        let address = book.epic1_read(self.relays, self.link)?.address;
        if first.transaction.entry.account != self.account
            || amount_sent(&first) != Some(self.amount.value())
            || paid.address != address
        {
            return Err(reused);
        }
        Ok(Some(paid))
    }
}

fn answer_entry(view: Epic1AnswerView) -> Epic1AnswerReport {
    Epic1AnswerReport {
        tx_id: view.tx_id.0,
        slate_id: view.slate_id.to_string(),
        mailbox: view.mailbox,
        posted: view.posted,
    }
}

/// The report of a payment, with the amount, fee and state of its stored transaction, so a
/// payment to an epic1 address reads like a send to any other address.
async fn paid_report<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    paid: Epic1Paid,
    repeated: bool,
) -> Result<Report, CliError> {
    let details = opened.wallet.sent_with_slate(paid.slate_id).await?;
    Ok(paid_report_of(paid, repeated, details.as_ref()))
}

fn paid_report_of(paid: Epic1Paid, repeated: bool, details: Option<&TransactionDetails>) -> Report {
    let entry = details.map(|details| &details.transaction.entry);
    Report::Epic1Paid(Epic1PaidReport {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        amount: details
            .and_then(amount_sent)
            .map(lepic_primitives::amount::Amount::new)
            .map(format_amount),
        fee: entry
            .map(|entry| format_units(entry.fee.map_or(0, lepic_primitives::amount::Fee::value))),
        state: entry.map(|entry| state_name(entry.state)),
        transport: "epic1",
        destination: paid.address.clone(),
        address: paid.address,
        attempts: paid
            .attempts
            .into_iter()
            .map(|attempt| Epic1AttemptReport {
                host: attempt.host,
                error: attempt.error,
                uncertain: attempt.uncertain,
                refusal: attempt.refusal.as_ref().map(Into::into),
            })
            .collect(),
        posted: paid.posted,
        posted_ok: paid.posted.is_some(),
        repeated,
        uncertain: paid.uncertain,
    })
}

#[cfg(test)]
mod tests {
    use lepic_wallet::event::SlateId;
    use lepic_wallet_contacts::Epic1Attempt;

    use super::*;

    #[test]
    fn a_paid_report_names_no_proof_address() {
        let paid = Epic1Paid {
            tx_id: lepic_store::TxId(7),
            slate_id: SlateId::from_bytes([4; 16]),
            address: "epic1test".into(),
            attempts: vec![Epic1Attempt {
                host: "relay.test".into(),
                error: None,
                uncertain: false,
                refusal: None,
            }],
            posted: Some(0),
            uncertain: None,
        };
        let json = serde_json::to_value(paid_report_of(paid, false, None)).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "address",
                "amount",
                "attempts",
                "destination",
                "fee",
                "posted",
                "posted_ok",
                "repeated",
                "slate_id",
                "state",
                "transport",
                "tx_id",
                "uncertain"
            ]
        );
    }
}
