// SPDX-License-Identifier: Apache-2.0
//! `lepic epic1`: payments taken at an epic1 address through links, and epic1 links paid
//! (RFC 0003 §5.19); `lepic epictx open`: an `.epictx` file shown as JSON (§5.10).

use lepic_primitives::amount::Amount;
use lepic_store::WalletStore as _;
use lepic_wallet::send::{SendError, SendRequest};
use lepic_wallet_contacts::{
    ContactError, ContactRelays, Epic1AnswerView, Epic1LinkKind, Epic1LinkRequest, Epic1LinkView,
    Epic1Paid, Epic1PayRequest, Epic1Refusal, WalletContacts,
};

use super::contact::{SlateFile, purpose_name, read_sealed, relays_in_mode};
use super::in_person::{host_report, slate_id};
use super::{Opened, Run, Spend, amount_sent, caller_slate_id, drawn_slate_id};
use crate::amount::{format_amount, parse_amount};
use crate::api::links::{self, Kept, kept_key, link_id};
use crate::cli::{Epic1Args, Epic1Command, Epic1LinkArgs, Epic1PayArgs, EpictxCommand};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    Epic1AddressEntryReport, Epic1AddressReport, Epic1AddressesReport, Epic1AnswerReport,
    Epic1AnswersReport, Epic1AttemptReport, Epic1IssuerReport, Epic1LinkEntryReport,
    Epic1LinkReport, Epic1LinksReport, Epic1PaidReport, Epic1PostReport, Epic1ReadReport,
    Epic1RestoreReport, Epic1RetireReport, EpictxOpenReport, Report,
};

/// The report of `epic1 addresses` for the account labelled `account`.
fn addresses_report(account: String, page: lepic_wallet_contacts::Epic1Addresses) -> Report {
    Report::Epic1Addresses(Epic1AddressesReport {
        account,
        highest: page.highest,
        addresses: page
            .addresses
            .into_iter()
            .map(|view| Epic1AddressEntryReport {
                index: view.index,
                address: view.address,
            })
            .collect(),
    })
}

impl<H: Host> Run<'_, H> {
    pub(super) async fn epic1(&mut self, args: Epic1Args) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let wallet = &opened.wallet;
        let relays = relays_in_mode(
            &opened,
            args.offline,
            args.epicbox_off,
            &self.settings.servers.meeting_relays,
        );
        let book = wallet.contact_book();
        Ok(match args.command {
            Epic1Command::Address(args) => {
                let account = wallet.account(&args.account.account)?.index;
                let address = book.epic1_address_at(account, args.index).await?;
                Report::Epic1Address(Epic1AddressReport {
                    account: args.account.account,
                    index: args.index,
                    address: address.encode(),
                })
            }
            Epic1Command::NewAddress(args) => {
                let account = wallet.account(&args.account)?.index;
                let (index, address) = book.epic1_new_address(account).await?;
                Report::Epic1Address(Epic1AddressReport {
                    account: args.account,
                    index,
                    address: address.encode(),
                })
            }
            Epic1Command::IssueHere => {
                book.epic1_issue_here().await?;
                Report::Epic1Issuer(Epic1IssuerReport { issuing: true })
            }
            Epic1Command::Addresses(args) => {
                let account = wallet.account(&args.account.account)?.index;
                let page = book.epic1_addresses(account, args.from, args.limit).await?;
                addresses_report(args.account.account, page)
            }
            Epic1Command::Link(args) => link(&opened, &relays, args).await?,
            Epic1Command::Retire(args) => {
                book.epic1_retire(wallet.account(&args.account.account)?.index, args.n)
                    .await?;
                Report::Epic1Retire(Epic1RetireReport {
                    account: args.account.account,
                    n: args.n,
                    retired: true,
                })
            }
            Epic1Command::Links => Report::Epic1Links(Epic1LinksReport {
                links: book
                    .epic1_links()
                    .await?
                    .into_iter()
                    .map(link_entry)
                    .collect(),
            }),
            Epic1Command::Read(args) => {
                let read = book.epic1_read(&relays, &args.link)?;
                Report::Epic1Read(Epic1ReadReport {
                    address: read.address,
                    amount: read.amount.map(format_amount),
                    message: read.message,
                    label: read.label,
                    hosts: read.hosts.iter().map(host_report).collect(),
                })
            }
            Epic1Command::Pay(args) => {
                let data_dir = self.settings.data_dir.clone();
                let (paid, repeated) = pay(&opened, &relays, args, &data_dir).await?;
                paid_report(paid, repeated)
            }
            Epic1Command::PostNext(args) => paid_report(
                book.epic1_post_next(&relays, slate_id(&args.slate_id)?, args.hosts_ok)
                    .await?,
                false,
            ),
            Epic1Command::Answers => Report::Epic1Answers(Epic1AnswersReport {
                answers: book
                    .epic1_answers(&relays)
                    .await?
                    .into_iter()
                    .map(answer_entry)
                    .collect(),
            }),
            Epic1Command::PostAnswer(args) => {
                let slate_id = slate_id(&args.slate_id)?;
                book.epic1_post_answer(&relays, slate_id, args.relay_ok)
                    .await?;
                Report::Epic1Post(Epic1PostReport {
                    slate_id: slate_id.to_string(),
                    posted: true,
                })
            }
            Epic1Command::Restore => Report::Epic1Restore(Epic1RestoreReport {
                taken: book.epic1_restore(&relays).await?,
            }),
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

/// Issues a link to the epic1 address of the account.
async fn link<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: Epic1LinkArgs,
) -> Result<Report, CliError> {
    let Epic1LinkArgs {
        account,
        index,
        amount,
        message,
        printed,
        epicbox: link_relays,
    } = args;
    let wallet = &opened.wallet;
    let account = wallet.account(&account.account)?.index;
    let kind = if printed {
        Epic1LinkKind::Printed
    } else {
        Epic1LinkKind::OnScreen
    };
    let request = Epic1LinkRequest {
        account,
        index,
        amount: amount.as_deref().map(parse_amount).transpose()?,
        message: message.message.clone(),
        kind,
        relays: link_relays,
    };
    // Kept for `GET /api/v1/links` as serve keeps it, with the mailbox in one transaction.
    let mut kept = Kept {
        text: String::new(),
        address_index: index,
        amount,
        message: message.message,
    };
    let record = links::record(account, kind, &kept, None).map_err(kept_error)?;
    let issued = wallet
        .contact_book()
        .epic1_link_recorded(relays, request, record)
        .await?;
    kept.text.clone_from(&issued.link);
    let text = serde_json::to_string(&kept).map_err(kept_error)?;
    let key = kept_key(&link_id(account, issued.kind, issued.n));
    wallet
        .session()?
        .store
        .write(|repos| repos.put_setting(&key, &text))?;
    Ok(Report::Epic1Link(Epic1LinkReport {
        link: issued.link,
        address: issued.address,
        index: issued.index,
        kind: kind_name(issued.kind),
        n: issued.n,
    }))
}

fn kept_error(error: serde_json::Error) -> CliError {
    CliError::Io {
        what: "keep the link for the API",
        source: std::io::Error::other(error),
    }
}

/// Pays an epic1 link: the amount given, or the one the link asks. Returns the payment and
/// whether it was made before under the caller's slate id, in which case nothing is sent.
async fn pay<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: Epic1PayArgs,
    data_dir: &std::path::Path,
) -> Result<(Epic1Paid, bool), CliError> {
    let Epic1PayArgs {
        link,
        amount,
        account,
        message,
        spend,
        hosts_ok,
        slate_id,
    } = args;
    let wallet = &opened.wallet;
    let book = wallet.contact_book();
    let caller_slate = slate_id
        .slate_id
        .as_deref()
        .map(caller_slate_id)
        .transpose()?;
    let account = wallet.account(&account.account)?.index;
    let amount: Amount = match amount {
        Some(amount) => parse_amount(&amount)?,
        None => book
            .epic1_read(relays, &link.link)?
            .amount
            .ok_or(CliError::Epic1Amount)?,
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
    let spend = Spend::from_args(&spend)?;
    let send = SendRequest {
        minimum_confirmations: spend.minimum_confirmations,
        change_outputs: spend.change_outputs,
        strategy: spend.strategy,
        ttl_blocks: spend.ttl_blocks,
        message: message.message,
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
            },
            hosts_ok,
        )
        .await;
    match (paid, caller_slate) {
        (Ok(paid), _) => Ok((paid, false)),
        // A payment under the same id that ran at the same time stored its transaction first,
        // or its payment, which then waits for its answer.
        (
            Err(
                error @ (ContactError::Send(SendError::SlateIdTaken { sent: Some(_), .. })
                | ContactError::Epic1(Epic1Refusal::PaymentPending)),
            ),
            Some(slate_id),
        ) => match first.find(opened, slate_id).await {
            Ok(Some(paid)) => Ok((paid, true)),
            _ => Err(error.into()),
        },
        (Err(error), _) => Err(error.into()),
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

fn kind_name(kind: Epic1LinkKind) -> &'static str {
    match kind {
        Epic1LinkKind::OnScreen => "on_screen",
        Epic1LinkKind::Printed => "printed",
    }
}

fn link_entry(view: Epic1LinkView) -> Epic1LinkEntryReport {
    Epic1LinkEntryReport {
        account: view.account.0,
        index: view.index,
        kind: kind_name(view.kind),
        n: view.n,
        issued_at: view.issued_at.to_string(),
        used_at: view.used_at.map(|used| used.to_string()),
        relays: view.relays,
    }
}

fn answer_entry(view: Epic1AnswerView) -> Epic1AnswerReport {
    Epic1AnswerReport {
        tx_id: view.tx_id.0,
        slate_id: view.slate_id.to_string(),
        mailbox: view.mailbox,
        host: view.report.as_ref().map(host_report),
        posted: view.posted,
    }
}

fn paid_report(paid: Epic1Paid, repeated: bool) -> Report {
    Report::Epic1Paid(Epic1PaidReport {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        address: paid.address,
        attempts: paid
            .attempts
            .into_iter()
            .map(|attempt| Epic1AttemptReport {
                host: attempt.host,
                error: attempt.error,
                uncertain: attempt.uncertain,
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
            }],
            posted: Some(0),
            uncertain: None,
        };
        let json = serde_json::to_value(paid_report(paid, false)).unwrap();
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
                "attempts",
                "posted",
                "posted_ok",
                "repeated",
                "slate_id",
                "tx_id",
                "uncertain"
            ]
        );
    }
}
