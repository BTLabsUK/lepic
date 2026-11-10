// SPDX-License-Identifier: Apache-2.0
//! `lepic epic1`: payments taken at an epic1 address through links, and epic1 links paid
//! (RFC 0003 §5.19); `lepic epictx open`: an `.epictx` file shown as JSON (§5.10).

use lepic_primitives::amount::Amount;
use lepic_wallet::send::SendRequest;
use lepic_wallet_contacts::{
    ContactRelays, Epic1AnswerView, Epic1LinkKind, Epic1LinkRequest, Epic1LinkView, Epic1Paid,
    Epic1PayRequest, WalletContacts,
};

use super::contact::{SlateFile, purpose_name, read_sealed, relays_in_mode};
use super::in_person::{host_report, slate_id};
use super::{Opened, Run, Spend, drawn_slate_id};
use crate::amount::{format_amount, parse_amount};
use crate::cli::{Epic1Args, Epic1Command, Epic1LinkArgs, Epic1PayArgs, EpictxCommand};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    Epic1AddressReport, Epic1AnswerReport, Epic1AnswersReport, Epic1AttemptReport,
    Epic1LinkEntryReport, Epic1LinkReport, Epic1LinksReport, Epic1PaidReport, Epic1PostReport,
    Epic1ReadReport, Epic1RestoreReport, Epic1RetireReport, EpictxOpenReport, Report,
};

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
            Epic1Command::Address(account) => {
                let index = wallet.account(&account.account)?.index;
                Report::Epic1Address(Epic1AddressReport {
                    account: account.account,
                    address: book.epic1_address(index)?.encode(),
                })
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
                paid_report(pay(&opened, &relays, args, &data_dir).await?)
            }
            Epic1Command::PostNext(args) => paid_report(
                book.epic1_post_next(&relays, slate_id(&args.slate_id)?, args.hosts_ok)
                    .await?,
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
        amount,
        message,
        printed,
        epicbox: link_relays,
    } = args;
    let wallet = &opened.wallet;
    let request = Epic1LinkRequest {
        account: wallet.account(&account.account)?.index,
        amount: amount.as_deref().map(parse_amount).transpose()?,
        message: message.message,
        kind: if printed {
            Epic1LinkKind::Printed
        } else {
            Epic1LinkKind::OnScreen
        },
        relays: link_relays,
    };
    let issued = wallet.contact_book().epic1_link(relays, request).await?;
    Ok(Report::Epic1Link(Epic1LinkReport {
        link: issued.link,
        address: issued.address,
        kind: kind_name(issued.kind),
        n: issued.n,
    }))
}

/// Pays an epic1 link: the amount given, or the one the link asks.
async fn pay<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: Epic1PayArgs,
    data_dir: &std::path::Path,
) -> Result<Epic1Paid, CliError> {
    let Epic1PayArgs {
        link,
        amount,
        account,
        message,
        spend,
        proof,
        hosts_ok,
    } = args;
    let wallet = &opened.wallet;
    let book = wallet.contact_book();
    let amount: Amount = match amount {
        Some(amount) => parse_amount(&amount)?,
        None => book
            .epic1_read(relays, &link.link)?
            .amount
            .ok_or(CliError::Epic1Amount)?,
    };
    let spend = Spend::from_args(&spend)?;
    let send = SendRequest {
        minimum_confirmations: spend.minimum_confirmations,
        change_outputs: spend.change_outputs,
        strategy: spend.strategy,
        ttl_blocks: spend.ttl_blocks,
        message: message.message,
        slate_id: Some(drawn_slate_id()?),
        ..SendRequest::new(wallet.account(&account.account)?.index, amount)
    };
    let slate_file = SlateFile::new(data_dir)?;
    Ok(book
        .epic1_pay(
            relays,
            Epic1PayRequest {
                link: link.link,
                send,
                proof,
                slate_file: slate_file.path.clone(),
            },
            hosts_ok,
        )
        .await?)
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

fn paid_report(paid: Epic1Paid) -> Report {
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
            })
            .collect(),
        posted: paid.posted,
        posted_ok: paid.posted.is_some(),
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
            }],
            posted: Some(0),
        };
        let json = serde_json::to_value(paid_report(paid)).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["address", "attempts", "posted", "posted_ok", "slate_id", "tx_id"]
        );
    }
}
