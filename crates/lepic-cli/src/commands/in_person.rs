// SPDX-License-Identifier: Apache-2.0
//! `lepic in-person`: payments asked for or made face to face, through a raw `lepic.v1` code
//! scanned once and a sealed answer posted to the mailbox it names (RFC 0003 §5.18).

use std::path::Path;

use lepic_transport::host_rule::{HostClass, HostReport};
use lepic_wallet::event::SlateId;
use lepic_wallet::receive::ReceiveRequest;
use lepic_wallet::selection::SelectionOptions;
use lepic_wallet::slate::Stage;
use lepic_wallet_contacts::{
    ContactRelays, InPersonCode, InPersonCodeView, InPersonInvoiceRequest, InPersonPaid,
    InPersonTaken, WalletContacts,
};

use super::contact::{from_hex, relays_in_mode, to_hex};
use super::{Opened, Run, Spend, propagation};
use crate::amount::{format_amount, format_fee, parse_amount};
use crate::cli::{
    InPersonArgs, InPersonCodeArg, InPersonCommand, InPersonInvoiceArgs, InPersonPayArgs,
    InPersonReadArgs, InPersonReceiveArgs, InPersonSendArgs, InPersonTakeArgs,
};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    FinalizeReport, InPersonAnswerReport, InPersonAnswersReport, InPersonCodeReport,
    InPersonHostReport, InPersonPaidReport, InPersonPostReport, InPersonReadReport,
    InPersonTakenReport, Report,
};

/// The most a code or answer file is read: far past the largest either is.
const MAX_IN_PERSON_FILE: u64 = 64 * 1024;

impl<H: Host> Run<'_, H> {
    pub(super) async fn in_person(&mut self, args: InPersonArgs) -> Result<Report, CliError> {
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
            InPersonCommand::Invoice(args) => {
                let InPersonInvoiceArgs {
                    amount,
                    account,
                    message,
                    ttl_blocks,
                    out,
                } = args;
                let request = InPersonInvoiceRequest {
                    account: wallet.account(&account.account)?.index,
                    amount: parse_amount(&amount)?,
                    message: message.message,
                    ttl_blocks,
                };
                let code = book.in_person_invoice(&relays, request).await?;
                code_report(out.out.as_deref(), code)?
            }
            InPersonCommand::Send(args) => {
                let InPersonSendArgs {
                    amount,
                    account,
                    message,
                    spend,
                    out,
                } = args;
                let request = Spend::from_args(&spend)?.send_request(
                    wallet.account(&account.account)?.index,
                    parse_amount(&amount)?,
                    message.message,
                );
                let code = book.in_person_send(&relays, request).await?;
                code_report(out.out.as_deref(), code)?
            }
            InPersonCommand::Read(args) => read(&opened, &relays, args).await?,
            InPersonCommand::Pay(args) => pay(&opened, &relays, args).await?,
            InPersonCommand::Receive(args) => {
                let InPersonReceiveArgs {
                    code,
                    account,
                    message,
                    out,
                } = args;
                let request = ReceiveRequest {
                    account: Some(account.account),
                    message: message.message,
                    ..ReceiveRequest::default()
                };
                let paid = book
                    .in_person_receive(&relays, &code_bytes(&code)?, request)
                    .await?;
                paid_report(out.out.as_deref(), paid)?
            }
            InPersonCommand::Post(args) => {
                let slate_id = slate_id(&args.slate.slate_id)?;
                book.in_person_post(&relays, slate_id, args.relay_ok)
                    .await?;
                Report::InPersonPost(InPersonPostReport {
                    slate_id: slate_id.to_string(),
                    posted: true,
                })
            }
            InPersonCommand::Take(args) => taken_report(take(&opened, args).await?),
            InPersonCommand::Answers(args) => {
                let view = book.in_person_answers(slate_id(&args.slate_id)?).await?;
                answers_report(view)
            }
            InPersonCommand::Finalize(args) => {
                let finalized = book
                    .in_person_finalize(
                        slate_id(&args.slate.slate_id)?,
                        args.answer,
                        propagation(args.fluff.fluff),
                    )
                    .await?;
                Report::Finalize(FinalizeReport {
                    tx_id: finalized.tx_id.0,
                    slate_id: finalized.slate.id().to_string(),
                    state: if finalized.pushed {
                        "posted"
                    } else {
                        "finalized"
                    }
                    .to_owned(),
                })
            }
        })
    }
}

/// Reads a scanned code and reports what it asks for.
async fn read<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: InPersonReadArgs,
) -> Result<Report, CliError> {
    let InPersonReadArgs {
        code,
        account,
        spend,
    } = args;
    let wallet = &opened.wallet;
    let bytes = code_bytes(&code)?;
    let spend = Spend::from_args(&spend)?;
    let options = SelectionOptions {
        minimum_confirmations: spend.minimum_confirmations,
        change_outputs: spend.change_outputs,
        strategy: spend.strategy,
        ..SelectionOptions::new(wallet.account(&account.account)?.index)
    };
    let read = wallet
        .contact_book()
        .in_person_read(relays, options, &bytes)
        .await?;
    Ok(Report::InPersonRead(InPersonReadReport {
        slate_id: read.slate_id.to_string(),
        stage: stage_name(read.stage),
        amount: format_amount(read.amount),
        fee: read.fee.map(format_fee),
        message: read.message,
        ttl_cutoff: read.ttl_cutoff,
        mailbox: read.mailbox.as_ref().map(host_report),
    }))
}

/// Pays a scanned invoice code and returns the sealed answer.
async fn pay<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: InPersonPayArgs,
) -> Result<Report, CliError> {
    let InPersonPayArgs {
        amount,
        code,
        account,
        message,
        spend,
        out,
    } = args;
    let wallet = &opened.wallet;
    let bytes = code_bytes(&code)?;
    let amount = parse_amount(&amount)?;
    let spend = Spend::from_args(&spend)?;
    let account = wallet.account(&account.account)?.index;
    let request = spend.pay_request(account, amount, message.message);
    let paid = wallet
        .contact_book()
        .in_person_pay(relays, &bytes, request)
        .await?;
    paid_report(out.out.as_deref(), paid)
}

/// Writes the code to show to `out` or prints it.
fn code_report(out: Option<&Path>, code: InPersonCode) -> Result<Report, CliError> {
    let (code_hex, file) = write_or_hex(out, &code.bytes)?;
    Ok(Report::InPersonCode(InPersonCodeReport {
        tx_id: code.tx_id.0,
        slate_id: code.slate_id.to_string(),
        code: code_hex,
        file,
        ttl_cutoff: code.ttl_cutoff,
        mailbox: code.mailbox,
    }))
}

/// Writes the sealed answer to `out` or prints it.
fn paid_report(out: Option<&Path>, paid: InPersonPaid) -> Result<Report, CliError> {
    let (envelope, file) = write_or_hex(out, &paid.envelope)?;
    Ok(Report::InPersonPaid(InPersonPaidReport {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        envelope,
        file,
        check_code: paid.check_code,
        mailbox: paid.mailbox.as_ref().map(host_report),
    }))
}

/// Takes an answer from a file, from hex digits, from armoured text or from UR parts.
async fn take<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: InPersonTakeArgs,
) -> Result<InPersonTaken, CliError> {
    let book = opened.wallet.contact_book();
    if let Some(path) = &args.file {
        return Ok(book.in_person_take(&read_limited(path)?).await?);
    }
    let is_ur = |part: &String| {
        part.trim()
            .get(..3)
            .is_some_and(|head| head.eq_ignore_ascii_case("ur:"))
    };
    if args.input.iter().any(is_ur) {
        return Ok(book.in_person_take_ur(&args.input).await?);
    }
    let text = args.input.join("\n");
    let bytes = if text.trim().bytes().all(|byte| byte.is_ascii_hexdigit()) {
        from_hex(&text)?
    } else {
        text.into_bytes()
    };
    Ok(book.in_person_take(&bytes).await?)
}

fn code_bytes(code: &InPersonCodeArg) -> Result<Vec<u8>, CliError> {
    match &code.file {
        Some(path) => read_limited(path),
        None => from_hex(code.hex.as_deref().unwrap_or_default()),
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>, CliError> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_IN_PERSON_FILE).read_to_end(&mut bytes))
        .map_err(CliError::io("read the in-person file"))?;
    Ok(bytes)
}

/// Writes `bytes` to `out`, or returns them as hex to print.
fn write_or_hex(
    out: Option<&Path>,
    bytes: &[u8],
) -> Result<(Option<String>, Option<String>), CliError> {
    match out {
        Some(path) => {
            lepic_store::file::write_owner_only_atomic(path, bytes)
                .map_err(CliError::io("write the in-person file"))?;
            Ok((None, Some(path.display().to_string())))
        }
        None => Ok((Some(to_hex(bytes)), None)),
    }
}

fn slate_id(text: &str) -> Result<SlateId, CliError> {
    SlateId::parse(text.trim()).map_err(|_| CliError::SlateId)
}

fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::S1 | Stage::S2 | Stage::S3 => "send",
        _ => "invoice",
    }
}

fn host_report(report: &HostReport) -> InPersonHostReport {
    InPersonHostReport {
        host: report.host.clone(),
        port: report.port,
        in_relay_list: report.in_relay_list,
        host_rule: match report.class {
            HostClass::Public => "public",
            HostClass::LocalNetwork => "local_network",
        },
    }
}

fn taken_report(taken: InPersonTaken) -> Report {
    Report::InPersonTaken(InPersonTakenReport {
        tx_id: taken.tx_id.0,
        slate_id: taken.slate_id.to_string(),
        answer: taken.answer,
        check_code: taken.check_code,
        same_code: taken.same_code,
        duplicate: taken.duplicate,
    })
}

fn answers_report(view: InPersonCodeView) -> Report {
    Report::InPersonAnswers(InPersonAnswersReport {
        tx_id: view.tx_id.0,
        slate_id: view.slate_id.to_string(),
        stage: stage_name(view.stage),
        ttl_cutoff: view.ttl_cutoff,
        mailbox: view.mailbox,
        closed: view.closed,
        finalized: view.finalized,
        answers: view
            .answers
            .into_iter()
            .map(|answer| InPersonAnswerReport {
                number: answer.number,
                check_code: answer.check_code,
                same_code: answer.same_code,
                received_at: answer.received_at.to_string(),
            })
            .collect(),
    })
}
