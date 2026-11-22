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
    Claim, ContactRelays, DOMAIN_FILE_MAX, InPersonCode, InPersonCodeView, InPersonInvoiceRequest,
    InPersonPaid, InPersonPostOutcome, InPersonPosted, InPersonTaken, RequestVerdict,
    WalletContacts, parse_invoice_link, request_claim,
};

use super::contact::{from_hex, relays_in_mode, to_hex};
use super::{Opened, Run, Spend, propagation};
use crate::amount::{format_amount, format_fee, parse_amount};
use crate::cli::{
    InPersonArgs, InPersonCodeArg, InPersonCommand, InPersonInvoiceArgs, InPersonPayArgs,
    InPersonReadArgs, InPersonReceiveArgs, InPersonScanArg, InPersonSendArgs, InPersonTakeArgs,
};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    FinalizeReport, InPersonAnswerReport, InPersonAnswersReport, InPersonCodeReport,
    InPersonDomainReport, InPersonHostReport, InPersonPaidReport, InPersonPostReport,
    InPersonReadReport, InPersonRoutePostReport, InPersonRouteReport, InPersonTakenReport, Report,
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
            &self.settings.servers.mailboxes.current(),
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
                    slate_id: None,
                    direct: Vec::new(),
                    claim: None,
                    shared_slot: false,
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
                let request = Spend::from_args(&spend)?
                    .with_default_ttl(self.settings.send_ttl_blocks)
                    .send_request(
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
                paid_report(out.out.as_deref(), &paid, None)?
            }
            InPersonCommand::Post(args) => {
                let slate_id = slate_id(&args.slate_id)?;
                let posted = book.in_person_post(&relays, slate_id).await?;
                post_report(slate_id, posted)
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
    let book = wallet.contact_book();
    let bytes = scan_bytes(&code)?;
    let spend = Spend::from_args(&spend)?;
    let options = SelectionOptions {
        minimum_confirmations: spend.minimum_confirmations,
        change_outputs: spend.change_outputs,
        strategy: spend.strategy,
        ..SelectionOptions::new(wallet.account(&account.account)?.index)
    };
    let read = book.in_person_read(relays, options, &bytes).await?;
    let domain = match &read.claim {
        Some(claim) => Some(domain_report(
            |file| book.in_person_request_verify(&bytes, file),
            claim,
            &code,
        )?),
        None => None,
    };
    Ok(Report::InPersonRead(InPersonReadReport {
        slate_id: read.slate_id.to_string(),
        stage: stage_name(read.stage),
        amount: format_amount(read.amount),
        fee: read.fee.map(format_fee),
        message: read.message,
        ttl_cutoff: read.ttl_cutoff,
        mailbox: read.mailbox.as_ref().map(host_report),
        domain,
        direct: read
            .direct
            .iter()
            .map(|route| InPersonRouteReport {
                method: route.method.to_string(),
                value: route.value.clone(),
            })
            .collect(),
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
    let book = wallet.contact_book();
    let bytes = scan_bytes(&code)?;
    // A claim the domain's file refuses stops the payment before anything is spent.
    let domain = match request_claim(&bytes) {
        Some(claim) => Some(domain_report(
            |file| book.in_person_request_verify(&bytes, file),
            &claim,
            &code,
        )?),
        None => None,
    };
    if let Some(InPersonDomainReport {
        domain,
        state: "refused",
        reason,
        ..
    }) = &domain
    {
        return Err(CliError::RequestDomainRefused {
            domain: domain.clone(),
            reason: reason.unwrap_or("refused"),
        });
    }
    let amount = parse_amount(&amount)?;
    let spend = Spend::from_args(&spend)?;
    let account = wallet.account(&account.account)?.index;
    let request = spend.pay_request(account, amount, message.message);
    let paid = book.in_person_pay(relays, &bytes, request).await?;
    paid_report(out.out.as_deref(), &paid, domain)
}

/// The domain `claim` of the scanned code `bytes` names, checked against the domain file the
/// command was given: `unchecked` without one.
fn domain_report(
    verify: impl FnOnce(&[u8]) -> RequestVerdict,
    claim: &Claim,
    code: &InPersonScanArg,
) -> Result<InPersonDomainReport, CliError> {
    let (state, reason) = match &code.domain_file {
        None => ("unchecked", None),
        Some(path) => match verify(&read_domain_file(path)?) {
            RequestVerdict::Checked { .. } => ("checked", None),
            RequestVerdict::Refused { reason, .. } => ("refused", Some(reason.as_str())),
            // The claim was read from these bytes, so the code is signed.
            RequestVerdict::Unsigned => ("unchecked", None),
        },
    };
    Ok(InPersonDomainReport {
        domain: claim.domain.as_str().to_owned(),
        state,
        reason,
        key: to_hex(claim.key.as_bytes()),
        issued_at: claim.issued_at,
    })
}

/// A domain's well-known file, read to one byte past the most a file may be, so a longer one
/// is refused as too large.
fn read_domain_file(path: &Path) -> Result<Vec<u8>, CliError> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take((DOMAIN_FILE_MAX as u64).saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(CliError::io("read the domain file"))?;
    Ok(bytes)
}

/// What `in-person post` did, route by route.
fn post_report(slate_id: SlateId, posted: InPersonPosted) -> Report {
    let accepted = posted.accepted();
    Report::InPersonPost(InPersonPostReport {
        slate_id: slate_id.to_string(),
        posted: accepted,
        check_code: posted.check_code,
        routes: posted
            .routes
            .into_iter()
            .map(|post| {
                let (outcome, reason) = match post.outcome {
                    InPersonPostOutcome::Accepted => ("accepted", None),
                    InPersonPostOutcome::Refused { reason } => ("refused", reason),
                    InPersonPostOutcome::Failed { reason } => ("failed", Some(reason)),
                };
                InPersonRoutePostReport {
                    method: post.route.method.to_string(),
                    value: post.route.value,
                    outcome,
                    reason,
                }
            })
            .collect(),
    })
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
fn paid_report(
    out: Option<&Path>,
    paid: &InPersonPaid,
    domain: Option<InPersonDomainReport>,
) -> Result<Report, CliError> {
    let (envelope, file) = write_or_hex(out, &paid.envelope)?;
    Ok(Report::InPersonPaid(InPersonPaidReport {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        envelope,
        file,
        mailbox: paid.mailbox.as_ref().map(host_report),
        domain,
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

/// A scanned code's bytes: from its file, its hex, or the invoice link that carries it.
pub(crate) fn scan_bytes(code: &InPersonScanArg) -> Result<Vec<u8>, CliError> {
    match (&code.file, &code.link) {
        (Some(path), _) => read_limited(path),
        (None, Some(link)) => parse_invoice_link(link).map_err(CliError::InvoiceLink),
        (None, None) => from_hex(code.hex.as_deref().unwrap_or_default()),
    }
}

pub(super) fn code_bytes(code: &InPersonCodeArg) -> Result<Vec<u8>, CliError> {
    match &code.file {
        Some(path) => read_limited(path),
        None => from_hex(code.hex.as_deref().unwrap_or_default()),
    }
}

pub(super) fn read_limited(path: &Path) -> Result<Vec<u8>, CliError> {
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

pub(super) fn slate_id(text: &str) -> Result<SlateId, CliError> {
    SlateId::parse(text.trim()).map_err(|_| CliError::SlateId)
}

fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::S1 | Stage::S2 | Stage::S3 => "send",
        _ => "invoice",
    }
}

pub(super) fn host_report(report: &HostReport) -> InPersonHostReport {
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

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use lepic_wallet_contacts::{DomainName, DomainRefused, InvoiceLinkError, VerifyingKey};

    use super::*;
    use crate::cli::{Cli, Command};

    const LINK: &str = "epiccash://invoice/1/AAAA";

    fn scan(line: &[&str]) -> InPersonScanArg {
        let cli = Cli::try_parse_from(line).unwrap();
        match cli.command {
            Command::InPerson(InPersonArgs {
                command: InPersonCommand::Read(read),
                ..
            }) => read.code,
            Command::InPerson(InPersonArgs {
                command: InPersonCommand::Pay(pay),
                ..
            }) => pay.code,
            other => panic!("{other:?}"),
        }
    }

    fn claim() -> Claim {
        let mut identity = [0; 32];
        identity[0] = 1;
        Claim {
            domain: DomainName::new("shop.test").unwrap(),
            key: VerifyingKey::from_bytes(&identity).unwrap(),
            issued_at: 7,
        }
    }

    #[test]
    fn in_person_read_and_pay_take_a_link_and_a_domain_file() {
        let read = scan(&[
            "lepic",
            "in-person",
            "read",
            "--link",
            LINK,
            "--domain-file",
            "lepic.json",
        ]);
        assert_eq!(read.link.as_deref(), Some(LINK));
        assert_eq!(read.domain_file.as_deref(), Some(Path::new("lepic.json")));
        let pay = scan(&["lepic", "in-person", "pay", "1", "--link", LINK]);
        assert_eq!(pay.link.as_deref(), Some(LINK));
        assert_eq!(pay.domain_file, None);
    }

    #[test]
    fn in_person_scan_takes_one_of_hex_file_and_link() {
        for line in [
            &["lepic", "in-person", "read", "--link", LINK, "--hex", "00"][..],
            &["lepic", "in-person", "read", "--link", LINK, "--file", "a"],
            &["lepic", "in-person", "read", "--domain-file", "lepic.json"],
        ] {
            assert!(Cli::try_parse_from(line).is_err(), "{line:?}");
        }
    }

    #[test]
    fn an_in_person_link_that_is_not_an_invoice_link_is_refused() {
        let code = scan(&[
            "lepic",
            "in-person",
            "read",
            "--link",
            "https://shop.test/pay",
        ]);
        assert!(matches!(
            scan_bytes(&code),
            Err(CliError::InvoiceLink(InvoiceLinkError::Prefix))
        ));
    }

    #[test]
    fn an_in_person_domain_is_unchecked_without_a_file_and_refused_as_the_file_says() {
        let claim = claim();
        let code = scan(&["lepic", "in-person", "read", "--link", LINK]);
        let report = domain_report(|_| panic!("no file to check"), &claim, &code).unwrap();
        assert_eq!((report.state, report.reason), ("unchecked", None));
        assert_eq!(report.domain, "shop.test");
        assert_eq!(report.issued_at, 7);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lepic.json");
        std::fs::write(&file, b"{}").unwrap();
        let mut code = code;
        code.domain_file = Some(file);
        let refused = |bytes: &[u8]| {
            assert_eq!(bytes, b"{}");
            RequestVerdict::Refused {
                domain: claim.domain.clone(),
                reason: DomainRefused::NoKeyMatches,
            }
        };
        let report = domain_report(refused, &claim, &code).unwrap();
        assert_eq!(report.state, "refused");
        assert_eq!(report.reason, Some(DomainRefused::NoKeyMatches.as_str()));
        let checked = |_: &[u8]| RequestVerdict::Checked {
            domain: claim.domain.clone(),
        };
        assert_eq!(
            domain_report(checked, &claim, &code).unwrap().state,
            "checked"
        );
    }
}
