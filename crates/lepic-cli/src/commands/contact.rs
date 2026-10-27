//! `lepic contact`: pairing with contacts (RFC 0002) and invoices and slates exchanged with them
//! through their mailboxes.

use lepic_primitives::amount::Amount;
use lepic_store::TxId;
use lepic_store::{AccountIndex, ContactId, ContactState, SealMode};
use lepic_transport::file::response_path;
use lepic_wallet::ReceiveRequest;
use lepic_wallet::contact::{
    AcceptRequest, CardRequest, CollectTrigger, ContactKind, ContactRelays, ContactView,
    InviteExpiry, InviteRequest, InvoiceDetails, KeysDecision, LinkOutcome, PairingFailure,
    Purpose, Refusal, RelayMode, SasDecision, SealedAnswer,
};
use lepic_wallet::event::SlateId;
use lepic_wallet::invoice::InvoiceRequest;
use lepic_wallet::slate::Stage;

use super::{Opened, Run, Spend};
use crate::amount::{format_amount, format_fee, parse_amount};
use crate::cli::{
    ContactArgs, ContactCommand, ContactKindArg, ContactOpenSealedArgs, InviteExpiryArg, KeysArg,
    OnOffArg, PurposeArg, SasArg,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    ContactAcceptReport, ContactCardReport, ContactCollectReport, ContactExportReport,
    ContactFailureReport, ContactImportReport, ContactInviteReport, ContactInvoiceIssueReport,
    ContactInvoiceListReport, ContactInvoiceReport, ContactKeyCheckReport, ContactLinkReport,
    ContactListReport, ContactPreviewReport, ContactRemoveReport, ContactReport,
    ContactSlateReport, InvoiceDeclineReport, InvoicePayReport, Report,
};

/// Contacts belong to the default account.
const CONTACT_ACCOUNT: AccountIndex = AccountIndex(0);

fn contact_id(text: &str) -> Result<ContactId, CliError> {
    let text = text.trim();
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::ContactId);
    }
    let mut id = [0u8; 16];
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| CliError::ContactId)?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| CliError::ContactId)?;
    }
    Ok(ContactId(id))
}

fn kind(kind: ContactKindArg) -> ContactKind {
    match kind {
        ContactKindArg::Person => ContactKind::Person,
        ContactKindArg::Shop => ContactKind::Shop,
        ContactKindArg::Exchange => ContactKind::Exchange,
    }
}

fn kind_name(kind: ContactKind) -> &'static str {
    match kind {
        ContactKind::Person => "person",
        ContactKind::Shop => "shop",
        ContactKind::Exchange => "exchange",
    }
}

fn purpose(purpose: PurposeArg) -> Purpose {
    match purpose {
        PurposeArg::Payment => Purpose::Payment,
        PurposeArg::Deposit => Purpose::DepositRequest,
        PurposeArg::Withdrawal => Purpose::Withdrawal,
        PurposeArg::Refund => Purpose::Refund,
        PurposeArg::Request => Purpose::Request,
    }
}

/// How the CLI names a contact: the user's label, else what the contact calls itself, in
/// quotes, else its id.
fn contact_name(view: Option<&ContactView>, id: ContactId) -> String {
    match view {
        Some(view) if !view.label.is_empty() => view.label.clone(),
        Some(ContactView {
            claimed_name: Some(claimed),
            ..
        }) => format!("\"{claimed}\""),
        _ => format!("contact {id}"),
    }
}

fn failure_name(reason: PairingFailure) -> &'static str {
    match reason {
        PairingFailure::Expired => "expired",
        PairingFailure::NotConfirmed => "not-confirmed",
        PairingFailure::ChangedOnTheWay => "changed-on-the-way",
        PairingFailure::Refused(Refusal::AlreadyUsed) => "refused-already-used",
        PairingFailure::Refused(Refusal::Expired) => "refused-expired",
        PairingFailure::Refused(Refusal::CancelledByInviter) => "refused-cancelled",
    }
}

fn purpose_name(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Payment => "payment",
        Purpose::DepositRequest => "deposit",
        Purpose::Withdrawal => "withdrawal",
        Purpose::Refund => "refund",
        Purpose::Request => "request",
    }
}

fn state_name(state: ContactState) -> &'static str {
    match state {
        ContactState::PendingInvite => "pending-invite",
        ContactState::PendingReply => "pending-reply",
        ContactState::Paired => "paired",
        ContactState::Verified => "verified",
        ContactState::KeysChanged => "keys-changed",
    }
}

fn contact_report(view: &ContactView) -> ContactReport {
    ContactReport {
        contact_id: view.contact_id.to_string(),
        label: view.label.clone(),
        claimed_name: view.claimed_name.clone(),
        kind: view.kind.map(kind_name),
        state: state_name(view.state).to_owned(),
        sas: view
            .sas
            .map(|symbols| {
                symbols
                    .iter()
                    .map(|symbol| format!("{} {}", symbol.emoji, symbol.name))
                    .collect()
            })
            .unwrap_or_default(),
        allow_invoices: view.allow_invoices,
        seal: match view.seal {
            SealMode::On => "on",
            SealMode::Off => "off",
            SealMode::Degraded => "degraded",
        }
        .to_owned(),
        home_relay: view.home_relay.clone(),
        lapsed: view.lapsed,
    }
}

/// The CLI's relays: its Epicbox transport, and LEPIC's built-in relays of its network, where
/// pairing words are offered and looked for. `--offline` and `--epicbox-off` keep every
/// contact command off the relays.
fn relays<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: &ContactArgs,
) -> ContactRelays {
    let mode = if args.offline {
        RelayMode::Offline
    } else if args.epicbox_off {
        RelayMode::EpicboxOff
    } else {
        RelayMode::Online
    };
    ContactRelays::new(opened.epicbox.clone(), mode)
}

/// The longest sealed text read from a file or standard input.
const MAX_SEALED_TEXT: u64 = 4 * 1024 * 1024;

fn read_sealed(input: &str) -> Result<String, CliError> {
    use std::io::Read as _;
    let mut text = String::new();
    if input == "-" {
        std::io::stdin()
            .lock()
            .take(MAX_SEALED_TEXT)
            .read_to_string(&mut text)
            .map_err(CliError::io("read sealed text from standard input"))?;
    } else {
        std::fs::File::open(input)
            .and_then(|file| file.take(MAX_SEALED_TEXT).read_to_string(&mut text))
            .map_err(CliError::io("read the sealed file"))?;
    }
    Ok(text)
}

/// Writes `text` to `out`, or returns it to print.
fn write_or_print(
    out: Option<std::path::PathBuf>,
    text: String,
) -> Result<(Option<String>, Option<String>), CliError> {
    match out {
        Some(path) => {
            std::fs::write(&path, text).map_err(CliError::io("write the slate file"))?;
            Ok((Some(path.display().to_string()), None))
        }
        None => Ok((None, Some(text))),
    }
}

fn answer_text(answer: SealedAnswer) -> String {
    match answer {
        SealedAnswer::Sealed(text) => text,
        SealedAnswer::Plain(wire) => wire.as_text().unwrap_or_default().to_owned(),
    }
}

impl<H: Host> Run<'_, H> {
    pub(super) async fn contact(&mut self, args: ContactArgs) -> Result<Report, CliError> {
        let opened: Opened<HostNode<H>> = self.open().await?;
        let wallet = &opened.wallet;
        let relays = relays(&opened, &args);
        Ok(match args.command {
            ContactCommand::Invite(args) => {
                let offer = wallet
                    .pairing_invite(
                        &relays,
                        InviteRequest {
                            account: CONTACT_ACCOUNT,
                            name: args.name.name,
                            kind: kind(args.kind),
                            expiry: match args.expiry {
                                InviteExpiryArg::Hour => InviteExpiry::OneHour,
                                InviteExpiryArg::Day => InviteExpiry::OneDay,
                                InviteExpiryArg::Week => InviteExpiry::SevenDays,
                            },
                            offer_words: args.pairing_words,
                            home_relay: None,
                        },
                    )
                    .await?;
                Report::ContactInvite(ContactInviteReport {
                    contact_id: offer.contact_id.to_string(),
                    link: offer.link,
                    expires_at: offer.expires_at.to_string(),
                    words: offer
                        .words
                        .iter()
                        .flatten()
                        .map(|symbol| format!("{} {}", symbol.emoji, symbol.name))
                        .collect(),
                })
            }
            ContactCommand::Open(args) => {
                let preview = wallet.pairing_preview(&args.link)?;
                Report::ContactPreview(ContactPreviewReport {
                    claimed_name: preview.claimed_name,
                    kind: kind_name(preview.kind),
                    expires_at: preview.expires_at.to_string(),
                    home_relay: preview.home_relay,
                    service: preview.service,
                })
            }
            ContactCommand::Accept(args) => {
                let outcome = wallet
                    .pairing_accept(
                        &relays,
                        AcceptRequest {
                            link: args.link.link,
                            account: CONTACT_ACCOUNT,
                            name: args.name.name,
                            by_hand: args.by_hand,
                        },
                    )
                    .await?;
                Report::ContactAccept(ContactAcceptReport {
                    contact_id: outcome.contact_id.to_string(),
                    reply_link: outcome.reply_link,
                    posted: outcome.posted,
                })
            }
            ContactCommand::Enter(args) => {
                let link = match args.input.as_slice() {
                    [link] if link.trim_start().starts_with("epiccash:") => link.clone(),
                    words => {
                        let link = wallet.pairing_find_words(&relays, words).await?;
                        return Ok(Report::ContactLink(ContactLinkReport {
                            outcome: "invite",
                            contact_id: None,
                            link: Some(link),
                        }));
                    }
                };
                let outcome = wallet.pairing_enter_link(&relays, &link).await?;
                Report::ContactLink(match outcome {
                    LinkOutcome::Confirm { contact_id, link } => ContactLinkReport {
                        outcome: "confirm",
                        contact_id: Some(contact_id.to_string()),
                        link: Some(link),
                    },
                    LinkOutcome::Paired { contact_id } => ContactLinkReport {
                        outcome: "paired",
                        contact_id: Some(contact_id.to_string()),
                        link: None,
                    },
                    LinkOutcome::Ignored => ContactLinkReport {
                        outcome: "ignored",
                        contact_id: None,
                        link: None,
                    },
                })
            }
            ContactCommand::Collect => {
                // The cycle runs the outbox itself, every queued entry at once.
                let collected = wallet
                    .contacts_collect(&relays, CollectTrigger::Pull)
                    .await?;
                Report::ContactCollect(ContactCollectReport {
                    mailboxes: collected.mailboxes,
                    messages: collected.messages,
                    paired: collected.paired,
                    delivered: collected.delivered,
                    failed: collected
                        .failed
                        .iter()
                        .map(|failed| ContactFailureReport {
                            contact_id: failed.contact_id.to_string(),
                            reason: failure_name(failed.reason),
                        })
                        .collect(),
                    unreachable: collected.unreachable,
                })
            }
            ContactCommand::Sas(args) => {
                let id = contact_id(&args.contact.contact)?;
                let decision = match args.result {
                    SasArg::Match => SasDecision::Match,
                    SasArg::Mismatch => SasDecision::Mismatch,
                    SasArg::Skip => SasDecision::Skip,
                };
                wallet.pairing_sas(&relays, id, decision).await?;
                if decision == SasDecision::Mismatch {
                    Report::ContactRemove(ContactRemoveReport {
                        contact_id: id.to_string(),
                        removed: true,
                    })
                } else {
                    Report::Contact(contact_report(&wallet.contact(id).await?))
                }
            }
            ContactCommand::ShowCard(args) => {
                let offer = wallet
                    .pairing_show_card(
                        &relays,
                        CardRequest {
                            account: CONTACT_ACCOUNT,
                            name: args.name.name,
                            kind: kind(args.kind),
                            home_relay: None,
                        },
                    )
                    .await?;
                Report::ContactCard(ContactCardReport {
                    contact_id: offer.contact_id.to_string(),
                    link: offer.link,
                })
            }
            ContactCommand::ScanCard(args) => {
                let id = contact_id(&args.contact.contact)?;
                let view = wallet.pairing_scan_card(&relays, id, &args.link).await?;
                Report::Contact(contact_report(&view))
            }
            ContactCommand::List => Report::ContactList(ContactListReport {
                contacts: wallet
                    .contacts()
                    .await?
                    .iter()
                    .map(contact_report)
                    .collect(),
            }),
            ContactCommand::KeyCheck(args) => {
                let new = contact_id(&args.new)?;
                let old = contact_id(&args.old)?;
                wallet.contact_key_check(&relays, new, old).await?;
                Report::ContactKeyCheck(ContactKeyCheckReport {
                    contact_id: new.to_string(),
                    old_contact_id: old.to_string(),
                })
            }
            ContactCommand::Keys(args) => {
                let new = contact_id(&args.new)?;
                match args.choice {
                    KeysArg::KeepOld => {
                        wallet
                            .contact_keys_resolve(new, KeysDecision::KeepOld)
                            .await?;
                        Report::ContactRemove(ContactRemoveReport {
                            contact_id: new.to_string(),
                            removed: true,
                        })
                    }
                    KeysArg::UseNew => {
                        wallet
                            .contact_keys_resolve(new, KeysDecision::UseNew)
                            .await?;
                        Report::Contact(contact_report(&wallet.contact(new).await?))
                    }
                }
            }
            ContactCommand::Seal(args) => {
                let id = contact_id(&args.slate.contact.contact)?;
                let tx_id = TxId(args.slate.tx.tx_id);
                let text = wallet
                    .contact_seal_slate(id, tx_id, args.slate.purpose.map(purpose))
                    .await?;
                let (file, text) = write_or_print(args.out.out, text)?;
                Report::ContactSlate(ContactSlateReport {
                    action: "sealed",
                    contact_id: Some(id.to_string()),
                    tx_id: Some(tx_id.0),
                    slate_id: None,
                    stage: None,
                    amount: None,
                    file,
                    text,
                })
            }
            ContactCommand::SendSlate(args) => {
                let id = contact_id(&args.contact.contact)?;
                let tx_id = TxId(args.tx.tx_id);
                wallet
                    .contact_post_slate(&relays, id, tx_id, args.purpose.map(purpose))
                    .await?;
                Report::ContactSlate(ContactSlateReport {
                    action: "sent",
                    contact_id: Some(id.to_string()),
                    tx_id: Some(tx_id.0),
                    slate_id: None,
                    stage: None,
                    amount: None,
                    file: None,
                    text: None,
                })
            }
            ContactCommand::Plain(args) => {
                let tx_id = TxId(args.tx.tx_id);
                let wire = wallet.contact_plain_fallback(tx_id).await?;
                let text = wire.as_text().unwrap_or_default().to_owned();
                let (file, text) = write_or_print(args.out.out, text)?;
                Report::ContactSlate(ContactSlateReport {
                    action: "plain",
                    contact_id: None,
                    tx_id: Some(tx_id.0),
                    slate_id: None,
                    stage: None,
                    amount: None,
                    file,
                    text,
                })
            }
            ContactCommand::OpenSealed(args) => open_sealed(&opened, args).await?,
            ContactCommand::Label(args) => {
                let id = contact_id(&args.contact.contact)?;
                wallet.contact_set_label(id, args.label).await?;
                Report::Contact(contact_report(&wallet.contact(id).await?))
            }
            ContactCommand::Remove(args) => {
                let id = contact_id(&args.contact)?;
                Report::ContactRemove(ContactRemoveReport {
                    contact_id: id.to_string(),
                    removed: wallet.contact_remove(id).await?,
                })
            }
            ContactCommand::AllowInvoices(args) => {
                let id = contact_id(&args.contact.contact)?;
                wallet
                    .contact_set_allow_invoices(id, args.state == OnOffArg::On)
                    .await?;
                wallet.contacts_outbox_deliver(&relays).await?;
                Report::Contact(contact_report(&wallet.contact(id).await?))
            }
            ContactCommand::Invoice(args) => {
                let id = contact_id(&args.contact.contact)?;
                let amount = parse_amount(&args.amount)?;
                let account = wallet.account(&args.account.account)?;
                let issued = wallet
                    .contact_issue_invoice(
                        &relays,
                        id,
                        InvoiceRequest {
                            account: account.index,
                            amount,
                            message: None,
                            ttl_blocks: None,
                        },
                        InvoiceDetails {
                            purpose: purpose(args.purpose),
                            reference: args.reference,
                            expires: None,
                        },
                    )
                    .await?;
                let view = wallet.contact(id).await.ok();
                Report::ContactInvoiceIssue(ContactInvoiceIssueReport {
                    contact_id: id.to_string(),
                    contact_name: contact_name(view.as_ref(), id),
                    tx_id: issued.tx_id.0,
                    slate_id: issued.slate_id.to_string(),
                    amount: format_amount(issued.amount),
                })
            }
            ContactCommand::Invoices => {
                let contacts = wallet.contacts().await?;
                let view = |id: ContactId| contacts.iter().find(|view| view.contact_id == id);
                Report::ContactInvoices(ContactInvoiceListReport {
                    invoices: wallet
                        .contact_invoices()
                        .await?
                        .into_iter()
                        .map(|invoice| ContactInvoiceReport {
                            slate_id: invoice.slate_id.to_string(),
                            contact_id: invoice.contact_id.to_string(),
                            contact_name: contact_name(
                                view(invoice.contact_id),
                                invoice.contact_id,
                            ),
                            verified: view(invoice.contact_id)
                                .is_some_and(|view| view.state == ContactState::Verified),
                            amount: format_amount(invoice.amount),
                            purpose: invoice.purpose.map(purpose_name),
                            reference: invoice.reference,
                            received_at: invoice.received_at.to_string(),
                            same_amount: invoice
                                .same_amount
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                        })
                        .collect(),
                })
            }
            ContactCommand::PayInvoice(args) => {
                let slate_id = SlateId::parse(&args.slate_id).map_err(|_| CliError::SlateId)?;
                let amount: Amount = parse_amount(&args.amount)?;
                let spend = Spend::from_args(&args.spend)?;
                let account = wallet.account(&args.account.account)?;
                let request = spend.pay_request(account.index, amount, args.message.message);
                let contact = wallet
                    .contact_invoices()
                    .await?
                    .into_iter()
                    .find(|invoice| invoice.slate_id == slate_id)
                    .map(|invoice| invoice.contact_id.to_string())
                    .unwrap_or_default();
                let paid = wallet
                    .contact_pay_invoice(&relays, slate_id, request)
                    .await?;
                Report::InvoicePay(InvoicePayReport {
                    tx_id: paid.tx_id.0,
                    slate_id: paid.slate.id().to_string(),
                    amount: format_amount(paid.slate.amount()),
                    fee: format_fee(paid.slate.fee()),
                    transport: "contact".to_owned(),
                    destination: contact,
                    reply_file: None,
                })
            }
            ContactCommand::Decline(args) => {
                let slate_id = SlateId::parse(&args.slate_id).map_err(|_| CliError::SlateId)?;
                wallet.contact_decline_invoice(slate_id).await?;
                wallet.contacts_outbox_deliver(&relays).await?;
                Report::InvoiceDecline(InvoiceDeclineReport {
                    slate_id: slate_id.to_string(),
                    state: "declined".to_owned(),
                })
            }
            ContactCommand::Export(args) => {
                let document = wallet.contacts_export().await?;
                std::fs::write(&args.file, document)
                    .map_err(CliError::io("write the contact backup"))?;
                Report::ContactExport(ContactExportReport {
                    file: args.file.display().to_string(),
                })
            }
            ContactCommand::Import(args) => {
                let document = std::fs::read_to_string(&args.file)
                    .map_err(CliError::io("read the contact backup"))?;
                let summary = wallet.contacts_import(document).await?;
                Report::ContactImport(ContactImportReport {
                    imported: summary.imported,
                    skipped_existing: summary.skipped_existing,
                    skipped_conflict: summary.skipped_conflict,
                })
            }
        })
    }
}

/// The amount a V3 slate's JSON names, for showing an invoice before it is paid.
fn shown_amount(wire: &lepic_wallet::slate::WireSlate) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(wire.as_text()?).ok()?;
    let amount = match value.get("amount")? {
        serde_json::Value::String(text) => text.parse::<u64>().ok()?,
        other => other.as_u64()?,
    };
    Some(format_amount(Amount::new(amount)))
}

/// Opens sealed text and acts on its slate as the file commands do, answering sealed on the
/// same channel. An I1 is paid only when its amount is given.
async fn open_sealed<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactOpenSealedArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let text = read_sealed(&args.input)?;
    let sealed = wallet.sealed_open(&text).await?;
    let contact_id = sealed.contact_id.map(|id| id.to_string());
    let stage = Some(sealed.stage.as_str());
    let answer_to = args
        .answer_file
        .clone()
        .or_else(|| (args.input != "-").then(|| response_path(std::path::Path::new(&args.input))));
    let (action, tx_id, slate, answer) = match sealed.stage {
        Stage::S1 => {
            let done = wallet
                .sealed_receive(
                    &text,
                    ReceiveRequest {
                        account: Some(args.account.account),
                        message: args.message.message,
                    },
                )
                .await?;
            (
                "received",
                done.received.tx_id,
                done.received.slate,
                Some(done.answer),
            )
        }
        Stage::I1 => {
            let Some(amount) = args.amount else {
                return Ok(Report::ContactSlate(ContactSlateReport {
                    action: "invoice",
                    contact_id,
                    tx_id: None,
                    slate_id: None,
                    stage,
                    amount: shown_amount(&sealed.wire),
                    file: None,
                    text: None,
                }));
            };
            let amount = parse_amount(&amount)?;
            let spend = Spend::from_args(&args.spend)?;
            let account = wallet.account(&args.account.account)?;
            let request = spend.pay_request(account.index, amount, args.message.message);
            let done = wallet.sealed_pay(&text, request).await?;
            ("paid", done.paid.tx_id, done.paid.slate, Some(done.answer))
        }
        _ => {
            let done = wallet
                .sealed_finalize(&text, super::propagation(args.fluff.fluff))
                .await?;
            ("finalized", done.tx_id, done.slate, None)
        }
    };
    let (file, text) = match answer {
        Some(answer) => write_or_print(answer_to, answer_text(answer))?,
        None => (None, None),
    };
    Ok(Report::ContactSlate(ContactSlateReport {
        action,
        contact_id,
        tx_id: Some(tx_id.0),
        slate_id: Some(slate.id().to_string()),
        stage,
        amount: Some(format_amount(slate.amount())),
        file,
        text,
    }))
}
