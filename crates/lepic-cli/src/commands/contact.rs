//! `lepic contact`: pairing with contacts (RFC 0002) and invoices and slates exchanged with them
//! through their mailboxes.

use lepic_primitives::amount::Amount;
use lepic_store::{AccountIndex, ContactId, ContactState, SealMode};
use lepic_wallet::contact::{
    AcceptRequest, CardRequest, CollectTrigger, ContactKind, ContactRelays, ContactView,
    InviteExpiry, InviteRequest, InvoiceDetails, KeysDecision, LinkOutcome, Purpose, RelayMode,
    SasDecision,
};
use lepic_wallet::event::SlateId;
use lepic_wallet::invoice::InvoiceRequest;

use super::{Opened, Run, Spend};
use crate::amount::{format_amount, format_fee, parse_amount};
use crate::cli::{
    ContactCommand, ContactKindArg, InviteExpiryArg, KeysArg, OnOffArg, PurposeArg, SasArg,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    ContactAcceptReport, ContactCardReport, ContactCollectReport, ContactExportReport,
    ContactImportReport, ContactInviteReport, ContactInvoiceIssueReport, ContactInvoiceListReport,
    ContactInvoiceReport, ContactKeyCheckReport, ContactLinkReport, ContactListReport,
    ContactPreviewReport, ContactRemoveReport, ContactReport, InvoicePayReport, Report,
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
/// pairing words are offered and looked for.
fn relays<N: lepic_node::NodeApi + 'static>(opened: &Opened<N>) -> ContactRelays {
    ContactRelays::new(opened.epicbox.clone(), RelayMode::Online)
}

impl<H: Host> Run<'_, H> {
    pub(super) async fn contact(&mut self, command: ContactCommand) -> Result<Report, CliError> {
        let opened: Opened<HostNode<H>> = self.open().await?;
        let wallet = &opened.wallet;
        let relays = relays(&opened);
        Ok(match command {
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
                let collected = wallet
                    .contacts_collect(&relays, CollectTrigger::Pull)
                    .await?;
                let delivered = wallet.contacts_outbox_deliver(&relays).await?;
                Report::ContactCollect(ContactCollectReport {
                    mailboxes: collected.mailboxes,
                    messages: collected.messages,
                    paired: collected.paired,
                    delivered: delivered.delivered,
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
                        },
                        InvoiceDetails {
                            purpose: purpose(args.purpose),
                            reference: args.reference,
                            expires: None,
                        },
                    )
                    .await?;
                Report::ContactInvoiceIssue(ContactInvoiceIssueReport {
                    contact_id: id.to_string(),
                    tx_id: issued.tx_id.0,
                    slate_id: issued.slate_id.to_string(),
                    amount: format_amount(issued.amount),
                })
            }
            ContactCommand::Invoices => Report::ContactInvoices(ContactInvoiceListReport {
                invoices: wallet
                    .contact_invoices()
                    .await?
                    .into_iter()
                    .map(|invoice| ContactInvoiceReport {
                        slate_id: invoice.slate_id.to_string(),
                        contact_id: invoice.contact_id.to_string(),
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
            }),
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
