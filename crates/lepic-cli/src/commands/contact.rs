// SPDX-License-Identifier: Apache-2.0
//! `lepic contact`: pairing with contacts (RFC 0002) and invoices and slates exchanged with them
//! through their mailboxes.

use std::path::{Path, PathBuf};

use lepic_primitives::amount::Amount;
use lepic_store::TxId;
use lepic_store::{AccountIndex, ContactId, ContactState, SealMode};
use lepic_transport::file::response_path;
use lepic_wallet::ReceiveRequest;
use lepic_wallet::event::SlateId;
use lepic_wallet::invoice::InvoiceRequest;
use lepic_wallet::send::{SendRequest, SentSlate};
use lepic_wallet::slate::Stage;
use lepic_wallet_contacts::{
    AcceptRequest, CardRequest, CollectTrigger, ContactKind, ContactRelays, ContactView,
    InviteExpiry, InviteRequest, InvoiceDetails, KeysDecision, LinkOutcome, MAX_APP_PAYLOAD_LEN,
    PairingClass, PairingEndReason, PairingFailure, PairingStatus, PayloadId, Purpose, Refusal,
    RelayMode, SasDecision, SasSymbol, SealedAnswer, WalletContacts,
};

use super::{Opened, Run, Spend};
use crate::amount::{format_amount, format_fee, parse_amount};
use crate::cli::{
    ContactAcceptArgs, ContactArgs, ContactCardArgs, ContactCommand, ContactEnterArgs,
    ContactExportArgs, ContactImportArgs, ContactInviteArgs, ContactInvoiceArgs,
    ContactKeyCheckArgs, ContactKeysArgs, ContactLabelArgs, ContactMoveArgs, ContactMoveHomeArgs,
    ContactOpenSealedArgs, ContactPayArgs, ContactPayloadArgs, ContactPayloadCommand,
    ContactPayloadPostArgs, ContactPlainArgs, ContactRequestArgs, ContactSasArgs, ContactSealArgs,
    ContactSendSlateArgs, ContactSlateIdArg, ContactSwitchArgs, InviteExpiryArg, KeysArg, OnOffArg,
    PurposeArg, SasArg,
};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{
    ContactAcceptReport, ContactCardReport, ContactCheckReport, ContactCollectReport,
    ContactExportReport, ContactFailureReport, ContactImportReport, ContactInviteReport,
    ContactInvoiceIssueReport, ContactInvoiceListReport, ContactInvoiceReport,
    ContactKeyCheckReport, ContactLinkReport, ContactListReport, ContactMoveHomeReport,
    ContactPayloadAckReport, ContactPayloadListReport, ContactPayloadPostReport,
    ContactPayloadReport, ContactPreviewReport, ContactQuarantineReport, ContactRemoveReport,
    ContactReport, ContactSlateReport, InvoiceDeclineReport, InvoicePayReport,
    QuarantinedMessageReport, Report,
};

/// Contacts belong to the default account.
const CONTACT_ACCOUNT: AccountIndex = AccountIndex(0);

pub(super) fn contact_id(text: &str) -> Result<ContactId, CliError> {
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

fn kind_name(kind: ContactKind) -> &'static str {
    match kind {
        ContactKind::Person => "person",
        ContactKind::Shop => "shop",
        ContactKind::Exchange => "exchange",
    }
}

pub(super) fn purpose(purpose: PurposeArg) -> Purpose {
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
        PairingFailure::KindDiffers => "kind-differs",
        PairingFailure::Refused(Refusal::AlreadyUsed) => "refused-already-used",
        PairingFailure::Refused(Refusal::Expired) => "refused-expired",
        PairingFailure::Refused(Refusal::CancelledByInviter) => "refused-cancelled",
        PairingFailure::OtherAddress => "other-address",
        PairingFailure::AddressProofMissing => "address-proof-missing",
        PairingFailure::Crossed => "crossed",
    }
}

pub(super) fn purpose_name(purpose: Purpose) -> &'static str {
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

fn contact_report(view: &ContactView) -> Result<ContactReport, CliError> {
    Ok(ContactReport {
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
        sas_indexes: view
            .sas
            .map(|symbols| symbols.iter().map(SasSymbol::index).collect())
            .transpose()
            .map_err(|_| CliError::SasTable)?
            .unwrap_or_default(),
        status: match view.status {
            PairingStatus::Waiting => "waiting",
            PairingStatus::Paired => "paired",
            PairingStatus::Verified => "verified",
            PairingStatus::KeysChanged => "keys-changed",
            PairingStatus::Ended => "ended",
        },
        peer_heard_at: view.peer_heard_at.map(|at| at.to_string()),
        peer_verified_at: view.peer_verified_at.map(|at| at.to_string()),
        peer_features: view.peer_features,
        peer_profile: view.peer_profile,
        native_slates: view.native_slates,
        ended_reason: view.ended_reason.map(|reason| match reason {
            PairingEndReason::Mismatch => "mismatch",
            PairingEndReason::PeerMismatch => "peer-mismatch",
            PairingEndReason::Unpaired => "unpaired",
            PairingEndReason::NeverFinished => "never-finished",
        }),
        ended_at: view.ended_at.map(|at| at.to_string()),
        allow_invoices: view.allow_invoices,
        seal: match view.seal {
            SealMode::On => "on",
            SealMode::Off => "off",
            SealMode::Degraded => "degraded",
        }
        .to_owned(),
        home_relay: view.home_relay.clone(),
        requested_relay: view.requested_relay.clone(),
        lapsed: view.lapsed,
        last_heard: view.last_sealed_in.map(|at| at.to_string()),
    })
}

/// The CLI's relays: its Epicbox transport, and the first Epicbox servers of the settings file,
/// where pairing words are offered and looked for. `--offline` and `--epicbox-off` keep every
/// contact command off the relays.
fn relays<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: &ContactArgs,
    meeting: &[lepic_epicbox::RelayEndpoint],
) -> ContactRelays {
    relays_in_mode(opened, args.offline, args.epicbox_off, meeting)
}

/// The relays `--offline` and `--epicbox-off` leave a command.
pub(super) fn relays_in_mode<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    offline: bool,
    epicbox_off: bool,
    meeting: &[lepic_epicbox::RelayEndpoint],
) -> ContactRelays {
    let mode = if offline {
        RelayMode::Offline
    } else if epicbox_off {
        RelayMode::EpicboxOff
    } else {
        RelayMode::Online
    };
    ContactRelays::new((*opened.epicbox).clone(), mode).with_meeting(meeting.to_vec())
}

/// Pays the contact `contact_id` through its mailbox, for `lepic tx send --to-contact`. The S1
/// passes through a file in the wallet's directory that is removed afterwards.
pub(super) async fn send_to_contact<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    contact_id: ContactId,
    request: SendRequest,
    purpose: Option<Purpose>,
    data_dir: &Path,
) -> Result<SentSlate, CliError> {
    let relays = ContactRelays::new((*opened.epicbox).clone(), RelayMode::Online);
    let slate_file = SlateFile::new(data_dir)?;
    Ok(opened
        .wallet
        .contact_book()
        .contact_send(
            &relays,
            contact_id,
            request,
            slate_file.path.clone(),
            purpose,
        )
        .await?)
}

/// A slate file that exists only for one send, removed when dropped, also when the send is
/// interrupted.
pub(super) struct SlateFile {
    pub(super) path: PathBuf,
}

impl SlateFile {
    pub(super) fn new(data_dir: &Path) -> Result<Self, CliError> {
        let name: [u8; 8] = super::random_bytes()?;
        let name: String = name.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            path: data_dir.join(format!(".lepic-{name}.slate")),
        })
    }
}

impl Drop for SlateFile {
    fn drop(&mut self) {
        // Absent when the send stopped before writing it.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The contact the transaction `tx_id` was sealed to or from, if any.
pub(super) async fn contact_of<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    tx_id: TxId,
) -> Result<Option<ContactId>, CliError> {
    Ok(opened
        .wallet
        .contact_book()
        .contact_of_transaction(tx_id)
        .await?)
}

/// The longest sealed text read from a file or standard input.
const MAX_SEALED_TEXT: u64 = 4 * 1024 * 1024;

/// Reads sealed text from a file or standard input (`-`), refused unless the classifier of
/// payment files (RFC 0003 5.12) says it is a payment file.
pub(super) fn read_sealed(input: &str) -> Result<String, CliError> {
    use std::io::Read as _;
    let mut data = Vec::new();
    if input == "-" {
        std::io::stdin()
            .lock()
            .take(MAX_SEALED_TEXT)
            .read_to_end(&mut data)
            .map_err(CliError::io("read sealed text from standard input"))?;
    } else {
        std::fs::File::open(input)
            .and_then(|file| file.take(MAX_SEALED_TEXT).read_to_end(&mut data))
            .map_err(CliError::io("read the sealed file"))?;
    }
    lepic_wallet_contacts::payment_file(&data)?;
    String::from_utf8(data)
        .map_err(|_| CliError::Contact(lepic_wallet_contacts::ContactError::NotPaymentFile))
}

/// The file the answer to the sealed text `text` read from `input` goes to: `<stem>-reply.epictx`
/// next to a native request, else `<input>.response`.
fn answer_path(input: &Path, text: &str) -> PathBuf {
    if lepic_wallet_contacts::is_epictx(text) {
        let stem = input
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        input.with_file_name(format!("{stem}-reply.epictx"))
    } else {
        response_path(input)
    }
}

/// Writes `text` to `out`, or returns it to print.
pub(super) fn write_or_print(
    out: Option<std::path::PathBuf>,
    text: String,
) -> Result<(Option<String>, Option<String>), CliError> {
    match out {
        Some(path) => {
            super::refuse_saved_txs(&path)?;
            lepic_store::file::write_owner_only_atomic(&path, text.as_bytes())
                .map_err(CliError::io("write the slate file"))?;
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
    fn note_ignored_kind(&mut self, kind: Option<crate::cli::ContactKindArg>) {
        if kind.is_some() {
            self.show_line(KIND_IGNORED);
        }
    }

    pub(super) async fn contact(&mut self, args: ContactArgs) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let wallet = &opened.wallet;
        let relays = relays(&opened, &args, &self.settings.servers.meeting_relays);
        Ok(match args.command {
            ContactCommand::Invite(args) => {
                self.note_ignored_kind(args.kind);
                invite(&opened, &relays, args).await?
            }
            ContactCommand::Request(args) => request(&opened, &relays, args).await?,
            ContactCommand::Open(args) => {
                let preview = wallet.contact_book().pairing_preview(&args.link).await?;
                Report::ContactPreview(ContactPreviewReport {
                    claimed_name: preview.claimed_name,
                    kind: kind_name(preview.kind),
                    expires_at: preview.expires_at.to_string(),
                    home_relay: preview.home_relay,
                    service: preview.service,
                })
            }
            ContactCommand::Accept(args) => accept(&opened, &relays, args).await?,
            ContactCommand::Enter(args) => enter(&opened, &relays, args).await?,
            ContactCommand::Collect => {
                let events = wallet.subscribe();
                let report = collect(&opened, &relays, CollectTrigger::Pull).await?;
                self.show_invoice_events(events);
                report
            }
            ContactCommand::Sas(args) => sas(&opened, &relays, args).await?,
            ContactCommand::ShowCard(args) => {
                self.note_ignored_kind(args.kind);
                show_card(&opened, &relays, args).await?
            }
            ContactCommand::ScanCard(args) => {
                let id = contact_id(&args.contact.contact)?;
                let view = wallet
                    .contact_book()
                    .pairing_scan_card(&relays, id, &args.link)
                    .await?;
                Report::Contact(contact_report(&view)?)
            }
            ContactCommand::List => Report::ContactList(ContactListReport {
                contacts: wallet
                    .contact_book()
                    .contacts()
                    .await?
                    .iter()
                    .map(contact_report)
                    .collect::<Result<_, _>>()?,
            }),
            ContactCommand::KeyCheck(args) => key_check(&opened, &relays, args).await?,
            ContactCommand::Keys(args) => resolve_keys(&opened, args).await?,
            ContactCommand::Seal(args) => seal(&opened, args).await?,
            ContactCommand::SendSlate(args) => send_slate(&opened, &relays, args).await?,
            ContactCommand::Plain(args) => plain(&opened, args).await?,
            ContactCommand::OpenSealed(args) => open_sealed(&opened, args).await?,
            ContactCommand::Label(args) => label(&opened, args).await?,
            ContactCommand::Move(args) => move_relay(&opened, args).await?,
            ContactCommand::MoveHome(args) => move_home(&opened, &relays, args).await?,
            ContactCommand::Check(args) => {
                let id = contact_id(&args.contact)?;
                wallet.contact_book().contact_check(&relays, id).await?;
                Report::ContactCheck(ContactCheckReport {
                    contact_id: id.to_string(),
                })
            }
            ContactCommand::Remove(args) => {
                let id = contact_id(&args.contact)?;
                Report::ContactRemove(ContactRemoveReport {
                    contact_id: id.to_string(),
                    removed: wallet.contact_book().contact_remove(id).await?,
                })
            }
            ContactCommand::AllowInvoices(args) => allow_invoices(&opened, &relays, args).await?,
            ContactCommand::Invoice(args) => issue_invoice(&opened, &relays, args).await?,
            ContactCommand::Invoices => invoices(&opened).await?,
            ContactCommand::PayInvoice(args) => pay_invoice(&opened, &relays, args).await?,
            ContactCommand::Decline(args) => decline(&opened, &relays, args).await?,
            ContactCommand::Export(args) => export(&opened, args).await?,
            ContactCommand::Import(args) => import(&opened, args).await?,
            ContactCommand::Quarantine => quarantine(&opened).await?,
            ContactCommand::Payload(args) => {
                let report = payload(&opened, &relays, args).await?;
                if let Report::ContactPayloadPost(posted) = &report
                    && posted.peer_lacks_app_payloads
                {
                    self.show_line(PEER_LACKS_APP_PAYLOADS);
                }
                report
            }
        })
    }
}

/// `lepic contact invite`: makes an invite to pair with a contact.
async fn invite<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactInviteArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let offer = wallet
        .contact_book()
        .pairing_invite(
            relays,
            InviteRequest {
                account: CONTACT_ACCOUNT,
                name: args.name.name,
                kind: ContactKind::Person,
                expiry: match args.expiry {
                    InviteExpiryArg::Hour => InviteExpiry::OneHour,
                    InviteExpiryArg::Day => InviteExpiry::OneDay,
                    InviteExpiryArg::Week => InviteExpiry::SevenDays,
                },
                offer_words: args.pairing_words,
                home_relay: None,
                class: PairingClass::Contact,
                expect_address: None,
            },
        )
        .await?;
    Ok(Report::ContactInvite(ContactInviteReport {
        contact_id: offer.contact_id.to_string(),
        link: offer.link,
        expires_at: offer.expires_at.to_string(),
        words: offer
            .words
            .iter()
            .flatten()
            .map(|symbol| format!("{} {}", symbol.emoji, symbol.name))
            .collect(),
    }))
}

/// `lepic contact request`: asks a proven wallet to pair, at its payments address.
async fn request<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactRequestArgs,
) -> Result<Report, CliError> {
    let offer = opened
        .wallet
        .contact_book()
        .pairing_request_send(relays, CONTACT_ACCOUNT, &args.address, &args.name.name)
        .await?;
    Ok(Report::ContactInvite(ContactInviteReport {
        contact_id: offer.contact_id.to_string(),
        link: offer.link,
        expires_at: offer.expires_at.to_string(),
        words: Vec::new(),
    }))
}

/// `lepic contact accept`: answers an invite.
async fn accept<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactAcceptArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let outcome = wallet
        .contact_book()
        .pairing_accept(
            relays,
            AcceptRequest {
                link: args.link.link,
                account: CONTACT_ACCOUNT,
                name: args.name.name,
                by_hand: args.by_hand,
                class: PairingClass::Contact,
                expect_address: None,
            },
        )
        .await?;
    Ok(Report::ContactAccept(ContactAcceptReport {
        contact_id: outcome.contact_id.to_string(),
        reply_link: outcome.reply_link,
        posted: outcome.posted,
    }))
}

/// `lepic contact enter`: takes a pairing link entered by hand, or finds an invite by its pairing words.
async fn enter<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactEnterArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let link = match args.input.as_slice() {
        [link] if link.trim_start().starts_with("epiccash:") => link.clone(),
        words => {
            let link = wallet
                .contact_book()
                .pairing_find_words(relays, words)
                .await?;
            return Ok(Report::ContactLink(ContactLinkReport {
                outcome: "invite",
                contact_id: None,
                link: Some(link),
            }));
        }
    };
    let outcome = wallet
        .contact_book()
        .pairing_enter_link(relays, &link)
        .await?;
    Ok(Report::ContactLink(match outcome {
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
    }))
}

/// `lepic contact sas`: records the user's SAS check.
async fn sas<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactSasArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.contact.contact)?;
    let decision = match args.result {
        SasArg::Match => SasDecision::Match,
        SasArg::Mismatch => SasDecision::Mismatch,
        SasArg::Skip => SasDecision::Skip,
    };
    wallet
        .contact_book()
        .pairing_sas(relays, id, decision)
        .await?;
    Ok(if decision == SasDecision::Mismatch {
        Report::ContactRemove(ContactRemoveReport {
            contact_id: id.to_string(),
            removed: true,
        })
    } else {
        Report::Contact(contact_report(&wallet.contact_book().contact(id).await?)?)
    })
}

/// `lepic contact show-card`: shows a card to pair in person.
async fn show_card<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactCardArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let offer = wallet
        .contact_book()
        .pairing_show_card(
            relays,
            CardRequest {
                account: CONTACT_ACCOUNT,
                name: args.name.name,
                kind: ContactKind::Person,
                home_relay: None,
            },
        )
        .await?;
    Ok(Report::ContactCard(ContactCardReport {
        contact_id: offer.contact_id.to_string(),
        link: offer.link,
    }))
}

/// `lepic contact key-check`: starts the key check of a contact paired again.
async fn key_check<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactKeyCheckArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let new = contact_id(&args.new)?;
    let old = contact_id(&args.old)?;
    wallet
        .contact_book()
        .contact_key_check(relays, new, old)
        .await?;
    Ok(Report::ContactKeyCheck(ContactKeyCheckReport {
        contact_id: new.to_string(),
        old_contact_id: old.to_string(),
    }))
}

/// `lepic contact keys`: resolves a new pairing in keys-changed.
async fn resolve_keys<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactKeysArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let new = contact_id(&args.new)?;
    Ok(match args.choice {
        KeysArg::KeepOld => {
            wallet
                .contact_book()
                .contact_keys_resolve(new, KeysDecision::KeepOld)
                .await?;
            Report::ContactRemove(ContactRemoveReport {
                contact_id: new.to_string(),
                removed: true,
            })
        }
        KeysArg::UseNew => {
            wallet
                .contact_book()
                .contact_keys_resolve(new, KeysDecision::UseNew)
                .await?;
            Report::Contact(contact_report(&wallet.contact_book().contact(new).await?)?)
        }
    })
}

/// `lepic contact seal`: seals a transaction's slate for a contact, to a file or to print.
async fn seal<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactSealArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.slate.contact.contact)?;
    let tx_id = TxId(args.slate.tx.tx_id);
    let text = wallet
        .contact_book()
        .contact_seal_slate(id, tx_id, args.slate.purpose.map(purpose))
        .await?;
    let (file, text) = write_or_print(args.out.out, text)?;
    Ok(Report::ContactSlate(ContactSlateReport {
        action: "sealed",
        contact_id: Some(id.to_string()),
        tx_id: Some(tx_id.0),
        slate_id: None,
        stage: None,
        amount: None,
        file,
        text,
    }))
}

/// `lepic contact send-slate`: posts a transaction's slate sealed to a contact's mailbox.
async fn send_slate<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactSendSlateArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.contact.contact)?;
    let tx_id = TxId(args.tx.tx_id);
    wallet
        .contact_book()
        .contact_post_slate(relays, id, tx_id, args.purpose.map(purpose))
        .await?;
    Ok(Report::ContactSlate(ContactSlateReport {
        action: "sent",
        contact_id: Some(id.to_string()),
        tx_id: Some(tx_id.0),
        slate_id: None,
        stage: None,
        amount: None,
        file: None,
        text: None,
    }))
}

/// `lepic contact plain`: a transaction's slate unsealed, for a contact that cannot open sealed ones.
async fn plain<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactPlainArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let tx_id = TxId(args.tx.tx_id);
    let wire = wallet.contact_book().contact_plain_fallback(tx_id).await?;
    let text = wire.as_text().unwrap_or_default().to_owned();
    let (file, text) = write_or_print(args.out.out, text)?;
    Ok(Report::ContactSlate(ContactSlateReport {
        action: "plain",
        contact_id: None,
        tx_id: Some(tx_id.0),
        slate_id: None,
        stage: None,
        amount: None,
        file,
        text,
    }))
}

/// `lepic contact label`: sets a contact's label.
async fn label<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactLabelArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.contact.contact)?;
    wallet
        .contact_book()
        .contact_set_label(id, args.label)
        .await?;
    Ok(Report::Contact(contact_report(
        &wallet.contact_book().contact(id).await?,
    )?))
}

/// `lepic contact move`: moves our mailbox with this contact to the relay it asked for.
async fn move_relay<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactMoveArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.contact.contact)?;
    wallet
        .contact_book()
        .apply_relay_move(id, args.apply.trim())
        .await?;
    Ok(Report::Contact(contact_report(
        &wallet.contact_book().contact(id).await?,
    )?))
}

/// `lepic contact move-home`: moves the wallet's own home relay for every paired contact.
async fn move_home<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactMoveHomeArgs,
) -> Result<Report, CliError> {
    let drain =
        std::time::Duration::from_secs(24 * 60 * 60).saturating_mul(u32::from(args.drain_days));
    let moved = opened
        .wallet
        .contact_book()
        .contacts_move_home(relays, &args.host, drain)
        .await?;
    // The core stamps the drain's end with its own clock; this reads the same moment to
    // the second.
    let drain_until = (args.drain_days > 0)
        .then(|| {
            let seconds = i64::try_from(drain.as_secs()).ok()?;
            jiff::Timestamp::from_second(jiff::Timestamp::now().as_second().checked_add(seconds)?)
                .ok()
        })
        .flatten()
        .map(|until| until.to_string());
    Ok(Report::ContactMoveHome(ContactMoveHomeReport {
        home_relay: args.host.trim().to_ascii_lowercase(),
        moved,
        drain_until,
    }))
}

/// `lepic contact allow-invoices`: lets a contact send invoices, or stops it.
async fn allow_invoices<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactSwitchArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.contact.contact)?;
    wallet
        .contact_book()
        .contact_set_allow_invoices(id, args.state == OnOffArg::On)
        .await?;
    wallet
        .contact_book()
        .contacts_outbox_deliver(relays)
        .await?;
    Ok(Report::Contact(contact_report(
        &wallet.contact_book().contact(id).await?,
    )?))
}

/// `lepic contact invoice`: sends a contact an invoice through its mailbox.
async fn issue_invoice<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactInvoiceArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let id = contact_id(&args.contact.contact)?;
    let amount = parse_amount(&args.amount)?;
    let account = wallet.account(&args.account.account)?;
    let issued = wallet
        .contact_book()
        .contact_issue_invoice(
            relays,
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
    let view = wallet.contact_book().contact(id).await.ok();
    Ok(Report::ContactInvoiceIssue(ContactInvoiceIssueReport {
        contact_id: id.to_string(),
        contact_name: contact_name(view.as_ref(), id),
        tx_id: issued.tx_id.0,
        slate_id: issued.slate_id.to_string(),
        amount: format_amount(issued.amount),
    }))
}

/// `lepic contact pay-invoice`: pays a contact's invoice.
async fn pay_invoice<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactPayArgs,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let slate_id = SlateId::parse(&args.slate_id).map_err(|_| CliError::SlateId)?;
    let amount: Amount = parse_amount(&args.amount)?;
    let spend = Spend::from_args(&args.spend)?;
    let account = wallet.account(&args.account.account)?;
    let request = spend.pay_request(account.index, amount, args.message.message);
    let contact = wallet
        .contact_book()
        .contact_invoices()
        .await?
        .into_iter()
        .find(|invoice| invoice.slate_id == slate_id)
        .map(|invoice| invoice.contact_id.to_string())
        .unwrap_or_default();
    let (paid, _) = wallet
        .contact_book()
        .contact_pay_invoice(relays, slate_id, request)
        .await?;
    Ok(Report::InvoicePay(InvoicePayReport {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate.id().to_string(),
        amount: format_amount(paid.slate.amount()),
        fee: format_fee(paid.slate.fee()),
        transport: "contact".to_owned(),
        destination: contact,
        reply_file: None,
    }))
}

/// `lepic contact decline`: declines a contact's invoice.
async fn decline<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactSlateIdArg,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let slate_id = SlateId::parse(&args.slate_id).map_err(|_| CliError::SlateId)?;
    wallet
        .contact_book()
        .contact_decline_invoice(slate_id)
        .await?;
    wallet
        .contact_book()
        .contacts_outbox_deliver(relays)
        .await?;
    Ok(Report::InvoiceDecline(InvoiceDeclineReport {
        slate_id: slate_id.to_string(),
        state: "declined".to_owned(),
    }))
}

/// `lepic contact quarantine`: lists the contact messages kept for the host.
async fn quarantine<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
) -> Result<Report, CliError> {
    let messages = opened.wallet.contact_book().contact_quarantine().await?;
    Ok(Report::ContactQuarantine(ContactQuarantineReport {
        messages: messages
            .into_iter()
            .map(|kept| QuarantinedMessageReport {
                id: kept.id,
                contact_id: kept.contact_id.to_string(),
                reason: kept.reason.name(),
                first_seen: kept.first_seen.to_string(),
                attempts: kept.attempts,
                size: kept.size,
            })
            .collect(),
    }))
}

/// The contact backup document.
pub(super) async fn export_document<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
) -> Result<String, CliError> {
    Ok(opened.wallet.contact_book().contacts_export().await?)
}

/// Restores the pairing records of a contact backup document.
pub(super) async fn import_document<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    document: String,
) -> Result<ContactImportReport, CliError> {
    let summary = opened
        .wallet
        .contact_book()
        .contacts_import(document)
        .await?;
    Ok(ContactImportReport {
        imported: summary.imported,
        skipped_existing: summary.skipped_existing,
        skipped_conflict: summary.skipped_conflict,
    })
}

/// `lepic contact export`: writes the contact backup.
async fn export<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactExportArgs,
) -> Result<Report, CliError> {
    let document = export_document(opened).await?;
    lepic_store::file::write_owner_only_atomic(&args.file, document.as_bytes())
        .map_err(CliError::io("write the contact backup"))?;
    Ok(Report::ContactExport(ContactExportReport {
        file: args.file.display().to_string(),
    }))
}

/// `lepic contact import`: reads a contact backup.
async fn import<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    args: ContactImportArgs,
) -> Result<Report, CliError> {
    let document =
        std::fs::read_to_string(&args.file).map_err(CliError::io("read the contact backup"))?;
    Ok(Report::ContactImport(
        import_document(opened, document).await?,
    ))
}

/// What `--kind` prints: the flag stays accepted for old scripts and changes nothing (ADR 0041).
const KIND_IGNORED: &str = "note: --kind is deprecated and ignored; new pairings write person";

/// The warning a post prints when the other wallet's features are known and lack app payloads.
const PEER_LACKS_APP_PAYLOADS: &str =
    "warning: the other wallet does not claim app payloads; it may not keep this one";

/// `lepic contact payload`: posts, lists and acknowledges the host app's payloads. LEPIC never
/// reads the bytes, and the CLI adds no rule of its own to what the wallet allows.
async fn payload<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    args: ContactPayloadArgs,
) -> Result<Report, CliError> {
    let book = opened.wallet.contact_book();
    Ok(match args.command {
        ContactPayloadCommand::Post(args) => {
            let id = contact_id(&args.contact.contact)?;
            let bytes = payload_bytes(&args)?;
            let posted = book.contact_post_payload(relays, id, bytes).await?;
            Report::ContactPayloadPost(ContactPayloadPostReport {
                contact_id: id.to_string(),
                payload_id: posted.id.to_string(),
                peer_lacks_app_payloads: posted.peer_lacks_app_payloads,
            })
        }
        ContactPayloadCommand::List => Report::ContactPayloadList(ContactPayloadListReport {
            payloads: book
                .contact_payloads()
                .await?
                .into_iter()
                .map(|kept| ContactPayloadReport {
                    id: kept.id.to_string(),
                    contact_id: kept.contact_id.to_string(),
                    received_at: kept.received_at.to_string(),
                    payload: to_hex(&kept.payload),
                })
                .collect(),
        }),
        ContactPayloadCommand::Ack(args) => {
            let ids = args
                .ids
                .iter()
                .map(|text| PayloadId::parse(text.trim()).ok_or(CliError::PayloadId))
                .collect::<Result<Vec<_>, _>>()?;
            Report::ContactPayloadAck(ContactPayloadAckReport {
                acknowledged: book.contact_payloads_ack(&ids).await?,
            })
        }
    })
}

/// The bytes `--hex` or `--file` gives. A file is read up to one byte past the largest
/// payload, so the wallet refuses a larger one without the whole file in memory.
fn payload_bytes(args: &ContactPayloadPostArgs) -> Result<Vec<u8>, CliError> {
    use std::io::Read as _;
    if let Some(path) = &args.file {
        let mut bytes = Vec::new();
        let limit = u64::try_from(MAX_APP_PAYLOAD_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        std::fs::File::open(path)
            .and_then(|file| file.take(limit).read_to_end(&mut bytes))
            .map_err(CliError::io("read the payload file"))?;
        return Ok(bytes);
    }
    from_hex(args.hex.as_deref().unwrap_or_default())
}

pub(super) fn from_hex(text: &str) -> Result<Vec<u8>, CliError> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::PayloadHex);
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or(CliError::PayloadHex)
        })
        .collect()
}

pub(super) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// `lepic contact collect`: runs one collecting cycle.
async fn collect<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    relays: &ContactRelays,
    trigger: CollectTrigger,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    // The cycle runs the outbox itself, every queued entry at once.
    let collected = wallet
        .contact_book()
        .contacts_collect(relays, trigger)
        .await?;
    Ok(Report::ContactCollect(ContactCollectReport {
        mailboxes: collected.mailboxes,
        capped: collected.capped,
        kept: collected.kept,
        refused: collected.refused,
        timed_out: collected.timed_out,
        not_reached: collected.not_reached,
        quarantined: collected.quarantined,
        quarantine_dropped: collected.quarantine_dropped,
        buffered: collected.buffered,
        messages: collected.messages,
        paired: collected.paired,
        delivered: collected.delivered,
        epic1: collected.epic1,
        failed: collected
            .failed
            .iter()
            .map(|failed| ContactFailureReport {
                contact_id: failed.contact_id.to_string(),
                reason: failure_name(failed.reason),
            })
            .collect(),
        unreachable: collected.unreachable,
    }))
}

/// One collecting cycle on the Epicbox transport and the meeting relays, for `lepic serve`.
#[cfg(unix)]
pub(super) async fn collect_online<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    meeting: &[lepic_epicbox::RelayEndpoint],
    trigger: CollectTrigger,
) -> Result<(), CliError> {
    let relays = ContactRelays::new((*opened.epicbox).clone(), RelayMode::Online)
        .with_meeting(meeting.to_vec());
    collect(opened, &relays, trigger).await.map(drop)
}

/// `lepic contact invoices`: lists the contacts' invoices waiting for the user.
async fn invoices<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
) -> Result<Report, CliError> {
    let wallet = &opened.wallet;
    let contacts = wallet.contact_book().contacts().await?;
    let view = |id: ContactId| contacts.iter().find(|view| view.contact_id == id);
    Ok(Report::ContactInvoices(ContactInvoiceListReport {
        invoices: wallet
            .contact_book()
            .contact_invoices()
            .await?
            .into_iter()
            .map(|invoice| ContactInvoiceReport {
                slate_id: invoice.slate_id.to_string(),
                contact_id: invoice.contact_id.to_string(),
                contact_name: contact_name(view(invoice.contact_id), invoice.contact_id),
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
    }))
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
    let sealed = wallet.contact_book().sealed_open(&text).await?;
    let contact_id = sealed.contact_id.map(|id| id.to_string());
    let stage = Some(sealed.stage.as_str());
    let answer_to = args
        .answer_file
        .clone()
        .or_else(|| (args.input != "-").then(|| answer_path(Path::new(&args.input), &text)));
    let (action, tx_id, slate, answer) = match sealed.stage {
        Stage::S1 => {
            let done = wallet
                .contact_book()
                .sealed_receive(
                    &text,
                    ReceiveRequest {
                        account: Some(args.account.account),
                        message: args.message.message,
                        ..ReceiveRequest::default()
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
            let done = wallet.contact_book().sealed_pay(&text, request).await?;
            ("paid", done.paid.tx_id, done.paid.slate, Some(done.answer))
        }
        _ => {
            let done = wallet
                .contact_book()
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
