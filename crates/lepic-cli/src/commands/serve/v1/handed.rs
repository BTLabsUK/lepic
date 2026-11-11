// SPDX-License-Identifier: Apache-2.0
//! Anything a user is handed: `POST /inspect` reads it, `POST /open` acts on it.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_wallet::receive::ReceiveRequest;
use lepic_wallet::slate::ur_slate::{MAX_FRAGMENT_LEN, decode_ur_slate, encode_ur_slate};
use lepic_wallet::slate::{MediaType, Slate, Stage, WireSlate};
use lepic_wallet_contacts::{ContactError, SealedAnswer, WalletContacts as _};
use serde::Deserialize;

use super::super::Service;
use super::Reply;
use super::events::{self, Change};
use super::payments::{self, view};
use crate::amount::{format_amount, format_fee};
use crate::api::model::{Handoff, Inspection, OpenResult};
use crate::api::{Category, Context, Problem, Request, ok};
use crate::api_clients::Role;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::Report;

/// The body of `POST /inspect` and `POST /open`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Handed {
    /// Taken, not used yet: an answer is handed back.
    #[serde(default, rename = "deliver")]
    _deliver: Option<bool>,
    /// Taken, not used yet.
    #[serde(default, rename = "relay_ok")]
    _relay_ok: Option<bool>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    file_base64: Option<String>,
    #[serde(default)]
    qr_frames: Option<Vec<String>>,
    #[serde(default)]
    expect: Vec<String>,
    #[serde(default)]
    message: Option<String>,
}

/// How the item came in, so an answer goes back the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Text,
    File,
    Qr,
}

impl Handed {
    /// The item as text, and the form it came in. Exactly one form is given.
    fn content(&self) -> Result<(String, Form), Problem> {
        let given = [
            self.text.is_some(),
            self.file_base64.is_some(),
            self.qr_frames.is_some(),
        ];
        if given.iter().filter(|each| **each).count() != 1 {
            return Err(Problem::usage(
                "give exactly one of text, file_base64 and qr_frames",
            ));
        }
        if let Some(text) = &self.text {
            return Ok((text.trim().to_owned(), Form::Text));
        }
        if let Some(file) = &self.file_base64 {
            let bytes = STANDARD
                .decode(file.trim())
                .map_err(|_| Problem::invalid("/file_base64", "file_base64 is not base64"))?;
            let text = String::from_utf8(bytes).map_err(|_| {
                Problem::invalid("/file_base64", "the file is not a text slate or address")
            })?;
            return Ok((text.trim().to_owned(), Form::File));
        }
        let frames = self.qr_frames.as_deref().unwrap_or_default();
        let progress = decode_ur_slate(frames)
            .map_err(|error| Problem::invalid("/qr_frames", format!("qr_frames: {error}")))?;
        let text = progress.json.ok_or_else(|| {
            Problem::invalid(
                "/qr_frames",
                format!(
                    "qr_frames hold {} of {} parts; scan more",
                    progress.resolved_fragments, progress.fragment_count
                ),
            )
        })?;
        Ok((text, Form::Qr))
    }
}

/// An item read: what it is, and the slate when it is one.
struct Read {
    inspection: Inspection,
    slate: Option<Slate>,
    /// The item as it was handed over: the armour text of a sealed file.
    wire: WireSlate,
    /// Set for a sealed file.
    sealed: Option<Sealed>,
}

/// A sealed file, opened with this wallet's keys or not.
enum Sealed {
    /// It opened; the contact whose key signed it, when one did.
    Opened { contact_id: Option<String> },
    /// It does not open here: why.
    Closed(String),
}

/// What `text` is. Slates are decoded; addresses are recognised by their shape only.
async fn read<H: Host>(service: &Service<'_, H>, text: &str) -> Result<Read, Problem> {
    let wire = WireSlate::text(MediaType::JSON, text.to_owned());
    let plain = |kind: &str, next: &str| Read {
        inspection: Inspection::new(kind, true, next),
        slate: None,
        wire: wire.clone(),
        sealed: None,
    };
    if matches!(
        lepic_wallet_contacts::payment_file(text.as_bytes()),
        Ok(lepic_wallet_contacts::PaymentFile::Armour)
    ) {
        return sealed_read(service, text, wire).await;
    }
    if text.starts_with('{') {
        return match service.held.file.decode(service.settings.network, &wire) {
            Ok(slate) => slate_read(service, slate, wire).await,
            Err(_) => Ok(plain("unknown", "none")),
        };
    }
    let lower = text.to_ascii_lowercase();
    let kind = if lower.starts_with("epic:") {
        "link"
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        if crate::commands::is_onion(text) {
            "onion_address"
        } else {
            "http_address"
        }
    } else if crate::commands::is_onion(text) {
        "onion_address"
    } else if lower.starts_with("epic1") && !lower.contains('@') && !lower.contains(' ') {
        "epic1_address"
    } else if is_epicbox(text) {
        "epicbox_address"
    } else {
        return Ok(plain("unknown", "none"));
    };
    let mut read = plain(kind, if kind == "link" { "open" } else { "pay" });
    read.inspection.summary_mut().to = Some(text.to_owned());
    Ok(read)
}

/// What a sealed file holds, opened with this wallet's keys as `contact open-sealed` opens it.
/// Nothing is stored: receiving, paying or finishing it later refreshes the contact.
async fn sealed_read<H: Host>(
    service: &Service<'_, H>,
    text: &str,
    wire: WireSlate,
) -> Result<Read, Problem> {
    let closed = |reason: String| Read {
        inspection: Inspection::new("sealed", true, "none"),
        slate: None,
        wire: wire.clone(),
        sealed: Some(Sealed::Closed(reason)),
    };
    let opened = match Box::pin(service.held.wallet.contact_book().sealed_peek(text)).await {
        Ok(opened) => opened,
        Err(error) if does_not_open(&error) => return Ok(closed(error.to_string())),
        Err(error) => return Err(CliError::from(error).into()),
    };
    let Ok(slate) = service
        .held
        .file
        .decode(service.settings.network, &opened.wire)
    else {
        return Ok(closed("the slate inside does not decode".to_owned()));
    };
    let contact_id = opened.contact_id.map(|id| id.to_string());
    let mut read = slate_read(service, slate, wire).await?;
    "sealed".clone_into(&mut read.inspection.kind);
    read.inspection
        .summary_mut()
        .contact_id
        .clone_from(&contact_id);
    read.sealed = Some(Sealed::Opened { contact_id });
    Ok(read)
}

/// The errors of sealed text that is not for this wallet, damaged, or holds no slate.
fn does_not_open(error: &ContactError) -> bool {
    matches!(
        error,
        ContactError::Decode(_)
            | ContactError::NotForThisInstall
            | ContactError::CannotOpen
            | ContactError::NotASlate
            | ContactError::SavedTransaction
            | ContactError::NotPaymentFile
            | ContactError::Epic1(_)
            | ContactError::TooLarge { .. }
    )
}

/// `key@host` or `key@host:port`, with no spaces.
fn is_epicbox(text: &str) -> bool {
    match text.split_once('@') {
        Some((key, host)) => {
            !key.is_empty()
                && !host.is_empty()
                && key.chars().all(|each| each.is_ascii_alphanumeric())
                && !host.contains(char::is_whitespace)
                && !host.contains('@')
        }
        None => false,
    }
}

/// The inspection of a decoded slate.
async fn slate_read<H: Host>(
    service: &Service<'_, H>,
    slate: Slate,
    wire: WireSlate,
) -> Result<Read, Problem> {
    let (kind, next) = match slate.stage() {
        Stage::S1 => ("slate_send", "open"),
        Stage::I1 => ("slate_invoice", "pay"),
        Stage::S2 | Stage::I2 => ("slate_answer", "open"),
        Stage::S3 | Stage::I3 => ("slate_answer", "none"),
    };
    let mut inspection = Inspection::new(kind, true, next);
    let id = slate.id().to_string();
    if view::find(service, &id).await?.is_some() {
        inspection.payment_id = Some(id);
    }
    let summary = inspection.summary_mut();
    summary.amount = Some(format_amount(slate.amount()));
    if slate.fee().value() != 0 {
        summary.fee = Some(format_fee(slate.fee()));
    }
    summary.message = message_of(&slate);
    summary.expires_at_height = slate
        .ttl_cutoff_height()
        .map(lepic_primitives::amount::Height::value);
    Ok(Read {
        inspection,
        slate: Some(slate),
        wire,
        sealed: None,
    })
}

/// The handoff of `answer`, the reply to payment `id`, with QR frames when `qr`.
pub(super) fn answer_handoff(id: &str, answer: SealedAnswer, qr: bool) -> Handoff {
    let (format, text, file_name) = match answer {
        SealedAnswer::Sealed(text) if lepic_wallet_contacts::is_epictx(&text) => {
            ("epictx", text, format!("{id}-reply.epictx"))
        }
        SealedAnswer::Sealed(text) => ("sealed", text, format!("{id}.epicsealed.response")),
        SealedAnswer::Plain(wire) => (
            "slate",
            wire.as_text().unwrap_or_default().to_owned(),
            format!("{id}.slate.response"),
        ),
    };
    with_frames(
        Handoff {
            format: format.to_owned(),
            text,
            file_name: Some(file_name),
            qr_frames: None,
        },
        qr,
    )
}

/// The handoff of `reply`, the answer to the plain slate `incoming` of payment `id`: sealed to
/// the reply key its LEPIC marker carries, as `answer_wire` does for the CLI, else plain.
pub(super) fn plain_answer_handoff<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    incoming: &WireSlate,
    reply: &WireSlate,
    qr: bool,
) -> Result<Handoff, Problem> {
    let sealed = service
        .held
        .wallet
        .contact_book()
        .sealed_answer_to_marker(incoming, reply)
        .map_err(CliError::from)?;
    let answer = match sealed {
        Some(text) => SealedAnswer::Sealed(text),
        None => SealedAnswer::Plain(reply.clone()),
    };
    Ok(answer_handoff(id, answer, qr))
}

/// `handoff` with QR frames added when `qr` asks for them and it has none.
fn with_frames(mut handoff: Handoff, qr: bool) -> Handoff {
    if qr && handoff.qr_frames.is_none() {
        handoff.qr_frames = encode_ur_slate(&handoff.text, MAX_FRAGMENT_LEN).ok();
    }
    handoff
}

/// The answer to a received payment: on a repeat the handoff stored the first time, with QR
/// frames added to this answer only; else `made`, stored as the payment's handoff.
fn keep_handoff<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    repeated: bool,
    qr: bool,
    made: impl FnOnce() -> Handoff,
) -> Result<Handoff, Problem> {
    let mut note = view::note(service, id)?;
    if repeated && let Some(stored) = note.handoff {
        return Ok(with_frames(stored, qr));
    }
    let handoff = made();
    note.handoff = Some(handoff.clone());
    view::put_note(service, id, &note)?;
    Ok(handoff)
}

/// The first message a participant wrote in `slate`.
fn message_of(slate: &Slate) -> Option<String> {
    slate
        .participants()
        .find_map(|(_, participant)| participant.message.as_ref())
        .map(|message| message.text().to_owned())
}

pub(super) async fn inspect<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    request.require(Role::Read)?;
    let body: Handed = request.json()?;
    let (text, _) = body.content()?;
    ok(&read(service, &text).await?.inspection)
}

pub(super) async fn open<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    request.require(Role::Receive)?;
    let body: Handed = request.json()?;
    let (text, form) = body.content()?;
    let read = read(service, &text).await?;
    if !body.expect.is_empty() && !body.expect.contains(&read.inspection.kind) {
        return Err(Problem::unexpected_input(format!(
            "this is a {}, which expect does not name",
            read.inspection.kind
        )));
    }
    if let Some(Sealed::Closed(reason)) = &read.sealed {
        return Err(Problem::conflict(
            "nothing_to_open",
            format!("this sealed file does not open with this wallet's keys: {reason}"),
        ));
    }
    let stage = read.slate.as_ref().map(Slate::stage);
    match stage {
        Some(Stage::S1) if read.sealed.is_some() => {
            receive_sealed(service, &text, form, body.message).await
        }
        Some(Stage::S1) => receive(service, read, form, body.message).await,
        Some(Stage::I1) => park(service, read, text).await,
        Some(Stage::S2 | Stage::I2) => {
            request.require(Role::Full)?;
            finish(service, read).await
        }
        Some(Stage::S3 | Stage::I3) => Err(Problem::conflict(
            "nothing_to_open",
            "this payment is already finished",
        )),
        None => Err(Problem::conflict(
            "nothing_to_open",
            match read.inspection.kind.as_str() {
                "unknown" => "this is not a slate or an address this wallet reads".to_owned(),
                kind => format!("a {kind} is paid with POST /payments, not opened"),
            },
        )),
    }
}

/// Receives a send slate and hands back its answer.
async fn receive<H: Host>(
    service: &Service<'_, H>,
    read: Read,
    form: Form,
    message: Option<String>,
) -> Reply {
    let opened = &*service.held;
    let account = lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned();
    let received = Box::pin(crate::commands::receive_slate(
        opened, &read.wire, account, message,
    ))
    .await?;
    let id = received.slate.id().to_string();
    let qr = form == Form::Qr;
    let made = plain_answer_handoff(service, &id, &read.wire, &received.reply, qr)?;
    let handoff = keep_handoff(service, &id, received.repeated, qr, || made)?;
    received_result(service, &id, received.repeated, handoff).await
}

/// Receives the send slate in sealed `text` as `contact open-sealed` does, and hands back the
/// answer sealed on the channel it came by.
async fn receive_sealed<H: Host>(
    service: &Service<'_, H>,
    text: &str,
    form: Form,
    message: Option<String>,
) -> Reply {
    let request = ReceiveRequest {
        account: Some(lepic_wallet::DEFAULT_ACCOUNT_LABEL.to_owned()),
        message,
        ..ReceiveRequest::default()
    };
    let done = Box::pin(
        service
            .held
            .wallet
            .contact_book()
            .sealed_receive(text, request),
    )
    .await
    .map_err(CliError::from)?;
    let id = done.received.slate.id().to_string();
    let repeated = done.received.repeated;
    let handoff = keep_handoff(service, &id, repeated, form == Form::Qr, || {
        answer_handoff(&id, done.answer, form == Form::Qr)
    })?;
    received_result(service, &id, repeated, handoff).await
}

/// What `open` answers for a received send: `received`, or `already_done` on a repeat.
async fn received_result<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    repeated: bool,
    handoff: Handoff,
) -> Reply {
    if !repeated {
        events::payment(service, id, Change::Created).await;
    }
    let payment = payments::object(service, id).await?;
    ok(&OpenResult {
        outcome: if repeated { "already_done" } else { "received" }.to_owned(),
        payment,
        contact: None,
        handoff: Some(handoff),
    })
}

/// Holds an invoice for approval (D5): nothing is paid until `approve` names its amount.
async fn park<H: Host>(service: &Service<'_, H>, read: Read, text: String) -> Reply {
    let Some(slate) = read.slate else {
        return Err(Problem::usage("this invoice did not decode"));
    };
    let id = slate.id().to_string();
    if let Some(payment) = payments::object(service, &id).await? {
        return ok(&OpenResult {
            outcome: "already_done".to_owned(),
            payment: Some(payment),
            contact: None,
            handoff: None,
        });
    }
    let expires_at_height = slate
        .ttl_cutoff_height()
        .map(lepic_primitives::amount::Height::value);
    if view::held_expired(service, expires_at_height)? {
        return Err(Problem::of(
            Category::Rejected,
            "payment_expired",
            "this invoice expired: ask the payee for a new one",
        ));
    }
    if view::live_held(service)?.len() >= service.host.max_held_invoices() {
        return Err(Problem::conflict(
            "too_many_held",
            "too many invoices wait for approval; approve or decline one first",
        ));
    }
    let (sealed, contact_id) = match read.sealed {
        Some(Sealed::Opened { contact_id }) => (true, contact_id),
        _ => (false, None),
    };
    let held = view::Held {
        wire: text,
        sealed,
        contact_id,
        amount: slate.amount().value(),
        message: message_of(&slate),
        expires_at_height,
        received_at: jiff::Timestamp::now().to_string(),
    };
    view::put_held(service, &id, &held)?;
    events::payment(service, &id, Change::Created).await;
    let payment = payments::object(service, &id).await?;
    ok(&OpenResult {
        outcome: "invoice_parked".to_owned(),
        payment,
        contact: None,
        handoff: None,
    })
}

/// Finishes one of this wallet's payments with the answer it was handed, and posts it.
async fn finish<H: Host>(service: &Service<'_, H>, read: Read) -> Reply {
    let id = read.slate.as_ref().map(|slate| slate.id().to_string());
    let before = match &id {
        Some(id) => payments::object(service, id).await?,
        None => None,
    };
    if let Some(payment) = before
        .filter(|payment| matches!(payment.state.as_str(), "finalized" | "posted" | "confirmed"))
    {
        return ok(&OpenResult {
            outcome: "already_done".to_owned(),
            payment: Some(payment),
            contact: None,
            handoff: None,
        });
    }
    let report = Box::pin(crate::commands::finalize_slate(
        &service.held,
        &read.wire,
        false,
    ))
    .await
    .map_err(Problem::from)?;
    let Report::Finalize(finalized) = report else {
        return Err(Problem::of(
            Category::Internal,
            "internal",
            "the wallet did not report the finalized payment",
        ));
    };
    events::payment(service, &finalized.slate_id, Change::State(None)).await;
    let payment = payments::object(service, &finalized.slate_id).await?;
    ok(&OpenResult {
        outcome: "finished".to_owned(),
        payment,
        contact: None,
        handoff: None,
    })
}
