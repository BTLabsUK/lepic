// SPDX-License-Identifier: Apache-2.0
//! Anything a user is handed: `POST /inspect` reads it, `POST /open` acts on it.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_wallet::slate::ur_slate::{MAX_FRAGMENT_LEN, decode_ur_slate, encode_ur_slate};
use lepic_wallet::slate::{MediaType, Slate, Stage, WireSlate};
use serde::Deserialize;

use super::super::Service;
use super::Reply;
use super::events::{self, Change};
use super::payments::{self, view};
use crate::amount::{format_amount, format_fee};
use crate::api::model::{Handoff, Inspection, OpenResult};
use crate::api::{Category, Context, Problem, Request, ok};
use crate::api_clients::Role;
use crate::host::Host;
use crate::output::Report;

/// The body of `POST /inspect` and `POST /open`.
#[derive(Debug, Deserialize)]
struct Handed {
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
    wire: WireSlate,
}

/// What `text` is. Slates are decoded; addresses are recognised by their shape only.
async fn read<H: Host>(service: &Service<'_, H>, text: &str) -> Result<Read, Problem> {
    let wire = WireSlate::text(MediaType::JSON, text.to_owned());
    let plain = |kind: &str, next: &str| Read {
        inspection: Inspection::new(kind, true, next),
        slate: None,
        wire: wire.clone(),
    };
    if matches!(
        lepic_wallet_contacts::payment_file(text.as_bytes()),
        Ok(lepic_wallet_contacts::PaymentFile::Armour)
    ) {
        return Ok(plain("sealed", "open"));
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
    })
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
    let stage = read.slate.as_ref().map(Slate::stage);
    match (read.inspection.kind.as_str(), stage) {
        (_, Some(Stage::S1)) => receive(service, read, form, body.message).await,
        (_, Some(Stage::I1)) => park(service, read, text).await,
        (_, Some(Stage::S2 | Stage::I2)) | ("sealed", None) => {
            request.require(Role::Full)?;
            finish(service, read).await
        }
        (kind, _) => Err(Problem::conflict(
            "nothing_to_open",
            match kind {
                "slate_answer" => "this payment is already finished".to_owned(),
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
    let answer = crate::commands::answer_wire(opened, &read.wire, &received.reply)?;
    let text = answer.as_text().unwrap_or_default().to_owned();
    let qr_frames = if form == Form::Qr {
        encode_ur_slate(&text, MAX_FRAGMENT_LEN).ok()
    } else {
        None
    };
    let handoff = Handoff {
        format: "slate".to_owned(),
        text,
        file_name: Some(format!("{id}.slate.response")),
        qr_frames,
    };
    let mut note = view::note(service, &id)?;
    note.handoff = Some(handoff.clone());
    view::put_note(service, &id, &note)?;
    if !received.repeated {
        events::payment(service, &id, Change::Created).await;
    }
    let payment = payments::object(service, &id).await?;
    ok(&OpenResult {
        outcome: if received.repeated {
            "already_done"
        } else {
            "received"
        }
        .to_owned(),
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
    let held = view::Held {
        wire: text,
        amount: slate.amount().value(),
        message: message_of(&slate),
        expires_at_height: slate
            .ttl_cutoff_height()
            .map(lepic_primitives::amount::Height::value),
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
