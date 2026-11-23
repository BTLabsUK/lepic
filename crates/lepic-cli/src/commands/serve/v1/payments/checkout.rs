// SPDX-License-Identifier: Apache-2.0
//! In-person payment requests: `POST /payments` with `kind: invoice, via: in_person`, the
//! `request` object of their payments, the answer the shop finalizes by hand (`post`) and the
//! driver that finalizes the first answer when the shop asked for that.
//!
//! A request keeps its own note beside the payment's ([`RequestNote`]), changed under one lock
//! so the driver, `post`, `cancel` and refusals never write over each other. The answer the
//! wallet finalized is the only one the request names: serve notes the answer it is about to
//! finalize apart from it ([`RequestNote::attempt`]), so a restart before the wallet finalized
//! finalizes that same answer again, and a different answer is refused once one is finalized.
//! Serve finalizes one answer at a time and keeps the attempt once the payment is paid: the
//! wallet names the answer it finalized only after the push, and until then the attempt is
//! that answer.

use std::convert::Infallible;
use std::time::Duration;

use hyper::StatusCode;
use lepic_node::{NodeApi as _, Propagation};
use lepic_store::{AccountIndex, TxState};
use lepic_transport::host_rule::{HostClass, classify_name};
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::event::{Event as EngineEvent, SlateId};
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::slate::ur_slate::{BINARY_FRAGMENT_LEN, encode_ur_binary};
use lepic_wallet_contacts::{
    ClaimSigner, ContactError, InPersonCodeView, InPersonInvoiceRequest, InPersonRefusal, MethodId,
    RouteEntry, WalletContacts as _, invoice_link, request_claim,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::time::MissedTickBehavior;

use super::super::super::Service;
use super::super::Reply;
use super::super::contacts;
use super::super::events::{self, Change};
use super::view::{self, Note};
use crate::amount::parse_amount;
use crate::api::model::{Answer, Handoff, Payment, PaymentRequest};
use crate::api::{Category, Problem, created};
use crate::exit::CliError;
use crate::host::Host;

/// The settings key prefix of a request serve still watches: one with `finalize: first` that
/// waits for its answer, or any request whose answers are not kept in its note yet.
const OPEN: &str = "api.request.open.";
/// The settings key prefix of a request's [`RequestNote`].
const REQUEST: &str = "api.request.note.";
/// The locks one serve holds over its checkout requests.
#[derive(Default)]
pub(in crate::commands::serve) struct Locks {
    /// Held while a request's note is read, changed and written.
    notes: tokio::sync::Mutex<()>,
    /// Held while serve finalizes an answer, from noting the attempt to settling the note:
    /// the attempt noted when a payment turns paid is the answer that paid it.
    finalizing: tokio::sync::Mutex<()>,
}
/// How often the driver looks at the open requests without an event: answers taken while it
/// was busy, and requests that ended.
const LOOK_EVERY: Duration = Duration::from_secs(30);

/// `finalize: first`: serve finalizes the first answer that checks.
pub(super) const FIRST: &str = "first";
/// `finalize: manual`: the shop picks the answer with `post`.
pub(super) const MANUAL: &str = "manual";

/// What serve keeps about a request beside the payment's note. Never sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in super::super) struct RequestNote {
    /// [`FIRST`] or [`MANUAL`].
    pub(in super::super) finalize: String,
    /// Whether the code names this serve's direct routes.
    #[serde(default)]
    pub(in super::super) direct: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) domain: Option<String>,
    /// The height from which the code is refused.
    #[serde(default)]
    pub(in super::super) ttl_cutoff: u64,
    /// The answer the wallet finalized, as it last said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) answer: Option<u32>,
    /// The answer serve last asked the wallet to finalize, written before it does and kept
    /// once the payment is paid. The request's answer only while its payment is paid and the
    /// wallet has not named one ([`paid_answer`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) attempt: Option<u32>,
    /// The check code of the finalized answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) reference: Option<String>,
    #[serde(default)]
    pub(in super::super) answers_refused: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) last_refusal: Option<String>,
    /// The answers as last read: the wallet forgets a code once its payment ends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) answers: Vec<Answer>,
    /// The shop cancelled the request.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(in super::super) cancelled: bool,
    /// The request's TTL passed while it waited for an answer, and the event saying so went out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(in super::super) expired: bool,
}

/// A request to issue, checked by the create.
pub(super) struct Issue {
    pub(super) id: Option<String>,
    /// The slate id `id` settles to.
    pub(super) slate_id: Option<String>,
    pub(super) account: String,
    pub(super) amount: String,
    pub(super) message: Option<String>,
    pub(super) ttl_blocks: Option<u64>,
    pub(super) finalize: String,
    pub(super) direct: bool,
    pub(super) note: Note,
}

/// `finalize` as the body gives it: [`MANUAL`] when left out, else 400 at `/finalize`.
pub(super) fn finalize_mode(finalize: Option<&str>) -> Result<String, Problem> {
    match finalize {
        None | Some(MANUAL) => Ok(MANUAL.to_owned()),
        Some(FIRST) => Ok(FIRST.to_owned()),
        Some(other) => Err(Problem::invalid(
            "/finalize",
            format!("finalize: {other} is not first or manual"),
        )),
    }
}

/// `direct` as the body gives it: when left out, whether serve has public addresses. 400 at
/// `/direct` for `true` without one.
pub(super) fn direct_mode<H: Host>(
    service: &Service<'_, H>,
    direct: Option<bool>,
) -> Result<bool, Problem> {
    let routes = !service.public_routes.is_empty();
    match direct {
        None => Ok(routes),
        Some(true) if !routes => Err(Problem::invalid(
            "/direct",
            "direct needs a public address: serve was started without --public-url",
        )),
        Some(direct) => Ok(direct),
    }
}

/// Issues the request `issue` asks for and answers 201 with its payment, whose handoff is the
/// code to show. 503 `node_unreachable` when the node does not answer: the code's TTL counts
/// from the chain tip.
pub(super) async fn make<H: Host>(service: &Service<'_, H>, issue: Issue) -> Reply {
    if let Err(error) = tip(service).await {
        return Err(Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            Category::Node,
            "node_unreachable",
            error.chain().join(": "),
        ));
    }
    let account = service
        .held
        .wallet
        .account(&issue.account)
        .map_err(CliError::from)?
        .index;
    let request = invoice_request(service, &issue, account)?;
    let code = service
        .held
        .wallet
        .contact_book()
        .in_person_invoice(&contacts::relays(service), request)
        .await
        .map_err(issue_problem)?;
    let slate_id = code.slate_id.to_string();
    if let Some(id) = issue.id.as_deref().filter(|id| *id != slate_id) {
        view::put_alias(service, id, &slate_id)?;
    }
    let link = invoice_link(&code.bytes);
    let handoff = Handoff {
        format: "in_person_code".to_owned(),
        text: crate::commands::contact::to_hex(&code.bytes),
        file_name: None,
        qr_frames: encode_ur_binary(&code.bytes, BINARY_FRAGMENT_LEN).ok(),
        link: Some(link.clone()),
    };
    let mut note = issue.note;
    note.handoff = Some(handoff.clone());
    let request = RequestNote {
        finalize: issue.finalize,
        direct: issue.direct,
        link: Some(link),
        domain: request_claim(&code.bytes).map(|claim| claim.domain.to_string()),
        ttl_cutoff: code.ttl_cutoff,
        ..RequestNote::default()
    };
    // A repeat issued the stored code: what the request has seen since stays.
    change(service, &slate_id, |stored| {
        if stored.is_none() {
            *stored = Some(request);
        }
        true
    })
    .await?;
    view::put_note(service, &slate_id, &note)?;
    view::put_setting(service, &format!("{OPEN}{slate_id}"), "")?;
    // The push sessions read the reply slot only once it is watched: watch it now, so an
    // answer is pushed instead of waiting for the next open.
    service.held.pairing_claims.add();
    events::payment(service, &slate_id, Change::Created).await;
    let mut payment = super::object(service, &slate_id)
        .await?
        .ok_or_else(|| super::unknown(&slate_id))?;
    payment.handoff = Some(handoff);
    created(&payment)
}

/// What the wallet is asked to issue: signed for the `domain` setting when there is one,
/// naming serve's public addresses when `direct`, answered to the account's shared slot.
fn invoice_request<H: Host>(
    service: &Service<'_, H>,
    issue: &Issue,
    account: AccountIndex,
) -> Result<InPersonInvoiceRequest, Problem> {
    let slate_id = match issue.slate_id.as_deref() {
        Some(id) => Some(SlateId::parse(id).map_err(|_| CliError::SlateId)?),
        None => None,
    };
    Ok(InPersonInvoiceRequest {
        account,
        amount: parse_amount(&issue.amount)
            .map_err(|error| Problem::invalid("/amount", format!("amount: {error}")))?,
        message: issue.message.clone(),
        ttl_blocks: issue.ttl_blocks,
        slate_id,
        direct: if issue.direct {
            service.public_routes.clone()
        } else {
            Vec::new()
        },
        claim: service
            .settings
            .domain
            .clone()
            .map(|domain| ClaimSigner { domain }),
        shared_slot: true,
    })
}

/// The problem a refused issue is: 400 at `/ttl_blocks` for a TTL too short to pay in, and
/// 409 `idempotency_mismatch` for an id whose request was issued before with another account,
/// amount or message.
fn issue_problem(error: ContactError) -> Problem {
    match error {
        ContactError::InPerson(refusal @ InPersonRefusal::TtlTooShort { .. }) => {
            Problem::invalid("/ttl_blocks", format!("ttl_blocks: {refusal}"))
        }
        ContactError::InPerson(InPersonRefusal::RepeatDiffers) => Problem::idempotency_mismatch(),
        error => Problem::from(CliError::from(error)),
    }
}

async fn tip<H: Host>(service: &Service<'_, H>) -> Result<u64, CliError> {
    let node = service.host.node(service.settings)?;
    Ok(node.get_tip().await?.height.value())
}

/// Fills in what `note` keeps about the request of `payment`: its `request` object, its
/// answers and the `post` action of a manual request that has answers. `tip` is the wallet's
/// last known tip.
pub(in super::super) async fn fill<H: Host>(
    service: &Service<'_, H>,
    details: &TransactionDetails,
    payment: &mut Payment,
    note: &RequestNote,
    tip: Option<u64>,
) {
    payment.via = "in_person".to_owned();
    payment.delivery = None;
    let live = match SlateId::parse(&payment.id) {
        Ok(slate) => service
            .held
            .wallet
            .contact_book()
            .in_person_answers(slate)
            .await
            .ok(),
        Err(_) => None,
    };
    let answers = live
        .as_ref()
        .map_or_else(|| note.answers.clone(), answers_of);
    let state = request_state(details.transaction.entry.state, note, tip);
    let finalized = paid_answer(live.as_ref(), note, state == "paid");
    let reference = finalized
        .filter(|_| state == "paid")
        .and_then(|number| check_code(&answers, number))
        .or_else(|| note.reference.clone().filter(|_| state == "paid"));
    if state == "open" && note.finalize == MANUAL && !answers.is_empty() {
        if !payment.actions.iter().any(|action| action == "post") {
            payment.actions.insert(0, "post".to_owned());
        }
    } else {
        payment
            .actions
            .retain(|action| action != "post" || state == "paid");
    }
    payment.check_code.clone_from(&reference);
    payment.answers = answers;
    payment.request = Some(PaymentRequest {
        state: state.to_owned(),
        reference,
        link: note.link.clone(),
        domain: note.domain.clone(),
        finalize: note.finalize.clone(),
        answers_refused: note.answers_refused,
        last_refusal: note.last_refusal.clone(),
    });
}

/// The request's state from its transaction's: `open` until an answer is finalized, its TTL
/// passes or it ends; `refused` when the shop cancelled it.
fn request_state(state: TxState, note: &RequestNote, tip: Option<u64>) -> &'static str {
    match state {
        TxState::Finalized | TxState::Posted | TxState::Confirmed => "paid",
        TxState::Cancelled if note.cancelled => "refused",
        TxState::Cancelled | TxState::Expired => "expired",
        TxState::Sent | TxState::Received => match tip {
            Some(tip) if tip >= note.ttl_cutoff => "expired",
            _ => "open",
        },
    }
}

/// The answers of `view` as the API shows them, each with the earlier one of the same check
/// code.
fn answers_of(view: &InPersonCodeView) -> Vec<Answer> {
    let mut shown: Vec<Answer> = Vec::with_capacity(view.answers.len());
    for answer in &view.answers {
        let same_code_as = shown
            .iter()
            .find(|earlier| earlier.check_code == answer.check_code)
            .map(|earlier| earlier.id.clone());
        shown.push(Answer {
            id: answer.number.to_string(),
            check_code: answer.check_code.clone(),
            received_at: answer.received_at.to_string(),
            same_code_as,
        });
    }
    shown
}

fn check_code(answers: &[Answer], number: u32) -> Option<String> {
    let id = number.to_string();
    answers
        .iter()
        .find(|answer| answer.id == id)
        .map(|answer| answer.check_code.clone())
}

/// The answer `post` finalizes: `chosen`, an answer id or a check code; with none, the only
/// answer. 400 at `/answer` when it names none of them or none is chosen among several, 409
/// `ambiguous_answer` for a check code two answers share.
pub(super) fn chosen_answer(answers: &[Answer], chosen: Option<&str>) -> Result<u32, Problem> {
    let number = |answer: &Answer| answer.id.parse::<u32>().ok();
    let Some(chosen) = chosen.map(str::trim) else {
        return match answers {
            [only] => number(only).ok_or_else(|| Problem::invalid("/answer", "answer is unknown")),
            [] => Err(Problem::conflict(
                "action_not_available",
                "the request has no answer to finalize yet",
            )),
            _ => Err(Problem::invalid(
                "/answer",
                "answer is required: the request has more than one",
            )),
        };
    };
    if let Some(found) = answers.iter().find(|answer| answer.id == chosen) {
        return number(found).ok_or_else(|| Problem::invalid("/answer", "answer is unknown"));
    }
    let wanted = chosen.to_ascii_uppercase();
    let mut matching = answers
        .iter()
        .filter(|answer| answer.check_code.to_ascii_uppercase() == wanted);
    match (matching.next(), matching.next()) {
        (Some(found), None) => {
            number(found).ok_or_else(|| Problem::invalid("/answer", "answer is unknown"))
        }
        (Some(_), Some(_)) => Err(Problem::conflict(
            "ambiguous_answer",
            "two answers have this check code: name the answer by its id",
        )
        .with_param("/answer")),
        (None, _) => Err(Problem::invalid(
            "/answer",
            format!("answer: {chosen} is not an answer of this request"),
        )),
    }
}

/// The answer request `note` was paid with: the wallet's, from `live` or as the note last kept
/// it (the wallet forgets a code once its payment is confirmed), else, while the payment is
/// `paid`, serve's attempt. The wallet names its answer only after the push, and serve
/// finalizes one answer at a time ([`Locks::finalizing`]), so a paid payment's attempt is the answer
/// that paid it.
fn paid_answer(live: Option<&InPersonCodeView>, note: &RequestNote, paid: bool) -> Option<u32> {
    live.and_then(|view| view.finalized)
        .or(note.answer)
        .or(note.attempt.filter(|_| paid))
}

/// Finalizes answer `answer` of the request `slate` and posts it with `propagation`, after
/// noting the attempt, so a restart before the wallet finalized finalizes the same answer. A
/// post the node did not take yet is left to the wallet's retries; the answer finalized before
/// is taken as it is. 409 `invoice_already_paid` when the wallet finalized another answer:
/// the note stays as it was.
pub(super) async fn finalize<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
    answer: u32,
    propagation: Propagation,
) -> Result<(), Problem> {
    let slate_id = SlateId::parse(slate).map_err(|_| CliError::SlateId)?;
    let _one = service.checkout.finalizing.lock().await;
    let book = service.held.wallet.contact_book();
    let live = book.in_person_answers(slate_id).await.ok();
    let Some(note) = request_note(service, slate)? else {
        return Err(super::unknown(slate));
    };
    let paid = matches!(
        tx_state(service, slate).await?,
        Some(TxState::Finalized | TxState::Posted | TxState::Confirmed)
    );
    match paid_answer(live.as_ref(), &note, paid) {
        Some(finalized) if finalized != answer => {
            settle(service, slate, slate_id).await?;
            return Err(paid_by_another(slate));
        }
        Some(_) if live.is_none() => return Ok(()),
        _ => {}
    }
    // Once the payment is paid the attempt names the answer that paid it.
    if !paid {
        change(service, slate, |request| match request {
            Some(request) if request.attempt != Some(answer) => {
                request.attempt = Some(answer);
                true
            }
            _ => false,
        })
        .await?;
    }
    match book.in_person_finalize(slate_id, answer, propagation).await {
        Ok(_) | Err(ContactError::Invoice(InvoiceError::NotPosted { .. })) => {}
        Err(ContactError::Invoice(InvoiceError::AlreadyFinalized { .. })) => {
            settle(service, slate, slate_id).await?;
            return Err(paid_by_another(slate));
        }
        Err(error) => return Err(Problem::from(CliError::from(error)).with_payment(slate)),
    }
    settle(service, slate, slate_id).await?;
    Ok(())
}

/// 409 `invoice_already_paid`: another answer to request `slate` was finalized.
fn paid_by_another(slate: &str) -> Problem {
    Problem::conflict(
        "invoice_already_paid",
        "another answer to this request was finalized",
    )
    .with_payment(slate)
}

/// Keeps the answers of request `slate` and, once its payment is past its answer, the
/// reference, in its note, and stops watching it. `true` when the note changed.
async fn settle<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
    slate_id: SlateId,
) -> Result<bool, CliError> {
    if request_note(service, slate)?.is_none() {
        view::delete_setting(service, &format!("{OPEN}{slate}"))?;
        return Ok(false);
    }
    let live = service
        .held
        .wallet
        .contact_book()
        .in_person_answers(slate_id)
        .await
        .ok();
    let state = tx_state(service, slate).await?;
    let past_answer = state.is_none_or(|state| !matches!(state, TxState::Sent | TxState::Received));
    let paid = matches!(
        state,
        Some(TxState::Finalized | TxState::Posted | TxState::Confirmed)
    );
    let changed = change(service, slate, |request| {
        let Some(request) = request else {
            return false;
        };
        let mut changed = false;
        if let Some(live) = &live {
            let answers = answers_of(live);
            if answers != request.answers {
                request.answers = answers;
                changed = true;
            }
            if live.finalized.is_some() && request.answer != live.finalized {
                request.answer = live.finalized;
                changed = true;
            }
        }
        if past_answer
            && paid
            && let Some(number) = request.answer.or(request.attempt)
            && let Some(reference) = check_code(&request.answers, number)
            && request.reference.as_ref() != Some(&reference)
        {
            request.reference = Some(reference);
            changed = true;
        }
        changed
    })
    .await?;
    if past_answer {
        view::delete_setting(service, &format!("{OPEN}{slate}"))?;
    }
    Ok(changed)
}

async fn tx_state<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
) -> Result<Option<TxState>, CliError> {
    Ok(view::Book::of(service, slate).await?.and_then(|book| {
        book.find(slate)
            .map(|details| details.transaction.entry.state)
    }))
}

/// Marks request `slate` as cancelled by the shop, once its payment is.
pub(super) async fn mark_cancelled<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
) -> Result<(), CliError> {
    change(service, slate, |request| match request {
        Some(request) if !request.cancelled => {
            request.cancelled = true;
            true
        }
        _ => false,
    })
    .await?;
    Ok(())
}

/// Takes the shop's cancel mark off request `slate` again, when the cancel failed.
pub(super) async fn unmark_cancelled<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
) -> Result<(), CliError> {
    change(service, slate, |request| match request {
        Some(request) if request.cancelled => {
            request.cancelled = false;
            true
        }
        _ => false,
    })
    .await?;
    Ok(())
}

/// Counts an answer to request `slate` the wallet refused for good, with its reason. The
/// request's state stays as it was.
async fn count_refusal<H: Host>(service: &Service<'_, H>, slate: &str, reason: &str) {
    let counted = change(service, slate, |request| {
        let Some(request) = request else {
            return false;
        };
        request.answers_refused = request.answers_refused.saturating_add(1);
        request.last_refusal = Some(reason.to_owned());
        true
    })
    .await;
    match counted {
        Ok(true) => events::payment(service, slate, Change::Updated(&["request"])).await,
        Ok(false) => {}
        Err(error) => tracing::warn!(
            error = %error,
            slate_id = slate,
            "a refused answer to a payment request was not counted"
        ),
    }
}

/// The note of request `slate`; `None` when the payment is no request.
pub(in super::super) fn request_note<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
) -> Result<Option<RequestNote>, CliError> {
    Ok(view::setting(service, &format!("{REQUEST}{slate}"))?
        .and_then(|text| serde_json::from_str(&text).ok()))
}

/// Runs `edit` on the note of request `slate` under [`Locks::notes`] and writes the note when `edit`
/// says it changed it. Returns what `edit` returned.
async fn change<H: Host>(
    service: &Service<'_, H>,
    slate: &str,
    edit: impl FnOnce(&mut Option<RequestNote>) -> bool,
) -> Result<bool, CliError> {
    let _held = service.checkout.notes.lock().await;
    let mut note = request_note(service, slate)?;
    let changed = edit(&mut note);
    if changed && let Some(note) = &note {
        let text = serde_json::to_string(note)
            .map_err(|error| CliError::io("a payment request")(error.into()))?;
        view::put_setting(service, &format!("{REQUEST}{slate}"), &text)?;
    }
    Ok(changed)
}

/// Watches the open requests: keeps their answers in their notes, finalizes the first answer
/// of a `finalize: first` request, says once that a request's TTL passed, and stops watching a
/// request once its payment is past its answer. Looks at every open request when it starts,
/// after missed events, when a sync reaches a new tip and every [`LOOK_EVERY`]; at one request
/// when an answer to it arrives.
pub(in crate::commands::serve) async fn driver<H: Host>(service: &Service<'_, H>) -> Infallible {
    let mut events = service.held.wallet.subscribe();
    let mut look = tokio::time::interval(LOOK_EVERY);
    look.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut synced_to = None;
    loop {
        tokio::select! {
            _ = look.tick() => look_at_all(service).await,
            event = events.recv() => match event {
                Ok(EngineEvent::InPersonAnswer(answer)) => {
                    look_at(service, &answer.slate_id.to_string()).await;
                }
                Ok(EngineEvent::Sync(progress))
                    if progress.height == progress.target && synced_to != Some(progress.height) =>
                {
                    synced_to = Some(progress.height);
                    look_at_all(service).await;
                }
                Ok(EngineEvent::InPersonAnswerRefused(refused)) => {
                    count_refusal(service, &refused.slate_id.to_string(), refused.reason).await;
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => look_at_all(service).await,
                Err(broadcast::error::RecvError::Closed) => {
                    match std::future::pending::<Infallible>().await {}
                }
            },
        }
    }
}

async fn look_at_all<H: Host>(service: &Service<'_, H>) {
    let open = match view::settings_with_prefix(service, OPEN) {
        Ok(open) => open,
        Err(error) => {
            tracing::warn!(error = %error, "the open payment requests were not read");
            return;
        }
    };
    for (key, _) in open {
        if let Some(slate) = key.strip_prefix(OPEN) {
            look_at(service, slate).await;
        }
    }
}

/// One look at request `slate`; a failure is logged and tried again on the next look.
async fn look_at<H: Host>(service: &Service<'_, H>, slate: &str) {
    if let Err(problem) = step(service, slate).await {
        tracing::warn!(
            code = problem.code(),
            slate_id = slate,
            "a payment request was not finalized"
        );
    }
}

async fn step<H: Host>(service: &Service<'_, H>, slate: &str) -> Result<(), Problem> {
    let Ok(slate_id) = SlateId::parse(slate) else {
        view::delete_setting(service, &format!("{OPEN}{slate}"))?;
        return Ok(());
    };
    if view::setting(service, &format!("{OPEN}{slate}"))?.is_none() {
        return Ok(());
    }
    let changed = settle(service, slate, slate_id).await?;
    let Some(request) = request_note(service, slate)? else {
        return Ok(());
    };
    let state = tx_state(service, slate).await?;
    let waiting = matches!(state, Some(TxState::Sent | TxState::Received));
    if let Some(state) = state.filter(|_| waiting)
        && request_state(state, &request, view::known_tip(service)?) == "expired"
    {
        // The payment stays as it is until the wallet ends it, and the wallet finalizes no
        // answer past the TTL: say once that the request ended.
        let marked = !request.expired
            && change(service, slate, |request| match request {
                Some(request) if !request.expired => {
                    request.expired = true;
                    true
                }
                _ => false,
            })
            .await?;
        if marked {
            events::payment(service, slate, Change::State(None)).await;
        }
        return Ok(());
    }
    if waiting && request.finalize == FIRST && !request.cancelled {
        let first = request.answer.or(request.attempt).or_else(|| {
            request
                .answers
                .iter()
                .filter_map(|answer| answer.id.parse::<u32>().ok())
                .min()
        });
        if let Some(answer) = first {
            finalize(service, slate, answer, Propagation::Stem).await?;
            events::payment(service, slate, Change::State(None)).await;
            return Ok(());
        }
    }
    if changed {
        events::payment(service, slate, Change::Updated(&["answers", "request"])).await;
    }
    Ok(())
}

/// The direct routes the payer may post its answer to, from serve's `--public-url` values: an
/// onion host is a `tor` entry, any other https host an `http` entry. A loopback or
/// local-network host is refused, as the payer refuses it.
pub(in crate::commands::serve) fn public_routes(
    urls: &[String],
) -> Result<Vec<RouteEntry>, CliError> {
    urls.iter()
        .flat_map(|urls| urls.split(','))
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(public_route)
        .collect()
}

fn public_route(url: &str) -> Result<RouteEntry, CliError> {
    let refuse = |why: &str| CliError::Arguments(format!("--public-url {url}: {why}"));
    let lower = url.to_ascii_lowercase();
    let (secure, rest) = if let Some(rest) = lower.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(refuse("the address starts with https://"));
    };
    if rest.contains(['?', '#', '@']) {
        return Err(refuse("the address has no user, query or fragment"));
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if !path.is_empty() {
        return Err(refuse("the address has no path"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || authority.starts_with('[') => {
            let port: u16 = port
                .parse()
                .map_err(|_| refuse("the port is not a number"))?;
            (host, Some(port))
        }
        _ => (authority, None),
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return Err(refuse("the address names no host"));
    }
    let onion = host.ends_with(".onion");
    if !secure && !onion {
        return Err(refuse("only an onion address goes over plain http://"));
    }
    match classify_name(host) {
        Ok(HostClass::Public) => {}
        Ok(HostClass::LocalNetwork) => {
            return Err(refuse("a local-network host, which payers refuse"));
        }
        Err(_) => return Err(refuse("a loopback host, which payers refuse")),
    }
    let (method, default_port) = if onion {
        (MethodId::Tor, 80)
    } else {
        (MethodId::Http, 443)
    };
    let value = match port {
        Some(port) if port != default_port => format!("{host}:{port}"),
        _ => host.to_owned(),
    };
    let entry = RouteEntry { method, value };
    if entry.direct_host_port().is_none() {
        return Err(refuse("the host is not one a payer posts to"));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    fn routes(urls: &[&str]) -> Result<Vec<RouteEntry>, CliError> {
        public_routes(&urls.iter().map(|url| (*url).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn an_https_host_is_an_http_entry_and_an_onion_a_tor_entry() {
        let found = routes(&[
            "https://Pay.Example.com/",
            &format!("http://{ONION}"),
            "https://pay.example.com:8443",
        ])
        .unwrap();
        let shown: Vec<_> = found
            .iter()
            .map(|entry| (entry.method, entry.value.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                (MethodId::Http, "pay.example.com"),
                (MethodId::Tor, ONION),
                (MethodId::Http, "pay.example.com:8443"),
            ]
        );
    }

    #[test]
    fn a_hyphenated_host_is_an_http_entry() {
        let found = routes(&[
            "https://Shop-Demo.example.com",
            "https://pay-shop.example:8443",
        ])
        .unwrap();
        let shown: Vec<_> = found.iter().map(|entry| entry.value.as_str()).collect();
        assert_eq!(shown, ["shop-demo.example.com", "pay-shop.example:8443"]);
        assert_eq!(
            found[0].direct_host_port(),
            Some(("shop-demo.example.com".to_owned(), 443))
        );
    }

    #[test]
    fn the_environment_form_splits_on_commas() {
        let found = routes(&[&format!("https://pay.example.com, https://{ONION}:81")]).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].value, format!("{ONION}:81"));
    }

    #[test]
    fn hosts_a_payer_refuses_are_refused_at_startup() {
        for url in [
            "https://localhost",
            "https://127.0.0.1",
            "https://[::1]:8443",
            "https://192.168.1.10",
            "https://10.0.0.2",
            "http://pay.example.com",
            "pay.example.com",
            "https://pay.example.com/shop",
            "https://user@pay.example.com",
            "https://pay.example.com?x=1",
            "https://pay.example.com:port",
            "https://-shop.example.com",
            "https://shop-.example.com",
        ] {
            assert!(
                matches!(routes(&[url]), Err(CliError::Arguments(_))),
                "{url} was taken"
            );
        }
    }

    #[test]
    fn no_address_is_no_route() {
        assert!(routes(&[]).unwrap().is_empty());
        assert!(routes(&[""]).unwrap().is_empty());
    }

    fn answer(id: u32, code: &str) -> Answer {
        Answer {
            id: id.to_string(),
            check_code: code.to_owned(),
            received_at: String::new(),
            same_code_as: None,
        }
    }

    #[test]
    fn post_takes_the_only_answer_or_the_one_named() {
        let one = [answer(1, "ABCD")];
        assert_eq!(chosen_answer(&one, None).unwrap(), 1);
        let two = [answer(1, "ABCD"), answer(2, "EFGH")];
        assert_eq!(chosen_answer(&two, Some("2")).unwrap(), 2);
        assert_eq!(chosen_answer(&two, Some("efgh")).unwrap(), 2);
        assert_eq!(
            chosen_answer(&two, None).unwrap_err().code(),
            "invalid_field"
        );
        assert_eq!(
            chosen_answer(&two, Some("ZZZZ")).unwrap_err().code(),
            "invalid_field"
        );
        let same = [answer(1, "ABCD"), answer(2, "ABCD")];
        assert_eq!(
            chosen_answer(&same, Some("ABCD")).unwrap_err().code(),
            "ambiguous_answer"
        );
        assert_eq!(
            chosen_answer(&[], None).unwrap_err().code(),
            "action_not_available"
        );
    }

    #[test]
    fn an_attempt_names_the_answer_only_of_a_paid_request_the_wallet_named_none_of() {
        let attempted = RequestNote {
            attempt: Some(2),
            ..RequestNote::default()
        };
        assert_eq!(paid_answer(None, &attempted, false), None);
        assert_eq!(paid_answer(None, &attempted, true), Some(2));
        let finalized = RequestNote {
            answer: Some(1),
            ..attempted
        };
        assert_eq!(paid_answer(None, &finalized, false), Some(1));
        assert_eq!(paid_answer(None, &finalized, true), Some(1));
    }

    #[test]
    fn a_request_is_open_until_its_ttl_and_refused_only_when_the_shop_cancelled() {
        let note = RequestNote {
            ttl_cutoff: 100,
            ..RequestNote::default()
        };
        assert_eq!(request_state(TxState::Received, &note, Some(99)), "open");
        assert_eq!(request_state(TxState::Received, &note, None), "open");
        assert_eq!(
            request_state(TxState::Received, &note, Some(100)),
            "expired"
        );
        assert_eq!(request_state(TxState::Posted, &note, Some(200)), "paid");
        assert_eq!(request_state(TxState::Cancelled, &note, Some(1)), "expired");
        let cancelled = RequestNote {
            cancelled: true,
            ..note
        };
        assert_eq!(
            request_state(TxState::Cancelled, &cancelled, Some(1)),
            "refused"
        );
    }
}
