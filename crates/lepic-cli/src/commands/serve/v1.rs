// SPDX-License-Identifier: Apache-2.0
//! The handlers of the wallet API (ADR 0055): one function per operation of
//! `docs/api/openapi.json`, grouped as the document's tags group them. The router has already
//! checked the caller's role, `x-socket-only` and the body's size; a handler checks the rest.
//!
//! Each handler takes the service, the request and the API's shared [`Context`], and answers
//! with a response or a [`Problem`]. A module that owns an object also gives the function that
//! builds it by id, which the event log uses for its snapshots.

mod coins;
mod consolidate;
mod contacts;
mod events;
mod handed;
mod mailboxes;
mod metrics;
mod network;
mod payments;
mod service;
mod wallet;
mod webhook;

use hyper::Response;
use serde_json::Value;

use super::Service;
use crate::api::idempotency::{self, Started};
use crate::api::{Answer, Body, Context, Op, Owner, Problem, Request};
use crate::exit::CliError;
use crate::host::Host;

pub(super) use events::{Log, writer as event_writer};
pub(super) use metrics::Counters;
pub(super) use payments::{CheckoutLocks, Creates, checkout_driver, make_queued, public_routes};
pub(super) use wallet::{Scans, drive as scan_driver};
pub(super) use webhook::drive as webhook_driver;

/// What a handler answers.
type Reply = Result<Response<Body>, Problem>;

/// A slate `message` as the API takes it: at most 256 bytes, with no control, line-break or
/// invisible formatting characters. A longer or marked text is refused, not cut, so the text
/// the caller sees is the text that is signed.
fn check_message(message: Option<&str>) -> Result<(), Problem> {
    let Some(text) = message else {
        return Ok(());
    };
    if text.len() > lepic_wallet::slate::MAX_MESSAGE_LEN {
        return Err(Problem::invalid(
            "/message",
            format!(
                "message is {} bytes; at most {} bytes are signed",
                text.len(),
                lepic_wallet::slate::MAX_MESSAGE_LEN
            ),
        ));
    }
    if lepic_wallet::epicbox_invoice::display_message(text) != text {
        return Err(Problem::invalid(
            "/message",
            "message has a control, line-break or invisible formatting character, which is refused",
        ));
    }
    Ok(())
}

impl<H: Host> Owner for Service<'_, H> {
    fn command_line<'a>(&'a self, request: Request) -> Answer<'a> {
        Box::pin(super::cli::run(self, request))
    }

    fn operate<'a>(&'a self, op: Op, request: Request, context: &'a Context) -> Answer<'a> {
        Box::pin(async move {
            let (reply, fresh) = idempotency::track(self.dispatch(op, request, context)).await;
            if reply.is_ok() && wallet::expects_reply(op) {
                wallet::expect_reply(self);
            }
            // A create that answers an error made nothing: its id can be used again.
            if let (Err(problem), Some((scope, id))) = (&reply, fresh)
                && idempotency::made_nothing(problem)
            {
                let _ = self.held.wallet.delete_api_request(scope, &id);
            }
            reply
        })
    }
}

impl<H: Host> Service<'_, H> {
    async fn dispatch(&self, op: Op, request: Request, context: &Context) -> Reply {
        {
            let s = self;
            let (r, c) = (request, context);
            match op {
                Op::GetStatus => service::get_status(s, r, c).await,
                Op::GetOpenApi => service::get_open_api(s, r, c).await,
                Op::GetMetrics => metrics::get(s, r, c).await,
                Op::GetWallet => wallet::get_wallet(s, r, c).await,
                Op::ChangeWalletPassword => wallet::change_password(s, r, c).await,
                Op::ScanWallet => wallet::scan(s, r, c).await,
                Op::SyncNow => wallet::sync(s, r, c).await,
                Op::BoostSync => wallet::boost(s, r, c).await,
                Op::EndBoost => wallet::end_boost(s, r, c).await,
                Op::ListAccounts => wallet::list_accounts(s, r, c).await,
                Op::CreateAccount => wallet::create_account(s, r, c).await,
                Op::GetNode => wallet::get_node(s, r, c).await,
                Op::ListPayments => payments::list(s, r, c).await,
                Op::CreatePayment => payments::create(s, r, c).await,
                Op::EstimatePayment => payments::estimate(s, r, c).await,
                Op::GetPayment => payments::get(s, r, c).await,
                Op::UpdatePayment => payments::update(s, r, c).await,
                Op::ApprovePayment => payments::approve(s, r, c).await,
                Op::DeclinePayment => payments::decline(s, r, c).await,
                Op::DeliverPayment => payments::deliver(s, r, c).await,
                Op::PostPayment => payments::post(s, r, c).await,
                Op::CancelPayment => payments::cancel(s, r, c).await,
                Op::RecoverPayment => payments::recover(s, r, c).await,
                Op::GetPaymentHandoff => payments::handoff(s, r, c).await,
                Op::Inspect => handed::inspect(s, r, c).await,
                Op::Open => handed::open(s, r, c).await,
                Op::ListOutputs => coins::list_outputs(s, r, c).await,
                Op::ConsolidateOutputs => consolidate::consolidate(s, r, c).await,
                Op::ListAddresses => coins::list_addresses(s, r, c).await,
                Op::CreateLink => coins::create_link(s, r, c).await,
                Op::ListContacts => contacts::list(s, r, c).await,
                Op::CreateContact => contacts::create(s, r, c).await,
                Op::GetContact => contacts::get(s, r, c).await,
                Op::UpdateContact => contacts::update(s, r, c).await,
                Op::DeleteContact => contacts::delete(s, r, c).await,
                Op::VerifyContact => contacts::verify(s, r, c).await,
                Op::CheckContact => contacts::check(s, r, c).await,
                Op::ResolveContactKeys => contacts::resolve_keys(s, r, c).await,
                Op::MoveContact => contacts::move_contact(s, r, c).await,
                Op::SendPayload => contacts::send_payload(s, r, c).await,
                Op::ExportContacts => contacts::export(s, r, c).await,
                Op::ImportContacts => contacts::import(s, r, c).await,
                Op::ListPayloads => contacts::list_payloads(s, r, c).await,
                Op::DeletePayload => contacts::delete_payload(s, r, c).await,
                Op::ListQuarantine => contacts::list_quarantine(s, r, c).await,
                Op::RetryQuarantined => contacts::retry_quarantined(s, r, c).await,
                Op::DeleteQuarantined => contacts::delete_quarantined(s, r, c).await,
                Op::GetRelay => network::get_relay(s, r, c).await,
                Op::MoveRelay => network::move_relay(s, r, c).await,
                Op::ListMailboxes => mailboxes::list(s, r, c).await,
                Op::AddMailbox => mailboxes::add(s, r, c).await,
                Op::ProbeMailbox => mailboxes::probe_one(s, r, c).await,
                Op::RemoveMailbox => mailboxes::remove(s, r, c).await,
                Op::GetProfile => network::get_profile(s, r, c).await,
                Op::UpdateProfile => network::update_profile(s, r, c).await,
                Op::GetProfileDomainFile => network::domain_file(s, r, c).await,
                Op::ListEvents => events::list(s, r, c).await,
                Op::GetWebhook => webhook::get(s, r, c).await,
                Op::ResumeWebhook => webhook::resume(s, r, c).await,
            }
        }
    }
}

/// A create with a caller's id, held as in progress until it drops.
pub(super) struct Create {
    /// The id was used before with the same body. Answer 200 with the object it names if it
    /// exists; else make it, as the first call did not get that far.
    pub(super) repeat: bool,
    _started: Started,
}

/// Starts the create `(scope, id)` with the request body `body`. 409 `in_progress` while another
/// call with the id is answered; 409 `idempotency_mismatch` when the id was used with another
/// body. A new id is recorded with the body's digest before the create runs, so a create cut
/// short by a crash is made by the next call with the same body; an error answer that made
/// nothing removes the record again.
pub(super) fn begin<H: Host>(
    service: &Service<'_, H>,
    context: &Context,
    scope: &'static str,
    id: &str,
    body: &Value,
) -> Result<Create, Problem> {
    let started = context.in_progress().start(scope, id)?;
    let create = record(service, started, scope, id, body)?;
    if !create.repeat {
        idempotency::note_fresh(scope, id);
    }
    Ok(create)
}

/// Records the create `(scope, id)` that `started` holds, as [`begin`] does, without noting the
/// record for the call's answer: the caller removes it when the create made nothing.
pub(super) fn record<H: Host>(
    service: &Service<'_, H>,
    started: Started,
    scope: &'static str,
    id: &str,
    body: &Value,
) -> Result<Create, Problem> {
    let digest = idempotency::digest(body);
    let wallet = &service.held.wallet;
    let recorded = wallet.api_request(scope, id).map_err(CliError::from)?;
    let repeat = match recorded {
        Some(recorded) if recorded.digest != digest => {
            return Err(Problem::idempotency_mismatch());
        }
        Some(_) => true,
        None => {
            wallet
                .put_api_request(scope, id, digest)
                .map_err(CliError::from)?;
            false
        }
    };
    Ok(Create {
        repeat,
        _started: started,
    })
}
