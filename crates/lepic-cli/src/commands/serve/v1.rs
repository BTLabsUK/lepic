// SPDX-License-Identifier: Apache-2.0
//! The handlers of the wallet API (ADR 0055): one function per operation of
//! `docs/api/openapi.json`, grouped as the document's tags group them. The router has already
//! checked the caller's role, `x-socket-only` and the body's size; a handler checks the rest.
//!
//! Each handler takes the service, the request and the API's shared [`Context`], and answers
//! with a response or a [`Problem`]. A module that owns an object also gives the function that
//! builds it by id, which the event log uses for its snapshots.

mod coins;
mod contacts;
mod events;
mod handed;
mod network;
mod payments;
mod service;
mod wallet;

use hyper::Response;
use serde_json::Value;

use super::Service;
use crate::api::idempotency::{self, Started};
use crate::api::{Answer, Body, Context, Op, Owner, Problem, Request};
use crate::exit::CliError;
use crate::host::Host;

pub(super) use events::{Log, writer as event_writer};
pub(super) use wallet::{Scans, drive as scan_driver};

/// What a handler answers.
type Reply = Result<Response<Body>, Problem>;

impl<H: Host> Owner for Service<'_, H> {
    fn operate<'a>(&'a self, op: Op, request: Request, context: &'a Context) -> Answer<'a> {
        Box::pin(async move {
            let s = self;
            let (r, c) = (request, context);
            match op {
                Op::GetStatus => service::get_status(s, r, c).await,
                Op::GetOpenApi => service::get_open_api(s, r, c).await,
                Op::GetWallet => wallet::get_wallet(s, r, c).await,
                Op::UpdateWallet => wallet::update_wallet(s, r, c).await,
                Op::ChangeWalletPassword => wallet::change_password(s, r, c).await,
                Op::ScanWallet => wallet::scan(s, r, c).await,
                Op::SyncNow => wallet::sync(s, r, c).await,
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
                Op::FinalizePayment => payments::finalize(s, r, c).await,
                Op::DeliverPayment => payments::deliver(s, r, c).await,
                Op::PostPayment => payments::post(s, r, c).await,
                Op::CancelPayment => payments::cancel(s, r, c).await,
                Op::GetPaymentHandoff => payments::handoff(s, r, c).await,
                Op::Inspect => handed::inspect(s, r, c).await,
                Op::Open => handed::open(s, r, c).await,
                Op::ListOutputs => coins::list_outputs(s, r, c).await,
                Op::ListAddresses => coins::list_addresses(s, r, c).await,
                Op::CreateAddress => coins::create_address(s, r, c).await,
                Op::ListLinks => coins::list_links(s, r, c).await,
                Op::CreateLink => coins::create_link(s, r, c).await,
                Op::RetireLink => coins::retire_link(s, r, c).await,
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
                Op::ListPairRequests => contacts::list_pair_requests(s, r, c).await,
                Op::AcceptPairRequest => contacts::accept_pair_request(s, r, c).await,
                Op::DeletePairRequest => contacts::delete_pair_request(s, r, c).await,
                Op::ListPayloads => contacts::list_payloads(s, r, c).await,
                Op::DeletePayload => contacts::delete_payload(s, r, c).await,
                Op::ListQuarantine => contacts::list_quarantine(s, r, c).await,
                Op::RetryQuarantined => contacts::retry_quarantined(s, r, c).await,
                Op::DeleteQuarantined => contacts::delete_quarantined(s, r, c).await,
                Op::GetRelay => network::get_relay(s, r, c).await,
                Op::MoveRelay => network::move_relay(s, r, c).await,
                Op::ListPeers => network::list_peers(s, r, c).await,
                Op::DeletePeer => network::delete_peer(s, r, c).await,
                Op::GetProfile => network::get_profile(s, r, c).await,
                Op::UpdateProfile => network::update_profile(s, r, c).await,
                Op::GetProfileDomainFile => network::domain_file(s, r, c).await,
                Op::ListEvents => events::list(s, r, c).await,
            }
        })
    }
}

/// A create with a caller's id, held as in progress until it drops.
pub(super) struct Create<'c> {
    /// The id was used before with the same body. Answer 200 with the object it names if it
    /// exists; else make it, as the first call did not get that far.
    pub(super) repeat: bool,
    _started: Started<'c>,
}

/// Starts the create `(scope, id)` with the request body `body`. 409 `in_progress` while another
/// call with the id is answered; 409 `idempotency_mismatch` when the id was used with another
/// body. A new id is recorded with the body's digest before the create runs, so a create cut
/// short by a crash is made by the next call with the same body.
pub(super) fn begin<'c, H: Host>(
    service: &Service<'_, H>,
    context: &'c Context,
    scope: &'static str,
    id: &str,
    body: &Value,
) -> Result<Create<'c>, Problem> {
    let started = context.in_progress().start(scope, id)?;
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
