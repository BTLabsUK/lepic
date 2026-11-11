// SPDX-License-Identifier: Apache-2.0
//! Contacts and pairing: `/contacts`, `/pair-requests`, `/payloads`, `/quarantine`.

use lepic_store::ContactId;

use super::super::Service;
use super::Reply;
use crate::api::model::{Contact, PairRequest, Payload, Quarantined};
use crate::api::{Context, Problem, Request};
use crate::host::Host;

pub(super) async fn list<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn create<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn get<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn update<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn delete<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn verify<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn check<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn resolve_keys<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn move_contact<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn send_payload<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn export<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn import<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn list_pair_requests<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn accept_pair_request<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn delete_pair_request<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn list_payloads<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn delete_payload<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn list_quarantine<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn retry_quarantined<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn delete_quarantined<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

/// The contact `id`, for `GET /contacts/{id}`, `POST /open` and the `contact.*` events; `None` when there is none.
pub(super) async fn object<H: Host>(
    _service: &Service<'_, H>,
    _id: &str,
) -> Result<Option<Contact>, Problem> {
    Err(Problem::not_implemented())
}

/// The pairing request `id`, for the `pair_request.received` event.
pub(super) async fn pair_request_object<H: Host>(
    _service: &Service<'_, H>,
    _id: &str,
) -> Result<Option<PairRequest>, Problem> {
    Err(Problem::not_implemented())
}

/// The payload `id`, for the `payload.received` event.
pub(super) async fn payload_object<H: Host>(
    _service: &Service<'_, H>,
    _id: &str,
) -> Result<Option<Payload>, Problem> {
    Err(Problem::not_implemented())
}

/// The quarantined message `id`, for the `quarantine.added` event.
pub(super) async fn quarantined_object<H: Host>(
    _service: &Service<'_, H>,
    _id: &str,
) -> Result<Option<Quarantined>, Problem> {
    Err(Problem::not_implemented())
}

/// The API's id of the contact `id`: its hex.
pub(super) fn api_id(id: ContactId) -> String {
    id.to_string()
}
