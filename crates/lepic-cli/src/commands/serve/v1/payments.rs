// SPDX-License-Identifier: Apache-2.0
//! Payments: `/payments` and the actions on one.

use lepic_store::TxId;

use super::super::Service;
use super::Reply;
use crate::api::model::Payment;
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

pub(super) async fn estimate<H: Host>(
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

pub(super) async fn approve<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn decline<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn finalize<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn deliver<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn post<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn cancel<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn handoff<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

/// The payment with slate id `id`, for `GET /payments/{id}` and the `payment.*` events; `None` when this wallet has none.
pub(super) async fn object<H: Host>(
    _service: &Service<'_, H>,
    _id: &str,
) -> Result<Option<Payment>, Problem> {
    Err(Problem::not_implemented())
}

/// The payment of the wallet's transaction `tx`, for the `payment.*` events the engine reports
/// by transaction; `None` when it has none.
pub(super) async fn object_of_tx<H: Host>(
    _service: &Service<'_, H>,
    _tx: TxId,
) -> Result<Option<Payment>, Problem> {
    Err(Problem::not_implemented())
}
