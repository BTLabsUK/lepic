// SPDX-License-Identifier: Apache-2.0
//! The relay, peers and profile: `/relay`, `/peers`, `/profile`.

use super::super::Service;
use super::Reply;
use crate::api::model::Relay;
use crate::api::{Context, Problem, Request};
use crate::host::Host;

pub(super) async fn get_relay<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn move_relay<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn list_peers<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn delete_peer<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn get_profile<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn update_profile<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn domain_file<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

/// The relay, for `GET /relay` and the `relay.updated` event.
pub(super) async fn relay_object<H: Host>(_service: &Service<'_, H>) -> Result<Relay, Problem> {
    Err(Problem::not_implemented())
}
