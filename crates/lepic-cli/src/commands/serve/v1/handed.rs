// SPDX-License-Identifier: Apache-2.0
//! Anything a user is handed: `POST /inspect` reads it, `POST /open` acts on it.

use super::super::Service;
use super::Reply;
use crate::api::{Context, Problem, Request};
use crate::host::Host;

pub(super) async fn inspect<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn open<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}
