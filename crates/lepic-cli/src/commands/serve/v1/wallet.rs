// SPDX-License-Identifier: Apache-2.0
//! The wallet, its accounts and the node: `/wallet`, `/wallet/password`, `/wallet/scan`, `/sync`, `/accounts`, `/node`.

use lepic_store::AccountIndex;

use super::super::Service;
use super::Reply;
use crate::api::model::{Account, Wallet};
use crate::api::{Context, Problem, Request};
use crate::host::Host;

pub(super) async fn get_wallet<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn update_wallet<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn change_password<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn scan<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn sync<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn list_accounts<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn create_account<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

pub(super) async fn get_node<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Err(Problem::not_implemented())
}

/// The wallet, for `GET /wallet` and the `wallet.progress` event.
pub(super) async fn wallet_object<H: Host>(_service: &Service<'_, H>) -> Result<Wallet, Problem> {
    Err(Problem::not_implemented())
}

/// The account `index`, for `GET /accounts` and the `account.balance_changed` event; `None`
/// when there is none.
pub(super) async fn account_object<H: Host>(
    _service: &Service<'_, H>,
    _index: AccountIndex,
) -> Result<Option<Account>, Problem> {
    Err(Problem::not_implemented())
}
