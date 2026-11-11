// SPDX-License-Identifier: Apache-2.0
//! The fine-grained `code` of each error a call can end with, and the status when it is not the
//! one its category gives. The codes name the same errors the app's `WalletErrorKind`s do
//! (`lepic-ffi`), in snake case, so no message the app tells apart is lost.

use hyper::StatusCode;

use crate::exit::CliError;

/// What [`classify`] found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Classified {
    /// `None`: the category's code.
    pub(crate) code: Option<&'static str>,
    /// `None`: the category's status.
    pub(crate) status: Option<StatusCode>,
}

/// The code and status of `error`.
pub(crate) fn classify(_error: &CliError) -> Classified {
    Classified::default()
}
