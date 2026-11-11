// SPDX-License-Identifier: Apache-2.0
//! `Wallet`, `Account`, `Balance`, `Output`, `Address`, `Link` and `Node`.

use serde::{Deserialize, Serialize};

/// The wallet serve holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Wallet {}

/// An account and its balance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Account {
    pub(crate) label: String,
}

/// An account's balance, by what can be done with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Balance {}

/// One coin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Output {
    pub(crate) commitment: String,
}

/// An address this wallet is paid at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Address {}

/// A pay link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Link {
    pub(crate) id: String,
}

/// The node the wallet reads the chain from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Node {}
