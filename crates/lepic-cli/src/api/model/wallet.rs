// SPDX-License-Identifier: Apache-2.0
//! `Wallet`, `Account`, `Balance`, `Output`, `Address`, `Link` and `Node`.

use serde::{Deserialize, Serialize};

/// The wallet serve holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Wallet {
    pub(crate) network: String,
    /// The tip the balances were computed at.
    pub(crate) height: u64,
    /// The node's tip is below the wallet's.
    pub(crate) node_behind: bool,
    /// The latest scan; absent when none ran since serve started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scan: Option<Scan>,
}

impl Wallet {
    /// This wallet with the latest scan's state: `running`, `done` or `failed`.
    pub(crate) fn with_scan(mut self, state: &str, height: u64, target_height: u64) -> Self {
        self.scan = Some(Scan {
            state: state.to_owned(),
            height,
            target_height,
        });
        self
    }
}

/// How far a scan has come.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Scan {
    /// `running`, `done` or `failed`.
    pub(crate) state: String,
    pub(crate) height: u64,
    pub(crate) target_height: u64,
}

/// An account and its balance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Account {
    pub(crate) label: String,
    pub(crate) index: u32,
    pub(crate) balance: Balance,
}

/// An account's balance, by what can be done with it. Amounts are decimal strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Balance {
    pub(crate) spendable: String,
    /// In a block, with fewer confirmations than spending needs.
    pub(crate) confirming: String,
    /// Not in a block yet.
    pub(crate) pending: String,
    /// Mining rewards not yet spendable.
    pub(crate) maturing: String,
    pub(crate) locked: String,
    pub(crate) total: String,
}

/// One coin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Output {
    pub(crate) commitment: String,
    /// The account's label.
    pub(crate) account: String,
    pub(crate) amount: String,
    /// `unspent`, `unconfirmed`, `locked` or `spent`.
    pub(crate) state: String,
    pub(crate) confirmations: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) lock_height: Option<u64>,
    pub(crate) coinbase: bool,
}

/// An address this wallet is paid at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Address {
    /// `epicbox`, `epic1`, `onion` or `http`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) text: String,
    /// The account's label.
    pub(crate) account: String,
    /// Always false: the wallet does not track which address was paid.
    pub(crate) used: bool,
}

/// A request link: the account's epic1 address with what it asks. Nothing is stored for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Link {
    /// The `epic:` link.
    pub(crate) text: String,
    /// The account's label.
    pub(crate) account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

/// The node the wallet reads the chain from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Node {
    pub(crate) version: String,
    pub(crate) tip_height: u64,
    /// The node's tip is below the wallet's.
    pub(crate) syncing: bool,
}
