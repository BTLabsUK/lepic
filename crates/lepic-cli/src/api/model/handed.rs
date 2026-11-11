// SPDX-License-Identifier: Apache-2.0
//! `Inspection` and `OpenResult`: anything a user is handed, read and acted on.

use serde::{Deserialize, Serialize};

use super::contact::Contact;
use super::payment::{Handoff, Payment};

/// What a text, file or QR code is, and what opening it would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Inspection {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// It belongs to this wallet's network.
    pub(crate) network_ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) summary: Option<Summary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer: Option<Peer>,
    /// The payment of this wallet it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) payment_id: Option<String>,
    /// `pay`, `open`, `accept_invite` or `none`.
    pub(crate) next: String,
}

impl Inspection {
    pub(crate) fn new(kind: &str, network_ok: bool, next: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            network_ok,
            summary: None,
            peer: None,
            payment_id: None,
            next: next.to_owned(),
        }
    }

    /// What it says, made when first asked for.
    pub(crate) fn summary_mut(&mut self) -> &mut Summary {
        self.summary.get_or_insert_with(Summary::default)
    }
}

/// What an inspected item says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Summary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_id: Option<String>,
}

/// What an address's wallet takes, as its relay says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Peer {
    pub(crate) native: bool,
    pub(crate) pays_invoices: bool,
}

/// What opening it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpenResult {
    /// `received`, `finished`, `answer_added`, `invoice_parked`, `pairing_advanced` or
    /// `already_done`.
    pub(crate) outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) payment: Option<Payment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact: Option<Contact>,
    /// The answer to give back by hand, in the format that came in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) handoff: Option<Handoff>,
}
