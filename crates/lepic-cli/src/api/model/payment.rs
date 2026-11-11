// SPDX-License-Identifier: Apache-2.0
//! `Payment`, `Delivery`, `Handoff` and `Estimate`.

use serde::{Deserialize, Serialize};

/// A payment: one slate's life, seen from this wallet. Its `id` is the slate id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Payment {
    pub(crate) id: String,
}

/// How a payment's slate is getting to the other wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Delivery {}

/// What to give the other person by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Handoff {}

/// What a payment would cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Estimate {}
