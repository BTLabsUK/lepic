// SPDX-License-Identifier: Apache-2.0
//! `Payment`, `Delivery`, `Handoff` and `Estimate`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A payment: one slate's life, seen from this wallet. Its `id` is the slate id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Payment {
    pub(crate) id: String,
    /// `send`, `invoice`, `coinbase` or `unknown` (found by a scan).
    pub(crate) kind: String,
    /// `in`, `out` or `self`.
    pub(crate) direction: String,
    pub(crate) state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) state_reason: Option<String>,
    /// The account's label; for `self`, the account it left.
    pub(crate) account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) to_account: Option<String>,
    /// What the payee gets.
    pub(crate) amount: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fee: Option<String>,
    /// The signed change to this wallet's balance, fee included.
    pub(crate) balance_change: String,
    pub(crate) via: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) counterparty: Option<Counterparty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) our_address: Option<OurAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) link_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
    /// Ours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) their_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) delivery: Option<Delivery>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) answers: Vec<Answer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) check_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) their_notices: Option<TheirNotices>,
    /// The calls that work on it now.
    pub(crate) actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cancellable_from_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) confirmations: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) confirmed_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kernel_excess: Option<String>,
    /// `wallet`, `imported` or `scan`.
    pub(crate) source: String,
    /// Local notes, never sent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    /// In create and open answers, when the payment goes by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) handoff: Option<Handoff>,
}

impl Payment {
    /// The other wallet, made when first asked for.
    pub(crate) fn counterparty_mut(&mut self) -> &mut Counterparty {
        self.counterparty.get_or_insert_with(Counterparty::default)
    }

    /// Which of this wallet's addresses the payment reached: `epicbox`, `epic1` or `listing`.
    pub(crate) fn set_our_address(&mut self, kind: &str, index: Option<u32>) {
        self.our_address = Some(OurAddress {
            kind: kind.to_owned(),
            index,
        });
    }

    /// What the other side reported, made when first asked for.
    pub(crate) fn their_notices_mut(&mut self) -> &mut TheirNotices {
        self.their_notices.get_or_insert_with(TheirNotices::default)
    }

    /// Leaves `their_notices` out when the other side reported nothing.
    pub(crate) fn drop_empty_notices(&mut self) {
        if self
            .their_notices
            .as_ref()
            .is_some_and(TheirNotices::is_empty)
        {
            self.their_notices = None;
        }
    }
}

/// The other wallet of a payment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Counterparty {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
}

/// Which of this wallet's addresses a payment reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OurAddress {
    /// `epicbox`, `epic1` or `listing`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) index: Option<u32>,
}

/// An answer to an in-person payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Answer {
    pub(crate) id: String,
    pub(crate) check_code: String,
    pub(crate) received_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) same_code_as: Option<String>,
}

/// What the other side reported about a payment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TheirNotices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) posted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cancelled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) declined_at: Option<String>,
}

impl TheirNotices {
    pub(crate) fn is_empty(&self) -> bool {
        self.posted_at.is_none() && self.cancelled_at.is_none() && self.declined_at.is_none()
    }
}

/// How a payment's slate is getting to the other wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Delivery {
    /// `queued`, `sent`, `uncertain`, `held`, `failed`, `refused` or `by_hand`.
    pub(crate) state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) relays_left: Option<u32>,
    pub(crate) attempts: u32,
    pub(crate) updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// What to give the other person by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Handoff {
    /// `slate`, `epictx`, `sealed`, `plain` or `in_person_code`.
    pub(crate) format: String,
    pub(crate) text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) qr_frames: Option<Vec<String>>,
}

/// What a payment would cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Estimate {
    pub(crate) fee: String,
    /// The most the account can send.
    pub(crate) max_amount: String,
    /// The coins it would use, as `Output` objects.
    pub(crate) outputs: Vec<Coin>,
}

impl Estimate {
    pub(crate) const fn new(fee: String, max_amount: String) -> Self {
        Self {
            fee,
            max_amount,
            outputs: Vec::new(),
        }
    }

    /// Adds a coin the estimate would use; `heights` is its height and lock height.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per field of an Output"
    )]
    pub(crate) fn push_coin(
        &mut self,
        commitment: String,
        account: String,
        amount: String,
        state: &str,
        confirmations: u64,
        coinbase: bool,
        heights: (Option<u64>, Option<u64>),
    ) {
        self.outputs.push(Coin {
            commitment,
            account,
            amount,
            state: state.to_owned(),
            confirmations,
            height: heights.0,
            lock_height: heights.1,
            coinbase,
            payment_id: None,
        });
    }
}

/// A coin the estimate would use: the `Output` schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Coin {
    pub(crate) commitment: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) payment_id: Option<String>,
}
