// SPDX-License-Identifier: Apache-2.0
//! The objects of the wallet API, as `docs/api/openapi.json` names them under
//! `components/schemas`. serve builds them (`commands::serve::v1`); a command forwarded to a
//! running serve reads them back (ADR 0053), so each one serializes and deserializes.
//!
//! Field names follow the schema exactly. Amounts are decimal strings ([`crate::amount`]);
//! times are RFC 3339 strings in UTC; an optional field the schema does not require is skipped
//! when absent.

mod contact;
mod handed;
mod network;
mod payment;
mod service;
mod wallet;

pub(crate) use contact::{
    Contact, ContactKeys, ContactsBackup, ImportResult, PairRequest, Payload, Quarantined,
};
pub(crate) use handed::{Inspection, OpenResult};
pub(crate) use network::{Peer, Profile, Relay};
pub(crate) use payment::{Delivery, Estimate, Handoff, Payment};
pub(crate) use service::{
    EpicboxListener, Event, HttpListener, Listeners, OwnerTls, Requests, Status, Task,
};
pub(crate) use wallet::{Account, Address, Balance, Link, Node, Output, Wallet};
