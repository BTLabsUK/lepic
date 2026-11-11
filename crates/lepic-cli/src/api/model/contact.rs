// SPDX-License-Identifier: Apache-2.0
//! `Contact`, `PairRequest`, `Payload`, `Quarantined`, `ContactKeys`, `ContactsBackup` and
//! `ImportResult`.

use serde::{Deserialize, Serialize};

/// A contact: a paired wallet, or a pairing on its way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Contact {
    pub(crate) id: String,
}

/// A pairing request another wallet sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PairRequest {
    pub(crate) id: String,
}

/// Data a contact sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Payload {
    pub(crate) id: String,
}

/// A message from the mailbox that could not be handled yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Quarantined {
    pub(crate) id: String,
}

/// What a contact's keys resolve to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContactKeys {}

/// The contact backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContactsBackup {}

/// What an import of the contact backup did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ImportResult {}
