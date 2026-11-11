// SPDX-License-Identifier: Apache-2.0
//! `Contact`, `PairRequest`, `Payload`, `Quarantined`, `ContactKeys`, `ContactsBackup` and
//! `ImportResult`.

use serde::{Deserialize, Serialize};

/// What the contact told this wallet about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContactProfile {
    pub(crate) flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) domain: Option<String>,
    pub(crate) domain_proven: bool,
}

/// What the contact's wallet can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContactFeatures {
    pub(crate) native_slates: bool,
}

/// A pairing on its way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContactPairing {
    pub(crate) method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) invite_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<String>,
}

/// A contact: a paired wallet, or a pairing on its way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Contact {
    pub(crate) id: String,
    pub(crate) class: String,
    pub(crate) state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ended_reason: Option<String>,
    pub(crate) label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) claimed_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verify_words: Option<Vec<String>>,
    pub(crate) allow_invoices: bool,
    pub(crate) seal: bool,
    pub(crate) home_relay: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requested_relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refused_relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) profile: Option<ContactProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) features: Option<ContactFeatures>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pairing: Option<ContactPairing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_heard_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ended_at: Option<String>,
    pub(crate) created_at: String,
}

/// A pairing request another wallet sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PairRequest {
    pub(crate) id: String,
    pub(crate) from_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) claimed_name: Option<String>,
    pub(crate) received_at: String,
    pub(crate) expires_at: String,
}

impl Contact {
    /// This contact with what it told this wallet about itself.
    pub(crate) fn with_profile(
        mut self,
        flags: Vec<String>,
        domain: Option<String>,
        proven: bool,
    ) -> Self {
        self.profile = Some(ContactProfile {
            flags,
            domain,
            domain_proven: proven,
        });
        self
    }

    /// This contact with what its wallet can do.
    pub(crate) fn with_features(mut self, native_slates: bool) -> Self {
        self.features = Some(ContactFeatures { native_slates });
        self
    }

    /// This contact with the pairing that is on its way.
    pub(crate) fn with_pairing(
        mut self,
        method: &str,
        invite_link: Option<String>,
        expires_at: Option<String>,
    ) -> Self {
        self.pairing = Some(ContactPairing {
            method: method.to_owned(),
            invite_link,
            expires_at,
        });
        self
    }
}

/// Data a contact sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Payload {
    pub(crate) id: String,
    pub(crate) contact_id: String,
    pub(crate) size: u64,
    pub(crate) received_at: String,
    pub(crate) data_base64: String,
}

/// A message from the mailbox that could not be handled yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Quarantined {
    pub(crate) id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contact_id: Option<String>,
    pub(crate) reason: String,
    pub(crate) size: u64,
    pub(crate) attempts: u32,
    pub(crate) first_seen_at: String,
}

/// The choice made for a contact whose keys changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactKeys {
    #[serde(rename = "use")]
    pub(crate) keep: String,
}

/// The contact backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactsBackup {
    pub(crate) document: String,
}

/// What an import of the contact backup did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ImportResult {
    pub(crate) imported: u32,
}
