// SPDX-License-Identifier: Apache-2.0
//! What LEPIC keeps of an epic1 link beside the wallet's own record of its mailbox: the link
//! text and what the link asks, for `GET /links`. `lepic serve` and `lepic epic1 link` keep the
//! same record, stored with the link mailbox in one store transaction.

use lepic_store::AccountIndex;
use lepic_wallet_contacts::Epic1LinkKind;
use serde::{Deserialize, Serialize};

/// The record kept of a link. `text` is empty until the link is issued, and for a link cut
/// short between the two writes; the list builds it again then.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Kept {
    #[serde(default)]
    pub(crate) text: String,
    pub(crate) address_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

pub(crate) const fn kind_part(kind: Epic1LinkKind) -> &'static str {
    match kind {
        Epic1LinkKind::OnScreen => "screen",
        Epic1LinkKind::Printed => "printed",
    }
}

/// The API id of the link `n` of `kind` of `account`.
pub(crate) fn link_id(account: AccountIndex, kind: Epic1LinkKind, n: u32) -> String {
    format!("{}.{}.{n}", account.0, kind_part(kind))
}

/// The setting the record of link `id` is kept under.
pub(crate) fn kept_key(id: &str) -> String {
    format!("api.link.{id}")
}

/// The settings to store with the link of `account` and `kind` once its number is known:
/// `kept`, and `extra` with its value made from the link id.
pub(crate) fn record(
    account: AccountIndex,
    kind: Epic1LinkKind,
    kept: &Kept,
    extra: Option<String>,
) -> Result<impl FnOnce(u32) -> Vec<(String, String)> + Send + 'static, serde_json::Error> {
    let text = serde_json::to_string(kept)?;
    Ok(move |n| {
        let id = link_id(account, kind, n);
        let mut settings = vec![(kept_key(&id), text)];
        if let Some(key) = extra {
            settings.push((key, id));
        }
        settings
    })
}
