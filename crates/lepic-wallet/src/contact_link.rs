//! Which paired contact a slate or a transaction was exchanged with. `lepic-wallet-contacts`
//! writes these links when it seals or opens a contact's slate; the engine reads them so a
//! contact's slates keep to the contact's mailbox and a contact's notices match only its own
//! transactions.

use lepic_store::{ContactId, Repositories, StoreError, TxId};
use uuid::Uuid;

const SLATE_PREFIX: &str = "contact.slate.";
const TX_PREFIX: &str = "contact.tx.";

/// Records that the slate `slate_id` belongs to an exchange with `contact`, so its answers go
/// through the contact's mailbox. A slate another contact holds is never moved: returns false
/// and changes nothing.
pub fn link_slate(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    contact: ContactId,
) -> Result<bool, StoreError> {
    if slate_contact(repos, slate_id)?.is_some_and(|other| other != contact) {
        return Ok(false);
    }
    repos.put_setting(&format!("{SLATE_PREFIX}{slate_id}"), &hex(&contact.0))?;
    Ok(true)
}

/// The contact the slate `slate_id` was exchanged with, if any.
pub fn slate_contact(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<ContactId>, StoreError> {
    Ok(repos
        .setting(&format!("{SLATE_PREFIX}{slate_id}"))?
        .and_then(|text| contact_from_hex(&text)))
}

/// Records that the transaction `tx_id` is an exchange with `contact`.
pub fn link_tx(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    contact: ContactId,
) -> Result<(), StoreError> {
    repos.put_setting(&format!("{TX_PREFIX}{tx_id}"), &hex(&contact.0))
}

/// The contact the transaction `tx_id` was exchanged with, if any: what a contact's notices
/// are matched by.
pub fn tx_contact(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<ContactId>, StoreError> {
    Ok(repos
        .setting(&format!("{TX_PREFIX}{tx_id}"))?
        .and_then(|text| contact_from_hex(&text)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn contact_from_hex(text: &str) -> Option<ContactId> {
    let mut id = [0u8; 16];
    if text.len() != 32 {
        return None;
    }
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(ContactId(id))
}
