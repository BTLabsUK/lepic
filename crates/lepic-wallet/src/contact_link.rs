// SPDX-License-Identifier: Apache-2.0
//! Which paired contact a slate or a transaction was exchanged with. `lepic-wallet-contacts`
//! writes these links when it seals or opens a contact's slate; the engine reads them so a
//! contact's slates keep to the contact's mailbox and a contact's notices match only its own
//! transactions.

use lepic_store::{ContactId, Repositories, StoreError, TxId};
use uuid::Uuid;

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
    repos.set_slate_contact(slate_id, contact)?;
    Ok(true)
}

/// The contact the slate `slate_id` was exchanged with, if any.
pub fn slate_contact(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<ContactId>, StoreError> {
    repos.slate_contact(slate_id)
}

/// Records that the transaction `tx_id` is an exchange with `contact`.
pub fn link_tx(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    contact: ContactId,
) -> Result<(), StoreError> {
    repos.set_tx_contact(tx_id, contact)
}

/// The contact the transaction `tx_id` was exchanged with, if any: what a contact's notices
/// are matched by.
pub fn tx_contact(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<ContactId>, StoreError> {
    repos.tx_contact(tx_id)
}
