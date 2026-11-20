// SPDX-License-Identifier: Apache-2.0
//! The epic1 address of each account (RFC 0003 §5.13): index 0 of the account, its one address.
//! The wallet keeps the index each payment came to, always 0, so a listing tells a payment to
//! the address from other receives. Coins do not depend on it.
//!
//! A store written by an earlier release may hold rows of numbered addresses and the links on
//! them. They are left as they are and never read: a payment sealed to an index past 0 is not
//! opened.

use lepic_store::{Repositories, StoreError, TxId};

/// The settings prefix of the index each payment came to, by transaction.
const TX_PREFIX: &str = "epic1.tx.";

/// Records that the payment `tx_id` came to the account's epic1 address, index 0.
pub(crate) fn record_payment(repos: &mut dyn Repositories, tx_id: TxId) -> Result<(), StoreError> {
    repos.put_setting(&format!("{TX_PREFIX}{}", tx_id.0), "0")
}

/// The epic1 address index the payment `tx_id` came to; `None` for a transaction that did not
/// come to an epic1 address, or whose stored index is damaged: it is only shown, and a
/// damaged one does not keep the transaction from being listed.
pub fn index_of(repos: &dyn Repositories, tx_id: TxId) -> Result<Option<u32>, StoreError> {
    Ok(repos
        .setting(&format!("{TX_PREFIX}{}", tx_id.0))?
        .and_then(|text| text.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lepic_store::{CONTEXT_KEY_LEN, MemoryStore, StoreKeys, WalletStore};

    #[test]
    fn a_payment_is_kept_at_index_0_and_a_damaged_index_only_hides_it() {
        let store = MemoryStore::new(StoreKeys::from_bytes(
            [2; CONTEXT_KEY_LEN],
            [2; CONTEXT_KEY_LEN],
        ));
        store
            .write(|repos| {
                record_payment(repos, TxId(7))?;
                assert_eq!(index_of(repos, TxId(7))?, Some(0));
                assert_eq!(index_of(repos, TxId(8))?, None);
                repos.put_setting(&format!("{TX_PREFIX}9"), "-1")?;
                assert_eq!(index_of(repos, TxId(9))?, None);
                Ok::<_, StoreError>(())
            })
            .unwrap();
    }
}
