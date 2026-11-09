// SPDX-License-Identifier: Apache-2.0
//! The per-slate keys of a slate exchanged in person (RFC 0003 §5.18): the reply mailbox the
//! code names in its tail, and the keys answers to it are posted from. Each is a key of the
//! LEPIC namespace, so the phrase gives them back.

use lepic_contact::Network;
use lepic_crypto::SecretKey;
use lepic_node::NodeApi;
use lepic_store::AccountIndex;

use crate::error::WalletError;
use crate::namespace::{self, PostRole};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// The settings prefix of the answers this wallet made to codes it scanned, by slate id. A
/// payment with an entry here is released at its TTL like one made over Epicbox.
pub const IN_PERSON_REPLY_PREFIX: &str = "inperson.reply.";

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The key of the reply mailbox of `account` on `network` for the slate `slate_id`: the
    /// mailbox an in-person code names, which answers to it are posted to.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn reply_mailbox_key(
        &self,
        account: AccountIndex,
        network: Network,
        slate_id: &[u8; 16],
    ) -> Result<SecretKey, WalletError> {
        namespace::reply_mailbox_key(&self.session()?.seed, account.0, network, slate_id)
    }

    /// The key `account` on `network` posts for the slate `slate_id` from, in `role`. It is
    /// apart from every address of the wallet, so a post does not name the wallet.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn post_key(
        &self,
        account: AccountIndex,
        network: Network,
        slate_id: &[u8; 16],
        role: PostRole,
    ) -> Result<SecretKey, WalletError> {
        namespace::post_key(&self.session()?.seed, account.0, network, slate_id, role)
    }
}
