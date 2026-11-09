// SPDX-License-Identifier: Apache-2.0
//! The per-slate keys of a slate exchanged in person (RFC 0003 §5.18): the reply mailbox the
//! code names in its tail, and the keys answers to it are posted from. Each is a key of the
//! LEPIC namespace, so the phrase gives them back. The keys of an account's epic1 address and
//! of the link mailboxes it hands out are here too.

use ed25519_dalek::SigningKey;
use lepic_contact::{EncSecretKey, Network};
use lepic_crypto::SecretKey;
use lepic_node::NodeApi;
use lepic_store::AccountIndex;

use crate::error::WalletError;
use crate::namespace::{self, LinkMailbox, PostRole, SealKeyKind};
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

    /// The seal key of the epic1 address of `account` on `network`: it opens what payers seal
    /// to the address.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn epic1_seal_key(
        &self,
        account: AccountIndex,
        network: Network,
    ) -> Result<EncSecretKey, WalletError> {
        namespace::seal_key(
            &self.session()?.seed,
            account.0,
            network,
            SealKeyKind::Epic1,
        )
    }

    /// The proof key of the epic1 address of `account` on `network`: it signs the payment
    /// proofs of slates that came to the address ([`crate::ProofKey::Epic1`]).
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn epic1_proof_key(
        &self,
        account: AccountIndex,
        network: Network,
    ) -> Result<SigningKey, WalletError> {
        namespace::epic1_proof_key(&self.session()?.seed, account.0, network)
    }

    /// The key of the link mailbox `mailbox` of `account` on `network`: the mailbox an epic1
    /// link names, which payers post to.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn link_mailbox_key(
        &self,
        account: AccountIndex,
        network: Network,
        mailbox: LinkMailbox,
    ) -> Result<SecretKey, WalletError> {
        namespace::link_mailbox_key(&self.session()?.seed, account.0, network, mailbox)
    }
}
