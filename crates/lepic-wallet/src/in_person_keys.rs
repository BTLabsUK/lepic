// SPDX-License-Identifier: Apache-2.0
//! The per-slate keys of a slate exchanged in person (RFC 0003 §5.18): the reply mailbox the
//! code names in its tail, and the keys answers to it are posted from. Each is a key of the
//! LEPIC namespace, so the phrase gives them back. The keys of an account's epic1 address and
//! of the link mailboxes it hands out are here too.

use ed25519_dalek::SigningKey;
use lepic_contact::{EncSecretKey, Network};
use lepic_crypto::SecretKey;
use lepic_node::NodeApi;
use lepic_store::{AccountIndex, WalletStore};

use crate::error::WalletError;
use crate::namespace::{self, LinkMailbox, PostRole};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// The settings prefix of the answers this wallet made to codes it scanned, by slate id. A
/// payment with an entry here is released at its TTL like one made over Epicbox.
pub const IN_PERSON_REPLY_PREFIX: &str = "inperson.reply.";

/// The seal keys of the epic1 addresses of one account, in the order they are tried.
pub struct Epic1AccountKeys {
    pub account: AccountIndex,
    /// The account's label, as a receive names the account.
    pub label: String,
    /// `(address index, seal key)`.
    pub keys: Vec<(u32, EncSecretKey)>,
}

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

    /// The seal key of the epic1 address `index` of `account` on `network`: it opens what
    /// payers seal to the address.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn epic1_seal_key(
        &self,
        account: AccountIndex,
        network: Network,
        index: u32,
    ) -> Result<EncSecretKey, WalletError> {
        let session = self.session()?;
        session
            .epic1_keys
            .key(&session.seed, account.0, network, index)
    }

    /// The proof key of the epic1 address `index` of `account` on `network`: it signs the
    /// payment proofs of slates that came to the address ([`crate::ProofKey::Epic1`]).
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn epic1_proof_key(
        &self,
        account: AccountIndex,
        network: Network,
        index: u32,
    ) -> Result<SigningKey, WalletError> {
        namespace::epic1_proof_key(&self.session()?.seed, account.0, network, index)
    }

    /// The seal keys of the epic1 addresses of `account` on `network` that a zero-hint
    /// envelope is tried with, each with its address index, in the order
    /// [`crate::epic1_index::trial_order`] gives: the index of the most recent payment, index
    /// 0, then the rest from the highest down. Keys derived once stay with the unlocked session.
    ///
    /// Fails with [`WalletError::Locked`] and [`WalletError::Store`].
    pub async fn epic1_trial_keys(
        &self,
        account: AccountIndex,
        network: Network,
    ) -> Result<Vec<(u32, EncSecretKey)>, WalletError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            let order = session
                .store
                .read(|repos| crate::epic1_index::trial_order(repos, account))?;
            session
                .epic1_keys
                .keys(&session.seed, account.0, network, &order)
        })
        .await
    }

    /// [`Wallet::epic1_trial_keys`] of every account of the wallet on its network, by account
    /// index, for an envelope that may be sealed to any address of the wallet: a file, pasted
    /// text, or a payment at the direct listener.
    ///
    /// Fails with [`WalletError::Locked`] and [`WalletError::Store`].
    pub async fn epic1_trial_keys_all(&self) -> Result<Vec<Epic1AccountKeys>, WalletError> {
        let network = crate::native_epicbox::contact_network(self.config().network);
        let session = self.session()?;
        self.blocking(move |_, _| {
            let accounts = session.store.read(|repos| {
                let mut accounts = Vec::new();
                for record in repos.accounts()? {
                    let order = crate::epic1_index::trial_order(repos, record.index)?;
                    accounts.push((record.index, record.label, order));
                }
                Ok::<_, lepic_store::StoreError>(accounts)
            })?;
            let mut keys = Vec::with_capacity(accounts.len());
            for (account, label, order) in accounts {
                keys.push(Epic1AccountKeys {
                    account,
                    label,
                    keys: session
                        .epic1_keys
                        .keys(&session.seed, account.0, network, &order)?,
                });
            }
            keys.sort_by_key(|entry| entry.account.0);
            Ok(keys)
        })
        .await
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
