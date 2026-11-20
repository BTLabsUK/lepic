// SPDX-License-Identifier: Apache-2.0
//! The per-slate keys of a slate exchanged in person (RFC 0003 §5.18): the reply mailbox the
//! code names in its tail, and the keys answers to it are posted from. Each is a key of the
//! LEPIC namespace, so the phrase gives them back. The seal and delivery keys of an account's
//! epic1 addresses are here too.

use lepic_contact::{EncSecretKey, Network};
use lepic_crypto::SecretKey;
use lepic_node::NodeApi;
use lepic_store::{AccountIndex, WalletStore};

use crate::error::WalletError;
use crate::namespace::{self, PostRole};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// The settings prefix of the answers this wallet made to codes it scanned, by slate id. A
/// payment with an entry here is released at its TTL like one made over Epicbox.
pub const IN_PERSON_REPLY_PREFIX: &str = "inperson.reply.";

/// The seal key of the epic1 address of one account.
pub struct Epic1AccountKeys {
    pub account: AccountIndex,
    /// The account's label, as a receive names the account.
    pub label: String,
    /// The seal key of the address, index 0.
    pub key: EncSecretKey,
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

    /// The key `account` on `network` posts for the payment `payment_id` from, in `role`. It
    /// is apart from every address of the wallet, so a post does not name the wallet.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn post_key(
        &self,
        account: AccountIndex,
        network: Network,
        payment_id: &[u8; 16],
        role: PostRole,
    ) -> Result<SecretKey, WalletError> {
        namespace::post_key(&self.session()?.seed, account.0, network, payment_id, role)
    }

    /// The seal key of the epic1 address of `account` on `network`, index 0: it opens what
    /// payers seal to the address.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn epic1_seal_key(
        &self,
        account: AccountIndex,
        network: Network,
    ) -> Result<EncSecretKey, WalletError> {
        let session = self.session()?;
        session.epic1_keys.key(&session.seed, account.0, network)
    }

    /// The delivery key of the epic1 address of `account` on `network`, index 0: the secp256k1
    /// key the address carries next to its seal key.
    ///
    /// Fails with [`WalletError::Locked`] and [`WalletError::NoValidKey`].
    pub fn epic1_delivery_key(
        &self,
        account: AccountIndex,
        network: Network,
    ) -> Result<SecretKey, WalletError> {
        namespace::epic1_delivery_key(&self.session()?.seed, account.0, network, 0)
    }

    /// The seal key of the epic1 address of every account of the wallet on its network, by
    /// account index, that a zero-hint envelope is tried with: a file, pasted text, or a payment
    /// at the direct listener. Keys derived once stay with the unlocked session.
    ///
    /// Fails with [`WalletError::Locked`] and [`WalletError::Store`].
    pub async fn epic1_trial_keys_all(&self) -> Result<Vec<Epic1AccountKeys>, WalletError> {
        let network = match self.config().network {
            lepic_primitives::params::Network::Mainnet => lepic_contact::Network::Mainnet,
            lepic_primitives::params::Network::Floonet => lepic_contact::Network::Floonet,
        };
        let session = self.session()?;
        self.blocking(move |_, _| {
            let accounts = session.store.read(|repos| {
                let mut accounts = Vec::new();
                for record in repos.accounts()? {
                    accounts.push((record.index, record.label));
                }
                Ok::<_, lepic_store::StoreError>(accounts)
            })?;
            let mut keys = Vec::with_capacity(accounts.len());
            for (account, label) in accounts {
                keys.push(Epic1AccountKeys {
                    account,
                    label,
                    key: session.epic1_keys.key(&session.seed, account.0, network)?,
                });
            }
            keys.sort_by_key(|entry| entry.account.0);
            Ok(keys)
        })
        .await
    }
}
