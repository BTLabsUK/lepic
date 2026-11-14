// SPDX-License-Identifier: Apache-2.0
//! The Epicbox identities of a wallet's addresses on this method's relay: the payments address
//! and the address of each listing.

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{ClientError, EpicboxAddress, Identity, Network};
use lepic_node::NodeApi;
use lepic_wallet::inbox::InboxError;
use lepic_wallet::namespace::Listing;
use lepic_wallet::{SecretVault, StoreOpener, Wallet, WalletError};

use super::{Epicbox, relay_network};

impl Epicbox {
    /// The wallet's Epicbox identity (the default account's first address) at this method's
    /// relay.
    ///
    /// Fails with [`InboxError::NetworkMismatch`] when this method serves the other network, and
    /// with [`InboxError::Wallet`] when the wallet is locked.
    pub(super) fn identity<N, S, V>(&self, wallet: &Wallet<N, S, V>) -> Result<Identity, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let network = self.checked_network(wallet)?;
        let secret = wallet.address_secret()?;
        let public = PublicKey::from_secret_key(&secret)
            .map_err(|_| InboxError::Identity(Box::new(ClientError::IdentityMismatch)))?;
        self.identity_at_relay(secret, public, network)
    }

    /// The identity of `wallet`'s `listing` address at this method's relay. Fails as
    /// [`Epicbox::identity`] does.
    pub(super) fn listing_identity<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listing: &Listing,
    ) -> Result<Identity, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let network = self.checked_network(wallet)?;
        let secret = wallet.listing_secret(listing)?;
        let public = PublicKey::from_secret_key(&secret)
            .map_err(|error| InboxError::Wallet(WalletError::Keychain(error.into())))?;
        self.identity_at_relay(secret, public, network)
    }

    /// The relay network of `wallet`, which must be the one this method serves.
    fn checked_network<N, S, V>(&self, wallet: &Wallet<N, S, V>) -> Result<Network, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let network = relay_network(wallet.config().network);
        if self.network() == network {
            Ok(network)
        } else {
            Err(InboxError::NetworkMismatch)
        }
    }

    fn identity_at_relay(
        &self,
        secret: SecretKey,
        public: PublicKey,
        network: Network,
    ) -> Result<Identity, InboxError> {
        let endpoint = &self.settings().endpoint;
        let address = EpicboxAddress::new(
            public,
            network,
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        Identity::new(secret, address).map_err(|error| InboxError::Identity(Box::new(error)))
    }
}
