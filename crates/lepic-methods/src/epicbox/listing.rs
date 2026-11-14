// SPDX-License-Identifier: Apache-2.0
//! Listing addresses over Epicbox: one address per listing with a name service, apart from the
//! payments address. A listing's mailbox is drained on its own connection, never by the
//! payments listener; what arrives there is answered from the listing's address.

use std::sync::Arc;

use lepic_crypto::{EcdsaSignature, PublicKey};
use lepic_epicbox::{
    Awaiting, ClientError, DrainConnection, EpicboxAddress, Identity, RELAY_RETENTION,
    ServiceDomain, TRANSPORT_ID,
};
use lepic_node::NodeApi;
use lepic_transport::method::Method;
use lepic_wallet::inbox::{InboxError, InboxSummary};
use lepic_wallet::namespace::Listing;
use lepic_wallet::{SecretVault, StoreOpener, Wallet, WalletError};
use tokio::time::{Instant, timeout_at};
use tracing::instrument;

use super::Epicbox;
use super::inbox::{PruneSchedule, Run, Source};
use super::relay_network;

impl Epicbox {
    /// The Epicbox address of `wallet`'s `listing` on this method's relay. Needs no relay.
    ///
    /// Fails with [`WalletError::Locked`] inside [`InboxError::Wallet`], and with
    /// [`InboxError::NetworkMismatch`] when this method serves the other network.
    pub fn address_at<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listing: &Listing,
    ) -> Result<EpicboxAddress, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        Ok(self.listing_identity(wallet, listing)?.address().clone())
    }

    /// Signs `message` for the app's `domain` with the key of `wallet`'s `listing` address,
    /// under the listing-signature tag, which nothing else in the wallet signs under;
    /// [`lepic_epicbox::listing_message_verifies`] checks it with no wallet open. Domains of
    /// LEPIC's own cannot be made, and no other key signs here.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn sign_with_address_key_at<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listing: &Listing,
        domain: &ServiceDomain,
        message: &[u8],
    ) -> Result<EcdsaSignature, WalletError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let key = wallet.listing_secret(listing)?;
        lepic_epicbox::sign_listing_message(domain, message, &key)
            .map_err(|error| WalletError::Keychain(error.into()))
    }

    /// Connects to this method's relay as `wallet`'s `listing` address once, handles every
    /// pending message there and disconnects, as [`Epicbox::drain`] does for the payments
    /// address, on its own connection: the payments listener and its attached identity are
    /// not touched, and no connection state is reported for it.
    ///
    /// An S1 is received into the default account, its transaction records the listing, and
    /// its S2 goes back from the listing's address. An S1 that asks for a payment proof is
    /// refused and nothing is signed for it. Notices are taken as on the payments address;
    /// any other slate is refused. Fails as [`Epicbox::drain`] does.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn drain_at<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listing: &Listing,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        self.drain_listing_on(wallet, listing, None, &mut None)
            .await
    }

    /// Drains each of `listings` as [`Epicbox::drain_at`] does, one after the other, on one
    /// relay connection where it can: after a listing ends quiet (nothing outstanding, nothing
    /// held, every message acknowledged) the next one subscribes on the same connection. After
    /// a message the wallet kept, or a connection that failed, the listings still to come
    /// continue on a fresh connection. A connection handed on that the relay had closed is
    /// replaced and the listing tried again once.
    ///
    /// The whole call is bound by the method's drain timeout; listings not reached by then fail
    /// with [`InboxError::Subscription`] and are left for the next drain. Returns one result
    /// per listing, in the order given.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str(), listings = listings.len()))]
    pub async fn drain_many_at<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listings: &[Listing],
    ) -> Vec<Result<InboxSummary, InboxError>>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let now = Instant::now();
        let deadline = now
            .checked_add(self.settings().drain_timeout)
            .unwrap_or(now);
        let mut results = Vec::with_capacity(listings.len());
        let mut carried: Option<DrainConnection> = None;
        for listing in listings {
            if Instant::now() >= deadline {
                // The deadline passed: the rest are not reached, not polled once.
                carried = None;
                results.push(Err(not_reached()));
                continue;
            }
            let handed = carried.take();
            let reused = handed.is_some();
            let mut outcome = timeout_at(
                deadline,
                self.drain_listing_on(wallet, listing, handed, &mut carried),
            )
            .await;
            if reused
                && matches!(
                    outcome,
                    Ok(Err(InboxError::Subscription(_) | InboxError::Transport(_)))
                )
            {
                carried = None;
                outcome = timeout_at(
                    deadline,
                    self.drain_listing_on(wallet, listing, None, &mut carried),
                )
                .await;
            }
            results.push(outcome.unwrap_or_else(|_| {
                carried = None;
                Err(not_reached())
            }));
        }
        if let Some(connection) = carried {
            connection.close().await;
        }
        results
    }

    /// One listing's drain on `handed` when given. `carried` receives the connection when the
    /// drain ended quiet, and is `None` otherwise.
    async fn drain_listing_on<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listing: &Listing,
        handed: Option<DrainConnection>,
        carried: &mut Option<DrainConnection>,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let identity = self.listing_identity(wallet, listing)?;
        // A method of its own, so replies go from the listing's address while deliveries
        // through this one keep the attached identity.
        let at_listing = Epicbox::new(self.settings().clone(), self.network(), self.connector());
        let client = at_listing.attach(identity);
        wallet.prune_arrivals(RELAY_RETENTION).await;
        let subscription = client
            .drain_on(handed)
            .map_err(|error| InboxError::Subscription(Box::new(error)))?;
        let method: Arc<dyn Method> = Arc::new(at_listing);
        let run = Run {
            wallet,
            method,
            source: Source::Socket(&subscription),
            listen: None,
            backoff: self.settings().backoff,
            pruning: PruneSchedule::default(),
            listing: Some(*listing),
        };
        let consumed = run.consume().await;
        let stopped = subscription
            .stop()
            .await
            .map_err(|error| InboxError::Subscription(Box::new(error)));
        // A drain that kept a message, was stopped or failed has no connection to hand back.
        let handed_back = subscription.take_connection();
        if consumed.is_ok() && stopped.is_ok() {
            *carried = handed_back;
        } else if let Some(connection) = handed_back {
            connection.close().await;
        }
        stopped?;
        consumed
    }

    fn listing_identity<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        listing: &Listing,
    ) -> Result<Identity, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let network = relay_network(wallet.config().network);
        if self.network() != network {
            return Err(InboxError::NetworkMismatch);
        }
        let secret = wallet.listing_secret(listing)?;
        let public = PublicKey::from_secret_key(&secret)
            .map_err(|error| InboxError::Wallet(WalletError::Keychain(error.into())))?;
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

/// The outcome of a listing the drain deadline cut off.
fn not_reached() -> InboxError {
    InboxError::Subscription(Box::new(ClientError::Timeout {
        awaiting: Awaiting::Connection,
    }))
}
