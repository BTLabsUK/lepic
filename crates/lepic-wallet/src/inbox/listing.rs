// SPDX-License-Identifier: Apache-2.0
//! Listing addresses: Epicbox addresses of keys from the LEPIC namespace, one per listing with a
//! directory, apart from the payments address. A listing's mailbox is drained on its own
//! connection, never by the payments listener; what arrives there is answered from the listing's
//! address and recorded with the listing.
//!
//! Only S1 slates and notices are taken at a listing. A payment that asks for a payment proof is
//! refused, so nothing about it is ever signed by the payments key. The app passes only the
//! directory key and the generation; no secret, signature over a LEPIC domain, or ECDH value
//! leaves the wallet.

use lepic_crypto::{EcdsaSignature, PublicKey};
use lepic_epicbox::EpicboxClient;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{EpicboxAddress, Identity, ServiceDomain};
use lepic_node::NodeApi;
use lepic_slate::codec::WireSlate;
use lepic_slate::stage::Stage;
use lepic_store::WalletStore;
use lepic_transport::transport::{Destination, Outbound};
use tracing::{info, instrument};

use super::{
    Hold, InboxError, InboxSummary, PruneSchedule, Refusal, Settlement, TRANSPORT_ID, backoff,
    relay_network,
};
use crate::error::WalletError;
use crate::namespace::{self, Listing};
use crate::notice::{self, Payload};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::legacy_codecs;
use crate::wallet::Wallet;

/// Where the messages of a listing drain are answered from.
pub(crate) struct ListingRoute {
    pub(crate) listing: Listing,
    client: EpicboxClient,
}

impl ListingRoute {
    /// Delivers `wire` to `to` from the listing's address.
    pub(crate) async fn reply(&self, to: &Destination, wire: &WireSlate) -> Result<(), Hold> {
        self.client.deliver(to, wire).await.map_err(Hold::Reply)?;
        info!(stage = Stage::S2.as_str(), "slate sent from a listing");
        Ok(())
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The Epicbox address of `listing` on the relay of `epicbox`. Needs no relay.
    ///
    /// Fails with [`WalletError::Locked`] inside [`InboxError::Wallet`], and with
    /// [`InboxError::NetworkMismatch`] when the transport serves the other network.
    pub fn epicbox_address_at(
        &self,
        listing: &Listing,
        epicbox: &EpicboxTransport,
    ) -> Result<EpicboxAddress, InboxError> {
        Ok(self.listing_identity(listing, epicbox)?.address().clone())
    }

    /// Signs `message` for the app's `domain` with the key of `listing`'s address, under the
    /// listing-signature tag, which nothing else in the wallet signs under;
    /// [`lepic_epicbox::listing_message_verifies`] checks it with no wallet open. Domains of
    /// LEPIC's own cannot be made, and no other key signs here.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn sign_with_address_key_at(
        &self,
        listing: &Listing,
        domain: &ServiceDomain,
        message: &[u8],
    ) -> Result<EcdsaSignature, WalletError> {
        let session = self.session()?;
        let key = namespace::listing_key(&session.seed, listing)?;
        lepic_epicbox::sign_listing_message(domain, message, &key)
            .map_err(|error| WalletError::Keychain(error.into()))
    }

    /// The public key of `listing`'s address, which its signatures verify with.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn address_key_at(&self, listing: &Listing) -> Result<PublicKey, WalletError> {
        let session = self.session()?;
        let key = namespace::listing_key(&session.seed, listing)?;
        PublicKey::from_secret_key(&key).map_err(|error| WalletError::Keychain(error.into()))
    }

    /// Connects to the relay of `epicbox` as `listing`'s address once, handles every pending
    /// message there and disconnects, as [`Wallet::epicbox_drain`] does for the payments
    /// address, on its own connection: the payments listener and its attached identity are
    /// not touched, and no connection state is reported for it.
    ///
    /// An S1 is received into the default account, its transaction records the listing, and
    /// its S2 goes back from the listing's address. An S1 that asks for a payment proof is
    /// refused and nothing is signed for it. Notices are taken as on the payments address;
    /// any other slate is refused. Fails as [`Wallet::epicbox_drain`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn drain_epicbox_at(
        &self,
        listing: &Listing,
        epicbox: &EpicboxTransport,
    ) -> Result<InboxSummary, InboxError> {
        self.check_epicbox_registered()?;
        let identity = self.listing_identity(listing, epicbox)?;
        let route = ListingRoute {
            listing: *listing,
            client: epicbox.client_for(identity),
        };
        self.prune_relay_inbox().await;
        let subscription = route.client.drain().map_err(InboxError::Subscription)?;
        let consumed = self
            .consume(
                &subscription,
                None,
                backoff(epicbox),
                &PruneSchedule::default(),
                Some(&route),
            )
            .await;
        subscription
            .stop()
            .await
            .map_err(InboxError::Subscription)?;
        consumed
    }

    /// Signs `transcript` with this wallet's device-link key. Both devices of one phrase hold
    /// the same key, so [`Wallet::device_link_verify`] on either takes the other's signature.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn device_link_sign(&self, transcript: &[u8]) -> Result<[u8; 64], WalletError> {
        namespace::device_link_sign(&self.session()?.seed, transcript)
    }

    /// Whether `signature` is the device-link signature of `transcript` by this wallet's own
    /// device-link key, that is by a wallet of the same phrase.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn device_link_verify(
        &self,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<bool, WalletError> {
        let key = namespace::device_link_key(&self.session()?.seed)?.verifying_key();
        Ok(namespace::device_link_verifies(&key, transcript, signature))
    }

    fn listing_identity(
        &self,
        listing: &Listing,
        epicbox: &EpicboxTransport,
    ) -> Result<Identity, InboxError> {
        let network = relay_network(self.config().network);
        if epicbox.network() != network {
            return Err(InboxError::NetworkMismatch);
        }
        let secret = namespace::listing_key(&self.session()?.seed, listing)?;
        let public = PublicKey::from_secret_key(&secret)
            .map_err(|error| InboxError::Wallet(WalletError::Keychain(error.into())))?;
        let endpoint = &epicbox.settings().endpoint;
        let address = EpicboxAddress::new(
            public,
            network,
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        Identity::new(secret, address).map_err(InboxError::Identity)
    }

    /// The listing the received payment `tx_id` came in on, as stored.
    pub(super) async fn receive_listing_of(
        &self,
        tx_id: lepic_store::TxId,
    ) -> Result<Option<Listing>, Hold> {
        let session = self.session().map_err(Hold::from)?;
        let stored: Option<lepic_store::ReceiveListing> = self
            .blocking(move |_, _| Ok(session.store.read(|repos| repos.receive_listing(tx_id))?))
            .await
            .map_err(Hold::from)?;
        stored
            .as_ref()
            .map(Listing::from_stored)
            .transpose()
            .map_err(Hold::from)
    }

    /// [`Self::apply`] for a message at a listing: S1 slates and notices only.
    pub(super) async fn apply_at_listing(
        &self,
        msg_id: Option<&str>,
        envelope: &lepic_transport::transport::Envelope,
        attempt: u32,
        route: &ListingRoute,
    ) -> Result<super::Handled, Settlement> {
        let reply_to = envelope.reply_to().ok_or(Refusal::NoReplyAddress)?;
        let transport = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .ok_or(Hold::NoOutbound {
                transport: TRANSPORT_ID,
            })?;
        match notice::classify(envelope.wire()) {
            Payload::Slate => {}
            Payload::Notice(notice) => return Ok(self.take_notice(notice, reply_to).await?),
            Payload::Unknown | Payload::Oversize | Payload::Malformed => {
                return Ok(super::Handled::Dropped);
            }
        }
        let codecs = legacy_codecs(self.config().network).map_err(Hold::Receive)?;
        let slate = transport
            .policy()
            .decode(&codecs, envelope.wire())
            .map_err(Refusal::Decode)?;
        match slate.stage() {
            Stage::S1 => {
                self.answer(msg_id, attempt, envelope, &slate, reply_to, Some(route))
                    .await
            }
            stage => Err(Refusal::UnsupportedStage { stage }.into()),
        }
    }
}
