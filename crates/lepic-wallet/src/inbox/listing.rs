// SPDX-License-Identifier: Apache-2.0
//! Listing addresses: addresses of keys from the LEPIC namespace, one per listing with a name
//! service, apart from the payments address. A method drains a listing's mailbox on its own
//! connection, never through the payments listener; what arrives there is answered from the
//! listing's address and recorded with the listing.
//!
//! Only S1 slates and notices are taken at a listing. A payment that asks for a payment proof is
//! refused, so nothing about it is ever signed by the payments key. The app passes only the
//! service key and the generation; no secret, signature over a LEPIC domain, or ECDH value
//! leaves the wallet except the listing's own key, to the method that receives under it.

use std::sync::Arc;

use lepic_crypto::PublicKey;
use lepic_node::NodeApi;
use lepic_slate::stage::Stage;
use lepic_store::WalletStore;
use lepic_transport::method::Method;

use super::{Hold, Refusal, Settlement};
use crate::error::WalletError;
use crate::namespace::{self, Listing};
use crate::notice::{self, Payload};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The public key of `listing`'s address, which its signatures verify with.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn address_key_at(&self, listing: &Listing) -> Result<PublicKey, WalletError> {
        let session = self.session()?;
        let key = namespace::listing_key(&session.seed, listing)?;
        PublicKey::from_secret_key(&key).map_err(|error| WalletError::Keychain(error.into()))
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

    /// [`Self::apply`] for a message at `listing`: S1 slates and notices only.
    pub(super) async fn apply_at_listing(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        envelope: &lepic_transport::transport::Envelope,
        attempt: u32,
        listing: Listing,
    ) -> Result<super::Handled, Settlement> {
        let reply_to = envelope.reply_to().ok_or(Refusal::NoReplyAddress)?;
        match notice::classify(envelope.wire()) {
            Payload::Slate => {}
            Payload::Notice(notice) => {
                return Ok(self.notice_arrived(method, reply_to, notice).await?);
            }
            Payload::Unknown | Payload::Oversize | Payload::Malformed => {
                return Ok(super::Handled::Dropped);
            }
        }
        let slate = method
            .decode(self.config().network, envelope.wire())
            .map_err(Refusal::Decode)?;
        match slate.stage() {
            Stage::S1 => {
                self.answer(
                    method,
                    msg_id,
                    attempt,
                    envelope,
                    &slate,
                    reply_to,
                    Some(listing),
                    None,
                )
                .await
            }
            stage => Err(Refusal::UnsupportedStage { stage }.into()),
        }
    }
}
