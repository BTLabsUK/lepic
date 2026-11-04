// SPDX-License-Identifier: Apache-2.0
//! Pairing with a contact over Epicbox (Way 1): a request carrying an invite of its own goes to
//! the contact's payments address, and the other wallet keeps it until its user answers or
//! dismisses it; and the standing invite the wallet shows to anyone.
//!
//! A request goes only to a key that ran LEPIC lately, never answered unmarked since, and
//! claimed pair requests: any other listener would never acknowledge it, and the relay drops a
//! whole queue after a few unacknowledged rounds. Each request has its own invite, which binds
//! the answer to the address the request went to. The receiving side keeps one request per
//! sender key, newer replacing older, stored before the relay message is acknowledged; it does
//! not know the address book, so the host decides which to show.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use jiff::Timestamp;
use lepic_contact::{ContactKind, Invite, PairingClass};
use lepic_epicbox::EpicboxAddress;
use lepic_epicbox::marker::features::PAIR_REQUESTS;
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{
    ContactId, ContactRecord, INVITE_ID_LEN, PAYMENTS_KEY_LEN, PairRequest, PairingRole,
    Repositories, StoreError, WalletStore,
};
use lepic_transport::transport::{Destination, Transport as _};
use lepic_wallet::Wallet;
use lepic_wallet::event::{Event, PairRequestNews};
use lepic_wallet::extension::PairRequests;
use lepic_wallet::inbox::relay_network;
use lepic_wallet::notice::{notice_length, pair_request_to};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use tracing::{debug, info, instrument, warn};

use super::keys::contact_network;
use super::pairing::{InviteExpiry, InviteOffer, InviteRequest};
use super::{CLOCK_SKEW, ContactError, ContactRelays, LockedRng};
use crate::ContactBook;

/// Live requests kept at once; the oldest goes first.
pub const MAX_LIVE_REQUESTS: usize = 20;

/// Dismissed and answered requests remembered at once, to drop a replay; the oldest goes first.
pub const MAX_SETTLED_REQUESTS: usize = 100;

/// How long a request's or the standing invite's invite lasts.
pub const REQUEST_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A standing invite with less than this left is replaced.
const STANDING_RENEW: Duration = Duration::from_secs(24 * 60 * 60);

/// The setting that names the standing invite's pairing.
pub(crate) const STANDING_KEY: &str = "pairing.standing";

/// A stored request, as the host shows it. Holds no key; its `Debug` leaves the link out.
#[derive(Clone, PartialEq, Eq)]
pub struct PairRequestView {
    /// The request's invite id, which [`ContactBook::pairing_request_dismiss`] takes.
    pub request_id: [u8; INVITE_ID_LEN],
    /// The sender's payments address, as the relay authenticated it.
    pub from_address: String,
    /// The name the invite gives its maker, unverified.
    pub claimed_name: String,
    pub kind: ContactKind,
    pub received_at: Timestamp,
    pub expires_at: Timestamp,
    /// The `epiccash://pair/1/...` invite, to answer with [`ContactBook::pairing_accept`].
    pub invite_link: String,
}

impl fmt::Debug for PairRequestView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairRequestView")
            .field("received_at", &self.received_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The engine's hook for pairing requests to the payments address.
pub(crate) struct StoredRequests;

impl<N, S, V> PairRequests<N, S, V> for StoredRequests
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn take<'a>(
        &'a self,
        wallet: &'a Wallet<N, S, V>,
        sender: &'a str,
        invite_link: String,
    ) -> BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            use crate::WalletContacts;
            wallet
                .contact_book()
                .take_pair_request(sender, &invite_link)
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

pub(crate) fn install_requests<N, S, V>(wallet: &Wallet<N, S, V>)
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    wallet.set_pair_requests(Arc::new(StoredRequests));
}

fn timestamp(seconds: u64) -> Timestamp {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| Timestamp::from_second(seconds).ok())
        .unwrap_or(Timestamp::MAX)
}

/// The 33-byte key of the Epicbox address `address` on `network`.
pub(crate) fn address_key(
    address: &str,
    network: lepic_primitives::params::Network,
) -> Result<[u8; PAYMENTS_KEY_LEN], ContactError> {
    EpicboxAddress::parse(address, relay_network(network))
        .map(|address| address.public_key().to_bytes())
        .map_err(|_| ContactError::RelayAddress)
}

/// Whether a pairing with the key `key` is live: stored and not ended.
pub(crate) fn live_pairing_with(
    repos: &dyn Repositories,
    key: &[u8; PAYMENTS_KEY_LEN],
) -> Result<bool, StoreError> {
    Ok(repos
        .contacts_by_payments_key(key)?
        .iter()
        .any(|record| record.facts.ended_reason.is_none()))
}

/// The unheard records whose proven key is `key`: pairings whose contact did not answer yet.
fn unheard_with(
    repos: &dyn Repositories,
    key: &[u8; PAYMENTS_KEY_LEN],
) -> Result<Vec<ContactRecord>, StoreError> {
    Ok(repos
        .contacts_by_payments_key(key)?
        .into_iter()
        .filter(|record| {
            record.facts.ended_reason.is_none() && record.facts.peer_heard_at.is_none()
        })
        .collect())
}

/// Drops the oldest requests past the bounds, and those whose invite expired at `now`.
fn bound_requests(repos: &mut dyn Repositories, now: Timestamp) -> Result<(), StoreError> {
    let mut live = Vec::new();
    let mut settled = Vec::new();
    for request in repos.pair_requests()? {
        if request
            .expires_at
            .checked_add(CLOCK_SKEW)
            .unwrap_or(Timestamp::MAX)
            <= now
        {
            repos.delete_pair_request(&request.sender_key)?;
        } else if request.live() {
            live.push(request);
        } else {
            settled.push(request);
        }
    }
    for (group, cap) in [(live, MAX_LIVE_REQUESTS), (settled, MAX_SETTLED_REQUESTS)] {
        let over = group.len().saturating_sub(cap);
        for request in group.into_iter().take(over) {
            repos.delete_pair_request(&request.sender_key)?;
        }
    }
    Ok(())
}

/// What became of a request that arrived.
enum Arrived {
    Stored([u8; INVITE_ID_LEN]),
    Dropped,
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes a pairing request from `sender`, the address the relay authenticated: it is kept,
    /// or dropped when its invite is expired or of another network, when a live pairing with
    /// the sender's key exists, when its invite was dismissed or answered here, or when it is not
    /// newer than the request kept from that key. A kept one raises
    /// [`Event::PairingRequested`].
    pub(crate) async fn take_pair_request(
        &self,
        sender: &str,
        invite_link: &str,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let Ok(sender_key) = address_key(sender, network) else {
            return Ok(());
        };
        let Ok(invite) = Invite::from_link(invite_link, contact_network(network)) else {
            debug!("pairing request with an invite not for this network dropped");
            return Ok(());
        };
        if invite.class() != PairingClass::Contact {
            return Ok(());
        }
        let sender = sender.to_owned();
        let address = sender.clone();
        let session = self.wallet.session()?;
        let arrived = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    bound_requests(repos, now)?;
                    let expires_at = timestamp(invite.fields().expires);
                    let invite_id = *invite.id().as_bytes();
                    if expires_at.checked_add(CLOCK_SKEW).unwrap_or(Timestamp::MAX) <= now
                        || live_pairing_with(repos, &sender_key)?
                        || repos
                            .pair_request_by_invite(&invite_id)?
                            .is_some_and(|known| !known.live() || known.sender_key != sender_key)
                    {
                        return Ok::<_, StoreError>(Arrived::Dropped);
                    }
                    if repos
                        .pair_request(&sender_key)?
                        .is_some_and(|kept| kept.expires_at >= expires_at)
                    {
                        return Ok(Arrived::Dropped);
                    }
                    repos.put_pair_request(&PairRequest {
                        sender_key,
                        sender_address: sender.clone(),
                        invite_id,
                        invite: invite.as_bytes().to_vec(),
                        expires_at,
                        received_at: now,
                        dismissed_at: None,
                        answered_at: None,
                    })?;
                    bound_requests(repos, now)?;
                    Ok(Arrived::Stored(invite_id))
                })?)
            })
            .await?;
        match arrived {
            Arrived::Stored(request_id) => {
                info!("pairing request stored");
                self.wallet.emit(Event::PairingRequested(PairRequestNews {
                    request_id,
                    sender: address,
                }));
            }
            Arrived::Dropped => debug!("pairing request dropped"),
        }
        Ok(())
    }

    /// The live pairing requests, oldest first: neither dismissed, answered nor expired.
    pub async fn pairing_requests(&self) -> Result<Vec<PairRequestView>, ContactError> {
        let net = contact_network(self.wallet.config().network);
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for request in repos.pair_requests()? {
                    if !request.live() || request.expires_at <= now {
                        continue;
                    }
                    let Ok(invite) = Invite::decode(&request.invite, net) else {
                        continue;
                    };
                    views.push(PairRequestView {
                        request_id: request.invite_id,
                        from_address: request.sender_address,
                        claimed_name: invite.fields().name.as_str().to_owned(),
                        kind: invite.fields().kind,
                        received_at: request.received_at,
                        expires_at: request.expires_at,
                        invite_link: invite.to_link(),
                    });
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }

    /// Hides the live request `request_id`. Its invite id is remembered until the invite
    /// expires, so a copy of it is dropped; a newer request from the same key shows again.
    ///
    /// Fails with [`ContactError::UnknownPairing`] when no live request has that id.
    pub async fn pairing_request_dismiss(
        &self,
        request_id: [u8; INVITE_ID_LEN],
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                let mut request = repos
                    .pair_request_by_invite(&request_id)?
                    .filter(PairRequest::live)
                    .ok_or(ContactError::UnknownPairing)?;
                request.dismissed_at = Some(now);
                repos.put_pair_request(&request)?;
                bound_requests(repos, now)?;
                Ok(())
            })
        })
        .await
    }

    /// Sends a pairing request to the contact at `to_address`: a new invite of its own, good
    /// for seven days, which only the wallet holding that address can answer, posted from the
    /// payments address. The invite is kept only when the post went through.
    ///
    /// Fails with [`ContactError::PeerNotProven`] unless the key ran LEPIC lately, answered
    /// nothing unmarked since and claimed pair requests; with [`ContactError::AlreadyPaired`]
    /// for a live pairing with that key; with [`ContactError::PairingInProgress`] for a pairing
    /// in progress with it, one waiting for it, or a live request from it; with
    /// [`ContactError::Offline`] or [`ContactError::EpicboxOff`]; and with
    /// [`ContactError::Relay`] when the post failed, with nothing kept.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_request_send(
        &self,
        relays: &ContactRelays,
        account: lepic_store::AccountIndex,
        to_address: &str,
        name: &str,
    ) -> Result<InviteOffer, ContactError> {
        self.check_contact_network(relays)?;
        super::relay::check_online(relays)?;
        let network = self.wallet.config().network;
        let key = address_key(to_address, network)?;
        let facts = self
            .wallet
            .peer_compat(to_address)
            .map_err(|_| ContactError::RelayAddress)?;
        let claims = facts
            .stored
            .is_some_and(|stored| stored.claimed & PAIR_REQUESTS != 0);
        if !facts.fresh || !claims {
            return Err(ContactError::PeerNotProven);
        }
        let session = self.wallet.session()?;
        {
            let session = Arc::clone(&session);
            self.contact_work(move |_, _| {
                session.store.read(|repos| check_free(repos, &key, true))
            })
            .await?;
        }
        let offer = self
            .pairing_invite(
                relays,
                InviteRequest {
                    account,
                    name: name.to_owned(),
                    kind: ContactKind::Person,
                    expiry: InviteExpiry::SevenDays,
                    offer_words: false,
                    home_relay: None,
                    class: PairingClass::Contact,
                    expect_address: Some(to_address.to_owned()),
                },
            )
            .await?;
        let length = notice_length(&mut LockedRng(&mut **self.wallet.ports().rng.lock()));
        let text = pair_request_to(&offer.link, length);
        let posted = match relays.epicbox.outbound() {
            Some(outbound) => outbound
                .deliver(
                    &Destination::new(to_address.to_owned()),
                    &WireSlate::text(MediaType::JSON, text),
                )
                .await
                .map_err(ContactError::Post),
            None => Err(ContactError::EpicboxOff),
        };
        if let Err(error) = posted {
            warn!(error = %ErrorChain(&error), "pairing request not posted");
            self.contact_remove(offer.contact_id).await?;
            return Err(error);
        }
        // An answer to it shows that pair requests work with the key.
        let contact_id = offer.contact_id;
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                repos.put_setting(&super::pairing::request_out_key(contact_id), "1")
            })?)
        })
        .await?;
        info!("pairing request sent");
        Ok(offer)
    }

    /// The live standing invite, made anew when there is none, when it was answered, when less
    /// than a day is left, when its relay is not the wallet's relay now, or when it carries
    /// another name than `name`. On a name change the old one is withdrawn as
    /// [`ContactBook::pairing_cancel`] does; otherwise it stays valid until it expires and is
    /// simply no longer standing. Sends nothing.
    ///
    /// Fails with [`ContactError::Name`] for a name the card cannot carry, and as
    /// [`ContactBook::pairing_invite`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_standing_invite(
        &self,
        relays: &ContactRelays,
        account: lepic_store::AccountIndex,
        name: &str,
    ) -> Result<InviteOffer, ContactError> {
        lepic_contact::ContactName::new(name).map_err(ContactError::Name)?;
        let net = contact_network(self.wallet.config().network);
        let relay = super::relay::host_text(&relays.epicbox.settings().endpoint);
        let session = self.wallet.session()?;
        let name_owned = name.to_owned();
        let current = {
            let session = Arc::clone(&session);
            self.contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.read(|repos| {
                    let Some(id) = standing_id(repos)? else {
                        return Ok::<_, StoreError>(Standing::None);
                    };
                    let pairing = repos.pending_pairing(super::pairing_id_of(id))?;
                    let record = repos.contact(id)?;
                    let (Some(pairing), Some(record)) = (pairing, record) else {
                        return Ok(Standing::None);
                    };
                    let Ok(invite) = Invite::decode(&pairing.invite, net) else {
                        return Ok(Standing::None);
                    };
                    let answered = record.peer.is_some() || pairing.cancelled_at.is_some();
                    let renew = pairing
                        .expires_at
                        .checked_sub(STANDING_RENEW)
                        .is_ok_and(|due| due <= now);
                    let home = super::manage::home_host(invite.fields().home_relay.as_str());
                    if invite.fields().name.as_str() != name_owned {
                        return Ok(Standing::Renamed(id));
                    }
                    if answered || renew || home != relay {
                        return Ok(Standing::None);
                    }
                    Ok(Standing::Live(InviteOffer {
                        contact_id: id,
                        link: invite.to_link(),
                        expires_at: pairing.expires_at,
                        words: None,
                    }))
                })?)
            })
            .await?
        };
        match current {
            Standing::Live(offer) => return Ok(offer),
            Standing::Renamed(old) => {
                self.pairing_cancel(old).await?;
            }
            Standing::None => {}
        }
        let offer = self
            .pairing_invite(
                relays,
                InviteRequest {
                    account,
                    name: name.to_owned(),
                    kind: ContactKind::Person,
                    expiry: InviteExpiry::SevenDays,
                    offer_words: false,
                    home_relay: None,
                    class: PairingClass::Contact,
                    expect_address: None,
                },
            )
            .await?;
        let id = offer.contact_id;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .write(|repos| repos.put_setting(STANDING_KEY, &id.to_string()))?)
        })
        .await?;
        info!("standing invite made");
        Ok(offer)
    }
}

/// Where the standing invite stands.
enum Standing {
    None,
    Live(InviteOffer),
    /// It carries another name: withdraw it.
    Renamed(ContactId),
}

/// The standing invite's record id, if one is named.
pub(crate) fn standing_id(repos: &dyn Repositories) -> Result<Option<ContactId>, StoreError> {
    Ok(repos
        .setting(STANDING_KEY)?
        .and_then(|text| crate::hex::decode_array(&text).ok())
        .map(ContactId))
}

/// Refuses a new pairing with the key `key` while one is live, in progress or waiting, or,
/// with `requests`, while a live request from it waits here.
pub(crate) fn check_free(
    repos: &dyn Repositories,
    key: &[u8; PAYMENTS_KEY_LEN],
    requests: bool,
) -> Result<(), ContactError> {
    if repos
        .contacts_by_payments_key(key)?
        .iter()
        .any(|record| record.facts.ended_reason.is_none() && record.facts.peer_heard_at.is_some())
    {
        return Err(ContactError::AlreadyPaired);
    }
    let pending = repos
        .pending_pairings()?
        .into_iter()
        .any(|pending| pending.cancelled_at.is_none() && pending.expect_key.as_ref() == Some(key));
    let request = requests
        && repos
            .pair_request(key)?
            .is_some_and(|request| request.live());
    if pending || request || !unheard_with(repos, key)?.is_empty() {
        return Err(ContactError::PairingInProgress);
    }
    Ok(())
}

/// The other wallet of a pairing with the key `theirs` made the invite that survives two
/// crossed pairings when its key is the lower one.
pub(crate) fn theirs_survives(
    ours: &[u8; PAYMENTS_KEY_LEN],
    theirs: &[u8; PAYMENTS_KEY_LEN],
) -> bool {
    theirs < ours
}

/// Our own request still out to the key `key`: an invite of ours that expects its proof.
pub(crate) fn own_request_to(
    repos: &dyn Repositories,
    key: &[u8; PAYMENTS_KEY_LEN],
) -> Result<Option<ContactId>, StoreError> {
    Ok(repos
        .pending_pairings()?
        .into_iter()
        .find(|pending| {
            pending.role == PairingRole::Inviter
                && pending.cancelled_at.is_none()
                && pending.expect_key.as_ref() == Some(key)
        })
        .map(|pending| pending.contact_id))
}

/// Marks the request whose invite is `invite_id` answered; `InviteDismissed` when it was
/// dismissed here.
pub(crate) fn answer_request(
    repos: &mut dyn Repositories,
    invite_id: &[u8; INVITE_ID_LEN],
    now: Timestamp,
) -> Result<(), ContactError> {
    let Some(mut request) = repos.pair_request_by_invite(invite_id)? else {
        return Ok(());
    };
    if request.dismissed_at.is_some() {
        return Err(ContactError::InviteDismissed);
    }
    if request.answered_at.is_none() {
        request.answered_at = Some(now);
        repos.put_pair_request(&request)?;
    }
    Ok(())
}
