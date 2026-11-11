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
use lepic_methods::epicbox::{NOTICE_LENGTHS, relay_network};
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{
    ContactId, ContactRecord, INVITE_ID_LEN, PAYMENTS_KEY_LEN, PairRequest, PairingRole,
    Repositories, StoreError, WalletStore,
};
use lepic_transport::marker::features::PAIR_REQUESTS;
use lepic_transport::method::Method;
use lepic_transport::transport::{Destination, Transport as _};
use lepic_wallet::Wallet;
use lepic_wallet::event::{Event, PairRequestNews};
use lepic_wallet::extension::PairRequests;
use lepic_wallet::notice::{notice_length, pair_request_to};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use tracing::{debug, info, instrument, warn};

use super::keys::contact_network;
use super::manage::PendingPairingView;
use super::pairing::{InviteExpiry, InviteOffer, InviteRequest};
use super::{CLOCK_SKEW, ContactError, ContactRelays, LockedRng};
use crate::{ContactBook, hex};

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
    /// Deprecated: always written for wallets that read it, never to be read for meaning;
    /// to be removed (docs/adr/0041 or RFC 0002 6.1).
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
    /// Kept under its invite id; `ended` are the pairings with its sender it ended.
    Stored {
        request_id: [u8; INVITE_ID_LEN],
        ended: Vec<ContactId>,
    },
    Dropped(Dropped),
}

/// Why a request that arrived was dropped, as the log names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropped {
    /// Its invite expired.
    Expired,
    /// Its invite was dismissed or answered here, or came from another sender before.
    Settled,
    /// It is the request kept from that sender, again.
    Replayed,
    /// The request kept from that sender is newer.
    Older,
    /// A pairing with the sender is live and the request cannot say it ended: the contact was
    /// not heard from yet, or the request does not postdate the pairing.
    LivePairing,
}

impl Dropped {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Settled => "settled",
            Self::Replayed => "replayed",
            Self::Older => "older",
            Self::LivePairing => "live_pairing",
        }
    }
}

/// Whether the request kept from a sender stays when `invite_id`, expiring at `expires_at`,
/// arrives from that sender, and why. A kept request that is not live gives way to any request
/// that is not older; a live one to another request that is not older.
fn kept_stays(
    kept: &PairRequest,
    invite_id: &[u8; INVITE_ID_LEN],
    expires_at: Timestamp,
) -> Option<Dropped> {
    if kept.live() && kept.invite_id == *invite_id {
        Some(Dropped::Replayed)
    } else if kept.expires_at > expires_at {
        Some(Dropped::Older)
    } else {
        None
    }
}

/// The live pairings with `key` that a request from that key, expiring at `expires_at`, ends;
/// `Err` when one of them it cannot end: a pairing whose contact was not heard from yet, or one
/// the request does not postdate (an old request a relay delivers again).
///
/// A pairing with a request from `key` known to be older (see [`remember_request`]) is
/// postdated by a request that expires later than that one, or in the same second with another
/// invite: both times come from the sender's clock, so how far it is from ours does not matter.
/// Any other pairing is postdated by a request issued no earlier than the pairing was made by
/// our clock.
///
/// The relay delivers a request only under a signature by `key` and sealed to us with a key
/// agreement only `key` can make, so a request from `key` says its holder dropped the pairing.
fn pairings_ended_by(
    repos: &dyn Repositories,
    key: &[u8; PAYMENTS_KEY_LEN],
    invite_id: &[u8; INVITE_ID_LEN],
    expires_at: Timestamp,
) -> Result<Result<Vec<ContactId>, Dropped>, StoreError> {
    let issued_at = expires_at
        .checked_sub(REQUEST_EXPIRY)
        .unwrap_or(Timestamp::MIN);
    let mut ended = Vec::new();
    for record in repos.contacts_by_payments_key(key)? {
        if record.facts.ended_reason.is_some() {
            continue;
        }
        let postdates = match request_before(repos, record.contact_id)? {
            Some((seconds, older_invite)) => {
                expires_at.as_second() > seconds
                    || (expires_at.as_second() == seconds && *invite_id != older_invite)
            }
            None => record.created_at.as_second() <= issued_at.as_second(),
        };
        if record.facts.peer_heard_at.is_none() || !postdates {
            return Ok(Err(Dropped::LivePairing));
        }
        ended.push(record.contact_id);
    }
    Ok(Ok(ended))
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes a pairing request from `sender`, the address the relay authenticated: it is kept,
    /// or dropped when its invite is expired or of another network, when its invite was
    /// dismissed or answered here, when it is the live request kept from that key again, or
    /// when it is older than the request kept from that key. A request from the key of a live
    /// pairing says the contact dropped it: the pairing ends as unpaired, raising
    /// [`Event::ContactUnpaired`], unless the contact was not heard from yet or the request
    /// does not postdate the pairing (see [`pairings_ended_by`]), and is then dropped. A kept
    /// one raises [`Event::PairingRequested`].
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
                    if expires_at.checked_add(CLOCK_SKEW).unwrap_or(Timestamp::MAX) <= now {
                        return Ok::<_, StoreError>(Arrived::Dropped(Dropped::Expired));
                    }
                    if repos
                        .pair_request_by_invite(&invite_id)?
                        .is_some_and(|known| !known.live() || known.sender_key != sender_key)
                    {
                        return Ok(Arrived::Dropped(Dropped::Settled));
                    }
                    if let Some(why) = repos
                        .pair_request(&sender_key)?
                        .and_then(|kept| kept_stays(&kept, &invite_id, expires_at))
                    {
                        return Ok(Arrived::Dropped(why));
                    }
                    let ended = match pairings_ended_by(repos, &sender_key, &invite_id, expires_at)?
                    {
                        Ok(ended) => ended,
                        Err(why) => return Ok(Arrived::Dropped(why)),
                    };
                    for contact_id in &ended {
                        super::manage::end_as_unpaired(repos, *contact_id, now)?;
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
                    Ok(Arrived::Stored {
                        request_id: invite_id,
                        ended,
                    })
                })?)
            })
            .await?;
        match arrived {
            Arrived::Stored { request_id, ended } => {
                if !ended.is_empty() {
                    info!(
                        count = ended.len(),
                        "pairing request from a paired contact ended its pairing"
                    );
                }
                for contact_id in ended {
                    self.emit_unpaired(contact_id);
                }
                info!("pairing request stored");
                self.wallet.emit(Event::PairingRequested(PairRequestNews {
                    request_id,
                    sender: address,
                }));
            }
            Arrived::Dropped(why) => info!(reason = why.as_str(), "pairing request dropped"),
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
        let method: Arc<dyn Method> = Arc::new(relays.epicbox.clone());
        let facts = self
            .wallet
            .peer_compat(&method, to_address)
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
                    home_relay: None,
                    class: PairingClass::Contact,
                    expect_address: Some(to_address.to_owned()),
                },
            )
            .await?;
        let length = notice_length(
            &NOTICE_LENGTHS,
            &mut LockedRng(&mut **self.wallet.ports().rng.lock()),
        );
        let text = pair_request_to(&offer.link, &NOTICE_LENGTHS, length);
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

    /// The pairing requests this wallet sent that wait for an answer, oldest first. Each is a
    /// pairing in progress; [`ContactBook::pairing_request_cancel`] withdraws one.
    pub async fn pairing_requests_sent(&self) -> Result<Vec<PendingPairingView>, ContactError> {
        let pending = self.pairings_pending().await?;
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                let mut sent = Vec::new();
                for view in pending {
                    if repos
                        .setting(&super::pairing::request_out_key(view.contact_id))?
                        .is_some()
                    {
                        sent.push(view);
                    }
                }
                Ok::<_, StoreError>(sent)
            })?)
        })
        .await
    }

    /// Withdraws a pairing request this wallet sent and nobody answered: the marker goes and
    /// the invite is cancelled as [`ContactBook::pairing_cancel`] does, so a late answer is
    /// refused and a new request to the same address may be sent.
    ///
    /// Fails with [`ContactError::UnknownPairing`] when `contact_id` is not a sent request
    /// still waiting.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_request_cancel(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let known = self
            .contact_work(move |_, _| {
                Ok(session.store.write(|repos| {
                    let key = super::pairing::request_out_key(contact_id);
                    let waiting = repos.setting(&key)?.is_some()
                        && repos
                            .pending_pairing(super::pairing_id_of(contact_id))?
                            .is_some_and(|pending| {
                                pending.role == PairingRole::Inviter
                                    && pending.cancelled_at.is_none()
                            })
                        && repos
                            .contact(contact_id)?
                            .is_some_and(|record| record.peer.is_none());
                    if waiting {
                        repos.delete_setting(&key)?;
                    }
                    Ok::<_, StoreError>(waiting)
                })?)
            })
            .await?;
        if !known {
            return Err(ContactError::UnknownPairing);
        }
        self.pairing_cancel(contact_id).await?;
        info!("pairing request cancelled");
        Ok(())
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

/// Marks the request whose invite is `invite_id` answered, and returns when its invite expires
/// by its sender's clock; `None` when no request has that invite, and `InviteDismissed` when it
/// was dismissed here.
pub(crate) fn answer_request(
    repos: &mut dyn Repositories,
    invite_id: &[u8; INVITE_ID_LEN],
    now: Timestamp,
) -> Result<Option<Timestamp>, ContactError> {
    let Some(mut request) = repos.pair_request_by_invite(invite_id)? else {
        return Ok(None);
    };
    if request.dismissed_at.is_some() {
        return Err(ContactError::InviteDismissed);
    }
    if request.answered_at.is_none() {
        request.answered_at = Some(now);
        repos.put_pair_request(&request)?;
    }
    Ok(Some(request.expires_at))
}

/// The setting beside the pairing record `contact_id` that holds a request from the contact
/// known to be older than the pairing: when that expires, in unix seconds by the clock of its
/// sender, a dot, and its invite id in hex.
fn request_key(contact_id: ContactId) -> String {
    lepic_store::contact_extra_key(contact_id, REQUEST_NAME)
}

const REQUEST_NAME: &str = "request_before_pairing";

/// Records that the request with `invite_id`, expiring at `expires_at` by its sender's clock,
/// is older than the pairing record `contact_id`: the record answered it, or it was here when
/// the pairing finished. The store drops it with the record.
pub(crate) fn remember_request(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    invite_id: &[u8; INVITE_ID_LEN],
    expires_at: Timestamp,
) -> Result<(), StoreError> {
    let value = format!("{}.{}", expires_at.as_second(), hex::encode(invite_id));
    repos.put_setting(&request_key(contact_id), &value)
}

/// When a pairing with a proven payments key finishes without a request it answered, records
/// the request kept from that key, if any, as older than the pairing: it arrived before the
/// pairing finished, so its sender signed it before. A pairing made from an invite link or in
/// person then compares a later request with it by the sender's clock alone.
pub(crate) fn remember_held_request(
    repos: &mut dyn Repositories,
    record: &ContactRecord,
) -> Result<(), StoreError> {
    let Some(key) = record.facts.payments_key else {
        return Ok(());
    };
    if repos.setting(&request_key(record.contact_id))?.is_some() {
        return Ok(());
    }
    match repos.pair_request(&key)? {
        Some(held) => remember_request(repos, record.contact_id, &held.invite_id, held.expires_at),
        None => Ok(()),
    }
}

/// The request from the contact known to be older than the pairing record `contact_id`: when
/// it expires by its sender's clock, and its invite id.
fn request_before(
    repos: &dyn Repositories,
    contact_id: ContactId,
) -> Result<Option<(i64, [u8; INVITE_ID_LEN])>, StoreError> {
    Ok(repos.setting(&request_key(contact_id))?.and_then(|value| {
        let (seconds, invite_id) = value.split_once('.')?;
        Some((
            seconds.parse::<i64>().ok()?,
            hex::decode_array::<INVITE_ID_LEN>(invite_id).ok()?,
        ))
    }))
}

#[cfg(test)]
mod tests {
    use lepic_store::{AccountIndex, ContactState, MemoryStore, PairingFacts, SealMode, StoreKeys};

    use super::*;

    const KEY: [u8; PAYMENTS_KEY_LEN] = [7; PAYMENTS_KEY_LEN];

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    /// A live pairing with `KEY`, heard from, made at `created_at` by our clock.
    fn paired(created_at: Timestamp) -> ContactRecord {
        ContactRecord {
            contact_id: ContactId([1; 16]),
            account: AccountIndex(0),
            slot: 0,
            box_salt: [0; 16],
            own_card: Vec::new(),
            peer: None,
            alternate: None,
            label: String::new(),
            state: ContactState::Verified,
            sas: None,
            verified_at: None,
            allow_invoices: false,
            seal: SealMode::On,
            last_sealed_in: None,
            app_contact: None,
            imported_from_backup: false,
            created_at,
            updated_at: created_at,
            facts: PairingFacts {
                payments_address: Some("key@relay.example".to_owned()),
                payments_key: Some(KEY),
                peer_heard_at: Some(created_at),
                ..PairingFacts::default()
            },
        }
    }

    fn ends(store: &MemoryStore, invite_id: u8, expires_at: Timestamp) -> bool {
        store
            .read(|repos| pairings_ended_by(repos, &KEY, &[invite_id; INVITE_ID_LEN], expires_at))
            .unwrap()
            .is_ok()
    }

    /// A pairing made by answering a request is ended by a later request from the same
    /// sender, however far the sender's clock is behind ours, and never by the answered
    /// request again or one before it.
    #[test]
    fn an_answered_pairing_compares_the_senders_own_times() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let day = i64::try_from(REQUEST_EXPIRY.as_secs()).unwrap() / 7;
        // Our clock says day 100; the sender's says day 10.
        let record = paired(at(100 * day));
        let answered = at(10 * day) + REQUEST_EXPIRY;
        store
            .write(|repos| {
                repos.put_contact(&record)?;
                remember_request(repos, record.contact_id, &[2; INVITE_ID_LEN], answered)
            })
            .unwrap();

        assert!(ends(&store, 3, answered + Duration::from_secs(1)));
        assert!(
            ends(&store, 3, answered),
            "another request in the same second"
        );
        assert!(!ends(&store, 2, answered), "the answered request again");
        assert!(!ends(&store, 3, answered - Duration::from_secs(1)));
    }

    /// A pairing that finished while a request from its contact was here (an invite-link
    /// pairing) takes that request as older: a later one ends it whatever the clocks, the held
    /// one again does not.
    #[test]
    fn a_held_request_is_older_than_the_pairing_it_was_here_for() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        // Our clock says day 100; the sender's, day 10.
        let day = i64::try_from(REQUEST_EXPIRY.as_secs()).unwrap() / 7;
        let record = paired(at(100 * day));
        let held = at(10 * day) + REQUEST_EXPIRY;
        store
            .write(|repos| {
                repos.put_pair_request(&PairRequest {
                    sender_key: KEY,
                    sender_address: "key@relay.example".to_owned(),
                    invite_id: [2; INVITE_ID_LEN],
                    invite: Vec::new(),
                    expires_at: held,
                    received_at: at(100 * day),
                    dismissed_at: None,
                    answered_at: None,
                })?;
                repos.put_contact(&record)?;
                remember_held_request(repos, &record)
            })
            .unwrap();

        assert!(ends(&store, 3, held + Duration::from_secs(1)));
        assert!(!ends(&store, 2, held), "the held request again");
        assert!(!ends(&store, 3, held - Duration::from_secs(1)));
    }

    /// A request the pairing answered stays the one compared with.
    #[test]
    fn an_answered_request_is_not_replaced_by_a_held_one() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let record = paired(at(1_000_000));
        let answered = at(2_000_000);
        store
            .write(|repos| {
                repos.put_contact(&record)?;
                remember_request(repos, record.contact_id, &[2; INVITE_ID_LEN], answered)?;
                repos.put_pair_request(&PairRequest {
                    sender_key: KEY,
                    sender_address: "key@relay.example".to_owned(),
                    invite_id: [4; INVITE_ID_LEN],
                    invite: Vec::new(),
                    expires_at: at(1_500_000),
                    received_at: at(1_000_000),
                    dismissed_at: None,
                    answered_at: None,
                })?;
                remember_held_request(repos, &record)
            })
            .unwrap();

        assert!(!ends(&store, 3, at(1_600_000)));
        assert!(ends(&store, 3, answered + Duration::from_secs(1)));
    }

    /// Without a request known to be older the pairing's own time decides, as before.
    #[test]
    fn another_pairing_compares_its_creation_with_the_request() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let record = paired(at(1_000_000));
        store.write(|repos| repos.put_contact(&record)).unwrap();

        assert!(ends(&store, 3, record.created_at + REQUEST_EXPIRY));
        assert!(!ends(
            &store,
            3,
            record.created_at + REQUEST_EXPIRY - Duration::from_secs(1)
        ));
    }
}
