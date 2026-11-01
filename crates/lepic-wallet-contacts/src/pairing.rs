// SPDX-License-Identifier: Apache-2.0
//! The pairing flows (RFC 0002 7.1 to 7.6): invites, replies, confirms, pairing in person and
//! the SAS check.

use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{
    ChannelKey, PairingClass, PrivateSecret, open_private_confirm, open_private_reply, private_sas,
    seal_private_confirm, seal_private_refusal, seal_private_reply,
};
use lepic_contact::{
    Commitment, Confirm, ConfirmBody, ConfirmCode, ContactCard, ContactKind, Invite, InviteFields,
    InviteId, Nonce, PairingCode, PairingExtras, PairingLink, ReplyBody, Sas, SealedEnvelope,
    open_confirm_with, open_reply_with, pairing_envelope_from_link, pairing_envelope_link,
    seal_confirm_with_extras, seal_reply_with,
};
use lepic_contact::{ContactName, Refusal, RelayHost, seal_refusal};
use lepic_epicbox::{EpicboxAddress, Identity, RelayEndpoint};
use lepic_node::NodeApi;
use lepic_store::{
    AccountIndex, ContactId, ContactMailbox, ContactRecord, ContactState, PairingId, PairingRole,
    PairingSecrets, PairingState, PeerCard, PendingPairing, Repositories, SealMode, StoreError,
    WalletStore,
};
use tracing::{debug, info, instrument, warn};

use super::address_proof::{
    Payments, ProofBinding, ProofStep, ProvenAddress, invite_mailbox_key, mailbox_key, proven,
};
use super::keys::{
    CardDetails, box_identity, contact_keys, contact_network, enc_secret, our_card,
    pairing_mailbox, signing_key,
};
use super::private::{PrivateSecrets, RecordClass, class_of, record_keys};
use super::relay::{endpoint_for, host_text, post_envelope};
use super::{
    CLOCK_SKEW, CONFIRM_WAIT, ContactError, ContactRelays, ContactView, LATE_DRAIN_WAIT, LockedRng,
    PairingFailure, new_id, pairing_id_of, same_secret,
};
use crate::ContactBook;
use lepic_wallet::SharedRng;
use lepic_wallet::event::{ContactEvent, Event, FailedPairing};
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// Slots a new store starts at are drawn below this, so twin installs rarely meet (RFC 0002 2.2).
const SLOT_START_BOUND: u32 = 32_768;

/// Codes tried before an invite gives up on finding one whose id no pending pairing uses.
const CODE_TRIES: usize = 8;

/// How long an invite may be used, as the user chooses it (RFC 0002 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteExpiry {
    OneHour,
    OneDay,
    SevenDays,
}

impl InviteExpiry {
    pub fn duration(self) -> Duration {
        Duration::from_secs(match self {
            Self::OneHour => 60 * 60,
            Self::OneDay => 24 * 60 * 60,
            Self::SevenDays => 7 * 24 * 60 * 60,
        })
    }
}

/// What a new invite says about the inviter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRequest {
    pub account: AccountIndex,
    /// The name the inviter gives itself; the invitee sees it as claimed.
    pub name: String,
    pub kind: ContactKind,
    pub expiry: InviteExpiry,
    /// Also offer five pairing words that find the invite (RFC 0002 7.7).
    pub offer_words: bool,
    /// Where the pairing's mailboxes live, `domain[:port]`; `None` is the wallet's own relay.
    pub home_relay: Option<String>,
    /// A contact, or a private pairing of two wallets of one owner, which carries only the host
    /// app's payloads and never offers words.
    pub class: PairingClass,
    /// The payments address, `key@relay`, the reply must prove; a reply that proves none or
    /// another key is refused with nothing stored.
    pub expect_address: Option<String>,
}

/// A new invite, to show as a link or a QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteOffer {
    pub contact_id: ContactId,
    /// `epiccash://pair/1/...`.
    pub link: String,
    pub expires_at: Timestamp,
    /// The five pairing words, when they were offered and the invite was posted for them.
    pub words: Option<[lepic_contact::SasSymbol; lepic_contact::WORD_COUNT]>,
}

/// What an invite claims, for the user to decide on before answering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePreview {
    /// The inviter's own name for itself, unverified.
    pub claimed_name: String,
    pub kind: ContactKind,
    pub expires_at: Timestamp,
    /// The relay where the pairing's mailboxes live.
    pub home_relay: String,
    /// The invite comes from a service with a fixed pairing inbox.
    pub service: bool,
    pub class: PairingClass,
}

/// How to answer an invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequest {
    /// The `epiccash://pair/1/...` link the preview came from.
    pub link: String,
    pub account: AccountIndex,
    /// The name this wallet gives itself in its card.
    pub name: String,
    /// Do not post the reply; the user sends the returned link by hand.
    pub by_hand: bool,
    /// The class the user means to answer; an invite of the other class is refused.
    pub class: PairingClass,
    /// The payments address, `key@relay`, the confirm must prove: the sender of a pairing
    /// request.
    pub expect_address: Option<String>,
}

/// An answered invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptOutcome {
    pub contact_id: ContactId,
    /// The reply as `epiccash://pair-reply/1/...`, to send by hand when it was not posted.
    pub reply_link: String,
    /// The reply reached the relay.
    pub posted: bool,
}

/// What a card shown for pairing in person says about its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardRequest {
    pub account: AccountIndex,
    pub name: String,
    pub kind: ContactKind,
    /// Where the pairing's mailboxes live, `domain[:port]`; `None` is the wallet's own relay.
    pub home_relay: Option<String>,
}

/// A card shown for pairing in person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardOffer {
    pub contact_id: ContactId,
    /// `epiccash://contact/1/...`.
    pub link: String,
}

/// What a link entered by hand did (RFC 0002 7.2 and 7.3, manual mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    /// A reply to one of this wallet's invites was taken; send `link`, the confirm, back by hand.
    Confirm { contact_id: ContactId, link: String },
    /// A confirm finished a pairing this wallet answered.
    Paired { contact_id: ContactId },
    /// The link answers nothing this wallet waits for.
    Ignored,
}

/// The user's answer to the SAS check (RFC 0002 7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasDecision {
    /// Both screens show the same entries: the contact becomes verified.
    Match,
    /// The screens differ: the pairing ends on both sides.
    Mismatch,
    /// Not checked: the contact stays paired, not verified.
    Skip,
}

/// What became of one reply or confirm.
pub(crate) enum Taken {
    Paired(ContactId),
    /// A confirm to send back by hand.
    ConfirmLink(ContactId, String),
    /// Ended without pairing; the pairing that ended with nothing stored, if one did.
    Failed(Option<FailedPairing>),
    Ignored,
}

fn unix_seconds(time: Timestamp) -> u64 {
    u64::try_from(time.as_second()).unwrap_or(0)
}

fn timestamp(seconds: u64) -> Timestamp {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| Timestamp::from_second(seconds).ok())
        .unwrap_or(Timestamp::MAX)
}

pub(crate) fn store_kind(kind: ContactKind) -> lepic_store::ContactKind {
    match kind {
        ContactKind::Person => lepic_store::ContactKind::Person,
        ContactKind::Shop => lepic_store::ContactKind::Shop,
        ContactKind::Exchange => lepic_store::ContactKind::Exchange,
    }
}

pub(crate) fn peer_card(card: &ContactCard) -> PeerCard {
    let fields = card.fields();
    PeerCard {
        bytes: card.as_bytes().to_vec(),
        sig_key: card.sig_key().to_bytes(),
        enc_key: *card.enc_key().as_bytes(),
        hint_key: *fields.hint_key.as_bytes(),
        seq: fields.seq,
        kind: store_kind(fields.kind),
        claimed_name: fields.name.as_str().to_owned(),
    }
}

/// Whether `card` carries the sig, enc and hint keys of the stored peer card. A contact's keys
/// never change by a card: only [`Wallet::contact_keys_resolve`] with `UseNew` moves a contact
/// to other keys.
pub(crate) fn same_keys(stored: &PeerCard, card: &ContactCard) -> bool {
    let fresh = peer_card(card);
    stored.sig_key == fresh.sig_key
        && stored.enc_key == fresh.enc_key
        && stored.hint_key == fresh.hint_key
}

/// The relay of a card's mailbox, as `domain:port`.
fn mailbox_relay(card: &ContactCard, relays: &ContactRelays) -> Result<String, ContactError> {
    let address = mailbox_address(card, relays)?;
    Ok(host_text(&super::relay::endpoint_of_address(
        &address, relays,
    )?))
}

pub(crate) fn mailbox_address(
    card: &ContactCard,
    relays: &ContactRelays,
) -> Result<EpicboxAddress, ContactError> {
    EpicboxAddress::parse(card.fields().mailbox.as_str(), relays.epicbox.network())
        .map_err(|_| ContactError::RelayAddress)
}

/// The home relay `host` names, or the relay of `relays` for none.
fn home_relay(host: Option<&str>, relays: &ContactRelays) -> Result<RelayEndpoint, ContactError> {
    match host {
        Some(host) => endpoint_for(host, relays),
        None => Ok(relays.epicbox.settings().endpoint.clone()),
    }
}

/// A record that pairs nobody yet.
fn pending_record(
    contact_id: ContactId,
    account: AccountIndex,
    slot: u32,
    box_salt: [u8; 16],
    own_card: &ContactCard,
    state: ContactState,
    now: Timestamp,
) -> ContactRecord {
    ContactRecord {
        contact_id,
        account,
        slot,
        box_salt,
        own_card: own_card.as_bytes().to_vec(),
        peer: None,
        alternate: None,
        label: String::new(),
        state,
        sas: None,
        verified_at: None,
        allow_invoices: false,
        seal: SealMode::On,
        last_sealed_in: None,
        app_contact: None,
        imported_from_backup: false,
        created_at: now,
        updated_at: now,
        facts: lepic_store::PairingFacts::default(),
    }
}

/// The fresh slot, box salt and keys of a new record.
struct NewSlot {
    contact_id: ContactId,
    slot: u32,
    box_salt: [u8; 16],
}

/// Where and when a new pairing record is made.
struct NewPairing<'a> {
    keychain: &'a lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    home: &'a RelayEndpoint,
    now: Timestamp,
    /// The wallet's payments identity, which a contact pairing's card names and proves.
    payments: Option<&'a Payments>,
    /// What the pairing's messages claim.
    features: u32,
}

/// A reply that opened under one of this wallet's invites, with the pairing's keys.
struct OpenedReply {
    contact_id: ContactId,
    keys: crate::key_schedule::ContactKeys,
    invite: Invite,
    reply: ReplyBody,
    /// What the reply carries beside its body.
    extras: PairingExtras,
    /// Our card of the pairing, which the invite committed to.
    own: ContactCard,
    /// A private pairing's secrets, with the channel key the reply made.
    private: Option<PrivateSecrets>,
}

/// What the store needs to decide on an opened reply.
struct ReplyTaking {
    network: lepic_primitives::params::Network,
    /// The reply was taken by hand with no relay to carry the invitee's finished notice.
    heard_by_hand: bool,
    pairing_id: PairingId,
    contact_id: ContactId,
    peer: ContactCard,
    n_b: Nonce,
    rc: [u8; 16],
    /// The invite's expiry, in unix seconds.
    expires: u64,
    onion: Option<String>,
    home_text: String,
    signer: lepic_contact::SigningKey,
    private: Option<PrivateSecrets>,
    /// The replier's payments address, when its proof verified.
    proven: Option<ProvenAddress>,
    /// What the reply claims.
    peer_features: u32,
    /// What our confirm carries beside its body.
    confirm_extras: PairingExtras,
}

/// Where the answers to a reply go: the replier's confirm mailbox on the home relay.
struct ReplyRoute<'a> {
    invitee: &'a ContactCard,
    rc: [u8; 16],
    home: &'a RelayEndpoint,
    onion: Option<&'a str>,
    channel: Option<&'a ChannelKey>,
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Makes an invite to pair with a contact (RFC 0002 7.1). Its home relay, where the reply
    /// mailbox and later both contact mailboxes live, is the request's or else the relay of
    /// `relays`; another relay is reached over TLS through the wallet's connector. The pending
    /// pairing is stored; [`Wallet::contacts_collect`] takes the reply. Without words nothing is
    /// sent.
    ///
    /// With `offer_words` the invite lasts 10 minutes and is also posted, sealed with five
    /// pairing words, to a rendezvous mailbox on each meeting relay (RFC 0002 7.7), whatever
    /// the home relay is; the reply still goes to the home relay. With no meeting relay named
    /// this fails with [`ContactError::WordsUnavailable`]; Offline or Epicbox off fail
    /// before anything is stored, and when no meeting relay takes the post this is
    /// [`ContactError::Relay`], with the invite withdrawn.
    ///
    /// Fails with [`ContactError::Name`] for a name the card cannot carry, with
    /// [`ContactError::NetworkMismatch`], and as the store does, for example when every slot of
    /// the account is used or 64 pairings are pending.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_invite(
        &self,
        relays: &ContactRelays,
        request: InviteRequest,
    ) -> Result<InviteOffer, ContactError> {
        self.check_contact_network(relays)?;
        let network = self.wallet.config().network;
        let home = home_relay(request.home_relay.as_deref(), relays)?;
        let offer_words = request.offer_words;
        let lifetime = invite_lifetime(relays, &request)?;
        let session = self.wallet.session()?;
        let payments = (request.class == PairingClass::Contact)
            .then(|| Payments::of(&session.keychain, network, relays))
            .transpose()?;
        let features = self.wallet.config().claimed_features();
        let mut offer = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                let expires_at = now
                    .checked_add(lifetime)
                    .map_err(|_| ContactError::InviteExpired)?;
                let at = NewPairing {
                    keychain: &session.keychain,
                    network,
                    home: &home,
                    now,
                    payments: payments.as_ref(),
                    features,
                };
                session
                    .store
                    .write(|repos| store_invite(repos, &ports.rng, &at, &request, expires_at))
            })
            .await?;
        info!("pairing invite made");
        if offer_words {
            self.offer_invite_words(relays, &mut offer).await?;
        }
        Ok(offer)
    }

    /// Posts a new invite for its pairing words and puts them in `offer`.
    async fn offer_invite_words(
        &self,
        relays: &ContactRelays,
        offer: &mut InviteOffer,
    ) -> Result<(), ContactError> {
        let invite = Invite::from_link(&offer.link, contact_network(self.wallet.config().network))
            .map_err(ContactError::StoredData)?;
        match self.post_invite_words(relays, &invite).await {
            Ok(words) => offer.words = Some(words),
            Err(error) => {
                // An invite nobody can find by its words is withdrawn at once, so it does
                // not hold a pending pairing until it expires.
                self.contact_remove(offer.contact_id).await?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Reads an invite link for the user to decide on (RFC 0002 7.2). Nothing is stored or sent.
    ///
    /// Fails with [`ContactError::Decode`] for text that is not an invite on the wallet's
    /// network, and with [`ContactError::InviteExpired`] for one past its expiry by more than
    /// [`CLOCK_SKEW`].
    pub fn pairing_preview(&self, link: &str) -> Result<InvitePreview, ContactError> {
        let invite = self.read_invite(link)?;
        let fields = invite.fields();
        Ok(InvitePreview {
            claimed_name: fields.name.as_str().to_owned(),
            kind: fields.kind,
            expires_at: timestamp(fields.expires),
            home_relay: fields.home_relay.as_str().to_owned(),
            service: fields.service_inbox.is_some(),
            class: invite.class(),
        })
    }

    fn read_invite(&self, link: &str) -> Result<Invite, ContactError> {
        let invite = Invite::from_link(link, contact_network(self.wallet.config().network))
            .map_err(ContactError::Decode)?;
        let now = unix_seconds(self.wallet.ports().clock.now());
        let deadline = invite.fields().expires.saturating_add(CLOCK_SKEW.as_secs());
        if now >= deadline {
            return Err(ContactError::InviteExpired);
        }
        Ok(invite)
    }

    /// Answers an invite (RFC 0002 7.2): stores the pending pairing first, so a reply that was
    /// posted is never lost to a closed app, then posts the reply to the invite's reply mailbox
    /// or service inbox unless `by_hand` is set. The reply link is returned either way, for
    /// "Send by hand" and for a post that failed. [`Wallet::contacts_collect`] takes the confirm.
    ///
    /// Fails as [`Wallet::pairing_preview`] does, with [`ContactError::AlreadyPaired`] for an
    /// invite this wallet made or answered already, and as the store does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_accept(
        &self,
        relays: &ContactRelays,
        request: AcceptRequest,
    ) -> Result<AcceptOutcome, ContactError> {
        self.check_contact_network(relays)?;
        let invite = self.read_invite(&request.link)?;
        if invite.class() != request.class {
            return Err(ContactError::WrongClass);
        }
        let network = self.wallet.config().network;
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let session = self.wallet.session()?;
        let invite_for_work = invite.clone();
        let home_for_work = home.clone();
        let by_hand = request.by_hand;
        let payments = (invite.class() == PairingClass::Contact)
            .then(|| Payments::of(&session.keychain, network, relays))
            .transpose()?;
        let features = self.wallet.config().claimed_features();
        let expect_key = expected_key(request.expect_address.as_deref(), network)?;
        let ours = payments.as_ref().map(Payments::key);
        let (contact_id, envelope, from, to) = self
            .contact_work(move |ports, _| {
                let invite = invite_for_work;
                let home = home_for_work;
                let at = NewPairing {
                    keychain: &session.keychain,
                    network,
                    home: &home,
                    now: ports.clock.now(),
                    payments: payments.as_ref(),
                    features,
                };
                session.store.write(|repos| {
                    if let (Some(theirs), Some(ours)) = (expect_key, &ours) {
                        free_to_answer(repos, ours, &theirs, at.now)?;
                    }
                    store_answer(repos, &ports.rng, &at, &invite, &request)
                })
            })
            .await?;
        let reply_link = pairing_envelope_link(PairingLink::Reply, &envelope);
        let posted = !by_hand
            && match post_envelope(
                relays,
                &from,
                &to,
                invite.fields().onion.as_ref().map(RelayHost::as_str),
                &envelope,
            )
            .await
            {
                Ok(()) => true,
                Err(error) => {
                    warn!(peer_relay = %host_text(&home), error = %lepic_wallet::inbox::ErrorChain(&error), "pairing reply not posted");
                    false
                }
            };
        info!("pairing invite answered");
        Ok(AcceptOutcome {
            contact_id,
            reply_link,
            posted,
        })
    }

    /// Shows a card to pair in person (RFC 0002 7.4): a fresh slot whose mailbox is on the
    /// request's home relay or else the relay of `relays`. [`Wallet::pairing_scan_card`] finishes the pairing with the other phone's
    /// card. Nothing is sent, so this works offline.
    ///
    /// Fails as [`Wallet::pairing_invite`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_show_card(
        &self,
        relays: &ContactRelays,
        request: CardRequest,
    ) -> Result<CardOffer, ContactError> {
        self.check_contact_network(relays)?;
        let network = self.wallet.config().network;
        let home = home_relay(request.home_relay.as_deref(), relays)?;
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                let new = take_slot(
                    repos,
                    &mut LockedRng(&mut **ports.rng.lock()),
                    request.account,
                )?;
                let keys = contact_keys(
                    &session.keychain,
                    network,
                    request.account,
                    new.slot,
                    new.box_salt,
                )?;
                let mailbox = box_identity(&keys, network, &home)?;
                let card = our_card(
                    &keys,
                    network,
                    mailbox.address(),
                    &CardDetails {
                        kind: request.kind,
                        name: &request.name,
                        seq: 1,
                        payments_address: None,
                    },
                )?;
                repos.put_contact(&pending_record(
                    new.contact_id,
                    request.account,
                    new.slot,
                    new.box_salt,
                    &card,
                    ContactState::PendingInvite,
                    now,
                ))?;
                Ok(CardOffer {
                    contact_id: new.contact_id,
                    link: card.to_link(),
                })
            })
        })
        .await
    }

    /// Finishes an in-person pairing with the card the other phone shows (RFC 0002 7.4): both
    /// nonces are zero and the cards are ordered by sig key for the SAS. The contact is paired,
    /// not verified, until [`Wallet::pairing_sas`] confirms the check.
    ///
    /// Fails with [`ContactError::UnknownContact`] when `contact_id` is not a card this wallet
    /// shows, [`ContactError::Decode`] for a link that is not a card on the wallet's network,
    /// and [`ContactError::AlreadyPaired`] for a card of a contact this wallet holds or its own.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_scan_card(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        link: &str,
    ) -> Result<ContactView, ContactError> {
        let network = self.wallet.config().network;
        let peer =
            ContactCard::from_link(link, contact_network(network)).map_err(ContactError::Decode)?;
        let peer_relay = mailbox_relay(&peer, relays)?;
        let session = self.wallet.session()?;
        let view = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mut record = repos
                        .contact(contact_id)?
                        .filter(|record| {
                            record.peer.is_none() && record.state == ContactState::PendingInvite
                        })
                        .ok_or(ContactError::UnknownContact)?;
                    if repos.pending_pairing(pairing_id_of(contact_id))?.is_some() {
                        return Err(ContactError::UnknownContact);
                    }
                    let own = ContactCard::decode(&record.own_card, contact_network(network))
                        .map_err(ContactError::StoredData)?;
                    refuse_known_card(repos, &peer, &own)?;
                    let home = EpicboxAddress::parse(
                        own.fields().mailbox.as_str(),
                        relays_network(network),
                    )
                    .map(|address| {
                        format!(
                            "{}:{}",
                            address.domain(),
                            address.port().unwrap_or(lepic_epicbox::DEFAULT_PORT)
                        )
                    })
                    .map_err(|_| ContactError::RelayAddress)?;
                    let sas = Sas::in_person(contact_network(network), &own, &peer);
                    record.peer = Some(peer_card(&peer));
                    record.state = ContactState::Paired;
                    record.sas = Some(*sas.as_bytes());
                    record.updated_at = now;
                    super::status::heard_now(&mut record, now);
                    repos.put_contact(&record)?;
                    repos.put_contact_mailbox(&ContactMailbox {
                        contact_id,
                        peer_mailbox: peer.fields().mailbox.as_str().to_owned(),
                        our_mailbox: own.fields().mailbox.as_str().to_owned(),
                        home_relay: home.clone(),
                        onion: None,
                        previous: None,
                        backoff: Vec::new(),
                    })?;
                    // A card QR is seen by anyone nearby: the first collect moves our mailbox.
                    repos.put_setting(&super::collect::in_person_key(contact_id), "1")?;
                    debug!(peer_relay = %peer_relay, "in-person pairing stored");
                    Ok(super::manage::view(&record, Some(home), now))
                })
            })
            .await?;
        info!("contact paired in person");
        self.wallet
            .emit(Event::PairingConfirmed(ContactEvent { contact_id }));
        Ok(view)
    }

    /// Records the user's SAS check (RFC 0002 7.5), also while the pairing waits for the
    /// contact. A match makes the contact verified and counts as hearing it; a contact that
    /// claims the status notices is told, with the hash of the SAS. A mismatch ends the
    /// pairing on this side, kept as ended: its invoices and queued messages are dropped, its
    /// mailbox is no longer collected so nothing more is finalized through it, and the contact
    /// is told as for a match. After a mismatch an inviter also posts a refusal to the
    /// invitee's confirm mailbox, best effort. Skipping leaves it paired.
    ///
    /// Fails with [`ContactError::Ended`] for a pairing that ended, and with
    /// [`ContactError::UnknownContact`] when no paired contact has that id.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    // Each decision's store work is short; split, the one transaction would read worse.
    #[allow(clippy::too_many_lines)]
    pub async fn pairing_sas(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        decision: SasDecision,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let tell = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mut record = repos
                        .contact(contact_id)?
                        .filter(|record| {
                            matches!(record.state, ContactState::Paired | ContactState::Verified)
                                && record.peer.is_some()
                        })
                        .ok_or(ContactError::UnknownContact)?;
                    if record.facts.ended_reason.is_some() {
                        return Err(ContactError::Ended);
                    }
                    let verdict = record.sas.as_ref().map(super::status::verdict_hash);
                    let queue =
                        |repos: &mut dyn lepic_store::Repositories,
                         record: &ContactRecord,
                         message: super::status::StatusMessage| {
                            if super::status::sends_status(record)
                                && let Err(error) = super::status::queue_status(
                                    repos,
                                    &session.keychain,
                                    network,
                                    &ports.rng,
                                    record,
                                    &super::status::Tell::Status(message),
                                    now,
                                )
                            {
                                super::status::queue_failed(&error);
                            }
                        };
                    match decision {
                        SasDecision::Match => {
                            record.state = ContactState::Verified;
                            record.verified_at = Some(now);
                            record.updated_at = now;
                            super::status::heard_now(&mut record, now);
                            repos.put_contact(&record)?;
                            if let Some(hash) = verdict {
                                queue(repos, &record, super::status::StatusMessage::Match(hash));
                            }
                        }
                        SasDecision::Mismatch => {
                            let pending = repos.pending_pairing(pairing_id_of(contact_id))?;
                            end_pending(repos, pairing_id_of(contact_id))?;
                            super::invoices::drop_contact_invoices(repos, contact_id)?;
                            super::status::drop_contact_outbox(repos, contact_id)?;
                            let channel = class_of(repos, &record)?
                                .private()
                                .and_then(|secrets| secrets.channel.clone());
                            super::status::end_record(
                                &mut record,
                                lepic_store::PairingEndReason::Mismatch,
                                now,
                            );
                            repos.put_contact(&record)?;
                            if let Some(hash) = verdict {
                                queue(repos, &record, super::status::StatusMessage::Mismatch(hash));
                            }
                            let tell = pending
                                .filter(|pending| pending.role == PairingRole::Inviter)
                                .and_then(|pending| {
                                    Some((
                                        pending.secrets.rc?,
                                        pending.invite,
                                        record.peer?.bytes,
                                        channel,
                                    ))
                                });
                            return Ok(tell);
                        }
                        SasDecision::Skip => {}
                    }
                    Ok(None)
                })
            })
            .await?;
        info!("sas check recorded");
        // The inviter tells the invitee, whose confirm may still wait on the relay.
        if let Some((rc, invite, peer, channel)) = tell {
            let net = contact_network(self.wallet.config().network);
            let card = ContactCard::decode(&peer, net).map_err(ContactError::StoredData)?;
            let invite = Invite::decode(&invite, net).map_err(ContactError::StoredData)?;
            let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
            self.post_refusal(
                relays,
                &card,
                rc,
                &home,
                invite.fields().onion.as_ref().map(RelayHost::as_str),
                Refusal::CancelledByInviter,
                channel.as_ref(),
            )
            .await;
        }
        if relays.mode == super::RelayMode::Online
            && let Err(error) = self.deliver_status(relays, false).await
        {
            warn!(error = %lepic_wallet::inbox::ErrorChain(&error), "pairing status not delivered");
        }
        Ok(())
    }

    /// Cancels a pairing in progress (RFC 0002 7.6). An invite of ours that no reply paired is
    /// kept, hidden, until it expires, so a late reply is refused with
    /// [`Refusal::CancelledByInviter`] and the replier learns it; its nonce is dropped, so
    /// nothing can pair with it any more. At most [`lepic_store::MAX_CANCELLED_PAIRINGS`] are
    /// kept, the oldest dropped. Any other pairing in progress, and our answer to an invite,
    /// are removed as [`Wallet::contact_remove`] removes them. Returns whether anything was
    /// cancelled.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_cancel(&self, contact_id: ContactId) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        let kept = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let Some(mut pending) = repos.pending_pairing(pairing_id_of(contact_id))?
                    else {
                        return Ok::<_, StoreError>(false);
                    };
                    let unanswered = pending.role == PairingRole::Inviter
                        && repos
                            .contact(contact_id)?
                            .is_some_and(|record| record.peer.is_none());
                    if !unanswered || pending.cancelled_at.is_some() {
                        return Ok(pending.cancelled_at.is_some());
                    }
                    let mut cancelled: Vec<_> = repos
                        .pending_pairings()?
                        .into_iter()
                        .filter(|other| other.cancelled_at.is_some())
                        .collect();
                    cancelled.sort_by_key(|other| other.cancelled_at);
                    let over = cancelled
                        .len()
                        .saturating_add(1)
                        .saturating_sub(lepic_store::MAX_CANCELLED_PAIRINGS);
                    for oldest in cancelled.into_iter().take(over) {
                        end_pending(repos, oldest.pairing_id)?;
                        repos.delete_contact(oldest.contact_id)?;
                        super::private::delete_secrets(repos, oldest.contact_id)?;
                    }
                    pending.secrets.na = None;
                    pending.cancelled_at = Some(now);
                    repos.put_pending_pairing(&pending)?;
                    Ok(true)
                })?)
            })
            .await?;
        if kept {
            info!("pairing invite cancelled");
            return Ok(true);
        }
        self.contact_remove(contact_id).await
    }

    /// Posts again the reply of each answer of ours still waiting for its confirm, in case the
    /// first post never reached the inviter. A reply the inviter took already is recognised
    /// there and changes nothing.
    pub(crate) async fn repost_replies(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let waiting = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.read(|repos| {
                    Ok::<_, StoreError>(
                        repos
                            .pending_pairings()?
                            .into_iter()
                            .filter(|pending| {
                                pending.role == PairingRole::Invitee
                                    && pending.cancelled_at.is_none()
                                    && pending.expires_at > now
                            })
                            .filter_map(|pending| {
                                Some((
                                    pending.secrets.code?,
                                    pending.peer_mailbox?,
                                    pending.reply?,
                                    pending.invite,
                                ))
                            })
                            .collect::<Vec<_>>(),
                    )
                })?)
            })
            .await?;
        for (code, to, reply, invite) in waiting {
            let invite = Invite::decode(&invite, net).map_err(ContactError::StoredData)?;
            let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
            let (_, from) = pairing_mailbox(&code, network, &home)?;
            let to = EpicboxAddress::parse(&to, relays.epicbox.network())
                .map_err(|_| ContactError::RelayAddress)?;
            let onion = invite.fields().onion.as_ref().map(RelayHost::as_str);
            if let Err(error) = post_envelope(relays, &from, &to, onion, &reply).await {
                debug!(error = %lepic_wallet::inbox::ErrorChain(&error), "pairing reply not posted again");
            }
        }
        Ok(())
    }

    /// Posts an anonymous refusal to the confirm mailbox of `rc`, under `channel` for a private
    /// pairing. Advisory, so a failure is logged and not returned.
    #[allow(clippy::too_many_arguments)] // Each is one fact of the refusal's address.
    async fn post_refusal(
        &self,
        relays: &ContactRelays,
        invitee: &ContactCard,
        rc: [u8; 16],
        home: &RelayEndpoint,
        onion: Option<&str>,
        refusal: Refusal,
        channel: Option<&ChannelKey>,
    ) {
        let posted = async {
            let envelope = {
                let mut guard = self.wallet.ports().rng.lock();
                let mut rng = LockedRng(&mut **guard);
                match channel {
                    None => seal_refusal(invitee, refusal, &mut rng),
                    Some(channel) => seal_private_refusal(invitee, refusal, channel, &mut rng),
                }
            }
            .map_err(ContactError::Encode)?;
            let (confirm_box, confirm_from) =
                pairing_mailbox(&rc, self.wallet.config().network, home)?;
            post_envelope(
                relays,
                &confirm_from,
                confirm_box.address(),
                onion,
                &envelope,
            )
            .await
        };
        if let Err(error) = posted.await {
            warn!(error = %lepic_wallet::inbox::ErrorChain(&error), "pairing refusal not posted");
        }
    }

    /// Takes a pairing reply or confirm the user pasted as `epiccash://pair-reply/1/...` or
    /// `epiccash://pair-confirm/1/...` (RFC 0002 7.2 and 7.3, manual mode). A reply to one of
    /// this wallet's invites pairs it and returns the confirm to send back by hand; a confirm
    /// finishes a pairing this wallet answered.
    ///
    /// Fails with [`ContactError::Decode`] for any other text.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_enter_link(
        &self,
        relays: &ContactRelays,
        text: &str,
    ) -> Result<LinkOutcome, ContactError> {
        let network = contact_network(self.wallet.config().network);
        let _turn = self.wallet.contact_turn().await;
        if let Ok(envelope) = pairing_envelope_from_link(text, PairingLink::Reply) {
            let sealed =
                SealedEnvelope::decode(&envelope, network).map_err(ContactError::Decode)?;
            let invite_id = *sealed.hint().as_bytes();
            let session = self.wallet.session()?;
            let pending = self
                .contact_work(move |_, _| {
                    Ok(session
                        .store
                        .read(|repos| repos.pending_pairing_by_invite(&invite_id))?)
                })
                .await?
                .filter(|pending| pending.role == PairingRole::Inviter);
            let Some(pending) = pending else {
                return Ok(LinkOutcome::Ignored);
            };
            return Ok(
                match self
                    .take_reply(relays, pending.pairing_id, &envelope, true)
                    .await?
                {
                    Taken::ConfirmLink(contact_id, link) => {
                        LinkOutcome::Confirm { contact_id, link }
                    }
                    Taken::Paired(contact_id) => LinkOutcome::Paired { contact_id },
                    Taken::Failed(failed) => match failed.and_then(|f| link_failure(f.reason)) {
                        Some(error) => return Err(error),
                        None => LinkOutcome::Ignored,
                    },
                    Taken::Ignored => LinkOutcome::Ignored,
                },
            );
        }
        let envelope =
            pairing_envelope_from_link(text, PairingLink::Confirm).map_err(ContactError::Decode)?;
        let session = self.wallet.session()?;
        let waiting = self
            .contact_work(move |_, _| Ok(session.store.read(|repos| repos.pending_pairings())?))
            .await?;
        for pending in waiting
            .into_iter()
            .filter(|pending| pending.role == PairingRole::Invitee)
        {
            match self.take_confirm(pending.pairing_id, &envelope).await? {
                Taken::Paired(contact_id) => return Ok(LinkOutcome::Paired { contact_id }),
                Taken::Failed(failed) => {
                    return match failed.and_then(|f| link_failure(f.reason)) {
                        Some(error) => Err(error),
                        None => Ok(LinkOutcome::Ignored),
                    };
                }
                Taken::ConfirmLink(..) | Taken::Ignored => {}
            }
        }
        Ok(LinkOutcome::Ignored)
    }

    /// The inviter's side of a reply (RFC 0002 7.3): the first reply whose code matches and whose
    /// card verifies pairs. Every refusal (used, expired, a card this wallet already holds or
    /// its own) is decided, and an accepted reply's record stored with nA consumed, in one store
    /// transaction before any confirm leaves: a refused reply gets only the anonymous one-byte
    /// refusal, and nA goes to the one card the record holds. The confirm is kept until the
    /// pairing ends, so a post that failed is repeated when the same reply is taken again.
    pub(crate) async fn take_reply(
        &self,
        relays: &ContactRelays,
        pairing_id: PairingId,
        envelope: &[u8],
        by_hand: bool,
    ) -> Result<Taken, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let Some(OpenedReply {
            contact_id,
            keys,
            invite,
            reply,
            extras,
            own,
            private,
        }) = self
            .open_pairing_reply(&session.keychain, pairing_id, envelope)
            .await?
        else {
            return Ok(Taken::Ignored);
        };
        let channel = private.as_ref().and_then(|secrets| secrets.channel.clone());
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let onion_text = invite.fields().onion.as_ref().map(RelayHost::as_str);
        let rc = *reply.confirm_code.expose_bytes();
        let (proven, confirm_extras) = if private.is_some() {
            (None, PairingExtras::default())
        } else {
            let payments = Payments::of(&session.keychain, network, relays)?;
            let features = self.wallet.config().claimed_features();
            reply_proofs(
                network, &keys, &invite, &reply, &own, &extras, &payments, features,
            )
        };
        let taking = ReplyTaking {
            network,
            heard_by_hand: by_hand && relays.mode != super::RelayMode::Online,
            pairing_id,
            contact_id,
            peer: reply.card.clone(),
            n_b: reply.nonce.clone(),
            rc,
            expires: invite.fields().expires,
            onion: onion_text.map(str::to_owned),
            home_text: host_text(&home),
            signer: signing_key(&keys),
            private,
            proven,
            peer_features: extras.features.unwrap_or(0),
            confirm_extras,
        };
        let decision = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session
                    .store
                    .write(|repos| decide_reply(repos, &ports.rng, net, now, taking))
            })
            .await?;
        let route = ReplyRoute {
            invitee: &reply.card,
            rc,
            home: &home,
            onion: onion_text,
            channel: channel.as_ref(),
        };
        let (envelope, first) = match decision {
            Decision::Drop => return Ok(Taken::Ignored),
            Decision::Unexpected(reason) => {
                warn!("pairing reply from another wallet than expected dropped");
                return Ok(self.pairing_failed(contact_id, reason));
            }
            Decision::Known(tell) => {
                warn!("pairing reply from a contact already paired refused");
                if tell && !by_hand {
                    self.refuse_reply(relays, &route, Refusal::AlreadyUsed)
                        .await;
                }
                return Ok(Taken::Failed(None));
            }
            Decision::Refuse(refusal, tell) => {
                debug!("pairing reply refused");
                if tell && !by_hand {
                    self.refuse_reply(relays, &route, refusal).await;
                }
                return Ok(Taken::Ignored);
            }
            Decision::Again(envelope) => (envelope, false),
            Decision::Confirm(envelope) => (envelope, true),
        };
        // Paired from here on, whether or not the confirm leaves now: the host hears it once,
        // and a confirm that did not leave goes out when the kept reply is taken again.
        if first {
            info!("pairing reply taken");
            self.wallet
                .emit(Event::PairingReplied(ContactEvent { contact_id }));
        }
        self.send_confirm(relays, &route, pairing_id, contact_id, &envelope, by_hand)
            .await
    }

    /// Sends the confirm of a reply that paired: posted to the replier's confirm mailbox, or
    /// returned as a link to send `by_hand`. Either way the confirm counts as sent.
    async fn send_confirm(
        &self,
        relays: &ContactRelays,
        route: &ReplyRoute<'_>,
        pairing_id: PairingId,
        contact_id: ContactId,
        envelope: &[u8],
        by_hand: bool,
    ) -> Result<Taken, ContactError> {
        if !by_hand {
            let (confirm_box, confirm_from) =
                pairing_mailbox(&route.rc, self.wallet.config().network, route.home)?;
            post_envelope(
                relays,
                &confirm_from,
                confirm_box.address(),
                route.onion,
                envelope,
            )
            .await?;
        }
        self.mark_confirm_out(pairing_id).await?;
        Ok(if by_hand {
            Taken::ConfirmLink(
                contact_id,
                pairing_envelope_link(PairingLink::Confirm, envelope),
            )
        } else {
            Taken::Paired(contact_id)
        })
    }

    /// The reply in `envelope` to this wallet's invite of `pairing_id`, opened and carrying the
    /// invite's code; `None` for anything else. A private pairing's reply opens only with its
    /// link secret, and makes the channel key.
    async fn open_pairing_reply(
        &self,
        keychain: &lepic_keychain::Keychain,
        pairing_id: PairingId,
        envelope: &[u8],
    ) -> Result<Option<OpenedReply>, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let Some((pending, record, class)) = self.pending_with_record(pairing_id).await? else {
            return Ok(None);
        };
        let Some(code) = pending.secrets.code else {
            return Ok(None);
        };
        if matches!(class, RecordClass::Unreadable) {
            warn!("pairing reply for a private pairing whose secrets do not open dropped");
            return Ok(None);
        }
        let keys = record_keys(keychain, network, &record, &class)?;
        let sealed = match SealedEnvelope::decode(envelope, net) {
            Ok(sealed) if sealed.hint().as_bytes() == &pending.invite_id => sealed,
            _ => return Ok(None),
        };
        let invite = Invite::decode(&pending.invite, net).map_err(ContactError::StoredData)?;
        let ((reply, extras), private) = match class.private() {
            None => match open_reply_with(&sealed, &enc_secret(&keys)) {
                Ok((reply, extras)) => ((reply, extras), None),
                Err(_) => {
                    debug!("pairing reply did not open");
                    return Ok(None);
                }
            },
            Some(secrets) => match open_private_reply(&sealed, &enc_secret(&keys), &secrets.link) {
                Ok((reply, joiner)) => {
                    let mut secrets = secrets.clone();
                    secrets.channel = Some(ChannelKey::channel(
                        &secrets.link,
                        &joiner,
                        &invite,
                        &reply.card,
                    ));
                    secrets.joiner = Some(joiner);
                    ((reply, PairingExtras::default()), Some(secrets))
                }
                Err(_) => {
                    debug!("pairing reply did not open");
                    return Ok(None);
                }
            },
        };
        if !same_secret(reply.code.expose_bytes(), &code) {
            debug!("pairing reply with another code dropped");
            return Ok(None);
        }
        let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
        Ok(Some(OpenedReply {
            contact_id: pending.contact_id,
            keys,
            invite,
            reply,
            extras,
            own,
            private,
        }))
    }

    /// Posts the refusal of a reply to the replier's confirm mailbox, best effort.
    async fn refuse_reply(&self, relays: &ContactRelays, route: &ReplyRoute<'_>, refusal: Refusal) {
        self.post_refusal(
            relays,
            route.invitee,
            route.rc,
            route.home,
            route.onion,
            refusal,
            route.channel,
        )
        .await;
    }

    /// The invitee's side of a confirm (RFC 0002 7.3): the revealed nonce and card must match
    /// the invite's commitment and enc key, or the pairing ends with nothing stored.
    // The checks of a confirm run in their order; split, the order would be harder to see.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn take_confirm(
        &self,
        pairing_id: PairingId,
        envelope: &[u8],
    ) -> Result<Taken, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let Some((pending, record, class)) = self.pending_with_record(pairing_id).await? else {
            return Ok(Taken::Ignored);
        };
        let contact_id = pending.contact_id;
        let Some(n_b) = pending.secrets.nb else {
            return Ok(Taken::Ignored);
        };
        if matches!(class, RecordClass::Unreadable) {
            warn!("pairing confirm for a private pairing whose secrets do not open dropped");
            return Ok(Taken::Ignored);
        }
        let keys = record_keys(&session.keychain, network, &record, &class)?;
        let (confirm, extras) = match open_pairing_confirm(envelope, net, &keys, &class) {
            Some((Confirm::Accepted(body), extras)) => (body, extras),
            Some((Confirm::Refused(refusal), _)) => {
                // Advisory: only the inviter knows the confirm mailbox, and nothing of the
                // refusal is kept but the end of this pairing.
                let pairing_id = pending.pairing_id;
                self.contact_work(move |_, _| {
                    session
                        .store
                        .write(|repos| drop_pairing(repos, pairing_id, contact_id))
                })
                .await?;
                info!("pairing refused by the inviter");
                return Ok(self.pairing_failed(contact_id, PairingFailure::Refused(refusal)));
            }
            None => return Ok(Taken::Ignored),
        };
        let invite = Invite::decode(&pending.invite, net).map_err(ContactError::StoredData)?;
        let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
        let pairing_id = pending.pairing_id;
        if !confirm.matches_invite(&invite) {
            self.contact_work(move |_, _| {
                session
                    .store
                    .write(|repos| drop_pairing(repos, pairing_id, contact_id))
            })
            .await?;
            warn!("pairing confirm does not match the invite");
            return Ok(self.pairing_failed(contact_id, PairingFailure::ChangedOnTheWay));
        }
        let Some(sas) = confirm_sas(net, &class, &confirm, &own, &Nonce::from_bytes(n_b)) else {
            return Ok(Taken::Ignored);
        };
        let proven = confirm_proven(network, &keys, &class, &confirm, &own, &invite, &extras);
        let expected = match unexpected(pending.expect_key.as_ref(), proven.as_ref()) {
            Ok(expected) => expected,
            Err(reason) => {
                self.contact_work(move |_, _| {
                    session
                        .store
                        .write(|repos| drop_pairing(repos, pairing_id, contact_id))
                })
                .await?;
                warn!("pairing confirm from another wallet than expected dropped");
                return Ok(self.pairing_failed(contact_id, reason));
            }
        };
        let peer_features = extras.features.unwrap_or(0);
        let peer = confirm.card.clone();
        let fields = invite.fields();
        let home_text = fields.home_relay.as_str().to_owned();
        let onion = fields.onion.as_ref().map(|onion| onion.as_str().to_owned());
        let stored = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    refuse_known_card(repos, &peer, &own)?;
                    let mut record = record;
                    record.facts.peer_features = peer_features;
                    set_proven(&mut record, proven);
                    super::status::learn_from_pairing(repos, &record, network, now)?;
                    record.peer = Some(peer_card(&peer));
                    record.state = ContactState::Paired;
                    record.sas = Some(*sas.as_bytes());
                    record.updated_at = now;
                    // The confirm itself is the inviter heard.
                    super::status::heard_now(&mut record, now);
                    if expected {
                        record.state = ContactState::Verified;
                        record.verified_at = Some(now);
                    }
                    repos.put_contact(&record)?;
                    repos.put_contact_mailbox(&paired_mailbox(
                        contact_id, &peer, &own, home_text, onion,
                    ))?;
                    end_pending(repos, pairing_id)?;
                    // An inviter that claims the status notices waits to hear that we finished.
                    if super::status::sends_status(&record)
                        && let Err(error) = super::status::queue_status(
                            repos,
                            &session.keychain,
                            network,
                            &ports.rng,
                            &record,
                            &super::status::Tell::Status(super::status::StatusMessage::Finished),
                            now,
                        )
                    {
                        super::status::queue_failed(&error);
                    }
                    Ok(())
                })
            })
            .await;
        match stored {
            Ok(()) => {}
            Err(ContactError::AlreadyPaired) => {
                warn!("pairing confirm from a contact already paired refused");
                return Ok(Taken::Failed(None));
            }
            Err(error) => return Err(error),
        }
        info!("pairing confirmed");
        self.wallet
            .emit(Event::PairingConfirmed(ContactEvent { contact_id }));
        Ok(Taken::Paired(contact_id))
    }

    /// Tells the host that the pairing of `contact_id` ended with nothing stored.
    fn pairing_failed(&self, contact_id: ContactId, reason: PairingFailure) -> Taken {
        let failed = FailedPairing { contact_id, reason };
        self.wallet.emit(Event::PairingFailed(failed));
        Taken::Failed(Some(failed))
    }

    /// Records that the confirm of `pairing_id` reached the relay or was handed to the user, so
    /// the invitee may hold the pairing.
    async fn mark_confirm_out(&self, pairing_id: PairingId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                if repos.pending_pairing(pairing_id)?.is_some() {
                    repos.put_setting(&confirm_out_key(pairing_id), "1")?;
                }
                Ok::<_, StoreError>(())
            })?)
        })
        .await
    }

    /// The pairing in progress `pairing_id`, its record and the record's class, as stored now.
    async fn pending_with_record(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<(PendingPairing, ContactRecord, RecordClass)>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                let Some(pending) = repos.pending_pairing(pairing_id)? else {
                    return Ok::<_, lepic_store::StoreError>(None);
                };
                let Some(record) = repos.contact(pending.contact_id)? else {
                    return Ok(None);
                };
                let class = class_of(repos, &record)?;
                Ok(Some((pending, record, class)))
            })?)
        })
        .await
    }

    pub(crate) fn check_contact_network(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        if relays.epicbox.network()
            != lepic_wallet::inbox::relay_network(self.wallet.config().network)
        {
            return Err(ContactError::NetworkMismatch);
        }
        Ok(())
    }

    /// Runs store and key work on the blocking pool.
    pub(crate) async fn contact_work<T, F>(&self, work: F) -> Result<T, ContactError>
    where
        T: Send + 'static,
        F: FnOnce(
                &lepic_wallet::Ports<N, S, V>,
                &lepic_wallet::WalletConfig,
            ) -> Result<T, ContactError>
            + Send
            + 'static,
    {
        self.wallet
            .blocking(move |ports, config| Ok(work(ports, config)))
            .await?
    }
}

/// The error a link entered by hand ends with when its pairing failed on the address it had to
/// prove; any other failure is told by its event alone.
fn link_failure(reason: PairingFailure) -> Option<ContactError> {
    match reason {
        PairingFailure::OtherAddress => Some(ContactError::OtherAddress),
        PairingFailure::AddressProofMissing => Some(ContactError::AddressProofMissing),
        _ => None,
    }
}

fn relays_network(network: lepic_primitives::params::Network) -> lepic_epicbox::Network {
    lepic_wallet::inbox::relay_network(network)
}

/// Takes the account's next slot, starting at a random slot for a new store, and a fresh salt
/// and record id.
fn take_slot(
    repos: &mut dyn Repositories,
    rng: &mut LockedRng<'_>,
    account: AccountIndex,
) -> Result<NewSlot, ContactError> {
    use rand_core::Rng;
    let start = rng.next_u32() % SLOT_START_BOUND;
    let slot = repos.take_contact_slot(account, start)?;
    Ok(NewSlot {
        contact_id: ContactId(new_id(rng)),
        slot,
        box_salt: new_id(rng),
    })
}

/// The id, slot and salt of a new record of `class`, with a private pairing's fresh secrets:
/// its own key secret and a link secret, which a joiner replaces with the invite's.
fn new_record(
    repos: &mut dyn Repositories,
    rng: &mut LockedRng<'_>,
    account: AccountIndex,
    class: PairingClass,
) -> Result<(NewSlot, Option<PrivateSecrets>), ContactError> {
    match class {
        PairingClass::Contact => Ok((take_slot(repos, rng, account)?, None)),
        PairingClass::Private => {
            let slot = super::private::take_private_slot(repos)?;
            let new = NewSlot {
                contact_id: ContactId(new_id(rng)),
                slot,
                box_salt: new_id(rng),
            };
            let secrets = PrivateSecrets {
                own: PrivateSecret::random(rng),
                link: PrivateSecret::random(rng),
                joiner: None,
                channel: None,
            };
            Ok((new, Some(secrets)))
        }
    }
}

/// Our keys for a new record: a contact's, or a private pairing's from its own secret.
fn new_keys(
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    account: AccountIndex,
    new: &NewSlot,
    private: Option<&PrivateSecrets>,
) -> Result<crate::key_schedule::ContactKeys, ContactError> {
    match private {
        None => contact_keys(keychain, network, account, new.slot, new.box_salt),
        Some(secrets) => {
            super::private::private_keys(keychain, network, account, new.slot, &secrets.own)
        }
    }
}

/// How long a new invite lasts. Words are posted, so offering them needs a relay reachable
/// before anything is stored and a meeting relay to post to.
fn invite_lifetime(
    relays: &ContactRelays,
    request: &InviteRequest,
) -> Result<Duration, ContactError> {
    // A private pairing's invite travels out of band only.
    if request.offer_words && request.class == PairingClass::Private {
        return Err(ContactError::WrongClass);
    }
    if request.offer_words {
        super::relay::check_online(relays)?;
        if relays.meeting.is_empty() {
            return Err(ContactError::WordsUnavailable);
        }
    }
    Ok(if request.offer_words {
        super::words::WORDS_INVITE_EXPIRY
    } else {
        request.expiry.duration()
    })
}

/// Our first card for a new record, its mailbox on the pairing's home relay.
fn new_card(
    keys: &crate::key_schedule::ContactKeys,
    at: &NewPairing<'_>,
    kind: ContactKind,
    name: &str,
) -> Result<ContactCard, ContactError> {
    let mailbox = box_identity(keys, at.network, at.home)?;
    let payments_address = at.payments.map(Payments::card_address).transpose()?;
    our_card(
        keys,
        at.network,
        mailbox.address(),
        &CardDetails {
            kind,
            name,
            seq: 1,
            payments_address,
        },
    )
}

/// Stores the record and pending pairing of a new invite, and returns the offer.
fn store_invite(
    repos: &mut dyn Repositories,
    rng: &SharedRng,
    at: &NewPairing<'_>,
    request: &InviteRequest,
    expires_at: Timestamp,
) -> Result<InviteOffer, ContactError> {
    let network = at.network;
    let (new, private) = {
        let mut guard = rng.lock();
        new_record(
            repos,
            &mut LockedRng(&mut **guard),
            request.account,
            request.class,
        )?
    };
    let keys = new_keys(
        at.keychain,
        network,
        request.account,
        &new,
        private.as_ref(),
    )?;
    let card = new_card(&keys, at, request.kind, &request.name)?;
    let (n_a, code) = {
        let mut guard = rng.lock();
        let mut rng = LockedRng(&mut **guard);
        (
            Nonce::from_bytes(new_id(&mut rng)),
            free_code(repos, &mut rng)?,
        )
    };
    let invite = Invite::new(
        contact_network(network),
        InviteFields {
            kind: request.kind,
            name: ContactName::new(&request.name).map_err(ContactError::Name)?,
            expires: unix_seconds(expires_at),
            code: code.clone(),
            commit: Commitment::new(&n_a, &card),
            enc_key: *card.enc_key(),
            home_relay: RelayHost::new(&host_text(at.home)).map_err(ContactError::Name)?,
            service_inbox: None,
            onion: None,
            link: private.as_ref().map(|secrets| secrets.link.clone()),
            mailbox_key: private.is_none().then(|| keys.box_public_key().to_bytes()),
        },
    )
    .map_err(ContactError::Encode)?;
    let (reply_box, _) = pairing_mailbox(code.expose_bytes(), network, at.home)?;
    if let Some(secrets) = &private {
        super::private::put_secrets(repos, new.contact_id, secrets)?;
    }
    repos.put_contact(&pending_record(
        new.contact_id,
        request.account,
        new.slot,
        new.box_salt,
        &card,
        ContactState::PendingInvite,
        at.now,
    ))?;
    repos.put_pending_pairing(&PendingPairing {
        pairing_id: pairing_id_of(new.contact_id),
        role: PairingRole::Inviter,
        contact_id: new.contact_id,
        secrets: PairingSecrets {
            code: Some(*code.expose_bytes()),
            na: Some(*n_a.expose_bytes()),
            nb: None,
            rc: None,
        },
        invite_id: *invite.id().as_bytes(),
        expires_at,
        our_mailbox: reply_box.address().to_string(),
        peer_mailbox: None,
        state: PairingState::PendingInvite,
        created_at: at.now,
        invite: invite.as_bytes().to_vec(),
        expect_address: request.expect_address.clone(),
        expect_key: expected_key(request.expect_address.as_deref(), network)?,
        reply: None,
        cancelled_at: None,
    })?;
    Ok(InviteOffer {
        contact_id: new.contact_id,
        link: invite.to_link(),
        expires_at,
        words: None,
    })
}

/// Stores the record and pending pairing of an answer to `invite`, and returns the record's id,
/// the sealed reply, the mailbox it is posted from and the one it is posted to.
fn store_answer(
    repos: &mut dyn Repositories,
    rng: &SharedRng,
    at: &NewPairing<'_>,
    invite: &Invite,
    request: &AcceptRequest,
) -> Result<(ContactId, Vec<u8>, Identity, EpicboxAddress), ContactError> {
    if repos
        .pending_pairing_by_invite(invite.id().as_bytes())?
        .is_some()
    {
        return Err(ContactError::AlreadyPaired);
    }
    let network = at.network;
    super::requests::answer_request(repos, invite.id().as_bytes(), at.now)?;
    let mut rng = LockedRng(&mut **rng.lock());
    let (new, mut private) = new_record(repos, &mut rng, request.account, request.class)?;
    if let (Some(secrets), Some(link)) = (&mut private, &invite.fields().link) {
        secrets.link = link.clone();
    }
    let keys = new_keys(
        at.keychain,
        network,
        request.account,
        &new,
        private.as_ref(),
    )?;
    let card = new_card(&keys, at, ContactKind::Person, &request.name)?;
    let n_b = Nonce::from_bytes(new_id(&mut rng));
    let rc = ConfirmCode::from_bytes(new_id(&mut rng));
    let body = ReplyBody {
        code: invite.fields().code.clone(),
        nonce: n_b.clone(),
        confirm_code: rc.clone(),
        card: card.clone(),
    };
    let extras = PairingExtras {
        address_proof: at.payments.and_then(|payments| {
            payments.prove(
                &invite_mailbox_key(invite)?,
                &ProofBinding {
                    network: invite.network(),
                    step: ProofStep::Reply,
                    prover_card: &card,
                    verifier_card: None,
                    invite: Some(invite.as_bytes()),
                },
            )
        }),
        features: Some(at.features),
    };
    let envelope = seal_answer(invite, &body, &card, &extras, &mut private, &mut rng)?;
    if let Some(secrets) = &private {
        super::private::put_secrets(repos, new.contact_id, secrets)?;
    }
    let code = *invite.fields().code.expose_bytes();
    let (reply_box, reply_from) = pairing_mailbox(&code, network, at.home)?;
    let (confirm_box, _) = pairing_mailbox(rc.expose_bytes(), network, at.home)?;
    let to = match &invite.fields().service_inbox {
        Some(inbox) => EpicboxAddress::parse(inbox.as_str(), relays_network(network))
            .map_err(|_| ContactError::RelayAddress)?,
        None => reply_box.address().clone(),
    };
    let expires_at =
        invitee_deadline(at.now, invite.fields().expires).ok_or(ContactError::InviteExpired)?;
    repos.put_contact(&pending_record(
        new.contact_id,
        request.account,
        new.slot,
        new.box_salt,
        &card,
        ContactState::PendingReply,
        at.now,
    ))?;
    repos.put_pending_pairing(&PendingPairing {
        pairing_id: pairing_id_of(new.contact_id),
        role: PairingRole::Invitee,
        contact_id: new.contact_id,
        secrets: PairingSecrets {
            code: Some(code),
            na: None,
            nb: Some(*n_b.expose_bytes()),
            rc: Some(*rc.expose_bytes()),
        },
        invite_id: *invite.id().as_bytes(),
        expires_at,
        our_mailbox: confirm_box.address().to_string(),
        peer_mailbox: Some(to.to_string()),
        state: PairingState::PendingReply,
        created_at: at.now,
        invite: invite.as_bytes().to_vec(),
        expect_address: request.expect_address.clone(),
        expect_key: expected_key(request.expect_address.as_deref(), network)?,
        // Posted again on each collect until the confirm or a refusal comes.
        reply: Some(envelope.clone()),
        cancelled_at: None,
    })?;
    Ok((new.contact_id, envelope, reply_from, to))
}

/// Seals the reply `body` to `invite`. A private pairing's reply carries a fresh joiner secret,
/// and the channel key it makes with our `card` is kept in `private`.
fn seal_answer(
    invite: &Invite,
    body: &ReplyBody,
    card: &ContactCard,
    extras: &PairingExtras,
    private: &mut Option<PrivateSecrets>,
    rng: &mut LockedRng<'_>,
) -> Result<Vec<u8>, ContactError> {
    match private {
        None => seal_reply_with(invite, body, extras, rng),
        Some(secrets) => {
            let joiner = PrivateSecret::random(rng);
            let sealed = seal_private_reply(invite, body, &joiner, rng);
            secrets.channel = Some(ChannelKey::channel(&secrets.link, &joiner, invite, card));
            secrets.joiner = Some(joiner);
            sealed
        }
    }
    .map_err(ContactError::Encode)
}

/// Decides on an opened reply inside the store transaction that stores an accepted one with nA
/// consumed and its confirm kept.
fn decide_reply(
    repos: &mut dyn Repositories,
    rng: &SharedRng,
    net: lepic_contact::Network,
    now: Timestamp,
    taking: ReplyTaking,
) -> Result<Decision, ContactError> {
    let ReplyTaking {
        network,
        heard_by_hand,
        pairing_id,
        contact_id,
        peer,
        n_b,
        rc,
        expires,
        onion,
        home_text,
        signer,
        private,
        proven,
        peer_features,
        confirm_extras,
    } = taking;
    // Read again inside the transaction: another reply may have paired since.
    let Some(mut pending) = repos.pending_pairing(pairing_id)? else {
        return Ok(Decision::Drop);
    };
    if pending.cancelled_at.is_some() {
        return Ok(Decision::Refuse(
            Refusal::CancelledByInviter,
            may_refuse(repos, pairing_id)?,
        ));
    }
    let Some(n_a) = pending.secrets.na else {
        return reply_taken_again(repos, pairing_id, contact_id, &peer);
    };
    // A reply the relay held at the deadline is still taken by the first drain
    // after it (RFC 0002 C-14): the pending pairing ends at that drain, so one
    // still here was not drained since.
    if unix_seconds(now) >= late_reply_end(expires) {
        return Ok(Decision::Refuse(
            Refusal::Expired,
            may_refuse(repos, pairing_id)?,
        ));
    }
    let mut record = repos
        .contact(contact_id)?
        .ok_or(ContactError::UnknownPairing)?;
    let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
    // Only a card already held is refused as known; a store error is an error.
    match refuse_known_card(repos, &peer, &own) {
        Ok(()) => {}
        Err(ContactError::AlreadyPaired) => {
            return Ok(Decision::Known(may_refuse(repos, pairing_id)?));
        }
        Err(error) => return Err(error),
    }
    let expected = match unexpected(pending.expect_key.as_ref(), proven.as_ref()) {
        Ok(expected) => expected,
        Err(reason) => {
            drop_pairing(repos, pairing_id, contact_id)?;
            return Ok(Decision::Unexpected(reason));
        }
    };
    let n_a = Nonce::from_bytes(n_a);
    let body = ConfirmBody {
        nonce: n_a.clone(),
        card: own.clone(),
    };
    let mut guard = rng.lock();
    let mut rng = LockedRng(&mut **guard);
    let (sas, envelope) = match &private {
        None => (
            Sas::compute(net, &own, &peer, &n_a, &n_b),
            seal_confirm_with_extras(&peer, &body, &signer, &confirm_extras, &mut rng),
        ),
        Some(secrets) => {
            let (Some(joiner), Some(channel)) = (&secrets.joiner, &secrets.channel) else {
                return Ok(Decision::Drop);
            };
            super::private::put_secrets(repos, contact_id, secrets)?;
            (
                private_sas(net, &own, &peer, &n_a, &n_b, &secrets.link, joiner),
                seal_private_confirm(&peer, &body, &signer, channel, &mut rng),
            )
        }
    };
    drop(guard);
    let envelope = envelope.map_err(ContactError::Encode)?;
    record.facts.peer_features = peer_features;
    set_proven(&mut record, proven);
    super::status::learn_from_pairing(repos, &record, network, now)?;
    record.peer = Some(peer_card(&peer));
    record.state = ContactState::Paired;
    record.sas = Some(*sas.as_bytes());
    record.updated_at = now;
    // A contact that does not send the status notices is heard by its reply; one that does is
    // heard when it says it finished, or by anything else it sends in the pairing.
    if !super::status::sends_status(&record) || heard_by_hand {
        super::status::heard_now(&mut record, now);
    }
    // The wallet behind the address the request went to answered: no words to check.
    if expected {
        record.state = ContactState::Verified;
        record.verified_at = Some(now);
    }
    repos.put_contact(&record)?;
    repos.put_contact_mailbox(&paired_mailbox(contact_id, &peer, &own, home_text, onion))?;
    // The code still finds the reply mailbox until the invite ends, to refuse
    // later replies; without nA no second reply can pair. The confirm code lets
    // a mismatch in the SAS check tell the invitee.
    pending.secrets.na = None;
    pending.secrets.rc = Some(rc);
    repos.put_pending_pairing(&pending)?;
    repos.put_setting(&confirm_key(pairing_id), &hex(&envelope))?;
    Ok(Decision::Confirm(envelope))
}

/// Decides on a reply that came after nA was consumed: the reply that paired, taken again, gets
/// its kept confirm again; any other is refused as used.
fn reply_taken_again(
    repos: &mut dyn Repositories,
    pairing_id: PairingId,
    contact_id: ContactId,
    peer: &ContactCard,
) -> Result<Decision, ContactError> {
    let stored = repos.setting(&confirm_key(pairing_id))?;
    let same_peer = repos.contact(contact_id)?.is_some_and(|record| {
        record.peer.as_ref().map(|card| card.sig_key) == Some(peer.sig_key().to_bytes())
    });
    Ok(match stored.and_then(|text| unhex(&text)) {
        // The reply that paired, taken again: its confirm goes out again.
        Some(envelope) if same_peer => Decision::Again(envelope),
        _ => Decision::Refuse(Refusal::AlreadyUsed, may_refuse(repos, pairing_id)?),
    })
}

/// The confirm in `envelope`, opened with the pairing's keys, or with its channel key for a
/// private pairing; `None` when it does not open.
fn open_pairing_confirm(
    envelope: &[u8],
    net: lepic_contact::Network,
    keys: &crate::key_schedule::ContactKeys,
    class: &RecordClass,
) -> Option<(Confirm, PairingExtras)> {
    let sealed = SealedEnvelope::decode(envelope, net).ok()?;
    match class.private() {
        None => open_confirm_with(&sealed, &enc_secret(keys)),
        Some(secrets) => {
            open_private_confirm(&sealed, &enc_secret(keys), secrets.channel.as_ref()?)
                .map(|confirm| (confirm, PairingExtras::default()))
        }
    }
    .ok()
}

/// The inviter's side of the address proofs of a reply: the replier's address, when the
/// reply's proof verifies for our mailbox key, and what our confirm carries, with our proof made
/// for the replier's mailbox key.
#[allow(clippy::too_many_arguments)] // each is one input of the two proofs
fn reply_proofs(
    network: lepic_primitives::params::Network,
    keys: &crate::key_schedule::ContactKeys,
    invite: &Invite,
    reply: &ReplyBody,
    own: &ContactCard,
    extras: &PairingExtras,
    payments: &Payments,
    features: u32,
) -> (Option<ProvenAddress>, PairingExtras) {
    let net = contact_network(network);
    let proven = proven(
        keys.expose_box_secret(),
        network,
        &ProofBinding {
            network: net,
            step: ProofStep::Reply,
            prover_card: &reply.card,
            verifier_card: None,
            invite: Some(invite.as_bytes()),
        },
        extras.address_proof.as_ref(),
    );
    let address_proof = mailbox_key(&reply.card, network).and_then(|verifier| {
        payments.prove(
            &verifier,
            &ProofBinding {
                network: net,
                step: ProofStep::Confirm,
                prover_card: own,
                verifier_card: Some(&reply.card),
                invite: Some(invite.as_bytes()),
            },
        )
    });
    (
        proven,
        PairingExtras {
            address_proof,
            features: Some(features),
        },
    )
}

/// The inviter's address, when the confirm's proof verifies for our mailbox key over its card,
/// our card and the invite. Private pairings prove none.
fn confirm_proven(
    network: lepic_primitives::params::Network,
    keys: &crate::key_schedule::ContactKeys,
    class: &RecordClass,
    confirm: &ConfirmBody,
    own: &ContactCard,
    invite: &Invite,
    extras: &PairingExtras,
) -> Option<ProvenAddress> {
    if !matches!(class, RecordClass::Contact) {
        return None;
    }
    proven(
        keys.expose_box_secret(),
        network,
        &ProofBinding {
            network: contact_network(network),
            step: ProofStep::Confirm,
            prover_card: &confirm.card,
            verifier_card: Some(own),
            invite: Some(invite.as_bytes()),
        },
        extras.address_proof.as_ref(),
    )
}

/// Records the payments address a pairing proved. Without a proof the stored one stays.
pub(crate) fn set_proven(record: &mut ContactRecord, proven: Option<ProvenAddress>) {
    if let Some(proven) = proven {
        record.facts.payments_address = Some(proven.address);
        record.facts.payments_key = Some(proven.key);
    }
}

/// The SAS of an invitee's pairing; `None` for a private pairing without its joiner secret.
fn confirm_sas(
    net: lepic_contact::Network,
    class: &RecordClass,
    confirm: &ConfirmBody,
    own: &ContactCard,
    n_b: &Nonce,
) -> Option<Sas> {
    Some(match class.private() {
        None => Sas::compute(net, &confirm.card, own, &confirm.nonce, n_b),
        Some(secrets) => private_sas(
            net,
            &confirm.card,
            own,
            &confirm.nonce,
            n_b,
            &secrets.link,
            secrets.joiner.as_ref()?,
        ),
    })
}

/// Checks that an answer to the request of the wallet with the key `theirs` may go ahead.
/// Two crossed pairings, ours to them and theirs to us, keep the invite of the wallet with the
/// lower key: when ours wins, this fails with [`ContactError::Crossed`]; when theirs does, our
/// own request is withdrawn as a cancel withdraws it.
fn free_to_answer(
    repos: &mut dyn Repositories,
    ours: &[u8; 33],
    theirs: &[u8; 33],
    now: Timestamp,
) -> Result<(), ContactError> {
    if let Some(own) = super::requests::own_request_to(repos, theirs)? {
        if !super::requests::theirs_survives(ours, theirs) {
            return Err(ContactError::Crossed);
        }
        if let Some(mut pending) = repos.pending_pairing(pairing_id_of(own))? {
            pending.secrets.na = None;
            pending.cancelled_at = Some(now);
            repos.put_pending_pairing(&pending)?;
        }
    }
    super::requests::check_free(repos, theirs, false)
}

/// The key of an address a pairing expects, as the store keeps it.
fn expected_key(
    address: Option<&str>,
    network: lepic_primitives::params::Network,
) -> Result<Option<[u8; 33]>, ContactError> {
    address
        .map(|address| super::requests::address_key(address, network))
        .transpose()
}

/// Whether an answer proved the address its pairing expected: `Ok(true)` when it did,
/// `Ok(false)` when nothing was expected, and the failure otherwise. Addresses are compared by
/// key.
fn unexpected(
    expected: Option<&[u8; 33]>,
    proven: Option<&ProvenAddress>,
) -> Result<bool, PairingFailure> {
    let Some(expected) = expected else {
        return Ok(false);
    };
    match proven {
        None => Err(PairingFailure::AddressProofMissing),
        Some(proven) if &proven.key != expected => Err(PairingFailure::OtherAddress),
        Some(_) => Ok(true),
    }
}

/// Ends a pairing in progress with nothing stored: its pending pairing, its record and the
/// record's secrets go together.
fn drop_pairing(
    repos: &mut dyn Repositories,
    pairing_id: PairingId,
    contact_id: ContactId,
) -> Result<(), ContactError> {
    end_pending(repos, pairing_id)?;
    repos.delete_contact(contact_id)?;
    super::private::delete_secrets(repos, contact_id)?;
    Ok(())
}

/// The mailboxes of a contact just paired: the peer's from its card, ours from our own.
fn paired_mailbox(
    contact_id: ContactId,
    peer: &ContactCard,
    own: &ContactCard,
    home_relay: String,
    onion: Option<String>,
) -> ContactMailbox {
    ContactMailbox {
        contact_id,
        peer_mailbox: peer.fields().mailbox.as_str().to_owned(),
        our_mailbox: own.fields().mailbox.as_str().to_owned(),
        home_relay,
        onion,
        previous: None,
        backoff: Vec::new(),
    }
}

/// Refuses a peer card that is this wallet's own card or the card of a contact it holds: the
/// peer's sig key identifies a contact, and an existing one never changes silently.
/// What the store decided about a reply, before anything leaves.
enum Decision {
    /// The pairing is gone.
    Drop,
    /// The reply's card is one this wallet already pairs with, or its own; whether the
    /// refusal is still sent.
    Known(bool),
    /// Refused; whether the refusal is still sent.
    Refuse(Refusal, bool),
    /// The reply that paired, taken again; its stored confirm.
    Again(Vec<u8>),
    /// Paired now; the confirm to send.
    Confirm(Vec<u8>),
    /// The reply did not prove the address the invite expected; the pairing is gone.
    Unexpected(PairingFailure),
}

const CONFIRM_PREFIX: &str = "contact.confirm.";
const CONFIRM_OUT_PREFIX: &str = "contact.confirmout.";
const REFUSALS_PREFIX: &str = "contact.refusals.";

/// Refusals one invite sends at most, so a leaked invite cannot make the inviter post to
/// mailboxes of the repliers' choosing without end (RFC 0002 C-15).
const MAX_REFUSALS_PER_INVITE: u32 = 3;

/// The setting that counts the refusals an invite sent, until its pairing ends.
pub(crate) fn refusals_key(pairing_id: PairingId) -> String {
    format!("{REFUSALS_PREFIX}{}", hex(&pairing_id.0))
}

/// Ends a pairing in progress: the pending pairing, its kept confirm and its refusal count go
/// together. Returns whether the pending pairing was stored.
pub(crate) fn end_pending(
    repos: &mut dyn Repositories,
    pairing_id: PairingId,
) -> Result<bool, StoreError> {
    repos.delete_setting(&confirm_key(pairing_id))?;
    repos.delete_setting(&confirm_out_key(pairing_id))?;
    repos.delete_setting(&refusals_key(pairing_id))?;
    repos.delete_pending_pairing(pairing_id)
}

/// The setting that marks an inviter's confirm as sent: posted, or handed out by hand.
pub(crate) fn confirm_out_key(pairing_id: PairingId) -> String {
    format!("{CONFIRM_OUT_PREFIX}{}", hex(&pairing_id.0))
}

/// Unix seconds from which an inviter refuses a reply to an invite that expires at `expires`:
/// the end of its drain window and of the wait for one drain after it.
fn late_reply_end(expires: u64) -> u64 {
    expires
        .saturating_add(CLOCK_SKEW.as_secs())
        .saturating_add(LATE_DRAIN_WAIT.as_secs())
}

/// When an invitee that answers at `now` an invite expiring at `expires` stops waiting for the
/// confirm: an hour after answering, and never before the inviter, its clock up to
/// [`CLOCK_SKEW`] apart, could still take the reply.
fn invitee_deadline(now: Timestamp, expires: u64) -> Option<Timestamp> {
    let wait = now.checked_add(CONFIRM_WAIT).ok()?;
    let late = timestamp(late_reply_end(expires).saturating_add(CLOCK_SKEW.as_secs()));
    Some(wait.max(late))
}

/// The time a pairing in progress is past: an invite's expiry with the skew it is drained for,
/// an answer's wait for its confirm.
pub(crate) fn pending_deadline(pending: &PendingPairing) -> Option<Timestamp> {
    match pending.role {
        PairingRole::Inviter => pending.expires_at.checked_add(CLOCK_SKEW).ok(),
        PairingRole::Invitee => Some(pending.expires_at),
    }
}

/// Counts one more refusal for the invite, and returns whether it may still be sent.
fn may_refuse(repos: &mut dyn Repositories, pairing_id: PairingId) -> Result<bool, StoreError> {
    let key = refusals_key(pairing_id);
    let sent = repos
        .setting(&key)?
        .and_then(|text| text.parse::<u32>().ok())
        .unwrap_or(0);
    if sent >= MAX_REFUSALS_PER_INVITE {
        return Ok(false);
    }
    repos.put_setting(&key, &sent.saturating_add(1).to_string())?;
    Ok(true)
}

/// The setting that keeps an inviter's confirm until its pairing ends.
pub(crate) fn confirm_key(pairing_id: PairingId) -> String {
    format!("{CONFIRM_PREFIX}{}", hex(&pairing_id.0))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn refuse_known_card(
    repos: &dyn Repositories,
    peer: &ContactCard,
    own: &ContactCard,
) -> Result<(), ContactError> {
    if peer.sig_key() == own.sig_key()
        || repos
            .contact_by_peer_sig_key(&peer.sig_key().to_bytes())?
            .is_some()
    {
        return Err(ContactError::AlreadyPaired);
    }
    Ok(())
}

/// A pairing code whose invite id no pending pairing of this store uses (RFC 0002 2.4).
fn free_code(
    repos: &dyn Repositories,
    rng: &mut LockedRng<'_>,
) -> Result<PairingCode, ContactError> {
    for _ in 0..CODE_TRIES {
        let code = PairingCode::from_bytes(new_id(rng));
        if repos
            .pending_pairing_by_invite(InviteId::from_code(&code).as_bytes())?
            .is_none()
        {
            return Ok(code);
        }
    }
    Err(ContactError::UnknownPairing)
}
