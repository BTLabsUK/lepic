//! The pairing flows (RFC 0002 7.1 to 7.6): invites, replies, confirms, pairing in person and
//! the SAS check.

use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{
    Commitment, Confirm, ConfirmBody, ConfirmCode, ContactCard, ContactKind, Invite, InviteFields,
    InviteId, Nonce, PairingCode, PairingLink, ReplyBody, Sas, SealedEnvelope,
    pairing_envelope_from_link, pairing_envelope_link, seal_confirm, seal_reply,
};
use lepic_contact::{ContactName, Refusal, RelayHost, open_confirm, open_reply, seal_refusal};
use lepic_epicbox::{EpicboxAddress, RelayEndpoint};
use lepic_node::NodeApi;
use lepic_store::{
    AccountIndex, ContactId, ContactMailbox, ContactRecord, ContactState, PairingId, PairingRole,
    PairingSecrets, PairingState, PeerCard, PendingPairing, Repositories, SealMode, StoreError,
    WalletStore,
};
use tracing::{debug, info, instrument, warn};

use super::keys::{
    CardDetails, box_identity, contact_keys, contact_network, enc_secret, our_card,
    pairing_mailbox, signing_key,
};
use super::relay::{endpoint_for, host_text, post_envelope};
use super::{
    CLOCK_SKEW, CONFIRM_WAIT, ContactError, ContactRelays, ContactView, LockedRng, PairingFailure,
    new_id, pairing_id_of, same_secret,
};
use crate::event::{ContactEvent, Event, FailedPairing};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

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
    /// The screens differ: the pairing is deleted on this side.
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
    }
}

/// The fresh slot, box salt and keys of a new record.
struct NewSlot {
    contact_id: ContactId,
    slot: u32,
    box_salt: [u8; 16],
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Makes an invite to pair with a contact (RFC 0002 7.1). Its home relay is the relay of
    /// `relays`, where the reply mailbox and later both contact mailboxes live. The pending
    /// pairing is stored; [`Wallet::contacts_collect`] takes the reply. Without words nothing is
    /// sent.
    ///
    /// With `offer_words` the invite lasts 10 minutes and is also posted, sealed with five
    /// pairing words, to a rendezvous mailbox (RFC 0002 7.7). Words are offered only when the
    /// relay is a built-in one, else this fails with [`ContactError::WordsUnavailable`]; Offline
    /// or Epicbox off fail before anything is stored, and a post that fails is
    /// [`ContactError::Relay`], with the invite withdrawn.
    ///
    /// Fails with [`ContactError::Name`] for a name the card cannot carry, with
    /// [`ContactError::NetworkMismatch`], and as the store does, for example when every slot of
    /// the account is used or 64 pairings are pending.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_invite(
        &self,
        relays: &ContactRelays,
        request: InviteRequest,
    ) -> Result<InviteOffer, ContactError> {
        self.check_contact_network(relays)?;
        let network = self.config().network;
        let home = relays.epicbox.settings().endpoint.clone();
        let offer_words = request.offer_words;
        if offer_words {
            // Words are posted, so a relay must be reachable before anything is stored.
            super::relay::check_online(relays)?;
            if !super::words::built_in(relays, &home) {
                return Err(ContactError::WordsUnavailable);
            }
        }
        let lifetime = if offer_words {
            super::words::WORDS_INVITE_EXPIRY
        } else {
            request.expiry.duration()
        };
        let session = self.session()?;
        let words_home = home.clone();
        let mut offer = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                let expires_at = now
                    .checked_add(lifetime)
                    .map_err(|_| ContactError::InviteExpired)?;
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
                        },
                    )?;
                    let (n_a, code) = {
                        let mut guard = ports.rng.lock();
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
                            home_relay: RelayHost::new(&host_text(&home))
                                .map_err(ContactError::Name)?,
                            service_inbox: None,
                            onion: None,
                        },
                    )
                    .map_err(ContactError::Encode)?;
                    let (reply_box, _) = pairing_mailbox(*code.expose_bytes(), network, &home)?;
                    repos.put_contact(&pending_record(
                        new.contact_id,
                        request.account,
                        new.slot,
                        new.box_salt,
                        &card,
                        ContactState::PendingInvite,
                        now,
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
                        created_at: now,
                        invite: invite.as_bytes().to_vec(),
                    })?;
                    Ok(InviteOffer {
                        contact_id: new.contact_id,
                        link: invite.to_link(),
                        expires_at,
                        words: None,
                    })
                })
            })
            .await?;
        info!("pairing invite made");
        if offer_words {
            let invite = Invite::from_link(&offer.link, contact_network(network))
                .map_err(ContactError::StoredData)?;
            match self.post_invite_words(relays, &invite, &words_home).await {
                Ok(words) => offer.words = Some(words),
                Err(error) => {
                    // An invite nobody can find by its words is withdrawn at once, so it does
                    // not hold a pending pairing until it expires.
                    self.contact_remove(offer.contact_id).await?;
                    return Err(error);
                }
            }
        }
        Ok(offer)
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
        })
    }

    fn read_invite(&self, link: &str) -> Result<Invite, ContactError> {
        let invite = Invite::from_link(link, contact_network(self.config().network))
            .map_err(ContactError::Decode)?;
        let now = unix_seconds(self.ports().clock.now());
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
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_accept(
        &self,
        relays: &ContactRelays,
        request: AcceptRequest,
    ) -> Result<AcceptOutcome, ContactError> {
        self.check_contact_network(relays)?;
        let invite = self.read_invite(&request.link)?;
        let network = self.config().network;
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let session = self.session()?;
        let invite_for_work = invite.clone();
        let home_for_work = home.clone();
        let (contact_id, envelope, from, to) = self
            .contact_work(move |ports, _| {
                let invite = invite_for_work;
                let home = home_for_work;
                let now = ports.clock.now();
                session.store.write(|repos| {
                    if repos
                        .pending_pairing_by_invite(invite.id().as_bytes())?
                        .is_some()
                    {
                        return Err(ContactError::AlreadyPaired);
                    }
                    let mut rng = LockedRng(&mut **ports.rng.lock());
                    let new = take_slot(repos, &mut rng, request.account)?;
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
                            kind: ContactKind::Person,
                            name: &request.name,
                            seq: 1,
                        },
                    )?;
                    let n_b = Nonce::from_bytes(new_id(&mut rng));
                    let rc = ConfirmCode::from_bytes(new_id(&mut rng));
                    let body = ReplyBody {
                        code: invite.fields().code.clone(),
                        nonce: n_b.clone(),
                        confirm_code: rc.clone(),
                        card: card.clone(),
                    };
                    let envelope =
                        seal_reply(&invite, &body, &mut rng).map_err(ContactError::Encode)?;
                    let code = *invite.fields().code.expose_bytes();
                    let (reply_box, reply_from) = pairing_mailbox(code, network, &home)?;
                    let (confirm_box, _) = pairing_mailbox(*rc.expose_bytes(), network, &home)?;
                    let to = match &invite.fields().service_inbox {
                        Some(inbox) => {
                            EpicboxAddress::parse(inbox.as_str(), relays_network(network))
                                .map_err(|_| ContactError::RelayAddress)?
                        }
                        None => reply_box.address().clone(),
                    };
                    let expires_at = now
                        .checked_add(CONFIRM_WAIT)
                        .map_err(|_| ContactError::InviteExpired)?;
                    repos.put_contact(&pending_record(
                        new.contact_id,
                        request.account,
                        new.slot,
                        new.box_salt,
                        &card,
                        ContactState::PendingReply,
                        now,
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
                        created_at: now,
                        invite: invite.as_bytes().to_vec(),
                    })?;
                    Ok((new.contact_id, envelope, reply_from, to))
                })
            })
            .await?;
        let reply_link = pairing_envelope_link(PairingLink::Reply, &envelope);
        let posted = !request.by_hand
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
                    warn!(relay = %host_text(&home), error = %crate::inbox::ErrorChain(&error), "pairing reply not posted");
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

    /// Shows a card to pair in person (RFC 0002 7.4): a fresh slot whose mailbox is on the relay
    /// of `relays`. [`Wallet::pairing_scan_card`] finishes the pairing with the other phone's
    /// card. Nothing is sent, so this works offline.
    ///
    /// Fails as [`Wallet::pairing_invite`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_show_card(
        &self,
        relays: &ContactRelays,
        request: CardRequest,
    ) -> Result<CardOffer, ContactError> {
        self.check_contact_network(relays)?;
        let network = self.config().network;
        let home = relays.epicbox.settings().endpoint.clone();
        let session = self.session()?;
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
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_scan_card(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        link: &str,
    ) -> Result<ContactView, ContactError> {
        let network = self.config().network;
        let peer =
            ContactCard::from_link(link, contact_network(network)).map_err(ContactError::Decode)?;
        let peer_relay = mailbox_relay(&peer, relays)?;
        let home = relays.epicbox.settings().endpoint.clone();
        let session = self.session()?;
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
                    let sas = Sas::in_person(contact_network(network), &own, &peer);
                    record.peer = Some(peer_card(&peer));
                    record.state = ContactState::Paired;
                    record.sas = Some(*sas.as_bytes());
                    record.updated_at = now;
                    repos.put_contact(&record)?;
                    repos.put_contact_mailbox(&ContactMailbox {
                        contact_id,
                        peer_mailbox: peer.fields().mailbox.as_str().to_owned(),
                        our_mailbox: own.fields().mailbox.as_str().to_owned(),
                        home_relay: host_text(&home),
                        onion: None,
                        previous: None,
                        backoff: Vec::new(),
                    })?;
                    // A card QR is seen by anyone nearby: the first collect moves our mailbox.
                    repos.put_setting(&super::collect::in_person_key(contact_id), "1")?;
                    debug!(peer_relay = %peer_relay, "in-person pairing stored");
                    Ok(super::manage::view(&record, Some(host_text(&home)), now))
                })
            })
            .await?;
        info!("contact paired in person");
        self.emit(Event::PairingConfirmed(ContactEvent { contact_id }));
        Ok(view)
    }

    /// Records the user's SAS check (RFC 0002 7.5): a match makes the contact verified, a
    /// mismatch deletes the pairing on this side, skipping leaves it paired. After a mismatch an
    /// inviter posts a refusal to the invitee's confirm mailbox, best effort.
    ///
    /// Fails with [`ContactError::UnknownContact`] when no paired contact has that id.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_sas(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        decision: SasDecision,
    ) -> Result<(), ContactError> {
        let session = self.session()?;
        let tell = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mut record = repos
                        .contact(contact_id)?
                        .filter(|record| {
                            matches!(record.state, ContactState::Paired | ContactState::Verified)
                        })
                        .ok_or(ContactError::UnknownContact)?;
                    match decision {
                        SasDecision::Match => {
                            record.state = ContactState::Verified;
                            record.verified_at = Some(now);
                            record.updated_at = now;
                            repos.put_contact(&record)?;
                        }
                        SasDecision::Mismatch => {
                            let pending = repos.pending_pairing(pairing_id_of(contact_id))?;
                            end_pending(repos, pairing_id_of(contact_id))?;
                            super::invoices::drop_contact_invoices(repos, contact_id)?;
                            repos.delete_contact(contact_id)?;
                            let tell = pending
                                .filter(|pending| pending.role == PairingRole::Inviter)
                                .and_then(|pending| {
                                    Some((pending.secrets.rc?, pending.invite, record.peer?.bytes))
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
        if let Some((rc, invite, peer)) = tell {
            let net = contact_network(self.config().network);
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
            )
            .await;
        }
        Ok(())
    }

    /// Posts an anonymous refusal to the confirm mailbox of `rc`. Advisory, so a failure is
    /// logged and not returned.
    async fn post_refusal(
        &self,
        relays: &ContactRelays,
        invitee: &ContactCard,
        rc: [u8; 16],
        home: &RelayEndpoint,
        onion: Option<&str>,
        refusal: Refusal,
    ) {
        let posted = async {
            let envelope = seal_refusal(
                invitee,
                refusal,
                &mut LockedRng(&mut **self.ports().rng.lock()),
            )
            .map_err(ContactError::Encode)?;
            let (confirm_box, confirm_from) = pairing_mailbox(rc, self.config().network, home)?;
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
            warn!(error = %crate::inbox::ErrorChain(&error), "pairing refusal not posted");
        }
    }

    /// Takes a pairing reply or confirm the user pasted as `epiccash://pair-reply/1/...` or
    /// `epiccash://pair-confirm/1/...` (RFC 0002 7.2 and 7.3, manual mode). A reply to one of
    /// this wallet's invites pairs it and returns the confirm to send back by hand; a confirm
    /// finishes a pairing this wallet answered.
    ///
    /// Fails with [`ContactError::Decode`] for any other text.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_enter_link(
        &self,
        relays: &ContactRelays,
        text: &str,
    ) -> Result<LinkOutcome, ContactError> {
        let network = contact_network(self.config().network);
        let _turn = self.contact_turn().await;
        if let Ok(envelope) = pairing_envelope_from_link(text, PairingLink::Reply) {
            let sealed =
                SealedEnvelope::decode(&envelope, network).map_err(ContactError::Decode)?;
            let invite_id = *sealed.hint().as_bytes();
            let session = self.session()?;
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
                    Taken::Failed(_) | Taken::Ignored => LinkOutcome::Ignored,
                },
            );
        }
        let envelope =
            pairing_envelope_from_link(text, PairingLink::Confirm).map_err(ContactError::Decode)?;
        let session = self.session()?;
        let waiting = self
            .contact_work(move |_, _| Ok(session.store.read(|repos| repos.pending_pairings())?))
            .await?;
        for pending in waiting
            .into_iter()
            .filter(|pending| pending.role == PairingRole::Invitee)
        {
            match self.take_confirm(pending.pairing_id, &envelope).await? {
                Taken::Paired(contact_id) => return Ok(LinkOutcome::Paired { contact_id }),
                Taken::Failed(_) => return Ok(LinkOutcome::Ignored),
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
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let Some((pending, record)) = self.pending_with_record(pairing_id).await? else {
            return Ok(Taken::Ignored);
        };
        let contact_id = pending.contact_id;
        let Some(code) = pending.secrets.code else {
            return Ok(Taken::Ignored);
        };
        let keys = contact_keys(
            &session.keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        )?;
        let sealed = match SealedEnvelope::decode(envelope, net) {
            Ok(sealed) if sealed.hint().as_bytes() == &pending.invite_id => sealed,
            _ => return Ok(Taken::Ignored),
        };
        let Ok(reply) = open_reply(&sealed, &enc_secret(&keys)) else {
            debug!("pairing reply did not open");
            return Ok(Taken::Ignored);
        };
        if !same_secret(reply.code.expose_bytes(), &code) {
            debug!("pairing reply with another code dropped");
            return Ok(Taken::Ignored);
        }
        let invite = Invite::decode(&pending.invite, net).map_err(ContactError::StoredData)?;
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let onion_text = invite.fields().onion.as_ref().map(RelayHost::as_str);
        let peer = reply.card.clone();
        let n_b = reply.nonce.clone();
        let rc = *reply.confirm_code.expose_bytes();
        let expires = invite.fields().expires;
        let onion = onion_text.map(str::to_owned);
        let home_text = host_text(&home);
        let signer = signing_key(&keys);
        let decision = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    // Read again inside the transaction: another reply may have paired since.
                    let Some(mut pending) = repos.pending_pairing(pairing_id)? else {
                        return Ok(Decision::Drop);
                    };
                    let Some(n_a) = pending.secrets.na else {
                        let stored = repos.setting(&confirm_key(pairing_id))?;
                        let same_peer = repos.contact(contact_id)?.is_some_and(|record| {
                            record.peer.as_ref().map(|card| card.sig_key)
                                == Some(peer.sig_key().to_bytes())
                        });
                        return Ok(match stored.and_then(|text| unhex(&text)) {
                            // The reply that paired, taken again: its confirm goes out again.
                            Some(envelope) if same_peer => Decision::Again(envelope),
                            _ => Decision::Refuse(
                                Refusal::AlreadyUsed,
                                may_refuse(repos, pairing_id)?,
                            ),
                        });
                    };
                    if unix_seconds(now) >= expires {
                        return Ok(Decision::Refuse(
                            Refusal::Expired,
                            may_refuse(repos, pairing_id)?,
                        ));
                    }
                    let mut record = repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownPairing)?;
                    let own = ContactCard::decode(&record.own_card, net)
                        .map_err(ContactError::StoredData)?;
                    // Only a card already held is refused as known; a store error is an error.
                    match refuse_known_card(repos, &peer, &own) {
                        Ok(()) => {}
                        Err(ContactError::AlreadyPaired) => {
                            return Ok(Decision::Known(may_refuse(repos, pairing_id)?));
                        }
                        Err(error) => return Err(error),
                    }
                    let n_a = Nonce::from_bytes(n_a);
                    let sas = Sas::compute(net, &own, &peer, &n_a, &n_b);
                    let envelope = seal_confirm(
                        &peer,
                        &ConfirmBody {
                            nonce: n_a,
                            card: own.clone(),
                        },
                        &signer,
                        &mut LockedRng(&mut **ports.rng.lock()),
                    )
                    .map_err(ContactError::Encode)?;
                    record.peer = Some(peer_card(&peer));
                    record.state = ContactState::Paired;
                    record.sas = Some(*sas.as_bytes());
                    record.updated_at = now;
                    repos.put_contact(&record)?;
                    repos.put_contact_mailbox(&ContactMailbox {
                        contact_id,
                        peer_mailbox: peer.fields().mailbox.as_str().to_owned(),
                        our_mailbox: own.fields().mailbox.as_str().to_owned(),
                        home_relay: home_text,
                        onion,
                        previous: None,
                        backoff: Vec::new(),
                    })?;
                    // The code still finds the reply mailbox until the invite ends, to refuse
                    // later replies; without nA no second reply can pair. The confirm code lets
                    // a mismatch in the SAS check tell the invitee.
                    pending.secrets.na = None;
                    pending.secrets.rc = Some(rc);
                    repos.put_pending_pairing(&pending)?;
                    repos.put_setting(&confirm_key(pairing_id), &hex(&envelope))?;
                    Ok(Decision::Confirm(envelope))
                })
            })
            .await?;
        let (envelope, first) = match decision {
            Decision::Drop => return Ok(Taken::Ignored),
            Decision::Known(tell) => {
                warn!("pairing reply from a contact already paired refused");
                if tell && !by_hand {
                    self.post_refusal(
                        relays,
                        &reply.card,
                        rc,
                        &home,
                        onion_text,
                        Refusal::AlreadyUsed,
                    )
                    .await;
                }
                return Ok(Taken::Failed(None));
            }
            Decision::Refuse(refusal, tell) => {
                debug!("pairing reply refused");
                if tell && !by_hand {
                    self.post_refusal(relays, &reply.card, rc, &home, onion_text, refusal)
                        .await;
                }
                return Ok(Taken::Ignored);
            }
            Decision::Again(envelope) => (envelope, false),
            Decision::Confirm(envelope) => (envelope, true),
        };
        if !by_hand {
            let (confirm_box, confirm_from) = pairing_mailbox(rc, network, &home)?;
            post_envelope(
                relays,
                &confirm_from,
                confirm_box.address(),
                onion_text,
                &envelope,
            )
            .await?;
        }
        if first {
            info!("pairing reply taken");
            self.emit(Event::PairingReplied(ContactEvent { contact_id }));
        }
        Ok(if by_hand {
            Taken::ConfirmLink(
                contact_id,
                pairing_envelope_link(PairingLink::Confirm, &envelope),
            )
        } else {
            Taken::Paired(contact_id)
        })
    }

    /// The invitee's side of a confirm (RFC 0002 7.3): the revealed nonce and card must match
    /// the invite's commitment and enc key, or the pairing ends with nothing stored.
    pub(crate) async fn take_confirm(
        &self,
        pairing_id: PairingId,
        envelope: &[u8],
    ) -> Result<Taken, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let Some((pending, record)) = self.pending_with_record(pairing_id).await? else {
            return Ok(Taken::Ignored);
        };
        let contact_id = pending.contact_id;
        let Some(n_b) = pending.secrets.nb else {
            return Ok(Taken::Ignored);
        };
        let keys = contact_keys(
            &session.keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        )?;
        let Ok(sealed) = SealedEnvelope::decode(envelope, net) else {
            return Ok(Taken::Ignored);
        };
        let confirm = match open_confirm(&sealed, &enc_secret(&keys)) {
            Ok(Confirm::Accepted(body)) => body,
            Ok(Confirm::Refused(refusal)) => {
                // Advisory: only the inviter knows the confirm mailbox, and nothing of the
                // refusal is kept but the end of this pairing.
                let pairing_id = pending.pairing_id;
                self.contact_work(move |_, _| {
                    session.store.write(|repos| {
                        end_pending(repos, pairing_id)?;
                        repos.delete_contact(contact_id)?;
                        Ok(())
                    })
                })
                .await?;
                info!("pairing refused by the inviter");
                let failed = FailedPairing {
                    contact_id,
                    reason: PairingFailure::Refused(refusal),
                };
                self.emit(Event::PairingFailed(failed));
                return Ok(Taken::Failed(Some(failed)));
            }
            Err(_) => return Ok(Taken::Ignored),
        };
        let invite = Invite::decode(&pending.invite, net).map_err(ContactError::StoredData)?;
        let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
        let pairing_id = pending.pairing_id;
        if !confirm.matches_invite(&invite) {
            self.contact_work(move |_, _| {
                session.store.write(|repos| {
                    end_pending(repos, pairing_id)?;
                    repos.delete_contact(contact_id)?;
                    Ok(())
                })
            })
            .await?;
            warn!("pairing confirm does not match the invite");
            let failed = FailedPairing {
                contact_id,
                reason: PairingFailure::ChangedOnTheWay,
            };
            self.emit(Event::PairingFailed(failed));
            return Ok(Taken::Failed(Some(failed)));
        }
        let sas = Sas::compute(
            net,
            &confirm.card,
            &own,
            &confirm.nonce,
            &Nonce::from_bytes(n_b),
        );
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
                    record.peer = Some(peer_card(&peer));
                    record.state = ContactState::Paired;
                    record.sas = Some(*sas.as_bytes());
                    record.updated_at = now;
                    repos.put_contact(&record)?;
                    repos.put_contact_mailbox(&ContactMailbox {
                        contact_id,
                        peer_mailbox: peer.fields().mailbox.as_str().to_owned(),
                        our_mailbox: own.fields().mailbox.as_str().to_owned(),
                        home_relay: home_text,
                        onion,
                        previous: None,
                        backoff: Vec::new(),
                    })?;
                    end_pending(repos, pairing_id)?;
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
        self.emit(Event::PairingConfirmed(ContactEvent { contact_id }));
        Ok(Taken::Paired(contact_id))
    }

    /// The pairing in progress `pairing_id` and its record, as stored now.
    async fn pending_with_record(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<(PendingPairing, ContactRecord)>, ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                let Some(pending) = repos.pending_pairing(pairing_id)? else {
                    return Ok::<_, lepic_store::StoreError>(None);
                };
                Ok(repos
                    .contact(pending.contact_id)?
                    .map(|record| (pending, record)))
            })?)
        })
        .await
    }

    pub(crate) fn check_contact_network(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        if relays.epicbox.network() != crate::inbox::relay_network(self.config().network) {
            return Err(ContactError::NetworkMismatch);
        }
        Ok(())
    }

    /// Runs store and key work on the blocking pool.
    pub(crate) async fn contact_work<T, F>(&self, work: F) -> Result<T, ContactError>
    where
        T: Send + 'static,
        F: FnOnce(&crate::Ports<N, S, V>, &crate::WalletConfig) -> Result<T, ContactError>
            + Send
            + 'static,
    {
        self.blocking(move |ports, config| Ok(work(ports, config)))
            .await?
    }
}

fn relays_network(network: lepic_primitives::params::Network) -> lepic_epicbox::Network {
    crate::inbox::relay_network(network)
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
}

const CONFIRM_PREFIX: &str = "contact.confirm.";
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
    repos.delete_setting(&refusals_key(pairing_id))?;
    repos.delete_pending_pairing(pairing_id)
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
