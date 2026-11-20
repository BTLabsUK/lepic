// SPDX-License-Identifier: Apache-2.0
//! The pairing flows (RFC 0002 7.1 to 7.6): invites, replies, confirms, pairing in person and
//! the SAS check.

use crate::hex;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::armor;
use lepic_contact::{
    ChannelKey, PairingClass, PrivateSecret, open_private_confirm, open_private_reply, private_sas,
    seal_private_confirm, seal_private_refusal, seal_private_reply,
};
use lepic_contact::{
    Commitment, Confirm, ConfirmBody, ConfirmCode, ContactCard, ContactKind, DomainClaim, Invite,
    InviteFields, InviteId, Nonce, PairingCode, PairingExtras, PairingLink, ReplyBody, Sas,
    SealedEnvelope, open_confirm_with, open_reply_with, pairing_envelope_from_link,
    pairing_envelope_link, seal_confirm_with_extras, seal_reply_with,
};
use lepic_contact::{ContactName, Refusal, RelayHost, seal_refusal};
use lepic_epic1::{MethodId, RouteEntry};
use lepic_epicbox::{EpicboxAddress, RelayEndpoint};
use lepic_methods::epicbox::relay_network;
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_store::{
    AccountIndex, ContactId, ContactMailbox, ContactRecord, ContactState, DomainClaimBytes,
    NativeOutboxId, OutboxState, PAYMENTS_KEY_LEN, PairingId, PairingRole, PairingSecrets,
    PairingState, PeerCard, PendingPairing, Repositories, SealMode, StoreError, WalletStore,
};
use tracing::{debug, info, instrument, warn};

use super::address_proof::{
    Payments, ProofBinding, ProofStep, ProvenAddress, domain_signer, invite_mailbox_key,
    mailbox_key, proven,
};
use super::keys::{
    CardDetails, box_identity, contact_keys, contact_network, enc_secret, our_card,
    pairing_mailbox, signing_key,
};
use super::outbox::queue_mail;
use super::private::{PrivateSecrets, RecordClass, class_of, record_keys};
use super::relay::{check_online, endpoint_for, host_text};
use super::{
    CLOCK_SKEW, CONFIRM_WAIT, ContactError, ContactRelays, LATE_DRAIN_WAIT, LockedRng,
    PairingFailure, new_id, pairing_id_of, same_secret,
};
use crate::ContactBook;
use crate::delivery::epicbox::{Envelope, MailboxRelay};
use crate::delivery::outbox::{Sender, link_carrier};
use crate::delivery::transport::Transport;
use crate::domain::DomainSigner;
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
    /// Deprecated: always written for wallets that read it, never to be read for meaning;
    /// to be removed (docs/adr/0041 or RFC 0002 6.1).
    pub kind: ContactKind,
    pub expiry: InviteExpiry,
    /// Where the pairing's mailboxes live, `domain[:port]`; `None` is the wallet's own relay.
    pub home_relay: Option<String>,
    /// A contact, or a private pairing of two wallets of one owner, which carries only the host
    /// app's payloads.
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
}

/// What an invite claims, for the user to decide on before answering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePreview {
    /// The inviter's own name for itself, unverified.
    pub claimed_name: String,
    /// Deprecated: always written for wallets that read it, never to be read for meaning;
    /// to be removed (docs/adr/0041 or RFC 0002 6.1).
    pub kind: ContactKind,
    pub expires_at: Timestamp,
    /// The relay where the pairing's mailboxes live.
    pub home_relay: String,
    /// The invite comes from a service with a fixed pairing inbox.
    pub service: bool,
    pub class: PairingClass,
    /// This wallet made the invite: standing, waiting or cancelled. Answering it fails with
    /// [`ContactError::AlreadyPaired`].
    pub own: bool,
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
/// never change by a card: only [`ContactBook::contact_keys_resolve`] with `UseNew` moves a contact
/// to other keys.
pub(crate) fn same_keys(stored: &PeerCard, card: &ContactCard) -> bool {
    let fresh = peer_card(card);
    stored.sig_key == fresh.sig_key
        && stored.enc_key == fresh.enc_key
        && stored.hint_key == fresh.hint_key
}

/// The home relay `host` names, or the first mailbox of the list for none.
fn home_relay(host: Option<&str>, relays: &ContactRelays) -> Result<RelayEndpoint, ContactError> {
    match host {
        Some(host) => endpoint_for(host, relays),
        None => Ok(relays.home()),
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
    /// Signs the domain claim the pairing's reply carries; none for a wallet that claims no
    /// domain and for a private pairing.
    domain: Option<&'a DomainSigner>,
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
    /// The domain the reply claims to speak for, unverified.
    peer_domain: Option<DomainClaim>,
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
    /// pairing is stored; [`ContactBook::contacts_collect`] takes the reply. Nothing is sent.
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
        let lifetime = request.expiry.duration();
        let session = self.wallet.session()?;
        let payments = (request.class == PairingClass::Contact)
            .then(|| Payments::of(&session.keychain, network, relays))
            .transpose()?;
        let features = self.wallet.config().pairing_features();
        let offer = self
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
                    // An invite carries no extensions; the replies do.
                    domain: None,
                };
                session
                    .store
                    .write(|repos| store_invite(repos, &ports.rng, &at, &request, expires_at))
            })
            .await?;
        info!("pairing invite made");
        Ok(offer)
    }

    /// Reads an invite link for the user to decide on (RFC 0002 7.2), and tells whether this
    /// wallet made it. Nothing is stored or sent.
    ///
    /// Fails with [`ContactError::Decode`] for text that is not an invite on the wallet's
    /// network, with [`ContactError::InviteExpired`] for one past its expiry by more than
    /// [`CLOCK_SKEW`], with [`lepic_wallet::WalletError::Locked`] and as the store does.
    pub async fn pairing_preview(&self, link: &str) -> Result<InvitePreview, ContactError> {
        let invite = self.read_invite(link)?;
        let session = self.wallet.session()?;
        let invite_id = invite.id().as_bytes().to_owned();
        // The pending pairing `pairing_accept` refuses an invite by, kept for standing,
        // waiting and cancelled invites alike.
        let own = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    repos
                        .pending_pairing_by_invite(&invite_id)
                        .map(|pending| pending.is_some_and(|p| p.role == PairingRole::Inviter))
                })?)
            })
            .await?;
        let fields = invite.fields();
        Ok(InvitePreview {
            claimed_name: fields.name.as_str().to_owned(),
            kind: fields.kind,
            expires_at: timestamp(fields.expires),
            home_relay: fields.home_relay.as_str().to_owned(),
            service: fields.service_inbox.is_some(),
            class: invite.class(),
            own,
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
    /// posted is never lost to a closed app, then posts the reply to the invite's reply mailbox or
    /// service inbox unless `by_hand` is set. The reply link is returned either way, for "Send by
    /// hand" and for a post that failed. [`ContactBook::contacts_collect`] takes the confirm.
    ///
    /// Fails as [`ContactBook::pairing_preview`] does, with [`ContactError::AlreadyPaired`] for an
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
        let features = self.wallet.config().pairing_features();
        let domain = if request.class == PairingClass::Contact {
            domain_signer(
                &session.keychain,
                network,
                self.wallet.config().domain.as_deref(),
            )?
        } else {
            None
        };
        let expect_key = expected_key(request.expect_address.as_deref(), network)?;
        let ours = payments.as_ref().map(Payments::key);
        let (contact_id, envelope, row) = self
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
                    domain: domain.as_ref(),
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
        let posted = !by_hand && check_online(relays).is_ok() && {
            let _turn = self.wallet.contact_turn().await;
            self.post_mail(relays, row, "pairing reply not posted")
                .await
        };
        info!("pairing invite answered");
        Ok(AcceptOutcome {
            contact_id,
            reply_link,
            posted,
        })
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
        let (tell, row) = self
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
                         notice: lepic_wallet::notice::Notice| {
                            if !super::status::sends_status(record) {
                                return None;
                            }
                            super::status::queue_status(
                                repos,
                                &session.keychain,
                                network,
                                &ports.rng,
                                record,
                                &notice,
                                now,
                            )
                            .unwrap_or_else(|error| {
                                super::status::queue_failed(&error);
                                None
                            })
                        };
                    let mut row = None;
                    match decision {
                        SasDecision::Match => {
                            record.state = ContactState::Verified;
                            record.verified_at = Some(now);
                            record.updated_at = now;
                            super::status::heard_now(&mut record, now);
                            repos.put_contact(&record)?;
                            if let Some(hash) = verdict {
                                row = queue(
                                    repos,
                                    &record,
                                    lepic_wallet::notice::Notice::PairMatch { sas: hash },
                                );
                            }
                        }
                        SasDecision::Mismatch => {
                            let pending = repos.pending_pairing(pairing_id_of(contact_id))?;
                            end_pending(repos, pairing_id_of(contact_id))?;
                            super::invoices::drop_contact_invoices(repos, contact_id)?;
                            super::outbox::drop_contact_rows(repos, contact_id)?;
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
                                row = queue(
                                    repos,
                                    &record,
                                    lepic_wallet::notice::Notice::PairMismatch { sas: hash },
                                );
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
                            return Ok((tell, row));
                        }
                        SasDecision::Skip => {}
                    }
                    Ok((None, row))
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
        if let Some(row) = row
            && check_online(relays).is_ok()
        {
            let _turn = self.wallet.contact_turn().await;
            self.post_mail(relays, row, "pairing status not posted")
                .await;
        }
        Ok(())
    }

    /// Cancels a pairing in progress (RFC 0002 7.6). An invite of ours that no reply paired is
    /// kept, hidden, until it expires, so a late reply is refused with
    /// [`Refusal::CancelledByInviter`] and the replier learns it; its nonce is dropped, so
    /// nothing can pair with it any more. At most [`lepic_store::MAX_CANCELLED_PAIRINGS`] are
    /// kept, the oldest dropped. Any other pairing in progress, and our answer to an invite,
    /// are removed as [`ContactBook::contact_remove`] removes them. Returns whether anything was
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

    /// Posts an anonymous refusal to the confirm mailbox of `rc`, under `channel` for a private
    /// pairing, once and with no outbox row: to every usable relay, and to the invite's relay
    /// `home` when the list lacks it. Advisory, so a failure is logged and not returned.
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
        let sealed = {
            let mut guard = self.wallet.ports().rng.lock();
            let mut rng = LockedRng(&mut **guard);
            match channel {
                None => seal_refusal(invitee, refusal, &mut rng),
                Some(channel) => seal_private_refusal(invitee, refusal, channel, &mut rng),
            }
        }
        .map_err(ContactError::Encode);
        let made = sealed.and_then(|envelope| {
            check_online(relays)?;
            let (confirm_box, from) = pairing_mailbox(&rc, self.wallet.config().network, home)?;
            Ok((envelope, confirm_box, from))
        });
        let (envelope, confirm_box, from) = match made {
            Ok(made) => made,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "pairing refusal not posted");
                return;
            }
        };
        let envelope = Envelope::Mailbox {
            from,
            payload: armor(&envelope),
            relay: Some(MailboxRelay {
                endpoint: home.clone(),
                onion: onion.map(str::to_owned),
            }),
            txid: None,
            list: None,
        };
        let route = RouteEntry {
            method: MethodId::Epicbox,
            value: confirm_box.address().key_text(),
        };
        // Boxed: the post's future is large, and every pairing step that awaits this one would
        // carry it on its own state and stack.
        let carrier = link_carrier(relays);
        if let Err(error) = Box::pin(carrier.post(&envelope, &route, None)).await {
            warn!(error = %ErrorChain(&error), "pairing refusal not posted");
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

    /// The address proof and the domain claim our confirm carries for a reply of a non-private
    /// pairing, and the address the reply proved (RFC 0002 6.2, 6.3). A private pairing proves
    /// and claims nothing.
    fn confirm_proofs(
        &self,
        relays: &ContactRelays,
        keychain: &lepic_keychain::Keychain,
        opened: &OpenedReply,
    ) -> Result<(Option<ProvenAddress>, PairingExtras), ContactError> {
        if opened.private.is_some() {
            return Ok((None, PairingExtras::default()));
        }
        let network = self.wallet.config().network;
        let payments = Payments::of(keychain, network, relays)?;
        let features = self.wallet.config().pairing_features();
        let claim = domain_signer(keychain, network, self.wallet.config().domain.as_deref())?.map(
            |domain| {
                let now = self.wallet.ports().clock.now();
                domain.claim(
                    contact_network(network),
                    &signing_key(&opened.keys).verifying_key(),
                    u64::try_from(now.as_second()).unwrap_or(0),
                )
            },
        );
        Ok(reply_proofs(
            network,
            &opened.keys,
            &opened.invite,
            &opened.reply,
            &opened.own,
            &opened.extras,
            &payments,
            features,
            claim,
        ))
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
        let Some(opened) = self
            .open_pairing_reply(&session.keychain, pairing_id, envelope)
            .await?
        else {
            return Ok(Taken::Ignored);
        };
        let (proven, confirm_extras) = self.confirm_proofs(relays, &session.keychain, &opened)?;
        let OpenedReply {
            contact_id,
            keys,
            invite,
            reply,
            extras,
            private,
            ..
        } = opened;
        let channel = private.as_ref().and_then(|secrets| secrets.channel.clone());
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let onion_text = invite.fields().onion.as_ref().map(RelayHost::as_str);
        let rc = *reply.confirm_code.expose_bytes();
        let confirm_to = pairing_mailbox(&rc, network, &home)?.0.address().key_text();
        let taking = ReplyTaking {
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
            peer_domain: extras.domain,
            confirm_extras,
        };
        let (decision, row) = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let decision = decide_reply(repos, &ports.rng, net, now, taking)?;
                    // The confirm leaves as a row in the same write as the decision, so it
                    // goes out whatever happens to this call.
                    let row = match &decision {
                        Decision::Confirm(envelope) | Decision::Again(envelope) if !by_hand => {
                            queue_confirm(repos, &ports.rng, pairing_id, confirm_to, envelope, now)?
                        }
                        _ => None,
                    };
                    Ok::<_, ContactError>((decision, row))
                })
            })
            .await?;
        let route = ReplyRoute {
            invitee: &reply.card,
            rc,
            home: &home,
            onion: onion_text,
            channel: channel.as_ref(),
        };
        let confirm = self
            .confirm_of(relays, &route, decision, contact_id, by_hand)
            .await;
        let (envelope, first) = match confirm {
            Ok(confirm) => confirm,
            Err(taken) => return Ok(taken),
        };
        // Paired from here on, whether or not the confirm leaves now: the host hears it once,
        // and a confirm that did not leave stays in the outbox for its back-off.
        if first {
            info!("pairing reply taken");
            self.wallet
                .emit(Event::PairingReplied(ContactEvent { contact_id }));
        }
        self.send_confirm(relays, row, pairing_id, contact_id, &envelope, by_hand)
            .await
    }

    /// The confirm of `decision` and whether it pairs now. Any other decision comes to what
    /// the reply is taken as, with the refusal posted first when one is still sent.
    async fn confirm_of(
        &self,
        relays: &ContactRelays,
        route: &ReplyRoute<'_>,
        decision: Decision,
        contact_id: ContactId,
        by_hand: bool,
    ) -> Result<(Vec<u8>, bool), Taken> {
        match decision {
            Decision::Drop => Err(Taken::Ignored),
            Decision::Unexpected(reason) => {
                warn!("pairing reply from another wallet than expected refused");
                // The pairing goes on; a reply taken by hand says why it was refused.
                Err(if by_hand {
                    Taken::Failed(Some(FailedPairing { contact_id, reason }))
                } else {
                    Taken::Ignored
                })
            }
            Decision::Known(tell) => {
                warn!("pairing reply from a contact already paired refused");
                if tell && !by_hand {
                    self.refuse_reply(relays, route, Refusal::AlreadyUsed).await;
                }
                Err(Taken::Failed(None))
            }
            Decision::Refuse(refusal, tell) => {
                debug!("pairing reply refused");
                if tell && !by_hand {
                    self.refuse_reply(relays, route, refusal).await;
                }
                Err(Taken::Ignored)
            }
            Decision::Again(envelope) => Ok((envelope, false)),
            Decision::Confirm(envelope) => Ok((envelope, true)),
        }
    }

    /// Sends the confirm of a reply that paired: its outbox row `row` posted at once, for a
    /// caller that holds the contact engine's turn, or the confirm returned as a link to send
    /// `by_hand`, which counts as sent. A posted row counts as sent when a relay takes it.
    async fn send_confirm(
        &self,
        relays: &ContactRelays,
        row: Option<NativeOutboxId>,
        pairing_id: PairingId,
        contact_id: ContactId,
        envelope: &[u8],
        by_hand: bool,
    ) -> Result<Taken, ContactError> {
        if by_hand {
            self.mark_confirm_out(pairing_id).await?;
            return Ok(Taken::ConfirmLink(
                contact_id,
                pairing_envelope_link(PairingLink::Confirm, envelope),
            ));
        }
        if let Some(row) = row
            && check_online(relays).is_ok()
        {
            self.post_mail(relays, row, "pairing confirm not posted")
                .await;
        }
        Ok(Taken::Paired(contact_id))
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
        if confirm.card.fields().kind != invite.fields().kind {
            self.contact_work(move |_, _| {
                session
                    .store
                    .write(|repos| drop_pairing(repos, pairing_id, contact_id))
            })
            .await?;
            warn!("pairing confirm card names another kind than the invite");
            return Ok(self.pairing_failed(contact_id, PairingFailure::KindDiffers));
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
        let peer_domain = extras.domain;
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
                    record.facts.peer_domain = peer_domain.as_ref().map(claim_bytes);
                    set_proven(&mut record, proven);
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
                    // An inviter that claims the status notices waits to hear that we finished. The
                    // collect run that took this confirm posts the row after its reads.
                    if super::status::sends_status(&record)
                        && let Err(error) = super::status::queue_status(
                            repos,
                            &session.keychain,
                            network,
                            &ports.rng,
                            &record,
                            &lepic_wallet::notice::Notice::PairFinished,
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
            != lepic_methods::epicbox::relay_network(self.wallet.config().network)
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
        PairingFailure::KindDiffers => Some(ContactError::KindDiffers),
        _ => None,
    }
}

fn relays_network(network: lepic_primitives::params::Network) -> lepic_epicbox::Network {
    lepic_methods::epicbox::relay_network(network)
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

/// The kind every new invite and card writes. The request's `kind` is deprecated and ignored: a
/// reader refuses a confirm or card update whose kind differs from the invite's or the stored
/// one, so the invite and the pairing's cards must agree, and every later card clones this one
/// (ADR 0041).
const WRITTEN_KIND: ContactKind = ContactKind::Person;

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
    let card = new_card(&keys, at, WRITTEN_KIND, &request.name)?;
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
            kind: WRITTEN_KIND,
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
    })
}

/// Stores the record and pending pairing of an answer to `invite`, and the outbox row of its
/// reply, and returns the record's id, the sealed reply and the row.
fn store_answer(
    repos: &mut dyn Repositories,
    rng: &SharedRng,
    at: &NewPairing<'_>,
    invite: &Invite,
    request: &AcceptRequest,
) -> Result<(ContactId, Vec<u8>, NativeOutboxId), ContactError> {
    if repos
        .pending_pairing_by_invite(invite.id().as_bytes())?
        .is_some()
    {
        return Err(ContactError::AlreadyPaired);
    }
    let network = at.network;
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
    let card = new_card(&keys, at, WRITTEN_KIND, &request.name)?;
    let n_b = Nonce::from_bytes(new_id(&mut rng));
    let rc = ConfirmCode::from_bytes(new_id(&mut rng));
    let body = ReplyBody {
        code: invite.fields().code.clone(),
        nonce: n_b.clone(),
        confirm_code: rc.clone(),
        card: card.clone(),
    };
    let extras = answer_extras(at, invite, &card, &keys);
    let envelope = seal_answer(invite, &body, &card, &extras, &mut private, &mut rng)?;
    if let Some(secrets) = &private {
        super::private::put_secrets(repos, new.contact_id, secrets)?;
    }
    let code = *invite.fields().code.expose_bytes();
    let (reply_box, _) = pairing_mailbox(&code, network, at.home)?;
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
        reply: Some(envelope.clone()),
        cancelled_at: None,
    })?;
    let row = queue_mail(
        repos,
        new_id(&mut rng),
        Sender::Pairing(pairing_id_of(new.contact_id)),
        to.key_text(),
        armor(&envelope),
        at.now,
    )?;
    Ok((new.contact_id, envelope, row))
}

/// What an answer to `invite` carries beside its card: the address proof, our features and the
/// domain claim.
fn answer_extras(
    at: &NewPairing<'_>,
    invite: &Invite,
    card: &ContactCard,
    keys: &crate::key_schedule::ContactKeys,
) -> PairingExtras {
    PairingExtras {
        address_proof: at.payments.and_then(|payments| {
            payments.prove(
                &invite_mailbox_key(invite)?,
                &ProofBinding {
                    network: invite.network(),
                    step: ProofStep::Reply,
                    prover_card: card,
                    verifier_card: None,
                    invite: Some(invite.as_bytes()),
                },
            )
        }),
        features: Some(at.features),
        domain: at.domain.map(|domain| {
            domain.claim(
                invite.network(),
                &signing_key(keys).verifying_key(),
                u64::try_from(at.now.as_second()).unwrap_or(0),
            )
        }),
    }
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
        peer_domain,
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
    // A reply the relay held at the deadline is still taken by the first read
    // after it (RFC 0002 C-14): the pending pairing ends at that read, so one
    // still here was not read since.
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
        // Anyone holding the invite may answer first: the pairing keeps waiting for the
        // wallet it expects.
        Err(reason) => return Ok(Decision::Unexpected(reason)),
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
    record.facts.peer_domain = peer_domain.as_ref().map(claim_bytes);
    set_proven(&mut record, proven);
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
    repos.put_setting(&confirm_key(pairing_id), &hex::encode(&envelope))?;
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
    Ok(match stored.and_then(|text| hex::unhex(&text)) {
        // The reply that paired, taken again: its confirm goes out again.
        Some(envelope) if same_peer => Decision::Again(envelope),
        _ => Decision::Refuse(Refusal::AlreadyUsed, may_refuse(repos, pairing_id)?),
    })
}

/// The outbox row of the confirm in `envelope` to the mailbox key `to_key`: `None` when a
/// relay took it already, so a reply read again, on another relay or later, sends no second
/// confirm; the row still waiting, if one does; else a new row.
fn queue_confirm(
    repos: &mut dyn Repositories,
    rng: &SharedRng,
    pairing_id: PairingId,
    to_key: String,
    envelope: &[u8],
    now: Timestamp,
) -> Result<Option<NativeOutboxId>, StoreError> {
    let sender = Sender::Pairing(pairing_id);
    let payload = armor(envelope);
    let rows = repos.native_outbox_from(&sender.from_ref())?;
    let same = rows.iter().filter(|row| row.entry.envelope == payload);
    let mut waiting = None;
    for row in same {
        match row.entry.state {
            OutboxState::Posted => return Ok(None),
            state if super::outbox::waiting(state) => waiting = Some(row.id),
            _ => {}
        }
    }
    if waiting.is_some() {
        return Ok(waiting);
    }
    let id = new_id(&mut LockedRng(&mut **rng.lock()));
    queue_mail(repos, id, sender, to_key, payload, now).map(Some)
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
    domain: Option<DomainClaim>,
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
            domain,
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

/// A received domain claim as the record keeps it: unverified, with the name beside the
/// bytes the host verifies later.
pub(crate) fn claim_bytes(claim: &DomainClaim) -> DomainClaimBytes {
    DomainClaimBytes {
        domain: claim.domain.as_str().to_owned(),
        attestation: claim.to_bytes(),
    }
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

/// Checks that an answer to the invite of the wallet with the key `theirs` may go ahead.
/// Two crossed pairings, ours to them and theirs to us, keep the invite of the wallet with the
/// lower key: when ours wins, this fails with [`ContactError::Crossed`]; when theirs does, our
/// own invite is withdrawn as a cancel withdraws it.
fn free_to_answer(
    repos: &mut dyn Repositories,
    ours: &[u8; 33],
    theirs: &[u8; 33],
    now: Timestamp,
) -> Result<(), ContactError> {
    if let Some(own) = own_request_to(repos, theirs)? {
        if !theirs_survives(ours, theirs) {
            return Err(ContactError::Crossed);
        }
        if let Some(mut pending) = repos.pending_pairing(pairing_id_of(own))? {
            pending.secrets.na = None;
            pending.cancelled_at = Some(now);
            repos.put_pending_pairing(&pending)?;
        }
    }
    check_free(repos, theirs)
}

/// The key of an address a pairing expects, as the store keeps it.
fn expected_key(
    address: Option<&str>,
    network: lepic_primitives::params::Network,
) -> Result<Option<[u8; 33]>, ContactError> {
    address
        .map(|address| address_key(address, network))
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
    /// The reply did not prove the address the invite expected; the pairing keeps waiting.
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
    format!("{REFUSALS_PREFIX}{}", hex::encode(&pairing_id.0))
}

/// Ends a pairing in progress: the pending pairing, its kept confirm, its refusal count and
/// the outbox rows of its reply or confirm go together. Returns whether the pending pairing
/// was stored.
pub(crate) fn end_pending(
    repos: &mut dyn Repositories,
    pairing_id: PairingId,
) -> Result<bool, StoreError> {
    repos.delete_native_outbox_from(&Sender::Pairing(pairing_id).from_ref())?;
    repos.delete_setting(&confirm_key(pairing_id))?;
    repos.delete_setting(&confirm_out_key(pairing_id))?;
    repos.delete_setting(&refusals_key(pairing_id))?;
    repos.delete_pending_pairing(pairing_id)
}

/// The setting that marks an inviter's confirm as sent: posted, or handed out by hand.
pub(crate) fn confirm_out_key(pairing_id: PairingId) -> String {
    format!("{CONFIRM_OUT_PREFIX}{}", hex::encode(&pairing_id.0))
}

/// Unix seconds from which an inviter refuses a reply to an invite that expires at `expires`:
/// the end of its read window and of the wait for one read after it.
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

/// The time a pairing in progress is past: an invite's expiry with the skew it is read for,
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
    format!("{CONFIRM_PREFIX}{}", hex::encode(&pairing_id.0))
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

/// A standing invite with less than this left is replaced.
const STANDING_RENEW: Duration = Duration::from_secs(24 * 60 * 60);

/// The setting that names the standing invite's pairing.
pub(crate) const STANDING_KEY: &str = "pairing.standing";

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

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
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
        let relay = super::relay::host_text(&relays.home());
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

/// Refuses a new pairing with the key `key` while one is live, in progress or waiting.
pub(crate) fn check_free(
    repos: &dyn Repositories,
    key: &[u8; PAYMENTS_KEY_LEN],
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
    if pending || !unheard_with(repos, key)?.is_empty() {
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

#[cfg(test)]
mod tests {
    use lepic_store::{MemoryStore, StoreKeys};

    use super::*;

    /// A source of counting bytes, so each new row gets an id of its own.
    struct Counter(u8);

    impl rand_core::TryRng for Counter {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(u32::from(self.0))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(u64::from(self.0))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0 = self.0.wrapping_add(1);
            dst.fill(self.0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Counter {}

    const KEY: &str = "key";
    const CONFIRM: &[u8] = b"confirm";

    /// Queues the confirm of pairing `pairing` and gives the row it names.
    fn queue(store: &MemoryStore, rng: &SharedRng, pairing: PairingId) -> Option<NativeOutboxId> {
        let now = Timestamp::from_second(1_800_000_000).unwrap();
        store
            .write(|repos| queue_confirm(repos, rng, pairing, KEY.to_owned(), CONFIRM, now))
            .unwrap()
    }

    /// Sets row `id` to `state`, on route `route` when one is given.
    fn set(store: &MemoryStore, id: NativeOutboxId, state: OutboxState, route: Option<&str>) {
        store
            .write(|repos| {
                let mut row = repos.native_outbox_entry(id)?.unwrap();
                row.entry.state = state;
                if let Some(route) = route {
                    row.entry.route_value = route.to_owned();
                }
                repos.update_native_outbox(id, &row.entry)
            })
            .unwrap();
    }

    /// The same confirm queued again: a row that waits, on the key or owed to one relay, is
    /// used again; a posted row gives none; after a failed row, a new row is queued.
    #[test]
    fn a_confirm_queued_again_follows_its_rows_state() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let rng = SharedRng::new(Counter(0));
        let pairing = PairingId([4; 16]);

        let first = queue(&store, &rng, pairing).unwrap();
        assert_eq!(queue(&store, &rng, pairing), Some(first));

        set(
            &store,
            first,
            OutboxState::Queued,
            Some("key@relay.test:80"),
        );
        assert_eq!(queue(&store, &rng, pairing), Some(first));

        set(&store, first, OutboxState::Uncertain, None);
        assert_eq!(queue(&store, &rng, pairing), Some(first));

        set(&store, first, OutboxState::Failed, None);
        let second = queue(&store, &rng, pairing).unwrap();
        assert_ne!(second, first);
        assert_eq!(queue(&store, &rng, pairing), Some(second));

        set(&store, second, OutboxState::Posted, None);
        assert_eq!(queue(&store, &rng, pairing), None);
        let rows = store
            .read(|repos| repos.native_outbox_from(&Sender::Pairing(pairing).from_ref()))
            .unwrap();
        assert_eq!(rows.len(), 2);
    }
}
