// SPDX-License-Identifier: Apache-2.0
//! Paired contacts as the host manages them: listing, removing, the per-contact switches, and
//! the backup of the pairing records (RFC 0002 7.6, 10.5 and 11.1).

use lepic_contact::{ContactKind, Sas};
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactRecord, ContactState, PairingEndReason, PairingRole, SealMode, StoreError,
    WalletStore,
};
use tracing::{info, instrument, warn};

use super::{ContactError, ContactRelays, ContactView, DomainVerdict, RelayMode, pairing_id_of};
use crate::ContactBook;
use lepic_methods::epicbox::NOTICE_LENGTHS;
use lepic_wallet::ports::{SecretVault, StoreOpener};

fn kind(kind: lepic_store::ContactKind) -> ContactKind {
    match kind {
        lepic_store::ContactKind::Person => ContactKind::Person,
        lepic_store::ContactKind::Shop => ContactKind::Shop,
        lepic_store::ContactKind::Exchange => ContactKind::Exchange,
    }
}

pub(crate) fn view(
    record: &ContactRecord,
    mailbox: Option<&lepic_store::ContactMailbox>,
    network: lepic_primitives::params::Network,
    native_direct: bool,
    now: jiff::Timestamp,
) -> ContactView {
    let facts = &record.facts;
    let home_relay = mailbox.map(|mailbox| mailbox.home_relay.clone());
    let requested_relay =
        mailbox.and_then(|mailbox| super::collect::requested_relay(record, mailbox, network));
    ContactView {
        contact_id: record.contact_id,
        account: record.account,
        label: record.label.clone(),
        claimed_name: record.peer.as_ref().map(|peer| peer.claimed_name.clone()),
        kind: record.peer.as_ref().map(|peer| kind(peer.kind)),
        state: record.state,
        sas: record
            .sas
            .and_then(|sas| Sas::from_bytes(sas).symbols().ok()),
        verified_at: record.verified_at,
        allow_invoices: record.allow_invoices,
        seal: record.seal,
        app_contact: record.app_contact.clone(),
        home_relay,
        imported_from_backup: record.imported_from_backup,
        lapsed: super::sealed::lapsed(record, now),
        last_sealed_in: record.last_sealed_in,
        removed_by_peer: facts.ended_reason == Some(PairingEndReason::Unpaired),
        requested_relay,
        created_at: record.created_at,
        status: super::status::status_of(record),
        payments_address: facts.payments_address.clone(),
        peer_heard_at: facts.peer_heard_at,
        // Shown only while the accepted verdict judged this record's words.
        peer_verified_at: facts
            .peer_verified_at
            .filter(|_| record.sas.as_ref().map(super::status::verdict_hash) == facts.peer_verdict),
        peer_features: facts.peer_features,
        peer_profile: facts.peer_features >> lepic_transport::marker::features::PROFILE_SHIFT,
        native_slates: super::native::wants_native(native_direct, record),
        peer_domain: facts.peer_domain.as_ref().map(|claim| claim.domain.clone()),
        peer_domain_attestation: facts
            .peer_domain
            .as_ref()
            .map(|claim| claim.attestation.clone()),
        peer_enc_key: record.peer.as_ref().map(|peer| peer.enc_key),
        ended_reason: facts.ended_reason,
        ended_at: facts.ended_at,
    }
}

/// Whether a pairing may be attached to an address-book entry whose Epicbox address has the
/// key `app_key`: the pairing must prove that key. Addresses are compared by key only.
fn check_attach_address(
    record: &ContactRecord,
    app_key: Option<&[u8; 33]>,
) -> Result<(), ContactError> {
    let Some(app_key) = app_key else {
        return Ok(());
    };
    match &record.facts.payments_key {
        None => Err(ContactError::AddressProofMissing),
        Some(proven) if proven != app_key => Err(ContactError::OtherAddress),
        Some(_) => Ok(()),
    }
}

/// How long removing a pairing waits for the contact's relay to take the unpaired notice.
const UNPAIRED_POST_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// An invite's home relay as records name one, `domain:port`, the port explicit.
pub(crate) fn home_host(host: &str) -> String {
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        host.to_owned()
    } else {
        format!("{host}:{}", lepic_epicbox::DEFAULT_PORT)
    }
}

/// The longest id of an app's address-book contact a pairing is attached to.
pub const MAX_APP_CONTACT_LEN: usize = 256;

/// The largest contact backup document read: 10,000 contacts with room to spare.
pub const MAX_BACKUP_LEN: usize = 32 * 1024 * 1024;

/// The longest a wallet that moved its own home relay drains the old mailboxes: a year.
pub const MAX_HOME_DRAIN: std::time::Duration = std::time::Duration::from_secs(365 * 24 * 60 * 60);

/// A pairing still in progress, as the host lists it. Holds no key and no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairingView {
    /// The record the pairing completes into; [`Wallet::contact_remove`] cancels it.
    pub contact_id: ContactId,
    /// `Inviter`: an invite of ours waits for a reply. `Invitee`: our reply waits for the
    /// confirmation.
    pub role: PairingRole,
    /// The name the invite gives its maker: ours as inviter, the inviter's (unverified) as
    /// invitee.
    pub invite_name: String,
    pub label: String,
    /// When the pairing stops waiting, before the wait for one drain after it
    /// ([`super::LATE_DRAIN_WAIT`]): the invite's expiry, or the end of the wait for the confirm.
    pub expires_at: jiff::Timestamp,
    pub created_at: jiff::Timestamp,
    /// The relay where the pairing's mailboxes live, `domain:port`.
    pub home_relay: String,
    /// Inviter: where the pairing request went. Invitee: the request's sender.
    pub expect_address: Option<String>,
}

/// Checks a record restored from a backup against this seed and rebuilds its mailbox from the
/// two cards (RFC 0002 10.5): our card must carry the keys this wallet derives for the record's
/// slot and box salt, and the mailbox fields are taken from the cards, never from the
/// document. Returns false for a record that is not this wallet's.
#[cfg(feature = "sqlite")]
fn restore_record(
    repos: &mut dyn lepic_store::Repositories,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    record: &ContactRecord,
) -> Result<bool, ContactError> {
    let net = super::keys::contact_network(network);
    let Ok(own) = lepic_contact::ContactCard::decode(&record.own_card, net) else {
        return Ok(false);
    };
    let keys = super::keys::contact_keys(
        keychain,
        network,
        record.account,
        record.slot,
        record.box_salt,
    )?;
    let relay_network = lepic_methods::epicbox::relay_network(network);
    let ours = lepic_epicbox::EpicboxAddress::parse(own.fields().mailbox.as_str(), relay_network);
    let mine = *own.sig_key() == super::keys::signing_key(&keys).verifying_key()
        && own.enc_key() == &super::keys::enc_secret(&keys).public_key()
        && ours
            .as_ref()
            .is_ok_and(|address| address.public_key() == keys.box_public_key());
    if !mine {
        return Ok(false);
    }
    let (Some(peer), Ok(ours)) = (&record.peer, ours) else {
        return Ok(true);
    };
    let Ok(peer_card) = lepic_contact::ContactCard::decode(&peer.bytes, net) else {
        return Ok(false);
    };
    let home_relay = format!(
        "{}:{}",
        ours.domain(),
        ours.port().unwrap_or(lepic_epicbox::DEFAULT_PORT)
    );
    repos.put_contact_mailbox(&lepic_store::ContactMailbox {
        contact_id: record.contact_id,
        peer_mailbox: peer_card.fields().mailbox.as_str().to_owned(),
        our_mailbox: ours.to_string(),
        home_relay,
        // A routed relay is dialled at its own onion; a document's onion is not trusted.
        onion: None,
        previous: None,
        backoff: Vec::new(),
    })?;
    Ok(true)
}

/// The record of a paired contact, or [`ContactError::UnknownContact`].
fn paired(
    repos: &dyn lepic_store::Repositories,
    id: ContactId,
) -> Result<ContactRecord, ContactError> {
    repos
        .contact(id)?
        .filter(|record| record.peer.is_some())
        .ok_or(ContactError::UnknownContact)
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The paired contacts, oldest first. Pairings still in progress and private pairings are
    /// left out. Fails with [`lepic_wallet::WalletError::Locked`] and as the store does.
    pub async fn contacts(&self) -> Result<Vec<ContactView>, ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let native_direct = self.wallet.config().native_direct;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for record in repos.contacts()? {
                    if record.peer.is_none() || super::private::is_private(&record) {
                        continue;
                    }
                    let mailbox = repos.contact_mailbox(record.contact_id)?;
                    views.push(view(&record, mailbox.as_ref(), network, native_direct, now));
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }

    /// The pairings still in progress, oldest first: invites waiting for a reply and replies
    /// waiting for the confirmation. A pairing that completed is listed by
    /// [`Wallet::contacts`] instead. Cancel one with [`Wallet::contact_remove`]. Fails with
    /// [`lepic_wallet::WalletError::Locked`] and as the store does.
    pub async fn pairings_pending(&self) -> Result<Vec<PendingPairingView>, ContactError> {
        let net = super::keys::contact_network(self.wallet.config().network);
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.read(|repos| {
                let standing = super::requests::standing_id(repos)?;
                let mut views = Vec::new();
                for pending in repos.pending_pairings()? {
                    // A cancelled invite is kept only to refuse late replies, and the standing
                    // invite shows only where the wallet shows its invite.
                    if pending.cancelled_at.is_some() || Some(pending.contact_id) == standing {
                        continue;
                    }
                    let Some(record) = repos.contact(pending.contact_id)?.filter(|record| {
                        record.peer.is_none() && !super::private::is_private(record)
                    }) else {
                        continue;
                    };
                    let invite = lepic_contact::Invite::decode(&pending.invite, net)
                        .map_err(ContactError::StoredData)?;
                    views.push(PendingPairingView {
                        contact_id: record.contact_id,
                        role: pending.role,
                        invite_name: invite.fields().name.as_str().to_owned(),
                        label: record.label,
                        expires_at: pending.expires_at,
                        created_at: pending.created_at,
                        home_relay: home_host(invite.fields().home_relay.as_str()),
                        expect_address: pending.expect_address,
                    });
                }
                views.sort_by_key(|view| view.created_at);
                Ok(views)
            })
        })
        .await
    }

    /// The private pairings (two wallets of one owner), oldest first, in progress or paired;
    /// the state tells which. Their words check is mandatory before payloads pass: see
    /// [`Wallet::pairing_sas`]. Remove one with [`Wallet::contact_remove`] or
    /// [`Wallet::contact_unpair`]. Fails with [`lepic_wallet::WalletError::Locked`] and as the store
    /// does.
    pub async fn private_pairings(&self) -> Result<Vec<ContactView>, ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let native_direct = self.wallet.config().native_direct;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for record in repos.contacts()? {
                    if !super::private::is_private(&record) {
                        continue;
                    }
                    let mailbox = repos.contact_mailbox(record.contact_id)?;
                    views.push(view(&record, mailbox.as_ref(), network, native_direct, now));
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }

    /// One paired contact. Fails with [`ContactError::UnknownContact`].
    pub async fn contact(&self, contact_id: ContactId) -> Result<ContactView, ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let native_direct = self.wallet.config().native_direct;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let record = paired(repos, contact_id)?;
                let mailbox = repos.contact_mailbox(contact_id)?;
                Ok(view(&record, mailbox.as_ref(), network, native_direct, now))
            })
        })
        .await
    }

    /// Removes a pairing or a pairing in progress: its record, mailboxes and pending pairing go,
    /// and the contact is not told (RFC 0002 C-19). The slot stays used. Returns whether
    /// anything was removed.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_remove(&self, contact_id: ContactId) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        let removed = self
            .contact_work(move |_, _| {
                Ok(session.store.write(|repos| {
                    let pending = super::pairing::end_pending(repos, pairing_id_of(contact_id))?;
                    super::invoices::drop_contact_invoices(repos, contact_id)?;
                    repos.delete_setting(&super::collect::stamped_key(contact_id))?;
                    super::keycheck::delete_contact_settings(repos, contact_id)?;
                    super::quarantine::delete_contact_entries(repos, contact_id)?;
                    let record = repos.delete_contact(contact_id)?;
                    super::private::delete_secrets(repos, contact_id)?;
                    Ok::<_, StoreError>(pending || record)
                })?)
            })
            .await?;
        if removed {
            info!("pairing removed");
        }
        Ok(removed)
    }

    /// Removes a pairing as [`Wallet::contact_remove`] does, after telling the contact, best
    /// effort: a signed unpaired notice goes straight to its mailbox, waiting at most a few
    /// seconds for the relay, so it stops sending through a pairing nobody reads (RFC 0002
    /// 7.6). Nothing is sent Offline, with Epicbox off, for a pairing still in progress, or for
    /// one the contact removed first. Returns whether anything was removed.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_unpair(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
    ) -> Result<bool, ContactError> {
        if relays.mode == RelayMode::Online {
            match tokio::time::timeout(UNPAIRED_POST_WAIT, self.post_unpaired(relays, contact_id))
                .await
            {
                Ok(Ok(true)) => info!("unpaired notice posted"),
                Ok(Ok(false)) => {}
                Ok(Err(error)) => {
                    warn!(error = %lepic_primitives::error_chain::ErrorChain(&error), "unpaired notice not posted");
                }
                Err(_) => warn!("unpaired notice not posted in time"),
            }
        }
        self.contact_remove(contact_id).await
    }

    /// Posts the unpaired notice to the contact's mailbox; false when there is nobody to tell.
    async fn post_unpaired(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
    ) -> Result<bool, ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let found = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let Some(record) = repos.contact(contact_id)?.filter(|record| {
                        record.peer.is_some()
                            && matches!(
                                record.state,
                                ContactState::Paired
                                    | ContactState::Verified
                                    | ContactState::KeysChanged
                            )
                    }) else {
                        return Ok::<_, StoreError>(None);
                    };
                    if record.facts.ended_reason.is_some() {
                        return Ok(None);
                    }
                    Ok(repos
                        .contact_mailbox(contact_id)?
                        .map(|mailbox| (record, mailbox)))
                })?)
            })
            .await?;
        let Some((record, mailbox)) = found else {
            return Ok(false);
        };
        let length = lepic_wallet::notice::notice_length(
            &NOTICE_LENGTHS,
            &mut **self.wallet.ports().rng.lock(),
        );
        let notice = lepic_wallet::notice::unpaired_notice_to(&NOTICE_LENGTHS, length).into_bytes();
        let envelope = self
            .seal_for_contact(
                &record,
                lepic_contact::Content::new(lepic_contact::MessageType::Notice, notice),
            )
            .await?;
        let session = self.wallet.session()?;
        let class = {
            let session = std::sync::Arc::clone(&session);
            let record = record.clone();
            self.contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| super::private::class_of(repos, &record))?)
            })
            .await?
        };
        let keys = super::private::record_keys(&session.keychain, network, &record, &class)?;
        let home = super::relay::endpoint_for(&mailbox.home_relay, relays)?;
        let from = super::keys::box_identity(&keys, network, &home)?;
        let to =
            lepic_epicbox::EpicboxAddress::parse(&mailbox.peer_mailbox, relays.epicbox.network())
                .map_err(|_| ContactError::RelayAddress)?;
        super::relay::post_envelope(relays, &from, &to, mailbox.onion.as_deref(), &envelope)
            .await?;
        Ok(true)
    }

    /// The contact said it removed its pairing: the record ends as unpaired, once, and is kept.
    /// Ended is final: a pairing that ended before stays as it ended.
    pub(crate) async fn take_unpaired(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let first = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let Some(mut record) = repos.contact(contact_id)? else {
                        return Ok::<_, StoreError>(false);
                    };
                    if !super::status::end_record(&mut record, PairingEndReason::Unpaired, now) {
                        return Ok(false);
                    }
                    super::invoices::drop_contact_invoices(repos, contact_id)?;
                    repos.put_contact(&record)?;
                    Ok(true)
                })?)
            })
            .await?;
        if first {
            info!("contact removed the pairing");
            self.wallet
                .emit(lepic_wallet::event::Event::ContactUnpaired(
                    lepic_wallet::event::ContactEvent { contact_id },
                ));
        }
        Ok(())
    }

    /// Gives every contact pairing that has not ended our card again, naming us `name`, as a
    /// contact update the next collect posts; private pairings are left alone. Returns how
    /// many were queued.
    ///
    /// Fails with [`ContactError::Name`] for a name the card cannot carry.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_set_own_name(
        &self,
        relays: &ContactRelays,
        name: &str,
    ) -> Result<u32, ContactError> {
        let name = lepic_contact::ContactName::new(name).map_err(ContactError::Name)?;
        let network = self.wallet.config().network;
        let features = self.wallet.config().pairing_features();
        let session = self.wallet.session()?;
        let payments = super::address_proof::Payments::of(&session.keychain, network, relays)?;
        let domain = super::address_proof::domain_signer(
            &session.keychain,
            network,
            self.wallet.config().domain.as_deref(),
        )?;
        let net = super::keys::contact_network(network);
        let queued = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let at = super::address_proof::CardUpdate {
                        keychain: &session.keychain,
                        network,
                        payments: &payments,
                        features,
                        domain: domain.as_ref(),
                        now,
                    };
                    let mut queued = 0u32;
                    for record in repos.contacts()? {
                        let same = lepic_contact::ContactCard::decode(&record.own_card, net)
                            .is_ok_and(|own| own.fields().name == name);
                        if same {
                            continue;
                        }
                        let name = name.clone();
                        if super::address_proof::queue_card_update(
                            repos,
                            &ports.rng,
                            &at,
                            record,
                            |fields| fields.name = name,
                        )? {
                            queued = queued.saturating_add(1);
                        }
                    }
                    Ok::<_, ContactError>(queued)
                })
            })
            .await?;
        info!(count = queued, "own name given to contacts");
        Ok(queued)
    }

    /// Tells every contact pairing that has not ended the owner's new `profile` (bits 16 to
    /// 31 of the pairing features), as a contact update the next collect posts: our card
    /// again with the next sequence number, and a features word built from `profile`; private
    /// pairings are left alone. Returns how many were queued.
    ///
    /// Nothing stored says what a contact was last told, so every eligible contact gets an
    /// update, also one that already has this value. The session's configured profile is not
    /// changed: later updates carry it again until the host opens the wallet with the new one.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_set_own_profile(
        &self,
        relays: &ContactRelays,
        profile: u16,
    ) -> Result<u32, ContactError> {
        let network = self.wallet.config().network;
        let features = self.wallet.config().pairing_features_with(profile);
        let session = self.wallet.session()?;
        let payments = super::address_proof::Payments::of(&session.keychain, network, relays)?;
        let domain = super::address_proof::domain_signer(
            &session.keychain,
            network,
            self.wallet.config().domain.as_deref(),
        )?;
        let queued = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let at = super::address_proof::CardUpdate {
                        keychain: &session.keychain,
                        network,
                        payments: &payments,
                        features,
                        domain: domain.as_ref(),
                        now,
                    };
                    let mut queued = 0u32;
                    for record in repos.contacts()? {
                        if super::address_proof::queue_card_update(
                            repos,
                            &ports.rng,
                            &at,
                            record,
                            |_| {},
                        )? {
                            queued = queued.saturating_add(1);
                        }
                    }
                    Ok::<_, ContactError>(queued)
                })
            })
            .await?;
        info!(count = queued, "own profile given to contacts");
        Ok(queued)
    }

    /// Tells every contact pairing that has not ended the domain this wallet claims, as a
    /// contact update the next collect posts: our card again with the next sequence number,
    /// the current features and a fresh domain claim signed for each pairing; private
    /// pairings are left alone. Returns how many were queued.
    ///
    /// Fails with [`ContactError::NoDomainConfigured`] when the wallet was opened without a
    /// domain, and with [`ContactError::Domain`] for one that is not a valid name.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_tell_domain(&self, relays: &ContactRelays) -> Result<u32, ContactError> {
        let network = self.wallet.config().network;
        let features = self.wallet.config().pairing_features();
        let session = self.wallet.session()?;
        let payments = super::address_proof::Payments::of(&session.keychain, network, relays)?;
        let domain = super::address_proof::domain_signer(
            &session.keychain,
            network,
            self.wallet.config().domain.as_deref(),
        )?
        .ok_or(ContactError::NoDomainConfigured)?;
        let queued = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let at = super::address_proof::CardUpdate {
                        keychain: &session.keychain,
                        network,
                        payments: &payments,
                        features,
                        domain: Some(&domain),
                        now,
                    };
                    let mut queued = 0u32;
                    for record in repos.contacts()? {
                        if super::address_proof::queue_card_update(
                            repos,
                            &ports.rng,
                            &at,
                            record,
                            |_| {},
                        )? {
                            queued = queued.saturating_add(1);
                        }
                    }
                    Ok::<_, ContactError>(queued)
                })
            })
            .await?;
        info!(count = queued, "domain given to contacts");
        Ok(queued)
    }

    /// The public key of this wallet's domain key on its network: what the domain lists in its
    /// well-known file (`DomainFile::render`) for the wallet's claims to verify. It needs no
    /// configured domain.
    pub fn own_domain_key(&self) -> Result<lepic_contact::VerifyingKey, ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let root = super::key_schedule::contact_root(
            &session.keychain,
            &lepic_wallet::account::parent_key_id(lepic_store::AccountIndex(0))?,
            network,
        )
        .map_err(ContactError::Keys)?;
        Ok(root
            .domain_key(network)
            .map_err(ContactError::Keys)?
            .public())
    }

    /// Whether the well-known file `file`, which the host fetched from the domain the contact
    /// claimed, proves the claim stored from its pairing (RFC 0002 6.3). Nothing is fetched or
    /// stored here, and the claim stays unverified in the record whatever the verdict.
    ///
    /// Fails with [`ContactError::UnknownContact`] and [`ContactError::NoDomainClaim`] when the
    /// contact claimed no domain.
    pub async fn domain_verify(
        &self,
        contact_id: ContactId,
        file: &[u8],
    ) -> Result<DomainVerdict, ContactError> {
        let network = self.wallet.config().network;
        let net = super::keys::contact_network(network);
        let session = self.wallet.session()?;
        let record = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| Ok::<_, ContactError>(repos.contact(contact_id)?))
            })
            .await?
            .ok_or(ContactError::UnknownContact)?;
        let stored = record
            .facts
            .peer_domain
            .as_ref()
            .ok_or(ContactError::NoDomainClaim)?;
        let peer = record.peer.as_ref().ok_or(ContactError::NoDomainClaim)?;
        let claim = lepic_contact::DomainClaim::from_bytes(&stored.attestation)
            .map_err(|_| ContactError::NoDomainClaim)?;
        let domain = lepic_contact::DomainName::new(&stored.domain)
            .map_err(|_| ContactError::NoDomainClaim)?;
        let sig_key = lepic_contact::VerifyingKey::from_bytes(&peer.sig_key)
            .map_err(|_| ContactError::NoDomainClaim)?;
        Ok(super::domain::verify(&domain, file, &claim, &sig_key, net))
    }

    /// Moves this wallet's home relay for its contacts to `host`, `domain[:port]` (RFC 0002
    /// 8.5): every paired contact pairing that has not ended and is not at home there gets our
    /// card naming our mailbox on `host`, once, as a contact update queued for the mailbox it
    /// reads now, and our mailbox for it moves to `host` in the same write. Returns how many
    /// moved.
    ///
    /// A contact that takes the update sees
    /// [`Event::ContactRelayMoveRequested`](lepic_wallet::event::Event::ContactRelayMoveRequested)
    /// and writes to the new mailbox once it applies the move. For `drain`, at most
    /// [`MAX_HOME_DRAIN`] (a longer one is cut to it), every collect still reads our old
    /// mailbox for each moved contact, as it reads a previous home after following a
    /// contact's move: what the contact sends there is taken as usual, and a contact check
    /// there is answered with the card naming the new mailbox, so a contact away longer than
    /// the relay keeps the update still learns of the move. There is one previous home per
    /// contact: this drain replaces one left by following a contact's move. A zero `drain`
    /// announces only: the old mailboxes are not read again, and what a contact sends before
    /// it follows, or all of it when it never takes the update, is lost and the pairing has
    /// to be made again. Private pairings and pairings in progress keep their relay. New
    /// invites name the relay of `relays`, so the host switches its own relay too.
    ///
    /// Fails with [`ContactError::RelayAddress`] for a host that is not a relay's name, and as
    /// the store does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_move_home(
        &self,
        relays: &ContactRelays,
        host: &str,
        drain: std::time::Duration,
    ) -> Result<u32, ContactError> {
        let drain = drain.min(MAX_HOME_DRAIN);
        self.check_contact_network(relays)?;
        let home = super::relay::endpoint_for(&host.trim().to_ascii_lowercase(), relays)?;
        let home_relay = super::relay::host_text(&home);
        let network = self.wallet.config().network;
        let features = self.wallet.config().pairing_features();
        let session = self.wallet.session()?;
        let payments = super::address_proof::Payments::of(&session.keychain, network, relays)?;
        let domain = super::address_proof::domain_signer(
            &session.keychain,
            network,
            self.wallet.config().domain.as_deref(),
        )?;
        // A collect on its way would drain the mailboxes this moves away from.
        let turn = self.wallet.contact_turn().await;
        let moved = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                let until = now.checked_add(drain).unwrap_or(now);
                session.store.write(|repos| {
                    let at = super::address_proof::CardUpdate {
                        keychain: &session.keychain,
                        network,
                        payments: &payments,
                        features,
                        domain: domain.as_ref(),
                        now,
                    };
                    let mut moved = 0u32;
                    for record in repos.contacts()? {
                        let Some(mut mailbox) = repos.contact_mailbox(record.contact_id)? else {
                            continue;
                        };
                        if mailbox.home_relay == home_relay {
                            continue;
                        }
                        let keys = super::keys::contact_keys(
                            &session.keychain,
                            network,
                            record.account,
                            record.slot,
                            record.box_salt,
                        )?;
                        let ours = super::keys::box_identity(&keys, network, &home)?
                            .address()
                            .to_string();
                        let named = lepic_contact::MailboxAddress::new(&ours)
                            .map_err(ContactError::Name)?;
                        if !super::address_proof::queue_card_update(
                            repos,
                            &ports.rng,
                            &at,
                            record,
                            |fields| fields.mailbox = named,
                        )? {
                            continue;
                        }
                        if until > now {
                            mailbox.previous = Some(lepic_store::PreviousHome {
                                relay: mailbox.home_relay.clone(),
                                peer_mailbox: mailbox.peer_mailbox.clone(),
                                our_mailbox: mailbox.our_mailbox.clone(),
                                until,
                            });
                        }
                        // Without a drain, only one left by following a contact's own move
                        // stays, to its end.
                        mailbox.home_relay.clone_from(&home_relay);
                        mailbox.our_mailbox = ours;
                        repos.put_contact_mailbox(&mailbox)?;
                        moved = moved.saturating_add(1);
                    }
                    Ok::<_, ContactError>(moved)
                })
            })
            .await?;
        drop(turn);
        self.deliver_soon(relays).await;
        info!(count = moved, "home relay moved for contacts");
        Ok(moved)
    }

    /// Sets the user's own name for a contact; an empty label clears it. A label follows the
    /// rule of card names: at most 48 bytes, no control or hidden formatting characters.
    /// Fails with [`ContactError::Name`] for another label and [`ContactError::UnknownContact`].
    pub async fn contact_set_label(
        &self,
        contact_id: ContactId,
        label: String,
    ) -> Result<(), ContactError> {
        if !label.is_empty() {
            lepic_contact::ContactName::new(&label).map_err(ContactError::Name)?;
        }
        self.update_contact(contact_id, move |record| {
            record.label = label;
            Ok(())
        })
        .await
    }

    /// Turns sealing of sends to a contact on or off (RFC 0002 9.3). Fails with
    /// [`ContactError::UnknownContact`].
    pub async fn contact_set_seal(
        &self,
        contact_id: ContactId,
        on: bool,
    ) -> Result<(), ContactError> {
        self.update_contact(contact_id, move |record| {
            record.seal = if on { SealMode::On } else { SealMode::Off };
            Ok(())
        })
        .await
    }

    /// Turns invoices from a contact on or off (RFC 0002 11.1). Only a verified contact may send
    /// invoices: turning them on for another fails with [`ContactError::NotVerified`], and with
    /// [`ContactError::Waiting`] or [`ContactError::Ended`] for a pairing that waits or ended. Turning
    /// them off deletes the contact's unpaid parked invoices and queues a sealed `declined` for
    /// each; a paid one finishes. Fails with [`ContactError::UnknownContact`].
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_set_allow_invoices(
        &self,
        contact_id: ContactId,
        allow: bool,
    ) -> Result<(), ContactError> {
        self.update_contact(contact_id, move |record| {
            if allow {
                super::status::require_live(record)?;
            }
            if allow && record.state != ContactState::Verified {
                return Err(ContactError::NotVerified);
            }
            record.allow_invoices = allow;
            Ok(())
        })
        .await?;
        info!("contact invoices switched");
        if !allow {
            let declined = self.decline_contact_invoices(contact_id).await?;
            info!(count = declined, "parked contact invoices declined");
        }
        Ok(())
    }

    /// Attaches a pairing to the app's address-book contact `app_contact`, an id the host
    /// chooses of at most [`MAX_APP_CONTACT_LEN`] bytes with no control characters, or
    /// detaches it with `None`. `app_address` is the entry's Epicbox address, if it has one:
    /// the pairing must then prove an address with the same key. Fails with
    /// [`ContactError::Name`] for another id, [`ContactError::RelayAddress`] for an address
    /// that is not one of the wallet's network, [`ContactError::OtherAddress`] when the pairing
    /// proves another key, [`ContactError::AddressProofMissing`] when it proves none (nothing
    /// changes in either case), and [`ContactError::UnknownContact`].
    pub async fn contact_attach(
        &self,
        contact_id: ContactId,
        app_contact: Option<String>,
        app_address: Option<String>,
    ) -> Result<(), ContactError> {
        let app_key = app_address
            .as_deref()
            .map(|address| {
                lepic_epicbox::EpicboxAddress::parse(
                    address,
                    lepic_methods::epicbox::relay_network(self.wallet.config().network),
                )
                .map(|address| address.public_key().to_bytes())
                .map_err(|_| ContactError::RelayAddress)
            })
            .transpose()?;
        if let Some(id) = &app_contact {
            if id.is_empty() || id.len() > MAX_APP_CONTACT_LEN {
                return Err(ContactError::Name(lepic_contact::TextError::Length {
                    found: id.len(),
                    max: MAX_APP_CONTACT_LEN,
                }));
            }
            if let Some(position) = id.chars().position(char::is_control) {
                return Err(ContactError::Name(
                    lepic_contact::TextError::HiddenCharacter { position },
                ));
            }
        }
        self.update_contact(contact_id, move |record| {
            if app_contact.is_some() {
                check_attach_address(record, app_key.as_ref())?;
            }
            record.app_contact = app_contact;
            Ok(())
        })
        .await
    }

    async fn update_contact(
        &self,
        contact_id: ContactId,
        change: impl FnOnce(&mut ContactRecord) -> Result<(), ContactError> + Send + 'static,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                let mut record = paired(repos, contact_id)?;
                change(&mut record)?;
                record.updated_at = now;
                repos.put_contact(&record)?;
                Ok(())
            })
        })
        .await
    }

    /// The pairing records and slot counters as the versioned JSON document the app adds to its
    /// `.wfeh` history payload (RFC 0002 10.5). It holds no secret.
    #[cfg(feature = "sqlite")]
    pub async fn contacts_export(&self) -> Result<String, ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                lepic_store::export_contacts_where(repos, network, |record| {
                    !super::private::is_private(record)
                })
            })?)
        })
        .await
    }

    /// Restores pairing records from a document [`Wallet::contacts_export`] wrote, flagged as
    /// possibly living on another device too, and raises the slot counters to the backup's.
    /// Records the store holds already are kept as they are.
    ///
    /// Fails with [`ContactError::TooLarge`] for a document over [`MAX_BACKUP_LEN`] bytes, and
    /// with a store error for a document this build cannot read; nothing is imported then.
    #[cfg(feature = "sqlite")]
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_import(
        &self,
        document: String,
    ) -> Result<lepic_store::ImportSummary, ContactError> {
        if document.len() > MAX_BACKUP_LEN {
            return Err(ContactError::TooLarge {
                max: MAX_BACKUP_LEN,
            });
        }
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let summary = self
            .contact_work(move |_, _| {
                let read_card = |bytes: &[u8]| {
                    lepic_contact::ContactCard::decode(bytes, super::keys::contact_network(network))
                        .ok()
                        .map(|card| super::pairing::peer_card(&card))
                };
                session.store.write(|repos| {
                    let before: Vec<ContactId> = repos
                        .contacts()?
                        .iter()
                        .map(|record| record.contact_id)
                        .collect();
                    let mut summary =
                        lepic_store::import_contacts(repos, &document, network, &read_card)?;
                    for record in repos.contacts()? {
                        if before.contains(&record.contact_id) {
                            continue;
                        }
                        if !restore_record(repos, &session.keychain, network, &record)? {
                            repos.delete_contact(record.contact_id)?;
                            super::private::delete_secrets(repos, record.contact_id)?;
                            summary.imported = summary.imported.saturating_sub(1);
                            summary.skipped_conflict = summary.skipped_conflict.saturating_add(1);
                        }
                    }
                    Ok::<_, ContactError>(summary)
                })
            })
            .await?;
        info!(count = summary.imported, "contacts imported");
        Ok(summary)
    }
}
