//! Paired contacts as the host manages them: listing, removing, the per-contact switches, and
//! the backup of the pairing records (RFC 0002 7.6, 10.5 and 11.1).

use lepic_contact::{ContactKind, Sas};
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactRecord, ContactState, PairingRole, SealMode, StoreError, WalletStore,
};
use tracing::{info, instrument, warn};

use super::{ContactError, ContactRelays, ContactView, RelayMode, pairing_id_of};
use crate::ContactBook;
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
    home_relay: Option<String>,
    removed_by_peer: bool,
    now: jiff::Timestamp,
) -> ContactView {
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
        removed_by_peer,
        created_at: record.created_at,
    }
}

const UNPAIRED_PREFIX: &str = "contact.unpaired.";

/// The setting that marks a pairing the contact removed on its side, with when it said so.
pub(crate) fn unpaired_key(contact_id: ContactId) -> String {
    let hex: String = contact_id
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{UNPAIRED_PREFIX}{hex}")
}

fn removed_by_peer(
    repos: &dyn lepic_store::Repositories,
    contact_id: ContactId,
) -> Result<bool, StoreError> {
    Ok(repos.setting(&unpaired_key(contact_id))?.is_some())
}

/// How long removing a pairing waits for the contact's relay to take the unpaired notice.
const UNPAIRED_POST_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// An invite's home relay as records name one, `domain:port`, the port explicit.
fn home_host(host: &str) -> String {
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
    let relay_network = lepic_wallet::inbox::relay_network(network);
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
        // A built-in relay is dialled at its own onion; a document's onion is not trusted.
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
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for record in repos.contacts()? {
                    if record.peer.is_none() || super::private::is_private(&record) {
                        continue;
                    }
                    let home = repos
                        .contact_mailbox(record.contact_id)?
                        .map(|mailbox| mailbox.home_relay);
                    let removed = removed_by_peer(repos, record.contact_id)?;
                    views.push(view(&record, home, removed, now));
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
                let mut views = Vec::new();
                for pending in repos.pending_pairings()? {
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
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for record in repos.contacts()? {
                    if !super::private::is_private(&record) {
                        continue;
                    }
                    let home = repos
                        .contact_mailbox(record.contact_id)?
                        .map(|mailbox| mailbox.home_relay);
                    let removed = removed_by_peer(repos, record.contact_id)?;
                    views.push(view(&record, home, removed, now));
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }

    /// One paired contact. Fails with [`ContactError::UnknownContact`].
    pub async fn contact(&self, contact_id: ContactId) -> Result<ContactView, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let record = paired(repos, contact_id)?;
                let home = repos
                    .contact_mailbox(contact_id)?
                    .map(|mailbox| mailbox.home_relay);
                let removed = removed_by_peer(repos, contact_id)?;
                Ok(view(&record, home, removed, now))
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
                    repos.delete_setting(&unpaired_key(contact_id))?;
                    repos.delete_setting(&super::collect::stamped_key(contact_id))?;
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
                    warn!(error = %lepic_wallet::inbox::ErrorChain(&error), "unpaired notice not posted");
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
                    if removed_by_peer(repos, contact_id)? {
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
        let envelope = self
            .seal_for_contact(
                &record,
                lepic_contact::Content::new(
                    lepic_contact::MessageType::Notice,
                    lepic_wallet::notice::unpaired_notice().into_bytes(),
                ),
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

    /// The contact said it removed its pairing: the record is marked, once, and kept.
    pub(crate) async fn take_unpaired(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let first = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    if repos.contact(contact_id)?.is_none() || removed_by_peer(repos, contact_id)? {
                        return Ok::<_, StoreError>(false);
                    }
                    repos.put_setting(&unpaired_key(contact_id), &now.as_second().to_string())?;
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
    /// invoices: turning them on for another fails with [`ContactError::NotVerified`]. Turning
    /// them off deletes the contact's unpaid parked invoices and queues a sealed `declined` for
    /// each; a paid one finishes. Fails with [`ContactError::UnknownContact`].
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_set_allow_invoices(
        &self,
        contact_id: ContactId,
        allow: bool,
    ) -> Result<(), ContactError> {
        self.update_contact(contact_id, move |record| {
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
    /// detaches it with `None`. Fails with [`ContactError::Name`] for another id and
    /// [`ContactError::UnknownContact`].
    pub async fn contact_attach(
        &self,
        contact_id: ContactId,
        app_contact: Option<String>,
    ) -> Result<(), ContactError> {
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
