//! Paired contacts as the host manages them: listing, removing, the per-contact switches, and
//! the backup of the pairing records (RFC 0002 7.6, 10.5 and 11.1).

use lepic_contact::{ContactKind, Sas};
use lepic_node::NodeApi;
use lepic_store::{ContactId, ContactRecord, ContactState, SealMode, StoreError, WalletStore};
use tracing::{info, instrument};

use super::{ContactError, ContactView, pairing_id_of};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

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
        created_at: record.created_at,
    }
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

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The paired contacts, oldest first. Pairings still in progress are left out. Fails with
    /// [`crate::WalletError::Locked`] and as the store does.
    pub async fn contacts(&self) -> Result<Vec<ContactView>, ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for record in repos.contacts()? {
                    if record.peer.is_none() {
                        continue;
                    }
                    let home = repos
                        .contact_mailbox(record.contact_id)?
                        .map(|mailbox| mailbox.home_relay);
                    views.push(view(&record, home, now));
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }

    /// One paired contact. Fails with [`ContactError::UnknownContact`].
    pub async fn contact(&self, contact_id: ContactId) -> Result<ContactView, ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let record = paired(repos, contact_id)?;
                let home = repos
                    .contact_mailbox(contact_id)?
                    .map(|mailbox| mailbox.home_relay);
                Ok(view(&record, home, now))
            })
        })
        .await
    }

    /// Removes a pairing or a pairing in progress: its record, mailboxes and pending pairing go,
    /// and the contact is not told (RFC 0002 C-19). The slot stays used. Returns whether
    /// anything was removed.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contact_remove(&self, contact_id: ContactId) -> Result<bool, ContactError> {
        let session = self.session()?;
        let removed = self
            .contact_work(move |_, _| {
                Ok(session.store.write(|repos| {
                    let pending = repos.delete_pending_pairing(pairing_id_of(contact_id))?;
                    let record = repos.delete_contact(contact_id)?;
                    Ok::<_, StoreError>(pending || record)
                })?)
            })
            .await?;
        if removed {
            info!("pairing removed");
        }
        Ok(removed)
    }

    /// Sets the user's own name for a contact. Fails with [`ContactError::UnknownContact`].
    pub async fn contact_set_label(
        &self,
        contact_id: ContactId,
        label: String,
    ) -> Result<(), ContactError> {
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
    /// invoices: turning them on for another fails with [`ContactError::NotVerified`]. Fails
    /// with [`ContactError::UnknownContact`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
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
        Ok(())
    }

    /// Attaches a pairing to the app's address-book contact `app_contact`, an id the host
    /// chooses, or detaches it with `None`. Fails with [`ContactError::UnknownContact`].
    pub async fn contact_attach(
        &self,
        contact_id: ContactId,
        app_contact: Option<String>,
    ) -> Result<(), ContactError> {
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
        let session = self.session()?;
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
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .read(|repos| lepic_store::export_contacts(repos))?)
        })
        .await
    }

    /// Restores pairing records from a document [`Wallet::contacts_export`] wrote, flagged as
    /// possibly living on another device too, and raises the slot counters to the backup's.
    /// Records the store holds already are kept as they are.
    ///
    /// Fails with a store error for a document this build cannot read; nothing is imported then.
    #[cfg(feature = "sqlite")]
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contacts_import(
        &self,
        document: String,
    ) -> Result<lepic_store::ImportSummary, ContactError> {
        let session = self.session()?;
        let summary = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .write(|repos| lepic_store::import_contacts(repos, &document))?)
            })
            .await?;
        info!(count = summary.imported, "contacts imported");
        Ok(summary)
    }
}
