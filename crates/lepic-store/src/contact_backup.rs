//! Export and import of pairing records for the app's `.wfeh` history payload (RFC 0002 10.5).
//!
//! The document is `{"version":1,"contacts":[...]}` with bytes in lowercase hex and times as
//! RFC 3339. It holds no secret: pairings in progress, outbox entries and relay backoff are not
//! exported, and a contact still waiting for its reply is left out because nothing could finish
//! it. A record restored from it is flagged [`ContactRecord::imported_from_backup`], because the
//! pairing may also live on the device the backup came from (cases C-11).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::contact::{
    ContactId, ContactKind, ContactMailbox, ContactRecord, ContactRepository, ContactState,
    PeerCard, PreviousHome, SealMode,
};
use crate::error::{Record, StoreError};

/// The document version this build writes and reads.
pub const CONTACT_BACKUP_VERSION: u64 = 1;

/// What an import did with the records of a backup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub imported: usize,
    /// Records whose contact id is already stored. The stored record wins.
    pub skipped_existing: usize,
    /// Records whose peer signing key belongs to another stored contact.
    pub skipped_conflict: usize,
}

#[derive(Serialize, Deserialize)]
struct Document {
    version: u64,
    contacts: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    contact_id: String,
    label: String,
    state: String,
    verified_at: Option<String>,
    allow_invoices: bool,
    seal: String,
    last_sealed_in: Option<String>,
    app_contact: Option<String>,
    created_at: String,
    updated_at: String,
    peer: CardEntry,
    alternate: Option<CardEntry>,
    mailbox: Option<MailboxEntry>,
}

#[derive(Serialize, Deserialize)]
struct CardEntry {
    card: String,
    sig_key: String,
    enc_key: String,
    hint_key: String,
    seq: u32,
    kind: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct MailboxEntry {
    peer_mailbox: String,
    our_mailbox: String,
    home_relay: String,
    onion: Option<String>,
    previous: Option<PreviousEntry>,
}

#[derive(Serialize, Deserialize)]
struct PreviousEntry {
    relay: String,
    peer_mailbox: String,
    our_mailbox: String,
    until: String,
}

const RECORD: Record = Record::Contact;

fn corrupt(field: &'static str) -> StoreError {
    StoreError::Corrupt {
        record: RECORD,
        field,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn from_hex(text: &str, field: &'static str) -> Result<Vec<u8>, StoreError> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(corrupt(field));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| corrupt(field))
        })
        .collect()
}

fn from_hex_fixed<const N: usize>(text: &str, field: &'static str) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(from_hex(text, field)?.as_slice()).map_err(|_| corrupt(field))
}

fn time(text: &str, field: &'static str) -> Result<Timestamp, StoreError> {
    text.parse().map_err(|_| corrupt(field))
}

fn optional_time(text: Option<&str>, field: &'static str) -> Result<Option<Timestamp>, StoreError> {
    text.map(|text| time(text, field)).transpose()
}

fn card_entry(card: &PeerCard) -> CardEntry {
    CardEntry {
        card: to_hex(&card.bytes),
        sig_key: to_hex(&card.sig_key),
        enc_key: to_hex(&card.enc_key),
        hint_key: to_hex(&card.hint_key),
        seq: card.seq,
        kind: card.kind.code().to_owned(),
        name: card.claimed_name.clone(),
    }
}

fn card_from(entry: &CardEntry) -> Result<PeerCard, StoreError> {
    Ok(PeerCard {
        bytes: from_hex(&entry.card, "card")?,
        sig_key: from_hex_fixed(&entry.sig_key, "sig key")?,
        enc_key: from_hex_fixed(&entry.enc_key, "enc key")?,
        hint_key: from_hex_fixed(&entry.hint_key, "hint key")?,
        seq: entry.seq,
        kind: ContactKind::from_code(&entry.kind).ok_or_else(|| corrupt("kind"))?,
        claimed_name: entry.name.clone(),
    })
}

fn mailbox_entry(mailbox: &ContactMailbox) -> MailboxEntry {
    MailboxEntry {
        peer_mailbox: mailbox.peer_mailbox.clone(),
        our_mailbox: mailbox.our_mailbox.clone(),
        home_relay: mailbox.home_relay.clone(),
        onion: mailbox.onion.clone(),
        previous: mailbox.previous.as_ref().map(|previous| PreviousEntry {
            relay: previous.relay.clone(),
            peer_mailbox: previous.peer_mailbox.clone(),
            our_mailbox: previous.our_mailbox.clone(),
            until: previous.until.to_string(),
        }),
    }
}

/// Serialises the paired contacts of the store, oldest first.
pub fn export_contacts<R: ContactRepository + ?Sized>(repos: &R) -> Result<String, StoreError> {
    let mut contacts = Vec::new();
    for contact in repos.contacts()? {
        if matches!(
            contact.state,
            ContactState::PendingInvite | ContactState::PendingReply
        ) {
            continue;
        }
        let Some(peer) = &contact.peer else {
            continue;
        };
        let mailbox = repos.contact_mailbox(contact.contact_id)?;
        contacts.push(Entry {
            contact_id: to_hex(&contact.contact_id.0),
            label: contact.label.clone(),
            state: contact.state.code().to_owned(),
            verified_at: contact.verified_at.map(|time| time.to_string()),
            allow_invoices: contact.allow_invoices,
            seal: contact.seal.code().to_owned(),
            last_sealed_in: contact.last_sealed_in.map(|time| time.to_string()),
            app_contact: contact.app_contact.clone(),
            created_at: contact.created_at.to_string(),
            updated_at: contact.updated_at.to_string(),
            peer: card_entry(peer),
            alternate: contact.alternate.as_ref().map(card_entry),
            mailbox: mailbox.as_ref().map(mailbox_entry),
        });
    }
    serde_json::to_string(&Document {
        version: CONTACT_BACKUP_VERSION,
        contacts,
    })
    .map_err(|_| corrupt("backup"))
}

fn record_from(entry: &Entry) -> Result<(ContactRecord, Option<ContactMailbox>), StoreError> {
    let state = ContactState::from_code(&entry.state).ok_or_else(|| corrupt("state"))?;
    if matches!(
        state,
        ContactState::PendingInvite | ContactState::PendingReply
    ) {
        return Err(corrupt("state"));
    }
    let contact_id = ContactId(from_hex_fixed(&entry.contact_id, "contact id")?);
    let record = ContactRecord {
        contact_id,
        peer: Some(card_from(&entry.peer)?),
        alternate: entry.alternate.as_ref().map(card_from).transpose()?,
        label: entry.label.clone(),
        state,
        verified_at: optional_time(entry.verified_at.as_deref(), "verified at")?,
        allow_invoices: entry.allow_invoices,
        seal: SealMode::from_code(&entry.seal).ok_or_else(|| corrupt("seal"))?,
        last_sealed_in: optional_time(entry.last_sealed_in.as_deref(), "last sealed in")?,
        app_contact: entry.app_contact.clone(),
        imported_from_backup: true,
        created_at: time(&entry.created_at, "created at")?,
        updated_at: time(&entry.updated_at, "updated at")?,
    };
    let mailbox = entry
        .mailbox
        .as_ref()
        .map(|mailbox| {
            Ok::<_, StoreError>(ContactMailbox {
                contact_id,
                peer_mailbox: mailbox.peer_mailbox.clone(),
                our_mailbox: mailbox.our_mailbox.clone(),
                home_relay: mailbox.home_relay.clone(),
                onion: mailbox.onion.clone(),
                previous: mailbox
                    .previous
                    .as_ref()
                    .map(|previous| {
                        Ok::<_, StoreError>(PreviousHome {
                            relay: previous.relay.clone(),
                            peer_mailbox: previous.peer_mailbox.clone(),
                            our_mailbox: previous.our_mailbox.clone(),
                            until: time(&previous.until, "previous until")?,
                        })
                    })
                    .transpose()?,
                backoff: Vec::new(),
            })
        })
        .transpose()?;
    Ok((record, mailbox))
}

/// Restores the records of `json` that the store does not hold yet, flagged as imported. Run it
/// inside one store write: a malformed record, an unsupported version or a reached contact cap
/// fails the whole import.
pub fn import_contacts<R: ContactRepository + ?Sized>(
    repos: &mut R,
    json: &str,
) -> Result<ImportSummary, StoreError> {
    let document: Document = serde_json::from_str(json).map_err(|_| corrupt("backup"))?;
    if document.version != CONTACT_BACKUP_VERSION {
        return Err(StoreError::UnsupportedBackup {
            found: document.version,
        });
    }
    let mut summary = ImportSummary::default();
    for entry in &document.contacts {
        let (record, mailbox) = record_from(entry)?;
        if repos.contact(record.contact_id)?.is_some() {
            summary.skipped_existing = summary.skipped_existing.saturating_add(1);
            continue;
        }
        let held_by_other = match &record.peer {
            Some(peer) => repos.contact_by_peer_sig_key(&peer.sig_key)?.is_some(),
            None => false,
        };
        if held_by_other {
            summary.skipped_conflict = summary.skipped_conflict.saturating_add(1);
            continue;
        }
        repos.put_contact(&record)?;
        if let Some(mailbox) = &mailbox {
            repos.put_contact_mailbox(mailbox)?;
        }
        summary.imported = summary.imported.saturating_add(1);
    }
    Ok(summary)
}
