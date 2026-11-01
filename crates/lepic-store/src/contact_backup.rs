// SPDX-License-Identifier: Apache-2.0
//! Export and import of pairing records for the app's `.wfeh` history payload (RFC 0002 10.5).
//!
//! The document is `{"version":1,"network":"mainnet","contacts":[...],"slot_counters":[...]}`
//! with bytes in lowercase hex and times as RFC 3339. The records keep their account, slot and
//! box salt, so a restore derives the same keys and mailboxes, and the counters keep a restored
//! wallet from handing out a slot twice. Cards are kept as their bytes only: on import every card
//! is decoded again by the caller's [`CardReader`] and its keys, seq, kind and name come from
//! that decoding, never from the document. The `.wfeh` key is the same on both networks, so the
//! document names its network and an import refuses the other one. It holds no secret: pairings
//! in progress, outbox entries and relay backoff are not exported, and a contact still waiting
//! for its reply is left out because nothing could finish it. Neither is a pairing that ended,
//! or one whose contact was never heard from, so no build restores either as paired. Nothing
//! learned about the contact's wallet is kept either (the features it claims, when it was heard
//! or said it verified): a restore learns it again. The contact's proven payments address is
//! kept, so a restored record can still be attached to an address book entry. A record restored
//! from it is flagged [`ContactRecord::imported_from_backup`], because the pairing may also live
//! on the device the backup came from (cases C-11).

use jiff::Timestamp;
use lepic_primitives::params::Network;
use serde::{Deserialize, Serialize};

use crate::account::AccountIndex;
use crate::contact::{
    ContactId, ContactMailbox, ContactRecord, ContactRepository, ContactState, PairingFacts,
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

/// Decodes card bytes for the backup's network and verifies their signature, as the wallet does
/// with `lepic-contact`; `None` refuses them. The store cannot read cards itself.
pub type CardReader<'a> = dyn Fn(&[u8]) -> Option<PeerCard> + 'a;

#[derive(Serialize, Deserialize)]
struct Document {
    version: u64,
    network: String,
    contacts: Vec<Entry>,
    slot_counters: Vec<CounterEntry>,
}

#[derive(Serialize, Deserialize)]
struct CounterEntry {
    account: u32,
    next_slot: u32,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    contact_id: String,
    account: u32,
    slot: u32,
    box_salt: String,
    sas: Option<String>,
    own_card: String,
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
    // Added later: absent in older documents, ignored by older readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payments_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payments_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_verdict: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CardEntry {
    card: String,
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
    }
}

/// The card of `entry` as `read_card` decodes it; the decoded bytes must be the stored ones.
fn card_from(entry: &CardEntry, read_card: &CardReader<'_>) -> Result<PeerCard, StoreError> {
    let bytes = from_hex(&entry.card, "card")?;
    let card = read_card(&bytes).ok_or_else(|| corrupt("card"))?;
    if card.bytes != bytes {
        return Err(corrupt("card"));
    }
    Ok(card)
}

fn network_code(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Floonet => "floonet",
    }
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

/// Serialises the paired contacts of the store, oldest first, for `network`.
pub fn export_contacts<R: ContactRepository + ?Sized>(
    repos: &R,
    network: Network,
) -> Result<String, StoreError> {
    export_contacts_where(repos, network, |_| true)
}

/// [`export_contacts`] of the records `keep` accepts only.
pub fn export_contacts_where<R: ContactRepository + ?Sized>(
    repos: &R,
    network: Network,
    keep: impl Fn(&ContactRecord) -> bool,
) -> Result<String, StoreError> {
    let mut contacts = Vec::new();
    for contact in repos.contacts()? {
        if !keep(&contact) {
            continue;
        }
        if matches!(
            contact.state,
            ContactState::PendingInvite | ContactState::PendingReply
        ) {
            continue;
        }
        let Some(peer) = &contact.peer else {
            continue;
        };
        let facts = &contact.facts;
        if facts.ended_reason.is_some() {
            continue;
        }
        if facts.peer_heard_at.is_none() {
            continue;
        }
        let mailbox = repos.contact_mailbox(contact.contact_id)?;
        contacts.push(Entry {
            contact_id: to_hex(&contact.contact_id.0),
            account: contact.account.0,
            slot: contact.slot,
            box_salt: to_hex(&contact.box_salt),
            sas: contact.sas.as_ref().map(|sas| to_hex(sas)),
            own_card: to_hex(&contact.own_card),
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
            payments_address: facts.payments_address.clone(),
            payments_key: facts.payments_key.as_ref().map(|key| to_hex(key)),
            peer_verdict: facts.peer_verdict.as_ref().map(|verdict| to_hex(verdict)),
        });
    }
    let slot_counters = repos
        .contact_slot_counters()?
        .into_iter()
        .map(|(account, next_slot)| CounterEntry {
            account: account.0,
            next_slot,
        })
        .collect();
    serde_json::to_string(&Document {
        version: CONTACT_BACKUP_VERSION,
        network: network_code(network).to_owned(),
        contacts,
        slot_counters,
    })
    .map_err(|_| corrupt("backup"))
}

fn record_from(
    entry: &Entry,
    read_card: &CardReader<'_>,
) -> Result<(ContactRecord, Option<ContactMailbox>), StoreError> {
    let state = ContactState::from_code(&entry.state).ok_or_else(|| corrupt("state"))?;
    if matches!(
        state,
        ContactState::PendingInvite | ContactState::PendingReply
    ) {
        return Err(corrupt("state"));
    }
    let contact_id = ContactId(from_hex_fixed(&entry.contact_id, "contact id")?);
    let own_card = from_hex(&entry.own_card, "own card")?;
    if read_card(&own_card).is_none() {
        return Err(corrupt("own card"));
    }
    let created_at = time(&entry.created_at, "created at")?;
    let payments_key = entry
        .payments_key
        .as_deref()
        .map(|key| from_hex_fixed(key, "payments key"))
        .transpose()?;
    // An address comes back only with its key.
    let payments_address = entry
        .payments_address
        .clone()
        .filter(|_| payments_key.is_some());
    let facts = PairingFacts {
        payments_key: payments_key.filter(|_| payments_address.is_some()),
        payments_address,
        // What the contact claims and when it was heard or said it verified are not kept in a
        // backup; a restored record counts as heard since it was made and learns the rest
        // again from the contact.
        peer_heard_at: Some(created_at),
        peer_verdict: entry
            .peer_verdict
            .as_deref()
            .map(|verdict| from_hex_fixed(verdict, "peer verdict"))
            .transpose()?,
        ..PairingFacts::default()
    };
    let record = ContactRecord {
        contact_id,
        account: AccountIndex(entry.account),
        slot: entry.slot,
        box_salt: from_hex_fixed(&entry.box_salt, "box salt")?,
        sas: entry
            .sas
            .as_deref()
            .map(|sas| from_hex_fixed(sas, "sas"))
            .transpose()?,
        own_card,
        peer: Some(card_from(&entry.peer, read_card)?),
        alternate: entry
            .alternate
            .as_ref()
            .map(|alternate| card_from(alternate, read_card))
            .transpose()?,
        label: entry.label.clone(),
        state,
        verified_at: optional_time(entry.verified_at.as_deref(), "verified at")?,
        allow_invoices: entry.allow_invoices,
        seal: SealMode::from_code(&entry.seal).ok_or_else(|| corrupt("seal"))?,
        last_sealed_in: optional_time(entry.last_sealed_in.as_deref(), "last sealed in")?,
        app_contact: entry.app_contact.clone(),
        imported_from_backup: true,
        created_at,
        updated_at: time(&entry.updated_at, "updated at")?,
        facts,
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

/// Restores the records of `json` that the store does not hold yet, flagged as imported, and
/// raises the slot counters to the backup's. Every card, ours and the peer's, is read with
/// `read_card` for `network`. Run it inside one store write: a backup of the other network, a
/// card that does not read, a malformed record, an unsupported version or a reached contact cap
/// fails the whole import.
pub fn import_contacts<R: ContactRepository + ?Sized>(
    repos: &mut R,
    json: &str,
    network: Network,
    read_card: &CardReader<'_>,
) -> Result<ImportSummary, StoreError> {
    let document: Document = serde_json::from_str(json).map_err(|_| corrupt("backup"))?;
    if document.version != CONTACT_BACKUP_VERSION {
        return Err(StoreError::UnsupportedBackup {
            found: document.version,
        });
    }
    if document.network != network_code(network) {
        return Err(StoreError::BackupOfOtherNetwork);
    }
    for counter in &document.slot_counters {
        repos.raise_contact_slot_counter(AccountIndex(counter.account), counter.next_slot)?;
    }
    let mut summary = ImportSummary::default();
    for entry in &document.contacts {
        let (record, mailbox) = record_from(entry, read_card)?;
        // Every slot in the backup was used on the seed, whether or not its record is imported.
        repos.raise_contact_slot_counter(record.account, record.slot.saturating_add(1))?;
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
