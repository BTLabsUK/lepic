//! Private pairings in the store: two wallets of one owner, whose channel carries only the host
//! app's payloads.
//!
//! A record is private exactly when its slot is at or above [`PRIVATE_SLOT_BASE`], which no
//! contact slot reaches. Its secrets (the record's own key secret, the invite's link secret,
//! the joiner's secret and the channel key derived from both) are sealed in the store with the
//! private transaction contexts, under the record's id. A private record whose secrets do not
//! open is neither class: nothing is sent or taken through it.

use lepic_contact::{ChannelKey, PrivateSecret};
use lepic_keychain::Keychain;

use crate::key_schedule::{ContactKeys, PRIVATE_SLOT_BASE};
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, ContactId, ContactRecord, ParticipantId, PrivateContext, Repositories, StoreError,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::ContactError;
use super::keys::contact_keys;
use lepic_wallet::account::parent_key_id;

/// The participant byte the secrets are sealed under: no slate participant uses it.
const SECRETS: ParticipantId = ParticipantId(0xc1);
/// The next private slot this store hands out.
const SLOT_KEY: &str = "contact.private_slot";
const FORMAT: u8 = 1;

/// The secrets of one private pairing.
#[derive(Debug, Clone)]
pub(crate) struct PrivateSecrets {
    /// Salts this record's keys.
    pub own: PrivateSecret,
    /// The invite's link secret: the inviter's own, or the one the joiner read.
    pub link: PrivateSecret,
    /// The joiner's secret, once the reply is made or taken.
    pub joiner: Option<PrivateSecret>,
    /// The key of every envelope after the reply, once both secrets are known.
    pub channel: Option<ChannelKey>,
}

impl PrivateSecrets {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(130));
        bytes.push(FORMAT);
        bytes.extend_from_slice(self.own.expose_bytes());
        bytes.extend_from_slice(self.link.expose_bytes());
        match &self.joiner {
            Some(joiner) => {
                bytes.push(1);
                bytes.extend_from_slice(joiner.expose_bytes());
            }
            None => bytes.push(0),
        }
        match &self.channel {
            Some(channel) => {
                bytes.push(1);
                bytes.extend_from_slice(channel.expose_bytes());
            }
            None => bytes.push(0),
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (&format, rest) = bytes.split_first()?;
        if format != FORMAT {
            return None;
        }
        let (own, rest) = rest.split_first_chunk::<32>()?;
        let (link, rest) = rest.split_first_chunk::<32>()?;
        let (joiner, rest) = optional(rest)?;
        let (channel, rest) = optional(rest)?;
        if !rest.is_empty() {
            return None;
        }
        Some(Self {
            own: PrivateSecret::from_bytes(*own),
            link: PrivateSecret::from_bytes(*link),
            joiner: joiner.map(PrivateSecret::from_bytes),
            channel: channel.map(ChannelKey::from_bytes),
        })
    }
}

fn optional(bytes: &[u8]) -> Option<(Option<[u8; 32]>, &[u8])> {
    match bytes.split_first()? {
        (0, rest) => Some((None, rest)),
        (1, rest) => {
            let (value, rest) = rest.split_first_chunk::<32>()?;
            Some((Some(*value), rest))
        }
        _ => None,
    }
}

/// Which class a stored record is of.
#[derive(Debug, Clone)]
pub(crate) enum RecordClass {
    Contact,
    Private(Box<PrivateSecrets>),
    /// A private record whose secrets are missing or do not open.
    Unreadable,
}

impl RecordClass {
    pub(crate) fn private(&self) -> Option<&PrivateSecrets> {
        match self {
            Self::Private(secrets) => Some(secrets),
            Self::Contact | Self::Unreadable => None,
        }
    }
}

/// Whether `record` is a private pairing's, readable or not.
pub(crate) fn is_private(record: &ContactRecord) -> bool {
    record.slot >= PRIVATE_SLOT_BASE
}

fn key_of(contact_id: ContactId) -> Uuid {
    Uuid::from_bytes(contact_id.0)
}

/// The class of `record`, reading its sealed secrets for a private one.
pub(crate) fn class_of(
    repos: &dyn Repositories,
    record: &ContactRecord,
) -> Result<RecordClass, StoreError> {
    if !is_private(record) {
        return Ok(RecordClass::Contact);
    }
    match repos.context(key_of(record.contact_id), SECRETS) {
        Ok(Some(context)) => Ok(PrivateSecrets::decode(context.expose())
            .map_or(RecordClass::Unreadable, |secrets| {
                RecordClass::Private(Box::new(secrets))
            })),
        Ok(None) | Err(StoreError::ContextUndecryptable) => Ok(RecordClass::Unreadable),
        Err(error) => Err(error),
    }
}

/// Seals and stores the secrets of the private record `contact_id`.
pub(crate) fn put_secrets(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    secrets: &PrivateSecrets,
) -> Result<(), StoreError> {
    repos.put_context(
        key_of(contact_id),
        SECRETS,
        &PrivateContext::new(secrets.encode().to_vec()),
    )
}

/// Forgets the secrets of `contact_id`, when it had any.
pub(crate) fn delete_secrets(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
) -> Result<(), StoreError> {
    repos.delete_context(key_of(contact_id), SECRETS)
}

/// The next private slot of this store, from [`PRIVATE_SLOT_BASE`] up, never reused.
pub(crate) fn take_private_slot(repos: &mut dyn Repositories) -> Result<u32, ContactError> {
    let slot = repos
        .setting(SLOT_KEY)?
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|slot| *slot >= PRIVATE_SLOT_BASE)
        .unwrap_or(PRIVATE_SLOT_BASE);
    if slot >= lepic_store::PRIVATE_SLOT_END {
        return Err(ContactError::NoFreeSlot);
    }
    let next = slot.checked_add(1).ok_or(ContactError::NoFreeSlot)?;
    repos.put_setting(SLOT_KEY, &next.to_string())?;
    Ok(slot)
}

/// Our keys for `record`: a contact's from its slot and box salt, a private pairing's from its
/// slot and own secret. An unreadable private record has none.
pub(crate) fn record_keys(
    keychain: &Keychain,
    network: Network,
    record: &ContactRecord,
    class: &RecordClass,
) -> Result<ContactKeys, ContactError> {
    match class {
        RecordClass::Contact => contact_keys(
            keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        ),
        RecordClass::Private(secrets) => {
            private_keys(keychain, network, record.account, record.slot, &secrets.own)
        }
        RecordClass::Unreadable => Err(ContactError::UnknownContact),
    }
}

/// The keys of a private pairing in `slot` of `account`, whose own secret is `own`.
pub(crate) fn private_keys(
    keychain: &Keychain,
    network: Network,
    account: AccountIndex,
    slot: u32,
    own: &PrivateSecret,
) -> Result<ContactKeys, ContactError> {
    let root = crate::key_schedule::contact_root(keychain, &parent_key_id(account)?, network)
        .map_err(ContactError::Keys)?;
    root.private_keys(slot, own.expose_bytes())
        .map_err(ContactError::Keys)
}
