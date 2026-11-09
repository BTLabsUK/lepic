// SPDX-License-Identifier: Apache-2.0
//! Our keys for a contact (RFC 0002 2.2), the pairing mailbox keys (8.1), and the cards made
//! from them.

use lepic_contact::{
    Capabilities, CardFields, ContactCard, ContactKind, ContactName, EncPublicKey, EncSecretKey,
    HintKey, MailboxAddress, Network as ContactNetwork, SigningKey,
};
use lepic_crypto::PublicKey;
use lepic_epicbox::{EpicboxAddress, Identity, RelayEndpoint};
use lepic_keychain::Keychain;

use crate::key_schedule::{BOX_SALT_LEN, ContactKeys, pairing_mailbox_keys};
use lepic_primitives::params::Network;
use lepic_store::AccountIndex;

use super::ContactError;
use lepic_methods::epicbox::relay_network;
use lepic_wallet::account::parent_key_id;

/// The envelope version this wallet reads, which its cards announce.
const MAX_ENVELOPE_VERSION: u8 = 1;

pub(crate) fn contact_network(network: Network) -> ContactNetwork {
    match network {
        Network::Mainnet => ContactNetwork::Mainnet,
        Network::Floonet => ContactNetwork::Floonet,
    }
}

/// Our keys for the contact in `slot` of `account`.
pub(crate) fn contact_keys(
    keychain: &Keychain,
    network: Network,
    account: AccountIndex,
    slot: u32,
    box_salt: [u8; BOX_SALT_LEN],
) -> Result<ContactKeys, ContactError> {
    let root = crate::key_schedule::contact_root(keychain, &parent_key_id(account)?, network)
        .map_err(ContactError::Keys)?;
    root.contact_keys(slot, box_salt)
        .map_err(ContactError::Keys)
}

/// The X25519 key envelopes from the contact are opened with.
pub(crate) fn enc_secret(keys: &ContactKeys) -> EncSecretKey {
    EncSecretKey::from_bytes(*keys.expose_enc_secret())
}

/// Our contact mailbox for the contact, `box_pk@<relay>`, with the key that reads it and posts
/// to the contact.
pub(crate) fn box_identity(
    keys: &ContactKeys,
    network: Network,
    relay: &RelayEndpoint,
) -> Result<Identity, ContactError> {
    let address = EpicboxAddress::new(
        *keys.box_public_key(),
        relay_network(network),
        relay.domain().clone(),
        Some(relay.port()),
    );
    Identity::new(keys.expose_box_secret().clone(), address).map_err(|_| ContactError::RelayAddress)
}

/// The mailbox of a pairing seed (`code`, `rc`) on `relay`: the identity that reads it, and the
/// identity messages to it are posted from.
pub(crate) fn pairing_mailbox(
    seed: &[u8; 16],
    network: Network,
    relay: &RelayEndpoint,
) -> Result<(Identity, Identity), ContactError> {
    let (box_sk, from_sk) = pairing_mailbox_keys(seed, network).map_err(ContactError::Keys)?;
    let identity = |secret: lepic_crypto::SecretKey| {
        let public = PublicKey::from_secret_key(&secret).map_err(|_| ContactError::RelayAddress)?;
        let address = EpicboxAddress::new(
            public,
            relay_network(network),
            relay.domain().clone(),
            Some(relay.port()),
        );
        Identity::new(secret, address).map_err(|_| ContactError::RelayAddress)
    };
    Ok((identity(box_sk)?, identity(from_sk)?))
}

/// What a wallet card says about its owner besides the keys and the mailbox.
pub(crate) struct CardDetails<'a> {
    pub kind: ContactKind,
    pub name: &'a str,
    pub seq: u32,
    /// The wallet's payments address (tag 09), which the pairing's address proof covers.
    pub payments_address: Option<MailboxAddress>,
}

/// Our signed card for the contact whose keys are `keys`, delivering to `mailbox`.
pub(crate) fn our_card(
    keys: &ContactKeys,
    network: Network,
    mailbox: &EpicboxAddress,
    details: &CardDetails<'_>,
) -> Result<ContactCard, ContactError> {
    let signing = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let fields = CardFields {
        kind: details.kind,
        name: ContactName::new(details.name).map_err(ContactError::Name)?,
        enc_key: EncPublicKey::from_bytes(keys.enc_public_key())
            .map_err(|_| ContactError::Encode(lepic_contact::EncodeError::Encapsulation))?,
        sig_key: signing.verifying_key(),
        hint_key: HintKey::from_bytes(*keys.expose_hint_key()),
        mailbox: MailboxAddress::new(&mailbox.to_string()).map_err(ContactError::Name)?,
        payments_address: details.payments_address.clone(),
        home_onion: None,
        caps: Capabilities::OPENS_SEALED_FILES
            .with(Capabilities::PAYS_INVOICES)
            .with(Capabilities::ISSUES_INVOICES),
        max_envelope_version: MAX_ENVELOPE_VERSION,
        seq: details.seq,
    };
    ContactCard::sign(contact_network(network), fields, &signing).map_err(ContactError::Encode)
}

/// The Ed25519 key our envelopes and cards for the contact are signed with.
pub(crate) fn signing_key(keys: &ContactKeys) -> SigningKey {
    SigningKey::from_bytes(&keys.expose_signing_key().to_bytes())
}

/// The public key of the one-time reply key for the slate `slate_id` this wallet starts in
/// `account` (RFC 0002 2.3), for the LEPIC marker. `None` when it cannot be derived; the slate
/// then goes out without one and its answer comes back plain.
fn reply_public_key(
    keychain: &Keychain,
    network: Network,
    account: AccountIndex,
    slate_id: [u8; 16],
) -> Option<[u8; 32]> {
    Some(
        *reply_secret_key(keychain, network, account, slate_id)?
            .public_key()
            .as_bytes(),
    )
}

/// The one-time reply key for the slate `slate_id` this wallet starts in `account`: the answer
/// sealed to [`reply_public_key`] opens with it.
fn reply_secret_key(
    keychain: &Keychain,
    network: Network,
    account: AccountIndex,
    slate_id: [u8; 16],
) -> Option<EncSecretKey> {
    let root =
        crate::key_schedule::contact_root(keychain, &parent_key_id(account).ok()?, network).ok()?;
    let reply = root.reply_key(slate_id).ok()?;
    Some(EncSecretKey::from_bytes(*reply.expose_x25519_secret()))
}

/// The engine's reply key hook: the key [`reply_public_key`] derives.
pub(crate) struct ContactReplyKeys;

impl lepic_wallet::extension::ReplyKeys for ContactReplyKeys {
    fn reply_public_key(
        &self,
        keychain: &Keychain,
        network: Network,
        account: AccountIndex,
        slate_id: [u8; 16],
    ) -> Option<[u8; 32]> {
        reply_public_key(keychain, network, account, slate_id)
    }

    fn reply_secret_key(
        &self,
        keychain: &Keychain,
        network: Network,
        account: AccountIndex,
        slate_id: [u8; 16],
    ) -> Option<EncSecretKey> {
        reply_secret_key(keychain, network, account, slate_id)
    }
}
