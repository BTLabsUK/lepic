// SPDX-License-Identifier: Apache-2.0
//! The pairing invite (RFC 0002 7.1) and its `epiccash://pair/1/` link.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::error::{DecodeError, EncodeError, Malformed};
use crate::pairing::{Commitment, InviteId, PairingCode};
use crate::private::{PairingClass, PrivateSecret};
use lepic_seal::ContactKind;
use lepic_seal::EncPublicKey;
use lepic_seal::Network;
use lepic_seal::wire::{Fields, Writer, check_format};
use lepic_seal::wire::{LinkKind, decode_link, encode_link};
use lepic_seal::{ContactName, MailboxAddress, RelayHost};

pub const MAX_INVITE_LEN: usize = 1024;
pub const INVITE_FORMAT: u8 = 1;

const TAG_FORMAT: u8 = 0x01;
const TAG_NETWORK: u8 = 0x02;
const TAG_KIND: u8 = 0x03;
const TAG_NAME: u8 = 0x04;
const TAG_EXPIRES: u8 = 0x05;
const TAG_CODE: u8 = 0x06;
const TAG_COMMIT: u8 = 0x07;
const TAG_ENC_KEY: u8 = 0x08;
const TAG_HOME_RELAY: u8 = 0x09;
const TAG_SERVICE_INBOX: u8 = 0x0a;
const TAG_ONION: u8 = 0x0b;
/// The link secret of a private pairing's invite: an extension, so a reader that predates
/// private pairings skips it, and its reply, sealed without the key, does not open.
const TAG_LINK_SECRET: u8 = 0x80;
/// The inviter's mailbox key for the pairing (its card's tag 08 key, a compressed secp256k1
/// key), which the invitee's address proof is made for. An extension older readers skip.
const TAG_MAILBOX_KEY: u8 = 0x81;
/// The length of a compressed secp256k1 public key.
pub const MAILBOX_KEY_LEN: usize = 33;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteFields {
    /// The inviter's card kind.
    ///
    /// Deprecated: always written for wallets that read it, never to be read for meaning;
    /// to be removed (docs/adr/0041 or RFC 0002 6.1).
    pub kind: ContactKind,
    /// The inviter's claimed name.
    pub name: ContactName,
    /// Unix seconds.
    pub expires: u64,
    pub code: PairingCode,
    pub commit: Commitment,
    /// The key the invitee seals its reply to.
    pub enc_key: EncPublicKey,
    /// The relationship's home relay, `domain[:port]`.
    pub home_relay: RelayHost,
    /// A service's fixed pairing inbox, used instead of the derived reply mailbox.
    pub service_inbox: Option<MailboxAddress>,
    pub onion: Option<RelayHost>,
    /// Set exactly for a private pairing's invite ([`PairingClass::Private`]).
    pub link: Option<PrivateSecret>,
    /// The inviter's mailbox key of the pairing, the key its card names in tag 08, for the
    /// invitee's address proof. Its curve point is the reader's check.
    pub mailbox_key: Option<[u8; MAILBOX_KEY_LEN]>,
}

/// An invite and its exact bytes, which hold the pairing code: wiped on drop, and `Debug` shows
/// only their length.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    network: Network,
    fields: InviteFields,
    bytes: Vec<u8>,
}

impl Drop for Invite {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("network", &self.network)
            .field("kind", &self.fields.kind)
            .field("expires", &self.fields.expires)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl Invite {
    pub fn new(network: Network, fields: InviteFields) -> Result<Self, EncodeError> {
        let mut writer = Writer::default();
        writer.field(TAG_FORMAT, &[INVITE_FORMAT])?;
        writer.field(TAG_NETWORK, &[network.byte()])?;
        writer.field(TAG_KIND, &[fields.kind.byte()])?;
        writer.field(TAG_NAME, fields.name.as_str().as_bytes())?;
        writer.field(TAG_EXPIRES, &fields.expires.to_be_bytes())?;
        writer.field(TAG_CODE, fields.code.expose_bytes())?;
        writer.field(TAG_COMMIT, fields.commit.as_bytes())?;
        writer.field(TAG_ENC_KEY, fields.enc_key.as_bytes())?;
        writer.field(TAG_HOME_RELAY, fields.home_relay.as_str().as_bytes())?;
        writer.optional(
            TAG_SERVICE_INBOX,
            fields
                .service_inbox
                .as_ref()
                .map(|inbox| inbox.as_str().as_bytes()),
        )?;
        writer.optional(
            TAG_ONION,
            fields.onion.as_ref().map(|onion| onion.as_str().as_bytes()),
        )?;
        if fields.link.is_some() && fields.service_inbox.is_some() {
            return Err(EncodeError::WrongClass);
        }
        writer.optional(
            TAG_LINK_SECRET,
            fields.link.as_ref().map(|link| &link.expose_bytes()[..]),
        )?;
        writer.optional(
            TAG_MAILBOX_KEY,
            fields.mailbox_key.as_ref().map(|key| &key[..]),
        )?;
        let bytes = writer.into_bytes();
        if bytes.len() > MAX_INVITE_LEN {
            return Err(EncodeError::Oversized {
                limit: MAX_INVITE_LEN,
                found: bytes.len(),
            });
        }
        Ok(Self {
            network,
            fields,
            bytes,
        })
    }

    pub fn decode(bytes: &[u8], network: Network) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_INVITE_LEN {
            return Err(DecodeError::Oversized {
                limit: MAX_INVITE_LEN,
                found: bytes.len(),
            });
        }
        check_format(bytes, TAG_FORMAT, INVITE_FORMAT)?;
        let fields = Fields::parse(bytes, TAG_ONION, None)?;
        if fields.require_u8(TAG_FORMAT)? != INVITE_FORMAT {
            return Err(Malformed::FieldValue { tag: TAG_FORMAT }.into());
        }
        network.expect_byte(fields.require_u8(TAG_NETWORK)?)?;
        let value = |tag| Malformed::FieldValue { tag };
        let kind = ContactKind::from_byte(fields.require_u8(TAG_KIND)?).ok_or(value(TAG_KIND))?;
        let name = ContactName::try_from(fields.require(TAG_NAME)?).map_err(|_| value(TAG_NAME))?;
        let expires = fields.require_u64(TAG_EXPIRES)?;
        let code = PairingCode::from_bytes(fields.require_array(TAG_CODE)?);
        let commit = Commitment::from_bytes(fields.require_array(TAG_COMMIT)?);
        let enc_key = EncPublicKey::from_pairing_bytes(fields.require_array(TAG_ENC_KEY)?)
            .map_err(|_| value(TAG_ENC_KEY))?;
        let home_relay = RelayHost::try_from(fields.require(TAG_HOME_RELAY)?)
            .map_err(|_| value(TAG_HOME_RELAY))?;
        let service_inbox = fields
            .get(TAG_SERVICE_INBOX)
            .map(|bytes| MailboxAddress::try_from(bytes).map_err(|_| value(TAG_SERVICE_INBOX)))
            .transpose()?;
        let onion = fields
            .get(TAG_ONION)
            .map(|bytes| RelayHost::try_from(bytes).map_err(|_| value(TAG_ONION)))
            .transpose()?;
        let link = fields
            .extension(TAG_LINK_SECRET)
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes)
                    .map(PrivateSecret::from_bytes)
                    .map_err(|_| value(TAG_LINK_SECRET))
            })
            .transpose()?;
        let mailbox_key = fields
            .extension(TAG_MAILBOX_KEY)
            .map(|bytes| {
                <[u8; MAILBOX_KEY_LEN]>::try_from(bytes).map_err(|_| value(TAG_MAILBOX_KEY))
            })
            .transpose()?;
        // A private pairing's messages never go to a service's fixed inbox.
        if link.is_some() && service_inbox.is_some() {
            return Err(value(TAG_LINK_SECRET).into());
        }
        Ok(Self {
            network,
            fields: InviteFields {
                kind,
                name,
                expires,
                code,
                commit,
                enc_key,
                home_relay,
                service_inbox,
                onion,
                link,
                mailbox_key,
            },
            bytes: bytes.to_vec(),
        })
    }

    pub fn from_link(text: &str, network: Network) -> Result<Self, DecodeError> {
        let bytes = Zeroizing::new(decode_link(text, LinkKind::Pair, MAX_INVITE_LEN)?);
        Self::decode(&bytes, network)
    }

    pub fn to_link(&self) -> String {
        encode_link(LinkKind::Pair, &self.bytes)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn fields(&self) -> &InviteFields {
        &self.fields
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Which pairing the invite makes.
    pub fn class(&self) -> PairingClass {
        if self.fields.link.is_some() {
            PairingClass::Private
        } else {
            PairingClass::Contact
        }
    }

    pub fn id(&self) -> InviteId {
        InviteId::from_code(&self.fields.code)
    }

    /// Whether the invite has expired at `now`, in unix seconds.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.fields.expires
    }
}
