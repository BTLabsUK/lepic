// SPDX-License-Identifier: Apache-2.0
//! The eight-byte envelope hint that lets a recipient pick the opening key (RFC 0002 3.2).

use crate::hash::{first8, hmac_sha256, sha256};
use crate::keys::{EncPublicKey, HintKey};
use crate::pairing_id::InviteId;

const FIXED_DOMAIN: &[u8] = b"epic-seal/1 fixed";
const REPLY_DOMAIN: &[u8] = b"epic-seal/1 reply";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hint([u8; 8]);

impl Hint {
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// To a contact: `HMAC(hint_key, enc)[0..8]`, unlinkable between envelopes.
    pub fn contact(hint_key: &HintKey, enc: &[u8; 32]) -> Self {
        Self(first8(&hmac_sha256(hint_key.as_bytes(), enc)))
    }

    /// To a contact whose card sets `fixed-hint`: the same value on every envelope.
    pub fn fixed(hint_key: &HintKey) -> Self {
        Self(first8(&sha256(&[FIXED_DOMAIN, hint_key.as_bytes()])))
    }

    /// To a one-time reply key.
    pub fn reply(reply_key: &EncPublicKey, enc: &[u8; 32]) -> Self {
        let key = sha256(&[REPLY_DOMAIN, reply_key.as_bytes()]);
        Self(first8(&hmac_sha256(&key, enc)))
    }

    /// A pairing reply carries the invite id.
    pub fn invite(id: &InviteId) -> Self {
        Self(*id.as_bytes())
    }
}

/// How the sender picks the hint of an envelope it seals.
#[derive(Debug, Clone, Copy)]
pub enum HintRule<'a> {
    /// To a paired contact, with the hint key from its card.
    Contact(&'a HintKey),
    /// To a contact whose card sets the `fixed-hint` capability.
    FixedContact(&'a HintKey),
    /// To a one-time reply key: the hint derives from the recipient key itself.
    ReplyKey,
    /// A pairing reply to an invite.
    Invite(InviteId),
}

impl HintRule<'_> {
    pub fn hint(&self, recipient: &EncPublicKey, enc: &[u8; 32]) -> Hint {
        match self {
            Self::Contact(key) => Hint::contact(key, enc),
            Self::FixedContact(key) => Hint::fixed(key),
            Self::ReplyKey => Hint::reply(recipient, enc),
            Self::Invite(id) => Hint::invite(id),
        }
    }
}
