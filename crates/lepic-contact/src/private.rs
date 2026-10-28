// SPDX-License-Identifier: Apache-2.0
//! Private pairings: a pairing class for two wallets of one owner, whose channel someone with
//! the recovery phrase alone can neither find, read nor write.
//!
//! The invite, which travels out of band only, carries a random link secret `sA`; the reply
//! carries the joiner's random secret `sB`. The reply is sealed in HPKE PSK mode under a key
//! from `sA`, and every later envelope of the pairing, both ways, under the channel key
//! `HMAC-SHA256(key = H("epic-private/1 channel" || sA || sB), H(invite) || H(cardB))`, which
//! binds both secrets to the invite and the joiner's card. Envelopes of a private pairing are
//! sealed with suite [`SUITE_PSK`] and open only with that key; a base-mode envelope is refused.
//! The words check covers both secrets, so a swapped secret shows as different words.

use std::fmt;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::card::ContactCard;
use crate::envelope::{Content, MessageType, SealedEnvelope, seal_psk};
use crate::error::{DecodeError, EncodeError, Malformed};
use crate::hash::{hmac_sha256, sha256};
use crate::hint::HintRule;
use crate::invite::Invite;
use crate::keys::EncSecretKey;
use crate::network::Network;
use crate::pairing::{Nonce, ReplyBody};
use crate::sas::Sas;

/// The HPKE suite of a private pairing's envelopes: the suite of [`crate::SUITE`] in PSK mode.
/// RFC 0002's kit keeps suite 2 as an unknown suite, so this one lies apart.
pub const SUITE_PSK: u8 = 0x41;

const REPLY_DOMAIN: &[u8] = b"epic-private/1 reply";
const CHANNEL_DOMAIN: &[u8] = b"epic-private/1 channel";
const SAS_DOMAIN: &[u8] = b"epic-private/1 sas";
/// The HPKE PSK id of every private pairing key.
pub(crate) const PSK_ID: &[u8] = b"epic-private/1";

/// Which kind of pairing an invite makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingClass {
    /// A contact (RFC 0002): slates, invoices and notices.
    Contact,
    /// Two wallets of one owner: only the host app's payloads.
    Private,
}

/// A random 32-byte secret of a private pairing: the inviter's link secret, the joiner's, or a
/// record's own key secret. Wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrivateSecret([u8; 32]);

impl PrivateSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivateSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateSecret(<redacted>)")
    }
}

/// An HPKE pre-shared key of a private pairing. Wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ChannelKey([u8; 32]);

impl ChannelKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key the joiner's reply is sealed under: from the link secret alone.
    pub fn reply(link: &PrivateSecret) -> Self {
        Self(sha256(&[REPLY_DOMAIN, link.expose_bytes()]))
    }

    /// The key of every envelope after the reply, both ways.
    pub fn channel(
        link: &PrivateSecret,
        joiner: &PrivateSecret,
        invite: &Invite,
        joiner_card: &ContactCard,
    ) -> Self {
        let key = Zeroizing::new(sha256(&[
            CHANNEL_DOMAIN,
            link.expose_bytes(),
            joiner.expose_bytes(),
        ]));
        let transcript = [sha256(&[invite.as_bytes()]), joiner_card.digest()].concat();
        Self(hmac_sha256(&key, &transcript))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelKey(<redacted>)")
    }
}

/// The words check of a private pairing:
/// `H("epic-private/1 sas" || net || H(cardA) || H(cardB) || nA || nB || H(sA || sB))[0..4]`.
pub fn private_sas(
    network: Network,
    inviter: &ContactCard,
    invitee: &ContactCard,
    inviter_nonce: &Nonce,
    invitee_nonce: &Nonce,
    link: &PrivateSecret,
    joiner: &PrivateSecret,
) -> Sas {
    let secrets = Zeroizing::new(sha256(&[link.expose_bytes(), joiner.expose_bytes()]));
    let [a, b, c, d, ..] = sha256(&[
        SAS_DOMAIN,
        &[network.byte()],
        &inviter.digest(),
        &invitee.digest(),
        inviter_nonce.expose_bytes(),
        invitee_nonce.expose_bytes(),
        secrets.as_slice(),
    ]);
    Sas::from_bytes([a, b, c, d])
}

/// Seals the joiner's reply to a private invite: `sB || body`, anonymous, hinted with the
/// invite id, under the reply key of the invite's link secret.
pub fn seal_private_reply<R: CryptoRng>(
    invite: &Invite,
    body: &ReplyBody,
    joiner: &PrivateSecret,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let network = invite.network();
    let link = invite
        .fields()
        .link
        .as_ref()
        .ok_or(EncodeError::WrongClass)?;
    if body.card.network() != network {
        return Err(EncodeError::WrongNetwork);
    }
    let encoded = body.encode();
    let mut plain = Zeroizing::new(Vec::with_capacity(encoded.len().saturating_add(32)));
    plain.extend_from_slice(joiner.expose_bytes());
    plain.extend_from_slice(&encoded);
    let mut content = Content::new(MessageType::PairingReply, plain.to_vec());
    let sealed = seal_psk(
        network,
        &invite.fields().enc_key,
        HintRule::Invite(invite.id()),
        &content,
        None,
        &ChannelKey::reply(link),
        rng,
    );
    content.body.zeroize();
    sealed
}

/// Opens a reply to a private invite whose link secret is `link`: the body and the joiner's
/// secret. A reply sealed in base mode, or signed, is refused.
pub fn open_private_reply(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    link: &PrivateSecret,
) -> Result<(ReplyBody, PrivateSecret), DecodeError> {
    let opened = envelope.open_psk(key, &ChannelKey::reply(link))?;
    if opened.sender.is_some() {
        return Err(Malformed::Signed {
            kind: MessageType::PairingReply.byte(),
        }
        .into());
    }
    if opened.content.kind != MessageType::PairingReply {
        return Err(Malformed::FieldValue { tag: 0x01 }.into());
    }
    let plain = Zeroizing::new(opened.content.body);
    let (secret, body) = plain
        .split_first_chunk::<32>()
        .ok_or(Malformed::Truncated)?;
    Ok((
        ReplyBody::decode(body, envelope.network())?,
        PrivateSecret::from_bytes(*secret),
    ))
}
