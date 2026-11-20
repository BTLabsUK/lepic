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

use lepic_seal::PresharedKey;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{DecodeError, EncodeError, Malformed};
use crate::invite::Invite;
use crate::pairing::{Nonce, ReplyBody};
use crate::sas::Sas;
use lepic_seal::ContactCard;
use lepic_seal::EncSecretKey;
use lepic_seal::HintRule;
use lepic_seal::Network;
use lepic_seal::wire::{hmac_sha256, sha256};
use lepic_seal::{Content, MessageType, SealedEnvelope, seal_psk};

pub use lepic_seal::SUITE_PSK;

const REPLY_DOMAIN: &[u8] = b"epic-private/1 reply";
const CHANNEL_DOMAIN: &[u8] = b"epic-private/1 channel";
const SAS_DOMAIN: &[u8] = b"epic-private/1 sas";

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

impl PresharedKey for ChannelKey {
    fn psk_bytes(&self) -> &[u8; 32] {
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

#[cfg(test)]
mod tests {
    // Tests may unwrap, index and panic (docs/rules.md).
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use lepic_seal::wire::PSK_ID;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// `testdata/vectors/keys/private_pairing_tags.json`, written by the conformance generator
    /// from the description with `ring`: the reply key, the channel key, the words check and
    /// the PSK id of a private pairing.
    #[test]
    fn private_pairing_tags_match_the_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/keys/private_pairing_tags.json"
        ))
        .unwrap();
        let inputs = &vector["inputs"];
        let expected = &vector["expected"];
        let bytes = |name: &str| unhex(inputs[name].as_str().unwrap());
        let secret = |name: &str| PrivateSecret::from_bytes(bytes(name).try_into().unwrap());
        let nonce = |name: &str| Nonce::from_bytes(bytes(name).try_into().unwrap());
        assert_eq!(inputs["network"], 1);
        let network = Network::Floonet;
        let (link, joiner) = (secret("link"), secret("joiner"));
        let invite = Invite::decode(&bytes("invite"), network).unwrap();
        let card_a = ContactCard::decode(&bytes("card_a"), network).unwrap();
        let card_b = ContactCard::decode(&bytes("card_b"), network).unwrap();
        assert_eq!(inputs["reply_domain"], "epic-private/1 reply");
        assert_eq!(inputs["channel_domain"], "epic-private/1 channel");
        assert_eq!(inputs["sas_domain"], "epic-private/1 sas");

        assert_eq!(
            hex(ChannelKey::reply(&link).expose_bytes()),
            expected["reply_key"]
        );
        assert_eq!(
            hex(ChannelKey::channel(&link, &joiner, &invite, &card_b).expose_bytes()),
            expected["channel_key"]
        );
        let sas = private_sas(
            network,
            &card_a,
            &card_b,
            &nonce("nonce_a"),
            &nonce("nonce_b"),
            &link,
            &joiner,
        );
        assert_eq!(hex(sas.as_bytes()), expected["sas"]);
        assert_eq!(PSK_ID, expected["psk_id"].as_str().unwrap().as_bytes());
    }
}
