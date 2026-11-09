// SPDX-License-Identifier: Apache-2.0
//! Codes and answers outside the in-person rules, for tests of the wallets that refuse them.
//! Built only with the `test-support` feature.

use lepic_native_slate::{FLAG_PROOF, NativeSlate, ReplyKey, ReplyMailbox, Tail};
use lepic_primitives::params::Network;
use lepic_seal::{EncPublicKey, HintRule, TxContent, TxKey, seal_tx};

use super::keys::contact_network;

/// The byte of an encoded code that holds its flags.
const FLAGS_AT: usize = 7;

/// `code` with the payment-proof flag set.
#[must_use]
pub fn with_proof(code: &[u8]) -> Vec<u8> {
    let mut out = code.to_vec();
    if let Some(flags) = out.get_mut(FLAGS_AT) {
        *flags |= FLAG_PROOF;
    }
    out
}

/// `code` with no tail records.
#[must_use]
pub fn without_tail(network: Network, code: &[u8]) -> Option<Vec<u8>> {
    let (slate, _) = NativeSlate::decode(network, code).ok()?.into_parts();
    Some(NativeSlate::new(slate, Tail::empty()).ok()?.encode(network))
}

/// `code` with its reply mailbox moved to `host`, the key kept.
#[must_use]
pub fn with_mailbox_host(network: Network, code: &[u8], host: &str) -> Option<Vec<u8>> {
    let (slate, tail) = NativeSlate::decode(network, code).ok()?.into_parts();
    let reply_key = ReplyKey::from_bytes(*tail.reply_key()?.as_bytes());
    let mailbox = ReplyMailbox::new(*tail.reply_mailbox()?.key(), host.to_owned()).ok()?;
    let tail = Tail::new(Some(reply_key), Some(mailbox), Vec::new()).ok()?;
    Some(NativeSlate::new(slate, tail).ok()?.encode(network))
}

/// `code`, read on `network`, encoded for `other`.
#[must_use]
pub fn for_network(network: Network, other: Network, code: &[u8]) -> Option<Vec<u8>> {
    Some(NativeSlate::decode(network, code).ok()?.encode(other))
}

/// `body` sealed to the reply key of `code` as an answer is, for `envelope` network. With
/// `tagged`, the content also names a reply key and a reply mailbox of its own.
#[must_use]
pub fn sealed_to_code<R: rand_core::CryptoRng>(
    network: Network,
    envelope: Network,
    code: &[u8],
    body: Vec<u8>,
    tagged: bool,
    rng: &mut R,
) -> Option<Vec<u8>> {
    let native = NativeSlate::decode(network, code).ok()?;
    let reply_to = EncPublicKey::from_bytes(*native.tail().reply_key()?.as_bytes()).ok()?;
    let mut content = TxContent::new(body);
    if tagged {
        content.reply_key = Some(reply_to);
        content.reply_mailbox = Some(lepic_seal::ReplyMailbox::new([2; 33], "relay.test").ok()?);
    }
    seal_tx(
        contact_network(envelope),
        &reply_to,
        TxKey::Seal(HintRule::ReplyKey),
        &content,
        None,
        rng,
    )
    .ok()
}

/// `envelope` as the armoured text a relay carries.
#[must_use]
pub fn armored(envelope: &[u8]) -> String {
    lepic_seal::armor_tx(envelope)
}
