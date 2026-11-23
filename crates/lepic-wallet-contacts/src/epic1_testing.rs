// SPDX-License-Identifier: Apache-2.0
//! Links and payments outside the epic1 rules, for tests of the wallets that refuse them.
//! Built only with the `test-support` feature.

use lepic_crypto::PublicKey;
use lepic_epic1::{Epic1Address, Epic1Link};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork};
use lepic_keychain::Seed;
use lepic_methods::epicbox::relay_network;
use lepic_primitives::params::Network;
use lepic_seal::{EncPublicKey, ReplyRoute, TxContent, TxKey, seal_epic1_notice, seal_tx};
use lepic_store::AccountIndex;
use lepic_wallet::namespace;

use super::keys::contact_network;
use crate::ContactError;

/// The epic1 address `index` of `account` on `network` of the wallet with `seed`, as an earlier
/// release may have handed out a numbered one.
///
/// # Errors
///
/// [`ContactError::Wallet`] when no valid delivery key derives.
pub fn address_any(
    seed: &Seed,
    network: Network,
    account: AccountIndex,
    index: u32,
) -> Result<Epic1Address, ContactError> {
    let net = contact_network(network);
    let seal = namespace::epic1_seal_key(seed, account.0, net, index)?.public_key();
    let delivery =
        PublicKey::from_secret_key(&namespace::epic1_delivery_key(seed, account.0, net, index)?)
            .map_err(|_| ContactError::RelayAddress)?;
    Ok(Epic1Address::new(relay_network(network), seal, delivery))
}

/// The delivery mailbox on the relay `domain` of the address `text` pays: a link or a bare
/// address.
#[must_use]
pub fn delivery_mailbox(text: &str, domain: &str) -> Option<EpicboxAddress> {
    let address = address_of(text)?;
    Some(EpicboxAddress::new(
        *address.delivery_key(),
        address.network(),
        Domain::parse(domain).ok()?,
        None,
    ))
}

/// The address of `text`: a link or a bare address.
fn address_of(text: &str) -> Option<Epic1Address> {
    match Epic1Link::parse(text) {
        Ok(link) => Some(link.address),
        Err(_) => Epic1Address::decode_any(text).ok(),
    }
}

/// `link` with the address's network replaced by `network`.
fn rebuilt(link: &str, network: RelayNetwork) -> Option<String> {
    let mut link = Epic1Link::parse(link).ok()?;
    link.address = Epic1Address::new(
        network,
        *link.address.seal_key(),
        *link.address.delivery_key(),
    );
    Some(link.to_uri())
}

/// `link` for the other network, its transports kept.
#[must_use]
pub fn for_other_network(link: &str) -> Option<String> {
    let network = match Epic1Link::parse(link).ok()?.address.network() {
        RelayNetwork::Mainnet => RelayNetwork::Floonet,
        RelayNetwork::Floonet => RelayNetwork::Mainnet,
    };
    rebuilt(link, network)
}

/// `link` with no route entry.
#[must_use]
pub fn without_transports(link: &str) -> Option<String> {
    let mut link = Epic1Link::parse(link).ok()?;
    link.routes.clear();
    Some(link.to_uri())
}

/// `body` sealed to the epic1 `address` as a payment is, for `network`. With `reply_key` the
/// content names a reply key (tag 03), with `reply_route` a reply route of one `epicbox` entry
/// (tag 09).
#[must_use]
pub fn sealed_to_epic1<R: rand_core::CryptoRng>(
    network: Network,
    address: &str,
    body: Vec<u8>,
    reply_key: bool,
    reply_route: bool,
    rng: &mut R,
) -> Option<Vec<u8>> {
    let address = Epic1Address::decode_any(address).ok()?;
    let mut content = TxContent::new(body);
    if reply_key {
        content.reply_key = Some(*address.seal_key());
    }
    if reply_route {
        content.reply_route = Some(ReplyRoute::epicbox([2; 33]));
    }
    seal_tx(
        contact_network(network),
        address.seal_key(),
        TxKey::Epic1,
        &content,
        None,
        rng,
    )
    .ok()
}

/// `body` sealed to the epic1 `address` for `network` as a LEPIC payer seals a file payment:
/// naming the reply key `reply` and asking a receipt for the payer key `receipt_ask`.
#[must_use]
pub fn sealed_asking_receipt<R: rand_core::CryptoRng>(
    network: Network,
    address: &str,
    body: Vec<u8>,
    reply: &EncPublicKey,
    receipt_ask: [u8; 33],
    rng: &mut R,
) -> Option<Vec<u8>> {
    let address = Epic1Address::decode_any(address).ok()?;
    let mut content = TxContent::new(body);
    content.reply_key = Some(*reply);
    content.receipt_ask = Some(receipt_ask);
    seal_tx(
        contact_network(network),
        address.seal_key(),
        TxKey::Epic1,
        &content,
        None,
        rng,
    )
    .ok()
}

/// `body` sealed to the epic1 `address` as a payer seals its payment, for `network`: naming
/// the reply key `reply_key` and the reply mailbox of the key `reply_mailbox`.
#[must_use]
pub fn sealed_payment<R: rand_core::CryptoRng>(
    network: Network,
    address: &str,
    body: Vec<u8>,
    (reply_key, reply_mailbox): (EncPublicKey, [u8; 33]),
    rng: &mut R,
) -> Option<Vec<u8>> {
    let address = Epic1Address::decode_any(address).ok()?;
    let mut content = TxContent::new(body);
    content.reply_key = Some(reply_key);
    content.reply_route = Some(ReplyRoute::epicbox(reply_mailbox));
    seal_tx(
        contact_network(network),
        address.seal_key(),
        TxKey::Epic1,
        &content,
        None,
        rng,
    )
    .ok()
}

/// The notice `body` sealed to the address `text` pays, a link or a bare address, as a payer
/// seals a `posted` or `cancelled` notice, for `network`.
#[must_use]
pub fn sealed_notice<R: rand_core::CryptoRng>(
    network: Network,
    text: &str,
    body: &[u8],
    rng: &mut R,
) -> Option<Vec<u8>> {
    let address = address_of(text)?;
    seal_epic1_notice(contact_network(network), address.seal_key(), body, rng).ok()
}

/// The native body of the V3 JSON slate `v3` for `network`, as a payment to an epic1 address
/// carries it: the body [`sealed_to_epic1`] seals.
#[must_use]
pub fn native_body_of(network: Network, v3: &[u8]) -> Option<Vec<u8>> {
    super::native::native_body(network, v3).ok()
}

/// The native S2 `body` for `network` with a forged answer: the payee's partial signature with
/// one byte changed, as one without the payee's key would send it. `None` when `body` is no
/// native slate whose receiver signed.
#[must_use]
pub fn forged_answer(network: Network, body: &[u8]) -> Option<Vec<u8>> {
    let (slate, tail) = lepic_native_slate::NativeSlate::decode(network, body)
        .ok()?
        .into_parts();
    let mut parts = slate.into_parts();
    let signature = parts.receiver.as_mut()?.partial_signature.as_mut()?;
    let mut bytes = signature.to_compact();
    let last = bytes.last_mut()?;
    *last ^= 1;
    *signature = lepic_crypto::Signature::from_compact(&bytes).ok()?;
    let slate = lepic_slate::model::Slate::from_parts(parts).ok()?;
    Some(
        lepic_native_slate::NativeSlate::new(slate, tail)
            .ok()?
            .encode(network),
    )
}
