// SPDX-License-Identifier: Apache-2.0
//! Links and payments outside the epic1 rules, for tests of the wallets that refuse them.
//! Built only with the `test-support` feature.

use lepic_epic1::{Epic1Address, Epic1Link};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork};
use lepic_primitives::params::Network;
use lepic_seal::{ReplyMailbox, TxContent, TxKey, seal_tx};

use super::keys::contact_network;

/// The link mailboxes `link` names, in link order.
#[must_use]
pub fn link_mailboxes(link: &str) -> Option<Vec<EpicboxAddress>> {
    let link = Epic1Link::parse(link).ok()?;
    link.transports
        .iter()
        .map(|transport| {
            Some(EpicboxAddress::new(
                *transport.mailbox(),
                link.address.network(),
                Domain::parse(transport.relay().as_str()).ok()?,
                transport.port(),
            ))
        })
        .collect()
}

/// `link` with the address's network replaced by `network`.
fn rebuilt(link: &str, network: RelayNetwork) -> Option<String> {
    let mut link = Epic1Link::parse(link).ok()?;
    let proof = link.address.proof_key().to_bytes();
    link.address =
        Epic1Address::from_key_bytes(network, &proof, *link.address.seal_key().as_bytes()).ok()?;
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

/// `link` asking no amount, everything else kept.
#[must_use]
pub fn without_amount(link: &str) -> Option<String> {
    let mut link = Epic1Link::parse(link).ok()?;
    link.amount = None;
    Some(link.to_uri())
}

/// `link` with no transport.
#[must_use]
pub fn without_transports(link: &str) -> Option<String> {
    let mut link = Epic1Link::parse(link).ok()?;
    link.transports.clear();
    Some(link.to_uri())
}

/// `body` sealed to the epic1 `address` as a payment is, for `network`. With `reply_key` the
/// content names a reply key (tag 03), with `reply_mailbox` a reply mailbox on `relay.test`
/// (tag 09).
#[must_use]
pub fn sealed_to_epic1<R: rand_core::CryptoRng>(
    network: Network,
    address: &str,
    body: Vec<u8>,
    reply_key: bool,
    reply_mailbox: bool,
    rng: &mut R,
) -> Option<Vec<u8>> {
    let address = Epic1Address::decode_any(address).ok()?;
    let mut content = TxContent::new(body);
    if reply_key {
        content.reply_key = Some(*address.seal_key());
    }
    if reply_mailbox {
        content.reply_mailbox = Some(ReplyMailbox::new([2; 33], "relay.test").ok()?);
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

/// The native body of the V3 JSON slate `v3` for `network`, as a payment to an epic1 address
/// carries it: the body [`sealed_to_epic1`] seals.
#[must_use]
pub fn native_body_of(network: Network, v3: &[u8]) -> Option<Vec<u8>> {
    super::native::native_body(network, v3).ok()
}
