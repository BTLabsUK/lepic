// SPDX-License-Identifier: Apache-2.0
//! Epicbox address keys and payment-proof keys, derived by the wallet's
//! `address::address_from_derivation_path`, and the default Epicbox address string on each network.

use epic_core::global::{self, ChainTypes};
use epic_keychain::Keychain;
use epic_util::secp::key::PublicKey;
use epic_wallet_libwallet::{EpicboxAddress, address, version_bytes};
use serde::Serialize;

use super::{AREA, Inconsistent, KeyPath, KeysPins, Network, SEEDS, ensure, keychain};
use crate::{Error, Rendered, chain_type_guard, hex, render};

/// The default account and a second one.
const PARENTS: [KeyPath; 2] = [KeyPath::new(2, [0, 0, 0, 0]), KeyPath::new(2, [1, 0, 0, 0])];

/// `epic-wallet` always uses index 0; the others show how the index enters the path.
const INDEXES: [u32; 3] = [0, 1, 100];

#[derive(Serialize)]
struct Inputs {
    seed: String,
    parents: Vec<KeyPath>,
    indexes: Vec<u32>,
}

#[derive(Serialize)]
struct Expected {
    cases: Vec<Case>,
}

/// `key_identifier` is the parent path with its second component set to 1 and the index appended.
/// `raw_secret_key` is the plain BIP32 key there; `address_secret_key` is its unkeyed BLAKE2b-256.
/// The payment-proof key is the ed25519 key whose seed is `address_secret_key`. Keychains for
/// either network give the same keys; only the Epicbox version bytes differ.
#[derive(Serialize)]
struct Case {
    parent_identifier: String,
    index: u32,
    key_identifier: String,
    key_bip32_path: String,
    raw_secret_key: String,
    address_secret_key: String,
    address_public_key: String,
    epicbox: Vec<EpicboxForm>,
    payment_proof_public_key: String,
    payment_proof_onion_v3: String,
}

/// `address` is upstream's display form with the default domain and no port.
#[derive(Serialize)]
struct EpicboxForm {
    network: &'static str,
    version_bytes: String,
    public_key: String,
    address: String,
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        let inputs = Inputs {
            seed: hex(seed.entropy),
            parents: PARENTS.to_vec(),
            indexes: INDEXES.to_vec(),
        };
        let expected = cases(seed.entropy)?;
        let name = format!("address_keys_{}", seed.name);
        vectors.push(render(AREA, &name, &pins.wallet, inputs, expected)?);
    }
    Ok(vectors)
}

fn cases(seed: &[u8]) -> Result<Expected, Error> {
    let mainnet = keychain(seed, Network::Mainnet)?;
    let floonet = keychain(seed, Network::Floonet)?;
    let secp = mainnet.secp();
    let mut cases = Vec::new();
    for parent in PARENTS {
        let parent_id = parent.identifier();
        for index in INDEXES {
            let address_key = address::address_from_derivation_path(&mainnet, &parent_id, index)
                .map_err(Error::reference("address key"))?;
            let floonet_key = address::address_from_derivation_path(&floonet, &parent_id, index)
                .map_err(Error::reference("floonet address key"))?;
            ensure(
                address_key == floonet_key,
                "address keys equal on both networks",
            )?;

            let mut key_path = parent;
            key_path.components = with_address_branch(parent, index)?;
            key_path.depth = parent
                .depth
                .checked_add(1)
                .ok_or(Error::reference("key path")(Inconsistent("depth overflow")))?;
            let key_id = key_path.identifier();
            let raw = mainnet
                .derive_key(0, &key_id, &epic_keychain::SwitchCommitmentType::None)
                .map_err(Error::reference("raw address key"))?;

            let public = PublicKey::from_secret_key(secp, &address_key)
                .map_err(Error::reference("address public key"))?;
            let (_, proof_public) = address::ed25519_keypair(&address_key)
                .map_err(Error::reference("payment proof key"))?;
            let onion = address::onion_v3_from_pubkey(&proof_public)
                .map_err(Error::reference("onion v3 address"))?;

            let epicbox = Network::ALL
                .iter()
                .map(|network| epicbox_form(*network, public))
                .collect::<Result<_, _>>()?;

            cases.push(Case {
                parent_identifier: parent_id.to_hex(),
                index,
                key_identifier: key_id.to_hex(),
                key_bip32_path: key_id.to_bip_32_string(),
                raw_secret_key: hex(raw.0),
                address_secret_key: hex(address_key.0),
                address_public_key: hex(public.serialize_vec(secp, true)),
                epicbox,
                payment_proof_public_key: hex(proof_public.as_bytes()),
                payment_proof_onion_v3: onion,
            });
        }
    }
    Ok(Expected { cases })
}

/// Mirrors the path `address_from_derivation_path` builds, so the vector can state it and record
/// the plain key there. The address key itself always comes from upstream.
fn with_address_branch(parent: KeyPath, index: u32) -> Result<[u32; 4], Error> {
    let mut components = parent.components;
    let slot = components
        .get_mut(1)
        .ok_or(Error::reference("key path")(Inconsistent("short path")))?;
    *slot = 1;
    let slot = components
        .get_mut(usize::from(parent.depth))
        .ok_or(Error::reference("key path")(Inconsistent("path too deep")))?;
    *slot = index;
    Ok(components)
}

fn epicbox_form(network: Network, public: PublicKey) -> Result<EpicboxForm, Error> {
    // Upstream picks the Epicbox version bytes from the process-wide chain type.
    let _chain_type = chain_type_guard();
    let previous = global::CHAIN_TYPE.read().clone();
    global::set_mining_mode(match network {
        Network::Mainnet => ChainTypes::Mainnet,
        Network::Floonet => ChainTypes::Floonet,
    });
    let version = version_bytes();
    let address = EpicboxAddress::new(public, None, None);
    let parsed = address.public_key();
    global::set_mining_mode(previous);
    let parsed = parsed.map_err(Error::reference("epicbox address public key"))?;
    ensure(parsed == public, "epicbox address round trip")?;
    Ok(EpicboxForm {
        network: network.name(),
        version_bytes: hex(version),
        address: address.to_string(),
        public_key: address.public_key,
    })
}
