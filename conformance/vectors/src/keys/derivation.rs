// SPDX-License-Identifier: Apache-2.0
//! BIP32 master key and child derivation as the node keychain does it, on both networks.

use epic_keychain::extkey_bip32::{BIP32GrinHasher, ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use epic_keychain::{Keychain, SwitchCommitmentType};
use epic_util::secp::key::PublicKey;
use serde::Serialize;

use super::{AREA, HARDENED, KeyPath, KeysPins, Network, SEEDS, ensure, keychain};
use crate::{Error, Rendered, hex, render};

/// The master, the default account and its outputs, the address-key branch, a second account,
/// the largest normal index, a depth-4 path and hardened components.
const PATHS: [KeyPath; 12] = [
    KeyPath::new(0, [0, 0, 0, 0]),
    KeyPath::new(1, [0, 0, 0, 0]),
    KeyPath::new(2, [0, 0, 0, 0]),
    KeyPath::new(3, [0, 0, 0, 0]),
    KeyPath::new(3, [0, 0, 1, 0]),
    KeyPath::new(3, [0, 0, 1000, 0]),
    KeyPath::new(3, [0, 0, HARDENED - 1, 0]),
    KeyPath::new(3, [0, 1, 0, 0]),
    KeyPath::new(3, [1, 0, 5, 0]),
    KeyPath::new(4, [0, 0, 0, 3]),
    KeyPath::new(2, [HARDENED, 1, 0, 0]),
    KeyPath::new(3, [HARDENED | 44, HARDENED, 7, 0]),
];

#[derive(Serialize)]
struct Inputs {
    seed: String,
    network: &'static str,
    paths: Vec<KeyPath>,
}

#[derive(Serialize)]
struct Expected {
    master: Master,
    keys: Vec<DerivedKey>,
}

/// `ext_priv_version` and `ext_pub_version` are the extended-key version bytes; nothing else in
/// a keychain depends on the network.
#[derive(Serialize)]
struct Master {
    secret_key: String,
    chain_code: String,
    public_key: String,
    ext_priv_version: String,
    ext_pub_version: String,
}

/// `secret_key` is the plain BIP32 key, without a switch commitment. `parent_fingerprint` is the
/// first four bytes of HASH160 of the parent public key.
#[derive(Serialize)]
struct DerivedKey {
    path: KeyPath,
    identifier: String,
    bip32_path: String,
    parent_identifier: String,
    secret_key: String,
    public_key: String,
    chain_code: String,
    parent_fingerprint: String,
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        for network in Network::ALL {
            let name = format!("derivation_{}_{}", seed.name, network.name());
            let inputs = Inputs {
                seed: hex(seed.entropy),
                network: network.name(),
                paths: PATHS.to_vec(),
            };
            let expected = derive(seed.entropy, network)?;
            vectors.push(render(AREA, &name, pins.node, inputs, expected)?);
        }
    }
    Ok(vectors)
}

fn derive(seed: &[u8], network: Network) -> Result<Expected, Error> {
    let keychain = keychain(seed, network)?;
    let secp = keychain.secp();
    let mut hasher = BIP32GrinHasher::new(network.is_floonet());
    let master_ext = &keychain.master;
    let master_pub = ExtendedPubKey::from_private(secp, master_ext, &mut hasher);
    ensure(
        master_pub.public_key == keychain.public_root_key(),
        "root public key",
    )?;
    let master = Master {
        secret_key: hex(master_ext.secret_key.0),
        chain_code: hex(master_ext.chain_code.as_bytes()),
        public_key: hex(master_pub.public_key.serialize_vec(secp, true)),
        ext_priv_version: hex(master_ext.network),
        ext_pub_version: hex(master_pub.network),
    };

    let mut keys = Vec::new();
    for path in PATHS {
        let id = path.identifier();
        let upstream_path = id.to_path();
        let children: Vec<ChildNumber> = upstream_path
            .path
            .iter()
            .take(usize::from(upstream_path.depth))
            .copied()
            .collect();
        let ext: ExtendedPrivKey = master_ext
            .derive_priv(secp, &mut hasher, &children)
            .map_err(Error::reference("bip32 derivation"))?;
        let secret = keychain
            .derive_key(0, &id, &SwitchCommitmentType::None)
            .map_err(Error::reference("keychain derivation"))?;
        ensure(secret == ext.secret_key, "keychain and bip32 derivation")?;
        let public = PublicKey::from_secret_key(secp, &secret)
            .map_err(Error::reference("derived public key"))?;
        keys.push(DerivedKey {
            path,
            identifier: id.to_hex(),
            bip32_path: id.to_bip_32_string(),
            parent_identifier: id.parent_path().to_hex(),
            secret_key: hex(secret.0),
            public_key: hex(public.serialize_vec(secp, true)),
            chain_code: hex(ext.chain_code.as_bytes()),
            parent_fingerprint: hex(ext.parent_fingerprint.as_bytes()),
        });
    }
    Ok(Expected { master, keys })
}
