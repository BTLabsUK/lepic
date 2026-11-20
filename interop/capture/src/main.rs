// SPDX-License-Identifier: Apache-2.0
//! Opens the Epicbox messages LEPIC posted to the peer wallet during an interop gate run, so
//! `frames.py` can look inside them.
//!
//!     PEER_WALLET_PASSWORD=... open-frames <wallet.seed> <peer address> < frames.jsonl
//!
//! Each line of stdin is a `PostSlate` frame (`from`, `str`, `signature`). The peer's
//! address key comes from its epic-wallet seed file, the same derivation LEPIC uses (index 0
//! under m/0/0), and must give the address named on the command line. Each line of stdout is
//! the frame's `from` and `to` with either `plaintext` (the decrypted text) or `error`.

use std::io::{BufRead as _, Write as _};

use anyhow::{Context as _, bail};
use lepic_crypto::PublicKey;
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork, ReceivedMessage};
use lepic_keychain::{Identifier, Keychain, WalletSeedFile};
use lepic_primitives::params::Network;
use serde_json::{Value, json};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, seed_path, address] = args.as_slice() else {
        bail!(
            "usage: PEER_WALLET_PASSWORD=... open-frames <wallet.seed> <peer address> < frames.jsonl"
        );
    };
    let password =
        std::env::var("PEER_WALLET_PASSWORD").context("PEER_WALLET_PASSWORD is not set")?;
    let seed_text =
        std::fs::read_to_string(seed_path).with_context(|| format!("reading {seed_path}"))?;
    let seed = WalletSeedFile::parse(&seed_text)?.decrypt(password.as_bytes())?;
    let keychain = Keychain::from_seed(&seed, Network::Mainnet)?;
    let secret = keychain.address_key(&Identifier::new(2, [0, 0, 0, 0])?, 0)?;
    let own = EpicboxAddress::parse(address, RelayNetwork::Mainnet)?;
    if PublicKey::from_secret_key(&secret)? != *own.public_key() {
        bail!("the seed's index-0 address key is not the key of {address}");
    }

    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let frame: Value = serde_json::from_str(&line).context("a frame line is not JSON")?;
        let field = |name: &str| frame.get(name).and_then(Value::as_str).unwrap_or_default();
        let opened = match ReceivedMessage::open(
            field("from"),
            field("str"),
            field("signature"),
            &own,
            &secret,
        ) {
            Ok(message) => json!({"plaintext": message.plaintext.expose_str()}),
            Err(error) => json!({"error": error.to_string()}),
        };
        let mut record = json!({"from": field("from"), "to": field("to")});
        if let (Some(record), Some(opened)) = (record.as_object_mut(), opened.as_object()) {
            record.extend(opened.clone());
        }
        writeln!(out, "{record}")?;
    }
    Ok(())
}
