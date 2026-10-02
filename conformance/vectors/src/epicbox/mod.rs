//! Epicbox area: address parse and display, the signatures the relay checks, and messages encrypted
//! by the reference `EncryptedMessage`.
//!
//! Addresses and signatures are deterministic. Messages are randomized: upstream draws the salt and
//! nonce itself, so each message vector records them, and the generator decrypts every message with
//! upstream code before it is written.

mod address;
mod message;
mod signature;

use std::panic;
use std::sync::{Mutex, PoisonError};

use epic_core::global::{self, ChainTypes};
use epic_util::secp::Secp256k1;
use epic_util::secp::key::{PublicKey, SecretKey};
use epic_wallet_libwallet::crypto::{
    Base58, EPICBOX_ADDRESS_VERSION_MAINNET, EPICBOX_ADDRESS_VERSION_TESTNET,
};
use serde::Serialize;

use crate::{Error, LOCKFILE, Pins, Rendered, Upstream, git_source};

const AREA: &str = "epicbox";

/// A property of upstream's output that the generator checks before writing a vector.
#[derive(Debug, thiserror::Error)]
enum CheckFailed {
    #[error("signature also verified under another key")]
    OtherKey,
    #[error("signature also verified over another text")]
    OtherText,
    #[error("decrypted text differs from the plaintext")]
    Plaintext,
    #[error("sender and receiver derived different keys")]
    SharedKey,
    #[error("tampered ciphertext decrypted")]
    Tampered,
    #[error("upstream did not parse an address the generator built")]
    Address,
    #[error("upstream's epicbox receive path did not return the slate")]
    ReceivePath,
}

pub(crate) fn generate(_pins: &Pins) -> Result<Vec<Rendered>, Error> {
    // Every case here runs epic-wallet code, whose commit `Pins` does not carry.
    let wallet = git_source(LOCKFILE, "epic_wallet_libwallet")?;
    let mut vectors = address::generate(&wallet)?;
    vectors.extend(signature::generate(&wallet)?);
    vectors.extend(message::generate(&wallet)?);
    Ok(vectors)
}

fn render<I: Serialize, E: Serialize>(
    name: &str,
    upstream: &Upstream,
    inputs: I,
    expected: E,
) -> Result<Rendered, Error> {
    crate::render(AREA, name, upstream, inputs, expected)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    fn version_bytes(self) -> Vec<u8> {
        match self {
            Network::Mainnet => EPICBOX_ADDRESS_VERSION_MAINNET.to_vec(),
            Network::Floonet => EPICBOX_ADDRESS_VERSION_TESTNET.to_vec(),
        }
    }

    fn chain_type(self) -> ChainTypes {
        match self {
            Network::Mainnet => ChainTypes::Mainnet,
            Network::Floonet => ChainTypes::Floonet,
        }
    }
}

// Upstream reads the address network from a process-wide chain type. Every use in this area holds
// this lock while the chain type is set, so cases built in parallel tests see the network they ask
// for, and the chain type is put back to mainnet afterwards.
static CHAIN_TYPE: Mutex<()> = Mutex::new(());

fn on_network<T>(network: Network, run: impl FnOnce() -> T) -> T {
    let _guard = CHAIN_TYPE.lock().unwrap_or_else(PoisonError::into_inner);
    global::set_mining_mode(network.chain_type());
    let result = run();
    global::set_mining_mode(ChainTypes::Mainnet);
    result
}

// Serializes the swap of the panic hook in `upstream_outcome`, so the original hook is always the
// one put back. Taken after `CHAIN_TYPE` when both are held.
static PANIC_HOOK: Mutex<()> = Mutex::new(());

/// Runs an upstream call whose verdict is whether it returns a value. Every other outcome is
/// recorded as a rejection and kept out of the generator's output.
fn upstream_outcome<T, E>(call: impl FnOnce() -> Result<T, E> + panic::UnwindSafe) -> Option<T> {
    let _guard = PANIC_HOOK.lock().unwrap_or_else(PoisonError::into_inner);
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let outcome = panic::catch_unwind(call);
    panic::set_hook(hook);
    outcome.ok().and_then(Result::ok)
}

/// A fixed test key and the forms of its public key the vectors use.
struct TestKey {
    secret: SecretKey,
    secret_bytes: [u8; 32],
    public: PublicKey,
}

impl TestKey {
    fn new(secret_bytes: [u8; 32]) -> Result<TestKey, Error> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&secp, &secret_bytes)
            .map_err(Error::reference("test secret key"))?;
        let public = PublicKey::from_secret_key(&secp, &secret)
            .map_err(Error::reference("test public key"))?;
        Ok(TestKey {
            secret,
            secret_bytes,
            public,
        })
    }

    fn public_hex(&self) -> String {
        crate::hex(self.public.serialize_vec(&Secp256k1::new(), true))
    }

    /// The 52-character base58check form upstream prints, without scheme or domain.
    fn address_key(&self, network: Network) -> String {
        self.public.to_base58_check(network.version_bytes())
    }
}

// Test-only secret keys, never real wallet material.
const ALICE: [u8; 32] = [0x01; 32];
const BOB: [u8; 32] = [0x02; 32];
const CAROL: [u8; 32] = [0x03; 32];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::DEFAULT_OUT;

    fn committed_path(name: &str) -> PathBuf {
        Path::new(DEFAULT_OUT)
            .join(AREA)
            .join(format!("{name}.json"))
    }

    #[test]
    fn deterministic_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        for vector in generate(&pins)? {
            if vector.name.starts_with("message_") {
                continue;
            }
            let path = committed_path(&vector.name);
            assert_eq!(std::fs::read(&path)?, vector.bytes, "{}", path.display());
        }
        Ok(())
    }

    #[test]
    fn committed_messages_decrypt_with_upstream() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = git_source(LOCKFILE, "epic_wallet_libwallet")?;
        for case in message::cases() {
            let path = committed_path(&format!("message_{}", case.name));
            let committed: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            assert_eq!(committed["upstream"], serde_json::to_value(&wallet)?);
            message::tests::verify_committed(&case, &committed)?;
        }
        Ok(())
    }

    #[test]
    fn committed_files_are_exactly_the_generated_cases() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        let generated: BTreeSet<String> = generate(&pins)?.into_iter().map(|v| v.name).collect();
        let mut committed = BTreeSet::new();
        for entry in std::fs::read_dir(Path::new(DEFAULT_OUT).join(AREA))? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let stem = path.file_stem().and_then(|s| s.to_str()).ok_or("name")?;
                committed.insert(stem.to_owned());
            }
        }
        assert_eq!(committed, generated);
        Ok(())
    }

    #[test]
    fn upstream_sees_the_requested_network() {
        assert!(on_network(Network::Floonet, global::is_floonet));
        assert!(!on_network(Network::Mainnet, global::is_floonet));
    }
}
